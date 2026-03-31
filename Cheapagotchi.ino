/*
 * ESP32 Cheapagotchi — WPA/WPA2 Handshake Sniffer  (v1.1.0)
 * Project: ESP32Gotchi | github: tworjaga | telegram: @al7exy
 *
 * Target  : ESP32 Dev Module (ESP32-WROOM-32, 30-pin)
 * Core    : esp32 by Espressif 2.0.x+
 * Libraries (install via Library Manager):
 *   - U8g2
 *   SD, SPI, WiFi, esp_wifi, FreeRTOS — bundled with core
 *
 * Arduino IDE:
 *   Board            : ESP32 Dev Module
 *   Partition scheme : Default 4MB with spiffs
 *   CPU freq         : 240 MHz
 *
 * ── v1.1.0 changes ──────────────────────────────────────────────────────────
 *  FIX-1  Button moved from GPIO0 (ESP32 boot-mode strapping pin) to GPIO4.
 *         Pressing the old GPIO0 button during a restart would pull the
 *         strapping pin LOW and lock the device in ROM Download Mode.
 *
 *  FIX-2  Task priorities rebalanced on Core 0.
 *         task_hop raised to priority 6 (above task_proc at 5) so channel
 *         hopping is guaranteed every 200 ms regardless of packet load.
 *         task_write raised to 4 so completed handshakes are flushed
 *         promptly even under heavy traffic.
 *
 *  FIX-3  Zero-allocation packet path.
 *         promisc_cb no longer calls malloc()/free() on every frame.
 *         A static pool of PKT_POOL_DEPTH fixed-size blocks is allocated
 *         once at boot.  The callback claims a block index from a free-list
 *         queue; task_proc returns it after processing (or hands it to the
 *         hs_raw_pool if the frame is stored as part of a handshake).
 *
 *  FIX-4  Handshake raw frames stored in a dedicated static pool.
 *         hs_slot_t no longer embeds raw[4][MAX_PKT_LEN] (which made each
 *         slot 6 430 bytes and the g_hs[] array 205 KB).  Instead each
 *         captured frame is kept as a pool-block index; the pool block is
 *         released to pkt_pool after the PCAP is written.
 *
 *  FIX-5  write_item_t is now a single uint8_t (slot index), not a 6 430-byte
 *         value copy.  The write queue therefore allocates 8 bytes instead of
 *         51 440 bytes, and task_write reads directly from g_hs[].
 *
 *  FIX-6  g_ap_mutex removed.  task_proc is the only writer of g_aps[]; the
 *         AP hash table is read by task_ui which only accesses g_ap_count
 *         (volatile uint32_t — naturally atomic on Xtensa LX6).  The mutex
 *         was protecting a race condition that cannot occur and was burning
 *         CPU on the hottest code path.
 *
 *  FIX-7  O(N) AP linear scan replaced with a 256-bucket open-addressing
 *         hash table keyed on the 6-byte MAC address.  Lookup is O(1)
 *         average, worst-case bounded by table density.
 *
 *  FIX-8  EAPOL slot-exhaustion DoS mitigated.  A global rate limiter caps
 *         new slot creation to one per 100 ms.  MAX_HS_SLOTS reduced to 16
 *         (ample for passive capture) and HS_EXPIRE_MS reduced to 15 s to
 *         recycle stale slots faster.
 * ────────────────────────────────────────────────────────────────────────────
 */

/* --------------------------------------------------------------------------
 * Includes
 * -------------------------------------------------------------------------- */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <SPI.h>
#include <Wire.h>
#include <U8g2lib.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <esp_task_wdt.h>
#include <lwip/def.h>       /* ntohs / ntohl */

/* --------------------------------------------------------------------------
 * Pin map
 *
 * FIX-1: Button moved from GPIO0 to GPIO4.
 *   GPIO0 is the ESP32 boot-mode strapping pin.  If it is held LOW when the
 *   chip samples strapping pins (~50 ms after reset), the ROM enters serial
 *   Download Mode and the user firmware never starts.  Because the long-press
 *   restart fires on button *release*, in normal use GPIO0 would already be
 *   HIGH by the time the chip reboots.  However, a user who keeps the button
 *   depressed through the reset (or releases slowly) will reliably brick the
 *   session.  GPIO4 has no strapping function on WROOM-32.
 *
 *   Hardware change required: move the button wire from DevKit pin IO0 to IO4.
 *
 * GPIO5/SD-CS note: GPIO5 is the SDIO-slave timing strapping pin but only
 *   affects SDIO peripheral mode.  In SPI mode (used here) it is safe.
 *   On a custom PCB, ensure no external pull-up stronger than 10 kΩ is placed
 *   on GPIO5 before the strapping window closes at boot.
 * -------------------------------------------------------------------------- */
#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        4   /* FIX-1: was 0 (boot strapping pin) */
#define PIN_LED        2

/* --------------------------------------------------------------------------
 * Tuning constants
 * -------------------------------------------------------------------------- */
#define PKT_POOL_DEPTH       32   /* static packet buffer blocks             */
#define HS_RAW_POOL_DEPTH    32   /* static hs-frame buffer blocks (≤4×slots)*/
#define PKT_QUEUE_DEPTH      32   /* in-flight packet index queue depth       */
#define WRITE_QUEUE_DEPTH     8   /* completed hs slot-index queue depth      */
#define MAX_HS_SLOTS         16   /* FIX-8: was 32; 16 is ample passively    */
#define MAX_UNIQUE_APS      256   /* hash table buckets (must be power of 2) */
#define CHANNEL_DWELL_MS    200
#define DEBOUNCE_MS          50
#define LONG_PRESS_MS      3000
#define SD_RETRY_MS       10000
#define MIN_FREE_BYTES    (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S        30
#define CHANNELS_2G          11
#define MAX_PKT_LEN        1600
#define HS_EXPIRE_MS      15000   /* FIX-8: was 30000; recycle stale slots faster */
#define HS_NEW_SLOT_RATE_MS 100   /* FIX-8: min ms between new slot creations */

/* --------------------------------------------------------------------------
 * OLED instance  (hardware I2C, address 0x3C)
 * -------------------------------------------------------------------------- */
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* --------------------------------------------------------------------------
 * Packed structures
 * -------------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint8_t  revision;
    uint8_t  pad;
    uint8_t  len_lo;   /* radiotap header length, little-endian */
    uint8_t  len_hi;
    uint32_t present;
} radiotap_hdr_t;

typedef struct {
    uint8_t  fc0;      /* frame control byte 0 */
    uint8_t  fc1;      /* frame control byte 1 */
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr_t;

typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t oui[3];
    uint8_t etype_hi;
    uint8_t etype_lo;
} llc_snap_hdr_t;

typedef struct {
    uint8_t version;
    uint8_t type;      /* 0x03 = Key */
    uint8_t len_hi;
    uint8_t len_lo;
} eapol_hdr_t;

typedef struct {
    uint8_t  descriptor;   /* 0x02 = RSN, 0xFE = WPA */
    uint8_t  ki_hi;        /* key_info high byte */
    uint8_t  ki_lo;        /* key_info low byte  */
    uint16_t key_length;
    uint8_t  replay_counter[8];
    uint8_t  nonce[32];
    uint8_t  iv[16];
    uint8_t  rsc[8];
    uint8_t  id[8];
    uint8_t  mic[16];
    uint16_t key_data_len;
} eapol_key_body_t;

typedef struct {
    uint32_t magic;        /* 0xa1b2c3d4 */
    uint16_t ver_major;    /* 2 */
    uint16_t ver_minor;    /* 4 */
    int32_t  thiszone;     /* 0 */
    uint32_t sigfigs;      /* 0 */
    uint32_t snaplen;      /* 65535 */
    uint32_t network;      /* 105 = IEEE 802.11 + radiotap */
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkt_hdr_t;

#pragma pack(pop)

/* --------------------------------------------------------------------------
 * FIX-3 / FIX-4: Static memory pools
 *
 * Two pools of fixed-size MAX_PKT_LEN blocks, allocated once at boot.
 * No malloc/free at runtime.
 *
 *  pkt_pool    — blocks claimed by promisc_cb, released by task_proc after
 *                parsing (or handed to hs_raw_pool if stored in a hs slot).
 *
 *  hs_raw_pool — blocks held for the lifetime of a handshake capture.
 *                Released by task_write after the PCAP file is closed.
 *
 * A block index (uint8_t) travels through queues; the block itself never
 * moves.  This eliminates all per-packet dynamic allocation.
 * -------------------------------------------------------------------------- */
static uint8_t pkt_pool_mem    [PKT_POOL_DEPTH]   [MAX_PKT_LEN];
static uint8_t hs_raw_pool_mem [HS_RAW_POOL_DEPTH][MAX_PKT_LEN];

/* Free-list queues: contain indices of available blocks */
static QueueHandle_t g_pkt_free_q;    /* free pkt_pool indices   */
static QueueHandle_t g_hs_raw_free_q; /* free hs_raw_pool indices */

/* Sentinel: block index is unallocated */
#define POOL_NONE 0xFF

/* --------------------------------------------------------------------------
 * Queue / task items
 * -------------------------------------------------------------------------- */

/* In-flight packet: index into pkt_pool_mem + metadata */
typedef struct {
    uint8_t  pool_idx; /* index into pkt_pool_mem[]          */
    uint16_t len;
    uint8_t  ch;
} pkt_item_t;

/* FIX-5: write queue now carries a single uint8_t slot index (was 6430 bytes) */
typedef uint8_t write_item_t;  /* index into g_hs[] */

/* --------------------------------------------------------------------------
 * FIX-4: Handshake slot — raw frame storage replaced with pool indices
 *
 * Before: raw[4][MAX_PKT_LEN] — 6400 bytes per slot, 205 KB for 32 slots.
 * After:  raw_idx[4]           — 4 bytes per slot, holds hs_raw_pool indices.
 *         raw_len[4]           — frame lengths.
 *         hs_raw_pool_mem[raw_idx[i]] holds the actual bytes.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  raw_idx[4];   /* hs_raw_pool_mem indices; POOL_NONE = not captured */
    uint16_t raw_len[4];
    bool     seen[4];
    bool     active;
    uint32_t last_ms;
} hs_slot_t;

/* --------------------------------------------------------------------------
 * FIX-7: AP hash table (replaces O(N) linear scan)
 *
 * Open-addressing table with 256 buckets (MAX_UNIQUE_APS must be power of 2).
 * Each bucket is either all-zeros (empty) or a 6-byte MAC address.
 * Collisions walk forward linearly.  At ≤75% load (192 MACs) performance
 * remains O(1) average.  The table never shrinks; once 192 entries are seen
 * the insert silently stops recording new APs (display cap).
 * -------------------------------------------------------------------------- */
#define AP_TABLE_MASK  (MAX_UNIQUE_APS - 1)  /* 0xFF */
#define AP_TABLE_MAX_LOAD 192                /* 75% of 256 */

static uint8_t  g_ap_table[MAX_UNIQUE_APS][6]; /* hash table; zero = empty */
static volatile uint32_t g_ap_count = 0;        /* FIX-6: no mutex needed  */

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */
static QueueHandle_t     g_pkt_queue;
static QueueHandle_t     g_write_queue;
static SemaphoreHandle_t g_hs_mutex;
/* FIX-6: g_ap_mutex removed */

static hs_slot_t g_hs[MAX_HS_SLOTS];

static volatile uint32_t g_hs_count      = 0;
static volatile uint32_t g_pkt_rate      = 0;
static volatile uint8_t  g_channel       = 1;
static volatile bool     g_sd_ok         = false;
static volatile uint32_t g_last_sd_retry = 0;

/* FIX-8: rate-limit new hs slot creation */
static volatile uint32_t g_last_slot_create_ms = 0;

typedef enum { LED_SLOW, LED_FAST, LED_FLASH, LED_ERROR } led_state_t;
static volatile led_state_t g_led = LED_SLOW;

typedef enum { FACE_NORMAL, FACE_CAPTURE, FACE_ERROR, FACE_IDLE } face_t;
static volatile face_t g_face = FACE_NORMAL;

static TaskHandle_t h_proc;
static TaskHandle_t h_ui;
static TaskHandle_t h_hop;
static TaskHandle_t h_write;

/* --------------------------------------------------------------------------
 * MAC helpers
 * -------------------------------------------------------------------------- */
static inline bool mac_eq(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}
static inline bool mac_zero(const uint8_t *a) {
    for (int i = 0; i < 6; i++) if (a[i]) return false;
    return true;
}
static void mac_str(const uint8_t *m, char *out) {
    sprintf(out, "%02x_%02x_%02x_%02x_%02x_%02x",
            m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* --------------------------------------------------------------------------
 * FIX-7: AP hash table operations (replaces ap_record linear scan)
 *
 * Hash: simple djb2-style mix of the 6 MAC bytes, folded to 8 bits.
 * No mutex needed — only task_proc writes; task_ui reads only g_ap_count
 * (volatile uint32_t, naturally atomic on Xtensa LX6).
 * -------------------------------------------------------------------------- */
static uint8_t mac_hash(const uint8_t *mac) {
    uint32_t h = 5381;
    for (int i = 0; i < 6; i++) h = ((h << 5) + h) ^ mac[i];
    return (uint8_t)(h & AP_TABLE_MASK);
}

static void ap_record(const uint8_t *bssid) {
    if (mac_zero(bssid)) return;
    if (g_ap_count >= AP_TABLE_MAX_LOAD) return;  /* table at capacity */

    uint8_t idx = mac_hash(bssid);
    for (uint32_t i = 0; i < MAX_UNIQUE_APS; i++) {
        uint8_t slot = (idx + i) & AP_TABLE_MASK;
        if (mac_zero(g_ap_table[slot])) {
            /* empty bucket — insert */
            memcpy(g_ap_table[slot], bssid, 6);
            g_ap_count++;   /* single writer; no lock needed */
            return;
        }
        if (mac_eq(g_ap_table[slot], bssid)) return;  /* already present */
    }
    /* table fully probed (should not reach here given load cap) */
}

/* --------------------------------------------------------------------------
 * SD
 * -------------------------------------------------------------------------- */
static bool sd_init(void) {
    SPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
    if (!SD.begin(PIN_SD_CS)) {
        g_sd_ok = false;
        g_face  = FACE_ERROR;
        g_led   = LED_ERROR;
        Serial.println("[SD] init failed");
        return false;
    }
    g_sd_ok = true;
    if (g_face == FACE_ERROR) g_face = FACE_NORMAL;
    g_led = LED_SLOW;
    if (!SD.exists("/handshakes")) SD.mkdir("/handshakes");
    Serial.println("[SD] OK");
    return true;
}

/* FIX-5: pcap_write takes a slot pointer directly; no copy needed */
static void pcap_write(uint8_t slot_idx) {
    if (!g_sd_ok) return;
    hs_slot_t *hs = &g_hs[slot_idx];

    uint64_t free_b = (uint64_t)SD.cardSize() - (uint64_t)SD.usedBytes();
    if (free_b < MIN_FREE_BYTES) {
        Serial.println("[SD] low space");
        g_face = FACE_ERROR;
        goto release_slots;
    }

    {
        char bssid_s[24];
        mac_str(hs->bssid, bssid_s);
        uint32_t ts = millis() / 1000;
        char path[80];
        snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap",
                 bssid_s, (unsigned long)ts);

        File f = SD.open(path, FILE_WRITE);
        if (!f) {
            Serial.printf("[SD] open failed: %s\n", path);
            goto release_slots;
        }

        pcap_file_hdr_t gh;
        gh.magic     = 0xa1b2c3d4;
        gh.ver_major = 2;
        gh.ver_minor = 4;
        gh.thiszone  = 0;
        gh.sigfigs   = 0;
        gh.snaplen   = 65535;
        gh.network   = 105;
        f.write((const uint8_t *)&gh, sizeof(gh));

        for (int i = 0; i < 4; i++) {
            if (!hs->seen[i] || hs->raw_len[i] == 0) continue;
            if (hs->raw_idx[i] == POOL_NONE) continue;

            pcap_pkt_hdr_t ph;
            ph.ts_sec  = ts;
            ph.ts_usec = (uint32_t)i * 1000;
            ph.incl_len = hs->raw_len[i];
            ph.orig_len = hs->raw_len[i];
            f.write((const uint8_t *)&ph, sizeof(ph));
            f.write(hs_raw_pool_mem[hs->raw_idx[i]], hs->raw_len[i]);
        }

        f.close();
        g_hs_count++;
        g_led = LED_FLASH;
        Serial.printf("[HS] saved %s  total=%lu\n", path, (unsigned long)g_hs_count);
    }

release_slots:
    /* Return hs_raw_pool blocks to the free list */
    for (int i = 0; i < 4; i++) {
        if (hs->raw_idx[i] != POOL_NONE) {
            uint8_t ridx = hs->raw_idx[i];
            xQueueSend(g_hs_raw_free_q, &ridx, 0);
            hs->raw_idx[i] = POOL_NONE;
        }
    }
    /* Mark slot free for reuse */
    if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        hs->active = false;
        xSemaphoreGive(g_hs_mutex);
    }
}

/* --------------------------------------------------------------------------
 * Handshake slot management  (caller must hold g_hs_mutex)
 * -------------------------------------------------------------------------- */
static hs_slot_t *hs_find_or_create(const uint8_t *bssid, const uint8_t *sta) {
    hs_slot_t *empty = NULL;
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active &&
            mac_eq(g_hs[i].bssid, bssid) &&
            mac_eq(g_hs[i].sta,   sta))
            return &g_hs[i];
        if (!g_hs[i].active && !empty)
            empty = &g_hs[i];
    }

    /* FIX-8: rate-limit new slot creation to prevent DoS exhaustion */
    uint32_t now = millis();
    if ((now - g_last_slot_create_ms) < HS_NEW_SLOT_RATE_MS) return NULL;

    if (empty) {
        memset(empty, 0, sizeof(hs_slot_t));
        for (int i = 0; i < 4; i++) empty->raw_idx[i] = POOL_NONE;
        memcpy(empty->bssid, bssid, 6);
        memcpy(empty->sta,   sta,   6);
        empty->active  = true;
        empty->last_ms = now;
        g_last_slot_create_ms = now;
    }
    return empty;
}

static void hs_expire(void) { /* caller holds g_hs_mutex */
    uint32_t now = millis();
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active && (now - g_hs[i].last_ms) > HS_EXPIRE_MS) {
            /* Release any held hs_raw_pool blocks */
            for (int j = 0; j < 4; j++) {
                if (g_hs[i].raw_idx[j] != POOL_NONE) {
                    uint8_t ridx = g_hs[i].raw_idx[j];
                    xQueueSend(g_hs_raw_free_q, &ridx, 0);
                    g_hs[i].raw_idx[j] = POOL_NONE;
                }
            }
            g_hs[i].active = false;
        }
    }
}

/* --------------------------------------------------------------------------
 * EAPOL message classifier
 *
 * IEEE 802.11-2020 §12.7.2 — key_info bit positions:
 *   bit 3  Key Type  (1 = pairwise)
 *   bit 6  Install
 *   bit 7  Key ACK
 *   bit 8  Key MIC
 *   bit 9  Secure
 *
 * 4-way messages:
 *   Msg1: pairwise, ACK=1, MIC=0, Install=0, Secure=0
 *   Msg2: pairwise, ACK=0, MIC=1, Install=0, Secure=0
 *   Msg3: pairwise, ACK=1, MIC=1, Install=1, Secure=1
 *   Msg4: pairwise, ACK=0, MIC=1, Install=0, Secure=1
 * -------------------------------------------------------------------------- */
static int eapol_msg_number(uint16_t ki) {
    bool pairwise = (ki >> 3) & 1;
    bool install  = (ki >> 6) & 1;
    bool ack      = (ki >> 7) & 1;
    bool mic      = (ki >> 8) & 1;
    bool secure   = (ki >> 9) & 1;

    if (!pairwise) return -1;

    if ( ack && !mic && !install && !secure) return 1;
    if (!ack &&  mic && !install && !secure) return 2;
    if ( ack &&  mic &&  install &&  secure) return 3;
    if (!ack &&  mic && !install &&  secure) return 4;
    return -1;
}

/* --------------------------------------------------------------------------
 * Core packet parser
 * FIX-3: pkt_buf is a pool block; pool_idx is returned to g_pkt_free_q
 *         unless the frame is kept for a handshake slot (handed to hs_raw_pool).
 * -------------------------------------------------------------------------- */
static void process_packet(uint8_t pkt_pool_idx, uint16_t len) {
    const uint8_t *buf = pkt_pool_mem[pkt_pool_idx];
    bool keep_block    = false;   /* will be set true if frame stored in a hs slot */

    if (len < sizeof(radiotap_hdr_t)) goto done;

    {
        const radiotap_hdr_t *rt = (const radiotap_hdr_t *)buf;
        uint16_t rt_len = (uint16_t)rt->len_lo | ((uint16_t)rt->len_hi << 8);
        if (rt_len >= len) goto done;

        const uint8_t *mf  = buf + rt_len;
        uint16_t       mfl = len - rt_len;

        if (mfl < sizeof(dot11_hdr_t)) goto done;

        const dot11_hdr_t *dh = (const dot11_hdr_t *)mf;

        uint8_t fc_type    = (dh->fc0 >> 2) & 0x03;
        uint8_t fc_subtype = (dh->fc0 >> 4) & 0x0F;
        uint8_t to_ds      =  dh->fc1       & 0x01;
        uint8_t from_ds    = (dh->fc1 >> 1) & 0x01;

        if (fc_type == 0 && (fc_subtype == 8 || fc_subtype == 5)) {
            ap_record(dh->addr3);
            goto done;
        }

        if (fc_type != 2) goto done;
        if (to_ds && from_ds)  goto done;

        uint8_t bssid[6], sta[6];
        if (!to_ds && !from_ds) {
            memcpy(bssid, dh->addr3, 6);
            memcpy(sta,   dh->addr2, 6);
        } else if (from_ds) {
            memcpy(bssid, dh->addr2, 6);
            memcpy(sta,   dh->addr1, 6);
        } else {
            memcpy(bssid, dh->addr1, 6);
            memcpy(sta,   dh->addr2, 6);
        }

        if (mac_zero(bssid) || mac_zero(sta)) goto done;
        ap_record(bssid);

        uint16_t mac_hdr_sz = (uint16_t)sizeof(dot11_hdr_t);
        if (fc_subtype & 0x08) mac_hdr_sz += 2;

        if (mfl < mac_hdr_sz + (uint16_t)sizeof(llc_snap_hdr_t)) goto done;

        const llc_snap_hdr_t *llc = (const llc_snap_hdr_t *)(mf + mac_hdr_sz);

        if (llc->dsap != 0xAA || llc->ssap != 0xAA)         goto done;
        if (llc->etype_hi != 0x88 || llc->etype_lo != 0x8E) goto done;

        uint16_t eapol_off = mac_hdr_sz + (uint16_t)sizeof(llc_snap_hdr_t);
        if (mfl < eapol_off + (uint16_t)sizeof(eapol_hdr_t) +
                              (uint16_t)sizeof(eapol_key_body_t)) goto done;

        const eapol_hdr_t      *eh = (const eapol_hdr_t *)(mf + eapol_off);
        const eapol_key_body_t *ek = (const eapol_key_body_t *)
                                     (mf + eapol_off + sizeof(eapol_hdr_t));

        if (eh->type != 0x03) goto done;
        if (ek->descriptor != 0x02 && ek->descriptor != 0xFE) goto done;

        uint16_t ki  = ((uint16_t)ek->ki_hi << 8) | ek->ki_lo;
        int      msg = eapol_msg_number(ki);
        if (msg < 1 || msg > 4) goto done;

        /* --- Handshake slot update --- */
        bool     complete  = false;
        uint8_t  done_idx  = 0xFF;

        if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(10)) != pdTRUE) goto done;

        hs_slot_t *slot = hs_find_or_create(bssid, sta);
        if (slot) {
            int frame_idx = msg - 1;
            if (!slot->seen[frame_idx]) {
                /* Try to claim an hs_raw_pool block for this frame */
                uint8_t rblk = POOL_NONE;
                xQueueReceive(g_hs_raw_free_q, &rblk, 0);

                if (rblk != POOL_NONE) {
                    /* Copy from the pkt_pool block into the hs_raw_pool block */
                    uint16_t cplen = (len > MAX_PKT_LEN) ? (uint16_t)MAX_PKT_LEN : len;
                    memcpy(hs_raw_pool_mem[rblk], buf, cplen);
                    slot->raw_idx[frame_idx] = rblk;
                    slot->raw_len[frame_idx] = cplen;
                    slot->seen[frame_idx]    = true;
                    slot->last_ms            = millis();
                    Serial.printf("[HS] %02x:%02x:%02x -> %02x:%02x:%02x  msg%d\n",
                        bssid[0], bssid[1], bssid[2],
                        sta[0],   sta[1],   sta[2],   msg);
                }
                /* else: hs_raw_pool exhausted, frame silently skipped */
            }

            g_face = FACE_CAPTURE;
            g_led  = LED_FAST;

            if (slot->seen[0] && slot->seen[1] && slot->seen[2] && slot->seen[3]) {
                /* All four messages captured — hand off to task_write */
                done_idx = (uint8_t)(slot - g_hs);  /* slot index */
                complete = true;
                /* Do NOT clear slot->active here; task_write owns it now */
            }
        }

        xSemaphoreGive(g_hs_mutex);

        if (complete) {
            /* FIX-5: send 1-byte slot index, not a 6430-byte struct copy */
            write_item_t wi = done_idx;
            if (xQueueSend(g_write_queue, &wi, 0) != pdTRUE) {
                Serial.println("[HS] write queue full, drop");
                /* Manually release the slot and its raw blocks */
                if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                    for (int j = 0; j < 4; j++) {
                        if (g_hs[done_idx].raw_idx[j] != POOL_NONE) {
                            uint8_t ridx = g_hs[done_idx].raw_idx[j];
                            xQueueSend(g_hs_raw_free_q, &ridx, 0);
                            g_hs[done_idx].raw_idx[j] = POOL_NONE;
                        }
                    }
                    g_hs[done_idx].active = false;
                    xSemaphoreGive(g_hs_mutex);
                }
            }
            g_face = FACE_NORMAL;
        }
    }

done:
    if (!keep_block) {
        /* Return pkt_pool block to the free list */
        xQueueSend(g_pkt_free_q, &pkt_pool_idx, 0);
    }
}

/* --------------------------------------------------------------------------
 * Promiscuous callback — Wi-Fi driver task context, must not block
 *
 * FIX-3: Claims a block from the static pkt_pool free-list instead of
 *         calling malloc().  If the pool is exhausted the packet is dropped
 *         (same outcome as malloc returning NULL, but without heap churn).
 * -------------------------------------------------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    /* Claim a pool block (non-blocking) */
    uint8_t pool_idx = POOL_NONE;
    BaseType_t woken = pdFALSE;
    if (xQueueReceiveFromISR(g_pkt_free_q, &pool_idx, &woken) != pdTRUE) return;

    memcpy(pkt_pool_mem[pool_idx], pkt->payload, plen);

    pkt_item_t item = { pool_idx, plen, g_channel };
    if (xQueueSendFromISR(g_pkt_queue, &item, &woken) != pdTRUE) {
        /* Queue full — return block immediately */
        xQueueSendFromISR(g_pkt_free_q, &pool_idx, &woken);
    }
    if (woken) portYIELD_FROM_ISR();
}

/* --------------------------------------------------------------------------
 * Task: packet processor  (core 0, priority 5)
 *
 * FIX-2: task_hop now runs at priority 6 (above this task) so it always
 *         gets its 200 ms dwell slot regardless of packet queue load.
 *         This task never needs to call vTaskDelay() explicitly because
 *         xQueueReceive with a timeout yields the scheduler; and in the
 *         worst case task_hop preempts us.
 * -------------------------------------------------------------------------- */
static void task_proc(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();

    while (1) {
        esp_task_wdt_reset();
        pkt_item_t item;
        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            process_packet(item.pool_idx, item.len);
            pkt_count++;
        }

        uint32_t now = millis();
        if (now - rate_window >= 1000) {
            g_pkt_rate  = pkt_count;
            pkt_count   = 0;
            rate_window = now;

            if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                hs_expire();
                xSemaphoreGive(g_hs_mutex);
            }

            if (!g_sd_ok && (now - g_last_sd_retry) > SD_RETRY_MS) {
                g_last_sd_retry = now;
                sd_init();
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: SD writer  (core 0, priority 4)
 *
 * FIX-5: receives a 1-byte slot index, reads g_hs[] directly, then
 *         releases pool blocks.  No memcpy of bulk frame data.
 *
 * FIX-2: raised from priority 2 to 4 so handshakes flush promptly
 *         even when task_proc is busy processing packets.
 * -------------------------------------------------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);
    while (1) {
        esp_task_wdt_reset();
        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(200)) == pdTRUE)
            pcap_write(wi);  /* wi is the slot index */
    }
}

/* --------------------------------------------------------------------------
 * Task: channel hopper  (core 0, priority 6)
 *
 * FIX-2: raised from priority 3 to 6 — highest priority on Core 0.
 *         This guarantees the hopper always runs every CHANNEL_DWELL_MS
 *         regardless of how busy task_proc is.  The hopper spends ~99.9%
 *         of its time blocked in vTaskDelay, so the higher priority costs
 *         nothing in practice.
 * -------------------------------------------------------------------------- */
static void task_hop(void *arg) {
    esp_task_wdt_add(NULL);
    uint8_t ch = 1;
    while (1) {
        esp_task_wdt_reset();
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_channel = ch;
        ch = (ch % CHANNELS_2G) + 1;
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
    }
}

/* --------------------------------------------------------------------------
 * LED state machine — non-blocking, ~10 ms tick
 * -------------------------------------------------------------------------- */
static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static bool     on        = false;
    static uint8_t  err_phase = 0;

    uint32_t now = millis();

    switch (g_led) {
        case LED_SLOW:
            if (now - last_ms >= 500) {
                on = !on;
                digitalWrite(PIN_LED, on ? HIGH : LOW);
                last_ms = now;
            }
            break;

        case LED_FAST:
            if (now - last_ms >= 100) {
                on = !on;
                digitalWrite(PIN_LED, on ? HIGH : LOW);
                last_ms = now;
            }
            break;

        case LED_FLASH:
            if (!on) {
                digitalWrite(PIN_LED, HIGH);
                on = true; last_ms = now;
            } else if (now - last_ms >= 120) {
                digitalWrite(PIN_LED, LOW);
                on = false; g_led = LED_SLOW;
            }
            break;

        case LED_ERROR:
            {
                uint32_t period;
                if      (err_phase == 6) period = 1000;
                else if (err_phase % 2 == 0) period = 2000;
                else                         period =  500;

                if (now - last_ms >= period) {
                    last_ms = now;
                    err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                    on = (err_phase % 2 == 0) && (err_phase < 6);
                    digitalWrite(PIN_LED, on ? HIGH : LOW);
                }
            }
            break;
    }
}

/* --------------------------------------------------------------------------
 * Button handler — non-blocking, ~10 ms tick
 *
 * FIX-1: PIN_BTN is now GPIO4 (not GPIO0).  Logic unchanged.
 *         Restart fires on release after a long press, so GPIO4 is already
 *         HIGH by the time the chip boots — no strapping-pin hazard.
 * -------------------------------------------------------------------------- */
static void btn_tick(void) {
    static bool     prev     = HIGH;
    static uint32_t press_ms = 0;
    static uint32_t last_ms  = 0;

    uint32_t now = millis();
    if (now - last_ms < (uint32_t)DEBOUNCE_MS) return;
    last_ms = now;

    bool cur = digitalRead(PIN_BTN);

    if (prev == HIGH && cur == LOW) {
        press_ms = now;
    } else if (prev == LOW && cur == HIGH) {
        uint32_t dur = now - press_ms;
        if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            g_channel = 1;
            Serial.println("[BTN] short press -> ch=1");
        }
    }
    prev = cur;
}

/* --------------------------------------------------------------------------
 * OLED draw — called every 200 ms
 * -------------------------------------------------------------------------- */
static void oled_draw(void) {
    static const char *faces[] = {
        "(o_o)",   /* FACE_NORMAL  */
        "(^o^)",   /* FACE_CAPTURE */
        "(X_X)",   /* FACE_ERROR   */
        "(-_-)"    /* FACE_IDLE    */
    };

    char line[24];
    face_t f = g_face;

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);

    display.drawStr(0, 10, faces[f]);

    snprintf(line, sizeof(line), "HS:  %lu", (unsigned long)g_hs_count);
    display.drawStr(0, 22, line);

    snprintf(line, sizeof(line), "CH:  %u",  (unsigned)g_channel);
    display.drawStr(0, 32, line);

    snprintf(line, sizeof(line), "AP:  %lu", (unsigned long)g_ap_count);
    display.drawStr(0, 42, line);

    snprintf(line, sizeof(line), "PKT: %lu", (unsigned long)g_pkt_rate);
    display.drawStr(0, 52, line);

    display.drawStr(0, 62, g_sd_ok ? "SD:  OK" : "SD:  ERR");

    display.sendBuffer();
}

/* --------------------------------------------------------------------------
 * Task: UI  (core 1, priority 1)
 * -------------------------------------------------------------------------- */
static void task_ui(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t last_oled = 0;

    while (1) {
        esp_task_wdt_reset();
        uint32_t now = millis();

        btn_tick();
        led_tick();

        if (now - last_oled >= 200) {
            oled_draw();
            last_oled = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* --------------------------------------------------------------------------
 * setup()
 * -------------------------------------------------------------------------- */
void setup(void) {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[BOOT] ESP32 Cheapagotchi v1.1.0");

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);   /* GPIO4 — no strapping conflict */
    digitalWrite(PIN_LED, LOW);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "v1.1.0 Boot...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    /* ── FIX-3: Initialise static pool free-lists ───────────────────────── */
    g_pkt_free_q    = xQueueCreate(PKT_POOL_DEPTH,    sizeof(uint8_t));
    g_hs_raw_free_q = xQueueCreate(HS_RAW_POOL_DEPTH, sizeof(uint8_t));
    configASSERT(g_pkt_free_q);
    configASSERT(g_hs_raw_free_q);

    for (uint8_t i = 0; i < PKT_POOL_DEPTH; i++)
        xQueueSend(g_pkt_free_q, &i, 0);
    for (uint8_t i = 0; i < HS_RAW_POOL_DEPTH; i++)
        xQueueSend(g_hs_raw_free_q, &i, 0);

    /* ── Main queues ────────────────────────────────────────────────────── */
    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,  sizeof(pkt_item_t));
    /* FIX-5: write queue items are 1 byte, not 6430 bytes */
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(write_item_t));
    g_hs_mutex    = xSemaphoreCreateMutex();
    /* FIX-6: g_ap_mutex not created — not needed */

    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);

    memset(g_hs,       0, sizeof(g_hs));
    memset(g_ap_table, 0, sizeof(g_ap_table));

    /* Initialise raw_idx sentinel values */
    for (int i = 0; i < MAX_HS_SLOTS; i++)
        for (int j = 0; j < 4; j++)
            g_hs[i].raw_idx[j] = POOL_NONE;

    sd_init();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA |
                      WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    /*
     * FIX-2: Revised priorities
     *   task_hop   priority 6 — highest on Core 0; always gets its dwell slot
     *   task_proc  priority 5 — unchanged
     *   task_write priority 4 — raised from 2; flushes handshakes promptly
     *   task_ui    priority 1 — Core 1; independent of Core 0 scheduling
     */
    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", 4096, NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", 4096, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   2048, NULL, 6, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       4096, NULL, 1, &h_ui,    1);

    display.clearBuffer();
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Running...");
    display.sendBuffer();

    Serial.println("[BOOT] tasks started");
    Serial.printf("[MEM]  free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());
    esp_task_wdt_delete(NULL);
}

/* --------------------------------------------------------------------------
 * loop() — idle; all logic in tasks
 * -------------------------------------------------------------------------- */
void loop(void) {
    vTaskDelay(portMAX_DELAY);
}
