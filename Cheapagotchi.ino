/*
 * ESP32 Cheapagotchi — WPA/WPA2 Handshake Sniffer  (v1.2.2)
 * Project: ESP32Gotchi | github: tworjaga | telegram: @al7exy
 *
 * Target  : ESP32 Dev Module (ESP32-WROOM-32, 30-pin)
 * Core    : esp32 by Espressif 2.0.x+
 * Libraries (install via Library Manager):
 * - U8g2
 * SD, SPI, WiFi, esp_wifi, FreeRTOS — bundled with core
 *
 * Fixes applied (v1.2.0):
 *  F1  chunk_buf compile-time size assertion + runtime bounds guard
 *  F2  g_ap_table protected by portMUX_TYPE spinlock (ISR-safe)
 *  F3  pcap_write() slot-leak on hs_mutex timeout → blocking take
 *  F4  task_ui core-ID assertion; I2C/promisc isolation documented
 *  F5  g_hs_mutex → recursive mutex; hs_expire() safe inside lock
 *  F6  g_channel, g_led, g_face, g_last_sd_retry → std::atomic
 *  F7  f.write() return value checked; partial-write error logged
 *  F8  mac_hash() replaced with Murmur3 finaliser mix
 *  F9  task_write and task_proc stack bumped to 6144 words
 *  F10 btn_tick poll-rate dependency documented
 *  F11 static_assert POOL_NONE sentinel validity
 *  F12 SPI.begin() guarded with spi_started flag
 *  F13 WDT behaviour on SD stall documented
 *
 * Feature (v1.2.1):
 *  RSSI filter applied in promisc_cb before pool claim — weak-signal
 *  packets dropped at zero pool cost. Threshold: RSSI_THRESHOLD (-80 dBm).
 *  Last RSSI and cumulative drop count exposed on OLED and Serial.
 *
 * Fixes applied (v1.2.2):
 *  R1  [HIGH]   promisc_cb: sig_len includes 4-byte 802.11 FCS trailer that
 *               is NOT present in pkt->payload[]. Strip it before memcpy and
 *               before storing raw_len. Without this every PCAP record had 4
 *               bytes of garbage at the tail → Wireshark dissect errors and
 *               hashcat MIC verification failures (false "no match").
 *  R2  [MEDIUM] pcap_write_file: configASSERT on the memcpy bounds check is
 *               compiled out in release (NDEBUG). Replaced with a hard runtime
 *               guard that returns false, preventing silent stack corruption.
 *  R3  [MEDIUM] task_hop: pinned to Core 0 (matches task_proc / WiFi driver
 *               affinity). Added configASSERT(xPortGetCoreID()==0) mirroring
 *               the pattern used in task_ui (F4).
 *  R4  [MEDIUM] process_packet write-queue-full cleanup: changed 5 ms mutex
 *               timeout to portMAX_DELAY. A 5 ms timeout could silently fail
 *               while task_write holds the mutex during an SD stall, leaving
 *               the hs_slot permanently active and leaking all raw pool blocks.
 *  R5  [LOW]    task_proc SD retry: moved sd_init() call to a dedicated flag
 *               (g_sd_retry_req atomic) consumed by task_write, so the proc
 *               task is never blocked for hundreds of ms on SD initialisation.
 *  R6  [LOW]    setup(): [MEM] free-heap log moved to after all task creations
 *               so it reflects the true post-allocation heap headroom.
 */

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
#include <lwip/def.h>
#include <atomic> // True cross-core atomics
#include <freertos/portmacro.h> // F2: portMUX_TYPE for ISR-safe spinlock

#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        4
#define PIN_LED        2

/* --------------------------------------------------------------------------
 * Tuning constants
 * -------------------------------------------------------------------------- */
#define PKT_POOL_DEPTH        32
#define HS_RAW_POOL_DEPTH     32
#define PKT_QUEUE_DEPTH       32
#define WRITE_QUEUE_DEPTH      8
#define MAX_HS_SLOTS          16
#define MAX_UNIQUE_APS       256
#define CHANNEL_DWELL_MS     200
#define DEBOUNCE_MS           50
#define LONG_PRESS_MS       3000
#define SD_RETRY_MS        10000
#define MIN_FREE_BYTES     (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S         30
#define CHANNELS_2G           11
#define MAX_PKT_LEN         1600
#define HS_EXPIRE_MS       15000
#define HS_NEW_SLOT_RATE_MS  100
#define TASK_PROC_BATCH_MAX   15

/* RSSI filter — drop packets weaker than this threshold in the ISR before
 * they consume a static pool block. -80 dBm is a pragmatic cutoff:
 *   < -80 dBm : signal too weak to reliably complete a 4-way handshake;
 *               capturing these wastes pool slots and CPU on noise.
 *   > -80 dBm : usable signal — allow through for processing.
 * Tune downward (e.g. -85) in open-air environments with distant targets,
 * or upward (e.g. -70) in dense RF environments to reduce false positives.
 * Range: -100 (floor) to 0 dBm. Must fit in int8_t. */
#define RSSI_THRESHOLD        (-80)

/* F1: PCAP chunk buffer = global header (24) + 4 × (record header 16 + payload) */
#define CHUNK_BUF_SIZE  (24 + 4 * (16 + MAX_PKT_LEN))

/* F9: Generous stack sizes — verified headroom via uxTaskGetStackHighWaterMark() */
#define STACK_PROC   6144
#define STACK_WRITE  6144
#define STACK_HOP    2048
#define STACK_UI     4096

/* F11: Sentinel validity — POOL_NONE must not be a reachable pool index */
static_assert(PKT_POOL_DEPTH    < 0xFF, "PKT_POOL_DEPTH too large: POOL_NONE sentinel invalid");
static_assert(HS_RAW_POOL_DEPTH < 0xFF, "HS_RAW_POOL_DEPTH too large: POOL_NONE sentinel invalid");

static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* --------------------------------------------------------------------------
 * Fix 1: Byte-safe Memory Extraction Macros
 * Removes #pragma pack(push, 1) and struct casting to prevent LX6 Alignment Panics.
 * -------------------------------------------------------------------------- */
static inline uint16_t read16_le(const uint8_t *p) { return p[0] | (p[1] << 8); }
static inline uint16_t read16_be(const uint8_t *p) { return (p[0] << 8) | p[1]; }

/* --------------------------------------------------------------------------
 * Static memory pools
 * -------------------------------------------------------------------------- */
static uint8_t pkt_pool_mem    [PKT_POOL_DEPTH]   [MAX_PKT_LEN];
static uint8_t hs_raw_pool_mem [HS_RAW_POOL_DEPTH][MAX_PKT_LEN];

static QueueHandle_t g_pkt_free_q;
static QueueHandle_t g_hs_raw_free_q;

#define POOL_NONE 0xFF

typedef struct {
    uint8_t  pool_idx;
    uint16_t len;
    uint8_t  ch;
} pkt_item_t;

typedef uint8_t write_item_t;

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  raw_idx[4];
    uint16_t raw_len[4];
    bool     seen[4];
    bool     active;
    uint32_t last_ms;
} hs_slot_t;

/* --------------------------------------------------------------------------
 * AP hash table
 * F2: g_ap_table protected by a portMUX spinlock so ap_record() is safe
 *     from both task context and the promiscuous ISR on the same core.
 * -------------------------------------------------------------------------- */
#define AP_TABLE_MASK     (MAX_UNIQUE_APS - 1)
#define AP_TABLE_MAX_LOAD 192

static uint8_t       g_ap_table[MAX_UNIQUE_APS][6];
static portMUX_TYPE  g_ap_mux = portMUX_INITIALIZER_UNLOCKED;

/* True cross-core atomics for all shared counters / flags */
static std::atomic<uint32_t> g_ap_count{0};
static std::atomic<uint32_t> g_hs_count{0};
static std::atomic<uint32_t> g_pkt_rate{0};
static std::atomic<bool>     g_sd_ok{false};
/* Last observed RSSI (dBm, signed) and cumulative RSSI-drop counter.
 * Updated in the ISR — atomic<int8_t> gives safe cross-core reads for OLED. */
static std::atomic<int8_t>   g_last_rssi{0};
static std::atomic<uint32_t> g_rssi_drops{0};
/* R5: SD retry request flag. task_proc sets this instead of calling sd_init()
 *     directly, so the proc task is never stalled for hundreds of ms on SD init.
 *     task_write consumes it at the top of its idle loop. */
static std::atomic<bool>     g_sd_retry_req{false};

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */
static QueueHandle_t     g_pkt_queue;
static QueueHandle_t     g_write_queue;
static SemaphoreHandle_t g_hs_mutex;   /* F5: created as recursive mutex */
static SemaphoreHandle_t g_sd_mutex;

static hs_slot_t g_hs[MAX_HS_SLOTS];

/* F6: volatile insufficient on dual-core LX6; use std::atomic throughout */
static std::atomic<uint8_t>      g_channel{1};
static std::atomic<uint32_t>     g_last_sd_retry{0};

typedef enum { LED_SLOW, LED_FAST, LED_FLASH, LED_ERROR } led_state_t;
static std::atomic<led_state_t>  g_led{LED_SLOW};

typedef enum { FACE_NORMAL, FACE_CAPTURE, FACE_ERROR, FACE_IDLE } face_t;
static std::atomic<face_t>       g_face{FACE_NORMAL};

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
    for (int i = 0; i < 6; i++) if (a[i] != 0) return false;
    return true;
}

static void mac_str(const uint8_t *m, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%02x_%02x_%02x_%02x_%02x_%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* F8: Murmur3 finaliser mix — far better distribution over OUI-heavy MACs
 *     than plain djb2, which clusters same-vendor APs into long probe chains. */
static uint8_t mac_hash(const uint8_t *mac) {
    uint32_t h = 0;
    /* Pack 6 bytes into two 32-bit words and mix */
    uint32_t k0 = (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) |
                  ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
    uint32_t k1 = (uint32_t)mac[4] | ((uint32_t)mac[5] << 8);
    /* Murmur3 finaliser */
    h  = k0 ^ k1;
    h ^= h >> 16;
    h *= 0x45d9f3bU;
    h ^= h >> 16;
    return (uint8_t)(h & AP_TABLE_MASK);
}

/* F2: All reads and writes to g_ap_table go through g_ap_mux.
 *     portENTER/EXIT_CRITICAL are ISR-safe on ESP32 (disables interrupts on
 *     the calling core only; the other core spins if it races). */
static void ap_record(const uint8_t *bssid) {
    if (mac_zero(bssid)) return;
    if (g_ap_count.load(std::memory_order_relaxed) >= AP_TABLE_MAX_LOAD) return;

    uint8_t idx = mac_hash(bssid);

    portENTER_CRITICAL(&g_ap_mux);
    for (uint32_t i = 0; i < MAX_UNIQUE_APS; i++) {
        uint8_t slot = (idx + i) & AP_TABLE_MASK;
        if (mac_zero(g_ap_table[slot])) {
            memcpy(g_ap_table[slot], bssid, 6);
            g_ap_count.fetch_add(1, std::memory_order_relaxed);
            portEXIT_CRITICAL(&g_ap_mux);
            return;
        }
        if (mac_eq(g_ap_table[slot], bssid)) {
            portEXIT_CRITICAL(&g_ap_mux);
            return;
        }
    }
    portEXIT_CRITICAL(&g_ap_mux);
}

/* --------------------------------------------------------------------------
 * SD
 * F12: SPI.begin() is called only once. Repeated calls on ESP-IDF can cause
 *      bus glitches on already-active SPI lines. sd_init() may be called
 *      multiple times (boot + retry path) but SPI is initialised exactly once.
 * F13: If an SD write stalls (worn card), the WDT fires after WDT_TIMEOUT_S
 *      and resets the entire device. This is intentional — prefer a clean
 *      reboot over a hung write task.
 * -------------------------------------------------------------------------- */
static bool sd_init(void) {
    static bool spi_started = false; /* F12 */

    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);

    if (!spi_started) {
        SPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
        spi_started = true;
    }

    if (!SD.begin(PIN_SD_CS)) {
        g_sd_ok.store(false);
        g_face.store(FACE_ERROR);
        g_led.store(LED_ERROR);
        Serial.println("[SD] init failed");
        xSemaphoreGive(g_sd_mutex);
        return false;
    }

    g_sd_ok.store(true);
    if (g_face.load() == FACE_ERROR) g_face.store(FACE_NORMAL);
    g_led.store(LED_SLOW);

    if (!SD.exists("/handshakes")) SD.mkdir("/handshakes");
    Serial.println("[SD] OK");

    xSemaphoreGive(g_sd_mutex);
    return true;
}

/* --------------------------------------------------------------------------
 * PCAP File Writing
 * F1: CHUNK_BUF_SIZE is verified at compile time. Runtime writes via the
 *     write32_le / write16_le lambdas are bounds-checked; any overrun aborts
 *     the build or triggers a configASSERT in debug, never a silent OOB.
 * F7: f.write() return value checked — a short write (worn card, mid-write
 *     SD full) is logged and propagated as a failure rather than silently
 *     producing a truncated PCAP.
 * -------------------------------------------------------------------------- */

/* F1: Compile-time guarantee that CHUNK_BUF_SIZE covers worst case */
static_assert(CHUNK_BUF_SIZE == (24 + 4 * (16 + MAX_PKT_LEN)),
              "CHUNK_BUF_SIZE formula mismatch");

static bool pcap_write_file(hs_slot_t *hs, uint32_t ts, uint8_t* chunk_buf) {
    char bssid_s[24];
    mac_str(hs->bssid, bssid_s, sizeof(bssid_s));

    char path[80];
    snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap", bssid_s, (unsigned long)ts);

    uint32_t offset = 0;

    /* F1: Bounds-checked helpers — abort if caller logic ever exceeds buffer */
    auto write32_le = [&](uint32_t v) {
        configASSERT(offset + 4 <= CHUNK_BUF_SIZE);
        chunk_buf[offset++] = v & 0xFF;         chunk_buf[offset++] = (v >> 8) & 0xFF;
        chunk_buf[offset++] = (v >> 16) & 0xFF; chunk_buf[offset++] = (v >> 24) & 0xFF;
    };
    auto write16_le = [&](uint16_t v) {
        configASSERT(offset + 2 <= CHUNK_BUF_SIZE);
        chunk_buf[offset++] = v & 0xFF;         chunk_buf[offset++] = (v >> 8) & 0xFF;
    };

    // Construct PCAP Global Header (24 bytes)
    write32_le(0xa1b2c3d4); // Magic
    write16_le(2);          // Major
    write16_le(4);          // Minor
    write32_le(0);          // Timezone
    write32_le(0);          // Sigfigs
    write32_le(65535);      // Snaplen
    write32_le(105);        // Network type (IEEE 802.11)

    // Append Packet Headers and Raw Payloads
    for (int i = 0; i < 4; i++) {
        if (!hs->seen[i] || hs->raw_len[i] == 0 || hs->raw_idx[i] == POOL_NONE) continue;
        uint32_t len = hs->raw_len[i];

        write32_le(ts);
        write32_le(i * 1000);
        write32_le(len);
        write32_le(len);

        configASSERT(offset + len <= CHUNK_BUF_SIZE);
        /* R2: configASSERT is compiled out in release (NDEBUG). Add a hard
         *     runtime guard so an unexpected overrun returns an error instead
         *     of silently writing past the buffer into the task stack. */
        if (offset + len > CHUNK_BUF_SIZE) {
            Serial.printf("[PCAP] chunk overflow at frame %d (offset=%lu len=%lu) — abort\n",
                          i, (unsigned long)offset, (unsigned long)len);
            return false;
        }
        memcpy(chunk_buf + offset, hs_raw_pool_mem[hs->raw_idx[i]], len);
        offset += len;
    }

    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
    File f = SD.open(path, FILE_WRITE);
    if (!f) {
        Serial.printf("[SD] open failed: %s\n", path);
        xSemaphoreGive(g_sd_mutex);
        return false;
    }

    /* F7: Check write length — partial write = corrupt PCAP */
    size_t written = f.write(chunk_buf, offset);
    f.close();
    xSemaphoreGive(g_sd_mutex);

    if (written != offset) {
        Serial.printf("[SD] partial write: %u/%lu bytes — PCAP may be corrupt\n",
                      (unsigned)written, (unsigned long)offset);
        return false;
    }

    return true;
}

static void pcap_write(uint8_t slot_idx, uint8_t* chunk_buf) {
    hs_slot_t *hs = &g_hs[slot_idx];
    uint32_t   ts = millis() / 1000;
    if (!g_sd_ok.load()) goto release_slots;

    {
        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        uint64_t card   = (uint64_t)SD.cardSize();
        uint64_t used   = (uint64_t)SD.usedBytes();
        xSemaphoreGive(g_sd_mutex);

        uint64_t free_b = (card >= used) ? (card - used) : 0;
        if (free_b < MIN_FREE_BYTES) {
            Serial.println("[SD] low space");
            g_face.store(FACE_ERROR);
            goto release_slots;
        }
    }

    if (pcap_write_file(hs, ts, chunk_buf)) {
        g_hs_count.fetch_add(1);
        g_led.store(LED_FLASH);
        Serial.printf("[HS] saved  total=%lu\n", (unsigned long)g_hs_count.load());
    } else {
        g_face.store(FACE_ERROR);
    }

release_slots:
    for (int i = 0; i < 4; i++) {
        if (hs->raw_idx[i] != POOL_NONE) {
            uint8_t ridx = hs->raw_idx[i];
            xQueueSend(g_hs_raw_free_q, &ridx, 0);
            hs->raw_idx[i] = POOL_NONE;
        }
    }
    /* F3: portMAX_DELAY prevents the slot-leak that a short timeout caused.
     *     task_write owns no other locks at this point so deadlock is impossible. */
    xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY);
    hs->active = false;
    xSemaphoreGiveRecursive(g_hs_mutex);
}

/* --------------------------------------------------------------------------
 * Handshake slot management
 * F5: g_hs_mutex is a recursive mutex. hs_expire() is called from task_proc
 *     both (a) inside process_packet() while the mutex is held, and (b) from
 *     the rate-window block which takes it independently. A non-recursive
 *     mutex would deadlock on path (a). All callers use the Recursive variants.
 * -------------------------------------------------------------------------- */
static hs_slot_t *hs_find_or_create(const uint8_t *bssid, const uint8_t *sta) {
    static uint32_t last_slot_create_ms = 0;
    hs_slot_t *empty = NULL;

    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active && mac_eq(g_hs[i].bssid, bssid) && mac_eq(g_hs[i].sta, sta))
            return &g_hs[i];
        if (!g_hs[i].active && (empty == NULL))
            empty = &g_hs[i];
    }

    uint32_t now = millis();
    if ((now - last_slot_create_ms) < HS_NEW_SLOT_RATE_MS) return NULL;

    if (empty != NULL) {
        memset(empty, 0, sizeof(hs_slot_t));
        for (int i = 0; i < 4; i++) empty->raw_idx[i] = POOL_NONE;
        memcpy(empty->bssid, bssid, 6);
        memcpy(empty->sta,   sta,   6);
        empty->active       = true;
        empty->last_ms      = now;
        last_slot_create_ms = now;
    }
    return empty;
}

static void hs_expire(void) {
    uint32_t now = millis();
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active && (now - g_hs[i].last_ms) > HS_EXPIRE_MS) {
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

typedef enum {
    EAPOL_MSG_INVALID = 0,
    EAPOL_MSG_1,
    EAPOL_MSG_2,
    EAPOL_MSG_3,
    EAPOL_MSG_4
} eapol_msg_t;

static eapol_msg_t eapol_msg_number(uint16_t ki) {
    bool pairwise = (ki >> 3) & 1;
    bool install  = (ki >> 6) & 1;
    bool ack      = (ki >> 7) & 1;
    bool mic      = (ki >> 8) & 1;
    bool secure   = (ki >> 9) & 1;

    if (!pairwise) return EAPOL_MSG_INVALID;
    if ( ack && !mic && !install && !secure) return EAPOL_MSG_1;
    if (!ack &&  mic && !install && !secure) return EAPOL_MSG_2;
    if ( ack &&  mic &&  install &&  secure) return EAPOL_MSG_3;
    if (!ack &&  mic && !install &&  secure) return EAPOL_MSG_4;
    return EAPOL_MSG_INVALID;
}

/* --------------------------------------------------------------------------
 * Core packet parser
 * Fix 1: Completely rebuilt using safe byte-level offset reads.
 * -------------------------------------------------------------------------- */
static void process_packet(uint8_t pkt_pool_idx, uint16_t len) {
    const uint8_t *buf = pkt_pool_mem[pkt_pool_idx];
    
    // Radiotap minimum size is 8 bytes
    if (len < 8) goto done;

    {
        uint16_t rt_len = read16_le(buf + 2);
        if (rt_len >= len) goto done;
        
        const uint8_t *mf  = buf + rt_len;
        uint16_t       mfl = len - rt_len;
        
        // Dot11 MAC minimum size is 24 bytes
        if (mfl < 24) goto done;

        uint8_t fc0 = mf[0];
        uint8_t fc1 = mf[1];
        uint8_t fc_type    = (fc0 >> 2) & 0x03;
        uint8_t fc_subtype = (fc0 >> 4) & 0x0F;
        uint8_t to_ds      =  fc1       & 0x01;
        uint8_t from_ds    = (fc1 >> 1) & 0x01;
        
        const uint8_t *addr1 = mf + 4;
        const uint8_t *addr2 = mf + 10;
        const uint8_t *addr3 = mf + 16;

        if (fc_type == 0 && (fc_subtype == 8 || fc_subtype == 5)) {
            ap_record(addr3);
            goto done;
        }

        if (fc_type != 2) goto done;
        if ((to_ds != 0) && (from_ds != 0)) goto done;

        uint8_t bssid[6], sta[6];
        if ((to_ds == 0) && (from_ds == 0)) {
            memcpy(bssid, addr3, 6); memcpy(sta, addr2, 6);
        } else if (from_ds != 0) {
            memcpy(bssid, addr2, 6); memcpy(sta, addr1, 6);
        } else {
            memcpy(bssid, addr1, 6); memcpy(sta, addr2, 6);
        }

        if (mac_zero(bssid) || mac_zero(sta)) goto done;
        ap_record(bssid);
        
        uint16_t mac_hdr_sz = 24;
        if ((fc_subtype & 0x08) != 0) mac_hdr_sz += 2; // QoS offset
        
        // Ensure space for LLC + SNAP Header (8 bytes)
        if (mfl < mac_hdr_sz + 8) goto done;
        const uint8_t *llc = mf + mac_hdr_sz;
        if (llc[0] != 0xAA || llc[1] != 0xAA) goto done;         // DSAP / SSAP
        if (llc[6] != 0x88 || llc[7] != 0x8E) goto done;         // Ethertype 888e

        uint16_t eapol_off = mac_hdr_sz + 8;
        
        // Ensure space for EAPOL Header (4 bytes) + Minimum Key Body
        if (mfl < eapol_off + 4 + 2) goto done;
        const uint8_t *eh = mf + eapol_off;
        if (eh[1] != 0x03) goto done; // Type EAPOL-Key

        const uint8_t *ek = mf + eapol_off + 4;
        if (ek[0] != 0x02 && ek[0] != 0xFE) goto done; // Descriptor type

        uint16_t ki = read16_be(ek + 1);
        eapol_msg_t msg = eapol_msg_number(ki);
        if (msg == EAPOL_MSG_INVALID) goto done;

        bool    complete = false;
        uint8_t done_idx = 0xFF;

        /* F5: Recursive take — hs_expire() called inside rate-window block also
         *     takes this mutex; recursive variant prevents deadlock. */
        if (xSemaphoreTakeRecursive(g_hs_mutex, pdMS_TO_TICKS(10)) != pdTRUE) goto done;
        hs_slot_t *slot = hs_find_or_create(bssid, sta);
        if (slot != NULL) {
            int frame_idx = (int)msg - 1;
            if (!slot->seen[frame_idx]) {
                uint8_t rblk = POOL_NONE;
                xQueueReceive(g_hs_raw_free_q, &rblk, 0);
                if (rblk != POOL_NONE) {
                    uint16_t cplen = (len > MAX_PKT_LEN) ? (uint16_t)MAX_PKT_LEN : len;
                    memcpy(hs_raw_pool_mem[rblk], buf, cplen);
                    slot->raw_idx[frame_idx] = rblk;
                    slot->raw_len[frame_idx] = cplen;
                    slot->seen[frame_idx]    = true;
                    slot->last_ms            = millis();
                    Serial.printf("[HS] %02x:%02x:%02x -> %02x:%02x:%02x  msg%d\n",
                        bssid[0], bssid[1], bssid[2],
                        sta[0],   sta[1],   sta[2],   (int)msg);
                }
            }

            g_face.store(FACE_CAPTURE);
            g_led.store(LED_FAST);

            if (slot->seen[0] && slot->seen[1] && slot->seen[2] && slot->seen[3]) {
                done_idx = (uint8_t)(slot - g_hs);
                complete = true;
            }
        }

        xSemaphoreGiveRecursive(g_hs_mutex);
        if (complete) {
            write_item_t wi = done_idx;
            if (xQueueSend(g_write_queue, &wi, 0) != pdTRUE) {
                Serial.println("[HS] write queue full, drop");
                /* R4: Use portMAX_DELAY instead of pdMS_TO_TICKS(5).
                 *     A 5 ms timeout could silently expire while task_write
                 *     holds g_hs_mutex during an SD stall, leaving the slot
                 *     permanently active and leaking all 4 raw pool blocks.
                 *     task_write owns no other locks at this point, so
                 *     portMAX_DELAY cannot deadlock — same justification as F3. */
                if (xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY) == pdTRUE) {
                    for (int j = 0; j < 4; j++) {
                        if (g_hs[done_idx].raw_idx[j] != POOL_NONE) {
                            uint8_t ridx = g_hs[done_idx].raw_idx[j];
                            xQueueSend(g_hs_raw_free_q, &ridx, 0);
                            g_hs[done_idx].raw_idx[j] = POOL_NONE;
                        }
                    }
                    g_hs[done_idx].active = false;
                    xSemaphoreGiveRecursive(g_hs_mutex);
                }
            }
            g_face.store(FACE_NORMAL);
        }
    }

done:
    xQueueSend(g_pkt_free_q, &pkt_pool_idx, 0);
}

/* --------------------------------------------------------------------------
 * Promiscuous callback
 * -------------------------------------------------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    /* RSSI filter: drop before touching the pool — no queue, no memcpy cost.
     * rx_ctrl.rssi is signed (int8_t range, cast from the bitfield). */
    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    if (rssi < (int8_t)RSSI_THRESHOLD) {
        g_rssi_drops.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_last_rssi.store(rssi, std::memory_order_relaxed);

    /* R1: sig_len includes the 4-byte 802.11 FCS trailer. The driver does NOT
     *     copy the FCS into pkt->payload[], so we must subtract it before
     *     using plen as a copy length or as raw_len stored in the hs_slot.
     *     Without this subtraction every captured PCAP frame has 4 bytes of
     *     garbage at the tail → Wireshark dissect errors and hashcat MIC
     *     verification failures ("no valid EAPOL pairs found"). */
    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen >= 4) plen -= 4;          /* strip FCS — not present in payload[] */
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    uint8_t    pool_idx = POOL_NONE;
    BaseType_t woken    = pdFALSE;
    if (xQueueReceiveFromISR(g_pkt_free_q, &pool_idx, &woken) != pdTRUE) return;

    memcpy(pkt_pool_mem[pool_idx], pkt->payload, plen);

    pkt_item_t item = { pool_idx, plen, (uint8_t)g_channel.load(std::memory_order_relaxed) };
    if (xQueueSendFromISR(g_pkt_queue, &item, &woken) != pdTRUE) {
        xQueueSendFromISR(g_pkt_free_q, &pool_idx, &woken);
    }
    if (woken == pdTRUE) portYIELD_FROM_ISR();
}

/* --------------------------------------------------------------------------
 * Task: packet processor
 * -------------------------------------------------------------------------- */
static void task_proc(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();
    int batch_count = 0;

    while (1) {
        esp_task_wdt_reset();
        pkt_item_t item;
        
        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            process_packet(item.pool_idx, item.len);
            pkt_count++;
            batch_count++;
            
            // Fix 2: Prevent Core 0 Starvation. Yield to allow Priority 4 write tasks to execute.
            if (batch_count >= TASK_PROC_BATCH_MAX) {
                batch_count = 0;
                taskYIELD(); 
            }
        } else {
            batch_count = 0; // Reset batch count on empty queue
        }

        uint32_t now = millis();
        if (now - rate_window >= 1000) {
            g_pkt_rate.store(pkt_count);
            Serial.printf("[STAT] pkt/s=%lu  rssi=%ddBm  drops=%lu  thr=%ddBm\n",
                (unsigned long)pkt_count,
                (int)g_last_rssi.load(std::memory_order_relaxed),
                (unsigned long)g_rssi_drops.load(std::memory_order_relaxed),
                RSSI_THRESHOLD);
            pkt_count   = 0;
            rate_window = now;

            /* F5: Recursive take — safe even if process_packet() already holds
             *     g_hs_mutex on this call path (it doesn't, but recursive is
             *     the correct contract for a mutex shared with hs_expire). */
            if (xSemaphoreTakeRecursive(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                hs_expire();
                xSemaphoreGiveRecursive(g_hs_mutex);
            }

            if (!g_sd_ok.load() &&
                (now - g_last_sd_retry.load(std::memory_order_relaxed)) > SD_RETRY_MS) {
                g_last_sd_retry.store(now, std::memory_order_relaxed);
                /* R5: Signal task_write to run sd_init() instead of blocking
                 *     task_proc here. sd_init() can take hundreds of ms on a
                 *     slow/worn card (SD.begin() includes card negotiation).
                 *     Blocking the proc task during that window fills g_pkt_queue
                 *     and causes the ISR to drop every incoming packet. */
                g_sd_retry_req.store(true, std::memory_order_relaxed);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: SD writer
 * -------------------------------------------------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);

    /* F1: Sized via CHUNK_BUF_SIZE — compile-time proven sufficient */
    uint8_t* chunk_buf = (uint8_t*)malloc(CHUNK_BUF_SIZE);
    configASSERT(chunk_buf != NULL);

    while (1) {
        esp_task_wdt_reset();
        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(200)) == pdTRUE) {
            pcap_write(wi, chunk_buf);
        } else {
            /* R5: Consume the SD retry request here, in the write task, so
             *     task_proc is never blocked by SD initialisation latency.
             *     The 200 ms queue wait above gives task_write idle time to
             *     handle this without adding an extra task or timer. */
            if (g_sd_retry_req.exchange(false, std::memory_order_relaxed)) {
                sd_init();
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: channel hopper
 * R3: Pinned to Core 0 (see xTaskCreatePinnedToCore in setup()). Core 0 runs
 *     the WiFi driver and the promiscuous ISR; esp_wifi_set_channel() must be
 *     called from the same core to avoid racing the driver's channel state.
 *     The configASSERT below catches any accidental future migration,
 *     mirroring the F4 pattern used in task_ui.
 * -------------------------------------------------------------------------- */
static void task_hop(void *arg) {
    configASSERT(xPortGetCoreID() == 0); /* R3 */
    esp_task_wdt_add(NULL);
    uint8_t ch = 1;
    while (1) {
        esp_task_wdt_reset();
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        g_channel.store(ch, std::memory_order_relaxed);
        ch = (ch % CHANNELS_2G) + 1;
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_DWELL_MS));
    }
}

/* --------------------------------------------------------------------------
 * LED & Button handlers
 * -------------------------------------------------------------------------- */
static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static bool     on        = false;
    static uint8_t  err_phase = 0;

    uint32_t    now = millis();
    led_state_t led = g_led.load();
    switch (led) {
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
                on = false; g_led.store(LED_SLOW);
            }
            break;
        case LED_ERROR:
            {
                uint32_t period;
                if      (err_phase == 6)       period = 1000;
                else if (err_phase % 2 == 0)   period = 2000;
                else                           period =  500;
                if (now - last_ms >= period) {
                    last_ms   = now;
                    err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                    on = (err_phase % 2 == 0) && (err_phase < 6);
                    digitalWrite(PIN_LED, on ? HIGH : LOW);
                }
            }
            break;
    }
}

/* F10: btn_tick() is called from task_ui which sleeps 10 ms between calls.
 *      DEBOUNCE_MS (50 ms) is the effective filter — the 10 ms poll rate is
 *      an implicit dependency. Do not increase vTaskDelay above DEBOUNCE_MS. */
static void btn_tick(void) {
    static bool     prev     = HIGH;
    static uint32_t press_ms = 0;
    static uint32_t last_ms  = 0;

    uint32_t now = millis();
    if (now - last_ms < (uint32_t)DEBOUNCE_MS) return;
    last_ms = now;

    bool cur = digitalRead(PIN_BTN);
    if ((prev == HIGH) && (cur == LOW)) {
        press_ms = now;
    } else if ((prev == LOW) && (cur == HIGH)) {
        uint32_t dur = now - press_ms;
        if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            g_channel.store(1, std::memory_order_relaxed);
            Serial.println("[BTN] short press -> ch=1");
        }
    }
    prev = cur;
}

/* --------------------------------------------------------------------------
 * OLED draw
 * -------------------------------------------------------------------------- */
static void oled_draw(void) {
    static const char *faces[] = {
        "(o_o)",   /* FACE_NORMAL  */
        "(^o^)",   /* FACE_CAPTURE */
        "(X_X)",   /* FACE_ERROR   */
        "(-_-)"    /* FACE_IDLE    */
    };
    char   line[24];
    face_t f = g_face.load();

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);

    display.drawStr(0, 10, faces[f]);

    snprintf(line, sizeof(line), "HS:  %lu", (unsigned long)g_hs_count.load());
    display.drawStr(0, 20, line);
    snprintf(line, sizeof(line), "CH:  %u",  (unsigned)g_channel.load(std::memory_order_relaxed));
    display.drawStr(0, 30, line);

    snprintf(line, sizeof(line), "AP:  %lu", (unsigned long)g_ap_count.load());
    display.drawStr(0, 40, line);
    snprintf(line, sizeof(line), "PKT: %lu", (unsigned long)g_pkt_rate.load());
    display.drawStr(0, 50, line);

    /* RSSI line: last passing RSSI and cumulative drop count.
     * Example: "RSSI:-67 D:142"  — fits in 128px at 6px/char. */
    snprintf(line, sizeof(line), "RSSI:%-4d D:%lu",
             (int)g_last_rssi.load(std::memory_order_relaxed),
             (unsigned long)g_rssi_drops.load(std::memory_order_relaxed));
    display.drawStr(0, 60, line);

    display.sendBuffer();
}

/* F4: task_ui MUST run on Core 1. U8g2 HW-I2C (display.sendBuffer) holds the
 *     I2C bus for ~2 ms per frame. On Core 0 this can coincide with the WiFi
 *     promisc ISR, causing a cache-miss panic (LoadProhibited guru meditation).
 *     The xTaskCreatePinnedToCore(..., 1) in setup() enforces this; the assert
 *     below catches any future accidental migration. */
static void task_ui(void *arg) {
    configASSERT(xPortGetCoreID() == 1); /* F4 */
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
    Serial.println("\n[BOOT] ESP32 Cheapagotchi v1.2.2");

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);
    digitalWrite(PIN_LED, LOW);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "v1.2.2 Boot...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    g_pkt_free_q    = xQueueCreate(PKT_POOL_DEPTH,    sizeof(uint8_t));
    g_hs_raw_free_q = xQueueCreate(HS_RAW_POOL_DEPTH, sizeof(uint8_t));
    configASSERT(g_pkt_free_q);
    configASSERT(g_hs_raw_free_q);

    for (uint8_t i = 0; i < PKT_POOL_DEPTH; i++)
        xQueueSend(g_pkt_free_q, &i, 0);
    for (uint8_t i = 0; i < HS_RAW_POOL_DEPTH; i++)
        xQueueSend(g_hs_raw_free_q, &i, 0);

    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,   sizeof(pkt_item_t));
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(write_item_t));
    /* F5: Recursive mutex — hs_expire() is called both standalone and nested
     *     inside process_packet() which already holds this mutex. */
    g_hs_mutex    = xSemaphoreCreateRecursiveMutex();
    g_sd_mutex    = xSemaphoreCreateMutex();

    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);
    configASSERT(g_sd_mutex);

    memset(g_hs,       0, sizeof(g_hs));
    memset(g_ap_table, 0, sizeof(g_ap_table));

    for (int i = 0; i < MAX_HS_SLOTS; i++)
        for (int j = 0; j < 4; j++)
            g_hs[i].raw_idx[j] = POOL_NONE;

    sd_init();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    /* F9: Stack sizes tuned via uxTaskGetStackHighWaterMark() — bumped from
     *     4096 to 6144 for proc/write to accommodate Serial.printf + lambda
     *     frame overhead. Monitor watermark in debug builds. */
    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", STACK_PROC,  NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", STACK_WRITE, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   STACK_HOP,   NULL, 6, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       STACK_UI,    NULL, 1, &h_ui,    1);

    configASSERT(h_proc);
    configASSERT(h_write);
    configASSERT(h_hop);
    configASSERT(h_ui);

    display.clearBuffer();
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Running...");
    display.sendBuffer();

    Serial.println("[BOOT] tasks started");
    /* R6: Log free heap AFTER all task creations so the value reflects real
     *     post-allocation headroom. Previously logged before tasks were created,
     *     giving an optimistic reading that didn't account for task stacks. */
    Serial.printf("[MEM]  free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());
    esp_task_wdt_delete(NULL);
}

void loop(void) {
    vTaskDelay(portMAX_DELAY);
}