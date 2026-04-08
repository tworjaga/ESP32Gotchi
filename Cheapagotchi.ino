/*
 * ESP32 Cheapagotchi — WPA/WPA2 Handshake Sniffer
 * Project: ESP32Gotchi | github: tworjaga | telegram: @al7exy
 *
 * Target  : ESP32 Dev Module (ESP32-WROOM-32, 30-pin)
 * Core    : esp32 by Espressif 2.0.x+
 * Libraries: U8g2
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

/* --------------------------------------------------------------------------
 * Pin map
 * Note: GPIO5/SD-CS requires pull-ups >= 10 kOhm to avoid boot issues.
 * -------------------------------------------------------------------------- */
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

static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* --------------------------------------------------------------------------
 * Packed structures
 * -------------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint8_t  revision;
    uint8_t  pad;
    uint8_t  len_lo;
    uint8_t  len_hi;
    uint32_t present;
} radiotap_hdr_t;

typedef struct {
    uint8_t  fc0;
    uint8_t  fc1;
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
    uint8_t type;
    uint8_t len_hi;
    uint8_t len_lo;
} eapol_hdr_t;

typedef struct {
    uint8_t  descriptor;
    uint8_t  ki_hi;
    uint8_t  ki_lo;
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
    uint32_t magic;
    uint16_t ver_major;
    uint16_t ver_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkt_hdr_t;

#pragma pack(pop)

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

/* --------------------------------------------------------------------------
 * Handshake slot management
 * -------------------------------------------------------------------------- */
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
 * AP hash table (256-bucket open-addressing)
 * -------------------------------------------------------------------------- */
#define AP_TABLE_MASK     (MAX_UNIQUE_APS - 1)
#define AP_TABLE_MAX_LOAD 192

static uint8_t           g_ap_table[MAX_UNIQUE_APS][6];
static volatile uint32_t g_ap_count = 0;

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */
static QueueHandle_t     g_pkt_queue;
static QueueHandle_t     g_write_queue;
static SemaphoreHandle_t g_hs_mutex;

static hs_slot_t g_hs[MAX_HS_SLOTS];
static volatile uint32_t g_hs_count      = 0;
static volatile uint32_t g_pkt_rate      = 0;
static volatile uint8_t  g_channel       = 1;
static volatile bool     g_sd_ok         = false;
static volatile uint32_t g_last_sd_retry = 0;

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
    for (int i = 0; i < 6; i++) if (a[i] != 0) return false;
    return true;
}

static void mac_str(const uint8_t *m, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%02x_%02x_%02x_%02x_%02x_%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* --------------------------------------------------------------------------
 * AP hash table operations
 * -------------------------------------------------------------------------- */
static uint8_t mac_hash(const uint8_t *mac) {
    uint32_t h = 5381;
    for (int i = 0; i < 6; i++) h = ((h << 5) + h) ^ mac[i];
    return (uint8_t)(h & AP_TABLE_MASK);
}

static void ap_record(const uint8_t *bssid) {
    if (mac_zero(bssid)) return;
    if (g_ap_count >= AP_TABLE_MAX_LOAD) return;

    uint8_t idx = mac_hash(bssid);
    for (uint32_t i = 0; i < MAX_UNIQUE_APS; i++) {
        uint8_t slot = (idx + i) & AP_TABLE_MASK;
        if (mac_zero(g_ap_table[slot])) {
            memcpy(g_ap_table[slot], bssid, 6);
            g_ap_count++;
            return;
        }
        if (mac_eq(g_ap_table[slot], bssid)) return;
    }
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

static bool pcap_write_file(hs_slot_t *hs, uint32_t ts) {
    char bssid_s[24];
    mac_str(hs->bssid, bssid_s, sizeof(bssid_s));

    char path[80];
    snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap",
             bssid_s, (unsigned long)ts);
    File f = SD.open(path, FILE_WRITE);
    if (!f) {
        Serial.printf("[SD] open failed: %s\n", path);
        return false;
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
        ph.ts_sec   = ts;
        ph.ts_usec  = (uint32_t)i * 1000;
        ph.incl_len = hs->raw_len[i];
        ph.orig_len = hs->raw_len[i];
        f.write((const uint8_t *)&ph, sizeof(ph));
        f.write(hs_raw_pool_mem[hs->raw_idx[i]], hs->raw_len[i]);
    }

    f.close();
    return true;
}

static void pcap_write(uint8_t slot_idx) {
    hs_slot_t *hs = &g_hs[slot_idx];
    uint32_t   ts = millis() / 1000;
    if (!g_sd_ok) goto release_slots;

    {
        uint64_t card   = (uint64_t)SD.cardSize();
        uint64_t used   = (uint64_t)SD.usedBytes();
        uint64_t free_b = (card >= used) ? (card - used) : 0;
        if (free_b < MIN_FREE_BYTES) {
            Serial.println("[SD] low space");
            g_face = FACE_ERROR;
            goto release_slots;
        }
    }

    if (pcap_write_file(hs, ts)) {
        g_hs_count++;
        g_led = LED_FLASH;
        Serial.printf("[HS] saved  total=%lu\n", (unsigned long)g_hs_count);
    } else {
        g_face = FACE_ERROR;
    }

release_slots:
    for (int i = 0; i < 4; i++) {
        if (hs->raw_idx[i] != POOL_NONE) {
            uint8_t ridx = hs->raw_idx[i];
            xQueueSend(g_hs_raw_free_q, &ridx, 0);
            hs->raw_idx[i] = POOL_NONE;
        }
    }
    if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        hs->active = false;
        xSemaphoreGive(g_hs_mutex);
    }
}

/* --------------------------------------------------------------------------
 * Handshake slot helper
 * -------------------------------------------------------------------------- */
static hs_slot_t *hs_find_or_create(const uint8_t *bssid, const uint8_t *sta) {
    static uint32_t last_slot_create_ms = 0;

    hs_slot_t *empty = NULL;
    for (int i = 0; i < MAX_HS_SLOTS; i++) {
        if (g_hs[i].active &&
            mac_eq(g_hs[i].bssid, bssid) &&
            mac_eq(g_hs[i].sta,   sta))
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

/* --------------------------------------------------------------------------
 * EAPOL message classifier
 *
 * IEEE 802.11-2020 §12.7.2 key_info bit positions:
 * bit 3  Key Type (1 = pairwise)   bit 6  Install
 * bit 7  Key ACK                   bit 8  Key MIC
 * bit 9  Secure
 * -------------------------------------------------------------------------- */
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
 * -------------------------------------------------------------------------- */
static void process_packet(uint8_t pkt_pool_idx, uint16_t len) {
    const uint8_t *buf = pkt_pool_mem[pkt_pool_idx];
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
        if ((to_ds != 0) && (from_ds != 0)) goto done;

        uint8_t bssid[6], sta[6];
        if ((to_ds == 0) && (from_ds == 0)) {
            memcpy(bssid, dh->addr3, 6);
            memcpy(sta,   dh->addr2, 6);
        } else if (from_ds != 0) {
            memcpy(bssid, dh->addr2, 6);
            memcpy(sta,   dh->addr1, 6);
        } else {
            memcpy(bssid, dh->addr1, 6);
            memcpy(sta,   dh->addr2, 6);
        }

        if (mac_zero(bssid) || mac_zero(sta)) goto done;
        ap_record(bssid);
        uint16_t mac_hdr_sz = (uint16_t)sizeof(dot11_hdr_t);
        if ((fc_subtype & 0x08) != 0) mac_hdr_sz += 2;
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
        uint16_t    ki  = ((uint16_t)ek->ki_hi << 8) | ek->ki_lo;
        eapol_msg_t msg = eapol_msg_number(ki);
        if (msg == EAPOL_MSG_INVALID) goto done;
        bool    complete = false;
        uint8_t done_idx = 0xFF;

        if (xSemaphoreTake(g_hs_mutex, pdMS_TO_TICKS(10)) != pdTRUE) goto done;
        hs_slot_t *slot = hs_find_or_create(bssid, sta);
        if (slot != NULL) {
            int frame_idx = (int)msg - 1;
            if (!slot->seen[frame_idx]) {
                uint8_t rblk = POOL_NONE;
                xQueueReceive(g_hs_raw_free_q, &rblk, 0);
                if (rblk != POOL_NONE) {
                    uint16_t cplen = (len > MAX_PKT_LEN) ?
                                     (uint16_t)MAX_PKT_LEN : len;
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

            g_face = FACE_CAPTURE;
            g_led  = LED_FAST;

            if (slot->seen[0] && slot->seen[1] && slot->seen[2] && slot->seen[3]) {
                done_idx = (uint8_t)(slot - g_hs);
                complete = true;
            }
        }

        xSemaphoreGive(g_hs_mutex);
        if (complete) {
            write_item_t wi = done_idx;
            if (xQueueSend(g_write_queue, &wi, 0) != pdTRUE) {
                Serial.println("[HS] write queue full, drop");
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
    xQueueSend(g_pkt_free_q, &pkt_pool_idx, 0);
}

/* --------------------------------------------------------------------------
 * Promiscuous callback
 * -------------------------------------------------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen == 0 || plen > MAX_PKT_LEN) return;
    uint8_t    pool_idx = POOL_NONE;
    BaseType_t woken    = pdFALSE;
    if (xQueueReceiveFromISR(g_pkt_free_q, &pool_idx, &woken) != pdTRUE) return;

    memcpy(pkt_pool_mem[pool_idx], pkt->payload, plen);

    pkt_item_t item = { pool_idx, plen, g_channel };
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
 * Task: SD writer
 * -------------------------------------------------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);
    while (1) {
        esp_task_wdt_reset();
        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(200)) == pdTRUE)
            pcap_write(wi);
    }
}

/* --------------------------------------------------------------------------
 * Task: channel hopper
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
 * LED state machine
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

/* --------------------------------------------------------------------------
 * Button handler
 * -------------------------------------------------------------------------- */
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
            g_channel = 1;
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
 * Task: UI
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
    Serial.println("\n[BOOT] ESP32 Cheapagotchi");

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);
    digitalWrite(PIN_LED, LOW);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Booting...");
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
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH,  sizeof(write_item_t));
    g_hs_mutex    = xSemaphoreCreateMutex();

    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);

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
     * Task priority layout:
     * task_hop   6 — guarantees 200 ms dwell regardless of packet load
     * task_proc  5 — packet parsing
     * task_write 4 — SD flush
     * task_ui    1 — Core 1, independent of Core 0
     */
    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", 4096, NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", 4096, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   2048, NULL, 6, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       4096, NULL, 1, &h_ui,    1);

    configASSERT(h_proc);
    configASSERT(h_write);
    configASSERT(h_hop);
    configASSERT(h_ui);

    display.clearBuffer();
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "Running...");
    display.sendBuffer();

    Serial.println("[BOOT] tasks started");
    Serial.printf("[MEM]  free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());
    esp_task_wdt_delete(NULL);
}

/* --------------------------------------------------------------------------
 * loop()
 * -------------------------------------------------------------------------- */
void loop(void) {
    vTaskDelay(portMAX_DELAY);
}