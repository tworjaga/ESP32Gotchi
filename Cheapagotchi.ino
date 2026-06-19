/*
 * ESP32 Cheapagotchi — WiFi AP Scanner & Monitor  (v1.2.2)
 * Project: ESP32Gotchi | github: tworjaga | telegram: @al7exy
 *
 * Target  : ESP32 Dev Module (ESP32-WROOM-32, 30-pin)
 * Core    : esp32 by Espressif 2.0.x+
 * Libraries: U8g2 (Library Manager); SD, SPI, WiFi, esp_wifi, FreeRTOS bundled with core
 *
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
#include <atomic>
#include <freertos/portmacro.h>
#include <esp_sleep.h>
#include <driver/adc.h>

/* --------------------------------------------------------------------------
 * Pin definitions
 * -------------------------------------------------------------------------- */
#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        4
#define PIN_LED        2
#define PIN_GPS_RX    16   /* N1: UART2 RX — connect to Neo-6M TX */
#define PIN_GPS_TX    17   /* N1: UART2 TX — connect to Neo-6M RX */
#define PIN_BATT_ADC  34   /* N7: ADC1_CH6 — voltage divider midpoint */

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
#define LONG_PRESS_MS       3000   /* N5: short=page cycle, long=restart */
#define SLEEP_PRESS_MS      6000   /* N8: extra-long press → deep sleep   */
#define SD_RETRY_MS        10000
#define MIN_FREE_BYTES     (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S         30
#define CHANNELS_2G           11
#define MAX_PKT_LEN         1600
#define HS_EXPIRE_MS       15000
#define HS_NEW_SLOT_RATE_MS  100
#define TASK_PROC_BATCH_MAX   15

/* N1: GPS */
#define GPS_BAUD            9600
#define GPS_FIX_TIMEOUT_MS 60000   /* give up waiting for first fix after 60 s */
#define GPS_STALE_MS       10000  /* invalidate fix if stale longer than this */
#define GPS_SENTENCE_LEN     128   /* max NMEA sentence buffer                  */

/* N2: AP log queue */
#define AP_LOG_QUEUE_DEPTH    16

/* N3/N4: CSV paths and rotation threshold */
#define APLOG_PATH          "/aplog/aps.csv"
#define APLOG_ROTATE_PATH   "/aplog/aps_1.csv"
#define STATS_PATH          "/stats/stats.csv"
#define STATS_ROTATE_PATH   "/stats/stats_1.csv"
#define CSV_ROTATE_BYTES    (4UL * 1024UL * 1024UL)   /* 4 MB */
#define STATS_INTERVAL_MS   60000UL

/* N7: Battery ADC */
#define BATT_SAMPLES          16
#define BATT_UPDATE_MS      30000
#define BATT_VREF_MV         3300   /* ESP32 Vref mV */
#define BATT_ADC_MAX         4095
#define BATT_DIVIDER            2   /* 100k / 100k divider: Vadc = Vbat/2 */
#define BATT_MAX_MV          4200   /* 100% */
#define BATT_MIN_MV          3500   /*   0% */

/* RSSI filter */
#define RSSI_THRESHOLD        (-80)

/* F1: PCAP chunk buffer = global header (24) + 4 × (record header 16 + payload) */
#define CHUNK_BUF_SIZE  (24 + 4 * (16 + MAX_PKT_LEN))

/* F9: Stack sizes — values are BYTES (ESP32 Arduino/FreeRTOS port's
 * xTaskCreatePinnedToCore stack-depth argument is bytes here, not words) */
#define STACK_PROC   6144
#define STACK_WRITE  6144
#define STACK_HOP    2048
#define STACK_UI     4096
#define STACK_GPS    3072   /* N1 */

/* F11 */
static_assert(PKT_POOL_DEPTH    < 0xFF, "PKT_POOL_DEPTH too large: POOL_NONE sentinel invalid");
static_assert(HS_RAW_POOL_DEPTH < 0xFF, "HS_RAW_POOL_DEPTH too large: POOL_NONE sentinel invalid");

static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* --------------------------------------------------------------------------
 * Fix 1: Byte-safe Memory Extraction Macros
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
    bool     queued;   /* true once handed to g_write_queue; blocks hs_expire() reclaim */
    uint32_t last_ms;
} hs_slot_t;

/* --------------------------------------------------------------------------
 * N2: AP log queue item — sent from promisc_cb to task_write
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
} ap_log_item_t;

static QueueHandle_t g_ap_log_queue;   /* N2 */

/* --------------------------------------------------------------------------
 * N1: GPS fix data — updated by task_gps, read by task_ui and task_write.
 *     Protected by g_gps_mutex (not atomic — struct is too large).
 * -------------------------------------------------------------------------- */
typedef struct {
    float    lat;          /* degrees, positive = N */
    float    lon;          /* degrees, positive = E */
    float    alt_m;        /* metres above MSL */
    float    hdop;
    uint8_t  sats;
    bool     valid;        /* true = at least one valid fix received */
    /* Soft RTC — UTC from GPS */
    uint16_t year;
    uint8_t  month, day;
    uint8_t  hour, minute, second;
    bool     time_set;     /* true once GPS time has been received */
    uint32_t last_fix_ms;  /* MEDIUM fix: millis() of last good 'A' status fix, for staleness */
} gps_fix_t;

static gps_fix_t     g_gps;
static SemaphoreHandle_t g_gps_mutex;
static std::atomic<bool> g_gps_available{false};   /* UART opened OK */
static std::atomic<bool> g_gps_fix{false};         /* valid fix received */

/* --------------------------------------------------------------------------
 * AP hash table
 * F2: g_ap_table protected by a portMUX spinlock
 * -------------------------------------------------------------------------- */
#define AP_TABLE_MASK     (MAX_UNIQUE_APS - 1)
#define AP_TABLE_MAX_LOAD 192

static uint8_t      g_ap_table[MAX_UNIQUE_APS][6];
static portMUX_TYPE g_ap_mux = portMUX_INITIALIZER_UNLOCKED;

/* True cross-core atomics */
static std::atomic<uint32_t> g_ap_count{0};
static std::atomic<uint32_t> g_hs_count{0};
static std::atomic<uint32_t> g_pkt_rate{0};
static std::atomic<bool>     g_sd_ok{false};
static std::atomic<int8_t>   g_last_rssi{0};
static std::atomic<uint32_t> g_rssi_drops{0};
static std::atomic<uint32_t> g_ap_log_drops{0};   /* MEDIUM fix: ap_log queue full */
static std::atomic<uint32_t> g_hs_pool_drops{0};  /* MEDIUM fix: hs raw-frame pool exhausted */
static std::atomic<bool>     g_sd_retry_req{false};   /* R5 */

/* N5: display page (0=Stats 1=GPS 2=SD 3=System) */
static std::atomic<uint8_t>  g_display_page{0};

/* N7: battery percentage 0–100 */
static std::atomic<uint8_t>  g_batt_pct{0};

/* N8: deep sleep request flag set in btn_tick, consumed in task_ui */
static std::atomic<bool>     g_sleep_req{false};

/* N3: last write status for SD page */
static std::atomic<bool>     g_last_write_ok{true};

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */
static QueueHandle_t     g_pkt_queue;
static QueueHandle_t     g_write_queue;
static SemaphoreHandle_t g_hs_mutex;
static SemaphoreHandle_t g_sd_mutex;

static hs_slot_t g_hs[MAX_HS_SLOTS];

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
static TaskHandle_t h_gps;   /* N1 */

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
static void mac_str_colon(const uint8_t *m, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* LOW fix: real Murmur3 fmix32 — two rounds, two constants — for better
 * avalanche than a single round, reducing AP-table collision clustering. */
static uint8_t mac_hash(const uint8_t *mac) {
    uint32_t h;
    uint32_t k0 = (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) |
                  ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
    uint32_t k1 = (uint32_t)mac[4] | ((uint32_t)mac[5] << 8);
    h  = k0 ^ k1;
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return (uint8_t)(h & AP_TABLE_MASK);
}

/* --------------------------------------------------------------------------
 * N1: Timestamp helper — returns ISO-8601 string from GPS soft RTC,
 *     or millis()-based uptime string if no GPS time available.
 * -------------------------------------------------------------------------- */
static void timestamp_str(char *out, size_t out_sz) {
    if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        if (g_gps.time_set) {
            snprintf(out, out_sz, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                     g_gps.year, g_gps.month, g_gps.day,
                     g_gps.hour, g_gps.minute, g_gps.second);
            xSemaphoreGive(g_gps_mutex);
            return;
        }
        xSemaphoreGive(g_gps_mutex);
    }
    /* Fallback: uptime */
    uint32_t s = millis() / 1000;
    snprintf(out, out_sz, "UP+%05lus", (unsigned long)s);
}

/* --------------------------------------------------------------------------
 * F2: AP hash table — ISR-safe via portMUX spinlock
 * Returns true if this is a NEW bssid (first time seen).
 * -------------------------------------------------------------------------- */
static bool ap_record(const uint8_t *bssid) {
    if (mac_zero(bssid)) return false;
    if (g_ap_count.load(std::memory_order_relaxed) >= AP_TABLE_MAX_LOAD) return false;

    uint8_t idx = mac_hash(bssid);
    bool    is_new = false;

    portENTER_CRITICAL(&g_ap_mux);
    for (uint32_t i = 0; i < MAX_UNIQUE_APS; i++) {
        uint8_t slot = (idx + i) & AP_TABLE_MASK;
        if (mac_zero(g_ap_table[slot])) {
            memcpy(g_ap_table[slot], bssid, 6);
            g_ap_count.fetch_add(1, std::memory_order_relaxed);
            is_new = true;
            break;
        }
        if (mac_eq(g_ap_table[slot], bssid)) {
            break;
        }
    }
    portEXIT_CRITICAL(&g_ap_mux);
    return is_new;
}

/* --------------------------------------------------------------------------
 * SD
 * F12: SPI.begin() called once only.
 * F13: WDT fires on SD stall → intentional reboot.
 * -------------------------------------------------------------------------- */
static bool sd_init(void) {
    static bool spi_started = false;

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
    if (!SD.exists("/aplog"))      SD.mkdir("/aplog");    /* N2 */
    if (!SD.exists("/stats"))      SD.mkdir("/stats");    /* N3 */
    Serial.println("[SD] OK");

    xSemaphoreGive(g_sd_mutex);
    return true;
}

/* --------------------------------------------------------------------------
 * N4: Log rotation helper
 *     Called from task_write (which already holds g_sd_mutex context via
 *     the surrounding write helpers). Caller must NOT hold g_sd_mutex —
 *     this function takes it internally.
 * -------------------------------------------------------------------------- */
static void check_rotate(const char *path, const char *rotated_path, uint32_t max_bytes) {
    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
    if (SD.exists(path)) {
        File f = SD.open(path, FILE_READ);
        if (f) {
            uint32_t sz = f.size();
            f.close();
            if (sz >= max_bytes) {
                if (SD.exists(rotated_path)) SD.remove(rotated_path);
                SD.rename(path, rotated_path);
                Serial.printf("[ROT] %s → %s\n", path, rotated_path);
            }
        }
    }
    xSemaphoreGive(g_sd_mutex);
}

/* --------------------------------------------------------------------------
 * N2: Append one AP row to /aplog/aps.csv
 *     Called from task_write only — SD access is safe here.
 * -------------------------------------------------------------------------- */
static void aplog_write(const ap_log_item_t *item) {
    check_rotate(APLOG_PATH, APLOG_ROTATE_PATH, CSV_ROTATE_BYTES);

    char ts[32];
    timestamp_str(ts, sizeof(ts));

    char mac[20];
    mac_str_colon(item->bssid, mac, sizeof(mac));

    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);

    bool write_header = !SD.exists(APLOG_PATH);
    File f = SD.open(APLOG_PATH, FILE_APPEND);
    if (!f) {
        Serial.println("[APLOG] open failed");
        xSemaphoreGive(g_sd_mutex);
        return;
    }
    if (write_header) {
        f.println("timestamp,bssid,rssi_dbm,channel");
    }
    char row[80];
    snprintf(row, sizeof(row), "%s,%s,%d,%u", ts, mac, (int)item->rssi, (unsigned)item->channel);
    f.println(row);
    f.close();

    xSemaphoreGive(g_sd_mutex);
}

/* --------------------------------------------------------------------------
 * N3: Append one stats row to /stats/stats.csv
 *     Called from task_write only.
 * -------------------------------------------------------------------------- */
static void stats_write(void) {
    check_rotate(STATS_PATH, STATS_ROTATE_PATH, CSV_ROTATE_BYTES);

    char ts[32];
    timestamp_str(ts, sizeof(ts));

    float lat = 0.0f, lon = 0.0f;
    bool  fix = false;
    if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        lat = g_gps.lat;
        lon = g_gps.lon;
        fix = g_gps.valid;
        xSemaphoreGive(g_gps_mutex);
    }

    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);

    bool write_header = !SD.exists(STATS_PATH);
    File f = SD.open(STATS_PATH, FILE_APPEND);
    if (!f) {
        Serial.println("[STATS] open failed");
        xSemaphoreGive(g_sd_mutex);
        return;
    }
    if (write_header) {
        f.println("timestamp,ap_count,pkt_rate,free_heap,rssi_last,rssi_drops,gps_lat,gps_lon,gps_fix");
    }
    char row[128];
    snprintf(row, sizeof(row),
             "%s,%lu,%lu,%lu,%d,%lu,%.6f,%.6f,%u",
             ts,
             (unsigned long)g_ap_count.load(),
             (unsigned long)g_pkt_rate.load(),
             (unsigned long)ESP.getFreeHeap(),
             (int)g_last_rssi.load(std::memory_order_relaxed),
             (unsigned long)g_rssi_drops.load(std::memory_order_relaxed),
             (double)lat, (double)lon,
             (unsigned)fix);
    f.println(row);
    f.close();

    xSemaphoreGive(g_sd_mutex);
}

/* --------------------------------------------------------------------------
 * PCAP File Writing (timestamp uses GPS soft RTC when available)
 * -------------------------------------------------------------------------- */
static_assert(CHUNK_BUF_SIZE == (24 + 4 * (16 + MAX_PKT_LEN)),
              "CHUNK_BUF_SIZE formula mismatch");

static bool pcap_write_file(hs_slot_t *hs, uint32_t ts, uint8_t *chunk_buf) {
    char bssid_s[24];
    mac_str(hs->bssid, bssid_s, sizeof(bssid_s));

    char path[80];
    snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap", bssid_s, (unsigned long)ts);

    uint32_t offset = 0;

    auto write32_le = [&](uint32_t v) {
        configASSERT(offset + 4 <= CHUNK_BUF_SIZE);
        chunk_buf[offset++] = v & 0xFF;         chunk_buf[offset++] = (v >> 8) & 0xFF;
        chunk_buf[offset++] = (v >> 16) & 0xFF; chunk_buf[offset++] = (v >> 24) & 0xFF;
    };
    auto write16_le = [&](uint16_t v) {
        configASSERT(offset + 2 <= CHUNK_BUF_SIZE);
        chunk_buf[offset++] = v & 0xFF;         chunk_buf[offset++] = (v >> 8) & 0xFF;
    };

    write32_le(0xa1b2c3d4);
    write16_le(2); write16_le(4);
    write32_le(0); write32_le(0);
    write32_le(65535);
    write32_le(105);

    for (int i = 0; i < 4; i++) {
        if (!hs->seen[i] || hs->raw_len[i] == 0 || hs->raw_idx[i] == POOL_NONE) continue;
        uint32_t len = hs->raw_len[i];

        write32_le(ts);
        write32_le(i * 1000);
        write32_le(len);
        write32_le(len);

        if (offset + len > CHUNK_BUF_SIZE) {
            Serial.printf("[PCAP] chunk overflow at frame %d — abort\n", i);
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
    size_t written = f.write(chunk_buf, offset);
    f.close();
    xSemaphoreGive(g_sd_mutex);

    if (written != offset) {
        Serial.printf("[SD] partial write: %u/%lu bytes\n",
                      (unsigned)written, (unsigned long)offset);
        return false;
    }
    return true;
}

static void pcap_write(uint8_t slot_idx, uint8_t *chunk_buf) {
    hs_slot_t *hs = &g_hs[slot_idx];
    uint32_t   ts = millis() / 1000;
    if (!g_sd_ok.load()) goto release_slots;

    {
        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        uint64_t card = (uint64_t)SD.cardSize();
        uint64_t used = (uint64_t)SD.usedBytes();
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
        g_last_write_ok.store(true);
        Serial.printf("[HS] saved  total=%lu\n", (unsigned long)g_hs_count.load());
    } else {
        g_face.store(FACE_ERROR);
        g_last_write_ok.store(false);
    }

release_slots:
    for (int i = 0; i < 4; i++) {
        if (hs->raw_idx[i] != POOL_NONE) {
            uint8_t ridx = hs->raw_idx[i];
            xQueueSend(g_hs_raw_free_q, &ridx, 0);
            hs->raw_idx[i] = POOL_NONE;
        }
    }
    xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY);
    hs->active = false;
    hs->queued = false;
    xSemaphoreGiveRecursive(g_hs_mutex);
}

/* --------------------------------------------------------------------------
 * Handshake slot management (unchanged)
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
        if (g_hs[i].active && !g_hs[i].queued && (now - g_hs[i].last_ms) > HS_EXPIRE_MS) {
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
    EAPOL_MSG_1, EAPOL_MSG_2, EAPOL_MSG_3, EAPOL_MSG_4
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
 * Core packet parser (unchanged logic; ap_record now returns bool for N2)
 * -------------------------------------------------------------------------- */
static void process_packet(uint8_t pkt_pool_idx, uint16_t len) {
    const uint8_t *buf = pkt_pool_mem[pkt_pool_idx];

    if (len < 8) goto done;

    {
        /* No radiotap header — buf starts directly at 802.11 Frame Control */
        const uint8_t *mf  = buf;
        uint16_t       mfl = len;

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
        if ((fc_subtype & 0x08) != 0) mac_hdr_sz += 2;

        if (mfl < mac_hdr_sz + 8) goto done;
        const uint8_t *llc = mf + mac_hdr_sz;
        if (llc[0] != 0xAA || llc[1] != 0xAA) goto done;
        if (llc[6] != 0x88 || llc[7] != 0x8E) goto done;

        uint16_t eapol_off = mac_hdr_sz + 8;
        if (mfl < eapol_off + 4 + 2) goto done;
        const uint8_t *eh = mf + eapol_off;
        if (eh[1] != 0x03) goto done;

        const uint8_t *ek = mf + eapol_off + 4;
        if (ek[0] != 0x02 && ek[0] != 0xFE) goto done;

        uint16_t    ki  = read16_be(ek + 1);
        eapol_msg_t msg = eapol_msg_number(ki);
        if (msg == EAPOL_MSG_INVALID) goto done;

        bool    complete = false;
        uint8_t done_idx = 0xFF;

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
                        sta[0],   sta[1],   sta[2], (int)msg);
                } else {
                    g_hs_pool_drops.fetch_add(1, std::memory_order_relaxed);
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
            if (xQueueSend(g_write_queue, &wi, 0) == pdTRUE) {
                if (xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY) == pdTRUE) {
                    g_hs[done_idx].queued = true;
                    xSemaphoreGiveRecursive(g_hs_mutex);
                }
            } else {
                Serial.println("[HS] write queue full, drop");
                if (xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY) == pdTRUE) {
                    for (int j = 0; j < 4; j++) {
                        if (g_hs[done_idx].raw_idx[j] != POOL_NONE) {
                            uint8_t ridx = g_hs[done_idx].raw_idx[j];
                            xQueueSend(g_hs_raw_free_q, &ridx, 0);
                            g_hs[done_idx].raw_idx[j] = POOL_NONE;
                        }
                    }
                    g_hs[done_idx].active = false;
                    g_hs[done_idx].queued = false;
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
 * N2: After ap_record returns true (new BSSID), enqueue to g_ap_log_queue.
 * -------------------------------------------------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    if (rssi < (int8_t)RSSI_THRESHOLD) {
        g_rssi_drops.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_last_rssi.store(rssi, std::memory_order_relaxed);

    /* R1: strip 4-byte FCS */
    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen >= 4) plen -= 4;
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    /* N2: extract BSSID from management frames for AP log (addr3 in beacon/probe) */
    if (type == WIFI_PKT_MGMT && plen >= 24) {
        const uint8_t *mf = pkt->payload;   /* no radiotap header — mf is the 802.11 frame */
        {
            uint8_t fc_subtype = (mf[0] >> 4) & 0x0F;
            if (fc_subtype == 8 || fc_subtype == 5) {   /* Beacon or Probe Response */
                const uint8_t *bssid = mf + 16;
                BaseType_t woken = pdFALSE;
                if (ap_record(bssid)) {   /* ISR-safe (spinlock); log if new */
                    ap_log_item_t item;
                    memcpy(item.bssid, bssid, 6);
                    item.rssi    = rssi;
                    item.channel = (uint8_t)g_channel.load(std::memory_order_relaxed);
                    if (xQueueSendFromISR(g_ap_log_queue, &item, &woken) != pdTRUE) {
                        g_ap_log_drops.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (woken == pdTRUE) portYIELD_FROM_ISR();
                }
            }
        }
    }

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
 * Task: packet processor (unchanged)
 * -------------------------------------------------------------------------- */
static void task_proc(void *arg) {
    esp_task_wdt_add(NULL);
    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();
    int      batch_count = 0;

    while (1) {
        esp_task_wdt_reset();
        pkt_item_t item;

        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            process_packet(item.pool_idx, item.len);
            pkt_count++;
            batch_count++;
            if (batch_count >= TASK_PROC_BATCH_MAX) {
                batch_count = 0;
                taskYIELD();
            }
        } else {
            batch_count = 0;
        }

        uint32_t now = millis();
        if (now - rate_window >= 1000) {
            g_pkt_rate.store(pkt_count);
            Serial.printf("[STAT] pkt/s=%lu  rssi=%ddBm  drops=%lu  thr=%ddBm  ap_log_drops=%lu  hs_pool_drops=%lu\n",
                (unsigned long)pkt_count,
                (int)g_last_rssi.load(std::memory_order_relaxed),
                (unsigned long)g_rssi_drops.load(std::memory_order_relaxed),
                RSSI_THRESHOLD,
                (unsigned long)g_ap_log_drops.load(std::memory_order_relaxed),
                (unsigned long)g_hs_pool_drops.load(std::memory_order_relaxed));
            pkt_count   = 0;
            rate_window = now;

            if (xSemaphoreTakeRecursive(g_hs_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                hs_expire();
                xSemaphoreGiveRecursive(g_hs_mutex);
            }

            if (!g_sd_ok.load() &&
                (now - g_last_sd_retry.load(std::memory_order_relaxed)) > SD_RETRY_MS) {
                g_last_sd_retry.store(now, std::memory_order_relaxed);
                g_sd_retry_req.store(true, std::memory_order_relaxed);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: SD writer
 * N2: Drains g_ap_log_queue in the idle branch.
 * N3: Writes stats row every STATS_INTERVAL_MS.
 * -------------------------------------------------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);

    uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK_BUF_SIZE);
    configASSERT(chunk_buf != NULL);

    uint32_t last_stats_ms = millis();

    while (1) {
        esp_task_wdt_reset();

        /* Primary: flush handshake write queue */
        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(50)) == pdTRUE) {
            pcap_write(wi, chunk_buf);
        }

        /* N2: drain AP log queue (one item per loop iteration — non-blocking) */
        ap_log_item_t ap_item;
        if (xQueueReceive(g_ap_log_queue, &ap_item, 0) == pdTRUE) {
            if (g_sd_ok.load()) aplog_write(&ap_item);
        }

        /* N3: stats log every 60 s */
        uint32_t now = millis();
        if (now - last_stats_ms >= STATS_INTERVAL_MS) {
            last_stats_ms = now;
            if (g_sd_ok.load()) stats_write();
        }

        /* R5: SD retry request */
        if (g_sd_retry_req.exchange(false, std::memory_order_relaxed)) {
            sd_init();
        }
    }
}

/* --------------------------------------------------------------------------
 * Task: channel hopper (unchanged)
 * R3: Pinned to Core 0.
 * -------------------------------------------------------------------------- */
static void task_hop(void *arg) {
    configASSERT(xPortGetCoreID() == 0);
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
 * N1: GPS task — parses NMEA on UART2
 *     Pinned to Core 1 (I2C-safe, no WiFi driver overlap).
 *     Stack: STACK_GPS (3072 words). Priority 2.
 *     Only dynamic alloc: 128-byte sentence buffer (malloc here, freed never).
 * -------------------------------------------------------------------------- */

/* Minimal NMEA helpers — no external library needed */
static float nmea_to_degrees(const char *val, char hemi) {
    /* val format: DDDMM.MMMM or DDMM.MMMM */
    if (!val || val[0] == '\0') return 0.0f;
    float raw  = atof(val);
    int   deg  = (int)(raw / 100);
    float mins = raw - deg * 100.0f;
    float result = deg + mins / 60.0f;
    if (hemi == 'S' || hemi == 'W') result = -result;
    return result;
}

/* MEDIUM fix: verify NMEA checksum so RF noise / bad solder joints can't
 * latch in bogus coordinates/time. sentence must start with '$' and contain
 * a '*' followed by two hex digits (the original, unmodified line). */
static bool nmea_checksum_ok(const char *sentence) {
    if (!sentence || sentence[0] != '$') return false;
    const char *star = strrchr(sentence, '*');
    if (!star || strlen(star) < 3) return false;
    uint8_t calc = 0;
    for (const char *p = sentence + 1; p < star; p++) calc ^= (uint8_t)*p;
    char hex[3] = { star[1], star[2], '\0' };
    uint8_t given = (uint8_t)strtol(hex, NULL, 16);
    return calc == given;
}

/* Split comma-separated NMEA sentence into tokens in-place.
 * Returns number of tokens found (max_tok limit). */
static int nmea_split(char *sentence, char **toks, int max_tok) {
    int n = 0;
    char *p = sentence;
    while (n < max_tok) {
        toks[n++] = p;
        p = strchr(p, ',');
        if (!p) break;
        *p++ = '\0';
    }
    return n;
}

static void task_gps(void *arg) {
    /* N1: single malloc for sentence accumulation buffer */
    char *sbuf = (char *)malloc(GPS_SENTENCE_LEN);
    configASSERT(sbuf != NULL);
    int spos = 0;

    Serial2.begin(GPS_BAUD, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);
    g_gps_available.store(true);

    uint32_t boot_ms    = millis();
    bool     fix_warned = false;

    while (1) {
        /* Read available bytes from UART2 */
        while (Serial2.available()) {
            char c = (char)Serial2.read();
            if (c == '\r') continue;
            if (c == '\n' || spos >= GPS_SENTENCE_LEN - 1) {
                sbuf[spos] = '\0';

                /* Only process $GPRMC and $GPGGA */
                if (strncmp(sbuf, "$GPRMC", 6) == 0 ||
                    strncmp(sbuf, "$GPGGA", 6) == 0) {

                    /* MEDIUM fix: verify checksum on the original (unmodified)
                     * line before trusting any field in it. */
                    bool csum_ok = nmea_checksum_ok(sbuf);

                    /* Strip checksum (*XX) before splitting */
                    char *star = strrchr(sbuf, '*');
                    if (star) *star = '\0';

                    char *toks[16] = {0};
                    char  tmp[GPS_SENTENCE_LEN];
                    strncpy(tmp, sbuf, GPS_SENTENCE_LEN - 1);
                    tmp[GPS_SENTENCE_LEN - 1] = '\0';
                    int n = csum_ok ? nmea_split(tmp, toks, 16) : 0;

                    if (csum_ok && xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {

                        if (strncmp(sbuf, "$GPRMC", 6) == 0 && n >= 10) {
                            /* $GPRMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,x.x,x.x,ddmmyy,... */
                            bool active = (toks[2] && toks[2][0] == 'A');
                            if (active) {
                                g_gps.lat   = nmea_to_degrees(toks[3], toks[4] ? toks[4][0] : 'N');
                                g_gps.lon   = nmea_to_degrees(toks[5], toks[6] ? toks[6][0] : 'E');
                                g_gps.valid = true;
                                g_gps.last_fix_ms = millis();
                                g_gps_fix.store(true);
                                /* Parse UTC time: hhmmss */
                                if (toks[1] && strlen(toks[1]) >= 6) {
                                    char t[3] = {0};
                                    t[0]=toks[1][0]; t[1]=toks[1][1]; g_gps.hour   = atoi(t);
                                    t[0]=toks[1][2]; t[1]=toks[1][3]; g_gps.minute = atoi(t);
                                    t[0]=toks[1][4]; t[1]=toks[1][5]; g_gps.second = atoi(t);
                                }
                                /* Parse date: ddmmyy */
                                if (toks[9] && strlen(toks[9]) >= 6) {
                                    char d[3] = {0};
                                    d[0]=toks[9][0]; d[1]=toks[9][1]; g_gps.day   = atoi(d);
                                    d[0]=toks[9][2]; d[1]=toks[9][3]; g_gps.month = atoi(d);
                                    d[0]=toks[9][4]; d[1]=toks[9][5]; g_gps.year  = 2000 + atoi(d);
                                    g_gps.time_set = true;
                                }
                            } else {
                                /* MEDIUM fix: status 'V' (void) — fix is no longer
                                 * trustworthy; stop reporting FIX:YES / stale coords. */
                                g_gps.valid = false;
                                g_gps_fix.store(false);
                            }
                        }

                        else if (strncmp(sbuf, "$GPGGA", 6) == 0 && n >= 10) {
                            /* $GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,... */
                            int fix_q = toks[6] ? atoi(toks[6]) : 0;
                            if (fix_q > 0) {
                                g_gps.sats  = toks[7] ? (uint8_t)atoi(toks[7]) : 0;
                                g_gps.hdop  = toks[8] ? atof(toks[8]) : 99.9f;
                                g_gps.alt_m = toks[9] ? atof(toks[9]) : 0.0f;
                            }
                        }

                        xSemaphoreGive(g_gps_mutex);
                    }
                }
                spos = 0;
            } else {
                sbuf[spos++] = c;
            }
        }

        /* MEDIUM fix: if the last good fix is older than GPS_STALE_MS,
         * downgrade valid/fix so the UI/CSV stop reporting a frozen,
         * indefinitely-stale position and timestamp. */
        if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            if (g_gps.valid && (millis() - g_gps.last_fix_ms) > GPS_STALE_MS) {
                g_gps.valid = false;
                g_gps_fix.store(false);
            }
            xSemaphoreGive(g_gps_mutex);
        }

        /* N1: warn once if no fix after GPS_FIX_TIMEOUT_MS */
        if (!fix_warned && !g_gps_fix.load() &&
            (millis() - boot_ms) > GPS_FIX_TIMEOUT_MS) {
            fix_warned = true;
            Serial.println("[GPS] no fix within 60 s — continuing without fix");
        }

        vTaskDelay(pdMS_TO_TICKS(20));
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
            if (now - last_ms >= 500) { on = !on; digitalWrite(PIN_LED, on); last_ms = now; }
            break;
        case LED_FAST:
            if (now - last_ms >= 100) { on = !on; digitalWrite(PIN_LED, on); last_ms = now; }
            break;
        case LED_FLASH:
            if (!on) { digitalWrite(PIN_LED, HIGH); on = true; last_ms = now; }
            else if (now - last_ms >= 120) { digitalWrite(PIN_LED, LOW); on = false; g_led.store(LED_SLOW); }
            break;
        case LED_ERROR: {
            uint32_t period;
            if      (err_phase == 6)       period = 1000;
            else if (err_phase % 2 == 0)   period = 2000;
            else                           period =  500;
            if (now - last_ms >= period) {
                last_ms   = now;
                err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                on = (err_phase % 2 == 0) && (err_phase < 6);
                digitalWrite(PIN_LED, on);
            }
            break;
        }
    }
}

/* F10: btn_tick polled at 10 ms from task_ui. DEBOUNCE_MS=50 is the filter.
 * N5:  Short press cycles display page (0→1→2→3→0).
 * N5:  Long press (≥3 s) = restart.
 * N8:  Extra-long press (≥6 s) = set g_sleep_req. */
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
        if (dur >= (uint32_t)SLEEP_PRESS_MS) {
            /* N8: deep sleep */
            g_sleep_req.store(true);
        } else if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            /* N5: cycle display page */
            uint8_t p = g_display_page.load();
            g_display_page.store((p + 1) % 4);
            Serial.printf("[BTN] page -> %u\n", (unsigned)g_display_page.load());
        }
    }
    prev = cur;
}

/* --------------------------------------------------------------------------
 * N7: Battery ADC — 16-sample average, returns percentage 0–100
 * -------------------------------------------------------------------------- */
static uint8_t batt_read_pct(void) {
    uint32_t sum = 0;
    for (int i = 0; i < BATT_SAMPLES; i++) {
        sum += analogRead(PIN_BATT_ADC);
        delayMicroseconds(200);
    }
    uint32_t avg = sum / BATT_SAMPLES;
    /* Convert ADC → mV at divider midpoint */
    uint32_t vadc_mv = (avg * BATT_VREF_MV) / BATT_ADC_MAX;
    /* Reconstruct Vbat (×2 for divider) */
    uint32_t vbat_mv = vadc_mv * BATT_DIVIDER;
    /* Clamp and map to 0–100% */
    if (vbat_mv >= BATT_MAX_MV) return 100;
    if (vbat_mv <= BATT_MIN_MV) return 0;
    return (uint8_t)(((vbat_mv - BATT_MIN_MV) * 100UL) / (BATT_MAX_MV - BATT_MIN_MV));
}

/* --------------------------------------------------------------------------
 * N5: OLED draw — 4 pages
 * -------------------------------------------------------------------------- */
static void oled_draw(void) {
    static const char *faces[] = {
        "(o_o)",   /* FACE_NORMAL  */
        "(^o^)",   /* FACE_CAPTURE */
        "(X_X)",   /* FACE_ERROR   */
        "(-_-)"    /* FACE_IDLE    */
    };
    char   line[24];
    face_t f    = g_face.load();
    uint8_t page = g_display_page.load();

    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 10, faces[f]);

    switch (page) {

        /* ── Page 0: Stats (original layout + page indicator) ── */
        case 0:
            snprintf(line, sizeof(line), "HS:  %lu", (unsigned long)g_hs_count.load());
            display.drawStr(0, 20, line);
            snprintf(line, sizeof(line), "CH:  %u",  (unsigned)g_channel.load(std::memory_order_relaxed));
            display.drawStr(0, 30, line);
            snprintf(line, sizeof(line), "AP:  %lu", (unsigned long)g_ap_count.load());
            display.drawStr(0, 40, line);
            snprintf(line, sizeof(line), "PKT: %lu", (unsigned long)g_pkt_rate.load());
            display.drawStr(0, 50, line);
            snprintf(line, sizeof(line), "RSSI:%-4d D:%lu",
                     (int)g_last_rssi.load(std::memory_order_relaxed),
                     (unsigned long)g_rssi_drops.load(std::memory_order_relaxed));
            display.drawStr(0, 60, line);
            display.drawStr(110, 10, "1/4");
            break;

        /* ── Page 1: GPS ── */
        case 1: {
            display.drawStr(110, 10, "2/4");
            bool fix = g_gps_fix.load();
            bool avail = g_gps_available.load();
            if (!avail) {
                display.drawStr(0, 30, "GPS: N/A");
                break;
            }
            snprintf(line, sizeof(line), "FIX: %s", fix ? "YES" : "NO");
            display.drawStr(0, 20, line);
            if (fix && xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                snprintf(line, sizeof(line), "LAT:%.5f", (double)g_gps.lat);
                display.drawStr(0, 30, line);
                snprintf(line, sizeof(line), "LON:%.5f", (double)g_gps.lon);
                display.drawStr(0, 40, line);
                snprintf(line, sizeof(line), "ALT:%.0fm", (double)g_gps.alt_m);
                display.drawStr(0, 50, line);
                snprintf(line, sizeof(line), "SAT:%u HDOP:%.1f", g_gps.sats, (double)g_gps.hdop);
                display.drawStr(0, 60, line);
                xSemaphoreGive(g_gps_mutex);
            } else if (!fix) {
                display.drawStr(0, 35, "Waiting for fix..");
            }
            break;
        }

        /* ── Page 2: SD ── */
        case 2: {
            display.drawStr(110, 10, "3/4");
            bool sd = g_sd_ok.load();
            snprintf(line, sizeof(line), "SD:  %s", sd ? "OK" : "ERR");
            display.drawStr(0, 20, line);
            if (sd) {
                uint64_t card = 0, used = 0;
                if (xSemaphoreTake(g_sd_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                    card = SD.cardSize();
                    used = SD.usedBytes();
                    xSemaphoreGive(g_sd_mutex);
                }
                uint32_t free_mb = (uint32_t)((card >= used ? card - used : 0) / (1024ULL * 1024ULL));
                snprintf(line, sizeof(line), "FREE:%luMB", (unsigned long)free_mb);
                display.drawStr(0, 30, line);

                /* Show aps.csv and stats.csv sizes */
                uint32_t ap_kb = 0, st_kb = 0;
                if (xSemaphoreTake(g_sd_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
                    if (SD.exists(APLOG_PATH)) {
                        File f = SD.open(APLOG_PATH, FILE_READ);
                        if (f) { ap_kb = f.size() / 1024; f.close(); }
                    }
                    if (SD.exists(STATS_PATH)) {
                        File f = SD.open(STATS_PATH, FILE_READ);
                        if (f) { st_kb = f.size() / 1024; f.close(); }
                    }
                    xSemaphoreGive(g_sd_mutex);
                }

                snprintf(line, sizeof(line), "APS: %luKB", (unsigned long)ap_kb);
                display.drawStr(0, 40, line);
                snprintf(line, sizeof(line), "STS: %luKB", (unsigned long)st_kb);
                display.drawStr(0, 50, line);
            }
            snprintf(line, sizeof(line), "WR:  %s", g_last_write_ok.load() ? "OK" : "ERR");
            display.drawStr(0, 60, line);
            break;
        }

        /* ── Page 3: System ── */
        case 3: {
            display.drawStr(110, 10, "4/4");
            snprintf(line, sizeof(line), "HEAP:%luB", (unsigned long)ESP.getFreeHeap());
            display.drawStr(0, 20, line);
            uint32_t up_s = millis() / 1000;
            snprintf(line, sizeof(line), "UP: %02lu:%02lu:%02lu",
                     (unsigned long)(up_s / 3600),
                     (unsigned long)((up_s % 3600) / 60),
                     (unsigned long)(up_s % 60));
            display.drawStr(0, 30, line);
            snprintf(line, sizeof(line), "PKT: %lu/s", (unsigned long)g_pkt_rate.load());
            display.drawStr(0, 40, line);
            snprintf(line, sizeof(line), "DRP: %lu", (unsigned long)g_rssi_drops.load(std::memory_order_relaxed));
            display.drawStr(0, 50, line);
            snprintf(line, sizeof(line), "BAT: %u%%", (unsigned)g_batt_pct.load());
            display.drawStr(0, 60, line);
            break;
        }
    }

    display.sendBuffer();
}

/* --------------------------------------------------------------------------
 * N8: Deep sleep sequence — called from task_ui when g_sleep_req is set.
 *     Flushes write queue (max 2 s), shows OLED message, sleeps.
 * -------------------------------------------------------------------------- */
static void do_deep_sleep(void) {
    Serial.println("[SLEEP] entering deep sleep");

    /* Show sleep message on OLED */
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(20, 30, "SLEEP ZZZ");
    display.drawStr(10, 45, "Hold BTN to wake");
    display.sendBuffer();

    /* Disable promiscuous mode to stop ISR activity */
    esp_wifi_set_promiscuous(false);

    /* Wait for write queue to drain (max 2 s) */
    uint32_t flush_start = millis();
    while (uxQueueMessagesWaiting(g_write_queue) > 0 &&
           (millis() - flush_start) < 2000) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    /* LOW fix: suspend task_write before tearing down SD so it can't attempt
     * a fresh SD.open() in the window before esp_deep_sleep_start(). */
    if (h_write != NULL) vTaskSuspend(h_write);

    /* Cleanly unmount SD */
    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
    SD.end();
    xSemaphoreGive(g_sd_mutex);

    vTaskDelay(pdMS_TO_TICKS(1000));   /* Let OLED message display */

    /* N8: wake on button GPIO4 LOW (EXT0) */
    esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_BTN, 0);
    esp_deep_sleep_start();
    /* Never returns */
}

/* F4: task_ui pinned to Core 1.
 * N5: cycles pages on short press.
 * N7: reads battery every BATT_UPDATE_MS.
 * N8: handles deep sleep request.
 */
static void task_ui(void *arg) {
    configASSERT(xPortGetCoreID() == 1);
    esp_task_wdt_add(NULL);

    uint32_t last_oled = 0;
    uint32_t last_batt = 0;

    /* Initial battery reading */
    g_batt_pct.store(batt_read_pct());

    while (1) {
        esp_task_wdt_reset();
        uint32_t now = millis();

        /* N8: check sleep request first */
        if (g_sleep_req.load()) {
            g_sleep_req.store(false);
            do_deep_sleep();
            /* unreachable */
        }

        btn_tick();
        led_tick();

        /* N7: update battery every 30 s */
        if (now - last_batt >= BATT_UPDATE_MS) {
            g_batt_pct.store(batt_read_pct());
            last_batt = now;
        }

        if (now - last_oled >= 200) {
            oled_draw();
            last_oled = now;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* --------------------------------------------------------------------------
 * N6: Startup self-test — runs before tasks are created.
 *     Shows each subsystem result on OLED for ~600 ms.
 * -------------------------------------------------------------------------- */
static void selftest(bool sd_ok, bool gps_uart_ok, bool wifi_ok) {
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 10, "Self-test v1.2.2");
    display.sendBuffer();
    delay(300);

    /* SD */
    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v1.2.2");
    char line[24];
    snprintf(line, sizeof(line), "SD:   %s", sd_ok ? "OK" : "FAIL");
    display.drawStr(0, 22, line);
    if (sd_ok) {
        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        uint64_t card = SD.cardSize();
        uint64_t used = SD.usedBytes();
        xSemaphoreGive(g_sd_mutex);
        uint32_t free_mb = (uint32_t)((card >= used ? card - used : 0) / (1024ULL * 1024ULL));
        snprintf(line, sizeof(line), "  free: %luMB", (unsigned long)free_mb);
        display.drawStr(0, 32, line);
    }
    display.sendBuffer();
    delay(600);

    /* GPS UART */
    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v1.2.2");
    snprintf(line, sizeof(line), "GPS:  %s", gps_uart_ok ? "UART OK" : "N/A");
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    /* Heap */
    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v1.2.2");
    snprintf(line, sizeof(line), "HEAP: %luB", (unsigned long)ESP.getFreeHeap());
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    /* WiFi promiscuous */
    display.clearBuffer();
    display.drawStr(0, 10, "Self-test v1.2.2");
    snprintf(line, sizeof(line), "WIFI: %s", wifi_ok ? "OK" : "FAIL");
    display.drawStr(0, 22, line);
    display.sendBuffer();
    delay(600);

    /* Ready */
    display.clearBuffer();
    display.drawStr(20, 25, "Cheapagotchi");
    display.drawStr(25, 40, "v1.2.2 Ready");
    display.sendBuffer();
    delay(1000);
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

    /* N7: configure ADC for battery pin */
    analogSetAttenuation(ADC_11db);
    analogReadResolution(12);
    pinMode(PIN_BATT_ADC, INPUT);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Cheapagotchi");
    display.drawStr(0, 34, "v1.2.2 Boot...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    /* Create synchronisation primitives */
    g_pkt_free_q    = xQueueCreate(PKT_POOL_DEPTH,    sizeof(uint8_t));
    g_hs_raw_free_q = xQueueCreate(HS_RAW_POOL_DEPTH, sizeof(uint8_t));
    g_ap_log_queue  = xQueueCreate(AP_LOG_QUEUE_DEPTH, sizeof(ap_log_item_t));  /* N2 */
    configASSERT(g_pkt_free_q);
    configASSERT(g_hs_raw_free_q);
    configASSERT(g_ap_log_queue);

    for (uint8_t i = 0; i < PKT_POOL_DEPTH; i++)
        xQueueSend(g_pkt_free_q, &i, 0);
    for (uint8_t i = 0; i < HS_RAW_POOL_DEPTH; i++)
        xQueueSend(g_hs_raw_free_q, &i, 0);

    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,   sizeof(pkt_item_t));
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(write_item_t));
    g_hs_mutex    = xSemaphoreCreateRecursiveMutex();
    g_sd_mutex    = xSemaphoreCreateMutex();
    g_gps_mutex   = xSemaphoreCreateMutex();   /* N1 */
    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);
    configASSERT(g_hs_mutex);
    configASSERT(g_sd_mutex);
    configASSERT(g_gps_mutex);

    memset(g_hs,       0, sizeof(g_hs));
    memset(g_ap_table, 0, sizeof(g_ap_table));
    memset(&g_gps,     0, sizeof(g_gps));   /* N1 */

    for (int i = 0; i < MAX_HS_SLOTS; i++)
        for (int j = 0; j < 4; j++)
            g_hs[i].raw_idx[j] = POOL_NONE;

    /* SD init */
    bool sd_ok = sd_init();

    /* N1: Open GPS UART2 for self-test check (task_gps will use it after) */
    Serial2.begin(GPS_BAUD, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);
    bool gps_uart_ok = true;   /* Serial2.begin() has no return status */
    g_gps_available.store(gps_uart_ok);
    Serial2.end();   /* task_gps will re-open it */

    /* WiFi init */
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    bool wifi_ok = (esp_wifi_set_promiscuous(true) == ESP_OK);
    if (!wifi_ok) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    /* N6: Self-test screen */
    selftest(sd_ok, gps_uart_ok, wifi_ok);

    /* Create tasks */
    xTaskCreatePinnedToCore(task_proc,  "pkt_proc", STACK_PROC,  NULL, 5, &h_proc,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", STACK_WRITE, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_hop,   "ch_hop",   STACK_HOP,   NULL, 6, &h_hop,   0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       STACK_UI,    NULL, 1, &h_ui,    1);
    xTaskCreatePinnedToCore(task_gps,   "gps",      STACK_GPS,   NULL, 2, &h_gps,   1);  /* N1 */

    configASSERT(h_proc);
    configASSERT(h_write);
    configASSERT(h_hop);
    configASSERT(h_ui);
    configASSERT(h_gps);

    /* R6: Log free heap after all task creations */
    Serial.printf("[MEM]  free heap: %lu bytes\n", (unsigned long)ESP.getFreeHeap());

    esp_task_wdt_delete(NULL);
}

void loop(void) {
    vTaskDelay(portMAX_DELAY);
}
