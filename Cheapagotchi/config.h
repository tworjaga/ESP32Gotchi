// Compile-time configuration: pins, tuning, paths, version.
#pragma once

#define FW_VERSION "1.2.2"

#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        4
#define PIN_LED        2
#define PIN_GPS_RX    16
#define PIN_GPS_TX    17
#define PIN_BATT_ADC  34

// PKT_POOL_DEPTH + HS_RAW_POOL_DEPTH slots of MAX_PKT_LEN bytes dominate static
// RAM; keep at 20, not 32 — at 32/32 the image overflows ESP32 internal DRAM and won't link.
#define PKT_POOL_DEPTH        20
#define HS_RAW_POOL_DEPTH     20
#define PKT_QUEUE_DEPTH       32
#define WRITE_QUEUE_DEPTH      8
#define MAX_HS_SLOTS          16
#define MAX_UNIQUE_APS       256
#define CHANNEL_DWELL_MS     200
#define DEBOUNCE_MS           50
#define LONG_PRESS_MS       3000
#define SLEEP_PRESS_MS      6000
#define SD_RETRY_MS        10000
#define MIN_FREE_BYTES     (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S         30
#define CHANNELS_2G           11
#define MAX_PKT_LEN         1600
#define HS_EXPIRE_MS       15000
#define HS_NEW_SLOT_RATE_MS  100
#define TASK_PROC_BATCH_MAX   15

#define AP_TABLE_MASK     (MAX_UNIQUE_APS - 1)
#define AP_TABLE_MAX_LOAD 192

#define GPS_BAUD            9600
#define GPS_FIX_TIMEOUT_MS 60000
#define GPS_STALE_MS       10000
#define GPS_SENTENCE_LEN     128

#define AP_LOG_QUEUE_DEPTH    16

#define APLOG_PATH          "/aplog/aps.csv"
#define APLOG_ROTATE_PATH   "/aplog/aps_1.csv"
#define STATS_PATH          "/stats/stats.csv"
#define STATS_ROTATE_PATH   "/stats/stats_1.csv"
#define CSV_ROTATE_BYTES    (4UL * 1024UL * 1024UL)
#define STATS_INTERVAL_MS   60000UL

#define BATT_SAMPLES          16
#define BATT_UPDATE_MS      30000
#define BATT_VREF_MV         3300
#define BATT_ADC_MAX         4095
#define BATT_DIVIDER            2
#define BATT_MAX_MV          4200
#define BATT_MIN_MV          3500

#define RSSI_THRESHOLD        (-80)

#define CHUNK_BUF_SIZE  (24 + 4 * (16 + MAX_PKT_LEN))

// Stack sizes in BYTES (ESP32 Arduino port's xTaskCreatePinnedToCore arg).
#define STACK_PROC   6144
#define STACK_WRITE  6144
#define STACK_HOP    2048
#define STACK_UI     4096
#define STACK_GPS    3072
