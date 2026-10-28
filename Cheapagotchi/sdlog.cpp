// SD mount, CSV logging (AP log + stats, with rotation), and the SD writer task.
#include "sdlog.h"
#include "state.h"
#include "gps.h"
#include "pcap.h"
#include "util.h"

#include <Arduino.h>
#include <SD.h>
#include <SPI.h>
#include <esp_task_wdt.h>

bool sd_init(void) {
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
    if (!SD.exists("/aplog"))      SD.mkdir("/aplog");
    if (!SD.exists("/stats"))      SD.mkdir("/stats");
    Serial.println("[SD] OK");

    xSemaphoreGive(g_sd_mutex);
    return true;
}

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

void task_write(void *arg) {
    esp_task_wdt_add(NULL);

    uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK_BUF_SIZE);
    configASSERT(chunk_buf != NULL);

    uint32_t last_stats_ms = millis();

    while (1) {
        esp_task_wdt_reset();

        write_item_t wi;
        if (xQueueReceive(g_write_queue, &wi, pdMS_TO_TICKS(50)) == pdTRUE) {
            pcap_write(wi, chunk_buf);
        }

        ap_log_item_t ap_item;
        if (xQueueReceive(g_ap_log_queue, &ap_item, 0) == pdTRUE) {
            if (g_sd_ok.load()) aplog_write(&ap_item);
        }

        uint32_t now = millis();
        if (now - last_stats_ms >= STATS_INTERVAL_MS) {
            last_stats_ms = now;
            if (g_sd_ok.load()) stats_write();
        }

        if (g_sd_retry_req.exchange(false, std::memory_order_relaxed)) {
            sd_init();
        }
    }
}
