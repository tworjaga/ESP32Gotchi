// PCAP file writing (GPS UTC timestamp when available). Runs only in task_write.
#include "pcap.h"
#include "state.h"
#include "gps.h"
#include "util.h"

#include <Arduino.h>
#include <SD.h>

static_assert(CHUNK_BUF_SIZE == (24 + 4 * (16 + MAX_PKT_LEN)),
              "CHUNK_BUF_SIZE formula mismatch");

static uint32_t pcap_record_ts(uint32_t uptime_fallback) {
    uint32_t epoch;
    return gps_now_epoch(&epoch) ? epoch : uptime_fallback;
}

static bool pcap_write_file(hs_slot_t *hs, uint32_t name_ts, uint32_t rec_ts,
                            uint8_t *chunk_buf) {
    char bssid_s[24];
    mac_str(hs->bssid, bssid_s, sizeof(bssid_s));

    char path[80];
    snprintf(path, sizeof(path), "/handshakes/hs_%s_%lu.pcap", bssid_s, (unsigned long)name_ts);

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

        write32_le(rec_ts);
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

void pcap_write(uint8_t slot_idx, uint8_t *chunk_buf) {
    hs_slot_t *hs = &g_hs[slot_idx];
    uint32_t   ts     = millis() / 1000;
    // rec_ts via gps before any g_sd_mutex, preserving gps-before-sd order.
    uint32_t   rec_ts = pcap_record_ts(ts);
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

    if (pcap_write_file(hs, ts, rec_ts, chunk_buf)) {
        g_hs_count.fetch_add(1);
        g_led.store(LED_FLASH);
        g_last_write_ok.store(true);
        Serial.printf("[HS] saved  total=%lu\n", (unsigned long)g_hs_count.load());
    } else {
        g_face.store(FACE_ERROR);
        g_last_write_ok.store(false);
    }

release_slots:
    // Atomic teardown: free raw blocks AND clear active/queued under g_hs_mutex together.
    xSemaphoreTakeRecursive(g_hs_mutex, portMAX_DELAY);
    for (int i = 0; i < 4; i++) {
        if (hs->raw_idx[i] != POOL_NONE) {
            uint8_t ridx = hs->raw_idx[i];
            xQueueSend(g_hs_raw_free_q, &ridx, 0);
            hs->raw_idx[i] = POOL_NONE;
        }
    }
    hs->active = false;
    hs->queued = false;
    xSemaphoreGiveRecursive(g_hs_mutex);
}
