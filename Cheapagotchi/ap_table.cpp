// AP hash table: g_ap_table guarded by the g_ap_mux spinlock.
#include "ap_table.h"
#include "state.h"
#include "util.h"

#include <string.h>

// Murmur3 fmix32.
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

bool ap_record(const uint8_t *bssid) {
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
