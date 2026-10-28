// Unique-AP hash table (ISR/callback-safe via g_ap_mux).
#pragma once

#include <stdint.h>

// Record a BSSID; returns true if it is a new (first-seen) bssid.
bool ap_record(const uint8_t *bssid);
