// Pure helpers: byte extraction + MAC formatting (header-only, static inline).
#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>

static inline uint16_t read16_be(const uint8_t *p) { return (p[0] << 8) | p[1]; }

static inline bool mac_eq(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}
static inline bool mac_zero(const uint8_t *a) {
    for (int i = 0; i < 6; i++) if (a[i] != 0) return false;
    return true;
}
static inline void mac_str(const uint8_t *m, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%02x_%02x_%02x_%02x_%02x_%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}
static inline void mac_str_colon(const uint8_t *m, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}
