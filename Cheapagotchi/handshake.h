// 802.11/EAPOL parsing and handshake-slot management.
#pragma once

#include <stdint.h>

void process_packet(uint8_t pkt_pool_idx, uint16_t len);
void hs_expire(void);   // caller must hold g_hs_mutex
