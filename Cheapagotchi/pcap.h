// Write a completed handshake's frames to a libpcap file on SD (task_write only).
#pragma once

#include <stdint.h>

void pcap_write(uint8_t slot_idx, uint8_t *chunk_buf);
