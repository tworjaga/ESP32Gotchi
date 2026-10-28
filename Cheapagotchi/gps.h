// NMEA parsing (task_gps) and GPS-derived time helpers.
#pragma once

#include <stdint.h>
#include <stddef.h>

void task_gps(void *arg);

// ISO-8601 UTC from the GPS soft RTC while the fix is valid/fresh, else "UP+NNNNNs".
void timestamp_str(char *out, size_t out_sz);

// UNIX epoch (s) from the GPS soft RTC; true only on a fresh valid fix with time set.
bool gps_now_epoch(uint32_t *epoch_out);
