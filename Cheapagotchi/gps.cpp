// NMEA parsing on UART2 (task_gps) and GPS time helpers. Writes g_gps under g_gps_mutex.
#include "gps.h"
#include "state.h"

#include <Arduino.h>
#include <string.h>
#include <stdlib.h>

static float nmea_to_degrees(const char *val, char hemi) {
    if (!val || val[0] == '\0') return 0.0f;
    float raw  = atof(val);
    int   deg  = (int)(raw / 100);
    float mins = raw - deg * 100.0f;
    float result = deg + mins / 60.0f;
    if (hemi == 'S' || hemi == 'W') result = -result;
    return result;
}

// Verify the NMEA checksum (*XX) on the original line before trusting any field.
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

void timestamp_str(char *out, size_t out_sz) {
    if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        if (g_gps.time_set && g_gps.valid &&
            (millis() - g_gps.last_fix_ms) < GPS_STALE_MS) {
            snprintf(out, out_sz, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                     g_gps.year, g_gps.month, g_gps.day,
                     g_gps.hour, g_gps.minute, g_gps.second);
            xSemaphoreGive(g_gps_mutex);
            return;
        }
        xSemaphoreGive(g_gps_mutex);
    }
    uint32_t s = millis() / 1000;
    snprintf(out, out_sz, "UP+%05lus", (unsigned long)s);
}

bool gps_now_epoch(uint32_t *epoch_out) {
    bool ok = false;
    if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        if (g_gps.time_set && g_gps.valid &&
            (millis() - g_gps.last_fix_ms) < GPS_STALE_MS) {
            // days_from_civil (proleptic Gregorian, 1970 epoch); year >= 2000 so days > 0.
            int      yy  = (int)g_gps.year - (g_gps.month <= 2);
            unsigned mo  = g_gps.month, d = g_gps.day;
            unsigned h   = g_gps.hour,  mi = g_gps.minute, s = g_gps.second;
            int      era = (yy >= 0 ? yy : yy - 399) / 400;
            unsigned yoe = (unsigned)(yy - era * 400);
            unsigned doy = (153u * (mo > 2 ? mo - 3 : mo + 9) + 2) / 5 + d - 1;
            unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            long     days = (long)era * 146097 + (long)doe - 719468;
            *epoch_out = (uint32_t)((unsigned long)days * 86400UL
                               + (unsigned long)h * 3600UL
                               + (unsigned long)mi * 60UL + s);
            ok = true;
        }
        xSemaphoreGive(g_gps_mutex);
    }
    return ok;
}

void task_gps(void *arg) {
    char *sbuf = (char *)malloc(GPS_SENTENCE_LEN);
    configASSERT(sbuf != NULL);
    int spos = 0;

    Serial2.begin(GPS_BAUD, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);
    g_gps_available.store(true);

    uint32_t boot_ms    = millis();
    bool     fix_warned = false;

    while (1) {
        while (Serial2.available()) {
            char c = (char)Serial2.read();
            if (c == '\r') continue;
            if (c == '\n' || spos >= GPS_SENTENCE_LEN - 1) {
                sbuf[spos] = '\0';

                if (strncmp(sbuf, "$GPRMC", 6) == 0 ||
                    strncmp(sbuf, "$GPGGA", 6) == 0) {

                    bool csum_ok = nmea_checksum_ok(sbuf);

                    char *star = strrchr(sbuf, '*');
                    if (star) *star = '\0';

                    char *toks[16] = {0};
                    char  tmp[GPS_SENTENCE_LEN];
                    strncpy(tmp, sbuf, GPS_SENTENCE_LEN - 1);
                    tmp[GPS_SENTENCE_LEN - 1] = '\0';
                    int n = csum_ok ? nmea_split(tmp, toks, 16) : 0;

                    if (csum_ok && xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {

                        if (strncmp(sbuf, "$GPRMC", 6) == 0 && n >= 10) {
                            bool active = (toks[2] && toks[2][0] == 'A');
                            if (active) {
                                g_gps.lat   = nmea_to_degrees(toks[3], toks[4] ? toks[4][0] : 'N');
                                g_gps.lon   = nmea_to_degrees(toks[5], toks[6] ? toks[6][0] : 'E');
                                g_gps.valid = true;
                                g_gps.last_fix_ms = millis();
                                g_gps_fix.store(true);
                                if (toks[1] && strlen(toks[1]) >= 6) {
                                    char t[3] = {0};
                                    t[0]=toks[1][0]; t[1]=toks[1][1]; g_gps.hour   = atoi(t);
                                    t[0]=toks[1][2]; t[1]=toks[1][3]; g_gps.minute = atoi(t);
                                    t[0]=toks[1][4]; t[1]=toks[1][5]; g_gps.second = atoi(t);
                                }
                                if (toks[9] && strlen(toks[9]) >= 6) {
                                    char d[3] = {0};
                                    d[0]=toks[9][0]; d[1]=toks[9][1]; g_gps.day   = atoi(d);
                                    d[0]=toks[9][2]; d[1]=toks[9][3]; g_gps.month = atoi(d);
                                    d[0]=toks[9][4]; d[1]=toks[9][5]; g_gps.year  = 2000 + atoi(d);
                                    g_gps.time_set = true;
                                }
                            } else {
                                g_gps.valid = false;
                                g_gps_fix.store(false);
                            }
                        }

                        else if (strncmp(sbuf, "$GPGGA", 6) == 0 && n >= 10) {
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

        // Downgrade a fix that has gone stale so the UI/CSV stop reporting it.
        if (xSemaphoreTake(g_gps_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            if (g_gps.valid && (millis() - g_gps.last_fix_ms) > GPS_STALE_MS) {
                g_gps.valid = false;
                g_gps_fix.store(false);
            }
            xSemaphoreGive(g_gps_mutex);
        }

        if (!fix_warned && !g_gps_fix.load() &&
            (millis() - boot_ms) > GPS_FIX_TIMEOUT_MS) {
            fix_warned = true;
            Serial.println("[GPS] no fix within 60 s — continuing without fix");
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
