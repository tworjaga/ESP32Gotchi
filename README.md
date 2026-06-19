# ESP32Gotchi

[![Platform](https://img.shields.io/badge/Platform-ESP32--WROOM--32-blue)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Arduino_IDE_2.x-orange)](https://www.arduino.cc/)
[![Author](https://img.shields.io/badge/Author-tworjaga-lightgrey)](https://github.com/tworjaga)
<img src="https://visitor-badge.laobi.icu/badge?page_id=tworjaga.ESP32Gotchi&"  />

> Autonomous WPA/WPA2 handshake capture and Wi-Fi AP monitoring device based on ESP32.  
> Low-cost, plug-and-play, no configuration required.

---

## Overview

ESP32Gotchi is a self-contained passive Wi-Fi handshake sniffer and AP logger inspired by the Pwnagotchi project. It runs on an ~10–15 EUR hardware stack, requires no host computer, and writes standard PCAP files and CSV logs directly to a microSD card. All operation is autonomous from power-on.

The firmware uses FreeRTOS with five independent tasks, a promiscuous-mode Wi-Fi callback, IEEE 802.11-2020 compliant EAPOL parsing, a dedicated SD write task to prevent I/O from stalling packet processing, and an optional GPS task for geolocation tagging.

---

## Hardware

### Bill of Materials

| Component | Specification | Approx. Cost |
|-----------|--------------|--------------|
| MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | ~5 EUR |
| Display | 0.96″ SSD1306 OLED, 128×64, I2C (4-pin) | ~3 EUR |
| Storage | MicroSD SPI module, 3.3V compatible | ~1 EUR |
| Button | Tactile push button | <0.50 EUR |
| LED | 3mm or 5mm LED + 220 Ω resistor | <0.50 EUR |
| Power (portable) | LiPo 3.7V + TP4056 USB-C charging module | ~2 EUR |
| **GPS (optional)** | **Neo-6M UART module** | **~3 EUR** |

**Total: ~10–15 EUR (with GPS)**

### Wiring

**OLED — I2C**
```
ESP32 GPIO21  ->  SDA
ESP32 GPIO22  ->  SCL
ESP32 3.3V    ->  VCC
ESP32 GND     ->  GND
```

**MicroSD — SPI**
```
ESP32 GPIO18  ->  SCK
ESP32 GPIO23  ->  MOSI
ESP32 GPIO19  ->  MISO
ESP32 GPIO5   ->  CS
ESP32 3.3V    ->  VCC
ESP32 GND     ->  GND
```

> **GPIO5 note:** GPIO5 is the SDIO-slave timing strapping pin but has no effect in SPI mode. Safe on DevKit V1. On a custom PCB, do not place an external pull-up stronger than 10 kΩ on GPIO5 before the strapping window closes at boot.

**Button — GPIO4**
```
ESP32 GPIO4   ->  Button  ->  GND
(internal pull-up enabled in firmware)
```

**LED (optional)**
```
ESP32 GPIO2   ->  220 ohm resistor  ->  LED anode
LED cathode   ->  GND
```

**GPS Neo-6M — UART2 (optional, v1.2.2)**
```
ESP32 GPIO16  ->  Neo-6M TX   (UART2 RX)
ESP32 GPIO17  ->  Neo-6M RX   (UART2 TX)
ESP32 3.3V    ->  Neo-6M VCC
ESP32 GND     ->  Neo-6M GND
```

**Battery voltage sense — ADC (optional, v1.2.2)**
```
Vbat  ->  100k resistor  ->  GPIO34  ->  100k resistor  ->  GND
(100k/100k divider: Vadc = Vbat / 2)
```

### Power Options

USB only (development / bench use):
```
USB -> ESP32 DevKit V1
```

Portable (battery operation):
```
LiPo 3.7V -> TP4056 -> ESP32 VIN
```

---

## Hardware Architecture

```
ESP32-WROOM-32
 |-- OLED SSD1306      (I2C: GPIO21/22)
 |-- MicroSD module    (SPI: GPIO18/19/23/5)
 |-- Tactile button    (GPIO4, active-low)
 |-- Status LED        (GPIO2, optional)
 |-- Neo-6M GPS        (UART2: GPIO16/17, optional)   ← v1.2.2
 |-- Batt ADC divider  (GPIO34, optional)              ← v1.2.2
 |-- LiPo + TP4056     (optional, portable)
```

---

## Firmware

### Architecture

Five FreeRTOS tasks with explicit core pinning:

| Task | Core | Priority | Stack | Function |
|------|------|----------|-------|----------|
| `task_hop` | 0 | **6** | 2 KB | Cycles channels 1–11, 200 ms dwell. Highest priority on Core 0 — guaranteed to run. |
| `task_proc` | 0 | 5 | 6 KB | Pulls packets from queue, parses 802.11/EAPOL, manages handshake slots. Drains AP log queue in idle window. |
| `task_write` | 0 | **4** | 6 KB | Receives completed handshakes (by slot index), writes PCAP to SD. Drains AP log queue, writes stats CSV every 60 s. |
| `task_ui` | 1 | 1 | 4 KB | Updates OLED every 200 ms, handles LED, button, battery ADC reads. |
| `task_gps` | 1 | 2 | 3 KB | Parses NMEA sentences from UART2; updates `g_gps` struct and soft RTC. *(new in v1.2.2)* |

### Memory Layout

All packet storage is statically allocated at boot. No `malloc()` or `free()` at runtime (task stacks and one GPS sentence buffer are the only dynamic allocations, made once at boot).

| Region | Size | Purpose |
|--------|------|---------|
| `pkt_pool_mem[32][1600]` | 51 200 B | In-flight packet buffers (claimed by `promisc_cb`, released by `task_proc`) |
| `hs_raw_pool_mem[32][1600]` | 51 200 B | Handshake frame storage (held until PCAP written, then released) |
| `g_hs[16]` metadata | ~640 B | Handshake slot state (indices into `hs_raw_pool_mem`, not frame data) |
| `g_ap_table[256][6]` | 1 536 B | AP hash table |
| **Total user static** | **~104 KB** | Well within the ~200 KB available after the Wi-Fi stack |

### EAPOL Detection

Implements IEEE 802.11-2020 §12.7.2 key_info bit field:

| Message | Pairwise | ACK | MIC | Install | Secure |
|---------|----------|-----|-----|---------|--------|
| Msg 1 | 1 | 1 | 0 | 0 | 0 |
| Msg 2 | 1 | 0 | 1 | 0 | 0 |
| Msg 3 | 1 | 1 | 1 | 1 | 1 |
| Msg 4 | 1 | 0 | 1 | 0 | 1 |

All four messages must be captured to mark a handshake as complete. Incomplete slots expire after 15 seconds.

### PCAP Output

Files are written to `/handshakes/` on the SD card.  
Naming: `hs_<bssid>_<uptime_seconds>.pcap`  
Example: `hs_aa_bb_cc_dd_ee_ff_3721.pcap`

When GPS time is available, the PCAP packet timestamp uses the GPS UTC clock instead of `millis()`.

Format: standard libpcap (magic `0xa1b2c3d4`), network type 105 (IEEE 802.11). Files open directly in Wireshark without conversion.

### AP Log Output (new in v1.2.2)

New BSSIDs seen in beacon and probe-response frames are logged to `/aplog/aps.csv`:

```
timestamp,bssid,rssi_dbm,channel
2024-06-01T14:32:01Z,AA:BB:CC:DD:EE:FF,-62,6
2024-06-01T14:32:04Z,11:22:33:44:55:66,-74,11
```

The file rotates to `aps_1.csv` when it reaches 4 MB. The timestamp is ISO-8601 UTC when a GPS fix is available, or an uptime string (`UP+00042s`) otherwise.

### Stats Log Output (new in v1.2.2)

A device statistics snapshot is appended to `/stats/stats.csv` every 60 seconds:

```
timestamp,ap_count,pkt_rate,free_heap,rssi_last,rssi_drops,gps_lat,gps_lon,gps_fix
2024-06-01T14:33:00Z,14,87,148320,-67,203,48.208176,16.373819,1
```

The file rotates to `stats_1.csv` at 4 MB.

### OLED Display Layout

The display now has four pages, cycled by short button press.

**Page 1 — Stats**
```
(o_o)              1/4
HS:  12
CH:  6
AP:  34
PKT: 128
RSSI:-67 D:203
```

**Page 2 — GPS**
```
(o_o)              2/4
FIX: YES
LAT:48.20818
LON:16.37382
ALT:183m
SAT:8 HDOP:1.1
```

**Page 3 — SD**
```
(o_o)              3/4
SD:  OK
FREE:3821MB
APS: 14KB
STS: 2KB
WR:  OK
```

**Page 4 — System**
```
(o_o)              4/4
HEAP:148320B
UP: 01:22:07
PKT: 87/s
DRP: 203
BAT: 78%
```

Face states:
- `(o_o)` — scanning normally
- `(^o^)` — EAPOL frames being collected
- `(X_X)` — error (SD missing, low space)
- `(-_-)` — idle

### LED Patterns

| Pattern | Meaning |
|---------|---------|
| Slow blink (1 Hz) | Normal scanning |
| Fast blink (5 Hz) | Handshake capture in progress |
| Single short flash | Handshake saved to SD |
| 3 × long flash (2 s) | SD error — repeating |

### Button Behaviour

| Press duration | Action |
|---------------|--------|
| Short (50 ms – 3 s) | Cycle OLED page (Stats → GPS → SD → System → Stats) |
| Long (3 s – 6 s) | `ESP.restart()` |
| Extra-long (≥ 6 s) | Enter deep sleep (wake on same button) |

### GPS Integration (new in v1.2.2)

Connect a Neo-6M (or compatible) GPS module to UART2 (GPIO16/GPIO17). `task_gps` parses `$GPRMC` and `$GPGGA` sentences with NMEA checksum verification. When a valid fix is active:

- All timestamps in `/aplog/aps.csv` and `/stats/stats.csv` switch to ISO-8601 UTC.
- PCAP packet record timestamps use GPS UTC instead of `millis()`.
- The GPS page (Page 2) shows lat, lon, altitude, satellite count, and HDOP.

A fix is considered stale after 10 seconds without a valid `$GPRMC` with status `A`; the firmware downgrades `FIX: YES` → `FIX: NO` and stops reporting coordinates until the next good fix. If no fix is obtained within 60 seconds of boot, a one-time warning is logged to Serial and operation continues without GPS.

The GPS module is optional. If not wired, `g_gps_available` remains `false` and all timestamps fall back to uptime strings. No code changes required.

### Battery Monitoring (new in v1.2.2)

Connect a 100 kΩ/100 kΩ voltage divider from the LiPo+ rail to GPIO34. The firmware reads 16 ADC samples every 30 seconds, averages them, reconstructs `Vbat`, and maps it to 0–100% (3 500 mV → 4 200 mV range). The percentage is shown on Page 4 (System). No external library required.

### Startup Self-Test (new in v1.2.2)

On boot the firmware runs a visual self-test sequence on the OLED before any tasks are started:

```
Self-test v1.2.2
SD:   OK
  free: 3821MB
```
```
Self-test v1.2.2
GPS:  UART OK
```
```
Self-test v1.2.2
HEAP: 152340B
```
```
Self-test v1.2.2
WIFI: OK
```
```
   Cheapagotchi
   v1.2.2 Ready
```

Each screen is displayed for ~600 ms. If SD fails, `SD: FAIL` is shown and the device continues without SD logging.

### Deep Sleep (new in v1.2.2)

An extra-long button press (≥ 6 seconds) triggers a clean shutdown sequence:

1. Promiscuous mode disabled.
2. Write queue flushed (up to 2 s timeout).
3. `task_write` suspended.
4. SD card cleanly unmounted.
5. OLED shows `SLEEP ZZZ / Hold BTN to wake`.
6. `esp_deep_sleep_start()` — wakes on GPIO4 LOW (same button).

---

## Build & Flash

### Requirements

- Arduino IDE 2.x or PlatformIO
- ESP32 board package by Espressif, version 2.0.x or later
- U8g2 library (install via Arduino Library Manager)
- No additional libraries required for GPS or battery monitoring

### Arduino IDE

1. Install board package: `File -> Preferences -> Additional Boards Manager URLs`  
   Add: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`

2. Install U8g2: `Tools -> Manage Libraries -> search "U8g2"`

3. Board settings:
   ```
   Board            : ESP32 Dev Module
   Partition scheme : Default 4MB with spiffs
   CPU Frequency    : 240 MHz
   Flash mode       : QIO
   Upload speed     : 921600
   ```

4. Open `Cheapagotchi.ino`, compile, and flash.

### PlatformIO

```ini
[env:esp32dev]
platform  = espressif32
board     = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps  = olikraus/U8g2
board_build.partitions = default.csv
```

---

## SD Card

- Format: FAT32
- Minimum recommended size: 2 GB
- The firmware creates `/handshakes/`, `/aplog/`, and `/stats/` automatically on first boot.
- Minimum free space check: 1 MB before each PCAP write. If space is below threshold, the device continues sniffing but skips saving.
- CSV files rotate at 4 MB (`aps.csv` → `aps_1.csv`, `stats.csv` → `stats_1.csv`).
- If SD is absent or fails, the device retries initialisation on the next retry cycle and displays `SD: ERR`.

---

## Serial Debug Output

Connect at 115200 baud. Example output:

```
[BOOT] ESP32 Cheapagotchi v1.2.2
[SD] OK
[WIFI] promiscuous active
[MEM]  free heap: 152340 bytes
[GPS] no fix within 60 s — continuing without fix
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg1
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg2
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg3
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg4
[HS] saved /handshakes/hs_aa_bb_cc_dd_ee_ff_3721.pcap  total=1
[STAT] pkt/s=23  rssi=-67dBm  drops=142  thr=-80dBm  ap_log_drops=0  hs_pool_drops=0
[BTN] page -> 1
[SLEEP] entering deep sleep
```

---

## Repository Structure

```
ESP32Gotchi/
 |-- Cheapagotchi.ino        # Full firmware source
 |-- README.md
 |-- LICENSE
 |-- hardware/
 |    └── BOM.md             # Bill of materials
 └── docs/
      └── pcap_analysis.md   # Notes on opening captures in Wireshark
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `SD: ERR` on boot | SD not inserted, wrong wiring, not FAT32 | Check SPI wiring, reformat to FAT32 |
| OLED blank | I2C address mismatch or wiring fault | Verify SDA/SCL, confirm 0x3C with I2C scanner |
| No handshakes captured | No WPA2 4-way exchanges occurring nearby | Use a test AP; deauth-based capture is outside scope of this firmware |
| Device reboots repeatedly | Watchdog trigger — task hang | Check serial output for last log line; report via Issues |
| PCAP not opening in Wireshark | Corrupt write (power cut during save) | Delete partial file; ensure stable power supply |
| `GPS: N/A` on Page 2 | GPS UART not wired or module not responding | Check GPIO16/17 wiring; GPS is optional |
| `FIX: NO` after 60 s | No satellite view | Move outdoors; wait for first fix (can take 1–2 min cold start) |
| `BAT: 0%` | Voltage divider not wired or wrong pins | Check GPIO34 / divider resistors; feature requires hardware |
| `ap_log_drops > 0` in Serial | AP log queue full — high beacon density | Normal in dense RF; rows are not lost, just rate-limited |

---

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| MCU | Xtensa LX6 dual-core, 240 MHz |
| RAM | 520 KB SRAM |
| Wi-Fi | 802.11 b/g/n, 2.4 GHz |
| Channels scanned | 1 – 11 |
| Channel dwell time | 200 ms |
| Packet queue depth | 32 items |
| Packet pool blocks | 32 × 1 600 B (static) |
| HS raw-frame pool blocks | 32 × 1 600 B (static) |
| Max concurrent handshake slots | 16 |
| Max tracked APs | 192 (hash table, 256 buckets) |
| Handshake slot timeout | 15 s |
| New slot rate limit | 1 per 100 ms |
| RSSI filter threshold | –80 dBm (tunable) |
| PCAP network type | 105 (802.11) |
| GPS baud rate | 9 600 (Neo-6M default) |
| GPS fix staleness timeout | 10 s |
| Stats log interval | 60 s |
| CSV rotation size | 4 MB |
| Battery ADC samples | 16-sample average |
| Battery update interval | 30 s |
| Watchdog timeout | 30 s |
| Min SD free space | 1 MB |
| Runtime heap allocations | **0** (excluding one-time GPS buffer) |

---

## Legal Notice

This tool is intended for **authorised security research and educational use only**.  
Capturing Wi-Fi handshakes on networks you do not own or have explicit written permission to test is illegal in most jurisdictions.  
The author assumes no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contact

Author: [@tworjaga](https://github.com/tworjaga)  
Telegram: [@smtrcv](https://t.me/smtrcv)  
Issues: [github.com/tworjaga/ESP32Gotchi/issues](https://github.com/tworjaga/ESP32Gotchi/issues)
