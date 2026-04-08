# ESP32Gotchi

[![Platform](https://img.shields.io/badge/Platform-ESP32--WROOM--32-blue)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Arduino_IDE_2.x-orange)](https://www.arduino.cc/)
[![Author](https://img.shields.io/badge/Author-tworjaga-lightgrey)](https://github.com/tworjaga)
<img src="https://visitor-badge.laobi.icu/badge?page_id=tworjaga.ESP32Gotchi&"  />

> Autonomous WPA/WPA2 handshake capture device based on ESP32.  
> Low-cost, plug-and-play, no configuration required.

---

## Overview

ESP32Gotchi is a self-contained passive Wi-Fi handshake sniffer inspired by the Pwnagotchi project. It runs on a ~10 EUR hardware stack, requires no host computer, and writes standard PCAP files directly to a microSD card. All operation is autonomous from power-on.

The firmware uses FreeRTOS with four independent tasks, a promiscuous-mode Wi-Fi callback, IEEE 802.11-2020 compliant EAPOL parsing, and a dedicated SD write task to prevent I/O from stalling packet processing.

---

## v1.1.0 — What Changed

### Hardware (one wire change required)

**The button must be moved from GPIO0 to GPIO4.**

GPIO0 is the ESP32 boot-mode strapping pin. The ROM samples it approximately 50 ms after every reset to decide whether to start the user firmware or enter serial Download Mode. The v1.0.0 wiring placed the user button on this pin. Although the restart fires on button *release* (so typical use is fine), a user who keeps the button pressed while the device reboots will land in Download Mode with a black screen that looks like a brick.

GPIO4 has no strapping function. Move the single button wire from DevKit pin `IO0` to `IO4`. No other hardware changes.

### Firmware — eight fixes applied

| Fix | Description |
|-----|-------------|
| FIX-1 | Button pin: `GPIO0` → `GPIO4` (strapping-pin hazard) |
| FIX-2 | Task priorities rebalanced: `task_hop` raised to 6 (was 3), `task_write` raised to 4 (was 2). Channel hopping now guaranteed regardless of packet load. |
| FIX-3 | Zero-allocation packet path: `promisc_cb` no longer calls `malloc()`/`free()`. A static pool of 32 fixed-size blocks is claimed/released via a FreeRTOS free-list queue. |
| FIX-4 | `hs_slot_t` no longer embeds `raw[4][1600]` (was 6 430 bytes/slot, 205 KB for 32 slots). Raw frames are stored in a separate 32-block static pool; slots hold pool indices. |
| FIX-5 | `write_item_t` is now `uint8_t` (slot index). The write queue allocates 8 bytes instead of 51 440 bytes. No bulk memcpy of frame data. |
| FIX-6 | `g_ap_mutex` removed. `task_proc` is the only writer of the AP table; `task_ui` reads only `g_ap_count` (naturally atomic on Xtensa LX6). |
| FIX-7 | O(N) AP linear scan replaced with a 256-bucket open-addressing hash table. AP lookup is O(1) average. |
| FIX-8 | EAPOL slot-exhaustion DoS mitigated: new slot creation rate-limited to one per 100 ms. `MAX_HS_SLOTS` reduced to 16; `HS_EXPIRE_MS` reduced to 15 s. |

---

## Hardware

### Bill of Materials

| Component | Specification | Approx. Cost |
|-----------|--------------|--------------|
| MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | ~5 EUR |
| Display | 0.96" SSD1306 OLED, 128x64, I2C (4-pin) | ~3 EUR |
| Storage | MicroSD SPI module, 3.3V compatible | ~1 EUR |
| Button | Tactile push button | <0.50 EUR |
| LED | 3mm or 5mm LED + 220 ohm resistor | <0.50 EUR |
| Power (portable) | LiPo 3.7V + TP4056 USB-C charging module | ~2 EUR |

**Total: ~10-12 EUR**

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

**Button — v1.1.0: GPIO4 (was GPIO0)**
```
ESP32 GPIO4   ->  Button  ->  GND
(internal pull-up enabled in firmware)
```

**LED (optional)**
```
ESP32 GPIO2   ->  220 ohm resistor  ->  LED anode
LED cathode   ->  GND
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
 |-- Tactile button    (GPIO4, active-low)   ← v1.1.0: was GPIO0
 |-- Status LED        (GPIO2, optional)
 |-- LiPo + TP4056     (optional, portable)
```

---

## Firmware

### Architecture

Four FreeRTOS tasks with explicit core pinning:

| Task | Core | Priority | Stack | Function |
|------|------|----------|-------|----------|
| `task_hop` | 0 | **6** | 2 KB | Cycles channels 1–11, 200 ms dwell. Highest priority on Core 0 — guaranteed to run. |
| `task_proc` | 0 | 5 | 4 KB | Pulls packets from queue, parses 802.11/EAPOL, manages handshake slots. |
| `task_write` | 0 | **4** | 4 KB | Receives completed handshakes (by slot index), writes PCAP to SD. |
| `task_ui` | 1 | 1 | 4 KB | Updates OLED every 200 ms, handles LED and button. |

### Memory Layout

All packet storage is statically allocated at boot. No `malloc()` or `free()` at runtime.

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

Format: standard libpcap (magic `0xa1b2c3d4`), network type 105 (IEEE 802.11 + radiotap header). Files open directly in Wireshark without conversion.

### OLED Display Layout

```
(o_o)          <- face (changes with state)
HS:  12        <- handshakes captured this session
CH:  6         <- current Wi-Fi channel
AP:  34        <- unique BSSIDs seen
PKT: 128       <- packets processed per second
SD:  OK        <- SD card status
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
| 3 x long flash (2 s) | SD error — repeating |

### Button Behaviour

| Press duration | Action |
|---------------|--------|
| Short (50 ms – 3 s) | Reset channel hopper to CH 1 |
| Long (> 3 s) | `ESP.restart()` |

---

## Build & Flash

### Requirements

- Arduino IDE 2.x or PlatformIO
- ESP32 board package by Espressif, version 2.0.x or later
- U8g2 library (install via Arduino Library Manager)

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
- The firmware creates `/handshakes/` automatically on first boot
- Minimum free space check: 1 MB before each write. If space is below threshold, the device continues sniffing but skips saving.
- If SD is absent or fails, the device retries initialisation every 10 seconds and displays `SD: ERR`.

---

## Serial Debug Output

Connect at 115200 baud. Example output:

```
[BOOT] ESP32 Cheapagotchi v1.1.0
[SD] OK
[WIFI] promiscuous active
[BOOT] tasks started
[MEM]  free heap: 152340 bytes
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg1
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg2
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg3
[HS] aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  msg4
[HS] saved /handshakes/hs_aa_bb_cc_dd_ee_ff_3721.pcap  total=1
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
| Black screen after long-press restart (v1.0.0 only) | Button was on GPIO0 strapping pin | Upgrade to v1.1.0 and move button wire to GPIO4 |

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
| PCAP network type | 105 (802.11 + radiotap) |
| Watchdog timeout | 30 s |
| Min SD free space | 1 MB |
| Runtime heap allocations | **0** |

---

## Future Improvements

- Custom PCB with LiPo connector and integrated charging
- Battery level monitoring via ADC
- Rotary encoder for menu navigation
- Buzzer feedback on handshake capture
- ESP32-S3 port (USB OTG for live PCAP streaming)
- PMKID capture (message 1 only)

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
Telegram: [@al7exy](https://t.me/al7exy)  
Issues: [github.com/tworjaga/ESP32Gotchi/issues](https://github.com/tworjaga/ESP32Gotchi/issues)
