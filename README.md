# ESP32Gotchi

[![Platform](https://img.shields.io/badge/Platform-ESP32--WROOM--32-blue)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Arduino_IDE_2.x-orange)](https://www.arduino.cc/)
[![Author](https://img.shields.io/badge/Author-tworjaga-lightgrey)](https://github.com/tworjaga)

> Autonomous WPA/WPA2 handshake capture device based on ESP32.  
> Low-cost, plug-and-play, no configuration required.

---

## Overview

ESP32Gotchi is a self-contained passive Wi-Fi handshake sniffer inspired by the Pwnagotchi project. It runs on a ~10 EUR hardware stack, requires no host computer, and writes standard PCAP files directly to a microSD card. All operation is autonomous from power-on.

The firmware uses FreeRTOS with four independent tasks, a promiscuous-mode Wi-Fi callback, IEEE 802.11-2020 compliant EAPOL parsing, and a dedicated SD write task to prevent I/O from stalling packet processing.

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

**Button**
```
ESP32 GPIO0   ->  Button  ->  GND
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
 |-- Tactile button    (GPIO0, active-low)
 |-- Status LED        (GPIO2, optional)
 |-- LiPo + TP4056     (optional, portable)
```

---

## Firmware

### Architecture

Four FreeRTOS tasks with explicit core pinning:

| Task | Core | Priority | Stack | Function |
|------|------|----------|-------|----------|
| `task_proc` | 0 | 5 | 8 KB | Pulls packets from queue, parses 802.11/EAPOL, manages handshake slots |
| `task_hop` | 0 | 3 | 2 KB | Cycles channels 1-11, 200 ms dwell per channel |
| `task_write` | 0 | 2 | 4 KB | Receives completed handshakes, writes PCAP to SD |
| `task_ui` | 1 | 1 | 4 KB | Updates OLED every 200 ms, handles LED and button |

The promiscuous callback (`promisc_cb`) runs in the Wi-Fi driver context. It performs only `malloc` + `xQueueSendFromISR` and returns immediately — no parsing in the callback.

### EAPOL Detection

Implements IEEE 802.11-2020 §12.7.2 key_info bit field:

| Message | Pairwise | ACK | MIC | Install | Secure |
|---------|----------|-----|-----|---------|--------|
| Msg 1 | 1 | 1 | 0 | 0 | 0 |
| Msg 2 | 1 | 0 | 1 | 0 | 0 |
| Msg 3 | 1 | 1 | 1 | 1 | 1 |
| Msg 4 | 1 | 0 | 1 | 0 | 1 |

All four messages must be captured to mark a handshake as complete. Incomplete slots expire after 30 seconds.

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

4. Open `ESP32Cheapagotchi.cpp`, compile, and flash.

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
[BOOT] ESP32 Cheapagotchi
[SD] OK
[WIFI] promiscuous active
[BOOT] tasks started
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
 |-- ESP32Cheapagotchi.cpp   # Full firmware source
 |-- README.md
 |-- LICENSE
 |-- hardware/
 |    |-- schematics/        # Wiring diagrams (KiCad / images)
 |    |-- images/            # Build photos
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

---

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| MCU | Xtensa LX6 dual-core, 240 MHz |
| RAM | 520 KB SRAM |
| Wi-Fi | 802.11 b/g/n, 2.4 GHz |
| Channels scanned | 1 – 11 |
| Channel dwell time | 200 ms |
| Packet queue depth | 64 items |
| Max concurrent handshake slots | 32 |
| Max tracked APs | 100 |
| Handshake slot timeout | 30 s |
| PCAP network type | 105 (802.11 + radiotap) |
| Watchdog timeout | 30 s |
| Min SD free space | 1 MB |

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