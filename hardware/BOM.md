# Bill of Materials

Complete component list for ESP32Gotchi v1.2.2.

---

## Core Components

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 1 | MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | 1 | ~5 EUR |
| 2 | Display | 0.96″ SSD1306 OLED, 128×64, I2C, 4-pin (VCC/GND/SDA/SCL) | 1 | ~3 EUR |
| 3 | Storage | MicroSD SPI module, 3.3V compatible | 1 | ~1 EUR |
| 4 | Button | Tactile push button, through-hole | 1 | ~0.10 EUR |
| 5 | Resistor | 220 Ω, 1/4W (for LED) | 1 | ~0.05 EUR |
| 6 | LED | 3mm or 5mm, any colour | 1 | ~0.10 EUR |
| 7 | MicroSD card | FAT32 formatted, 2 GB minimum | 1 | ~2 EUR |

**Core total: ~11 EUR**

---

## Optional — GPS (v1.2.2)

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 8 | GPS module | Neo-6M UART, 3.3V-compatible, with antenna | 1 | ~3 EUR |

Connect to ESP32 UART2: TX → GPIO16, RX → GPIO17. The module is entirely optional — the firmware detects its absence and falls back to uptime-based timestamps.

---

## Optional — Battery Voltage Monitor (v1.2.2)

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 9 | Resistor | 100 kΩ, 1/4W | 2 | ~0.10 EUR |

Wire as a voltage divider: Vbat → 100 kΩ → GPIO34 → 100 kΩ → GND. This halves the battery voltage to within the ESP32 ADC range (0–3.3 V). Connect GPIO34 only — it is an input-only pin, safe for direct voltage divider use.

---

## Optional — Portable Operation

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 10 | Battery | LiPo 3.7V, 1000 mAh or larger | 1 | ~4 EUR |
| 11 | Charger | TP4056 module, USB-C, with protection circuit | 1 | ~1 EUR |
| 12 | Switch | SPDT slide switch or mini toggle | 1 | ~0.50 EUR |

**Portable add-on total: ~5.60 EUR**

---

## Total Cost Summary

| Configuration | Approx. Cost |
|---------------|-------------|
| Core only | ~11 EUR |
| Core + GPS | ~14 EUR |
| Core + GPS + battery monitor + portable | ~20 EUR |

---

## Tools Required

- Soldering iron
- Solder
- Jumper wires or breadboard for prototyping
- USB-A to Micro-USB cable (for flashing)
- Computer with Arduino IDE 2.x or PlatformIO

---

## Sourcing

Components are available from:
- AliExpress (lowest cost, 2–4 week shipping)
- LCSC Electronics (good quality, reasonable shipping)
- Mouser / Digi-Key (fast shipping, higher cost)
- Local electronics shops

Search terms:
- `ESP32 DevKit V1 30pin`
- `SSD1306 0.96 OLED I2C`
- `Micro SD SPI module 3.3V`
- `Neo-6M GPS module UART`
- `TP4056 USB-C protection`
