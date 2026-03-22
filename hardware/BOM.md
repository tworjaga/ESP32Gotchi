# Bill of Materials

Complete component list for ESP32Gotchi.

---

## Core Components

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 1 | MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | 1 | ~5 EUR |
| 2 | Display | 0.96" SSD1306 OLED, 128x64, I2C, 4-pin (VCC/GND/SDA/SCL) | 1 | ~3 EUR |
| 3 | Storage | MicroSD SPI module, 3.3V compatible | 1 | ~1 EUR |
| 4 | Button | Tactile push button, through-hole | 1 | ~0.10 EUR |
| 5 | Resistor | 220 ohm, 1/4W (for LED) | 1 | ~0.05 EUR |
| 6 | LED | 3mm or 5mm, any colour | 1 | ~0.10 EUR |
| 7 | MicroSD card | FAT32 formatted, 2 GB minimum | 1 | ~2 EUR |

**Core total: ~11 EUR**

---

## Optional — Portable Operation

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 8 | Battery | LiPo 3.7V, 1000 mAh or larger | 1 | ~4 EUR |
| 9 | Charger | TP4056 module, USB-C, with protection circuit | 1 | ~1 EUR |
| 10 | Switch | SPDT slide switch or mini toggle | 1 | ~0.50 EUR |

**Portable add-on total: ~5.50 EUR**

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
- AliExpress (lowest cost, 2-4 week shipping)
- LCSC Electronics (good quality, reasonable shipping)
- Mouser / Digi-Key (fast shipping, higher cost)
- Local electronics shops

Search terms:
- `ESP32 DevKit V1 30pin`
- `SSD1306 0.96 OLED I2C`
- `Micro SD SPI module 3.3V`
- `TP4056 USB-C protection`