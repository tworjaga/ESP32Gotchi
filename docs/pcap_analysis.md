# PCAP Analysis Guide

This document covers how to open, inspect, and use the `.pcap` files produced by ESP32Gotchi.

---

## File Location

Files are written to `/handshakes/` on the microSD card.

Naming convention:
```
hs_<bssid>_<uptime_seconds>.pcap
```
Example:
```
hs_aa_bb_cc_dd_ee_ff_3721.pcap
```

---

## Opening in Wireshark

1. Remove the SD card from the device and mount it on your computer.
2. Open Wireshark.
3. `File -> Open` — navigate to the `.pcap` file.
4. Wireshark will decode the file automatically. Network type is **105 (IEEE 802.11 + radiotap)**.

You should see four packets — the WPA2 4-way handshake messages (EAPOL-Key frames).

Useful Wireshark display filter to isolate EAPOL frames:
```
eapol
```

To inspect a specific AP by BSSID:
```
wlan.bssid == aa:bb:cc:dd:ee:ff
```

---

## Cracking with hashcat

### Step 1 — Convert PCAP to hashcat format

Use `hcxpcapngtool` from the [hcxtools](https://github.com/ZerBea/hcxtools) suite:

```bash
hcxpcapngtool -o capture.hc22000 hs_aa_bb_cc_dd_ee_ff_3721.pcap
```

### Step 2 — Run hashcat

```bash
hashcat -m 22000 capture.hc22000 wordlist.txt
```

Common wordlists: `rockyou.txt`, custom lists generated with `hashcat --stdout` rules.

### Notes

- All four EAPOL messages (1, 2, 3, 4) must be present in the capture for a full handshake crack.
- If only messages 1 and 2 are present, PMKID cracking may still be possible depending on the AP.
- Verify capture completeness in Wireshark before running hashcat.

---

## Verifying Capture Integrity

In Wireshark, check the following for each of the four packets:

| Frame | Key Info flags | Expected |
|-------|---------------|----------|
| Msg 1 | ACK=1, MIC=0 | AP -> STA |
| Msg 2 | ACK=0, MIC=1 | STA -> AP |
| Msg 3 | ACK=1, MIC=1, Install=1 | AP -> STA |
| Msg 4 | ACK=0, MIC=1, Secure=1 | STA -> AP |

If any message is missing, the handshake is incomplete. The device may have missed a packet due to channel timing. Leave the device running longer near the target AP, or trigger a re-authentication.

---

## Tools Reference

| Tool | Purpose | Link |
|------|---------|-------|
| Wireshark | PCAP inspection | [wireshark.org](https://www.wireshark.org/) |
| hcxtools | PCAP -> hashcat conversion | [github.com/ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) |
| hashcat | Password recovery | [hashcat.net](https://hashcat.net/) |
| aircrack-ng | Alternative cracking | [aircrack-ng.org](https://www.aircrack-ng.org/) |

---

## Legal Notice

Only analyse captures from networks you own or have explicit written authorisation to test.