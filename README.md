# wifit3
> A standalone USB and pcie Wi-Fi auditor for Linux

<p align="center">
  <img src="assets/wifit3-1-splash.png" alt="wifit3 splash / adapter picker" width="700">
</p>

> *At least* one of the [supported adapters](#supported-hardware) — a USB dongle or a PCIe/M.2 card — is **required**.

## Why?
* **Cross-Platform (USB):** The userspace USB drivers run identically on Linux, macOS, and Windows.
* **PCIe/M.2 on Linux:** Drives built-in and M.2 cards (e.g. MediaTek MT7922) via the in-kernel driver — no USB dongle needed.
* **Wireless Driver Heaven:** Built-in wireless stack avoids kernel driver versioning hell and Windows' NDIS.
* **Few Runtime Dependencies:** No `aircrack-ng` or `reaver` — the USB stack is pure Python (PyUSB & Textual); the Linux PCIe/M.2 path additionally uses the in-kernel driver with `iw`/`nmcli`.

<p align="center">
  <img src="assets/wifit3-demo.gif" alt="wifit3 in action: WPS PushButton PSK capture" width="700">
</p>

---

## Features

### Reconnaissance & Analysis
- **Multi-Card Aggregation:** Capture packets across multiple adapters simultaneously; pick a dedicated card to inject.
- **Real-time Scanner:** 2.4GHz & 5GHz channel-hopping (split for multi-cards); tracks signal strength, encryption suites, WPA3/SAE transition modes.
- **AP & Client Identification:** Fingerprints device vendors and categories; extracts router make and model from WPS beacons.
- **VAP Decloaking:** Identifies hidden networks by correlating their BSSIDs with known visible siblings.
- **Packet Dashboard:** Visualizes real-time beacon, data, injection, and deauthentication packet rates.

### Attacks & Captures
- **WPA/WPA2 Handshakes:** Passive sniffing and targeted deauthentication; validates crackable pairs; exports `.pcap` and `.hc22000` files.
- **PMKID Harvesting:** Active association harvest and passive sniffing for WPA/WPA2 PMKID key material (`.hc22000`).
- **EvilTwin WPA3 Downgrade:** Clones the AP and evicts clients (via CSA, BTM, and de-auths) to capture handshakes. Works on single and multiple cards.
- **WPS Recovery Suite:**
  - **PixieDust (2 Modes):** Instant offline PIN recovery exploiting *Null Secret* and *Static Secret* PRNG weaknesses.
  - **PushButton (PBC):** Detects physical WPS button presses and immediately extracts the plaintext WPA PSK.
  - **PIN Brute-Force:** Resumable WPS PIN cracking with known-PIN database and AP lock monitoring.
- **WEP Suite:** Pure Python ARP replay, ChopChop, Fake Authentication, and PTW key recovery.

## Screenshots

| Scanner | Focus (single target) |
|---|---|
| ![Scanner](assets/wifit3-2-scanner.png) | ![Focus](assets/wifit3-3-focus-handshake.png) |

## Supported Hardware

> **Important:** *At least one supported adapter is required — a USB dongle (any platform) or a PCIe/M.2 card (Linux only).*

### USB adapters (Linux, Windows, macOS)

| Chipset | Bands | Cards (Make + Model) |
|---|---|---|
| Atheros AR9271 | 2.4 GHz | ALFA AWUS036**NHA**, TP-Link TL-WN722N V1 |
| MediaTek MT7601U | 2.4 GHz | Generic unbranded "nano" dongles |
| MediaTek MT7610U | 2.4 / 5 GHz | ALFA AWUS036**ACHM**, Panda PAU0B |
| MediaTek MT7612U | 2.4 / 5 GHz | ALFA AWUS036**ACM** |
| MediaTek MT7921AU | 2.4 / 5 GHz | ALFA AWUS036**AXM[L]**, Panda PAU0F |
| MediaTek MT7925U | 2.4 / 5 GHz | Netgear A9000 |
| Realtek RTL8812AU | 2.4 / 5 GHz | ALFA AWUS036**ACH** |
| Realtek RTL8814AU | 2.4 / 5 GHz | ALFA AWUS1900, ASUS USB-AC68 |
| Realtek RTL8821AU | 2.4 / 5 GHz | ALFA AWUS036**ACS**, TP-Link Archer T2U Plus/Nano |
| Realtek RTL8821CU | 2.4 / 5 GHz | Auscoumer 600 Mbps, Mercusys MU6H |
| Realtek RTL8922AU | 2.4 / 5 GHz | ASUS USB-BE93 |
| Realtek RTL8822BU | 2.4 / 5 GHz | TP-Link T3U Plus, Archer T4U v3 / T4U+ |
| Realtek RTL8822CU | 2.4 / 5 GHz | D-Link AC13U |
| Realtek RTL8187L | 2.4 GHz | ALFA AWUS036**H** |
| Realtek RTL8188EUS | 2.4 GHz | TP-Link TL-WN722N v2/v3, Mercusys MW150US |
| Realtek RTL8188FTV | 2.4 GHz | Generic unbranded dongles |
| Realtek RTL8192FU | 2.4 GHz | D-Link AN3U rev. A1 |
| Ralink RT2570 | 2.4 GHz | Buffalo Nintendo Wi-Fi USB Controller |
| Ralink RT3070 | 2.4 GHz | ALFA AWUS036**NH**, TP-Link TL-WN7200ND |
| Ralink RT5370 | 2.4 GHz | LOTEKOO 150 Mbps |
| Ralink RT5372 | 2.4 GHz | Panda PAU05/PAU06 |
| Ralink RT5572 | 2.4 / 5 GHz | Panda PAU09 N600 |

### PCIe / M.2 cards (Linux only)

Driven through the card's in-kernel driver via `nl80211`/`iw` and `AF_PACKET` — not a userspace chip port. The driver hops 2.4 and 5 GHz channels.

| Chipset | Bands | PCI ID |
|---|---|---|
| MediaTek MT7922 | 2.4 / 5 GHz | `14c3:7922` |
| MediaTek MT7921E | 2.4 / 5 GHz | `14c3:7961` |
| MediaTek MT7921K | 2.4 / 5 GHz | `14c3:0608` |

Breakdown of each USB device's capabilities and limitations: [Supported Hardware Doc](docs/SUPPORTED-HARDWARE.md).

## Installation & Running

### Option 1: Download Prebuilt Binaries (Recommended)
Download the latest standalone executable from [**Releases**](https://github.com/K4kt00z/wifit3/releases/latest):

* **Windows:** Download and run `wifit3-windows-x64.exe`.
* **Linux (non-sudo):** `chmod +x wifit3-linux-x64 && ./wifit3-linux-x64`
* **macOS:** (bypass quarantine)
  ```bash
  xattr -d com.apple.quarantine wifit3-macos-universal2
  chmod +x wifit3-macos-universal2
  ./wifit3-macos-universal2
  ```

> The PCIe/M.2 (Linux netdev) backend is available only in the Linux builds; the Windows and macOS builds drive USB adapters only.

### Option 2: Run from Source
wifit3 uses Astral's [`uv`](https://docs.astral.sh/uv/). `sync` sets up dependencies:
```bash
uv sync
uv run wifit3
```

### Option 3: Build your own binary
```bash
uv run pyinstaller wifit3.spec --noconfirm --clean
```
Binary executable is written to `dist/` subdirectory.

## One-Time Driver Setup

wifit3 automatically handles hardware configuration within the app, after clicking the `START` button:

- **Linux (USB):** Prompts once via `pkexec`/`sudo` to write udev permissions and blocklists in `/etc/modprobe.d/`.
- **Linux (PCIe/M.2):** No install step — the card keeps its in-kernel driver. wifit3 switches it to monitor mode with `iw` (prompting once for root via `pkexec`/`sudo`) and restores it to NetworkManager on exit.
- **macOS:** No installation required; plug in the device and select *Allow* in the authorization dialog.
- **Windows:** Prompts once via UAC to install WinUSB for the device.
- **VirtualBox:** Add your device(s) to VirtualBox's `USB Filters` *before* plugging in.

## Uninstalling
Return the previously-installed device to your operating system's Wi-Fi stack:

1. Select the card on the wifit3 splash screen.
2. Click the `Uninstall` button and confirm.
3. Accept the elevation prompt (UAC on Windows or `pkexec` on Linux).
4. Unplug and re-plug the adapter.

On Linux, this deletes wifit3's `udev` and `modprobe` rules.
On Windows, this uninstalls the WinUSB binding, and triggers a PnP device rescan (old driver reattaches).

## *Thank you, Linux!*

wifit3 only exists because of the great people who reverse-engineered and maintained these Linux wireless
drivers. It's usually a thankless job.

Special thanks to:
- **Christian "kimo" B. ([@kimocoder](https://github.com/kimocoder))** who maintains **wifite2** and `aircrack-ng`'s RTL8188EUS DKMS driver.
- [**Neur0sp1cy**](https://github.com/neur0sp1cy): Close friend and the master to my Linux & wireless-hacking apprenticeship.
- **Nick Morrow** ([@morrownr](https://github.com/morrownr)), legend, maintains the out-of-tree Realtek USB
  DKMS drivers.

The full list is in **[CREDITS.md](docs/CREDITS.md)**.

## How it Works

### USB adapters: userspace mini-drivers

For USB adapters, wifit3 bypasses the operating system's native Wi-Fi stack entirely. It ships with lightweight Python ports of Linux kernel drivers ([src/wifit3/chips/\*](src/wifit3/chips)) that directly control the device over USB bulk and control transfers.

Because register-level frame injection and monitor mode are performed entirely in user space, Windows NDIS restrictions and Linux kernel driver locking do not apply. This path is cross-platform (Linux, Windows, macOS).

### PCIe / M.2 cards: Linux netdev backend

PCIe and M.2 cards take a different route — there is no userspace chip port. The `LinuxNetdevDriver` keeps the card's in-kernel driver loaded and rides it: it switches the interface to monitor mode with `nl80211`/`iw`, captures and injects raw 802.11 frames over an `AF_PACKET` socket, and parses radiotap headers for RSSI. Because it relies on the kernel driver, `iw`, and (when present) `nmcli`, this backend is **Linux only**.

For architecture details, driver porting methodology, and USB trace replay tooling, see the [Porting Documentation](docs/porting/METHODOLOGY.md) and the [PCIe/netdev design notes](docs/planning/PCIE-NETDEV-PORTING.md).

## License & Disclaimer

**Code:** Licensed under [**GNU General Public License v2.0**](LICENSE) (matching upstream Linux drivers).

**Firmware:** Vendor firmware blobs loaded onto adapters are redistributed verbatim under their respective manufacturers' licenses (details in [FIRMWARE.md](docs/FIRMWARE.md)).

**⚠️ Notice & Disclaimer:** For use only on networks and equipment you own or are explicitly authorized to audit. wifit3 operates directly on USB hardware registers (and, for PCIe/M.2 cards, the kernel's raw monitor interface) without the usual OS Wi-Fi guardrails; use at your own risk.
