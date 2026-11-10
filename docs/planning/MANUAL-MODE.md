# Manual Mode + airgeddon feature parity (planning stub)

Status: **not started.** Scope/plan only. Start a fresh session (this one was context-bound).
First task in that session: run the brainstorming skill to pin the manual-mode flow before code.

## Goal

Two separable layers — do them in order, don't conflate:

1. **Manual mode** (bounded first increment): an airgeddon-style free-navigation path in the TUI —
   pick interface → scan → pick target(s) → pick attack → run — instead of only the automated
   campaign flow. Reuses the existing drivers/campaigns underneath; it's a UX layer, not new attacks.
2. **Feature parity** (big, phased): close gaps vs airgeddon, one attack family per increment.

## What wifit3 already has (confirm before building — from AGENTS.md)

- Campaigns: `AutoDeauth`, PMKID harvest, WPS PIN, WEP/Replay, `EvilTwin` (`src/wifit3/campaigns/`).
- Cracking: `vault/` + `tools/` (hashcat), `crack/` (WPA PSK, WEP, hc22000).
- Screens: Splash (adapter pick) → Scanner (live AP table, hopping) → FocusViewV2 (single AP).
- Drivers incl. the new Linux netdev (PCIe/M.2) backend.

So this is **fill-the-gaps + a manual UX**, not a from-scratch port.

## Manual mode — design sketch (verify against real screens)

The Scanner→Focus screens already do target selection + per-AP actions. Manual mode likely =
making that flow fully user-driven and exposing every attack as an explicit menu action, rather
than the campaign auto-picking. Open questions for brainstorming:

- Is manual mode a new top-level screen, or a "mode" toggle on Scanner/Focus (auto vs manual)?
- Multi-target selection (airgeddon does one target at a time; wifit3 scans many).
- Where do attack params (deauth count, channel, WPS pin, wordlist) get entered — modal per attack?
- Interface/band selection, 2.4/5 GHz, regdomain set (`iw reg set`) — airgeddon exposes these.

## airgeddon → wifit3 gap list (triage; ✓ exists, ~ partial, ✗ missing)

| airgeddon feature | wifit3 | Notes |
|---|---|---|
| Monitor mode on/off, iface mgmt | ✓ | drivers + setup/ |
| DoS: deauth (aireplay/mdk4), multiple methods | ~ | AutoDeauth exists; expose methods/params manually |
| Handshake capture | ✓ | capture + persist |
| PMKID capture | ✓ | PMKID harvest campaign |
| WPS: pixie-dust, bully/reaver, PIN DB, bruteforce | ~ | WPS PIN exists; check pixie-dust + PIN DB coverage |
| WEP all-in-one | ~ | WEP/Replay campaign |
| Evil Twin: captive portal, sniffing, BeEF, DoS pairing | ~ | EvilTwin exists; portal/BeEF variants likely missing |
| WPA/WPA2 Enterprise (hostapd-wpe) | ✗ | likely missing |
| Offline crack: aircrack/hashcat/john, rules | ~ | hashcat via vault; aircrack/john? |
| Handshake/PMKID cleaning + decrypt | ~ | crack/ has checks; decrypt-to-plaintext? |
| 5/6 GHz support | ~ | netdev driver tunes 5 GHz; regdomain gating |
| DoS: beacon flood, auth DoS, WIDS (mdk4) | ✗ | likely missing |

(Marks are best-guess from AGENTS.md — the fresh session must grep `campaigns/` to confirm each.)

## Build order (proposed)

1. Brainstorm + spec manual-mode flow → `docs/planning/` spec.
2. Manual mode UX over existing Scanner/Focus (no new attacks).
3. Per-increment: pick one ✗/~ attack family, port it as a campaign + manual action + tests.

## Constraints

- Keep attack logic in `campaigns/`, netdev-specific code confined to `chips/netdev/` (don't bleed
  into core — the fork's upstream-sync stays cheap that way).
- Every new attack family: tests (USB mocked; no hardware needed) + a live smoke on MT7922.
- Recover a wedged PCIe card mid-session: `scripts/recover_netdev.py`.
