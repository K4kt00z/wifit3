# TKIP injection attacks (Beck-Tews) — design

Status: approved (2026-11-20) · Date: 2026-11-20 · Approach: A (single-radio
Beck-Tews + group-cipher-downgrade mode; Ohigashi-Morii MITM deferred to a
follow-up project)

## Intent and why

wifit3 has no WPA1/TKIP-specific attacks today. WPA1 is rendered "out of scope"
in the UI, PMKID is hidden for it, and the only path that touches a WPA1-PSK AP
is the generic deauth→handshake→offline-crack ladder, which reaches WPA1 only
because the WPA vendor-IE PSK selector maps to the same `AKM_PSK` value as RSN.

The user wants **real injection capability in the field** against TKIP: the
ability to forge and inject frames onto a live TKIP-protected network without
the passphrase. That capability is exactly what the Beck-Tews attack (2008)
delivers, and it also applies to the large installed base of *mixed* WPA/WPA2
APs whose **group cipher is downgraded to TKIP** even when the pairwise cipher
is CCMP — broadcast/multicast on those networks is TKIP-protected and therefore
attackable in the AP→station (GTK) direction.

This is an authorized-auditing capability for a security-auditing tool, in the
same family as the WEP, WPS, PMKID, and EvilTwin campaigns already shipped.

## What the attack actually is (so the builder scopes it correctly)

Beck-Tews is **not** passphrase recovery and **not** full traffic decryption.
Against a captured short known-plaintext frame (an ARP) it recovers:

1. the frame's **keystream** for its TSC/IV, and
2. the **Michael MIC key** for one traffic direction (AP→STA or the GTK
   broadcast direction),

by chopping the frame byte-by-byte (CRC32/ICV fix-up is linear, identical to the
existing WEP chopchop) and using the **client's Michael MIC-failure report** as
the oracle. Crucial direction note: the forged guess frame is replayed toward
the *receiver* of the captured AP→STA (or GTK broadcast) frame — the associated
**client**. A wrong ICV is silently dropped; a correct-ICV guess passes the ICV
check, fails Michael, and makes the **client** emit an EAPOL-Key MIC-failure
report **to the AP**, which the attacker sniffs (client source, AP dest, Key Info
Error+Request+Secure). The AP does not emit it for these directions. The oracle
is therefore a bare **boolean** (failure observed / silence), carrying no guess
value. Michael is invertible, so recovered plaintext+MIC yields the MIC key for
that direction.

Result: the attacker can **forge a small number of short frames** (typically
~7–15, one per unused QoS TID whose TSC counter is behind the captured frame's),
each with a valid Michael MIC and ICV, and inject them — e.g. ARP cache
poisoning / gratuitous ARP (gateway redirect), or a DNS response.

### Preconditions (the campaign must detect and surface these)
- Pairwise **or** group cipher is TKIP (`CIPHER_TKIP`). Group-only TKIP on a
  CCMP-pairwise AP is the "downgrade" target mode, attacking the GTK direction.
- **WMM/QoS** negotiated, with at least one TID queue whose TSC is usable (this
  is what bypasses the TKIP replay counter — the replay window is per-TID).
- At least one **associated client** — it is both the source of the capturable
  short frame (ARP) and, as the receiver of the replayed guesses, the **emitter
  of the MIC-failure oracle**. No client means no attack, not merely no ARP.
  Deauth can provoke a fresh ARP, reusing the existing deauth primitive.
- The AP's **rekey interval** must exceed the attack time. The 802.11 TKIP
  **countermeasure** rule (two Michael failures within 60 s → the AP tears down
  and stalls ~60 s) forces ≤1 guess per 60 s, so recovering ~12 unknown bytes
  takes ~12–15 min. If the AP rekeys sooner, the attack cannot complete; the
  campaign detects this (rekey observed mid-walk) and reports it rather than
  spinning.

None of these are knowable with certainty from a beacon alone; the campaign
reports the ones it *can* see (TKIP, WMM, client present) up front and discovers
rekey-too-fast by failing, surfacing a clear reason.

## Goals
- An **up-front vulnerability pre-check** that assesses attackability from what
  is observable *before* committing the ~12–15 min walk, and surfaces a verdict
  (attackable / not attackable / unknown) with the reason. It checks: TKIP
  present as pairwise or (downgraded) group cipher; WMM/QoS advertised; at least
  one associated client. It cannot know the rekey interval up front, so a
  "looks attackable" verdict is explicitly best-effort — a too-fast rekey is
  still only discovered by the walk failing, and the verdict says so. This gates
  the campaign (feeds `visible()`/`ineligible_reason()`) and is shown to the
  operator so they aren't surprised by a long run against a likely-futile target.
- Native, pure-Python Michael (MIC + inverse), unit-tested offline against
  published Beck-Tews / 802.11i test vectors, matching the `crack/wep.py` ethos
  (no external aircrack).
- A single-radio `campaigns/tkip/` campaign that runs the full Beck-Tews loop
  end-to-end on live hardware: provoke/capture ARP → chop against the MIC-failure
  oracle with 60 s countermeasure pacing → recover keystream + MIC key → expose a
  live **injection session**.
- Group-cipher-downgrade handled as a *target mode* of the same campaign (GTK
  direction), not duplicate code.
- An injection session the operator drives in the field: a canned **ARP-spoof /
  gratuitous-ARP** payload (gateway redirect) plus a **custom raw-payload** entry,
  bounded by the number of recovered TID slots.
- Results persisted as a new capture/record kind (recovered MIC key, keystream,
  TSC, direction, usable TID count) to `captures/`, and surfaced in the Focus UI
  with live progress (bytes recovered, next-guess countdown, countermeasure
  stalls).
- Correct detection/eligibility: a `TkipInject` campaign `visible()` only when a
  TKIP pairwise or group cipher is present; `ineligible_reason()` when WMM is
  absent, no client is present, or the AP is CCMP/GCMP-only.

## Non-goals
- Passphrase/PMK recovery (Beck-Tews does not yield it).
- Full bidirectional traffic decryption.
- Ohigashi-Morii MITM variant — explicitly a **follow-up project** built on this
  core's primitives plus EvilTwin's FakeAP/CSA (most of its relay scaffolding
  already exists; a true two-channel bidirectional relay is the new part and may
  want a second device).
- Unlimited injection — the attack is inherently bounded by recovered TID slots;
  the UI must make that bound explicit, not imply a persistent channel.

## Anti-goals (failure even if it "works")
- Silently triggering TKIP countermeasures in a way that rekeys the AP and
  destroys the in-progress attack without telling the operator why.
- A UI that presents injection as unlimited or as a decrypted-traffic feed.
- Any external-tool dependency (aircrack/tkiptun-ng) — rejected in approach
  selection; breaks the native stack and can't drive the PyUSB interface.

## Constraints
- Core-engine rules: `dot11/` and anything reusable stays generic — no imports
  from `ui/`, `vault/`, `persist/`, `campaigns/`; no wifit3 product concepts.
  Michael lives in `dot11/michael.py`; EAPOL MIC-failure parsing extends
  `dot11/eapol.py` / `dot11/parser.py`.
- Code style per AGENTS.md (public-API docstrings only, ≤2 lines,
  intention-revealing names). Never run `ruff format`.
- All hardware I/O is mockable; the chop loop must be offline-unit-testable the
  way `WepChopChop._probe` is injectable (a `probe(body)->accepted` seam).
- Tests via `uv run pytest`; no hardware required in CI.

## Approaches considered
- **A (chosen).** Single-radio Beck-Tews + group-downgrade mode now, each piece
  reviewed/verified on its own; Ohigashi-Morii as a committed follow-up. Fastest
  path to real single-radio field injection.
- **B (rejected for now).** All three in one shipment incl. the Ohigashi-Morii
  bidirectional relay. Widest coverage but the relay is the riskiest, least
  testable-here part and ~doubles build+review time.
- **C (rejected).** Shell out to aircrack-ng `tkiptun-ng`. Violates the native
  ethos (`crack/wep.py` deliberately avoids external aircrack), won't integrate
  with the driver/injection layer or TUI, can't drive the userland interface.

## The how — decided

### New / changed modules
- Vulnerability pre-check — a pure, side-effect-free assessor (given an
  `AccessPoint` + observed client presence → verdict + reason). Lives with the
  campaign's eligibility logic (`campaigns/tkip/`), reusing the group-cipher and
  WMM fields added below; drives `visible()`/`ineligible_reason()` and the status
  surface. Unit-testable offline on synthetic `AccessPoint` fixtures.
- `dot11/michael.py` — Michael MIC + inverse. Pure spec, no I/O. Tested offline.
- `dot11/parser.py` — inbound EAPOL-Key is already parsed in `_parse_eapol`
  (key_info/mic/nonce/msg_num); add recognition of a **MIC-failure report**
  (Key Info Error `0x0400` + Request `0x0800` + Secure, group key type) on the
  parsed packet so a campaign RX callback can detect it. `_classify_eapol_msg`
  must **not** misfile this as handshake M4 (a MIC-failure report looks like
  ack=0/mic=1/install=0/key_data_len=0) — gate it out of the handshake path.
  `dot11/eapol.py` is build-only today (that's fine; parsing stays in parser.py).
  TKIP key-descriptor version (`HMAC_MD5_RC4`) already present in `eapol.py`.
- `dot11/tkip.py` (or extend an existing module) — TKIP per-packet key mixing
  (Phase 1/2) and TSC/IV handling needed to forge a valid frame from recovered
  keystream + MIC key on a chosen TID. Pure spec, tested offline.
- `crack/` — the keystream + MIC-key recovery bookkeeping (byte-walk state,
  Michael inversion), offline-testable against a synthesized TKIP frame under a
  known key, mirroring `tests/crack/test_wep_crack.py`.
- `campaigns/tkip/` — `__init__.py`, `campaign.py` (orchestrator, owns the
  "one TX activity at a time" rule like WEP), `chop.py` (the MIC-oracle chop
  loop), `inject.py` (build/forge/inject the recovered-capability payloads),
  plus a README. **What transfers from `wep/chopchop.py` and what does not:**
  the `register_rx_callback` tap and the injectable `probe(body)->accepted` seam
  transfer directly. The WEP "identity-by-construction" trick — blast all 256
  guesses in a rolling stream, stamp the guess into the destination MAC, read the
  accepted guess back out of the AP's relayed frame — does **not**, because the
  TKIP oracle is boolean with no value to read back. Instead: serialize guesses
  for a byte position; wrong guesses are silently dropped (no penalty) so they
  can go out at ~RTT spacing, and the first guess that yields a MIC-failure
  report is the byte. Spacing must exceed the report RTT so the single failure
  attributes unambiguously to the in-flight guess. Then wait the countermeasure
  interval before the next byte.
- **Group-cipher-downgrade data path (net-new, ~4 files).** `group_cipher_suite`
  is computed in `RsnElement` (`dot11/rsn.py`, `parser.py:833`) but then
  **discarded** — `_parse_tags` never reads it, `BeaconPacket` has no group field,
  `AccessPoint` has none. The downgrade target mode requires plumbing it through:
  `RsnElement` → `_parse_tags` → `BeaconPacket` → `WlanSink` → `AccessPoint`.
  Pairwise-TKIP detection already works via `ap.pairwise_cipher == "TKIP"`.
- `models/` + `persist/` — a new capture/record kind for a TKIP injection
  capability (not a PSK credential). Concretely: a new `CaptureType` member
  (`models/access_point.py`), a filename branch in `persist/common.py`
  (`LEGACY_CAPTURE_RE`) and `capture_history._parse_file`, a save path in
  `persist/save.py`, and extending `capture_history.summarize()` (today a fixed
  hs/pmkid/wep/psk tuple) so history can badge it.
- `ui/` — a `TkipInject` button + an **interactive injection modal** (operator
  picks canned ARP-spoof vs raw payload, sees slots remaining), following the
  `eviltwin_modal.py` / `decloak_modal.py` / `verify_menu.py` precedent — the
  Campaign base only exposes passive status strings, so the interactive surface
  is a modal, not just a panel. Wiring lives in `ui/focus_model.py`
  (`BUTTON_CAMPAIGNS`) and `focus_v2/screen.py` (`_ATTACK_BUTTONS`,
  `_BUTTON_TIPS`, `_SHORT_BUTTON_LABELS`, `_campaign_toggles`, `on_button_pressed`,
  a `_finish_<key>` reap handler, hotkey Bindings) — **not** `campaign_controls.py`,
  which is only touched if `TkipInject`'s constructor signature differs from the
  generic `(array, ap, log=)` form. Button CSS overrides go in the screen `CSS`,
  not `app.py` (per AGENTS.md).
- `ui/encryption_format.py` — stop treating TKIP-bearing APs as flatly "out of
  scope"; mark TKIP (pairwise or downgraded group) as an attackable target.

### Oracle & pacing (the delicate part)
- Oracle = inbound client-sourced EAPOL-Key MIC-failure report (client→AP),
  read via `register_rx_callback`, attributed to the in-flight guess by send
  ordering/RTT, not inferred from timing alone.
- Pacing is **per recovered byte**, not per guess: wrong guesses are silently
  dropped and incur no countermeasure, so only a *successful* (MIC-failing) guess
  counts toward the 2-in-60 s threshold. Wait the countermeasure interval between
  bytes; detect an observed rekey/teardown and abort with a clear reason.
  (Operator-overridable aggressiveness is a possible later knob, not in scope.)
- TID selection: parse the WMM IE to pick an unused lower-priority TID for the
  TSC bypass; fall back to probing TIDs 1–7 if WMM parameters are unavailable.
  Note: WMM is **not** parsed on the beacon path today (only the QoS Control
  field length is accounted for), so both up-front "WMM present" reporting and
  TID selection need new beacon parsing.

### Output / UX model
- On success the campaign holds a live injection session bounded by recovered TID
  slots. Operator picks a canned ARP-spoof (gateway redirect) or enters a raw
  payload; each injection consumes one slot, and the UI shows slots remaining.
- The recovered material (MIC key, keystream, TSC, direction, TID slots) is saved
  to `captures/` as the new record kind for the record/audit trail. Note this is
  **not** a durably resumable session: the keystream and MIC key die at the next
  GTK/PTK rekey, which (per the preconditions) is only minutes away. Injection is
  expected to happen within the same run; the UI must not imply a persistent
  channel.

## Left to the builder
- Exact on-wire layout matching for the MIC-failure report across AP vendors
  (Key Info bit combinations); confirm against a real capture if one is available,
  else against the 802.11i spec text.
- Precise WMM-IE parsing vs. the TID-probing fallback — builder picks the
  simplest correct form; this does not change the external behavior.
- File/record naming for the new capture kind, consistent with `persist/`
  conventions.
- Whether `dot11/tkip.py` is a new module or an extension of an existing one.

## Testing
- Offline, no hardware: Michael MIC + inverse vectors; TKIP phase-1/2 key-mixing
  vectors; end-to-end recovery against a synthesized TKIP frame under a known key
  (assert keystream + MIC key recovered), mirroring the WEP crack test.
- Campaign chop loop driven through the injectable `probe`/oracle seam with a
  simulated receiver (correct-ICV→client MIC-failure report, wrong-ICV→silent
  drop, countermeasure on 2-in-60 s), asserting the byte-walk, guess-attribution,
  per-byte pacing, and rekey-abort paths.

## Note for human review
This spec and the new `campaigns/tkip/README.md` are human-facing docs; a human
should review the wording.
