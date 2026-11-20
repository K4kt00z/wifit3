# TKIP injection attacks (Beck-Tews) — design

Status: proposed · Date: 2026-11-20 · Approach: A (single-radio Beck-Tews +
group-cipher-downgrade mode; Ohigashi-Morii MITM deferred to a follow-up project)

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
existing WEP chopchop) and using the AP's **Michael MIC-failure report** as the
oracle: a wrong ICV is silently dropped; a correct ICV with a wrong Michael MIC
makes the AP emit an EAPOL-Key MIC-failure report. Michael is invertible, so
plaintext+MIC yields the MIC key.

Result: the attacker can **forge a small number of short frames** (typically
~7–15, one per unused QoS TID whose TSC counter is behind the captured frame's),
each with a valid Michael MIC and ICV, and inject them — e.g. ARP cache
poisoning / gratuitous ARP (gateway redirect), or a DNS response.

### Preconditions (the campaign must detect and surface these)
- Pairwise **or** group cipher is TKIP (`CIPHER_TKIP`). Group-only TKIP on a
  CCMP-pairwise AP is the "downgrade" target mode, attacking the GTK direction.
- **WMM/QoS** negotiated, with at least one TID queue whose TSC is usable (this
  is what bypasses the TKIP replay counter — the replay window is per-TID).
- At least one **associated client** generating a capturable short frame (ARP).
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
- `dot11/michael.py` — Michael MIC + inverse. Pure spec, no I/O. Tested offline.
- `dot11/eapol.py` + `dot11/parser.py` — recognize an inbound EAPOL-Key
  **MIC-failure report** (Key Info: Error+Request+Secure, pairwise bit per
  direction), exposed on the parsed packet so a campaign RX callback can detect
  it. TKIP key-descriptor version (`HMAC_MD5_RC4`) already present.
- `dot11/tkip.py` (or extend an existing module) — TKIP per-packet key mixing
  (Phase 1/2) and TSC/IV handling needed to forge a valid frame from recovered
  keystream + MIC key on a chosen TID. Pure spec, tested offline.
- `crack/` — the keystream + MIC-key recovery bookkeeping (byte-walk state,
  Michael inversion), offline-testable against a synthesized TKIP frame under a
  known key, mirroring `tests/crack/test_wep_crack.py`.
- `campaigns/tkip/` — `__init__.py`, `campaign.py` (orchestrator, owns the
  "one TX activity at a time" rule like WEP), `chop.py` (the MIC-oracle chop loop,
  structurally mirroring `wep/chopchop.py`: `register_rx_callback`, injectable
  `probe`, rolling sends, state machine), `inject.py` (build/forge/inject the
  recovered-capability payloads), plus a README.
- `models/` + `persist/` — a new capture/record kind for a TKIP injection
  capability (not a `CaptureType` PSK credential); surfaced in history.
- `ui/screens/focus_v2/` — a `TkipInject` button + status panel (progress,
  countdown, countermeasure stalls, recovered-slot count, inject controls);
  wired in `campaign_controls.py` alongside WEP/EvilTwin/Decloak. Button CSS
  overrides go in the screen `CSS`, not `app.py` (per AGENTS.md).
- `ui/encryption_format.py` — stop treating TKIP-bearing APs as flatly "out of
  scope"; mark TKIP (pairwise or downgraded group) as an attackable target.

### Oracle & pacing (the delicate part)
- Oracle = inbound EAPOL-Key MIC-failure report matched to our injected guess,
  read via `register_rx_callback`, not inferred from timing.
- Conservative default pacing: ≤1 MIC-failing guess per 60 s to stay under the
  countermeasure threshold; detect an observed rekey/teardown and abort with a
  clear reason. (Operator-overridable aggressiveness is a possible later knob,
  not in scope now.)
- TID selection: parse the WMM IE to pick an unused lower-priority TID for the
  TSC bypass; fall back to probing TIDs 1–7 if WMM parameters are unavailable.

### Output / UX model
- On success the campaign holds a live injection session bounded by recovered TID
  slots. Operator picks a canned ARP-spoof (gateway redirect) or enters a raw
  payload; each injection consumes one slot, and the UI shows slots remaining.
- The recovered material (MIC key, keystream, TSC, direction, TID slots) is saved
  to `captures/` as the new record kind so a later session can resume injection
  while the keys remain valid (until the AP rekeys).

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
  simulated AP (correct-ICV→MIC-failure, wrong-ICV→silent-drop, countermeasure
  on 2-in-60 s), asserting the byte-walk, pacing, and rekey-abort paths.

## Note for human review
This spec and the new `campaigns/tkip/README.md` are human-facing docs; a human
should review the wording.
