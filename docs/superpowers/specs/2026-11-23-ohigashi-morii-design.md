# Ohigashi-Morii TKIP MITM attack — design

Status: approved-by-opt-out (2026-11-23; human let the scope be chosen) · Approach: A
(two-radio MITM repeater reusing EvilTwin scaffolding + the Beck-Tews core)

## Intent and why

The Beck-Tews attack already on the branch recovers a TKIP keystream + Michael MIC key,
but only against APs that advertise **WMM/QoS** — it relies on injecting chopchop guesses
on a spare QoS TID whose TSC replay counter is behind the captured frame's. Many real
TKIP APs (especially older WPA1-only gear) do **not** advertise WMM, so that path can't
touch them.

Ohigashi-Morii (2009) removes the WMM requirement by putting the attacker **between** the
client and the AP as a channel-based man-in-the-middle. From that position the attacker
sends chopchop guesses straight to the client and reads the client's Michael MIC-failure
reports, while **withholding the captured frame from the client** so its TSC is never
consumed — so no spare QoS queue is needed, and recovery is faster. The user wants this to
widen coverage to no-WMM TKIP APs, keeping the same injection payoff.

## What it is (and what it reuses)

The attacker impersonates the target AP's BSSID on a **different channel** and moves the
real client onto it (CSA punt), while keeping a link to the **real AP on its own channel**.
It relays association/key traffic so the client stays usable, then runs the existing
Beck-Tews byte-walk against the client directly.

Reused as-is (from `campaigns/eviltwin/`): two-interface election (`EvilTwinInput`:
`twin_iface` on the decoy channel, `punt_iface`), `beacon_clone` (same-BSSID twin beacon on
the decoy channel), `Punter` (CSA/deauth/BTM eviction), and `FakeAP`'s beacon + probe/auth/
assoc responder and per-client state. Reused from the TKIP work: `BeckTewsWalk`/`recover`
(crack/tkip_beck_tews.py), `dot11/michael.py`, `dot11/tkip.py`, the `mic_failure` oracle
flag (dot11/parser.py), `forge_tkip_frame`/`arp_spoof_plaintext` (campaigns/tkip/inject.py),
the `TKIP_INJECT` capture kind, and the injection modal.

## Goals
- A new campaign (`campaigns/tkip_mitm/`) that establishes the two-radio MITM position by
  reusing `EvilTwinInput` + `beacon_clone` + `Punter` + `FakeAP`, with the twin on the
  **same BSSID** as the target (impersonation, not a decoy SSID).
- A **relay** that forwards the frames needed to keep the punted client associated/alive
  across the two interfaces (client on the decoy channel ⇄ real AP on its channel), enough
  for the attack to proceed — not a general traffic bridge.
- A **MITM chop driver** that runs `BeckTewsWalk` from the MITM position: emit each guess
  to the client on the decoy-channel interface, read the client's `mic_failure` EAPOL-Key
  report as the boolean oracle, and withhold the seed frame from the client so its TSC is
  not consumed — **no QoS/WMM TID bypass**. Keep the `probe` seam injectable for offline
  tests, as `TkipChop` does.
- A pre-check variant for this path that does **not** require WMM (it still needs TKIP +
  a client + a long-enough rekey), reusing `precheck.assess` with WMM relaxed.
- Output unchanged: a `Recovered` → the existing forge/inject/capture/modal, so the operator
  gets the same ARP-spoof / custom-payload injection with slots-remaining.
- Offline tests for the relay frame-rewrite (pure functions) and the MITM chop driver
  (through the injected oracle seam), plus the WMM-relaxed pre-check.

## Non-goals
- Single-radio operation (two interfaces, consistent with EvilTwin).
- Full bulk traffic decryption or a general L2 MITM bridge — only the frames the attack
  needs are relayed.
- Any new cryptography — the recovery, Michael, TKIP mixing, and forge are reused verbatim.
- Changing the Beck-Tews (QoS) campaign — this is an additive sibling.

## Anti-goals (failure even if it "works")
- Silently wedging the victim client's connectivity with no indication (the relay must keep
  it usable enough, and the UI must show MITM state).
- Presenting the capability as full traffic interception — it is the same bounded
  frame-injection payoff as Beck-Tews, reached a different way.
- Firing against a client without confirming the operator targeted it (same authorization
  posture as EvilTwin).

## Constraints
- Core-engine rules: `dot11/`/`crack/` stay generic. New code is app-layer under
  `campaigns/tkip_mitm/`.
- Code style per AGENTS.md (public-API docstrings only ≤2 lines; no private-helper comments;
  intention-revealing names). Never `ruff format`.
- Two interfaces required; election reuses `EvilTwinInput` and its modal path.
- All radio I/O mockable; the chop driver and relay logic are offline-unit-testable via
  injectable seams (`probe`, and a frame-in → frames-out relay function). `uv run pytest`,
  no hardware in CI.
- The live two-radio MITM, channel timing, and real relay behavior are **not** testable in
  CI or in this environment — they are explicitly deferred to live hardware validation, as
  the Beck-Tews on-wire fidelity was.

## Approaches considered
- **A (chosen).** Two-radio MITM repeater reusing EvilTwin's scaffolding + the Beck-Tews
  core, with a minimal relay (keep-alive, not bulk bridge) and a MITM chop driver. Smallest
  net-new surface; leans on code already reviewed and merged.
- **B (rejected).** Single-radio channel-hopping MITM. Fragile timing, can't hold two
  channels reliably, and out of the chosen scope.
- **C (rejected).** Full L2 bridging / traffic interception between client and AP. Large,
  risky, far beyond the attack's needs, and overlaps a different feature class.

## The how — decided

### New modules (`campaigns/tkip_mitm/`)
- `__init__.py`, `campaign.py` — `OhigashiMoriiCampaign(Campaign)`: builds the same-BSSID
  twin via `beacon_clone`, elects interfaces via `EvilTwinInput`, starts `FakeAP` + `Punter`
  to move the client to the decoy channel, holds the recovered capability for the modal.
  Owns the single-TX-per-radio discipline.
- `relay.py` — the keep-alive relay: a pure frame-rewrite core (given a frame seen on one
  side, produce the frame(s) to emit on the other — BSSID/channel/seq handling) behind an
  async driver that pumps between the two interfaces. Pure core is unit-tested; the pump is
  thin.
- `chop.py` — `MitmChopDriver`: drives `BeckTewsWalk` with a `probe` that emits a guess to
  the client on the decoy-channel iface and awaits the client's `mic_failure` report; it
  withholds the seed frame from the client (so the TSC stays unused) instead of using a QoS
  TID. Injectable `probe` seam for offline tests; rekey-abort like `TkipChop`.
- `precheck.py` (or extend `campaigns/tkip/precheck.py`) — `assess_mitm(ap, has_client)`:
  TKIP (pairwise or group) + client required; **WMM not required**.

### UI
A `btn-tkip-mitm` button + reuse of the TKIP injection modal for the output, wired in
`focus_model.py`/`focus_v2/screen.py` beside the existing TKIP and EvilTwin buttons, using
the two-interface election modal EvilTwin already uses. Button CSS in the screen `CSS`.

### Output / persistence
Same `Recovered` → `save_tkip_capability` / `TKIP_INJECT` capture → injection modal. No new
capture kind.

## Left to the builder
- The exact set of frames the relay must forward to keep the punted client associated and
  the attack progressing (association/EAPOL/keep-alive) vs. what can be dropped — the
  minimal viable relay, discovered against the EvilTwin FakeAP state machine.
- The precise MITM sequencing that lets the byte-walk proceed without the QoS/TSC bypass
  (withholding the seed frame from the client; ordering guesses vs. the client's own
  traffic). Internally consistent and offline-testable via the seam; on-wire timing is a
  live-hardware question.
- Whether `OhigashiMoriiCampaign` needs a bespoke `campaign_controls.start()` branch (it
  takes an `EvilTwinInput`-style two-iface input, so likely yes — mirror EvilTwin's).
- Whether to extend `campaigns/tkip/precheck.py` or add a sibling for the WMM-relaxed check.

## Testing
- Offline: relay frame-rewrite vectors (frame in → expected frame out); `MitmChopDriver`
  byte-walk + rekey-abort through the injected oracle (simulated client MIC-failure), reusing
  the Beck-Tews synthetic-frame construction; WMM-relaxed pre-check cases.
- Live (deferred, not in CI): two-radio MITM establishment, CSA punt of a real client, relay
  keep-alive, end-to-end recovery against a no-WMM TKIP AP.

## Note for human review
This spec, the planned `campaigns/tkip_mitm/README.md`, and any human-facing docs are
agent-written — a human should review the wording.
