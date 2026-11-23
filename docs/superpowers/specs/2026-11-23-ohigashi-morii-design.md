# Ohigashi-Morii TKIP MITM attack — design

Status: approved-by-opt-out (2026-11-23; human let the scope be chosen), revised after
builder-check (transparent-repeater correction) · Approach: A (two-radio MITM repeater
reusing `beacon_clone`/`Punter` + the Beck-Tews core)

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
It acts as a **transparent repeater**: the client and the real AP complete a genuine
4-way handshake and exchange traffic *through* the attacker, who forwards 802.11 frames
between the two channels. The attacker never learns the PSK/PTK — it just relays — but from
that position it runs the existing Beck-Tews byte-walk against the client, withholding the
seed frame from the client so its TSC is not consumed (no QoS/WMM TID needed).

**Correction after builder-check — FakeAP is NOT reused as a responder.** EvilTwin's
`FakeAP` terminates auth/assoc and fabricates the first EAPOL messages **locally** (its own
random ANonce; it never contacts a real AP; it deauths stray data frames). That is the wrong
base here: a session the twin fabricates has a MIC key the twin itself chose, so recovering
it is pointless. Ohigashi-Morii requires the client's session to be **genuinely with the
real AP**, so auth/assoc/EAPOL/data must be **proxied through**, not answered locally.
Therefore the **relay is the primary component**, and only `beacon_clone` (the same-BSSID
beacon that draws/holds the client on the decoy channel) is reused from the EvilTwin stack —
plus `EvilTwinInput`'s two-interface *shape* and `Punter` (CSA/deauth/BTM) for the initial
punt. `FakeAP`'s responder/per-client state is replaced by the repeater, not reused.

Reused from the TKIP work (unchanged): `BeckTewsWalk`/`recover` (crack/tkip_beck_tews.py) —
confirmed injection-mechanism-agnostic, so the MITM driver feeds it through a client-facing
probe with no interface change; `dot11/michael.py`, `dot11/tkip.py`, the `mic_failure`
oracle flag (dot11/parser.py), `forge_tkip_frame`/`arp_spoof_plaintext`
(campaigns/tkip/inject.py), the `TKIP_INJECT` capture kind, and the injection modal.

## Goals
- A new campaign (`campaigns/tkip_mitm/`) that establishes the two-radio MITM position by
  reusing `beacon_clone` (same-BSSID twin beacon on the decoy channel), the `EvilTwinInput`
  two-interface shape, and `Punter` for the initial CSA punt — with a **hard requirement
  that the two interfaces are distinct** (enforced in the campaign; the EvilTwin modal's
  single-card fallback must NOT be silently accepted, since MITM needs continuous
  simultaneous presence on two channels).
- A **transparent repeater relay** (the primary component): proxy the client's auth/assoc/
  EAPOL/data between the decoy-channel interface (client side) and the real-AP-channel
  interface, so the client completes a **genuine** TKIP session with the real AP. It owns
  the data/control-plane forwarding decisions — including **withholding the captured seed
  frame from the client** so the seed TSC stays unconsumed. It forwards the session's 802.11
  frames; it does not route, NAT, or read above L2.
- A **MITM chop driver** that runs `BeckTewsWalk` from the MITM position: emit each guess
  to the client on the decoy-channel interface, read the client's `mic_failure` EAPOL-Key
  report as the boolean oracle — **no QoS/WMM TID bypass**. Keep the `probe` seam injectable
  for offline tests, as `TkipChop` does; same rekey-abort.
- A pre-check variant for this path that does **not** require WMM (it still needs TKIP +
  a client + a long-enough rekey): a new kwarg on `precheck.assess` (or a sibling).
- Output unchanged: a `Recovered` → the existing forge/inject/capture/modal.
- Offline tests for the relay frame-rewrite (pure functions), the MITM chop driver (through
  the injected oracle seam), the WMM-relaxed pre-check, and the distinct-interface guard.

## Non-goals
- Single-radio operation (two distinct interfaces required).
- Traffic **decryption**, L3 routing/NAT, or interception above L2 — the repeater forwards
  the session's 802.11 frames to keep the client↔AP session genuine, but reads nothing and
  provides no interception channel. The payoff is the same bounded frame injection as
  Beck-Tews.
- Any new cryptography — recovery, Michael, TKIP mixing, and forge are reused verbatim.
- Changing the Beck-Tews (QoS) campaign — this is an additive sibling.
- Reusing `FakeAP`'s responder (it fabricates a local session — wrong for this attack).

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
  twin via `beacon_clone`, takes an `EvilTwinInput`-shaped two-interface input and
  **raises if the two interfaces are not distinct**, starts the repeater + `Punter` to move
  the client to the decoy channel, then drives the chop and holds the recovered capability
  for the modal. Owns the single-TX-per-radio discipline. Needs its own
  `campaign_controls.start()` branch + a modal-push/callback pair in `screen.py` mirroring
  EvilTwin's `_start_eviltwin`/`_on_eviltwin_input` (this is required, not optional).
- `relay.py` — the **transparent repeater** (primary component): a pure frame-rewrite core
  (frame seen on one side → frame(s) to emit on the other; same BSSID, channel/seq handling,
  and the forward/drop/withhold decision per frame type) behind an async pump between the two
  interfaces. The pure core and the per-frame decision are unit-tested; the live two-radio
  pump and its timing are hardware-validated, not CI-tested.
- `chop.py` — `MitmChopDriver`: drives `BeckTewsWalk` with a `probe` that emits a guess to
  the client on the decoy-channel iface and awaits the client's `mic_failure` report, with
  the seed frame withheld from the client (TSC unconsumed) instead of a QoS TID. Injectable
  `probe` seam for offline tests; rekey-abort like `TkipChop`.
- extend `campaigns/tkip/precheck.py` — add a `require_wmm: bool = True` kwarg to `assess`
  so the MITM path can pass `require_wmm=False` (TKIP + client still required).

### UI
A `btn-tkip-mitm` button + reuse of the TKIP injection modal for the output, wired in
`focus_model.py`/`focus_v2/screen.py` beside the existing TKIP and EvilTwin buttons, using
the two-interface election modal EvilTwin already uses. Button CSS in the screen `CSS`.

### Output / persistence
Same `Recovered` → `save_tkip_capability` / `TKIP_INJECT` capture → injection modal. No new
capture kind.

## Left to the builder
- The exact set of 802.11 frames the repeater forwards to establish and hold a genuine
  client↔AP session (auth, assoc, the full 4-way EAPOL, data) vs. drops, and the per-frame
  rewrite (channel; same BSSID; sequence handling). Minimal viable repeater, discovered
  against the real handshake flow; the pure per-frame decision is unit-testable, the live
  pump is hardware-validated.
- The precise MITM sequencing that lets the byte-walk proceed without the QoS/TSC bypass
  (withholding the seed frame from the client; ordering guesses vs. the client's own
  traffic). Offline-testable via the seam; on-wire timing is a live-hardware question.
- How the repeater interacts with the real AP's rekey (the recovery's rekey-abort must fire
  on the genuine session's rekey, observed through the relay).

## Testing
- Offline: relay frame-rewrite + per-frame forward/drop/withhold decision (frame in →
  expected action/frame out); `MitmChopDriver` byte-walk + rekey-abort through the injected
  oracle (simulated client MIC-failure), reusing the Beck-Tews synthetic-frame construction;
  WMM-relaxed pre-check cases; the distinct-interface guard raising on a single-card input.
- Live (deferred, not in CI): two-radio MITM establishment, CSA punt of a real client, relay
  keep-alive, end-to-end recovery against a no-WMM TKIP AP.

## Note for human review
This spec, the planned `campaigns/tkip_mitm/README.md`, and any human-facing docs are
agent-written — a human should review the wording.
