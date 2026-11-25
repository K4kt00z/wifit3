# Ohigashi-Morii TKIP MITM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Ohigashi-Morii TKIP attack: a two-radio transparent repeater that proxies a genuine client↔AP session, then runs the existing Beck-Tews recovery from the MITM position — hitting TKIP APs that lack the WMM/QoS precondition.

**Architecture:** Reuse the Beck-Tews core (`crack/tkip_beck_tews.py`, `dot11/michael.py`, `dot11/tkip.py`, `campaigns/tkip/inject.py`) and EvilTwin's `beacon_clone`/`Punter` to establish a same-BSSID twin on a decoy channel. A new transparent-repeater relay forwards the real session across two interfaces; a MITM chop driver feeds the Beck-Tews walk through a client-facing MIC-failure oracle (no QoS TID bypass). Output is the unchanged `Recovered` → forge/inject/capture/modal.

**Tech Stack:** Python 3, asyncio, PyUSB userland stack, Textual TUI, uv/pytest.

**Spec:** `docs/superpowers/specs/2026-11-23-ohigashi-morii-design.md`

## Global Constraints

- Native pure-Python; **no new cryptography** — reuse Beck-Tews recovery/Michael/TKIP/forge verbatim.
- Core-engine import rule: `dot11/`/`crack/` import nothing from `ui/`/`vault/`/`persist/`/`campaigns/`. New code is app-layer under `campaigns/tkip_mitm/`.
- **Two DISTINCT interfaces required** — the campaign raises if `twin_iface is punt_iface`; the EvilTwin single-card fallback must not be silently accepted.
- **`FakeAP`'s responder is NOT reused** (it fabricates a local session). Only `beacon_clone` + `Punter` + the `EvilTwinInput` two-interface shape are reused from the EvilTwin stack.
- Code style: docstrings on PUBLIC APIs only, ≤2 lines; NO comments on private helpers; intention-revealing names. **Never run `ruff format`**; use `ruff check`.
- Tests: `uv run pytest`; no hardware in CI; `asyncio_mode = "auto"`. The live two-radio repeater pump + on-wire timing are **hardware-validated, not CI-tested** — only pure cores and seam-driven logic are unit-tested.
- 6 pre-existing `tests/ui/test_mobile_viewport.py` `_WpaHost.guessid` failures are known/unrelated; the failing set must stay exactly those 6.

## Review Focus

- **Single-card input (`twin_iface is punt_iface`):** campaign must raise a clear error, not silently fail to hold two channels. → test in Task 4.
- **No-WMM TKIP AP + client:** pre-check must return attackable on the MITM path (the whole point). → test in Task 1.
- **CCMP/GCMP-only (no TKIP):** not attackable; campaign not visible. → test in Task 1 + Task 4.
- **AP rekey mid-walk:** `MitmChopDriver` aborts with a clear reason, not spinning. → test in Task 3.
- **Unrecognized frame type at the relay:** a sensible default (drop) rather than a crash/KeyError. → test in Task 2.

---

### Task 1: WMM-relaxable pre-check

**Files:**
- Modify: `src/wifang/campaigns/tkip/precheck.py` (`assess`)
- Test: `tests/campaigns/tkip/test_precheck.py` (extend)

**Interfaces:**
- Produces: `assess(ap, has_client: bool, *, require_wmm: bool = True) -> Verdict` — when `require_wmm=False`, a TKIP AP (pairwise or group) with a client is attackable even if `ap.wmm` is False; direction precedence and all other gating unchanged.

- [ ] **Step 1: Write failing tests**

```python
def test_no_wmm_attackable_when_wmm_not_required():
    v = assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True, require_wmm=False)
    assert v.attackable is True and v.direction == "pairwise"

def test_no_wmm_still_blocked_by_default():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True).attackable is False

def test_ccmp_only_not_attackable_even_without_wmm_requirement():
    assert assess(ap(pairwise="CCMP", group="CCMP", wmm=False), has_client=True, require_wmm=False).attackable is False

def test_no_client_not_attackable_mitm_path():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=False, require_wmm=False).attackable is False
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/campaigns/tkip/test_precheck.py -v`.
- [ ] **Step 3: Implement** the `require_wmm` keyword: gate the WMM check on it; everything else unchanged. Keep the default `True` so existing callers/tests are unaffected.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip): WMM-relaxable pre-check for the MITM path`.

---

### Task 2: Transparent-repeater frame decision + rewrite (pure core)

**Files:**
- Create: `src/wifang/campaigns/tkip_mitm/__init__.py`, `src/wifang/campaigns/tkip_mitm/relay.py`
- Test: `tests/campaigns/tkip_mitm/test_relay.py`

**Interfaces:**
- Produces:
  - an enum/str `RelayAction` with members `FORWARD`, `DROP`, `WITHHOLD_SEED`;
  - `relay_decision(frame: bytes, *, from_client: bool, seed_captured: bool) -> RelayAction` — classifies a frame by 802.11 type/subtype: management (auth/assoc/probe) and EAPOL-Key and data → FORWARD to the other side to sustain the genuine session; the one captured TKIP data seed frame (when `seed_captured` and it matches the seed) → WITHHOLD_SEED so the client's TSC is not consumed; unrecognized/malformed → DROP (never raise).
  - `rewrite_for_other_side(frame: bytes, *, to_channel: int) -> bytes` — pass through unchanged on-air addressing (same BSSID both sides), adjusting only what the two-channel relay requires; returns the bytes to transmit on the far interface.

- [ ] **Step 1: Write failing tests**

```python
def test_eapol_and_assoc_forwarded():
    assert relay_decision(assoc_req_frame(), from_client=True, seed_captured=False) == RelayAction.FORWARD
    assert relay_decision(eapol_key_frame(), from_client=False, seed_captured=False) == RelayAction.FORWARD

def test_seed_frame_withheld_from_client():
    assert relay_decision(the_seed_frame(), from_client=False, seed_captured=True) == RelayAction.WITHHOLD_SEED

def test_unrecognized_frame_dropped_not_raised():
    assert relay_decision(b"\x00\x01", from_client=True, seed_captured=False) == RelayAction.DROP  # Review Focus

def test_rewrite_preserves_bssid():
    out = rewrite_for_other_side(data_frame(bssid=BSSID), to_channel=6)
    assert out[a:b] == BSSID  # addr fields unchanged
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** `relay_decision` (parse FC type/subtype via the existing `dot11` header helpers; guard length; default DROP) and `rewrite_for_other_side`. Pure, no I/O.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip-mitm): transparent-repeater frame decision + rewrite`.

---

### Task 3: MITM chop driver

**Files:**
- Create: `src/wifang/campaigns/tkip_mitm/chop.py`
- Test: `tests/campaigns/tkip_mitm/test_chop.py`

**Interfaces:**
- Consumes: Task 2 relay types; `crack/tkip_beck_tews.py` `BeckTewsWalk(cipher, known_plaintext_prefix, *, da, sa, priority, tsc)` with `.done/.bytes_done/.next_guess_frame()/.on_oracle(bool)/.recovered`; `campaigns/tkip/inject.py` guess building; the parser `mic_failure` flag.
- Produces: `MitmChopDriver(iface, cipher, prefix, *, da, sa, priority, tsc, probe=None, should_stop=None, probe_timeout=0.5)` with `async run() -> Optional[Recovered]`, `.recovered`, `.abort_reason` ("AP rekeyed" or None), `.bytes_done`. Default `probe` emits a guess on the client-facing `iface` and awaits the client's `mic_failure` report; injectable for tests. Rekey observed (a 4-way/group handshake EAPOL) → abort with reason, like `TkipChop`.

- [ ] **Step 1: Write failing tests**

```python
async def test_mitm_walk_via_boolean_oracle():
    # probe returns True only on the correct trailing byte; assert recovery completes,
    # one fired guess per byte, no QoS TID involved.

async def test_mitm_aborts_on_rekey():
    # feed a group-rekey EAPOL during the walk; assert abort_reason == "AP rekeyed".  # Review Focus
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** `MitmChopDriver` mirroring `campaigns/tkip/chop.py`'s `TkipChop` structure (register_rx_callback, injectable probe, rekey watch), but the probe sends straight to the client (no spare-TID logic) — reuse the Beck-Tews synthetic-frame oracle pattern for the test.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip-mitm): MITM Beck-Tews chop driver`.

---

### Task 4: OhigashiMoriiCampaign

**Files:**
- Modify: `src/wifang/campaigns/tkip_mitm/__init__.py` (export `OhigashiMoriiCampaign`)
- Create: `src/wifang/campaigns/tkip_mitm/campaign.py`, `src/wifang/campaigns/tkip_mitm/README.md`
- Test: `tests/campaigns/tkip_mitm/test_campaign.py`

**Interfaces:**
- Consumes: Task 1 `assess(..., require_wmm=False)`; Task 2 relay; Task 3 `MitmChopDriver`; `campaigns/eviltwin` `beacon_clone`, `Punter`, and the `EvilTwinInput`-shaped two-interface input; `Campaign` ABC; `forge_tkip_frame`.
- Produces: `OhigashiMoriiCampaign(Campaign)` — `key="tkip-mitm"`, `button_id="btn-tkip-mitm"`, `hotkey=("m","MITM")`, `idle_label="MITM"`; `__init__(array, target, mitm_input)` **raises `ValueError` if `mitm_input.twin_iface is mitm_input.punt_iface`**; classmethods `visible(cls, ap)` (TKIP pairwise/group present) and `ineligible_reason(cls, ap)` (the `assess(require_wmm=False)` reason); `_loop` establishes the twin + punt, runs the relay + `MitmChopDriver`, holds `.recovered`/`.direction`/`.client_mac`/`.abort_reason`; status_* lines.

- [ ] **Step 1: Write failing tests**

```python
def test_rejects_single_card_input():
    import pytest
    one = object()
    with pytest.raises(ValueError):
        OhigashiMoriiCampaign(array, ap(pairwise="TKIP", group="TKIP"), mitm_input(twin=one, punt=one))  # Review Focus

def test_visible_only_for_tkip():
    assert OhigashiMoriiCampaign.visible(ap(pairwise="TKIP", group="TKIP")) is True
    assert OhigashiMoriiCampaign.visible(ap(pairwise="CCMP", group="CCMP")) is False
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the campaign mirroring `EvilTwinCampaign` (same-BSSID `beacon_clone`, `Punter`, two-iface input) and `campaigns/tkip/campaign.py` (visible/ineligible via `assess`, capability held for the modal, single-TX discipline). The live relay pump wiring is structural; keep the driver seam injectable. Short human-facing README.
- [ ] **Step 4: Run to verify pass** (+ full `uv run pytest`, failing set still exactly the 6 known).
- [ ] **Step 5: Commit** — `feat(tkip-mitm): Ohigashi-Morii campaign (two-radio MITM)`.

---

### Task 5: Focus UI wiring

**Files:**
- Modify: `src/wifang/ui/focus_model.py` (`BUTTON_CAMPAIGNS`), `src/wifang/ui/screens/focus_v2/screen.py` (button registries, `_start_tkip_mitm`/`_on_tkip_mitm_input` mirroring `_start_eviltwin`/`_on_eviltwin_input`, `_finish_tkip_mitm` reap, Bindings), `src/wifang/ui/screens/focus_v2/campaign_controls.py` (a bespoke `elif` branch, required)
- Test: `tests/ui/test_tkip_mitm_wiring.py`

**Interfaces:**
- Consumes: Task 4 `OhigashiMoriiCampaign`; the existing EvilTwin two-interface input modal (reused for interface election); the existing TKIP injection modal (reused for output).

- [ ] **Step 1: Write failing tests** — assert `"tkip-mitm"` in `focus_model.BUTTON_CAMPAIGNS` and the `screen` button registries; assert `campaign_controls.start` has a branch constructing `OhigashiMoriiCampaign` with the two-iface input (not the generic `(array, ap, log=)` form).
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the wiring mirroring EvilTwin's button + modal-push/callback + `campaign_controls` branch, plus the reap handler. Button CSS in the screen `CSS`, not `app.py`.
- [ ] **Step 4: Run to verify pass** (full suite; failing set still exactly the 6 known).
- [ ] **Step 5: Commit** — `feat(ui): Ohigashi-Morii MITM attack button + interface/injection modals`.

---

## Self-Review

**1. Spec coverage:** WMM-relaxed pre-check (T1) ✓; transparent-repeater frame decision/rewrite + unrecognized-frame-safe (T2) ✓; MITM chop driver reusing BeckTewsWalk via client-facing oracle + rekey-abort (T3) ✓; campaign with hard distinct-interface guard, beacon_clone/Punter reuse, visible/ineligible via assess, capability-for-modal (T4) ✓; UI button + reused interface/injection modals + required campaign_controls branch (T5) ✓. Non-goals (no FakeAP responder reuse, no new crypto, no L3 interception, live pump hardware-pending) are respected by construction. The live two-radio relay pump is intentionally not CI-tested (spec constraint).

**2. Step scan:** Bodies appear only as test assertions and the one relay-decision classification the signature doesn't fully pin; other code steps are signature + file + "mirror X". No decide-nothing lines.

**3. Type consistency:** `assess(..., require_wmm=)` (T1) consumed in T4; `RelayAction`/`relay_decision`/`rewrite_for_other_side` (T2) consumed in T3/T4; `MitmChopDriver(...)` (T3) consumed in T4; `OhigashiMoriiCampaign` key/button_id/hotkey stable T4→T5. `Recovered` reused from the merged Beck-Tews core.

**4. Review Focus:** all five lines have an owning task's test (T4, T1, T1/T4, T3, T2).

**5. Proportion:** Plan is comparable to the spec; code blocks are assertions + one classification sketch, not implementations.

## Note for human review

This plan, the spec, and the planned `campaigns/tkip_mitm/README.md` are human-facing docs agents wrote — a human should review wording.
