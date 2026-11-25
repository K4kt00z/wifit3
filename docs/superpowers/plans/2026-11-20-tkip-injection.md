# TKIP Injection Attacks (Beck-Tews) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single-radio Beck-Tews TKIP attack to wifang that recovers a frame's keystream + Michael MIC key from a live network and drives an operator injection session (ARP-spoof default), covering WPA1-TKIP and WPA/WPA2 group-cipher-downgrade targets.

**Architecture:** Pure-spec crypto (`dot11/michael.py`, `dot11/tkip.py`) and an offline-testable recovery core (`crack/tkip_beck_tews.py`) sit under a radio-owning campaign (`campaigns/tkip/`) that mirrors the WEP chopchop's RX-callback + injectable-`probe` seams but drives a boolean MIC-failure oracle with per-byte countermeasure pacing. A vulnerability pre-check gates it; a new capture kind and a Focus modal surface it.

**Tech Stack:** Python 3, `asyncio`, PyUSB userland stack, Textual TUI, `uv`/`pytest`, `pytest-mock`.

**Spec:** `docs/superpowers/specs/2026-11-20-tkip-injection-design.md`

## Global Constraints

- Native pure-Python only; **no** external aircrack/`tkiptun-ng` dependency.
- Core-engine import rule: `dot11/` imports nothing from `ui/`/`vault/`/`persist/`/`campaigns/`; `crack/` stays generic (no app-layer imports).
- Code style (outside `chips/`): public-API docstrings only, ≤2 lines; intention-revealing names. **Never run `ruff format`.**
- Tests: `uv run pytest`; no hardware (all USB/RX/TX mocked); `asyncio_mode = "auto"` (no decorator on async tests).
- Pacing: conservative — ≤1 *MIC-failing* guess per 60 s, paced **per recovered byte**; wrong guesses (silent ICV drop) carry no penalty.
- Oracle: the **client-sourced** EAPOL-Key MIC-failure report (client→AP), Key Info Error `0x0400` + Request `0x0800` + Secure; recovered key is the AP→STA / GTK direction.
- Default injection payload: canned ARP-spoof (gateway redirect) + a custom raw-payload entry.
- Button CSS overrides live in the screen `CSS`, never `app.py`.

## Review Focus

- **CCMP/GCMP-only AP (no TKIP anywhere):** campaign must stay hidden and the pre-check must return "not attackable", not throw. → test in Task 7.
- **Group-only TKIP on a CCMP-pairwise AP (downgrade):** must be detected via the new group-cipher field, since `ap.pairwise_cipher == "TKIP"` is false here. → test in Task 4 and Task 7.
- **No associated client:** pre-check returns "not attackable (no client)" because the oracle emitter is absent, not merely the ARP source. → test in Task 7.
- **AP rekey observed mid-walk:** chop loop aborts with a clear reason instead of spinning for the full duration. → test in Task 9.
- **MIC-failure report vs handshake M4:** a MIC-failure report (ack=0, mic=1, install=0, key_data_len=0) must not be filed as M4 or pollute the handshake registry. → test in Task 3.

---

### Task 1: Michael MIC + inverse (`dot11/michael.py`)

**Files:**
- Create: `src/wifang/dot11/michael.py`
- Test: `tests/dot11/test_michael.py`

**Interfaces:**
- Produces: `michael(key: bytes, data: bytes) -> bytes` (8-byte MIC; `key` is 8 bytes), and `michael_key_from_mic(data: bytes, mic: bytes) -> bytes` (recovers the 8-byte key given known `data` and its `mic`, exploiting Michael's invertible block function).

- [ ] **Step 1: Write failing tests**

```python
def test_michael_matches_known_vector():
    # 802.11i / Beck-Tews reference vector (fill from spec reference).
    assert michael(bytes.fromhex("0000000000000000"), b"").hex() == "82925c1ca1d130b8"

def test_michael_key_recovery_roundtrips():
    key = bytes.fromhex("d55e100510128986")
    data = b"\xaa\xaa\x03\x00\x00\x00\x08\x06arbitrary"
    assert michael_key_from_mic(data, michael(key, data)) == key
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/dot11/test_michael.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement** `michael` (block function b0..b1, the `<<<` rotations and swaps per 802.11i Annex) and `michael_key_from_mic` (run the block function backwards from the MIC over the known data to recover `(l,r)` at the start = the key). Pure functions, no I/O.
- [ ] **Step 4: Run to verify pass** — same command → PASS.
- [ ] **Step 5: Commit** — `feat(dot11): Michael MIC and key inversion`.

---

### Task 2: TKIP per-packet key mixing + TSC (`dot11/tkip.py`)

**Files:**
- Create: `src/wifang/dot11/tkip.py`
- Test: `tests/dot11/test_tkip.py`

**Interfaces:**
- Produces: `tkip_rc4_key(tk: bytes, ta: bytes, tsc: int) -> bytes` (Phase-1 + Phase-2 mixing → the 16-byte per-packet RC4 key), and `tsc_to_iv(tsc: int) -> bytes` (the WEP-seed/IV + extended-IV layout, including the WEP-seed byte and Ext-IV bit).

- [ ] **Step 1: Write failing tests** — assert `tkip_rc4_key` against the 802.11i Phase-1/Phase-2 test vectors (exact TK/TA/TSC → key, values from spec reference); assert `tsc_to_iv` byte layout for a known TSC.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the S-box Phase-1 (`TTAK`) and Phase-2 mixing and the IV layout. Pure functions.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(dot11): TKIP per-packet key mixing`.

---

### Task 3: Recognize inbound MIC-failure report (`dot11/parser.py`, `dot11/packet.py`)

**Files:**
- Modify: `src/wifang/dot11/parser.py` (`_parse_eapol`, `_classify_eapol_msg`), `src/wifang/dot11/packet.py` (`EapolPacket`)
- Test: `tests/dot11/test_parser_mic_failure.py`

**Interfaces:**
- Produces: `EapolPacket.mic_failure: bool` (True when Key Info has Error `0x0400` + Request `0x0800`), and `_classify_eapol_msg` returns `0` for such a frame (not `4`).

- [ ] **Step 1: Write failing tests**

```python
def test_mic_failure_report_flagged_and_not_m4():
    frame = _eapol_key(key_info=0x0400 | 0x0800 | 0x0010, key_data_len=0)  # Error+Request+Secure
    pkt = Dot11Parser.parse(frame)
    assert pkt.mic_failure is True
    assert pkt.msg_num == 0            # must NOT be classified as M4

def test_real_m4_still_classified_m4():
    frame = _eapol_key(key_info=0x0100 | 0x0010, key_data_len=0)  # MIC+Secure, no ACK/Install
    assert Dot11Parser.parse(frame).msg_num == 4
    assert Dot11Parser.parse(frame).mic_failure is False
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — add `mic_failure` to `EapolPacket`; in `_parse_eapol` set it from `key_info & 0x0400 and key_info & 0x0800`; in `_classify_eapol_msg` return `0` when the Error bit is set so a MIC-failure report never reaches the handshake path.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(dot11): detect TKIP MIC-failure report`.

---

### Task 4: Group-cipher plumbing (RsnElement → AccessPoint)

**Files:**
- Modify: `src/wifang/dot11/parser.py` (`_parse_tags`), `src/wifang/dot11/packet.py` (`BeaconPacket`), `src/wifang/wlan/sink.py` (`_on_beacon_frame`), `src/wifang/models/access_point.py` (`AccessPoint`)
- Test: `tests/dot11/test_group_cipher.py`

**Interfaces:**
- Produces: `BeaconPacket.group_cipher: Optional[str]` and `AccessPoint.group_cipher: Optional[str]` ("TKIP"/"CCMP"/… via the existing `_CIPHER_NAMES`), populated from `RsnElement.group_cipher_suite` (already computed, currently discarded).

- [ ] **Step 1: Write failing test**

```python
def test_mixed_ap_exposes_tkip_group_cipher():
    # RSN IE: pairwise CCMP, group TKIP, AKM PSK.
    pkt = Dot11Parser.parse(beacon_with_rsn(pairwise=CIPHER_CCMP, group=CIPHER_TKIP, akm=AKM_PSK))
    assert pkt.pairwise_cipher == "CCMP"
    assert pkt.group_cipher == "TKIP"
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — carry `rsn.group_cipher_suite` through `_parse_tags` into `parsed["group_cipher"]` (named via `_CIPHER_NAMES`), add the field to `BeaconPacket` and `AccessPoint`, and copy it in `WlanSink._on_beacon_frame` where `akm_suites`/`pairwise_cipher` are copied.
- [ ] **Step 4: Run to verify pass** (add a model round-trip assertion that `AccessPoint.group_cipher` is set from the sink).
- [ ] **Step 5: Commit** — `feat: surface RSN group cipher on AccessPoint`.

---

### Task 5: WMM presence + usable TID (`dot11/parser.py`)

**Files:**
- Modify: `src/wifang/dot11/parser.py` (vendor-IE handling in `_parse_tags`), `src/wifang/dot11/packet.py` (`BeaconPacket`), `src/wifang/models/access_point.py`, `src/wifang/wlan/sink.py`
- Test: `tests/dot11/test_wmm.py`

**Interfaces:**
- Produces: `BeaconPacket.wmm: bool` and `AccessPoint.wmm: bool` (True when a WMM Parameter/Info element — OUI `00-50-F2` type `2` — is present).

- [ ] **Step 1: Write failing test** — beacon with a WMM Information element → `pkt.wmm is True`; beacon without → `False`.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — in the existing `tag_id == 221` branch, flag `WPA_OUI` + `oui_type == 2` as WMM; thread the field through packet/model/sink like Task 4.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat: detect WMM/QoS advertisement on beacons`.

---

### Task 6: Beck-Tews recovery core (`crack/tkip_beck_tews.py`)

**Files:**
- Create: `src/wifang/crack/tkip_beck_tews.py`
- Test: `tests/crack/test_tkip_beck_tews.py`

**Interfaces:**
- Consumes: Task 1 (`michael`, `michael_key_from_mic`), Task 2 (`tkip_rc4_key`), and the existing `dot11/wep/crypto.py` (`icv`, `chop_last_byte_and_fixup`, `CRC32_RESIDUE`).
- Produces:
  - `class BeckTewsWalk` with `__init__(self, cipher: bytes, known_plaintext_prefix: bytes)`, `next_guess_frame() -> bytes` (the next candidate body to inject), `on_oracle(fired: bool) -> None` (feed the boolean MIC-failure result for the last candidate), `done -> bool`, `bytes_done -> int`.
  - `recover(cipher, prefix, probe: Callable[[bytes], Awaitable[bool]]) -> Recovered` driving the walk through an injectable async `probe` (returns True on MIC-failure). `Recovered` = `@dataclass(keystream: bytes, mic_key: bytes, tsc: int)`.

- [ ] **Step 1: Write failing tests**

```python
async def test_recovers_keystream_and_mic_key_from_synthetic_tkip_frame():
    # Build a TKIP frame (ARP) under a known TK + MIC key + TSC, then recover via an
    # oracle that fires iff the candidate's trailing byte matches the true plaintext
    # (correct ICV) — mirrors tests/crack/test_wep_crack.py's known-key construction.
    rec = await recover(cipher, KNOWN_ARP16, probe=oracle)
    assert rec.mic_key == true_mic_key
    assert rec.keystream[:16] == xor(cipher[:16], KNOWN_ARP16)

def test_walk_stops_at_known_prefix_floor():
    walk = BeckTewsWalk(cipher, KNOWN_ARP16)
    # feed correct-byte oracle results; assert it never chops into the known prefix
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — byte-walk from the frame tail: emit a candidate per guess, fix the ICV via `chop_last_byte_and_fixup` (CRC32 linear, as WEP), recover `ks[i] = body[i] ^ guess` on a fired oracle; stop at the known-prefix floor; invert Michael over the recovered plaintext+MIC for `mic_key`.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(crack): Beck-Tews keystream + MIC-key recovery`.

---

### Task 7: Vulnerability pre-check (`campaigns/tkip/precheck.py`)

**Files:**
- Create: `src/wifang/campaigns/tkip/__init__.py`, `src/wifang/campaigns/tkip/precheck.py`
- Test: `tests/campaigns/tkip/test_precheck.py`

**Interfaces:**
- Consumes: `AccessPoint.pairwise_cipher`, `.group_cipher` (Task 4), `.wmm` (Task 5).
- Produces: `assess(ap: AccessPoint, has_client: bool) -> Verdict` where `Verdict = @dataclass(attackable: bool, reason: str, direction: str | None)` (`direction` ∈ `{"pairwise", "group", None}`).

- [ ] **Step 1: Write failing tests** (covers Review Focus lines)

```python
def test_ccmp_only_not_attackable():
    assert assess(ap(pairwise="CCMP", group="CCMP", wmm=True), has_client=True).attackable is False

def test_group_tkip_downgrade_attackable_group_direction():
    v = assess(ap(pairwise="CCMP", group="TKIP", wmm=True), has_client=True)
    assert v.attackable is True and v.direction == "group"

def test_pairwise_tkip_attackable():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=True), has_client=True).direction == "pairwise"

def test_no_client_not_attackable():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=True), has_client=False).attackable is False

def test_no_wmm_not_attackable():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True).attackable is False
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — TKIP as pairwise → `direction="pairwise"`; else TKIP as group → `"group"`; require `wmm` and `has_client`; each negative returns a specific `reason`. Note in the docstring the verdict is best-effort (rekey interval unknown up front).
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip): attackability pre-check`.

---

### Task 8: Forge + inject payloads (`campaigns/tkip/inject.py`)

**Files:**
- Create: `src/wifang/campaigns/tkip/inject.py`
- Test: `tests/campaigns/tkip/test_inject.py`

**Interfaces:**
- Consumes: Task 1 (`michael`), Task 2 (`tkip_rc4_key`, `tsc_to_iv`), Task 6 (`Recovered`), `dot11/wep/crypto.py` (`icv`), `dot11/eapol.py` (`data_header`).
- Produces: `forge_tkip_frame(recovered: Recovered, tid: int, plaintext: bytes, *, bssid, client) -> bytes` (valid TKIP data frame: Michael MIC appended, ICV appended, encrypted with the per-packet key for `tid`'s TSC), and `arp_spoof_plaintext(sender_ip, target_ip, sender_mac) -> bytes` (gratuitous/spoofed ARP, the default payload).

- [ ] **Step 1: Write failing tests** — `forge_tkip_frame` output decrypts (under the known TK) back to `plaintext + michael(mic_key, plaintext) + icv`; `arp_spoof_plaintext` has the LLC/SNAP + ARP-reply layout with the given addresses.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the forge (keystream from `tkip_rc4_key`, or reuse `recovered.keystream` when within its length) and the ARP builder.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip): forge injectable TKIP frames; ARP-spoof payload`.

---

### Task 9: Chop-loop campaign (`campaigns/tkip/chop.py`, `campaigns/tkip/campaign.py`)

**Files:**
- Create: `src/wifang/campaigns/tkip/chop.py`, `src/wifang/campaigns/tkip/campaign.py`, `src/wifang/campaigns/tkip/README.md`
- Test: `tests/campaigns/tkip/test_chop.py`, `tests/campaigns/tkip/test_campaign.py`

**Interfaces:**
- Consumes: Task 6 (`BeckTewsWalk`/`recover`), Task 7 (`assess`), Task 8 (`forge_tkip_frame`, `arp_spoof_plaintext`), `WlanInterface.send_no_wait` + `register_rx_callback`, the deauth primitive, `Campaign` ABC.
- Produces: `class TkipChop` with an injectable `probe` seam (default: inject candidate via `send_no_wait`, await a matching client-sourced `mic_failure` EAPOL-Key within a timeout → bool) and per-byte pacing; `class TkipInject(Campaign)` (`key="tkip"`, `button_id="btn-tkip"`, `hotkey=("t","TKIP")`, `idle_label="TKIP"`, classmethods `visible`/`ineligible_reason`/`button_label` backed by `assess`, instance `_loop`/`teardown`/`status_*`).

- [ ] **Step 1: Write failing tests**

```python
async def test_chop_walks_via_boolean_oracle(mocker):
    # probe fires True only on the correct trailing byte; assert recovery completes
    # and only ONE fired guess per byte position counts (wrong guesses free).

async def test_aborts_on_observed_rekey(mocker):
    # feed a group-rekey EAPOL during the walk; assert TkipChop stops with
    # reason "AP rekeyed" instead of continuing.  # Review Focus

def test_campaign_visible_only_for_attackable(mocker):
    assert TkipInject.visible(ap(pairwise="TKIP", group="TKIP")) is True
    assert TkipInject.visible(ap(pairwise="CCMP", group="CCMP")) is False
```

- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — `TkipChop`: serialize guesses at ~RTT spacing (wrong = silent), stop on the first fired oracle per byte, wait the countermeasure interval between bytes, watch for an interleaved rekey and abort with a reason; `TkipInject`: own the single-TX rule like `WepCampaign`, run pre-check in `visible`/`ineligible_reason`, deauth to provoke an ARP, drive `recover`, then hold the recovered capability for Task 11's modal. Keep the `probe` seam injectable for the offline tests.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(tkip): Beck-Tews chop campaign with pacing + rekey abort`.

---

### Task 10: New capture kind (`models/`, `persist/`)

**Files:**
- Modify: `src/wifang/models/access_point.py` (`CaptureType`), `src/wifang/persist/common.py` (`LEGACY_CAPTURE_RE`), `src/wifang/persist/capture_history.py` (`_parse_file`, `summarize`), `src/wifang/persist/save.py`
- Test: `tests/persist/test_tkip_capture.py`

**Interfaces:**
- Produces: `CaptureType.TKIP_INJECT = "TKIP_INJECT"`, a save path `save_tkip_capability(...)` writing the recovered material (MIC key, keystream, TSC, direction, TID slots) under `captures/`, and a `summarize()` count for it.

- [ ] **Step 1: Write failing tests** — save a capability then `_parse_file` recovers a `PersistedCapture(type=TKIP_INJECT, bssid=…)`; `summarize()` counts it.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the enum member, filename pattern branch, save and parse, and extend `summarize()` (document the tuple change at its call sites).
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit** — `feat(persist): TKIP injection-capability capture kind`.

---

### Task 11: Focus UI — button, modal, wiring

**Files:**
- Create: `src/wifang/ui/screens/focus_v2/tkip_modal.py`
- Modify: `src/wifang/ui/focus_model.py` (`BUTTON_CAMPAIGNS`), `src/wifang/ui/screens/focus_v2/screen.py` (`_ATTACK_BUTTONS`, `_BUTTON_TIPS`, `_SHORT_BUTTON_LABELS`, `_campaign_toggles`, `on_button_pressed`, a `_finish_tkip` reap handler, Bindings), `src/wifang/ui/encryption_format.py`
- Test: `tests/ui/test_tkip_wiring.py`

**Interfaces:**
- Consumes: `TkipInject` (Task 9), the capability record (Task 10), modal precedent `decloak_modal.py`/`eviltwin_modal.py`.
- Produces: a `TkipModal` (operator picks canned ARP-spoof vs raw payload, shows slots remaining) and registry entries so the button renders and dispatches.

- [ ] **Step 1: Write failing tests** — assert `"tkip"` is in `BUTTON_CAMPAIGNS` and `screen._ATTACK_BUTTONS`/`_SHORT_BUTTON_LABELS` carry it; assert `encryption_format` no longer tags a pairwise/group-TKIP AP as out-of-scope (renders attackable).
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the registry entries + reap handler following the Decloak pattern, the modal (payload choice + slot counter), and the `encryption_format` change. Button CSS in the screen `CSS` only.
- [ ] **Step 4: Run to verify pass** — wiring tests pass; note in the commit body that the modal interaction itself is verified live (TUI).
- [ ] **Step 5: Commit** — `feat(ui): TKIP attack button, injection modal, attackable label`.

---

## Self-Review

**1. Spec coverage:** Michael + inverse (T1) ✓; TKIP mixing/TSC (T2) ✓; MIC-failure parsing incl. no-M4-pollution (T3) ✓; group-cipher downgrade path (T4) ✓; WMM detection (T5) ✓; keystream+MIC-key recovery with injectable probe, offline-tested like WEP (T6) ✓; up-front pre-check feeding visible/ineligible (T7) ✓; forge + ARP-spoof default + raw payload (T8) ✓; single-radio chop loop, boolean oracle, per-byte pacing, rekey abort, deauth-provoked ARP, single-TX rule (T9) ✓; new non-PSK capture kind through persist (T10) ✓; button/modal/wiring + attackable label + CSS rule (T11) ✓. Ohigashi-Morii is a non-goal (follow-up) — intentionally absent.

**2. Step scan:** Bodies appear only for the two algorithms the signatures don't determine (Michael block function, the byte-walk) and are described, not transcribed; every other code step is signature + file. No "TBD"/"handle edge cases" lines.

**3. Type consistency:** `Recovered(keystream, mic_key, tsc)` defined T6, consumed T8/T9/T10; `Verdict(attackable, reason, direction)` defined T7, consumed T9; `michael`/`michael_key_from_mic`/`tkip_rc4_key`/`tsc_to_iv`/`forge_tkip_frame`/`arp_spoof_plaintext`/`assess` names used consistently across tasks; `AccessPoint.group_cipher`/`.wmm`/`EapolPacket.mic_failure`/`CaptureType.TKIP_INJECT` names stable where referenced.

**4. Review Focus:** all five lines have an owning task's test (T3, T4+T7, T7, T9).

**5. Proportion:** Plan is comparable in length to the spec; code blocks are test assertions and two genuine algorithms, not full implementations.

## Note for human review

This plan, the spec, and the planned `campaigns/tkip/README.md` are human-facing docs — a human should review the wording.
