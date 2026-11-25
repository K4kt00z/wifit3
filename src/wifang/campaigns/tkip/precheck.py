"""Attackability pre-check for a TKIP Michael-MIC injection attack."""
from dataclasses import dataclass
from typing import Optional

from wifang.models.access_point import AccessPoint


@dataclass
class Verdict:
    """Outcome of :func:`assess`: whether to attempt the attack and from which cipher."""
    attackable: bool
    reason: str
    direction: Optional[str] = None


def assess(ap: AccessPoint, has_client: bool, *, require_wmm: bool = True) -> Verdict:
    """Best-effort check of whether `ap` looks worth a TKIP injection attempt.

    `require_wmm=False` skips the QoS/WMM gate, for the MITM path, which needs no QoS data channel.
    """
    if ap.pairwise_cipher == "TKIP":
        direction = "pairwise"
    elif ap.group_cipher == "TKIP":
        direction = "group"
    else:
        return Verdict(attackable=False, reason="no TKIP cipher advertised (pairwise or group)", direction=None)

    if require_wmm and not ap.wmm:
        return Verdict(attackable=False, reason="QoS/WMM not advertised; no QoS data channel to inject on", direction=None)

    if not has_client:
        return Verdict(attackable=False, reason="no associated client seen to supply a QoS data stream", direction=None)

    qos_note = "WMM and " if ap.wmm else ""
    return Verdict(attackable=True, reason=f"TKIP {direction} cipher with {qos_note}an associated client", direction=direction)
