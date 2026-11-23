"""Attackability pre-check for a TKIP Michael-MIC injection attack."""
from dataclasses import dataclass
from typing import Optional

from wifit3.models.access_point import AccessPoint


@dataclass
class Verdict:
    """Outcome of :func:`assess`: whether to attempt the attack and from which cipher."""
    attackable: bool
    reason: str
    direction: Optional[str] = None


def assess(ap: AccessPoint, has_client: bool) -> Verdict:
    """Best-effort check of whether `ap` looks worth a TKIP injection attempt.

    Best-effort: the rekey interval is unknown up front, so a positive verdict is not a guarantee.
    """
    if ap.pairwise_cipher == "TKIP":
        direction = "pairwise"
    elif ap.group_cipher == "TKIP":
        direction = "group"
    else:
        return Verdict(attackable=False, reason="no TKIP cipher advertised (pairwise or group)", direction=None)

    if not ap.wmm:
        return Verdict(attackable=False, reason="QoS/WMM not advertised; no QoS data channel to inject on", direction=None)

    if not has_client:
        return Verdict(attackable=False, reason="no associated client seen to supply a QoS data stream", direction=None)

    return Verdict(attackable=True, reason=f"TKIP {direction} cipher with WMM and an associated client", direction=direction)
