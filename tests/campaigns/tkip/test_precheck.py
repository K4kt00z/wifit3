from typing import Optional

from wifit3.campaigns.tkip import assess
from wifit3.models.access_point import AccessPoint


def ap(pairwise: Optional[str], group: Optional[str], wmm: bool) -> AccessPoint:
    return AccessPoint(bssid="AA:BB:CC:DD:EE:FF", pairwise_cipher=pairwise, group_cipher=group, wmm=wmm)


def test_ccmp_only_not_attackable():
    v = assess(ap(pairwise="CCMP", group="CCMP", wmm=True), has_client=True)
    assert v.attackable is False
    assert v.reason


def test_group_tkip_downgrade_attackable_group_direction():
    v = assess(ap(pairwise="CCMP", group="TKIP", wmm=True), has_client=True)
    assert v.attackable is True
    assert v.direction == "group"
    assert v.reason


def test_pairwise_tkip_attackable():
    v = assess(ap(pairwise="TKIP", group="TKIP", wmm=True), has_client=True)
    assert v.attackable is True
    assert v.direction == "pairwise"
    assert v.reason


def test_no_client_not_attackable():
    v = assess(ap(pairwise="TKIP", group="TKIP", wmm=True), has_client=False)
    assert v.attackable is False
    assert v.direction is None
    assert v.reason


def test_no_wmm_not_attackable():
    v = assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True)
    assert v.attackable is False
    assert v.direction is None
    assert v.reason
