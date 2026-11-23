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


def test_no_wmm_attackable_when_wmm_not_required():
    v = assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True, require_wmm=False)
    assert v.attackable is True and v.direction == "pairwise"


def test_no_wmm_still_blocked_by_default():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=True).attackable is False


def test_ccmp_only_not_attackable_even_without_wmm_requirement():
    assert assess(ap(pairwise="CCMP", group="CCMP", wmm=False), has_client=True, require_wmm=False).attackable is False


def test_no_client_not_attackable_mitm_path():
    assert assess(ap(pairwise="TKIP", group="TKIP", wmm=False), has_client=False, require_wmm=False).attackable is False
