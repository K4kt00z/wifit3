from wifit3.campaigns.tkip.campaign import TkipInject
from wifit3.models.access_point import AccessPoint


def ap(pairwise, group, wmm=True) -> AccessPoint:
    return AccessPoint(bssid="AA:BB:CC:DD:EE:FF", pairwise_cipher=pairwise,
                       group_cipher=group, wmm=wmm)


def test_campaign_visible_only_for_attackable():
    assert TkipInject.visible(ap(pairwise="TKIP", group="TKIP")) is True
    assert TkipInject.visible(ap(pairwise="CCMP", group="CCMP")) is False


def test_campaign_visible_for_group_downgrade():
    assert TkipInject.visible(ap(pairwise="CCMP", group="TKIP")) is True


def test_ineligible_reason_none_when_attackable():
    assert TkipInject.ineligible_reason(ap(pairwise="TKIP", group="TKIP")) is None


def test_ineligible_reason_reports_missing_wmm():
    reason = TkipInject.ineligible_reason(ap(pairwise="TKIP", group="TKIP", wmm=False))
    assert reason and "WMM" in reason
