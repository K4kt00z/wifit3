"""TKIP attack button/modal wiring: registry entries + the attackable label."""
from wifang.campaigns.tkip import TkipInject
from wifang.models import AccessPoint
from wifang.ui import focus_model as fm
from wifang.ui.encryption_format import format_encryption_markup
from wifang.ui.screens.focus_v2 import screen as screen_mod
from wifang.ui.screens.focus_v2.tkip_modal import TkipModal, available_tids


def _ap(**kw) -> AccessPoint:
    return AccessPoint(bssid="aa:bb:cc:dd:ee:ff", **kw)


def test_tkip_registered_as_a_button_campaign():
    assert TkipInject in fm.BUTTON_CAMPAIGNS
    assert fm.CAMPAIGN_BY_KEY["tkip"] is TkipInject


def test_tkip_button_in_attack_buttons():
    assert ("btn-tkip", "TKIP") in screen_mod._ATTACK_BUTTONS


def test_tkip_has_a_short_stop_label_and_tip():
    assert "Stop TKIP" in screen_mod._SHORT_BUTTON_LABELS
    assert "TKIP" in screen_mod._BUTTON_TIPS


def test_tkip_campaign_toggle_wired_on_instance():
    screen = screen_mod.FocusViewV2()
    assert "tkip" in screen._campaign_toggles
    assert screen._campaign_toggles["tkip"] == screen._toggle_tkip


def test_tkip_hotkey_binding_present():
    sig = {(b.key, b.action) for b in screen_mod.FocusViewV2.BINDINGS}
    assert ("t", "campaign('tkip')") in sig


# ---- encryption_format: TKIP is attackable, not out-of-scope --------------

def test_pairwise_tkip_is_attackable():
    ap = _ap(encryption="WPA2-PSK-TKIP", akms=["PSK"], akm_suites=[2], pairwise_cipher="TKIP")
    m = format_encryption_markup(ap, detailed=True)
    assert "[bright_green]WPA2[/bright_green]" in m
    assert "[red]" not in m and "[yellow]" not in m


def test_group_tkip_downgrade_is_attackable():
    """A WPA2 AP with CCMP pairwise but a TKIP group cipher (mixed-mode downgrade)
    is still a Beck-Tews target even though its pairwise traffic is unaffected."""
    ap = _ap(encryption="WPA2-EAP-CCMP", akms=["EAP"], akm_suites=[1],
             pairwise_cipher="CCMP", group_cipher="TKIP")
    m = format_encryption_markup(ap, detailed=True)
    assert "[bright_green]WPA2[/bright_green]" in m


# ---- modal -----------------------------------------------------------------

def test_available_tids_excludes_seed_and_used():
    tids = available_tids(seed_tid=0, used={1, 2})
    assert 0 not in tids
    assert 1 not in tids
    assert 2 not in tids
    assert len(tids) == 13


def test_tkip_modal_is_a_screen_type():
    assert hasattr(TkipModal, "compose")
