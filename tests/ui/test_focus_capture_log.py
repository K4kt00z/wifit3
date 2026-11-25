"""FocusViewV2 logs its target's captures from ApWatcher events, without saving them again."""
from pathlib import Path

import pytest

from wifang.models import AccessPoint
from wifang.persist.vault import HashlineSaveResult
from wifang.ui.app import WifiteApp
from wifang.watchers.ap_watcher import PmkidCaptured
from wifang.wlan.array import WlanArray


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_focus_logs_the_watchers_save_result_for_its_target_only():
    app = WifiteApp()
    async with app.run_test() as pilot:
        array = WlanArray()
        target = AccessPoint(bssid="aa:bb:cc:dd:ee:01", ssid="Target", channel=6)
        array.access_points[target.bssid] = target
        app.array = array
        app.push_screen(app.scanner_view)
        await pilot.pause(0)
        app.target_ap = target
        app.push_screen(app.focus_view)
        await pilot.pause(0.1)
        focus = app.screen
        lines: list[str] = []
        focus._log = lines.append
        app.vault.save_pmkid = lambda *a: pytest.fail("Focus must not save again")

        saved = HashlineSaveResult(path=Path("x_pmkid.22000"), was_new=True)
        for bssid in ("aa:bb:cc:dd:ee:02", target.bssid):
            ev = PmkidCaptured(bssid=bssid, ssid="Target", channel=6,
                               client_mac="11:22:33:44:55:66", save_result=saved)
            focus.on_wifite_app_ap_event_detected(WifiteApp.ApEventDetected(ev))

        assert len([ln for ln in lines if "PMKID captured" in ln]) == 1
        assert any("saved:" in ln for ln in lines)
