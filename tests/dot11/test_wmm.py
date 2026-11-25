"""WMM/QoS advertisement plumbing: vendor IE OUI 00-50-F2 type 2 -> BeaconPacket.wmm
-> AccessPoint.wmm, needed for Beck-Tews to detect a QoS data channel."""
from wifang.dot11.packet import BeaconPacket
from wifang.dot11.parser import WlanFrameParser
from wifang.models import AccessPoint
from wifang.wlan.sink import WlanSink

from tests.frames import pkt

BSSID = "aa:bb:cc:dd:ee:ff"


def _beacon(*, extra_ies: bytes) -> bytes:
    fc, dur = b"\x80\x00", b"\x00\x00"
    addr = b"\x11\x22\x33\x44\x55\x66"
    mac_hdr = fc + dur + b"\xff\xff\xff\xff\xff\xff" + addr + addr + b"\x00\x00"
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x01\x00"  # ESS
    ssid = b"TestNet"
    tag_ssid = bytes([0x00, len(ssid)]) + ssid
    tag_rates = b"\x01\x04\x82\x84\x8b\x96"
    return mac_hdr + fixed + tag_ssid + tag_rates + extra_ies


def _wmm_ie() -> bytes:
    body = b"\x00\x50\xf2\x02\x01\x01\x00"  # OUI + type=2 (WMM) + subtype/version/qos-info
    return bytes([221, len(body)]) + body


def test_beacon_with_wmm_element_sets_wmm_true():
    frame = _beacon(extra_ies=_wmm_ie())
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert isinstance(parsed, BeaconPacket)
    assert parsed.wmm is True


def test_beacon_without_wmm_element_sets_wmm_false():
    frame = _beacon(extra_ies=b"")
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert isinstance(parsed, BeaconPacket)
    assert parsed.wmm is False


def test_access_point_wmm_round_trips_through_sink():
    sink = WlanSink()
    beacon = pkt({
        "type": "beacon", "bssid": BSSID, "source": BSSID, "dest": "ff:ff:ff:ff:ff:ff",
        "rssi": -40, "ssid": "Test_SSID", "channel": 6, "encryption": "WPA2", "wmm": True,
    })
    sink.update(beacon, "wlan0")
    ap = sink.get_access_points()[0]
    assert isinstance(ap, AccessPoint)
    assert ap.wmm is True
