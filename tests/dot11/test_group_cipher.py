"""RSN group cipher plumbing: RsnElement.group_cipher_suite -> BeaconPacket.group_cipher
-> AccessPoint.group_cipher, surfacing a TKIP-downgraded group cipher on a CCMP-pairwise AP."""
import struct

from wifang.dot11.parser import WlanFrameParser
from wifang.dot11.packet import BeaconPacket
from wifang.dot11.rsn import AKM_PSK, CIPHER_CCMP, CIPHER_TKIP
from wifang.models import AccessPoint
from wifang.wlan.sink import WlanSink

from tests.frames import pkt

BSSID = "aa:bb:cc:dd:ee:ff"


def _rsn_ie(*, group_cipher: int, pairwise_cipher: int, akm: int) -> bytes:
    body = b"\x01\x00"  # Version = 1
    body += b"\x00\x0f\xac" + bytes([group_cipher])
    body += struct.pack("<H", 1) + b"\x00\x0f\xac" + bytes([pairwise_cipher])
    body += struct.pack("<H", 1) + b"\x00\x0f\xac" + bytes([akm])
    body += struct.pack("<H", 0)  # RSN Capabilities
    return bytes([48, len(body)]) + body


def beacon_with_rsn(*, pairwise: int, group: int, akm: int) -> bytes:
    fc, dur = b"\x80\x00", b"\x00\x00"
    addr = b"\x11\x22\x33\x44\x55\x66"
    mac_hdr = fc + dur + b"\xff\xff\xff\xff\xff\xff" + addr + addr + b"\x00\x00"
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x01\x00"  # ESS
    ssid = b"TestNet"
    tag_ssid = bytes([0x00, len(ssid)]) + ssid
    tag_rates = b"\x01\x04\x82\x84\x8b\x96"
    rsn_ie = _rsn_ie(group_cipher=group, pairwise_cipher=pairwise, akm=akm)
    return mac_hdr + fixed + tag_ssid + tag_rates + rsn_ie


def test_mixed_ap_exposes_tkip_group_cipher():
    pkt_ = WlanFrameParser.parse_80211_frame(
        beacon_with_rsn(pairwise=CIPHER_CCMP, group=CIPHER_TKIP, akm=AKM_PSK), -50
    )
    assert isinstance(pkt_, BeaconPacket)
    assert pkt_.pairwise_cipher == "CCMP"
    assert pkt_.group_cipher == "TKIP"


def test_wpa1_only_ap_has_no_group_cipher():
    wpa_ie = b"\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02"
    fc, dur = b"\x80\x00", b"\x00\x00"
    addr = b"\x11\x22\x33\x44\x55\x66"
    mac_hdr = fc + dur + b"\xff\xff\xff\xff\xff\xff" + addr + addr + b"\x00\x00"
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x01\x00"
    ssid = b"TestNet"
    tag_ssid = bytes([0x00, len(ssid)]) + ssid
    tag_rates = b"\x01\x04\x82\x84\x8b\x96"
    frame = mac_hdr + fixed + tag_ssid + tag_rates + wpa_ie
    parsed = WlanFrameParser.parse_80211_frame(frame, -50)
    assert isinstance(parsed, BeaconPacket)
    assert parsed.group_cipher is None


def test_access_point_group_cipher_round_trips_through_sink():
    sink = WlanSink()
    beacon = pkt({
        "type": "beacon", "bssid": BSSID, "source": BSSID, "dest": "ff:ff:ff:ff:ff:ff",
        "rssi": -40, "ssid": "Test_SSID", "channel": 6, "encryption": "WPA2",
        "pairwise_cipher": "CCMP", "group_cipher": "TKIP",
    })
    sink.update(beacon, "wlan0")
    ap = sink.get_access_points()[0]
    assert isinstance(ap, AccessPoint)
    assert ap.pairwise_cipher == "CCMP"
    assert ap.group_cipher == "TKIP"
