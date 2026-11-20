"""Tests for recognizing an inbound TKIP MIC-failure report as EAPOL-Key traffic."""

import struct

from wifit3.dot11.parser import WlanFrameParser

_BSSID = b"\xaa\xbb\xcc\x00\x11\x22"
_CLIENT = b"\x11\x22\x33\x44\x55\x66"


def _eapol_key(key_info: int, key_data_len: int = 0) -> bytes:
    """Build a minimal 802.11 data frame carrying an EAPOL-Key payload with the given Key Info."""
    mac_hdr = bytes([0x08, 0x01]) + b"\x00\x00" + _BSSID + _CLIENT + _BSSID + b"\x00\x00"
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    key_data = b"\x00" * key_data_len
    key_descriptor = (
        b"\x02"
        + struct.pack(">H", key_info)
        + b"\x00\x10"
        + b"\x00" * 8  # Replay Counter
        + b"\x00" * 32  # Key Nonce
        + b"\x00" * 16  # Key IV
        + b"\x00" * 8  # Key RSC
        + b"\x00" * 8  # Reserved
        + b"\x00" * 16  # Key MIC
        + struct.pack(">H", key_data_len)
        + key_data
    )
    x802_1x = b"\x01\x03" + struct.pack(">H", len(key_descriptor))
    return mac_hdr + llc_snap + x802_1x + key_descriptor


def test_mic_failure_report_flagged_and_not_m4():
    frame = _eapol_key(key_info=0x0400 | 0x0800 | 0x0100 | 0x0010)
    pkt = WlanFrameParser.parse_80211_frame(frame, -50)
    assert pkt.mic_failure is True
    assert pkt.msg_num == 0


def test_real_m4_still_classified_m4():
    frame = _eapol_key(key_info=0x0100 | 0x0010)
    pkt = WlanFrameParser.parse_80211_frame(frame, -50)
    assert pkt.msg_num == 4
    assert pkt.mic_failure is False
