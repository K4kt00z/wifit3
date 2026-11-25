"""Forge tests: pure software, no hardware.

Proves that a frame forged from recovered keystream decrypts back to the correct
TKIP body (payload || Michael MIC || ICV) with the TID in the QoS control field
and the IV derived from the recovered TSC, and that the spoofed-ARP payload has
the LLC/SNAP + ARP-reply layout.
"""
import pytest

from wifang.campaigns.tkip.inject import arp_spoof_plaintext, forge_tkip_frame
from wifang.crack.tkip_beck_tews import Recovered
from wifang.dot11.michael import michael
from wifang.dot11.tkip import tsc_to_iv
from wifang.dot11.wep.crypto import icv

_MIC_KEY = bytes.fromhex("0102030405060708")
_TSC = 0x0000000000AB
_BSSID = bytes.fromhex("aabbccddeeff")
_CLIENT = bytes.fromhex("112233445566")
_TID = 1

_QOS_HEADER_LEN = 26
_IV_LEN = 8
_BODY_START = _QOS_HEADER_LEN + _IV_LEN


def _keystream(length: int) -> bytes:
    return bytes((i * 37 + 11) & 0xFF for i in range(length))


def _recovered(keystream_len: int) -> Recovered:
    return Recovered(_keystream(keystream_len), _MIC_KEY, _TSC)


def _michael_input(plaintext: bytes) -> bytes:
    return _CLIENT + _BSSID + bytes([_TID]) + b"\x00\x00\x00" + plaintext


def test_forged_body_decrypts_to_payload_mic_icv():
    plaintext = bytes(range(20))
    rec = _recovered(256)
    frame = forge_tkip_frame(rec, _TID, plaintext, bssid=_BSSID, client=_CLIENT)

    mic = michael(_MIC_KEY, _michael_input(plaintext))
    expected_body = plaintext + mic + icv(plaintext + mic)
    ciphertext = frame[_BODY_START:]
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, rec.keystream))

    assert decrypted == expected_body


def test_forged_frame_carries_tid_and_iv():
    plaintext = bytes(range(20))
    rec = _recovered(256)
    frame = forge_tkip_frame(rec, _TID, plaintext, bssid=_BSSID, client=_CLIENT)

    assert frame[24] & 0x0F == _TID
    assert frame[_QOS_HEADER_LEN:_QOS_HEADER_LEN + _IV_LEN] == tsc_to_iv(_TSC)


def test_forged_frame_is_qos_protected_from_ds():
    frame = forge_tkip_frame(_recovered(256), _TID, bytes(20), bssid=_BSSID, client=_CLIENT)

    assert frame[0] == 0x88                    # QoS data subtype
    assert frame[1] & 0x02                     # FromDS (AP -> client)
    assert frame[1] & 0x40                     # Protected
    assert frame[4:10] == _CLIENT              # addr1 = DA
    assert frame[10:16] == _BSSID              # addr2 = TA
    assert frame[16:22] == _BSSID              # addr3 = SA


def test_body_longer_than_keystream_raises():
    plaintext = bytes(40)
    rec = _recovered(len(plaintext) + 8 + 4 - 1)
    with pytest.raises(ValueError):
        forge_tkip_frame(rec, _TID, plaintext, bssid=_BSSID, client=_CLIENT)


def test_arp_spoof_plaintext_layout():
    sender_ip = bytes([192, 168, 1, 1])
    target_ip = bytes([192, 168, 1, 2])
    sender_mac = bytes.fromhex("021122334455")

    payload = arp_spoof_plaintext(sender_ip, target_ip, sender_mac)

    assert payload[0:8] == bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06])
    assert payload[8:16] == bytes([0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02])
    assert payload[16:22] == sender_mac
    assert payload[22:26] == sender_ip
    assert payload[26:32] == b"\x00" * 6
    assert payload[32:36] == target_ip


def test_arp_spoof_rejects_bad_lengths():
    with pytest.raises(ValueError):
        arp_spoof_plaintext(bytes(3), bytes(4), bytes(6))
