"""TkipChop tests: pure software, no hardware. The ``probe`` seam stands in for the
live MIC-failure oracle, exactly like WepChopChop's injectable ``_probe``.
"""
import zlib

from wifang.campaigns.tkip.chop import REKEY_ABORT_REASON, TkipChop
from wifang.dot11.michael import michael
from wifang.dot11.mac import mac_to_str
from wifang.dot11.packet import EapolPacket
from wifang.dot11.tkip import tkip_rc4_key
from wifang.dot11.wep.crypto import CRC32_RESIDUE, icv
from wifang.crack.wep import rc4_keystream

_KNOWN_ARP16 = bytes([
    0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
])
_TK = bytes(range(16))
_MIC_KEY = bytes.fromhex("0102030405060708")
_BSSID = bytes.fromhex("aabbccddeeff")
_CLIENT = bytes.fromhex("112233445566")
_TID = 0
_TSC = 0x0000000000AB


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _michael_input(payload: bytes) -> bytes:
    return _CLIENT + _BSSID + bytes([_TID]) + b"\x00\x00\x00" + payload


def _synth_tkip_arp():
    payload = _KNOWN_ARP16 + bytes.fromhex("c0a80101000000000000c0a80102")
    mic = michael(_MIC_KEY, _michael_input(payload))
    plaintext = payload + mic
    full = plaintext + icv(plaintext)
    keystream = rc4_keystream(tkip_rc4_key(_TK, _BSSID, _TSC), len(full))
    return _xor(full, keystream), keystream


def _icv_probe(keystream: bytes, on_call=None):
    async def probe(candidate: bytes) -> bool:
        plain = _xor(candidate, keystream)
        fired = (zlib.crc32(plain) & 0xFFFFFFFF) == CRC32_RESIDUE
        if on_call is not None:
            on_call(fired)
        return fired

    return probe


async def test_chop_walks_via_boolean_oracle(mocker):
    cipher, keystream = _synth_tkip_arp()
    fired_count = 0
    call_count = 0

    def tally(fired: bool) -> None:
        nonlocal fired_count, call_count
        call_count += 1
        if fired:
            fired_count += 1

    iface = mocker.Mock()
    chop = TkipChop(
        iface, cipher, _KNOWN_ARP16, bssid=_BSSID, client=_CLIENT, tid=_TID, tsc=_TSC,
        probe=_icv_probe(keystream, on_call=tally), countermeasure_interval=0,
    )

    recovered = await chop.run()

    assert recovered is not None
    assert recovered.mic_key == _MIC_KEY
    assert recovered.keystream == keystream
    bytes_to_recover = len(cipher) - len(_KNOWN_ARP16)
    # Exactly one fired guess per byte position: wrong guesses never count.
    assert fired_count == bytes_to_recover
    assert call_count >= fired_count
    iface.register_rx_callback.assert_called_once()
    iface.unregister_rx_callback.assert_called_once()


async def test_chop_recovers_group_direction(mocker):
    """Group-cipher downgrade: the seed frame's DA is the broadcast/group address, so the
    walk's Michael input must bind that group DA (how the campaign builds the group walk)."""
    group = bytes.fromhex("ffffffffffff")
    payload = _KNOWN_ARP16 + bytes.fromhex("c0a80101000000000000c0a80102")
    mic = michael(_MIC_KEY, group + _BSSID + bytes([_TID]) + b"\x00\x00\x00" + payload)
    plaintext = payload + mic
    full = plaintext + icv(plaintext)
    keystream = rc4_keystream(tkip_rc4_key(_TK, _BSSID, _TSC), len(full))
    cipher = _xor(full, keystream)

    iface = mocker.Mock()
    chop = TkipChop(
        iface, cipher, _KNOWN_ARP16, bssid=_BSSID, client=group, tid=_TID, tsc=_TSC,
        probe=_icv_probe(keystream), countermeasure_interval=0,
    )

    recovered = await chop.run()

    assert recovered is not None
    assert recovered.mic_key == _MIC_KEY
    assert recovered.keystream == keystream


async def test_aborts_on_observed_rekey(mocker):
    cipher, keystream = _synth_tkip_arp()
    bytes_to_recover = len(cipher) - len(_KNOWN_ARP16)
    rx_cb = {}

    def capture_cb(cb):
        rx_cb["cb"] = cb

    iface = mocker.Mock()
    iface.register_rx_callback.side_effect = capture_cb

    def rekey_frame() -> EapolPacket:
        return EapolPacket(
            type="eapol", type_id=2, subtype_id=0, bssid=mac_to_str(_BSSID),
            source=mac_to_str(_BSSID), dest=mac_to_str(_CLIENT),
            to_ds=False, from_ds=True, rssi=-40, raw=b"", msg_num=1,
        )

    fired_so_far = 0

    async def probe(candidate: bytes) -> bool:
        nonlocal fired_so_far
        plain = _xor(candidate, keystream)
        fired = (zlib.crc32(plain) & 0xFFFFFFFF) == CRC32_RESIDUE
        if fired:
            fired_so_far += 1
            if fired_so_far == 1:
                rx_cb["cb"](rekey_frame())    # a 4-way-handshake message interleaves
        return fired

    chop = TkipChop(
        iface, cipher, _KNOWN_ARP16, bssid=_BSSID, client=_CLIENT, tid=_TID, tsc=_TSC,
        probe=probe, countermeasure_interval=0,
    )

    recovered = await chop.run()

    assert recovered is None
    assert chop.abort_reason == REKEY_ABORT_REASON
    assert chop.bytes_done < bytes_to_recover
