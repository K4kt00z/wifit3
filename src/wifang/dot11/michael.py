"""Michael MIC (Ferguson, "Michael: an improved MIC for 802.11 WEP"; IEEE
802.11i), the TKIP message integrity code: a keyed 64-bit MIC built from an
invertible block function, which is exactly what lets a known (data, mic)
pair be run backwards to recover the key.
"""
from __future__ import annotations

_MASK32 = 0xFFFFFFFF


def _rotl32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & _MASK32


def _rotr32(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (32 - bits))) & _MASK32


def _swap_halfword_bytes(value: int) -> int:
    return ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8)


def _block(left: int, right: int) -> tuple[int, int]:
    right = (right ^ _rotl32(left, 17)) & _MASK32
    left = (left + right) & _MASK32
    right = (right ^ _swap_halfword_bytes(left)) & _MASK32
    left = (left + right) & _MASK32
    right = (right ^ _rotl32(left, 3)) & _MASK32
    left = (left + right) & _MASK32
    right = (right ^ _rotr32(left, 2)) & _MASK32
    left = (left + right) & _MASK32
    return left, right


def _block_inverse(left: int, right: int) -> tuple[int, int]:
    left = (left - right) & _MASK32
    right = (right ^ _rotr32(left, 2)) & _MASK32
    left = (left - right) & _MASK32
    right = (right ^ _rotl32(left, 3)) & _MASK32
    left = (left - right) & _MASK32
    right = (right ^ _swap_halfword_bytes(left)) & _MASK32
    left = (left - right) & _MASK32
    right = (right ^ _rotl32(left, 17)) & _MASK32
    return left, right


def _padded_words(data: bytes) -> list[int]:
    # Michael's padding: a single 0x5a byte, zero-padded to a 4-byte boundary,
    # followed by one more all-zero 32-bit word.
    padded = data + b"\x5a"
    padded += bytes(-len(padded) % 4)
    padded += b"\x00\x00\x00\x00"
    return [int.from_bytes(padded[i:i + 4], "little") for i in range(0, len(padded), 4)]


def michael(key: bytes, data: bytes) -> bytes:
    """Michael MIC of `data` under the 8-byte `key`, as 8 bytes."""
    left = int.from_bytes(key[0:4], "little")
    right = int.from_bytes(key[4:8], "little")
    for word in _padded_words(data):
        left ^= word
        left, right = _block(left, right)
    return left.to_bytes(4, "little") + right.to_bytes(4, "little")


def michael_key_from_mic(data: bytes, mic: bytes) -> bytes:
    """The 8-byte key that produces `mic` as the Michael MIC of `data`.

    Runs the (invertible) block function backwards over `data`'s padded
    words, starting from `mic`, to recover the key the block chain began with.
    """
    left = int.from_bytes(mic[0:4], "little")
    right = int.from_bytes(mic[4:8], "little")
    for word in reversed(_padded_words(data)):
        left, right = _block_inverse(left, right)
        left ^= word
    return left.to_bytes(4, "little") + right.to_bytes(4, "little")
