"""TKIP per-packet key mixing (IEEE 802.11-2012 Annex M.6.3 TKIP test
vector): TK/TA taken from the standard, Phase-1/Phase-2 outputs and the
TSC/IV byte layout cross-checked against hostap's wlantest reference
implementation (wlantest/tkip.c, compiled and run directly against this
TK/TA/TSC)."""
from wifit3.dot11.tkip import tkip_rc4_key, tsc_to_iv

_TK = bytes.fromhex("12345678901234567890123456789012")
_TA = bytes.fromhex("020304050607")


def test_tkip_rc4_key_matches_annex_vector_at_tsc_1():
    assert tkip_rc4_key(_TK, _TA, 1) == bytes.fromhex("0020014cfe67bed27c867b1bf8028b1c")


def test_tkip_rc4_key_changes_with_tsc_low_only():
    assert tkip_rc4_key(_TK, _TA, 0xABCD) == bytes.fromhex("ab2bcd35970d1cf51e159092ed2f791c")


def test_tkip_rc4_key_matches_annex_vector_with_full_tsc():
    assert tkip_rc4_key(_TK, _TA, 0x0A0B0C0D0E0F) == bytes.fromhex(
        "0e2e0fd6bc0334effcb7aa750bc7bff3"
    )


def test_tsc_to_iv_layout_for_small_tsc():
    assert tsc_to_iv(1) == bytes.fromhex("0020012000000000")


def test_tsc_to_iv_layout_for_full_tsc():
    assert tsc_to_iv(0x0A0B0C0D0E0F) == bytes.fromhex("0e2e0f200d0c0b0a")


def test_tsc_to_iv_prefix_matches_rc4_key_wep_seed():
    # WEPSeed[0:3] is always the transmitted WEP IV, so it must equal the
    # first 3 bytes of tsc_to_iv's own IV field.
    tsc = 0x0A0B0C0D0E0F
    assert tkip_rc4_key(_TK, _TA, tsc)[0:3] == tsc_to_iv(tsc)[0:3]


def test_tsc_to_iv_sets_ext_iv_bit():
    assert tsc_to_iv(1)[3] & 0x20
