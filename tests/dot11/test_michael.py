"""Michael MIC (IEEE 802.11i) test vectors: the chained key->digest sequence
from `crypto/testmgr.h` (Linux kernel), sourced to IEEE 802.11i."""
from wifit3.dot11.michael import michael, michael_key_from_mic

# Each entry's digest becomes the next entry's key, exactly as chained in the
# kernel's michael_mic_tv_template.
_VECTORS = [
    ("0000000000000000", b"", "82925c1ca1d130b8"),
    ("82925c1ca1d130b8", b"M", "434721ca40639b3f"),
    ("434721ca40639b3f", b"Mi", "e8f9becae97e5d29"),
    ("e8f9becae97e5d29", b"Mic", "90038fc6cf13c1db"),
    ("90038fc6cf13c1db", b"Mich", "d55e100510128986"),
    ("d55e100510128986", b"Michael", "0a942b124ecaa546"),
]


def test_michael_matches_ieee80211i_vectors():
    for key_hex, data, expected_hex in _VECTORS:
        assert michael(bytes.fromhex(key_hex), data) == bytes.fromhex(expected_hex)


def test_michael_key_recovery_roundtrips():
    key = bytes.fromhex("d55e100510128986")
    data = b"\xaa\xaa\x03\x00\x00\x00\x08\x06arbitrary"
    assert michael_key_from_mic(data, michael(key, data)) == key


def test_michael_key_recovery_roundtrips_on_empty_data():
    key = bytes.fromhex("90038fc6cf13c1db")
    assert michael_key_from_mic(b"", michael(key, b"")) == key


def test_michael_key_recovery_roundtrips_on_block_boundary_data():
    # Data length a multiple of 4: exercises the padding's extra all-zero block.
    key = bytes.fromhex("e8f9becae97e5d29")
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert michael_key_from_mic(data, michael(key, data)) == key
