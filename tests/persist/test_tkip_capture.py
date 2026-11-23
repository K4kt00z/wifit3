"""Tests for the TKIP injection-capability capture kind (save + parse + summarize)."""
from __future__ import annotations

from wifit3.models import AccessPoint, CaptureType, PersistedCapture
from wifit3.persist.capture_history import load_capture_index, summarize
from wifit3.persist.save import save_tkip_capability

_BSSID_COLON = "aa:bb:cc:dd:ee:ff"


def _ap() -> AccessPoint:
    return AccessPoint(bssid=_BSSID_COLON, ssid="HomeNet")


class TestSaveTkipCapability:
    def test_writes_recovered_material(self, tmp_path):
        result = save_tkip_capability(
            _ap(), mic_key=b"abcdefgh", keystream=b"\x01\x02\x03", tsc=42,
            direction="AP->STA", tid_slots={3: 128},
        )
        assert result is not None and result.was_new is True
        assert result.path.name.endswith("_tkip_inject.txt")
        body = result.path.read_text(encoding="utf-8")
        assert "MIC key (hex):   6162636465666768" in body
        assert "Keystream (hex): 010203" in body
        assert "TSC: 42" in body
        assert "Direction: AP->STA" in body
        assert "TID 3:128" in body

    def test_dedupes_same_mic_key(self, tmp_path):
        first = save_tkip_capability(
            _ap(), mic_key=b"abcdefgh", keystream=b"\x01", tsc=1,
            direction="AP->STA", tid_slots={3: 1},
        )
        again = save_tkip_capability(
            _ap(), mic_key=b"abcdefgh", keystream=b"\x09", tsc=9,
            direction="STA->AP", tid_slots={5: 1},
        )
        assert again is not None and again.was_new is False
        assert again.path == first.path

    def test_empty_mic_key_returns_none(self, tmp_path):
        assert save_tkip_capability(
            _ap(), mic_key=b"", keystream=b"\x01", tsc=1,
            direction="AP->STA", tid_slots={3: 1},
        ) is None


class TestParseTkipCapture:
    def test_round_trips_through_capture_history(self, tmp_path):
        save_tkip_capability(
            _ap(), mic_key=b"abcdefgh", keystream=b"\x01\x02\x03", tsc=42,
            direction="AP->STA", tid_slots={3: 128},
        )
        index = load_capture_index()
        captures = index[_BSSID_COLON]
        assert len(captures) == 1
        capture = captures[0]
        assert isinstance(capture, PersistedCapture)
        assert capture.type == CaptureType.TKIP_INJECT
        assert capture.bssid == _BSSID_COLON
        assert capture.value == "6162636465666768"


class TestSummarizeTkip:
    def test_counts_tkip_capability(self, tmp_path):
        save_tkip_capability(
            _ap(), mic_key=b"abcdefgh", keystream=b"\x01", tsc=1,
            direction="AP->STA", tid_slots={3: 1},
        )
        hs, pmkid, wep, psk, tkip = summarize(load_capture_index())
        assert (hs, pmkid, wep, psk, tkip) == (0, 0, 0, 0, 1)
