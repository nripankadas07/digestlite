"""to_bytes / ensure_key helpers."""
import pytest

import digestlite
from digestlite._validate import ensure_key, to_bytes


class TestToBytes:
    def test_bytes_passes_through(self) -> None:
        assert to_bytes(b"abc") == b"abc"

    def test_bytearray_is_copied(self) -> None:
        src = bytearray(b"abc")
        assert to_bytes(src) == b"abc"

    def test_memoryview_is_materialised(self) -> None:
        assert to_bytes(memoryview(b"abc")) == b"abc"

    def test_str_is_utf8_encoded(self) -> None:
        assert to_bytes("héllo") == "héllo".encode("utf-8")

    def test_bool_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            to_bytes(True)
        with pytest.raises(digestlite.InvalidInputError):
            to_bytes(False)

    def test_int_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            to_bytes(123)

    def test_none_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            to_bytes(None)


class TestEnsureKey:
    def test_bytes_passes_through(self) -> None:
        assert ensure_key(b"k") == b"k"

    def test_str_is_utf8_encoded(self) -> None:
        assert ensure_key("k") == b"k"

    def test_bytearray_is_copied(self) -> None:
        assert ensure_key(bytearray(b"k")) == b"k"

    def test_memoryview_is_materialised(self) -> None:
        assert ensure_key(memoryview(b"k")) == b"k"

    def test_empty_key_is_allowed(self) -> None:
        assert ensure_key(b"") == b""
        assert ensure_key("") == b""

    def test_bool_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            ensure_key(True)

    def test_int_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            ensure_key(0)
