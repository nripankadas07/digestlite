"""One-shot hash / hmac / verify helpers."""
import hashlib
import hmac as _stdlib_hmac

import pytest

import digestlite


class TestHashFunction:
    def test_default_encoding_is_hex(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert digestlite.hash("abc") == expected

    def test_str_input_uses_utf8(self) -> None:
        expected = hashlib.sha256("héllo".encode("utf-8")).hexdigest()
        assert digestlite.hash("héllo") == expected

    def test_bytes_input_passes_through(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert digestlite.hash(b"abc") == expected

    def test_alternate_algorithm(self) -> None:
        expected = hashlib.sha512(b"abc").hexdigest()
        assert digestlite.hash("abc", algorithm="sha512") == expected

    def test_raw_encoding_returns_bytes(self) -> None:
        out = digestlite.hash("abc", encoding="raw")
        assert isinstance(out, bytes)
        assert out == hashlib.sha256(b"abc").digest()

    def test_base64_encoding(self) -> None:
        import base64
        out = digestlite.hash("abc", encoding="base64")
        assert isinstance(out, str)
        assert base64.b64decode(out) == hashlib.sha256(b"abc").digest()

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedAlgorithmError):
            digestlite.hash("abc", algorithm="nope")

    def test_unsupported_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError):
            digestlite.hash("abc", encoding="rot13")


class TestHmacFunction:
    def test_default_encoding_is_hex(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"v", "sha256").hexdigest()
        assert digestlite.hmac("k", "v") == expected

    def test_alternate_algorithm(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"v", "sha512").hexdigest()
        assert digestlite.hmac("k", "v", algorithm="sha512") == expected

    def test_raw_encoding_returns_bytes(self) -> None:
        out = digestlite.hmac("k", "v", encoding="raw")
        assert isinstance(out, bytes)
        assert out == _stdlib_hmac.new(b"k", b"v", "sha256").digest()

    def test_unsupported_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError):
            digestlite.hmac("k", "v", encoding="rot13")


class TestVerify:
    def test_matching_str_returns_true(self) -> None:
        assert digestlite.verify("abc", "abc") is True

    def test_mismatching_str_returns_false(self) -> None:
        assert digestlite.verify("abc", "abd") is False

    def test_matching_bytes_returns_true(self) -> None:
        assert digestlite.verify(b"\x01\x02", b"\x01\x02") is True

    def test_mixed_str_bytes_returns_true(self) -> None:
        assert digestlite.verify("abc", b"abc") is True

    def test_length_mismatch_returns_false(self) -> None:
        assert digestlite.verify("abc", "abcd") is False

    def test_round_trip_with_hash(self) -> None:
        expected = digestlite.hash("payload")
        assert digestlite.verify(expected, digestlite.hash("payload"))

    def test_round_trip_with_hmac(self) -> None:
        expected = digestlite.hmac("k", "msg")
        assert digestlite.verify(expected, digestlite.hmac("k", "msg"))

    def test_bool_input_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.verify(True, True)
