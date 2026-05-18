"""Digest encoding helpers."""
import base64

import pytest

import digestlite
from digestlite._encoding import canonical_encoding, encode


class TestCanonicalEncoding:
    @pytest.mark.parametrize(
        "alias, canonical",
        [
            ("hex", "hex"),
            ("HEX", "hex"),
            ("base32", "base32"),
            ("BASE-32", "base32"),
            ("b32", "base32"),
            ("base64", "base64"),
            ("b64", "base64"),
            ("base64url", "base64url"),
            ("b64url", "base64url"),
            ("urlsafe", "base64url"),
            ("Urlsafe-B64", "base64url"),
            ("raw", "raw"),
            ("bytes", "raw"),
        ],
    )
    def test_aliases_map_to_canonical(self, alias: str, canonical: str) -> None:
        assert canonical_encoding(alias) == canonical

    def test_unknown_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError) as ctx:
            canonical_encoding("rot13")
        assert ctx.value.encoding == "rot13"

    def test_non_string_raises_invalid_input(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            canonical_encoding(None)  # type: ignore[arg-type]


class TestEncode:
    def test_hex_roundtrip(self) -> None:
        digest = bytes(range(32))
        encoded = encode(digest, "hex")
        assert encoded == digest.hex()
        assert bytes.fromhex(str(encoded)) == digest

    def test_base32_roundtrip(self) -> None:
        digest = bytes(range(32))
        encoded = encode(digest, "base32")
        assert base64.b32decode(str(encoded)) == digest

    def test_base64_roundtrip(self) -> None:
        digest = bytes(range(32))
        encoded = encode(digest, "base64")
        assert base64.b64decode(str(encoded)) == digest

    def test_base64url_has_no_padding(self) -> None:
        digest = bytes(range(32))
        encoded = encode(digest, "base64url")
        assert isinstance(encoded, str)
        assert "=" not in encoded
        # Re-pad before decoding.
        padded = encoded + "=" * (-len(encoded) % 4)
        assert base64.urlsafe_b64decode(padded) == digest

    def test_raw_returns_bytes_untouched(self) -> None:
        digest = bytes(range(32))
        assert encode(digest, "raw") == digest

    def test_uncanonical_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError):
            encode(b"x", "HEX")
