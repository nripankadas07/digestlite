"""Streaming Hasher class."""
import hashlib

import pytest

import digestlite


class TestConstruction:
    def test_default_algorithm_is_sha256(self) -> None:
        hasher = digestlite.Hasher()
        assert hasher.algorithm == "sha256"

    def test_alias_is_normalised(self) -> None:
        assert digestlite.Hasher("SHA-512").algorithm == "sha512"

    def test_unknown_algorithm_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedAlgorithmError):
            digestlite.Hasher("rot13")

    def test_reports_digest_size(self) -> None:
        assert digestlite.Hasher("sha256").digest_size == 32
        assert digestlite.Hasher("sha512").digest_size == 64


class TestUpdate:
    def test_single_update_matches_hashlib(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert digestlite.Hasher().update(b"abc").hexdigest() == expected

    def test_chunked_updates_match_one_shot(self) -> None:
        expected = hashlib.sha256(b"hello world").hexdigest()
        hasher = digestlite.Hasher()
        hasher.update(b"hello").update(b" ").update(b"world")
        assert hasher.hexdigest() == expected

    def test_update_returns_self_for_chaining(self) -> None:
        hasher = digestlite.Hasher()
        assert hasher.update(b"a") is hasher

    def test_update_accepts_str(self) -> None:
        expected = hashlib.sha256("héllo".encode("utf-8")).hexdigest()
        assert digestlite.Hasher().update("héllo").hexdigest() == expected

    def test_update_accepts_bytearray(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert (
            digestlite.Hasher()
            .update(bytearray(b"abc"))
            .hexdigest()
            == expected
        )

    def test_update_accepts_memoryview(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        assert (
            digestlite.Hasher()
            .update(memoryview(b"abc"))
            .hexdigest()
            == expected
        )

    def test_update_rejects_bool(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.Hasher().update(True)

    def test_update_rejects_int(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.Hasher().update(99)

    def test_update_after_finalise_raises(self) -> None:
        hasher = digestlite.Hasher()
        hasher.update(b"x").hexdigest()
        with pytest.raises(RuntimeError):
            hasher.update(b"y")

    def test_update_many_consumes_iterable(self) -> None:
        expected = hashlib.sha256(b"abcde").hexdigest()
        hasher = digestlite.Hasher()
        hasher.update_many([b"ab", b"cd", b"e"])
        assert hasher.hexdigest() == expected

    def test_update_many_returns_self(self) -> None:
        hasher = digestlite.Hasher()
        assert hasher.update_many([b"a"]) is hasher


class TestDigestEncodings:
    def test_hex_default_for_hexdigest(self) -> None:
        expected = hashlib.sha256(b"hi").hexdigest()
        assert digestlite.Hasher().update(b"hi").hexdigest() == expected

    def test_base32_decodes_to_raw(self) -> None:
        import base64
        hasher = digestlite.Hasher()
        hasher.update(b"hi")
        raw = hashlib.sha256(b"hi").digest()
        assert base64.b32decode(hasher.b32digest()) == raw

    def test_base64_decodes_to_raw(self) -> None:
        import base64
        hasher = digestlite.Hasher()
        hasher.update(b"hi")
        raw = hashlib.sha256(b"hi").digest()
        assert base64.b64decode(hasher.b64digest()) == raw

    def test_urlsafe_base64_has_no_padding(self) -> None:
        hasher = digestlite.Hasher()
        hasher.update(b"hi")
        out = hasher.urlsafe_b64digest()
        assert "=" not in out

    def test_raw_returns_bytes(self) -> None:
        raw = digestlite.Hasher().update(b"hi").raw_digest()
        assert raw == hashlib.sha256(b"hi").digest()

    def test_digest_with_alias_encoding(self) -> None:
        out = digestlite.Hasher().update(b"hi").digest("B64")
        assert isinstance(out, str)

    def test_digest_with_unknown_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError):
            digestlite.Hasher().update(b"hi").digest("rot13")

    def test_finalised_flag_flips_after_digest(self) -> None:
        hasher = digestlite.Hasher()
        hasher.update(b"x")
        assert not hasher.finalised
        hasher.hexdigest()
        assert hasher.finalised


class TestKnownVectors:
    @pytest.mark.parametrize(
        "algorithm, message, expected",
        [
            ("sha1", b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("sha256", b"",
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
             "1eda3"[:64]),
            ("md5", b"",  "d41d8cd98f00b204e9800998ecf8427e"),
        ],
    )
    def test_known_vector_matches(
        self, algorithm: str, message: bytes, expected: str
    ) -> None:
        out = digestlite.Hasher(algorithm).update(message).hexdigest()
        assert out == expected
