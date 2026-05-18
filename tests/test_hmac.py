"""Streaming Hmac class."""
import hmac as _stdlib_hmac

import pytest

import digestlite


class TestConstruction:
    def test_default_algorithm_is_sha256(self) -> None:
        mac = digestlite.Hmac(b"k")
        assert mac.algorithm == "sha256"

    def test_alias_is_normalised(self) -> None:
        assert digestlite.Hmac(b"k", "SHA-512").algorithm == "sha512"

    def test_unknown_algorithm_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedAlgorithmError):
            digestlite.Hmac(b"k", "rot13")

    def test_key_must_be_bytes_or_str(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.Hmac(42)  # type: ignore[arg-type]

    def test_key_bool_is_rejected(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.Hmac(True)  # type: ignore[arg-type]

    def test_reports_digest_size(self) -> None:
        assert digestlite.Hmac(b"k", "sha256").digest_size == 32
        assert digestlite.Hmac(b"k", "sha512").digest_size == 64


class TestUpdate:
    def test_single_update_matches_stdlib(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"abc", "sha256").hexdigest()
        assert digestlite.Hmac(b"k").update(b"abc").hexdigest() == expected

    def test_chunked_updates_match_one_shot(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"hello world", "sha256").hexdigest()
        mac = digestlite.Hmac(b"k")
        mac.update(b"hello").update(b" ").update(b"world")
        assert mac.hexdigest() == expected

    def test_update_returns_self_for_chaining(self) -> None:
        mac = digestlite.Hmac(b"k")
        assert mac.update(b"a") is mac

    def test_update_accepts_str(self) -> None:
        expected = _stdlib_hmac.new(b"k", "héllo".encode("utf-8"),
                                    "sha256").hexdigest()
        assert digestlite.Hmac(b"k").update("héllo").hexdigest() == expected

    def test_update_after_finalise_raises(self) -> None:
        mac = digestlite.Hmac(b"k")
        mac.update(b"x").hexdigest()
        with pytest.raises(RuntimeError):
            mac.update(b"y")

    def test_update_many_consumes_iterable(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"abcde", "sha256").hexdigest()
        mac = digestlite.Hmac(b"k")
        mac.update_many([b"ab", b"cd", b"e"])
        assert mac.hexdigest() == expected

    def test_update_many_returns_self(self) -> None:
        mac = digestlite.Hmac(b"k")
        assert mac.update_many([b"a"]) is mac

    def test_update_rejects_bool(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            digestlite.Hmac(b"k").update(True)


class TestDigestEncodings:
    def test_hex_matches_stdlib(self) -> None:
        expected = _stdlib_hmac.new(b"k", b"hi", "sha256").hexdigest()
        assert digestlite.Hmac(b"k").update(b"hi").hexdigest() == expected

    def test_base32_decodes_to_raw(self) -> None:
        import base64
        mac = digestlite.Hmac(b"k")
        mac.update(b"hi")
        raw = _stdlib_hmac.new(b"k", b"hi", "sha256").digest()
        assert base64.b32decode(mac.b32digest()) == raw

    def test_base64_decodes_to_raw(self) -> None:
        import base64
        mac = digestlite.Hmac(b"k")
        mac.update(b"hi")
        raw = _stdlib_hmac.new(b"k", b"hi", "sha256").digest()
        assert base64.b64decode(mac.b64digest()) == raw

    def test_urlsafe_base64_has_no_padding(self) -> None:
        mac = digestlite.Hmac(b"k")
        mac.update(b"hi")
        assert "=" not in mac.urlsafe_b64digest()

    def test_raw_digest_matches_stdlib(self) -> None:
        raw = digestlite.Hmac(b"k").update(b"hi").raw_digest()
        assert raw == _stdlib_hmac.new(b"k", b"hi", "sha256").digest()

    def test_digest_with_unknown_encoding_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedEncodingError):
            digestlite.Hmac(b"k").update(b"hi").digest("rot13")

    def test_finalised_flag_flips_after_digest(self) -> None:
        mac = digestlite.Hmac(b"k")
        mac.update(b"x")
        assert not mac.finalised
        mac.hexdigest()
        assert mac.finalised


class TestKnownVectors:
    def test_rfc_2202_test_case_1(self) -> None:
        # RFC 2202 test case 1 for HMAC-SHA1
        key = b"\x0b" * 20
        data = b"Hi There"
        expected = "b617318655057264e28bc0b6fb378c8ef146be00"
        assert (
            digestlite.Hmac(key, "sha1").update(data).hexdigest() == expected
        )

    def test_str_key_matches_bytes_key(self) -> None:
        a = digestlite.Hmac("key").update(b"data").hexdigest()
        b = digestlite.Hmac(b"key").update(b"data").hexdigest()
        assert a == b
