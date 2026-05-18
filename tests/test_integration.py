"""End-to-end / cross-module integration tests."""
import hashlib
import hmac as _stdlib_hmac

import digestlite


def test_streaming_hash_matches_one_shot_across_chunks() -> None:
    payload = b"this is a moderately long payload " * 32
    streamed = digestlite.Hasher().update_many(
        [payload[i : i + 17] for i in range(0, len(payload), 17)]
    ).hexdigest()
    assert streamed == hashlib.sha256(payload).hexdigest()


def test_streaming_hmac_matches_one_shot_across_chunks() -> None:
    payload = b"streaming HMAC payload " * 64
    streamed = digestlite.Hmac(b"secret").update_many(
        [payload[i : i + 11] for i in range(0, len(payload), 11)]
    ).hexdigest()
    assert streamed == _stdlib_hmac.new(b"secret", payload, "sha256").hexdigest()


def test_verify_accepts_round_tripped_hex() -> None:
    expected_hex = digestlite.hash("important payload")
    actual_hex = digestlite.hash("important payload")
    assert digestlite.verify(expected_hex, actual_hex)


def test_verify_detects_tampering() -> None:
    a = digestlite.hash("payload-a")
    b = digestlite.hash("payload-b")
    assert digestlite.verify(a, b) is False


def test_b64url_roundtrip_for_hmac() -> None:
    import base64
    out = digestlite.Hmac(b"k").update(b"hi").urlsafe_b64digest()
    padded = out + "=" * (-len(out) % 4)
    raw = base64.urlsafe_b64decode(padded)
    assert raw == _stdlib_hmac.new(b"k", b"hi", "sha256").digest()


def test_multi_algorithm_pipeline() -> None:
    payload = b"abc"
    for algorithm in ("sha1", "sha256", "sha512", "blake2b"):
        hex_out = digestlite.Hasher(algorithm).update(payload).hexdigest()
        assert len(hex_out) == digestlite.Hasher(algorithm).digest_size * 2


def test_aliases_consistent_with_canonical() -> None:
    assert (
        digestlite.hash("abc", algorithm="SHA-256")
        == digestlite.hash("abc", algorithm="sha256")
    )
    assert (
        digestlite.hmac("k", "v", algorithm="SHA-256")
        == digestlite.hmac("k", "v", algorithm="sha256")
    )


def test_chunked_update_with_mixed_types() -> None:
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert (
        digestlite.Hasher()
        .update("hello")
        .update(b" ")
        .update(bytearray(b"world"))
        .hexdigest()
        == expected
    )


def test_str_and_bytes_yield_same_hash() -> None:
    assert digestlite.hash("abc") == digestlite.hash(b"abc")


def test_to_bytes_used_by_verify_handles_unicode() -> None:
    assert digestlite.verify("héllo", "héllo")
    assert not digestlite.verify("héllo", "hello")
