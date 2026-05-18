"""The public API surface is locked down via __all__."""
import digestlite


def test_public_all_is_stable() -> None:
    assert sorted(digestlite.__all__) == [
        "DigestError",
        "Hasher",
        "Hmac",
        "InvalidInputError",
        "UnsupportedAlgorithmError",
        "UnsupportedEncodingError",
        "available_algorithms",
        "available_encodings",
        "hash",
        "hmac",
        "to_bytes",
        "verify",
    ]


def test_every_public_name_is_importable() -> None:
    for name in digestlite.__all__:
        assert hasattr(digestlite, name), name


def test_error_hierarchy_is_rooted_at_digest_error() -> None:
    for cls in (
        digestlite.UnsupportedAlgorithmError,
        digestlite.UnsupportedEncodingError,
        digestlite.InvalidInputError,
    ):
        assert issubclass(cls, digestlite.DigestError)


def test_module_has_version() -> None:
    assert isinstance(digestlite.__version__, str)
    assert digestlite.__version__.count(".") >= 1


def test_available_algorithms_lists_canonical_names() -> None:
    algorithms = digestlite.available_algorithms()
    assert "sha256" in algorithms
    assert "sha512" in algorithms
    assert "blake2b" in algorithms
    assert algorithms == sorted(algorithms)


def test_available_encodings_lists_canonical_names() -> None:
    encodings = digestlite.available_encodings()
    assert encodings == sorted(encodings)
    assert "hex" in encodings
    assert "base32" in encodings
    assert "base64" in encodings
    assert "base64url" in encodings
    assert "raw" in encodings
