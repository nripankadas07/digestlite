"""Algorithm registry + canonicalisation."""
import pytest

import digestlite
from digestlite._algorithms import (
    canonical_algorithm,
    constructor_for,
    digest_size_for,
)


class TestCanonicalAlgorithm:
    def test_lowercase_passes_through(self) -> None:
        assert canonical_algorithm("sha256") == "sha256"

    def test_uppercase_normalises(self) -> None:
        assert canonical_algorithm("SHA256") == "sha256"

    def test_hyphens_normalise(self) -> None:
        assert canonical_algorithm("SHA-256") == "sha256"

    def test_spaces_normalise(self) -> None:
        assert canonical_algorithm(" sha 256 ") == "sha256"

    def test_sha3_with_hyphen_normalises(self) -> None:
        assert canonical_algorithm("SHA3-256") == "sha3_256"

    def test_unknown_algorithm_raises(self) -> None:
        with pytest.raises(digestlite.UnsupportedAlgorithmError) as ctx:
            canonical_algorithm("nope")
        assert ctx.value.algorithm == "nope"

    def test_non_string_raises_invalid_input(self) -> None:
        with pytest.raises(digestlite.InvalidInputError):
            canonical_algorithm(42)  # type: ignore[arg-type]


class TestConstructorFor:
    def test_returns_callable_for_canonical_name(self) -> None:
        ctor = constructor_for("sha256")
        assert ctor().digest_size == 32

    def test_rejects_uncanonical_input(self) -> None:
        with pytest.raises(digestlite.UnsupportedAlgorithmError):
            constructor_for("SHA-256")


class TestDigestSizeFor:
    @pytest.mark.parametrize(
        "name, expected_size",
        [
            ("md5", 16),
            ("sha1", 20),
            ("sha224", 28),
            ("sha256", 32),
            ("sha384", 48),
            ("sha512", 64),
            ("sha3_256", 32),
            ("sha3_512", 64),
            ("blake2s", 32),
            ("blake2b", 64),
        ],
    )
    def test_known_algorithms_report_expected_sizes(
        self, name: str, expected_size: int
    ) -> None:
        assert digest_size_for(name) == expected_size


class TestAvailableAlgorithms:
    def test_includes_all_canonical_names(self) -> None:
        names = digestlite.available_algorithms()
        for name in ("md5", "sha1", "sha256", "sha512", "sha3_256",
                     "sha3_512", "blake2b", "blake2s"):
            assert name in names
