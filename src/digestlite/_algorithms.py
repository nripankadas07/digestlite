"""Registry of supported hash algorithms.

Each algorithm is exposed under a single canonical name (matching the
:mod:`hashlib` constructor name) and aliases that people commonly type —
``SHA-256``, ``sha 256``, ``SHA3-256`` — are normalised at lookup time.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping

from ._errors import InvalidInputError, UnsupportedAlgorithmError

__all__ = [
    "available_algorithms",
    "canonical_algorithm",
    "constructor_for",
    "digest_size_for",
]

# Type alias for a no-arg constructor returning anything with an
# ``update``/``digest`` interface (hashlib._Hash, blake2b, blake2s).
HashConstructor = Callable[[], Any]


# Constructor factory functions keyed by canonical algorithm name.
_CONSTRUCTORS: Mapping[str, HashConstructor] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def _normalise(algorithm: object) -> str:
    if not isinstance(algorithm, str):
        raise InvalidInputError(
            f"Algorithm name must be a string, got "
            f"{type(algorithm).__name__!s}."
        )
    base = algorithm.strip().lower().replace(" ", "")
    if base in _CONSTRUCTORS:
        return base
    # ``SHA-256`` → ``sha256``: try collapsing the hyphen first.
    collapsed = base.replace("-", "")
    if collapsed in _CONSTRUCTORS:
        return collapsed
    # ``SHA3-256`` → ``sha3_256``: try the underscore form.
    underscored = base.replace("-", "_")
    if underscored in _CONSTRUCTORS:
        return underscored
    return base  # caller will raise UnsupportedAlgorithmError.


def available_algorithms() -> list[str]:
    """Return the sorted list of canonical algorithm names."""
    return sorted(_CONSTRUCTORS)


def canonical_algorithm(algorithm: object) -> str:
    """Resolve *algorithm* to a canonical name.

    The lookup is case-insensitive and tolerates spaces and hyphens
    (``"SHA-256"`` and ``"sha 256"`` both resolve to ``"sha256"``;
    ``"SHA3-256"`` resolves to ``"sha3_256"``).
    """
    name = _normalise(algorithm)
    if name not in _CONSTRUCTORS:
        raise UnsupportedAlgorithmError(algorithm)
    return name


def constructor_for(algorithm: str) -> HashConstructor:
    """Return the ``hashlib`` constructor for an already-canonical name."""
    if algorithm not in _CONSTRUCTORS:
        raise UnsupportedAlgorithmError(algorithm)
    return _CONSTRUCTORS[algorithm]


def digest_size_for(algorithm: str) -> int:
    """Return the digest byte length for an already-canonical name."""
    ctor = constructor_for(algorithm)
    size = ctor().digest_size
    assert isinstance(size, int)
    return size
