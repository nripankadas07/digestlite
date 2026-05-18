"""Streaming hasher with multi-encoding output."""
from __future__ import annotations

from typing import Iterable

from ._algorithms import (
    canonical_algorithm,
    constructor_for,
    digest_size_for,
)
from ._encoding import canonical_encoding, encode
from ._validate import to_bytes

__all__ = ["Hasher"]


class Hasher:
    """Streaming digest computation with a fluent ``update`` interface.

    The class wraps a single :mod:`hashlib` instance, exposes the digest in
    every supported encoding, and tolerates ``str`` / ``bytes`` / ``bytearray``
    / ``memoryview`` inputs.  Once :meth:`digest` (or any of its sibling
    methods) is called the hasher is finalised — subsequent updates raise
    :class:`RuntimeError`.
    """

    __slots__ = ("_algorithm", "_impl", "_finalised", "_size")

    def __init__(self, algorithm: str = "sha256") -> None:
        canonical = canonical_algorithm(algorithm)
        self._algorithm = canonical
        self._impl = constructor_for(canonical)()
        self._finalised = False
        self._size = digest_size_for(canonical)

    @property
    def algorithm(self) -> str:
        """Canonical name of the underlying algorithm."""
        return self._algorithm

    @property
    def digest_size(self) -> int:
        """Length in bytes of the digest this hasher will emit."""
        return self._size

    @property
    def finalised(self) -> bool:
        """``True`` once :meth:`digest` (or an encoded variant) was called."""
        return self._finalised

    def update(self, data: object) -> "Hasher":
        """Feed *data* into the hash and return ``self`` for chaining."""
        if self._finalised:
            raise RuntimeError(
                "Hasher has already been finalised; create a new instance "
                "to compute another digest."
            )
        self._impl.update(to_bytes(data))
        return self

    def update_many(self, chunks: Iterable[object]) -> "Hasher":
        """Feed each item of *chunks* into the hash in order."""
        for chunk in chunks:
            self.update(chunk)
        return self

    def digest(self, encoding: str = "raw") -> str | bytes:
        """Finalise and return the digest, encoded as requested."""
        canonical = canonical_encoding(encoding)
        self._finalised = True
        return encode(self._impl.digest(), canonical)

    def hexdigest(self) -> str:
        """Return the digest as a lowercase hex string."""
        result = self.digest("hex")
        assert isinstance(result, str)
        return result

    def b32digest(self) -> str:
        """Return the digest as an unpadded RFC 4648 base32 string."""
        result = self.digest("base32")
        assert isinstance(result, str)
        return result

    def b64digest(self) -> str:
        """Return the digest as a standard base64 string (with padding)."""
        result = self.digest("base64")
        assert isinstance(result, str)
        return result

    def urlsafe_b64digest(self) -> str:
        """Return the digest as a URL-safe base64 string (no padding)."""
        result = self.digest("base64url")
        assert isinstance(result, str)
        return result

    def raw_digest(self) -> bytes:
        """Return the raw digest bytes."""
        result = self.digest("raw")
        assert isinstance(result, bytes)
        return result
