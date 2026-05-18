"""Streaming HMAC computation."""
from __future__ import annotations

import hmac as _stdlib_hmac
from typing import Iterable

from ._algorithms import (
    canonical_algorithm,
    constructor_for,
    digest_size_for,
)
from ._encoding import canonical_encoding, encode
from ._validate import ensure_key, to_bytes

__all__ = ["Hmac"]


class Hmac:
    """Streaming HMAC with a fluent ``update`` interface.

    The class wraps a :class:`hmac.HMAC` instance and exposes the digest in
    every encoding supported by :func:`digestlite.encode`.  Once any digest
    method is called the instance is finalised — further ``update`` calls
    raise :class:`RuntimeError`.
    """

    __slots__ = ("_algorithm", "_impl", "_finalised", "_size")

    def __init__(self, key: object, algorithm: str = "sha256") -> None:
        canonical = canonical_algorithm(algorithm)
        key_bytes = ensure_key(key)
        self._algorithm = canonical
        self._impl = _stdlib_hmac.new(
            key_bytes, digestmod=constructor_for(canonical)
        )
        self._finalised = False
        self._size = digest_size_for(canonical)

    @property
    def algorithm(self) -> str:
        """Canonical name of the underlying hash algorithm."""
        return self._algorithm

    @property
    def digest_size(self) -> int:
        """Length in bytes of the HMAC tag."""
        return self._size

    @property
    def finalised(self) -> bool:
        """``True`` once :meth:`digest` (or an encoded variant) was called."""
        return self._finalised

    def update(self, data: object) -> "Hmac":
        """Feed *data* into the HMAC and return ``self`` for chaining."""
        if self._finalised:
            raise RuntimeError(
                "Hmac has already been finalised; create a new instance "
                "to compute another tag."
            )
        self._impl.update(to_bytes(data))
        return self

    def update_many(self, chunks: Iterable[object]) -> "Hmac":
        """Feed each item of *chunks* into the HMAC in order."""
        for chunk in chunks:
            self.update(chunk)
        return self

    def digest(self, encoding: str = "raw") -> str | bytes:
        """Finalise and return the HMAC, encoded as requested."""
        canonical = canonical_encoding(encoding)
        self._finalised = True
        return encode(self._impl.digest(), canonical)

    def hexdigest(self) -> str:
        """Return the HMAC as a lowercase hex string."""
        result = self.digest("hex")
        assert isinstance(result, str)
        return result

    def b32digest(self) -> str:
        """Return the HMAC as an unpadded RFC 4648 base32 string."""
        result = self.digest("base32")
        assert isinstance(result, str)
        return result

    def b64digest(self) -> str:
        """Return the HMAC as a standard base64 string (with padding)."""
        result = self.digest("base64")
        assert isinstance(result, str)
        return result

    def urlsafe_b64digest(self) -> str:
        """Return the HMAC as a URL-safe base64 string (no padding)."""
        result = self.digest("base64url")
        assert isinstance(result, str)
        return result

    def raw_digest(self) -> bytes:
        """Return the raw HMAC bytes."""
        result = self.digest("raw")
        assert isinstance(result, bytes)
        return result
