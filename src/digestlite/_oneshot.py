"""Convenience one-shot wrappers around :class:`Hasher` and :class:`Hmac`."""
from __future__ import annotations

import hmac as _stdlib_hmac

from ._encoding import canonical_encoding, encode
from ._hasher import Hasher
from ._hmac import Hmac
from ._validate import to_bytes

__all__ = ["hash", "hmac", "verify"]


def hash(  # noqa: A001 - intentional shadow; the API is "digestlite.hash".
    data: object,
    *,
    algorithm: str = "sha256",
    encoding: str = "hex",
) -> str | bytes:
    """Hash *data* and return the digest in *encoding*.

    ``data`` may be a ``str``, ``bytes``, ``bytearray`` or ``memoryview``.
    Strings are encoded with UTF-8 before hashing.
    """
    canonical = canonical_encoding(encoding)
    hasher = Hasher(algorithm)
    hasher.update(data)
    return encode(hasher.raw_digest(), canonical)


def hmac(
    key: object,
    data: object,
    *,
    algorithm: str = "sha256",
    encoding: str = "hex",
) -> str | bytes:
    """Compute an HMAC of *data* under *key* and return the tag in *encoding*."""
    canonical = canonical_encoding(encoding)
    mac = Hmac(key, algorithm)
    mac.update(data)
    return encode(mac.raw_digest(), canonical)


def verify(expected: object, actual: object) -> bool:
    """Constant-time equality check for two digests.

    Both arguments are coerced via :func:`digestlite.to_bytes` first, so you
    can pass any combination of ``str`` and ``bytes`` — for example, a hex
    string from a header and the bytes returned by :func:`hash`.
    """
    return _stdlib_hmac.compare_digest(to_bytes(expected), to_bytes(actual))
