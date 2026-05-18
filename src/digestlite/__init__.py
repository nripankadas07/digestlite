"""digestlite — zero-dep wrapper around :mod:`hashlib` and :mod:`hmac`.

A small, type-safe library that unifies the most common digest workflows:

* Multi-algorithm hash and HMAC (SHA-1/224/256/384/512, SHA-3, BLAKE2, MD5)
* Streaming ``update`` API with chained method calls
* Multi-encoding output: hex, base32, base64, URL-safe base64, or raw bytes
* Constant-time digest comparison via :func:`verify`
* A friendly :class:`DigestError` hierarchy for every failure mode

Example::

    >>> import digestlite as dl
    >>> dl.hash("hello", algorithm="sha256")
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    >>> dl.hmac("k", "v", algorithm="sha256")
    '...'
"""
from __future__ import annotations

from ._algorithms import available_algorithms
from ._encoding import available_encodings
from ._errors import (
    DigestError,
    InvalidInputError,
    UnsupportedAlgorithmError,
    UnsupportedEncodingError,
)
from ._hasher import Hasher
from ._hmac import Hmac
from ._oneshot import hash, hmac, verify
from ._validate import to_bytes

__all__ = [
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

__version__ = "0.1.0"
