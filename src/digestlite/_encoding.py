"""Output-encoding helpers for digest byte strings."""
from __future__ import annotations

import base64

from ._errors import InvalidInputError, UnsupportedEncodingError

__all__ = [
    "available_encodings",
    "canonical_encoding",
    "encode",
]


_CANONICAL_ENCODINGS: dict[str, str] = {
    "hex": "hex",
    "raw": "raw",
    "bytes": "raw",
    "base32": "base32",
    "b32": "base32",
    "base64": "base64",
    "b64": "base64",
    "base64url": "base64url",
    "b64url": "base64url",
    "urlsafe": "base64url",
    "urlsafeb64": "base64url",
}


def available_encodings() -> list[str]:
    """Return the sorted list of canonical encoding names."""
    return sorted(set(_CANONICAL_ENCODINGS.values()))


def canonical_encoding(encoding: object) -> str:
    """Resolve *encoding* to a canonical name.

    The lookup is case-insensitive and tolerates spaces/hyphens.  ``b64url``,
    ``base64url``, ``urlsafe`` all map to the same canonical name.
    """
    if not isinstance(encoding, str):
        raise InvalidInputError(
            f"Encoding name must be a string, got {type(encoding).__name__!s}."
        )
    name = encoding.strip().lower().replace(" ", "").replace("-", "")
    if name in _CANONICAL_ENCODINGS:
        return _CANONICAL_ENCODINGS[name]
    raise UnsupportedEncodingError(encoding)


def encode(digest: bytes, encoding: str) -> str | bytes:
    """Encode *digest* using a canonical *encoding* name.

    ``raw`` returns the bytes untouched; every other encoding returns ``str``.
    """
    if encoding == "hex":
        return digest.hex()
    if encoding == "base32":
        return base64.b32encode(digest).decode("ascii")
    if encoding == "base64":
        return base64.b64encode(digest).decode("ascii")
    if encoding == "base64url":
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if encoding == "raw":
        return digest
    raise UnsupportedEncodingError(encoding)
