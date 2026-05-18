"""Input validation helpers used across the package."""
from __future__ import annotations

from ._errors import InvalidInputError

__all__ = [
    "to_bytes",
    "ensure_key",
]


def to_bytes(value: object) -> bytes:
    """Coerce *value* to ``bytes`` for hashing.

    Accepts ``bytes`` / ``bytearray`` / ``memoryview`` verbatim and encodes
    ``str`` with UTF-8.  Any other type raises :class:`InvalidInputError`.
    Booleans are rejected because Python's ``bool`` is a subclass of ``int``
    but is never meaningful as digest input.
    """
    if isinstance(value, bool):
        raise InvalidInputError(
            "Boolean values are not accepted as digest input; "
            "pass bytes or str."
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise InvalidInputError(
        f"Cannot hash {type(value).__name__!s}; expected bytes, bytearray, "
        "memoryview, or str."
    )


def ensure_key(value: object) -> bytes:
    """Coerce an HMAC key to ``bytes``.

    Empty keys are permitted by RFC 2104 (they degrade to a deterministic
    output for the given data) and so are accepted here; callers that need
    a minimum-length check should perform it themselves.
    """
    if isinstance(value, bool):
        raise InvalidInputError(
            "Boolean values are not accepted as HMAC keys."
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise InvalidInputError(
        f"HMAC key must be bytes or str, got {type(value).__name__!s}."
    )
