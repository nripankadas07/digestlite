"""Exception tree for the :mod:`digestlite` package.

All errors raised by :mod:`digestlite` derive from :class:`DigestError` so
callers can catch one class to handle every library-specific failure.
"""
from __future__ import annotations

__all__ = [
    "DigestError",
    "UnsupportedAlgorithmError",
    "UnsupportedEncodingError",
    "InvalidInputError",
]


class DigestError(Exception):
    """Base class for every error raised by :mod:`digestlite`."""


class UnsupportedAlgorithmError(DigestError):
    """Raised when a caller requests an unknown hash algorithm."""

    def __init__(self, algorithm: object) -> None:
        self.algorithm = algorithm
        super().__init__(
            f"Unsupported algorithm: {algorithm!r}. "
            "Use digestlite.available_algorithms() to see the supported set."
        )


class UnsupportedEncodingError(DigestError):
    """Raised when a caller requests an unknown output encoding."""

    def __init__(self, encoding: object) -> None:
        self.encoding = encoding
        super().__init__(
            f"Unsupported encoding: {encoding!r}. "
            "Use digestlite.available_encodings() to see the supported set."
        )


class InvalidInputError(DigestError):
    """Raised when an argument has the wrong type or is otherwise malformed."""
