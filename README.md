# digestlite

Zero-dependency wrapper around Python's `hashlib` and `hmac` modules with a
unified streaming API, multi-encoding output, and a small, friendly error
hierarchy.

* Multi-algorithm hash and HMAC: MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512,
  BLAKE2b/BLAKE2s
* Streaming `update()` API with chainable calls and `update_many()` for
  iterables
* Multi-encoding output: `hex`, `base32`, `base64`, URL-safe base64 (no
  padding), or raw bytes
* Constant-time digest comparison via `verify()`
* Friendly `DigestError` hierarchy for every failure mode
* Type hints, `py.typed`, `mypy --strict` clean
* 100 % line + branch coverage

## Install

```bash
pip install digestlite
```

`digestlite` has zero runtime dependencies and works on Python 3.10+.

## Usage

```python
import digestlite as dl

# One-shot hashing, hex output by default
dl.hash("hello world")
# '...'

# Pick another algorithm and encoding
dl.hash("hello world", algorithm="sha512", encoding="base64")
# '...'

# Streaming hash with chunked updates
hasher = dl.Hasher("sha256")
for chunk in stream_chunks():
    hasher.update(chunk)
print(hasher.hexdigest())

# Or feed an iterable
print(dl.Hasher().update_many([b"hello", b" ", b"world"]).hexdigest())

# One-shot HMAC
dl.hmac("secret-key", "payload", algorithm="sha256")

# Streaming HMAC
mac = dl.Hmac("secret-key", "sha512")
mac.update(b"part-1").update(b"part-2")
mac.urlsafe_b64digest()

# Constant-time compare (works on str or bytes)
dl.verify(expected_tag, actual_tag)
```

## API

### `digestlite.hash(data, *, algorithm="sha256", encoding="hex") -> str | bytes`

Hash `data` (`str`, `bytes`, `bytearray`, or `memoryview`) and return the
digest in the requested `encoding`. Strings are encoded with UTF-8.

### `digestlite.hmac(key, data, *, algorithm="sha256", encoding="hex") -> str | bytes`

Compute an HMAC tag for `data` using `key` and return it in the requested
`encoding`.

### `digestlite.verify(expected, actual) -> bool`

Constant-time equality check for two digests. Accepts any combination of
`str` and `bytes`; strings are encoded with UTF-8 before comparison.

### `digestlite.Hasher(algorithm="sha256")`

Streaming hash with:

* `update(data) -> Self` — feed a chunk
* `update_many(chunks) -> Self` — feed each item of an iterable
* `digest(encoding="raw") -> str | bytes`
* `hexdigest()` / `b32digest()` / `b64digest()` /
  `urlsafe_b64digest()` / `raw_digest()`
* Properties: `algorithm`, `digest_size`, `finalised`

### `digestlite.Hmac(key, algorithm="sha256")`

Streaming HMAC with the same interface as `Hasher`.

### Other helpers

* `digestlite.available_algorithms() -> list[str]`
* `digestlite.available_encodings() -> list[str]`
* `digestlite.to_bytes(value) -> bytes`

### Errors

```
DigestError
├── UnsupportedAlgorithmError
├── UnsupportedEncodingError
└── InvalidInputError
```

## Algorithm aliases

Names are case-insensitive and tolerate spaces / hyphens. `"SHA-256"`,
`"sha 256"`, and `"sha256"` all resolve to the canonical `"sha256"`.

## Encoding aliases

| Canonical    | Aliases                          |
|--------------|----------------------------------|
| `hex`        | `hex`                            |
| `base32`     | `base32`, `b32`                  |
| `base64`     | `base64`, `b64`                  |
| `base64url`  | `base64url`, `b64url`, `urlsafe` |
| `raw`        | `raw`, `bytes`                   |

## Running tests

```bash
pip install pytest pytest-cov
PYTHONPATH=src pytest --cov=digestlite --cov-branch --cov-report=term-missing
```

The suite contains 95+ tests across api_surface, algorithms, encoding,
validate, hasher, hmac, oneshot, and integration; line and branch coverage
are gated at 100 %.

## License

MIT
