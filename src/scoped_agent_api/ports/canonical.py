"""Canonical encoding of M14's integer/string JSON domain.

Reject floating point rather than approximate RFC 8785's ECMAScript number
serialization. Domain requests/events have no fractional numeric fields. A future
broader wire contract needs a pinned full JCS implementation before accepting them.
"""

import hashlib
import json


def _validate(value: object) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            raise ValueError("integer outside interoperable JSON range")
        return
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return
    if isinstance(value, list):
        for item in value:
            _validate(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _validate(key)
            _validate(item)
        return
    raise ValueError("unsupported JSON value")


def _encode(value: object) -> str:
    if isinstance(value, dict):
        # JCS property ordering uses UTF-16 code units, not Python code points.
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_encode(key) + ":" + _encode(value[key]) for key in keys) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def canonical_bytes(value: object) -> bytes:
    _validate(value)
    return _encode(value).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
