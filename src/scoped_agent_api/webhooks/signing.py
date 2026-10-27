"""Standard Webhooks v1 raw-body HMAC, with injected clock/keyring."""

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from datetime import datetime

from .envelope import MAX_BODY


def _key(secret: str) -> bytes:
    if not secret.startswith("whsec_"):
        raise ValueError("invalid_webhook_key")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid_webhook_key") from exc
    if len(key) < 32:
        raise ValueError("short_webhook_key")
    return key


def _message(event_id: str, timestamp: str, body: bytes) -> bytes:
    if not event_id or len(event_id) > 200 or any(ord(c) < 33 or ord(c) > 126 for c in event_id):
        raise ValueError("invalid_webhook_id")
    if not isinstance(body, bytes) or len(body) > MAX_BODY:
        raise ValueError("event_body_size")
    return event_id.encode("ascii") + b"." + timestamp.encode("ascii") + b"." + body


def sign(body: bytes, event_id: str, now: datetime, secrets: Sequence[str]) -> dict[str, str]:
    if now.tzinfo is None or not secrets:
        raise ValueError("clock_or_keyring")
    timestamp = str(int(now.timestamp()))
    message = _message(event_id, timestamp, body)
    signatures = ["v1," + base64.b64encode(hmac.digest(_key(key), message, hashlib.sha256)).decode("ascii")
                  for key in secrets]
    return {"webhook-id": event_id, "webhook-timestamp": timestamp,
            "webhook-signature": " ".join(signatures)}


def verify(body: bytes, headers: Mapping[str, str], secrets: Sequence[str], now: datetime) -> None:
    """Verify before callers decode JSON. Explicit fixture clock; +/-300 seconds."""
    if now.tzinfo is None or not secrets:
        raise ValueError("clock_or_keyring")
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in normalized:
            raise ValueError("duplicate_webhook_header")
        normalized[lower] = value
    try:
        event_id = normalized["webhook-id"]
        timestamp = normalized["webhook-timestamp"]
        if not timestamp.isascii() or not timestamp.isdecimal() or len(timestamp) > 12:
            raise ValueError("invalid_timestamp")
        if abs(now.timestamp() - int(timestamp)) > 300:
            raise ValueError("timestamp_tolerance")
        signature = normalized["webhook-signature"]
        if len(signature) > 4096:
            raise ValueError("signature_size")
        message = _message(event_id, timestamp, body)
        candidates = []
        for item in signature.split():
            if item.startswith("v1,"):
                try:
                    candidates.append(base64.b64decode(item[3:], validate=True))
                except binascii.Error:
                    continue
        valid = False
        for secret in secrets:
            expected = hmac.digest(_key(secret), message, hashlib.sha256)
            for candidate in candidates:
                valid = hmac.compare_digest(expected, candidate) or valid
        if not valid:
            raise ValueError("invalid_signature")
    except KeyError as exc:
        raise ValueError("missing_webhook_header") from exc
