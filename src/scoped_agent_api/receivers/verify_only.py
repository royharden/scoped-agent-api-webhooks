"""Signature-only comparison arm: accepted arrivals each overwrite business state."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from ..webhooks.envelope import parse
from ..webhooks.signing import verify
from .inbox import ReceiverStore, apply_snapshot, count
from .reference import MAX_BODY_BYTES


class VerifyOnlyReceiver:
    def __init__(self, store: ReceiverStore, secrets: Callable[[], Sequence[str]]) -> None:
        self.store = store
        self.secrets = secrets

    def receive(
        self, body: bytes, headers: Mapping[str, str], now: datetime
    ) -> dict[str, Any]:
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("event body exceeds 32 KiB")
        verify(body, headers, self.secrets(), now)
        event = parse(body)
        with self.store.transaction() as connection:
            count(connection, "verify_only", "accepted")
            apply_snapshot(connection, "verify_only", event, guarded=False)
            count(connection, "verify_only", "processed")
        return {"status": 200}
