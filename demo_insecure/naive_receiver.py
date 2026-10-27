"""NON-DEPLOYABLE: deliberately accepts unverified, duplicate and stale arrivals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from scoped_agent_api.receivers.inbox import ReceiverStore, apply_snapshot, count
from scoped_agent_api.webhooks.envelope import parse


class NaiveReceiver:
    """Demo comparison only. Never register as a real application endpoint."""

    def __init__(self, store: ReceiverStore) -> None:
        self.store = store

    def receive(
        self, body: bytes, headers: Mapping[str, str], now: datetime
    ) -> dict[str, Any]:
        del headers, now
        if len(body) > 32 * 1024:
            raise ValueError("event body exceeds 32 KiB")
        event = parse(body)
        with self.store.transaction() as connection:
            count(connection, "naive", "accepted")
            apply_snapshot(connection, "naive", event, guarded=False)
            count(connection, "naive", "processed")
        return {"status": 200, "insecure_demo": True}
