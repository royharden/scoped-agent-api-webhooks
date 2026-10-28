"""Verify, durably enqueue before acknowledgement, then atomically apply newer snapshots."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from ..webhooks.envelope import parse
from ..webhooks.signing import verify
from .inbox import ReceiverStore, apply_snapshot, count, timestamp

MAX_BODY_BYTES = 32 * 1024


class ReferenceReceiver:
    def __init__(
        self, store: ReceiverStore, secrets: Callable[[], Sequence[str]]
    ) -> None:
        self.store = store
        self.secrets = secrets

    def receive(
        self, body: bytes, headers: Mapping[str, str], now: datetime
    ) -> dict[str, Any]:
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("event body exceeds 32 KiB")
        verify(body, headers, self.secrets(), now)
        parse(body)  # Parse only verified bytes; reject malformed signed snapshots.
        normalized = {key.lower(): value for key, value in headers.items()}
        event_id = normalized.get("webhook-id", "")
        if not event_id or len(event_id) > 256:
            raise ValueError("invalid webhook-id")
        digest = hashlib.sha256(body).hexdigest()
        conflict = False
        duplicate = False
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT body_digest FROM receiver_inbox WHERE event_id=?", (event_id,)
            ).fetchone()
            if prior is not None and prior[0] != digest:
                conflict = True
                connection.execute(
                    "INSERT INTO receiver_conflicts(event_id,original_digest,received_digest,received_at) "
                    "VALUES (?,?,?,?)", (event_id, prior[0], digest, timestamp(now))
                )
                count(connection, "reference", "conflicts")
            else:
                count(connection, "reference", "accepted")
                if prior is None:
                    connection.execute(
                        "INSERT INTO receiver_inbox(event_id,body_digest,body,received_at) VALUES (?,?,?,?)",
                        (event_id, digest, body, timestamp(now)),
                    )
                    count(connection, "reference", "inserted")
                else:
                    duplicate = True
                    count(connection, "reference", "duplicates")
        # Commit precedes both ACK and conflict refusal; the conflict record survives.
        if conflict:
            raise ValueError("webhook-id body digest conflict")
        return {"status": 202, "event_id": event_id, "duplicate": duplicate}

    def process_pending(self, now: datetime, limit: int = 100) -> int:
        if not 1 <= limit <= 100:
            raise ValueError("processing limit must be between 1 and 100")
        processed = 0
        for _ in range(limit):
            with self.store.transaction() as connection:
                row = connection.execute(
                    "SELECT event_id,body FROM receiver_inbox WHERE processed_at IS NULL "
                    "ORDER BY received_at,event_id LIMIT 1"
                ).fetchone()
                if row is None:
                    break
                event = parse(bytes(row["body"]))
                apply_snapshot(connection, "reference", event, guarded=True)
                connection.execute(
                    "UPDATE receiver_inbox SET processed_at=? WHERE event_id=?",
                    (timestamp(now), row["event_id"]),
                )
                count(connection, "reference", "processed")
            processed += 1
        return processed
