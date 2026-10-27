"""Durable scanning of immutable host events and bounded authorized replay."""

import json
import sqlite3
from datetime import datetime
from typing import Any
from uuid import uuid4

from scoped_agent_api.host.policy import DomainError, PrincipalContext

from .management import mutate
from .subscriptions import SubscriptionService, audit

REPLAY_SECONDS = 7 * 86400


def event_time(value: str) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event_timestamp_utc")
    return parsed.timestamp()


def enqueue(conn: sqlite3.Connection, now: datetime, limit: int = 100) -> int:
    """A wake hint can be lost: eligible unqueued pairs remain discoverable.

    Subscription starts at creation; no historical backfill on new subscriptions.
    Pagination is over missing pairs, not a repeated first page of old events.
    Call inside the host Store transaction. No new event/body is manufactured.
    """
    if not 1 <= limit <= 100:
        raise ValueError("enqueue_limit")
    subscriptions = conn.execute("SELECT id,event_types,created_at FROM webhook_subscriptions WHERE state='active' ORDER BY id").fetchall()
    count = 0
    for sub_id, types_json, created in subscriptions:
        types = json.loads(types_json)
        placeholders = ",".join("?" for _ in types)
        if not placeholders:
            continue
        rows = conn.execute(f"""SELECT id,occurred_at FROM domain_events e
            WHERE e.event_type IN ({placeholders})
            AND NOT EXISTS (SELECT 1 FROM webhook_deliveries d WHERE d.event_id=e.id AND d.subscription_id=?)
            ORDER BY e.occurred_at,e.id""", (*types, sub_id))
        for event_id, occurred in rows:
            stamp = event_time(occurred)
            if stamp < created or stamp > now.timestamp():
                continue
            conn.execute("""INSERT OR IGNORE INTO webhook_deliveries
                (id,event_id,subscription_id,state,due_at,created_at) VALUES (?,?,?,'pending',?,?)""",
                (str(uuid4()), event_id, sub_id, now.timestamp(), now.timestamp()))
            count += 1
            if count >= limit:
                return count
    return count


class DeliveryService:
    def __init__(self, subscriptions: SubscriptionService) -> None:
        self.subscriptions = subscriptions
        self.store = subscriptions.store
        self.clock = subscriptions.clock

    def _authorize(self, conn: sqlite3.Connection, principal: PrincipalContext, now: datetime) -> None:
        self.subscriptions._authorize(conn, principal, now)

    def _delivery(self, conn: sqlite3.Connection, principal: PrincipalContext, delivery_id: str) -> dict[str, Any]:
        cursor = conn.execute("""SELECT d.*,e.occurred_at,s.state AS subscription_state
            FROM webhook_deliveries d JOIN domain_events e ON e.id=d.event_id
            JOIN webhook_subscriptions s ON s.id=d.subscription_id
            WHERE d.id=? AND s.subject=? AND s.grant_id=?""",
            (delivery_id, principal.subject, principal.grant_id))
        row = cursor.fetchone()
        if row is None:
            raise DomainError("delivery_not_found", 404)
        return dict(zip((column[0] for column in cursor.description), row))

    def get(self, principal: PrincipalContext, delivery_id: str) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authorize(conn, principal, self.clock.now())
            return self._delivery(conn, principal, delivery_id)

    def list(self, principal: PrincipalContext) -> list[dict[str, Any]]:
        with self.store.transaction() as conn:
            self._authorize(conn, principal, self.clock.now())
            ids = conn.execute("""SELECT d.id FROM webhook_deliveries d JOIN webhook_subscriptions s
                ON s.id=d.subscription_id WHERE s.subject=? AND s.grant_id=?
                ORDER BY d.created_at,d.id LIMIT 100""", (principal.subject, principal.grant_id)).fetchall()
            return [self._delivery(conn, principal, row[0]) for row in ids]

    def _replay(self, conn: sqlite3.Connection, principal: PrincipalContext, delivery_id: str, now: datetime) -> dict[str, Any]:
        row = self._delivery(conn, principal, delivery_id)
        age = now.timestamp() - event_time(row["occurred_at"])
        if age < 0 or age > REPLAY_SECONDS:
            raise DomainError("replay_expired", 409)
        if row["subscription_state"] != "active":
            raise DomainError("subscription_inactive", 409)
        if row["state"] in {"pending", "sending"}:
            raise DomainError("delivery_in_progress", 409)
        conn.execute("""UPDATE webhook_deliveries SET state='pending',due_at=?,attempts=0,
            last_status=NULL,last_error=NULL,replay=1 WHERE id=?""", (now.timestamp(), delivery_id))
        audit(conn, "delivery_replayed", principal.subject, principal.grant_id,
              now.timestamp(), row["subscription_id"], delivery_id)
        return self._delivery(conn, principal, delivery_id)

    def replay(self, principal: PrincipalContext, delivery_id: str, *, idempotency_key: str) -> dict[str, Any]:
        return mutate(self, principal, "delivery.replay", idempotency_key, {"id": delivery_id},
                      lambda conn, now: self._replay(conn, principal, delivery_id, now))

    def recover(self, principal: PrincipalContext, since: datetime, limit: int = 100, *,
                idempotency_key: str) -> list[dict[str, Any]]:
        if since.tzinfo is None or not 1 <= limit <= 100:
            raise DomainError("recover_input", 400)
        def operation(conn: sqlite3.Connection, now: datetime) -> list[dict[str, Any]]:
            candidates = conn.execute("""SELECT d.id,e.occurred_at FROM webhook_deliveries d
                JOIN domain_events e ON e.id=d.event_id JOIN webhook_subscriptions s ON s.id=d.subscription_id
                WHERE s.subject=? AND s.grant_id=? AND s.state='active'
                AND d.state IN ('delivered','dead','cancelled') ORDER BY e.occurred_at,e.id""",
                (principal.subject, principal.grant_id)).fetchall()
            ids = [row[0] for row in candidates if max(since.timestamp(), now.timestamp()-REPLAY_SECONDS)
                   <= event_time(row[1]) <= now.timestamp()][:limit]
            return [self._replay(conn, principal, delivery_id, now) for delivery_id in ids]
        return mutate(self, principal, "delivery.recover", idempotency_key,
                      {"since": since.isoformat(), "limit": limit}, operation)
