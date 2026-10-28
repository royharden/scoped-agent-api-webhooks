"""Grant-bound subscription management and transactional revocation cascade."""

import base64
import json
import secrets
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from uuid import uuid4

from scoped_agent_api.host.policy import DomainError, PrincipalContext

from .envelope import EVENT_TYPES
from .management import mutate

REQUIRED = frozenset({"workorders:read", "webhooks:manage"})


def audit(conn: sqlite3.Connection, action: str, subject: str, grant_id: str,
          now: float, subscription_id: str | None = None,
          delivery_id: str | None = None, detail: str = "") -> None:
    conn.execute("INSERT INTO webhook_audit VALUES (?,?,?,?,?,?,?,?)",
                 (str(uuid4()), action, subject, grant_id, subscription_id, delivery_id, now, detail))


def active_secrets(row: Mapping[str, Any], now: float) -> list[str]:
    keys = [row["secret"]]
    if row["previous_secret"] is not None and row["rotated_at"] is not None and now < row["rotated_at"] + 3600:
        keys.append(row["previous_secret"])
    return keys


def suspend_grant(conn: sqlite3.Connection, grant_id: str, now: datetime) -> None:
    """DL2 calls within its revoke transaction AND GRANT_LOCKS.hold(grant_id).

    Invalidating grant/family/tokens is DL2-owned. This function never commits.
    Retain original grant binding forever; re-grant never resumes these rows.
    """
    stamp = now.timestamp()
    rows = conn.execute("SELECT id,subject FROM webhook_subscriptions WHERE grant_id=? AND state!='suspended'",
                        (grant_id,)).fetchall()
    for row in rows:
        sub_id, subject = row[0], row[1]
        deliveries = conn.execute("SELECT id FROM webhook_deliveries WHERE subscription_id=? AND state IN ('pending','sending')",
                                  (sub_id,)).fetchall()
        for delivery in deliveries:
            audit(conn, "delivery_cancelled", subject, grant_id, stamp, sub_id, delivery[0], "grant_revoked")
        conn.execute("UPDATE webhook_deliveries SET state='cancelled',last_error='grant_revoked' WHERE subscription_id=? AND state IN ('pending','sending')", (sub_id,))
        conn.execute("UPDATE webhook_subscriptions SET state='suspended' WHERE id=?", (sub_id,))
        audit(conn, "subscription_suspended", subject, grant_id, stamp, sub_id, detail="grant_revoked")


class SubscriptionService:
    def __init__(self, store: Any, clock: Any, endpoint_guard: Any,
                 grant_validator: Callable[[str, frozenset[str]], bool]) -> None:
        self.store = store
        self.clock = clock
        self.endpoint_guard = endpoint_guard
        self.grant_validator = grant_validator

    def _authorize(self, conn: sqlite3.Connection, principal: PrincipalContext, now: datetime) -> PrincipalContext:
        current = self.store.current_principal(conn, principal, now)
        if not REQUIRED.issubset(current.scopes):
            raise DomainError("insufficient_scope", 403, tuple(sorted(REQUIRED)))
        return current

    @staticmethod
    def _owned(conn: sqlite3.Connection, principal: PrincipalContext, sub_id: str) -> dict[str, Any]:
        cursor = conn.execute("SELECT * FROM webhook_subscriptions WHERE id=? AND subject=? AND grant_id=?",
                              (sub_id, principal.subject, principal.grant_id))
        row = cursor.fetchone()
        if row is None:
            raise DomainError("subscription_not_found", 404)
        return dict(zip((column[0] for column in cursor.description), row))

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: row[key] for key in ("id", "subject", "grant_id", "endpoint", "event_types", "state", "created_at")}

    def create(self, principal: PrincipalContext, endpoint: str, event_types: list[str], *,
               idempotency_key: str) -> dict[str, Any]:
        def operation(conn: sqlite3.Connection, now: datetime) -> dict[str, Any]:
            self.endpoint_guard.validate(endpoint)
            if not event_types or not set(event_types).issubset(EVENT_TYPES):
                raise DomainError("invalid_event_types", 400)
            sub_id = str(uuid4())
            secret = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            conn.execute("""INSERT INTO webhook_subscriptions
                (id,subject,grant_id,endpoint,event_types,secret,state,created_at)
                VALUES (?,?,?,?,?,?,'active',?)""",
                (sub_id, principal.subject, principal.grant_id, endpoint,
                 json.dumps(sorted(set(event_types))), secret, now.timestamp()))
            audit(conn, "subscription_created", principal.subject, principal.grant_id, now.timestamp(), sub_id)
            result = self._public(self._owned(conn, principal, sub_id))
            # Returned only to authenticated creator or same-key recovery.
            result["secret"] = secret
            return result
        return mutate(self, principal, "subscription.create", idempotency_key,
                      {"endpoint": endpoint, "event_types": event_types}, operation)

    def get(self, principal: PrincipalContext, sub_id: str) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authorize(conn, principal, self.clock.now())
            return self._public(self._owned(conn, principal, sub_id))

    def list(self, principal: PrincipalContext) -> list[dict[str, Any]]:
        with self.store.transaction() as conn:
            self._authorize(conn, principal, self.clock.now())
            cursor = conn.execute("SELECT * FROM webhook_subscriptions WHERE subject=? AND grant_id=? ORDER BY created_at,id LIMIT 100",
                                  (principal.subject, principal.grant_id))
            names = [column[0] for column in cursor.description]
            return [self._public(dict(zip(names, row))) for row in cursor.fetchall()]

    def set_enabled(self, principal: PrincipalContext, sub_id: str, enabled: bool, *,
                    idempotency_key: str) -> dict[str, Any]:
        if type(enabled) is not bool:
            raise DomainError("invalid_enabled", 400)
        def operation(conn: sqlite3.Connection, now: datetime) -> dict[str, Any]:
            row = self._owned(conn, principal, sub_id)
            if row["state"] == "suspended":
                raise DomainError("subscription_suspended", 409)
            self.endpoint_guard.validate(row["endpoint"])
            conn.execute("UPDATE webhook_subscriptions SET state=? WHERE id=?", ("active" if enabled else "disabled", sub_id))
            if not enabled:
                pending = conn.execute("SELECT id FROM webhook_deliveries WHERE subscription_id=? AND state IN ('pending','sending')", (sub_id,)).fetchall()
                for delivery in pending:
                    audit(conn, "delivery_cancelled", principal.subject, principal.grant_id,
                          now.timestamp(), sub_id, delivery[0], "subscription_disabled")
                conn.execute("UPDATE webhook_deliveries SET state='cancelled',last_error='subscription_disabled' WHERE subscription_id=? AND state IN ('pending','sending')", (sub_id,))
            audit(conn, "subscription_enabled" if enabled else "subscription_disabled", principal.subject,
                  principal.grant_id, now.timestamp(), sub_id)
            return self._public(self._owned(conn, principal, sub_id))
        return mutate(self, principal, "subscription.enable" if enabled else "subscription.disable",
                      idempotency_key, {"id": sub_id, "enabled": enabled}, operation)

    def rotate(self, principal: PrincipalContext, sub_id: str, *, idempotency_key: str) -> dict[str, str]:
        def operation(conn: sqlite3.Connection, now: datetime) -> dict[str, str]:
            row = self._owned(conn, principal, sub_id)
            if row["state"] != "active":
                raise DomainError("subscription_inactive", 409)
            if row["rotated_at"] is not None and now.timestamp() < row["rotated_at"] + 3600:
                raise DomainError("rotation_overlap_active", 409)
            secret = "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            conn.execute("UPDATE webhook_subscriptions SET previous_secret=secret,secret=?,rotated_at=? WHERE id=?", (secret, now.timestamp(), sub_id))
            audit(conn, "subscription_rotated", principal.subject, principal.grant_id, now.timestamp(), sub_id)
            return {"id": sub_id, "secret": secret}
        return mutate(self, principal, "subscription.rotate", idempotency_key, {"id": sub_id}, operation)
