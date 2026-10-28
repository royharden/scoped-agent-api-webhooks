"""Synchronous durable webhook dispatcher with injected transport and clock.

No worker threads, socket calls, database initialization or wake loops occur on
import. A single process owns these fixtures. Startup recovery must precede
dispatch, never run concurrently with a live worker.
"""

import sqlite3
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import uuid4

from .endpoint_guard import EndpointGuard
from .locks import GRANT_LOCKS, GrantLocks
from .retry_policy import (
    AUTOMATIC_HORIZON_SECONDS,
    MAX_ATTEMPTS,
    REPLAY_WINDOW_SECONDS,
    RetryPolicy,
    utc_timestamp,
)
from .signing import sign
from .subscriptions import active_secrets


class Store(Protocol):
    def transaction(self) -> AbstractContextManager[sqlite3.Connection]: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]


class Transport(Protocol):
    """Adapter contract: no redirects, no proxies, five-second total bound.

    For HTTPX use trust_env=False, follow_redirects=False, and a bounded total
    request deadline in addition to phase timeouts. No adapter may resolve a
    hostname supplied by a request; endpoints already are literal loopback.
    """

    def send(
        self,
        endpoint: str,
        body: bytes,
        headers: Mapping[str, str],
        *,
        timeout: float,
    ) -> TransportResponse: ...


def _row(cursor: sqlite3.Cursor) -> dict[str, object] | None:
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(zip((column[0] for column in cursor.description), row, strict=True))


def _event_time(value: object) -> float:
    """DL1 domain_events stores an immutable ISO UTC timestamp."""
    if not isinstance(value, str):
        raise ValueError("event_timestamp_required")
    return utc_timestamp(datetime.fromisoformat(value.replace("Z", "+00:00")))


class DeliveryWorker:
    def __init__(
        self,
        store: Store,
        clock: Clock,
        transport: Transport,
        endpoint_guard: EndpointGuard,
        grant_validator: Callable[[str, frozenset[str]], bool],
        retry_policy: RetryPolicy,
        *,
        grant_validator_in_transaction: Callable[[sqlite3.Connection, str, frozenset[str], datetime], bool],
        grant_locks: GrantLocks = GRANT_LOCKS,
        barrier: Callable[[str, str], None] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock
        self.transport = transport
        self.endpoint_guard = endpoint_guard
        self.grant_validator = grant_validator
        self.grant_validator_in_transaction = grant_validator_in_transaction
        self.retry_policy = retry_policy
        self.grant_locks = grant_locks
        self.barrier = barrier or (lambda _point, _grant: None)

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        action: str,
        row: Mapping[str, object],
        at: float,
        detail: str,
    ) -> None:
        connection.execute(
            "INSERT INTO webhook_audit "
            "(id,action,subject,grant_id,subscription_id,delivery_id,at,detail) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                str(uuid4()), action, row["subject"], row["grant_id"],
                row["subscription_id"], row["id"], at, detail,
            ),
        )

    @staticmethod
    def _delivery(connection: sqlite3.Connection, delivery_id: str) -> dict[str, object] | None:
        return _row(connection.execute(
            "SELECT d.*, s.subject, s.grant_id, s.endpoint, "
            "s.state AS subscription_state, s.secret, s.previous_secret, "
            "s.rotated_at, s.cooldown_until, e.body, e.occurred_at "
            "FROM webhook_deliveries d "
            "JOIN webhook_subscriptions s ON s.id=d.subscription_id "
            "JOIN domain_events e ON e.id=d.event_id WHERE d.id=?",
            (delivery_id,),
        ))

    def recover_inflight(self) -> int:
        """Startup-only send-before-record recovery; stable body/ID may repeat."""
        with self.store.transaction() as connection:
            cursor = connection.execute(
                "UPDATE webhook_deliveries SET state='pending', "
                "last_error='send_result_unknown_after_restart' WHERE state='sending'"
            )
            return cursor.rowcount

    def run_due(self, now: datetime, *, limit: int = 100) -> int:
        at = utc_timestamp(now)
        if not 1 <= limit <= 100:
            raise ValueError("batch_limit_out_of_range")
        with self.store.transaction() as connection:
            candidates = connection.execute(
                "SELECT d.id,s.grant_id FROM webhook_deliveries d "
                "JOIN webhook_subscriptions s ON s.id=d.subscription_id "
                "WHERE d.state='pending' AND d.due_at<=? "
                "ORDER BY d.due_at,d.id LIMIT ?",
                (at, limit),
            ).fetchall()
        started = 0
        for delivery_id, grant_id in candidates:
            with self.grant_locks.hold(str(grant_id)):
                started += int(self._dispatch(str(delivery_id), at))
        return started

    def _dispatch(self, delivery_id: str, scheduled_at: float) -> bool:
        # The provided clock is read at the last possible point so natural
        # expiry during an earlier candidate's send does not use stale time.
        now = self.clock.now()
        at = max(scheduled_at, utc_timestamp(now))
        with self.store.transaction() as connection:
            row = self._delivery(connection, delivery_id)
        if row is None or row["state"] != "pending" or float(row["due_at"]) > at:
            return False
        grant_id = str(row["grant_id"])
        self.barrier("eligibility_check", grant_id)
        active = self.grant_validator(grant_id, frozenset({"workorders:read", "webhooks:manage"}))
        horizon = REPLAY_WINDOW_SECONDS if row["replay"] else AUTOMATIC_HORIZON_SECONDS
        cutoff = _event_time(row["occurred_at"]) + horizon
        code: str | None = None
        terminal = "cancelled"
        if row["subscription_state"] != "active" or not active:
            code = "subscription_or_grant_inactive"
        elif at > cutoff or int(row["attempts"]) >= MAX_ATTEMPTS:
            code, terminal = "attempt_limit_or_horizon", "dead"
        else:
            try:
                self.endpoint_guard.validate(str(row["endpoint"]))
            except ValueError:
                code, terminal = "endpoint_refused", "dead"
        if code is not None:
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE webhook_deliveries SET state=?,last_error=? "
                    "WHERE id=? AND state='pending'", (terminal, code, delivery_id),
                )
                self._audit(connection, "delivery_" + terminal, row, at, code)
            return False
        cooldown = float(row["cooldown_until"])
        if cooldown > at:
            with self.store.transaction() as connection:
                if cooldown > cutoff:
                    connection.execute(
                        "UPDATE webhook_deliveries SET state='dead',last_error='cooldown_horizon' "
                        "WHERE id=? AND state='pending'", (delivery_id,),
                    )
                else:
                    connection.execute(
                        "UPDATE webhook_deliveries SET due_at=? WHERE id=? AND state='pending'",
                        (cooldown, delivery_id),
                    )
            return False
        body = bytes(row["body"])
        try:
            headers = sign(body, str(row["event_id"]), now, active_secrets(row, at))
        except ValueError:
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE webhook_deliveries SET state='dead',last_error='signing_configuration' "
                    "WHERE id=? AND state='pending'", (delivery_id,),
                )
            return False
        attempt_id = str(uuid4())
        with self.store.transaction() as connection:
            # A different writer may have held SQLite past the grant's expiry.
            # Recheck on THIS connection after BEGIN IMMEDIATE acquired the
            # writer, without opening a nested connection/transaction.
            start_now = self.clock.now()
            start_at = utc_timestamp(start_now)
            if (start_at > cutoff or not self.grant_validator_in_transaction(
                    connection, grant_id, frozenset({"workorders:read", "webhooks:manage"}), start_now)):
                connection.execute(
                    "UPDATE webhook_deliveries SET state='cancelled',last_error='authority_expired_before_start' "
                    "WHERE id=? AND state='pending'", (delivery_id,),
                )
                self._audit(connection, "delivery_cancelled", row, start_at, "authority_expired_before_start")
                return False
            at = start_at
            cursor = connection.execute(
                "UPDATE webhook_deliveries SET state='sending',attempts=attempts+1 "
                "WHERE id=? AND state='pending'", (delivery_id,),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                "INSERT INTO webhook_attempts(id,delivery_id,started_at,status,error) "
                "VALUES (?,?,?,NULL,NULL)", (attempt_id, delivery_id, at),
            )
            self._audit(connection, "attempt_started", row, at, "bounded_send")
        self.barrier("send_start", grant_id)
        status: int | None = None
        response_headers: Mapping[str, str] = {}
        error: str | None = None
        try:
            # A deterministic send barrier or scheduling pause may advance time
            # after the durable start. Check outside the writer immediately
            # before actual bytes, using the uncached authoritative callback.
            send_active = self.grant_validator(
                grant_id, frozenset({"workorders:read", "webhooks:manage"}))
            send_now = self.clock.now()
            if utc_timestamp(send_now) > cutoff or not send_active:
                error = "authority_expired_before_send"
            else:
                headers = sign(body, str(row["event_id"]), send_now, active_secrets(row, utc_timestamp(send_now)))
                response = self.transport.send(str(row["endpoint"]), body, headers, timeout=5.0)
                if type(response.status) is not int or not 100 <= response.status <= 599:
                    error = "invalid_transport_response"
                else:
                    status, response_headers = response.status, response.headers
        except Exception:
            # Never persist exception text: adapters may include URLs/secrets.
            error = "transport_failure"
        finished = max(at, utc_timestamp(self.clock.now()))
        attempts = int(row["attempts"]) + 1
        with self.store.transaction() as connection:
            connection.execute(
                "UPDATE webhook_attempts SET status=?,error=? WHERE id=?",
                (status, error, attempt_id),
            )
            if error == "authority_expired_before_send":
                connection.execute(
                    "UPDATE webhook_deliveries SET state='cancelled',last_error=? WHERE id=? AND state='sending'",
                    (error, delivery_id),
                )
                self._audit(connection, "delivery_cancelled", row, finished, error)
            elif status is not None and 200 <= status < 300:
                connection.execute(
                    "UPDATE webhook_deliveries SET state='delivered',last_status=?,last_error=NULL "
                    "WHERE id=? AND state='sending'", (status, delivery_id),
                )
                self._audit(connection, "delivery_succeeded", row, finished, "http_2xx")
            elif status == 410:
                connection.execute(
                    "UPDATE webhook_subscriptions SET state='disabled' WHERE id=?",
                    (row["subscription_id"],),
                )
                connection.execute(
                    "UPDATE webhook_deliveries SET state='cancelled',last_status=410,"
                    "last_error='endpoint_gone' WHERE subscription_id=? "
                    "AND state IN ('pending','sending')", (row["subscription_id"],),
                )
                self._audit(connection, "subscription_disabled", row, finished, "http_410")
            else:
                retry_value = next((v for k, v in response_headers.items() if k.lower() == "retry-after"), None)
                decision = self.retry_policy.after_failure(
                    attempts=attempts, now=finished, event_created_at=_event_time(row["occurred_at"]),
                    status=status, retry_after_value=retry_value, cooldown_until=cooldown,
                    replay=bool(row["replay"]),
                )
                connection.execute(
                    "UPDATE webhook_subscriptions SET cooldown_until=max(cooldown_until,?) WHERE endpoint=?",
                    (decision.cooldown_until, row["endpoint"]),
                )
                connection.execute(
                    "UPDATE webhook_deliveries SET state=?,due_at=?,last_status=?,last_error=? "
                    "WHERE id=? AND state='sending'",
                    (
                        "dead" if decision.due_at is None else "pending",
                        finished if decision.due_at is None else decision.due_at,
                        status, error or decision.code, delivery_id,
                    ),
                )
                self._audit(connection, "delivery_failed", row, finished, decision.code)
        return True
