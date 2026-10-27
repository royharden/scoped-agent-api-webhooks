"""Single transactional command path for API, CLI-over-HTTP and human UI."""

import sqlite3
from datetime import datetime
from typing import Any
from uuid import uuid4

from ..ports.canonical import canonical_bytes
from ..ports.clock import Clock, utc
from . import audit, capabilities, idempotency
from .domain import text, transition
from .policy import DomainError, PrincipalContext, authorize
from .store import Store

_FIELDS: dict[str, set[str]] = {
    "list": {"limit", "offset"}, "get": {"id"}, "create": {"title", "assignee"},
    "edit": {"id", "expected_version", "title", "assignee"},
    "submit": {"id", "expected_version"}, "close": {"id", "expected_version"},
    "cancel": {"id", "expected_version"},
    "approve": {"id", "expected_version", "capability_id", "statement"},
    "challenge": {"id"}, "confirm": {"id", "confirmed", "statement"},
}


class CommandService:
    def __init__(self, store: Store, clock: Clock, *, executor_subject: str = "appr.sam") -> None:
        self.store = store
        self.clock = clock
        # Server-side configuration only; never obtained from request arguments.
        if not executor_subject:
            raise ValueError("a server-selected human executor is required")
        self.executor_subject = executor_subject

    def execute(self, action: str, principal: PrincipalContext, arguments: dict[str, Any],
                idempotency_key: str | None, surface: str = "api") -> dict[str, Any]:
        if surface not in {"api", "cli", "ui"}:
            raise DomainError("invalid_surface", 400)
        if action not in _FIELDS:
            raise DomainError("unknown_operation", 400)
        if not isinstance(arguments, dict) or arguments.keys() - _FIELDS[action]:
            raise DomainError("invalid_arguments", 400)
        try:
            canonical_bytes(arguments)
        except (ValueError, UnicodeError) as exc:
            raise DomainError("invalid_arguments", 400) from exc
        # Each transaction obtains a fresh lookup before any saved success lookup.
        # BEGIN IMMEDIATE serializes revocation writes and this entire mutation.
        failure: DomainError | None = None
        response: dict[str, Any]
        with self.store.transaction() as conn:
            now = utc(self.clock.now())
            current = self.store.current_principal(conn, principal, now)
            authorize(current, action)
            if current.actor_kind == "agent" and surface == "ui":
                raise DomainError("agent_ui_unsupported", 403)
            if action in {"get", "list"}:
                return self._read(conn, action, arguments)
            if idempotency_key is None:
                raise DomainError("idempotency_key_required", 400)
            saved = idempotency.lookup(conn, current, action, idempotency_key, arguments, now)
            if saved is not None:
                if "__domain_error__" in saved:
                    error = saved["__domain_error__"]
                    raise DomainError(error["code"], error["status"], tuple(error["required_scopes"]))
                return saved
            # Cache a deterministic denial without committing a partial mutation.
            # Authorization denials above are deliberately never cached: current
            # authority must govern every attempt, including previous successes.
            conn.execute("SAVEPOINT command_effect")
            try:
                response = self._mutate(conn, action, current, arguments, now, surface)
            except DomainError as exc:
                conn.execute("ROLLBACK TO command_effect")
                failure = exc
                response = {"__domain_error__": {"code": exc.code, "status": exc.status,
                            "required_scopes": list(exc.required_scopes)}}
            conn.execute("RELEASE command_effect")
            idempotency.save(conn, current, action, idempotency_key, arguments, response, now)
        if failure is not None:
            raise failure
        return response

    @staticmethod
    def _order(conn: sqlite3.Connection, arguments: dict[str, Any]) -> dict[str, Any]:
        order_id = text(arguments.get("id"), "id")
        row = conn.execute("SELECT * FROM work_orders WHERE id=?", (order_id,)).fetchone()
        if row is None:
            raise DomainError("not_found", 404)
        return dict(row)

    def _read(self, conn: sqlite3.Connection, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "get":
            return self._order(conn, arguments)
        limit, offset = arguments.get("limit", 100), arguments.get("offset", 0)
        if type(limit) is not int or type(offset) is not int or not 1 <= limit <= 100 or offset < 0:
            raise DomainError("invalid_pagination", 400)
        rows = conn.execute("SELECT * FROM work_orders ORDER BY id LIMIT ? OFFSET ?", (limit, offset))
        return {"items": [dict(row) for row in rows], "limit": limit, "offset": offset}

    def _mutate(self, conn: sqlite3.Connection, action: str, principal: PrincipalContext,
                arguments: dict[str, Any], now: datetime, surface: str) -> dict[str, Any]:
        stamp = now.isoformat()
        if action == "confirm":
            text(arguments.get("id"), "id")
            return capabilities.confirm(conn, principal, arguments, now)
        if action == "create":
            order = {"id": str(uuid4()), "title": text(arguments.get("title"), "title"),
                     "status": "draft", "assignee": text(arguments.get("assignee"), "assignee", nullable=True),
                     "version": 1, "created_at": stamp, "updated_at": stamp}
            conn.execute("INSERT INTO work_orders VALUES (?,?,?,?,?,?,?)",
                tuple(order[key] for key in ("id", "title", "status", "assignee", "version", "created_at", "updated_at")))
        else:
            before = self._order(conn, arguments)
            if action == "challenge":
                return capabilities.challenge(conn, principal, before, now, self.executor_subject)
            expected = arguments.get("expected_version")
            if type(expected) is not int or expected < 1:
                raise DomainError("expected_version_required", 400)
            if before["version"] != expected:
                raise DomainError("version_conflict", 409)
            order = transition(before, action, arguments)
            order["updated_at"] = stamp
            # Validate/consume after version validation, inside the same transaction.
            if action == "approve":
                text(arguments.get("capability_id"), "capability_id")
                capabilities.consume(conn, principal, before, arguments, now)
            updated = conn.execute("UPDATE work_orders SET title=?,status=?,assignee=?,version=?,updated_at=? "
                "WHERE id=? AND version=?", (order["title"], order["status"], order["assignee"],
                order["version"], stamp, order["id"], expected))
            if updated.rowcount != 1:
                raise DomainError("version_conflict", 409)
        effect_ref = audit.record(conn, principal, action, surface, order)
        return {**order, "effect_ref": effect_ref}
