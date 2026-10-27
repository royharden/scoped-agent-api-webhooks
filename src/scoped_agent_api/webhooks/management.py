"""Atomic management idempotency in the same current-authority transaction."""

import json
import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Any

from scoped_agent_api.host.policy import DomainError, PrincipalContext
from scoped_agent_api.ports.canonical import digest

from .locks import GRANT_LOCKS


def mutate(service: Any, principal: PrincipalContext, action: str, key: str,
           arguments: dict[str, Any], operation: Callable[[sqlite3.Connection, datetime], Any]) -> Any:
    if not isinstance(key, str) or not key.strip() or len(key) > 200:
        raise DomainError("invalid_idempotency_key", 400)
    request_digest = digest(arguments)
    namespace = (principal.subject, principal.grant_id, action, key)
    with GRANT_LOCKS.hold(principal.grant_id), service.store.transaction() as conn:
        # Time is captured after both locks. Authentication always precedes
        # lookup, including recovery of a previous successful operation.
        now = service.clock.now()
        service._authorize(conn, principal, now)
        row = conn.execute("""SELECT request_sha256,expires_at,response FROM webhook_management_keys
            WHERE principal=? AND grant_id=? AND action=? AND key=?""", namespace).fetchone()
        if row is not None:
            if row[0] != request_digest:
                raise DomainError("idempotency_conflict", 409)
            if now.timestamp() >= row[1] or row[2] is None:
                raise DomainError("idempotency_expired", 409)
            return json.loads(row[2])
        result = operation(conn, now)
        conn.execute("INSERT INTO webhook_management_keys VALUES (?,?,?,?,?,?,?)",
                     (*namespace, request_digest, now.timestamp() + 8 * 86400,
                      json.dumps(result, separators=(",", ":"), allow_nan=False)))
        return result


def expire_results(conn: sqlite3.Connection, now: datetime) -> int:
    """Preserve used-key tombstones for the fixture lifetime."""
    return conn.execute("UPDATE webhook_management_keys SET response=NULL WHERE expires_at<=? AND response IS NOT NULL",
                        (now.timestamp(),)).rowcount
