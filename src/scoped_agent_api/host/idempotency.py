"""Result retention with permanent workspace-lifetime used-key tombstones."""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any, cast

from ..ports.canonical import canonical_bytes, digest
from .policy import DomainError, PrincipalContext


def namespace(principal: PrincipalContext, action: str, key: str) -> tuple[str, str, str, str]:
    if not isinstance(key, str) or not key.strip() or len(key) > 200:
        raise DomainError("invalid_idempotency_key", 400)
    return principal.subject, principal.grant_id, action, key


def lookup(conn: sqlite3.Connection, principal: PrincipalContext, action: str,
           key: str, arguments: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    ns = namespace(principal, action, key)
    row = conn.execute("SELECT request_sha256,expires_at FROM idempotency_keys "
                       "WHERE principal=? AND grant_id=? AND action=? AND key=?", ns).fetchone()
    if row is None:
        return None
    if row["request_sha256"] != digest(arguments):
        raise DomainError("idempotency_conflict", 409)
    if now >= datetime.fromisoformat(row["expires_at"]):
        raise DomainError("idempotency_expired", 409)
    result = conn.execute("SELECT response FROM idempotency_results "
                          "WHERE principal=? AND grant_id=? AND action=? AND key=?", ns).fetchone()
    if result is None:
        raise DomainError("idempotency_expired", 409)
    decoded: object = json.loads(result["response"])
    if not isinstance(decoded, dict):
        raise DomainError("idempotency_record_invalid", 500)
    return cast(dict[str, Any], decoded)


def save(conn: sqlite3.Connection, principal: PrincipalContext, action: str, key: str,
         arguments: dict[str, Any], response: dict[str, Any], now: datetime) -> None:
    ns = namespace(principal, action, key)
    conn.execute("INSERT INTO idempotency_keys VALUES (?,?,?,?,?,?,?)",
                 (*ns, digest(arguments), now.isoformat(), (now + timedelta(days=8)).isoformat()))
    conn.execute("INSERT INTO idempotency_results VALUES (?,?,?,?,?)",
                 (*ns, canonical_bytes(response).decode("utf-8")))


def expire_results(conn: sqlite3.Connection, now: datetime) -> int:
    """Remove response bodies only. Used-key rows must never be purged/rebound."""
    result = conn.execute("DELETE FROM idempotency_results WHERE EXISTS "
        "(SELECT 1 FROM idempotency_keys k WHERE k.principal=idempotency_results.principal "
        "AND k.grant_id=idempotency_results.grant_id AND k.action=idempotency_results.action "
        "AND k.key=idempotency_results.key AND julianday(k.expires_at)<=julianday(?))", (now.isoformat(),))
    return result.rowcount
