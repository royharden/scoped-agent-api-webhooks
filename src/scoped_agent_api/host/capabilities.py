"""Durable human handoff. All functions run inside the caller's transaction."""

import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from ..ports.canonical import canonical_bytes
from .policy import DomainError, PrincipalContext


def approval_statement(order_id: str) -> dict[str, str]:
    # Version is bound independently so a stale-version witness is unmasked.
    return {"action": "approve", "decision": "approve", "order_id": order_id}


def challenge(conn: sqlite3.Connection, principal: PrincipalContext, order: dict[str, Any],
              now: datetime, executor_subject: str) -> dict[str, Any]:
    if order["status"] != "submitted":
        raise DomainError("invalid_transition", 409)
    challenge_id = str(uuid4())
    expires = (now + timedelta(minutes=5)).isoformat()
    statement = approval_statement(order["id"])
    conn.execute("INSERT INTO approval_challenges "
        "(id,order_id,resource_version,requestor,requestor_kind,requestor_client_id,"
        "requestor_grant_id,resource,executor_subject,action,statement,created_at,expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (challenge_id, order["id"], order["version"], principal.subject, principal.actor_kind,
         principal.client_id, principal.grant_id, principal.resource, executor_subject, "approve",
         canonical_bytes(statement), now.isoformat(), expires))
    return {"id": challenge_id, "order_id": order["id"], "resource_version": order["version"],
            "executor_subject": executor_subject, "statement": statement, "expires_at": expires}


def confirm(conn: sqlite3.Connection, principal: PrincipalContext, arguments: dict[str, Any],
            now: datetime) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM approval_challenges WHERE id=?", (arguments.get("id"),)).fetchone()
    if row is None:
        raise DomainError("challenge_not_found", 404)
    if arguments.get("confirmed") is not True:
        raise DomainError("human_confirmation_required", 400)
    if principal.subject != row["executor_subject"] or principal.resource != row["resource"]:
        raise DomainError("wrong_executor", 403)
    if now >= datetime.fromisoformat(row["expires_at"]):
        raise DomainError("challenge_expired", 409)
    if canonical_bytes(arguments.get("statement")) != bytes(row["statement"]):
        raise DomainError("statement_mismatch", 409)
    order = conn.execute("SELECT version,status FROM work_orders WHERE id=?", (row["order_id"],)).fetchone()
    if order is None or order["version"] != row["resource_version"] or order["status"] != "submitted":
        raise DomainError("capability_stale", 409)
    updated = conn.execute("UPDATE approval_challenges SET confirmed=1 WHERE id=? AND confirmed=0",
                           (row["id"],))
    if updated.rowcount != 1:
        raise DomainError("challenge_confirmed", 409)
    capability_id, nonce = str(uuid4()), secrets.token_urlsafe(32)
    expires = (now + timedelta(minutes=5)).isoformat()
    conn.execute("INSERT INTO approval_capabilities "
        "(id,challenge_id,order_id,resource_version,requestor,requestor_grant_id,approver,"
        "executor_subject,executor_client_id,executor_grant_id,resource,action,statement,nonce,created_at,expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (capability_id, row["id"], row["order_id"], row["resource_version"], row["requestor"],
         row["requestor_grant_id"], principal.subject, principal.subject, principal.client_id,
         principal.grant_id, principal.resource, "approve", row["statement"], nonce, now.isoformat(), expires))
    return {"capability_id": capability_id, "order_id": row["order_id"],
            "resource_version": row["resource_version"], "expires_at": expires}


def consume(conn: sqlite3.Connection, principal: PrincipalContext, order: dict[str, Any],
            arguments: dict[str, Any], now: datetime) -> None:
    row = conn.execute("SELECT * FROM approval_capabilities WHERE id=?",
                       (arguments.get("capability_id"),)).fetchone()
    if row is None:
        raise DomainError("capability_required", 403)
    if (principal.actor_kind != "human" or row["approver"] != principal.subject
            or row["executor_subject"] != principal.subject
            or row["executor_client_id"] != principal.client_id
            or row["executor_grant_id"] != principal.grant_id
            or row["resource"] != principal.resource):
        raise DomainError("wrong_executor", 403)
    if row["consumed"]:
        raise DomainError("capability_consumed", 409)
    if now >= datetime.fromisoformat(row["expires_at"]):
        raise DomainError("capability_expired", 409)
    if row["order_id"] != order["id"] or row["action"] != "approve":
        raise DomainError("capability_binding", 403)
    if row["resource_version"] != order["version"]:
        raise DomainError("capability_stale", 409)
    statement = arguments.get("statement", approval_statement(order["id"]))
    if canonical_bytes(statement) != bytes(row["statement"]):
        raise DomainError("statement_mismatch", 409)
    original = conn.execute("SELECT * FROM approval_challenges WHERE id=?", (row["challenge_id"],)).fetchone()
    if (original is None or not original["confirmed"]
            or original["requestor"] != row["requestor"]
            or original["requestor_grant_id"] != row["requestor_grant_id"]
            or original["executor_subject"] != row["executor_subject"]
            or original["order_id"] != row["order_id"]
            or original["resource_version"] != row["resource_version"]
            or bytes(original["statement"]) != bytes(row["statement"])):
        raise DomainError("capability_binding", 403)
    result = conn.execute("UPDATE approval_capabilities SET consumed=1,consumed_at=? "
                          "WHERE id=? AND consumed=0", (now.isoformat(), row["id"]))
    if result.rowcount != 1:
        raise DomainError("capability_consumed", 409)
