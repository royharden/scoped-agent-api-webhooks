"""Atomic domain audit and immutable event insert, never denial telemetry."""

import hashlib
import sqlite3
from typing import Any
from uuid import uuid4

from ..ports.events import EventEnvelope
from .policy import PrincipalContext

_EVENTS = {"create": "created", "edit": "updated", "submit": "submitted",
           "approve": "approved", "close": "closed", "cancel": "cancelled"}


def record(conn: sqlite3.Connection, principal: PrincipalContext, action: str,
           surface: str, order: dict[str, Any]) -> str:
    event_id = str(uuid4())
    event_type = "work_order." + _EVENTS[action]
    conn.execute("INSERT INTO domain_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
        (str(uuid4()), order["id"], principal.subject, principal.actor_kind, principal.client_id,
         principal.grant_id, action, surface, order["version"], order["updated_at"]))
    raw = EventEnvelope(event_type, order["updated_at"], order["id"], order["version"], order).to_bytes()
    conn.execute("INSERT INTO domain_events VALUES (?,?,?,?,?,?,?)",
        (event_id, event_type, order["id"], order["version"], order["updated_at"],
         raw, hashlib.sha256(raw).hexdigest()))
    return event_id
