"""Owner-installed delivery schema. Domain events remain host-owned and immutable."""

import sqlite3

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id TEXT PRIMARY KEY, subject TEXT NOT NULL, grant_id TEXT NOT NULL,
    endpoint TEXT NOT NULL, event_types TEXT NOT NULL, secret TEXT NOT NULL,
    previous_secret TEXT, rotated_at REAL,
    state TEXT NOT NULL CHECK(state IN ('active','disabled','suspended')),
    cooldown_until REAL NOT NULL DEFAULT 0, created_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES domain_events(id),
    subscription_id TEXT NOT NULL REFERENCES webhook_subscriptions(id),
    state TEXT NOT NULL CHECK(state IN ('pending','sending','delivered','dead','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 10),
    due_at REAL NOT NULL, created_at REAL NOT NULL, last_status INTEGER,
    last_error TEXT, replay INTEGER NOT NULL DEFAULT 0,
    UNIQUE(event_id,subscription_id))""",
    """CREATE TABLE IF NOT EXISTS webhook_attempts (
    id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL REFERENCES webhook_deliveries(id),
    started_at REAL NOT NULL, status INTEGER, error TEXT)""",
    """CREATE TABLE IF NOT EXISTS webhook_audit (
    id TEXT PRIMARY KEY, action TEXT NOT NULL, subject TEXT NOT NULL,
    grant_id TEXT NOT NULL, subscription_id TEXT, delivery_id TEXT,
    at REAL NOT NULL, detail TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS webhook_due ON webhook_deliveries(state,due_at)",
    "CREATE INDEX IF NOT EXISTS webhook_grant ON webhook_subscriptions(grant_id)",
    """CREATE TABLE IF NOT EXISTS webhook_management_keys (
    principal TEXT NOT NULL, grant_id TEXT NOT NULL, action TEXT NOT NULL,
    key TEXT NOT NULL, request_sha256 TEXT NOT NULL, expires_at REAL NOT NULL,
    response TEXT, PRIMARY KEY(principal,grant_id,action,key))""",
)


def initialize(conn: sqlite3.Connection) -> None:
    """Call explicitly inside Store.transaction(); never commits a caller transaction."""
    for statement in SCHEMA:
        conn.execute(statement)
