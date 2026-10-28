"""Durable receiver storage; initialization is always an explicit caller action."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

RETENTION = timedelta(days=8)
MINIMUM_RETENTION = timedelta(days=7, seconds=300 + 5 + 3600)

SCHEMA = """
CREATE TABLE IF NOT EXISTS receiver_inbox (
    event_id TEXT PRIMARY KEY,
    body_digest TEXT NOT NULL,
    body BLOB NOT NULL,
    received_at REAL NOT NULL,
    processed_at REAL
);
CREATE TABLE IF NOT EXISTS receiver_resources (
    arm TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_version INTEGER NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (arm, resource_id)
);
CREATE TABLE IF NOT EXISTS receiver_counters (
    arm TEXT NOT NULL,
    name TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (arm, name)
);
CREATE TABLE IF NOT EXISTS receiver_conflicts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    original_digest TEXT NOT NULL,
    received_digest TEXT NOT NULL,
    received_at REAL NOT NULL
);
"""


def timestamp(now: datetime) -> float:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("receiver clock must be timezone-aware")
    return now.timestamp()


def count(connection: sqlite3.Connection, arm: str, name: str) -> None:
    connection.execute(
        "INSERT INTO receiver_counters(arm,name,value) VALUES (?,?,1) "
        "ON CONFLICT(arm,name) DO UPDATE SET value=value+1",
        (arm, name),
    )


def apply_snapshot(
    connection: sqlite3.Connection, arm: str, event: dict[str, Any], *, guarded: bool
) -> bool:
    resource_id = event["resource_id"]
    version = event["resource_version"]
    previous = connection.execute(
        "SELECT resource_version FROM receiver_resources WHERE arm=? AND resource_id=?",
        (arm, resource_id),
    ).fetchone()
    if guarded and previous is not None and version <= previous[0]:
        count(connection, arm, "stale")
        return False
    connection.execute(
        "INSERT INTO receiver_resources(arm,resource_id,resource_version,snapshot) "
        "VALUES (?,?,?,?) ON CONFLICT(arm,resource_id) DO UPDATE SET "
        "resource_version=excluded.resource_version,snapshot=excluded.snapshot",
        (arm, resource_id, version, json.dumps(event["data"], separators=(",", ":"))),
    )
    count(connection, arm, "applied")
    return True


class ReceiverStore:
    """One receiver database per arm/environment; no module-import effects."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("durable receiver requires a file-backed database")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def initialize(self) -> None:
        if RETENTION <= MINIMUM_RETENTION:
            raise ValueError("receiver retention must exceed replay safety bound")
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def counters(self, arm: str = "reference") -> dict[str, int]:
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT name,value FROM receiver_counters WHERE arm=?", (arm,)
            ).fetchall()
        result = dict.fromkeys(
            ("accepted", "inserted", "processed", "applied", "stale", "duplicates", "conflicts"), 0
        )
        result.update({row["name"]: row["value"] for row in rows})
        return result

    def resource(self, resource_id: str, arm: str = "reference") -> dict[str, Any] | None:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT snapshot FROM receiver_resources WHERE arm=? AND resource_id=?",
                (arm, resource_id),
            ).fetchone()
        return None if row is None else json.loads(row[0])

    def prune(self, now: datetime) -> int:
        """Only completed rows expire; counters and resource versions survive."""
        cutoff = timestamp(now) - RETENTION.total_seconds()
        with self.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM receiver_inbox WHERE processed_at IS NOT NULL AND received_at<?",
                (cutoff,),
            )
            return cursor.rowcount
