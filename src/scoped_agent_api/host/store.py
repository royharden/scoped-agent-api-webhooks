"""Explicit SQLite lifecycle and shared transaction/authentication seams."""

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .policy import DomainError, PrincipalContext

PrincipalValidator = Callable[[sqlite3.Connection, PrincipalContext, datetime], PrincipalContext]


class Store:
    def __init__(self, path: str | Path) -> None:
        if str(path) == ":memory:":
            raise ValueError("use a disposable file: connections are transaction-scoped")
        self.path = str(path)
        self._principal_validator: PrincipalValidator | None = None

    def set_principal_validator(self, validator: PrincipalValidator) -> None:
        """Install the AS-owned uncached lookup; never trust a posted context."""
        self._principal_validator = validator

    def current_principal(self, conn: sqlite3.Connection, principal: PrincipalContext,
                          now: datetime) -> PrincipalContext:
        if self._principal_validator is None:
            raise DomainError("authentication_unavailable", 503)
        current = self._principal_validator(conn, principal, now)
        if not isinstance(current, PrincipalContext) or current != principal:
            raise DomainError("invalid_principal", 401)
        return current

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def initialize(self) -> None:
        """Explicit host-only migration; authz/webhook schemas are owner-installed."""
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            migration = Path(__file__).with_name("migrations") / "001_domain.sql"
            conn.executescript("BEGIN IMMEDIATE;\n" + migration.read_text(encoding="utf-8") + "\nCOMMIT;")
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
