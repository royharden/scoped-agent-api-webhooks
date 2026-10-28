"""M14-owned durable authorization policy. No import-time DB or network effects."""

import base64
import hashlib
import re
import secrets
import sqlite3
from contextvars import ContextVar
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ..host.policy import DomainError, PrincipalContext
from ..ports.clock import utc

SCOPES = frozenset({"workorders:read", "workorders:write", "workorders:submit",
                    "workorders:approve", "webhooks:manage"})
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def scope_set(value: str) -> frozenset[str]:
    result = frozenset(value.split())
    if not result or not result <= SCOPES:
        raise DomainError("invalid_scope", 400)
    return result


class Authority:
    def __init__(self, store: Any, clock: Any, settings: dict[str, Any]) -> None:
        self.store, self.clock, self.settings = store, clock, settings
        self.issuer = settings["issuer"]
        self.resource = settings["resource"]
        for value in (self.issuer, self.resource):
            if not isinstance(value, str) or any(ord(char) < 33 for char in value):
                raise ValueError("configured issuer and resource URLs required")
            parts = urlsplit(value)
            if (parts.scheme not in {"http", "https"} or not parts.netloc or parts.username
                    or parts.password or parts.query or parts.fragment or '"' in value or "\\" in value):
                raise ValueError("invalid configured issuer or resource URL")
        self.clients = settings.get("clients", {})
        # Proof binds a request's context to its actual token/session, including
        # token expiry rechecked inside the command transaction. No global cache.
        self._proof: ContextVar[tuple[str, str] | None] = ContextVar("m14_proof", default=None)

    def initialize(self) -> None:
        """Explicit schema activation; never called by application creation."""
        sql = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self.store.transaction() as conn:
            # executescript commits an existing transaction; execute statements
            # separately to keep this owner's migration atomic.
            for statement in sql.split(";"):
                if statement.strip():
                    conn.execute(statement)

    def client(self, client_id: str) -> dict[str, Any]:
        client = self.clients.get(client_id)
        if not isinstance(client, dict) or client.get("actor_kind") not in {"human", "agent"}:
            raise DomainError("invalid_client", 400)
        return client

    def _grant(self, conn: sqlite3.Connection, grant_id: str, now: datetime) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM oauth_grants WHERE id=?", (grant_id,)).fetchone()
        if (row is None or row["revoked_at"] is not None
                or now >= datetime.fromisoformat(row["expires_at"])
                or row["issuer"] != self.issuer or row["resource"] != self.resource):
            raise DomainError("invalid_token", 401)
        return row

    @staticmethod
    def _context(row: sqlite3.Row, scopes: frozenset[str]) -> PrincipalContext:
        return PrincipalContext(row["subject"], row["actor_kind"], row["client_id"],
                                row["id"], scopes, row["resource"])

    def _token_context(self, conn: sqlite3.Connection, token_digest: str,
                       now: datetime) -> PrincipalContext:
        token = conn.execute("SELECT * FROM oauth_tokens WHERE digest=? AND kind='access'",
                             (token_digest,)).fetchone()
        if (token is None or token["revoked_at"] is not None
                or now >= datetime.fromisoformat(token["expires_at"])):
            raise DomainError("invalid_token", 401)
        grant = self._grant(conn, token["grant_id"], now)
        family = conn.execute("SELECT * FROM oauth_families WHERE id=?", (token["family_id"],)).fetchone()
        if (family is None or family["revoked_at"] is not None
                or now >= datetime.fromisoformat(family["expires_at"])):
            raise DomainError("invalid_token", 401)
        scopes = scope_set(token["scopes"])
        if not scopes <= scope_set(grant["scopes"]):
            raise DomainError("invalid_token", 401)
        return self._context(grant, scopes)

    def authenticate(self, access_token: str) -> PrincipalContext:
        if not isinstance(access_token, str) or not 1 <= len(access_token) <= 2048:
            raise DomainError("invalid_token", 401)
        key = digest(access_token)
        with self.store.transaction() as conn:
            principal = self._token_context(conn, key, utc(self.clock.now()))
        self._proof.set(("access", key))
        return principal

    def validate_principal(self, conn: sqlite3.Connection, principal: PrincipalContext,
                           now: datetime) -> PrincipalContext:
        proof = self._proof.get()
        if proof is None:
            raise DomainError("invalid_principal", 401)
        if proof[0] == "access":
            current = self._token_context(conn, proof[1], utc(now))
        else:
            current, _ = self._session_context(conn, proof[1], utc(now))
        if current != principal:
            raise DomainError("invalid_principal", 401)
        return current

    def clear_proof(self) -> None:
        self._proof.set(None)

    def authorize_code(self, client_id: str, redirect_uri: str, resource: str,
                       scopes: str, challenge: str, consent_fixture_id: str) -> str:
        """Called only by the protocol adapter after S256/state request validation.

        Subject/consent come from a server-owned fixture resolver, never posted
        principal fields. This mock resolver is explicitly not a hosted login.
        """
        client = self.client(client_id)
        if redirect_uri not in client.get("redirect_uris", ()) or resource != self.resource:
            raise DomainError("invalid_request", 400)
        if not _CHALLENGE.fullmatch(challenge):
            raise DomainError("invalid_request", 400)
        requested = scope_set(scopes)
        if not requested <= frozenset(client.get("allowed_scopes", ())):
            raise DomainError("invalid_scope", 400)
        if client["actor_kind"] == "agent" and "workorders:approve" in requested:
            raise DomainError("invalid_scope", 400)
        resolver = self.settings.get("consent_resolver")
        if not callable(resolver):
            raise DomainError("consent_unavailable", 503)
        consent = resolver(consent_fixture_id, client_id, requested, resource)
        if (not isinstance(consent, dict) or consent.get("allowed") is not True
                or not isinstance(consent.get("subject"), str) or not consent["subject"]):
            raise DomainError("access_denied", 403)
        grant_id, code = str(uuid4()), secrets.token_urlsafe(32)
        lifetime = self.settings.get("grant_lifetime_seconds", 86400)
        if type(lifetime) is not int or not 60 <= lifetime <= 8 * 86400 + 3600:
            raise DomainError("invalid_fixture_lifetime", 400)
        with self.store.transaction() as conn:
            now = utc(self.clock.now())
            conn.execute("INSERT INTO oauth_grants VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                         (grant_id, consent["subject"], client["actor_kind"], client_id,
                          self.issuer, self.resource, " ".join(sorted(requested)),
                          now.isoformat(), (now + timedelta(seconds=lifetime)).isoformat()))
            conn.execute("INSERT INTO oauth_codes VALUES (?,?,?,?,?,?,?,NULL)",
                         (digest(code), grant_id, client_id, redirect_uri, resource, challenge,
                          (now + timedelta(seconds=60)).isoformat()))
        return code

    def _issue(self, conn: sqlite3.Connection, grant: sqlite3.Row, family_id: str,
               scopes: frozenset[str], now: datetime) -> dict[str, Any]:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        expires = min(now + timedelta(minutes=5), datetime.fromisoformat(grant["expires_at"]))
        family = conn.execute("SELECT * FROM oauth_families WHERE id=?", (family_id,)).fetchone()
        for raw, kind, expiry in ((access, "access", expires),
                                  (refresh, "refresh", datetime.fromisoformat(family["expires_at"]))):
            conn.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?,NULL,NULL)",
                         (digest(raw), kind, grant["id"], family_id,
                          " ".join(sorted(scopes)), expiry.isoformat()))
        return {"access_token": access, "token_type": "Bearer", "expires_in": int((expires-now).total_seconds()),
                "refresh_token": refresh, "scope": " ".join(sorted(scopes))}

    def exchange_code(self, code: str, client_id: str, redirect_uri: str,
                      resource: str, verifier: str) -> dict[str, Any]:
        self.client(client_id)
        if resource != self.resource or not _VERIFIER.fullmatch(verifier):
            raise DomainError("invalid_grant", 400)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        with self.store.transaction() as conn:
            now = utc(self.clock.now())
            row = conn.execute("SELECT * FROM oauth_codes WHERE digest=?", (digest(code),)).fetchone()
            if (row is None or row["consumed_at"] is not None
                    or row["client_id"] != client_id or row["redirect_uri"] != redirect_uri
                    or row["resource"] != resource or now >= datetime.fromisoformat(row["expires_at"])
                    or not secrets.compare_digest(row["challenge"], challenge)):
                raise DomainError("invalid_grant", 400)
            grant = self._grant(conn, row["grant_id"], now)
            conn.execute("UPDATE oauth_codes SET consumed_at=? WHERE digest=? AND consumed_at IS NULL",
                         (now.isoformat(), row["digest"]))
            family_id = str(uuid4())
            conn.execute("INSERT INTO oauth_families VALUES (?,?,?,NULL)",
                         (family_id, grant["id"], grant["expires_at"]))
            return self._issue(conn, grant, family_id, scope_set(grant["scopes"]), now)

    def _revocation_hooks(self) -> tuple[Any, Any]:
        # Exactly DL3's process-owned registry, also used by dispatch. Never
        # create a second local lock or silently skip lifecycle cancellation.
        try:
            from ..webhooks.locks import GRANT_LOCKS
            from ..webhooks.subscriptions import suspend_grant
        except ImportError as exc:
            raise DomainError("revocation_unavailable", 503) from exc
        return GRANT_LOCKS.hold, lambda conn, grant, now, reason: suspend_grant(conn, grant, now)

    def _revoke(self, conn: sqlite3.Connection, grant_id: str, now: datetime, reason: str,
                cascade: Any) -> None:
        stamp = now.isoformat()
        conn.execute("UPDATE oauth_grants SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", (stamp, grant_id))
        conn.execute("UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,?) WHERE grant_id=?", (stamp, grant_id))
        conn.execute("UPDATE oauth_tokens SET revoked_at=COALESCE(revoked_at,?) WHERE grant_id=?", (stamp, grant_id))
        conn.execute("UPDATE oauth_ui_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE grant_id=?", (stamp, grant_id))
        cascade(conn, grant_id, now, reason)
        conn.execute("INSERT INTO oauth_security_events VALUES (?,?,?,?)", (str(uuid4()), grant_id, reason, stamp))

    def refresh(self, refresh_token: str, client_id: str, resource: str,
                scopes: str | None = None) -> dict[str, Any]:
        self.client(client_id)
        if resource != self.resource:
            raise DomainError("invalid_grant", 400)
        key = digest(refresh_token)
        # Discover only the lock identity. All eligibility is rechecked under lock.
        with self.store.transaction() as conn:
            row = conn.execute("SELECT grant_id FROM oauth_tokens WHERE digest=? AND kind='refresh'", (key,)).fetchone()
        if row is None:
            raise DomainError("invalid_grant", 400)
        lock, cascade = self._revocation_hooks()
        reused = False
        result: dict[str, Any] = {}
        with lock(row["grant_id"]):
            with self.store.transaction() as conn:
                now = utc(self.clock.now())
                token = conn.execute("SELECT * FROM oauth_tokens WHERE digest=? AND kind='refresh'", (key,)).fetchone()
                grant = self._grant(conn, token["grant_id"], now)
                family = conn.execute("SELECT * FROM oauth_families WHERE id=?", (token["family_id"],)).fetchone()
                if (grant["client_id"] != client_id or token["revoked_at"] is not None
                        or family is None or family["revoked_at"] is not None
                        or now >= datetime.fromisoformat(token["expires_at"])
                        or now >= datetime.fromisoformat(family["expires_at"])):
                    raise DomainError("invalid_grant", 400)
                if token["used_at"] is not None:
                    # Commit the cascade before returning a protocol error.
                    self._revoke(conn, grant["id"], now, "refresh_reuse", cascade)
                    reused = True
                else:
                    requested = scope_set(scopes) if scopes is not None else scope_set(token["scopes"])
                    if not requested <= scope_set(token["scopes"]) or not requested <= scope_set(grant["scopes"]):
                        raise DomainError("invalid_scope", 400)
                    conn.execute("UPDATE oauth_tokens SET used_at=? WHERE digest=? AND used_at IS NULL", (now.isoformat(), key))
                    result = self._issue(conn, grant, family["id"], requested, now)
        if reused:
            raise DomainError("invalid_grant", 400)
        return result

    def revoke(self, token: str, client_id: str) -> None:
        self.client(client_id)
        with self.store.transaction() as conn:
            row = conn.execute("SELECT t.grant_id,g.client_id FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id WHERE t.digest=?", (digest(token),)).fetchone()
        # RFC7009 does not disclose unknown or another client's tokens.
        if row is None or row["client_id"] != client_id:
            return
        lock, cascade = self._revocation_hooks()
        with lock(row["grant_id"]):
            with self.store.transaction() as conn:
                self._revoke(conn, row["grant_id"], utc(self.clock.now()), "revoked", cascade)

    def create_ui_session(self, principal: PrincipalContext) -> dict[str, str]:
        raw, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.transaction() as conn:
            now = utc(self.clock.now())
            current = self.validate_principal(conn, principal, now)
            if current.actor_kind != "human":
                raise DomainError("human_required", 403)
            conn.execute("INSERT INTO oauth_ui_sessions VALUES (?,?,?,?,?,NULL)",
                         (digest(raw), current.grant_id, " ".join(sorted(current.scopes)), csrf,
                          (now + timedelta(minutes=15)).isoformat()))
        return {"session_id": raw, "csrf_token": csrf}

    def _session_context(self, conn: sqlite3.Connection, key: str,
                         now: datetime) -> tuple[PrincipalContext, str]:
        session = conn.execute("SELECT * FROM oauth_ui_sessions WHERE digest=?", (key,)).fetchone()
        if (session is None or session["revoked_at"] is not None
                or now >= datetime.fromisoformat(session["expires_at"])):
            raise DomainError("invalid_session", 401)
        grant = self._grant(conn, session["grant_id"], now)
        if grant["actor_kind"] != "human":
            raise DomainError("human_required", 403)
        scopes = scope_set(session["scopes"])
        if not scopes <= scope_set(grant["scopes"]):
            raise DomainError("invalid_session", 401)
        return self._context(grant, scopes), session["csrf_token"]

    def resolve_ui_session(self, session_id: str) -> tuple[PrincipalContext, str]:
        key = digest(session_id)
        with self.store.transaction() as conn:
            result = self._session_context(conn, key, utc(self.clock.now()))
        self._proof.set(("session", key))
        return result

    def grant_is_active(self, grant_id: str, required_scopes: frozenset[str]) -> bool:
        """Dispatch checks grant/family expiry, not short access-token expiry."""
        with self.store.transaction() as conn:
            return self.grant_validator_in_transaction(conn, grant_id, required_scopes,
                                                       utc(self.clock.now()))

    def grant_validator_in_transaction(self, conn: sqlite3.Connection, grant_id: str,
                                       required_scopes: frozenset[str], now: datetime) -> bool:
        """Last eligibility check using the worker's already-held writer.

        Worker passes current aware UTC after acquiring BEGIN IMMEDIATE, before
        attempt_started. Never acquire a grant lock, open a connection, commit,
        consult request proof or use a previously captured time in this callback.
        """
        now = utc(now)
        try:
            grant = self._grant(conn, grant_id, now)
            families = conn.execute("SELECT expires_at FROM oauth_families WHERE grant_id=? AND revoked_at IS NULL", (grant_id,))
            return (required_scopes <= scope_set(grant["scopes"])
                    and any(now < datetime.fromisoformat(row["expires_at"]) for row in families))
        except DomainError:
            return False

    def begin_ui_login(self, client_id: str, redirect_uri: str,
                       scopes: str | frozenset[str]) -> dict[str, str]:
        client = self.client(client_id)
        requested = scope_set(scopes if isinstance(scopes, str) else " ".join(sorted(scopes)))
        if (client["actor_kind"] != "human" or redirect_uri not in client.get("redirect_uris", ())
                or not requested <= frozenset(client.get("allowed_scopes", ()))):
            raise DomainError("invalid_client", 400)
        login_id, state, verifier = (secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                                      secrets.token_urlsafe(48))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        with self.store.transaction() as conn:
            conn.execute("INSERT INTO oauth_ui_logins VALUES (?,?,?,?,?,?,?,NULL)",
                         (digest(login_id), digest(state), verifier, client_id, redirect_uri,
                          " ".join(sorted(requested)), (utc(self.clock.now()) + timedelta(minutes=5)).isoformat()))
        return {"login_id": login_id, "state": state, "code_challenge": challenge}

    def finish_ui_login(self, login_id: str, state: str, issuer: str, code: str,
                        transport: Any) -> PrincipalContext:
        if issuer != self.issuer or not callable(transport) or not code:
            raise DomainError("invalid_oauth_callback", 400)
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM oauth_ui_logins WHERE digest=?", (digest(login_id),)).fetchone()
            if (row is None or row["consumed_at"] is not None
                    or utc(self.clock.now()) >= datetime.fromisoformat(row["expires_at"])
                    or not secrets.compare_digest(row["state_digest"], digest(state))):
                raise DomainError("invalid_oauth_state", 400)
            conn.execute("UPDATE oauth_ui_logins SET consumed_at=? WHERE digest=? AND consumed_at IS NULL",
                         (utc(self.clock.now()).isoformat(), row["digest"]))
        # No writer lock held over transport. A failed exchange consumes this
        # login attempt; starting a fresh login is required. Only configured URL.
        try:
            result = transport(self.issuer.rstrip("/") + "/token", {"grant_type": "authorization_code",
                "client_id": row["client_id"], "redirect_uri": row["redirect_uri"],
                "resource": self.resource, "code": code, "code_verifier": row["verifier"]})
        except Exception:
            raise DomainError("oauth_transport_failed", 502) from None
        if (not isinstance(result, dict) or not isinstance(result.get("token_type"), str)
                or result["token_type"].lower() != "bearer"
                or not isinstance(result.get("access_token"), str)):
            raise DomainError("invalid_oauth_response", 502)
        principal = self.authenticate(result["access_token"])
        if (principal.client_id != row["client_id"] or principal.actor_kind != "human"
                or principal.scopes != scope_set(row["scopes"])):
            raise DomainError("invalid_oauth_response", 502)
        return principal
