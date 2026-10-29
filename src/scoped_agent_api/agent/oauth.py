"""Fixture OAuth client source; no activation, persistence or implicit authority fallback."""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit

from .client import Response


class OAuthError(RuntimeError):
    """Sanitized protocol failure; never includes request, callback or token values."""


class OAuthTransport(Protocol):
    def request(self, method: str, url: str, *, query: dict[str, str] | None = None,
                form: dict[str, str] | None = None) -> Response: ...


class HttpxOAuthTransport:
    """Bounded transport; controller supplies only its pinned authority endpoints."""
    def request(self, method: str, url: str, *, query: dict[str, str] | None = None,
                form: dict[str, str] | None = None) -> Response:
        import httpx
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            return client.request(method, url, params=query, data=form,
                                  headers={"Accept": "application/json"})


def _url(value: str) -> None:
    parts = urlsplit(value)
    if (not parts.hostname or parts.scheme not in {"http", "https"}
            or parts.username or parts.password or parts.query or parts.fragment
            or any(c.isspace() or ord(c) < 33 for c in value)):
        raise ValueError("invalid configured fixture URL")
    if parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("plain HTTP is fixture-loopback only")
    # Force invalid/out-of-range ports to fail during configuration.
    _ = parts.port


_SCOPES = frozenset({"workorders:read", "workorders:write", "workorders:submit",
                     "workorders:approve", "webhooks:manage"})


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    resource: str
    client_id: str
    redirect_uri: str
    allowed_clients: frozenset[str]
    allowed_redirect_uris: frozenset[str]
    allowed_scopes: frozenset[str]
    consent_fixture_id: str
    actor_kind: str = "agent"

    def __post_init__(self) -> None:
        for value in (self.issuer, self.resource, self.redirect_uri):
            _url(value)
        if (not self.client_id or self.client_id not in self.allowed_clients
                or self.redirect_uri not in self.allowed_redirect_uris
                or self.actor_kind not in {"agent", "human"}
                or not self.allowed_scopes <= _SCOPES
                or not 1 <= len(self.consent_fixture_id) <= 200):
            raise ValueError("fixture client configuration is not allowlisted")
        if self.actor_kind == "agent" and "workorders:approve" in self.allowed_scopes:
            raise ValueError("agents cannot be configured for approval scope")


@dataclass(repr=False)
class _Tokens:
    access: str = field(repr=False)
    refresh: str = field(repr=False)
    scopes: frozenset[str]
    expires_at: datetime


class OAuthController:
    """Single-threaded in-memory fixture controller with explicit consent.

    consent(auth_url) must use the configured fixture AS and return its actual
    callback URL, or None for refusal. It must not fabricate successful callbacks
    or bypass authlib_spike_pending. No browser/process is launched here. The
    callback is consumed inside login; there is no replayable external completion
    method. Separate factory instances are required for separate fixture users.
    """
    def __init__(self, config: OAuthConfig, transport: OAuthTransport,
                 consent: Callable[[str], str | None], clock: Callable[[], datetime]) -> None:
        self.config, self.transport, self.consent, self.clock = config, transport, consent, clock
        self.stopped = False
        self._tokens: _Tokens | None = None
        self._metadata: dict[str, object] | None = None
        self._busy = False
        self._used_states: set[str] = set()
        self._used_token_digests: set[str] = set()

    @property
    def scopes(self) -> frozenset[str]:
        return self._tokens.scopes if self._tokens else frozenset()

    def stop(self) -> None:
        """Local refusal/revocation is permanent; no method can reopen this object."""
        self.stopped = True
        self._tokens = None

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise OAuthError("invalid fixture clock")
        return value.astimezone(timezone.utc)

    def _json(self, method: str, url: str, *, form: dict[str, str] | None = None) -> dict[str, object]:
        response = self.transport.request(method, url, form=form)
        status = response.status_code
        if isinstance(status, bool) or not isinstance(status, int) or status != 200:
            # Includes 503 authlib_spike_pending: no fallback or synthetic success.
            raise OAuthError("authorization protocol unavailable or refused")
        value = response.json()
        if not isinstance(value, dict) or "error" in value:
            raise OAuthError("invalid authorization protocol response")
        return dict(value)

    def _discover(self) -> dict[str, object]:
        if self._metadata is not None:
            return self._metadata
        c = self.config
        # Never follow a challenge URL or metadata-supplied destination.
        resource = self._json("GET", c.resource.rstrip("/") + "/.well-known/oauth-protected-resource")
        if resource.get("resource") != c.resource or resource.get("authorization_servers") != [c.issuer]:
            raise OAuthError("resource metadata binding failed")
        base = c.issuer.rstrip("/")
        metadata = self._json("GET", base + "/.well-known/oauth-authorization-server")
        exact = {"issuer": c.issuer, "authorization_endpoint": base + "/authorize",
                 "token_endpoint": base + "/token", "revocation_endpoint": base + "/revoke",
                 "authorization_response_iss_parameter_supported": True}
        if any(metadata.get(key) != value for key, value in exact.items()):
            raise OAuthError("authorization metadata binding failed")
        requirements = {"code_challenge_methods_supported": "S256",
                        "response_types_supported": "code",
                        "token_endpoint_auth_methods_supported": "none",
                        "grant_types_supported": "authorization_code"}
        for key, item in requirements.items():
            value = metadata.get(key)
            if not isinstance(value, list) or item not in value:
                raise OAuthError("required authorization protocol unavailable")
        grants = metadata.get("grant_types_supported")
        if not isinstance(grants, list) or "refresh_token" not in grants:
            raise OAuthError("refresh protocol unavailable")
        self._metadata = metadata
        return metadata

    def _scope_request(self, scopes: frozenset[str]) -> frozenset[str]:
        requested = frozenset(scopes)
        if (not requested or not requested <= self.config.allowed_scopes
                or self.config.actor_kind == "agent" and "workorders:approve" in requested):
            raise OAuthError("requested scopes are not allowlisted")
        return requested

    def _accept_tokens(self, value: dict[str, object], requested: frozenset[str],
                       *, requested_at: datetime, previous_refresh: str | None = None) -> None:
        access, refresh, scope, lifetime = (value.get("access_token"), value.get("refresh_token"),
                                           value.get("scope"), value.get("expires_in"))
        if (value.get("token_type") != "Bearer" or not isinstance(access, str)
                or not isinstance(refresh, str) or not access or not refresh
                or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in access + refresh)
                or len(access) > 4096 or len(refresh) > 4096 or access == refresh
                or not isinstance(scope, str) or isinstance(lifetime, bool)
                or not isinstance(lifetime, int) or not 1 <= lifetime <= 300):
            raise OAuthError("malformed token response")
        scopes = frozenset(scope.split())
        if (not scopes or len(scope.split()) != len(scopes) or not scopes <= requested
                or not scopes <= self.config.allowed_scopes
                or self.config.actor_kind == "agent" and "workorders:approve" in scopes):
            raise OAuthError("token scopes widened")
        digests = {hashlib.sha256(token.encode()).hexdigest() for token in (access, refresh)}
        if digests & self._used_token_digests or refresh == previous_refresh:
            raise OAuthError("token rotation or uniqueness failed")
        # All fields validated before changing live token state.
        expires_at = requested_at + timedelta(seconds=lifetime)
        if self._now() >= expires_at:
            raise OAuthError("token expired before receipt")
        self._used_token_digests.update(digests)
        self._tokens = _Tokens(access, refresh, scopes, expires_at)

    def login(self, scopes: frozenset[str]) -> bool:
        if self.stopped or self._busy:
            self.stop()
            return False
        self._busy = True
        try:
            requested = self._scope_request(scopes)
            self._discover()
            c = self.config
            verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
            deadline = self._now() + timedelta(minutes=5)
            query = {"response_type": "code", "client_id": c.client_id,
                     "redirect_uri": c.redirect_uri, "scope": " ".join(sorted(requested)),
                     "resource": c.resource, "state": state, "code_challenge": challenge,
                     "code_challenge_method": "S256", "consent_fixture_id": c.consent_fixture_id}
            callback = self.consent(c.issuer.rstrip("/") + "/authorize?" + urlencode(query))
            # Callback handling is one-use even when validation/exchange fails.
            state_digest = hashlib.sha256(state.encode()).hexdigest()
            if state_digest in self._used_states:
                raise OAuthError("authorization state reused")
            self._used_states.add(state_digest)
            if self.stopped or not isinstance(callback, str) or self._now() >= deadline:
                raise OAuthError("fixture consent refused or expired")
            received, expected = urlsplit(callback), urlsplit(c.redirect_uri)
            if (received.scheme, received.netloc, received.path) != (expected.scheme, expected.netloc, expected.path) or received.fragment:
                raise OAuthError("authorization callback destination mismatch")
            pairs = parse_qsl(received.query, keep_blank_values=True, strict_parsing=True)
            fields = dict(pairs)
            if (len(fields) != len(pairs) or fields.keys() != {"code", "state", "iss"}
                    or fields["state"] != state or fields["iss"] != c.issuer
                    or not fields["code"] or len(fields["code"]) > 4096):
                raise OAuthError("authorization callback binding failed")
            requested_at = self._now()
            token = self._json("POST", c.issuer.rstrip("/") + "/token", form={
                "grant_type": "authorization_code", "client_id": c.client_id,
                "code": fields["code"], "redirect_uri": c.redirect_uri,
                "resource": c.resource, "code_verifier": verifier})
            self._accept_tokens(token, requested, requested_at=requested_at)
            return True
        except Exception:
            self.stop()
            return False
        finally:
            self._busy = False

    def step_up(self, scopes: frozenset[str]) -> bool:
        if self.stopped:
            return False
        # Existing resource Session owns the one-attempt per-operation budget.
        requested = self.scopes | frozenset(scopes)
        if not self.login(requested) or not requested <= self.scopes:
            self.stop()
            return False
        return True

    def bearer(self) -> str:
        try:
            if self.stopped or self._tokens is None or self._now() >= self._tokens.expires_at:
                raise OAuthError("fixture authorization inactive or expired")
            return self._tokens.access
        except Exception:
            self.stop()
            raise OAuthError("fixture authorization inactive or expired") from None

    def refresh(self) -> bool:
        if self.stopped or self._busy or self._tokens is None:
            self.stop()
            return False
        self._busy = True
        try:
            # Refresh is explicit before expiry; expiry never silently resumes authority.
            if self._now() >= self._tokens.expires_at:
                raise OAuthError("fixture access expired")
            self._discover()
            previous = self._tokens
            requested_at = self._now()
            token = self._json("POST", self.config.issuer.rstrip("/") + "/token", form={
                "grant_type": "refresh_token", "client_id": self.config.client_id,
                "refresh_token": previous.refresh, "resource": self.config.resource,
                "scope": " ".join(sorted(previous.scopes))})
            self._accept_tokens(token, previous.scopes, requested_at=requested_at,
                                previous_refresh=previous.refresh)
            return True
        except Exception:
            self.stop()
            return False
        finally:
            self._busy = False

    def revoke(self) -> None:
        # Close locally before I/O so a failed revocation cannot resume calls.
        previous = self._tokens
        self.stop()
        if previous is None:
            return
        try:
            response = self.transport.request("POST", self.config.issuer.rstrip("/") + "/revoke",
                form={"token": previous.refresh, "client_id": self.config.client_id,
                      "token_type_hint": "refresh_token"})
            if response.status_code != 200:
                raise OAuthError("fixture revocation unconfirmed")
        except Exception:
            raise OAuthError("fixture revocation unconfirmed") from None
