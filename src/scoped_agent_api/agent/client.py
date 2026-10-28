"""Injected public HTTP transport and bounded scope step-up. No local database access."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol
from urllib.parse import quote, urlsplit
import re


class Response(Protocol):
    status_code: int
    headers: Mapping[str, str]
    def json(self) -> object: ...


class Transport(Protocol):
    def request(self, method: str, url: str, *, headers: dict[str, str],
                json: dict[str, object] | None) -> Response: ...


class ResponseError(RuntimeError):
    """The public HTTP response did not have the expected JSON representation."""


# Closed literals declared by host/api/authz source, plus client-local failures.
# Never treat arbitrary strings in a problem response as safe diagnostic text.
_PROBLEM_CODES = frozenset({
    "access_denied", "agent_ui_unsupported", "authentication_unavailable",
    "authlib_spike_pending", "capability_binding", "capability_consumed",
    "capability_expired", "capability_required", "capability_stale",
    "challenge_confirmed", "challenge_expired", "challenge_not_found",
    "consent_unavailable", "empty_edit", "expected_version_required", "http_error",
    "human_confirmation_required", "human_required", "idempotency_conflict",
    "idempotency_expired", "idempotency_key_required", "idempotency_record_invalid",
    "insufficient_scope", "invalid_arguments", "invalid_assignee", "invalid_client",
    "invalid_fixture_lifetime", "invalid_grant", "invalid_idempotency_key",
    "invalid_limit", "invalid_oauth_callback", "invalid_oauth_response",
    "invalid_oauth_state", "invalid_pagination", "invalid_principal",
    "invalid_request", "invalid_scope", "invalid_session", "invalid_surface",
    "invalid_title", "invalid_token", "invalid_token_transport", "invalid_transition",
    "json_required", "not_found", "oauth_transport_failed", "revocation_unavailable",
    "session_stopped", "statement_mismatch", "submitted_title_immutable",
    "transport_error", "unexpected_authlib_token_path", "unknown_operation",
    "unsupported_grant_type", "version_conflict", "webhooks_unavailable", "wrong_executor",
})


def problem(status: int, code: object) -> dict[str, object]:
    """Build the closed problem shape from locally selected, nonsecret values."""
    safe_code = code if isinstance(code, str) and code in _PROBLEM_CODES else "http_error"
    # Correlation stays local rather than echoing an unvalidated response ID.
    return {"type": "about:blank", "title": "Public HTTP request failed",
            "status": status if 400 <= status <= 599 else 502,
            "code": safe_code, "request_id": "client"}


@dataclass(frozen=True)
class Result:
    status: int
    data: dict[str, object]
    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class Session:
    # Token values are supplied in memory by a separately validated fixture auth flow.
    resource: str
    transport: Transport
    bearer: Callable[[], str] = field(repr=False)
    scopes: frozenset[str] = frozenset()
    step_up: Callable[[frozenset[str]], bool] | None = field(default=None, repr=False)
    stopped: bool = False
    _attempted: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        parts = urlsplit(self.resource)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username or parts.password or parts.query or parts.fragment):
            raise ValueError("resource must be an explicit origin/base URL")
        if parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("plain HTTP is fixture-loopback only")
        self.resource = self.resource.rstrip("/")

    def call(self, operation: str, method: str, path: str,
             body: dict[str, object] | None = None, key: str | None = None,
             *, surface: str = "api") -> Result:
        if self.stopped:
            return Result(403, problem(403, "session_stopped"))
        if not path.startswith("/v1/") or "?" in path or "#" in path:
            raise ValueError("only declared public resource routes are allowed")
        result, challenge = self._send(method, path, body, key, surface)
        if result.status == 401:
            self.stopped = True
            return result
        marker = (self.resource, operation)
        if (result.status == 403 and result.data.get("code") == "insufficient_scope"
                and challenge and marker not in self._attempted):
            self._attempted.add(marker)
            match = re.fullmatch(
                r'(?i:Bearer)\s+error="insufficient_scope"\s*,\s*'
                r'scope="([a-z][a-z0-9:_-]*(?: [a-z][a-z0-9:_-]*)*)"', challenge)
            required = frozenset(match.group(1).split()) if match else frozenset()
            # Human-only approval cannot be acquired or consumed by this agent.
            if (not required or "workorders:approve" in required or self.step_up is None
                    or not self.step_up(self.scopes | required)):
                self.stopped = True
                return result
            self.scopes |= required
            # _send stopped the session before parsing the refusal. Only this
            # validated, consented challenge permits one bounded internal call.
            # Keep it stopped if decoding that retry fails as well.
            result, _ = self._send(method, path, body, key, surface)
            if result.status not in {401, 403}:
                self.stopped = False
        if result.status in {401, 403}:
            self.stopped = True
        return result

    def _send(self, method: str, path: str, body: dict[str, object] | None,
              key: str | None, surface: str) -> tuple[Result, str]:
        token = self.bearer()
        if not token or any(c.isspace() for c in token):
            raise ValueError("missing or malformed in-memory bearer")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
                   "X-M14-Surface": surface}
        if key:
            if len(key) > 200 or any(ord(c) < 33 or ord(c) > 126 for c in key):
                raise ValueError("invalid idempotency key")
            headers["Idempotency-Key"] = key
        response = self.transport.request(method, self.resource + path, headers=headers, json=body)
        try:
            status = response.status_code
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ResponseError("invalid HTTP status")
            # A refusal closes authority even if reading headers/JSON later fails.
            if status in {401, 403}:
                self.stopped = True
            challenge = response.headers.get("WWW-Authenticate", "")
            if not isinstance(challenge, str):
                raise ResponseError("invalid authentication challenge")
            value = response.json()
            if not isinstance(value, dict):
                raise ResponseError("expected JSON object")
        except Exception:
            # Decoders can raise ValueError/TypeError; these are response failures,
            # never command input errors. Do not retain their potentially secret text.
            raise ResponseError("invalid public HTTP response") from None
        data = dict(value)
        if status >= 300:
            # Response strings are untrusted, even inside declared problem fields.
            data = problem(status, data.get("code"))
        return Result(status, data), challenge


class HttpxTransport:
    """One bounded request; redirects disabled so bearer authority never migrates."""
    def request(self, method: str, url: str, *, headers: dict[str, str],
                json: dict[str, object] | None) -> Response:
        import httpx
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            return client.request(method, url, headers=headers, json=json)


READS = {"list", "get", "subscriptions", "subscription", "deliveries", "delivery"}


def route(operation: str, arguments: dict[str, object]) -> tuple[str, str, dict[str, object] | None]:
    """Only route syntax; authority and state transitions remain server-side."""
    args = dict(arguments)
    identifier = args.pop("id", None)
    item = quote(str(identifier), safe="") if identifier is not None else None
    if item in {".", ".."}:
        raise ValueError("invalid identifier")
    paths = {
        "list": ("GET", "/v1/work-orders"), "create": ("POST", "/v1/work-orders"),
        "subscriptions": ("GET", "/v1/subscriptions"),
        "subscribe": ("POST", "/v1/subscriptions"),
        "deliveries": ("GET", "/v1/deliveries"), "recover": ("POST", "/v1/deliveries/recover"),
    }
    if operation in paths:
        method, path = paths[operation]
    else:
        if not item:
            raise ValueError("operation requires id")
        if operation in {"get", "edit", "submit", "approve", "close", "cancel", "challenge"}:
            if operation == "challenge":
                args["id"] = identifier
                method, path = "POST", "/v1/approval-challenges"
            else:
                method = "GET" if operation == "get" else "PATCH" if operation == "edit" else "POST"
                path = "/v1/work-orders/" + item
                if operation not in {"get", "edit"}:
                    path += "/" + operation
        elif operation == "confirm":
            method, path = "POST", "/v1/approval-challenges/" + item + "/confirm"
        elif operation in {"subscription", "disable", "enable"}:
            method = "GET" if operation == "subscription" else "POST"
            path = "/v1/subscriptions/" + item
            if operation != "subscription":
                path += "/" + operation
        elif operation in {"delivery", "replay"}:
            method = "GET" if operation == "delivery" else "POST"
            path = "/v1/deliveries/" + item + ("/replay" if operation == "replay" else "")
        else:
            raise ValueError("unknown operation")
    if method == "GET" and args:
        raise ValueError("read operation takes only id")
    return method, path, None if method == "GET" else args


@dataclass(frozen=True)
class FixtureConsent:
    """Issued by the future disposable fixture launcher, never from posted API authority."""
    workspace_id: str
    consent_fixture_id: str
    disposable: bool
    human_confirmed: bool

    def permits(self) -> bool:
        return bool(self.workspace_id and self.consent_fixture_id and self.disposable and self.human_confirmed)


def run_task(task: dict[str, object], session: Session | None = None, *, apply_fixture: bool = False,
             consent: FixtureConsent | None = None,
             session_factory: Callable[[str], Session] | None = None) -> list[dict[str, object]]:
    """Developer tasks, never oracle expectations. Stops after first refusal/failure."""
    if task.get("schema_version") != "m14.task.v1":
        raise ValueError("unsupported task major/version")
    steps = task.get("steps")
    if not isinstance(steps, list):
        raise ValueError("steps must be an array")
    if apply_fixture and (consent is None or not consent.permits()
            or task.get("consent_fixture_id") != consent.consent_fixture_id):
        raise ValueError("disposable human fixture consent required")
    output = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get("arguments", {}), dict):
            raise ValueError("invalid task step")
        operation = str(step.get("operation", ""))
        if operation in {"approve", "confirm"}:
            result = Result(403, {"code": "human_only"})
            if session is not None:
                session.stopped = True
        else:
            arguments = dict(step.get("arguments", {}))
            if step.get("expected_version") is not None:
                arguments["expected_version"] = step["expected_version"]
            method, path, body = route(operation, arguments)
            key = step.get("idempotency_key")
            if method != "GET" and not apply_fixture:
                result = Result(200, {"code": "dry_run"})
            elif method != "GET" and (not isinstance(key, str) or not key):
                raise ValueError("mutation requires idempotency_key")
            else:
                if session is None and session_factory is not None:
                    session = session_factory("agent")
                if session is None:
                    raise ValueError("authenticated fixture session required")
                result = session.call(operation, method, path, body, str(key) if key else None)
        output.append({"task_id": task.get("task_id"), "step_id": str(index),
                       "decision": "dry_run" if result.data.get("code") == "dry_run" else "allowed" if result.ok else "denied",
                       "code": result.data.get("code", "ok"), "resource_id": result.data.get("id"),
                       "resource_version": result.data.get("version"), "effect_ref": None})
        if not result.ok:
            break
    return output
