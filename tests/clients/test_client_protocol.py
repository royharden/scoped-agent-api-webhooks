"""Construction-exposed DEVELOPMENT regressions, never study/oracle evidence.

Scripted responses below exercise client error handling only. They are not an
authorization-server implementation, interoperability proof, or Authlib spike.
No test fabricates a successful authorization callback.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from scoped_agent_api.agent.client import ResponseError, Session
from scoped_agent_api.agent.oauth import OAuthConfig, OAuthController, OAuthError


@dataclass
class Reply:
    status_code: int = 200
    value: object = field(default_factory=dict, repr=False)
    headers: dict[str, str] = field(default_factory=dict)
    malformed: bool = False

    def json(self) -> object:
        if self.malformed:
            raise ValueError("development malformed reply")
        return self.value


class RecordingTransport:
    def __init__(self, *replies: Reply) -> None:
        self.replies = list(replies)
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs: object) -> Reply:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.replies:
            raise AssertionError("unexpected additional development request")
        return self.replies.pop(0)


READ = frozenset({"workorders:read"})
WRITE = frozenset({"workorders:write"})
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def config() -> OAuthConfig:
    return OAuthConfig(
        issuer="https://as.development.invalid", resource="https://api.development.invalid",
        client_id="development-agent", redirect_uri="https://client.development.invalid/callback",
        allowed_clients=frozenset({"development-agent"}),
        allowed_redirect_uris=frozenset({"https://client.development.invalid/callback"}),
        allowed_scopes=READ | WRITE, consent_fixture_id="development-explicit-consent",
    )


def metadata_replies() -> list[Reply]:
    c = config()
    return [Reply(value={"resource": c.resource, "authorization_servers": [c.issuer]}), Reply(value={
        "issuer": c.issuer, "authorization_endpoint": c.issuer + "/authorize",
        "token_endpoint": c.issuer + "/token", "revocation_endpoint": c.issuer + "/revoke",
        "authorization_response_iss_parameter_supported": True,
        "code_challenge_methods_supported": ["S256"], "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    })]


@pytest.mark.parametrize("status", [401, 403])
def test_malformed_denial_closes_before_decode_and_blocks_second_request(status: int) -> None:
    transport = RecordingTransport(Reply(status_code=status, malformed=True))
    session = Session(config().resource, transport, bearer=lambda: secrets.token_urlsafe(24))
    with pytest.raises(ResponseError):
        session.call("list", "GET", "/v1/work-orders")
    assert session.stopped
    blocked = session.call("list", "GET", "/v1/work-orders")
    assert blocked.status == 403 and blocked.data["code"] == "session_stopped"
    assert set(blocked.data) == {"type", "title", "status", "code", "request_id"}
    assert len(transport.calls) == 1


def scope_reply(scope: str = "workorders:write") -> Reply:
    return Reply(status_code=403, value={"code": "insufficient_scope"}, headers={
        "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"',
    })


def test_step_up_uses_union_once_and_keeps_exact_retry_key() -> None:
    transport = RecordingTransport(scope_reply(), Reply(value={"id": "development-order"}), scope_reply())
    requested: list[frozenset[str]] = []
    session = Session(config().resource, transport, bearer=lambda: secrets.token_urlsafe(24),
                      scopes=READ, step_up=lambda scopes: requested.append(scopes) is None)
    first = session.call("create", "POST", "/v1/work-orders", {"title": "Inspect pump"}, "same-key")
    assert first.ok and not session.stopped
    second = session.call("create", "POST", "/v1/work-orders", {"title": "Inspect pump"}, "same-key")
    assert second.status == 403 and session.stopped
    assert requested == [READ | WRITE]
    assert len(transport.calls) == 3
    assert all(call["headers"]["Idempotency-Key"] == "same-key" for call in transport.calls)


@pytest.mark.parametrize("scope,allowed", [("workorders:write", False), ("workorders:approve", True)])
def test_refused_or_human_scope_stops_without_retry(scope: str, allowed: bool) -> None:
    transport = RecordingTransport(scope_reply(scope))
    decisions: list[frozenset[str]] = []
    def consent(scopes: frozenset[str]) -> bool:
        decisions.append(scopes)
        return allowed
    session = Session(config().resource, transport, bearer=lambda: secrets.token_urlsafe(24),
                      scopes=READ, step_up=consent)
    assert session.call("create", "POST", "/v1/work-orders", {}, "development-key").status == 403
    assert session.stopped and len(transport.calls) == 1
    assert len(decisions) == (0 if scope == "workorders:approve" else 1)


@pytest.mark.parametrize("defect", ["state", "issuer", "redirect", "duplicate", "missing_code", "error"])
def test_invalid_callback_never_exchanges_code_or_reopens(defect: str) -> None:
    c = config()
    transport = RecordingTransport(*metadata_replies())
    def malformed_callback(auth_url: str) -> str:
        query = parse_qs(urlsplit(auth_url).query)
        assert query["resource"] == [c.resource]
        assert query["code_challenge_method"] == ["S256"]
        assert "code_verifier" not in query
        fields = {"code": "development-invalid-code", "state": query["state"][0], "iss": c.issuer}
        destination = c.redirect_uri
        if defect == "state": fields["state"] = "development-wrong-state"
        elif defect == "issuer": fields["iss"] = "https://untrusted.development.invalid"
        elif defect == "redirect": destination += "/wrong"
        elif defect == "missing_code": fields.pop("code")
        elif defect == "error": fields["error"] = "access_denied"
        result = destination + "?" + urlencode(fields)
        return result + ("&state=duplicate" if defect == "duplicate" else "")
    controller = OAuthController(c, transport, malformed_callback, lambda: NOW)
    assert not controller.login(READ)
    assert controller.stopped and len(transport.calls) == 2
    assert not controller.login(READ)
    assert len(transport.calls) == 2


def test_pinned_metadata_rejects_substituted_token_endpoint() -> None:
    replies = metadata_replies()
    replies[1].value["token_endpoint"] = "https://untrusted.development.invalid/token"
    transport = RecordingTransport(*replies)
    consent_calls: list[str] = []
    controller = OAuthController(config(), transport, lambda url: consent_calls.append(url), lambda: NOW)
    assert not controller.login(READ)
    assert controller.stopped and not consent_calls and len(transport.calls) == 2


def preloaded_controller(*replies: Reply) -> tuple[OAuthController, RecordingTransport, str]:
    """Set up a client-state primitive, NOT a successful AS/login fixture.

    This deliberately bypasses no server gate: no server is instantiated. It
    exercises refresh/revoke handling of an existing in-memory client state.
    """
    transport = RecordingTransport(*replies)
    controller = OAuthController(config(), transport, lambda _: None, lambda: NOW)
    refresh = secrets.token_urlsafe(32)
    controller._accept_tokens({"access_token": secrets.token_urlsafe(32), "refresh_token": refresh,
                               "token_type": "Bearer", "scope": "workorders:read", "expires_in": 300},
                              READ, requested_at=NOW)
    return controller, transport, refresh


@pytest.mark.parametrize("defect", ["widening", "reused_refresh", "malformed"])
def test_refresh_rejects_widening_reuse_and_malformed_response(defect: str) -> None:
    response = Reply(value={"access_token": secrets.token_urlsafe(32), "refresh_token": secrets.token_urlsafe(32),
                            "token_type": "Bearer", "scope": "workorders:read", "expires_in": 300})
    controller, transport, old_refresh = preloaded_controller(*metadata_replies(), response)
    if defect == "widening": response.value["scope"] = "workorders:read workorders:write"
    elif defect == "reused_refresh": response.value["refresh_token"] = old_refresh
    else: response.malformed = True
    assert not controller.refresh()
    assert controller.stopped
    with pytest.raises(OAuthError): controller.bearer()
    assert not controller.refresh() and len(transport.calls) == 3
    sent = transport.calls[-1]["form"]
    assert sent["grant_type"] == "refresh_token"
    assert sent["scope"] == "workorders:read" and sent["resource"] == config().resource


def test_refresh_rotates_local_state_without_claiming_as_interop() -> None:
    new_access, new_refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    controller, transport, _ = preloaded_controller(*metadata_replies(), Reply(value={
        "access_token": new_access, "refresh_token": new_refresh, "token_type": "Bearer",
        "scope": "workorders:read", "expires_in": 300,
    }))
    assert controller.refresh()
    assert controller.bearer() == new_access and controller.scopes == READ
    # No scripted revoke response remains: local closure must survive transport failure.
    with pytest.raises(OAuthError):
        controller.revoke()
    assert controller.stopped and len(transport.calls) == 4


@pytest.mark.parametrize("status", [200, 503])
def test_revoke_closes_before_transport_and_cannot_resume(status: int) -> None:
    controller, transport, _ = preloaded_controller(Reply(status_code=status))
    if status == 200:
        controller.revoke()
    else:
        with pytest.raises(OAuthError): controller.revoke()
    assert controller.stopped
    with pytest.raises(OAuthError): controller.bearer()
    assert not controller.login(READ) and not controller.refresh()
    assert len(transport.calls) == 1
    assert transport.calls[0]["url"] == config().issuer + "/revoke"


def test_expiry_prevents_bearer_and_refresh_network() -> None:
    controller, transport, _ = preloaded_controller()
    controller.clock = lambda: NOW + timedelta(seconds=300)
    with pytest.raises(OAuthError): controller.bearer()
    assert not controller.refresh() and controller.stopped and not transport.calls
