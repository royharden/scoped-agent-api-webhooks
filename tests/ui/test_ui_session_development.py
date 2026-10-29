"""Construction-exposed local development cases; no independent study claims.

All callback exchanges use injected in-process Authority code exchange, no HTTP.
"""

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from werkzeug.datastructures import MultiDict

from scoped_agent_api.api.app import create_app
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.ui.oauth import LOGIN_COOKIE
from scoped_agent_api.ui.routes import SESSION_COOKIE
from scoped_agent_api.webhooks.schema import initialize


@pytest.fixture
def ui(tmp_path):
    scopes = frozenset({"workorders:read", "workorders:write"})
    state = {}

    def exchange(url, data):
        assert url == "https://issuer.example.test/token"
        if state.get("transport_error"):
            raise ValueError("PRIVATE_PROVIDER_VALUE")
        result = state["authority"].exchange_code(data["code"], data["client_id"],
            data["redirect_uri"], data["resource"], data["code_verifier"])
        state["tokens"] = result.copy()
        if "token_type" in state:
            result["token_type"] = state["token_type"]
        return result

    settings = {
        "issuer": "https://issuer.example.test", "resource": "https://resource.example.test",
        "first_party_client_id": "human-browser",
        "ui_redirect_uri": "https://resource.example.test/ui/oauth/callback",
        "ui_scopes": scopes, "oauth_token_transport": exchange,
        "consent_resolver": lambda *_: {"allowed": True, "subject": "dev.human"},
        "clients": {"human-browser": {"actor_kind": "human", "allowed_scopes": scopes,
            "redirect_uris": ["https://resource.example.test/ui/oauth/callback"]}},
    }
    store = Store(tmp_path / "ui.sqlite")
    clock = VirtualClock(datetime(2026, 10, 27, tzinfo=UTC))
    app = create_app(store, clock, settings)
    app.config["TESTING"] = True
    authority = app.extensions["m14"]["authority"]
    state.update(app=app, store=store, authority=authority, clock=clock)
    store.initialize()
    authority.initialize()
    with store.transaction() as conn:
        initialize(conn)
    return state


def callback(ui, client):
    start = client.get("/ui/oauth/start", base_url="https://resource.example.test")
    assert start.status_code == 303
    query = {key: values[0] for key, values in parse_qs(urlsplit(start.location).query).items()}
    assert query["code_challenge_method"] == "S256"
    authority = ui["authority"]
    code = authority.authorize_code(query["client_id"], query["redirect_uri"], query["resource"],
                                    query["scope"], query["code_challenge"], "dev-consent")
    return client.get("/ui/oauth/callback", base_url="https://resource.example.test", query_string={
        "state": query["state"], "iss": authority.issuer, "code": code})


def signed_in(ui):
    client = ui["app"].test_client()
    response = callback(ui, client)
    assert response.status_code == 303
    assert response.location == "/ui/"
    cookie = client.get_cookie(SESSION_COOKIE, domain="resource.example.test", path="/ui")
    assert cookie is not None and cookie.secure and cookie.http_only and cookie.same_site == "Lax"
    principal, csrf = ui["authority"].resolve_ui_session(cookie.value)
    assert principal.subject == "dev.human"
    ui["authority"].clear_proof()
    return client, csrf


def test_cookie_session_and_csrf_guard_actual_mutation(ui):
    client, csrf = signed_in(ui)
    assert client.get("/ui/", base_url="https://resource.example.test").status_code == 200
    for supplied in (None, "wrong-csrf", "\u2603"):
        form = {"title": "Cannot create", "idempotency_key": "denied"}
        if supplied is not None:
            form["csrf_token"] = supplied
        response = client.post("/ui/work-orders", data=form, base_url="https://resource.example.test")
        assert response.status_code == 403
        assert "csrf_invalid" in response.get_data(as_text=True)
    duplicate = MultiDict([("csrf_token", csrf), ("csrf_token", csrf),
                           ("title", "Cannot create"), ("idempotency_key", "duplicate")])
    assert client.post("/ui/work-orders", data=duplicate,
                       base_url="https://resource.example.test").status_code == 403
    with ui["store"].transaction() as conn:
        assert conn.execute("SELECT count(*) FROM work_orders").fetchone()[0] == 0
    response = client.post("/ui/work-orders", data={"title": "Created by browser", "csrf_token": csrf,
                           "idempotency_key": "accepted"}, base_url="https://resource.example.test")
    assert response.status_code == 303
    with ui["store"].transaction() as conn:
        assert conn.execute("SELECT count(*) FROM work_orders").fetchone()[0] == 1
        assert conn.execute("SELECT surface FROM domain_audit").fetchone()[0] == "ui"


def test_revoked_grant_invalidates_existing_browser_session(ui):
    client, csrf = signed_in(ui)
    ui["authority"].revoke(ui["tokens"]["access_token"], "human-browser")
    response = client.post("/ui/work-orders", data={"title": "Cannot create", "csrf_token": csrf,
                           "idempotency_key": "revoked"}, base_url="https://resource.example.test")
    assert response.status_code == 401
    with ui["store"].transaction() as conn:
        assert conn.execute("SELECT count(*) FROM work_orders").fetchone()[0] == 0


@pytest.mark.parametrize("token_type", [None, 7, [], {}, "Basic", "PRIVATE_PROVIDER_VALUE"])
def test_malformed_token_type_callback_is_sanitized_and_sets_no_session(ui, token_type):
    ui["token_type"] = token_type
    client = ui["app"].test_client()
    response = callback(ui, client)
    assert response.status_code == 502
    assert "invalid_oauth_response" in response.get_data(as_text=True)
    assert "PRIVATE_PROVIDER_VALUE" not in response.get_data(as_text=True)
    assert ui["tokens"]["access_token"] not in response.get_data(as_text=True)
    assert client.get_cookie(SESSION_COOKIE, domain="resource.example.test", path="/ui") is None
    assert client.get_cookie(LOGIN_COOKIE, domain="resource.example.test", path="/ui/oauth") is None
    with ui["store"].transaction() as conn:
        assert conn.execute("SELECT count(*) FROM oauth_ui_sessions").fetchone()[0] == 0


def test_callback_transport_value_error_is_sanitized(ui):
    ui["transport_error"] = True
    client = ui["app"].test_client()
    response = callback(ui, client)
    assert response.status_code == 502
    assert "oauth_transport_failed" in response.get_data(as_text=True)
    assert "PRIVATE_PROVIDER_VALUE" not in response.get_data(as_text=True)
    assert client.get_cookie(SESSION_COOKIE, domain="resource.example.test", path="/ui") is None


def test_ui_refuses_bearer_even_when_human_session_is_valid(ui):
    client, _ = signed_in(ui)
    response = client.get("/ui/", base_url="https://resource.example.test",
                          headers={"Authorization": "Bearer " + ui["tokens"]["access_token"]})
    assert response.status_code == 400
    assert "ui_bearer_refused" in response.get_data(as_text=True)
