"""Construction-exposed development regressions, not study/oracle evidence.

Use an external pytest --basetemp; these cases never open an HTTP socket.
"""

import base64
import hashlib
from datetime import UTC, datetime

import pytest

from scoped_agent_api.api.app import create_app
from scoped_agent_api.host.policy import DomainError
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.schema import initialize


@pytest.fixture
def api(tmp_path):
    scopes = frozenset({"workorders:read", "workorders:write", "webhooks:manage"})
    settings = {
        "issuer": "https://issuer.example.test",
        "resource": "https://resource.example.test",
        "first_party_client_id": "human-browser",
        "ui_redirect_uri": "https://resource.example.test/ui/oauth/callback",
        "ui_scopes": scopes,
        "clients": {"human-browser": {
            "actor_kind": "human", "allowed_scopes": scopes,
            "redirect_uris": ["https://resource.example.test/ui/oauth/callback"],
        }},
        "consent_resolver": lambda *_: {"allowed": True, "subject": "dev.human"},
        "endpoint_guard": EndpointGuard(["http://127.0.0.1:23456/hooks/dev"]),
    }
    store = Store(tmp_path / "api.sqlite")
    clock = VirtualClock(datetime(2026, 10, 27, tzinfo=UTC))
    app = create_app(store, clock, settings)
    app.config["TESTING"] = True
    authority = app.extensions["m14"]["authority"]
    store.initialize()
    authority.initialize()
    with store.transaction() as conn:
        initialize(conn)
    verifier = "d" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code = authority.authorize_code("human-browser", settings["ui_redirect_uri"],
                                    settings["resource"], " ".join(sorted(scopes)), challenge, "dev-consent")
    tokens = authority.exchange_code(code, "human-browser", settings["ui_redirect_uri"],
                                     settings["resource"], verifier)
    authority.clear_proof()
    return app, store, authority, tokens


def bearer(tokens, key="create-once"):
    return {"Authorization": "Bearer " + tokens["access_token"], "Idempotency-Key": key}


def test_saved_success_is_denied_after_current_grant_revocation(api):
    app, store, authority, tokens = api
    client = app.test_client()
    body = {"title": "Development order"}
    first = client.post("/v1/work-orders", json=body, headers=bearer(tokens))
    assert first.status_code == 200
    replay = client.post("/v1/work-orders", json=body, headers=bearer(tokens))
    assert replay.status_code == 200
    assert replay.json == first.json
    authority.revoke(tokens["access_token"], "human-browser")
    denied = client.post("/v1/work-orders", json=body, headers=bearer(tokens))
    assert denied.status_code == 401
    assert denied.json["code"] == "invalid_token"
    assert first.json["id"] not in denied.get_data(as_text=True)
    with store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM work_orders").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM domain_audit").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM domain_events").fetchone()[0] == 1


def test_http_request_proof_cannot_be_reused_after_request_teardown(api):
    app, _, authority, tokens = api
    principal = authority.authenticate(tokens["access_token"])
    assert app.test_client().get("/v1/work-orders", headers=bearer(tokens)).status_code == 200
    commands = app.extensions["m14"]["commands"]
    with pytest.raises(DomainError) as error:
        commands.execute("list", principal, {}, None)
    assert error.value.code == "invalid_principal"


def test_valid_human_session_cookie_alone_does_not_authenticate_api(api):
    app, _, authority, tokens = api
    principal = authority.authenticate(tokens["access_token"])
    session = authority.create_ui_session(principal)
    client = app.test_client()
    client.set_cookie("m14_ui_session", session["session_id"], path="/")
    authority.clear_proof()
    response = client.get("/v1/work-orders")
    assert response.status_code == 401
    assert response.json["code"] == "invalid_token"
    assert "Bearer resource_metadata=" in response.headers["WWW-Authenticate"]


@pytest.mark.parametrize("transport", ["query", "form"])
def test_api_refuses_even_valid_bearer_when_token_is_also_in_url_or_form(api, transport):
    app, _, _, tokens = api
    client = app.test_client()
    arguments = {"query_string": {"access_token": tokens["access_token"]}} if transport == "query" else {
        "data": {"access_token": tokens["access_token"]}}
    response = client.get("/v1/work-orders", headers=bearer(tokens), **arguments)
    assert response.status_code == 400
    assert response.json["code"] == "invalid_token_transport"
    assert tokens["access_token"] not in response.get_data(as_text=True)


@pytest.mark.parametrize("endpoint,event_types", [
    ("http://127.0.0.1:23456/hooks/not-allowlisted", ["work_order.created"]),
    ("http://127.0.0.1:23456/hooks/dev", ["\ud800"]),
])
def test_webhook_invalid_endpoint_or_unicode_is_sanitized_without_effects(api, endpoint, event_types):
    app, store, _, tokens = api
    response = app.test_client().post("/v1/subscriptions", headers=bearer(tokens, "invalid-subscription"),
                                      json={"endpoint": endpoint, "event_types": event_types})
    assert response.status_code == 400
    assert response.json["code"] == "invalid_arguments"
    assert endpoint not in response.get_data(as_text=True)
    with store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM webhook_subscriptions").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM webhook_audit").fetchone()[0] == 0


def test_service_rechecks_grant_before_returning_saved_webhook_secret(api):
    app, store, authority, tokens = api
    principal = authority.authenticate(tokens["access_token"])
    management = app.extensions["m14"]["management"]
    arguments = {"endpoint": "http://127.0.0.1:23456/hooks/dev", "event_types": ["work_order.created"]}
    first = management.execute("subscriptions.create", principal, arguments, "subscription-once")
    assert first["secret"].startswith("whsec_")
    assert management.execute("subscriptions.create", principal, arguments, "subscription-once") == first
    authority.revoke(tokens["access_token"], "human-browser")
    with pytest.raises(DomainError) as error:
        management.execute("subscriptions.create", principal, arguments, "subscription-once")
    assert error.value.status == 401
    with store.transaction() as conn:
        rows = conn.execute("SELECT state FROM webhook_subscriptions").fetchall()
        assert [row["state"] for row in rows] == ["suspended"]


class NeverSendTransport:
    follow_redirects = False
    trust_env = False
    total_timeout_seconds = 1

    def send(self, *args, **kwargs):
        raise AssertionError("composition development case must never send")


def compose(api, tmp_path, **overrides):
    from scoped_agent_api.api.composition import compose_fixture

    _, _, authority, _ = api
    settings = dict(authority.settings)
    settings["oauth_token_transport"] = lambda *_: (_ for _ in ()).throw(
        AssertionError("composition case must never exchange"))
    settings.update(overrides)
    return compose_fixture(Store(tmp_path / "composition.sqlite"), authority.clock, settings,
        allowed_endpoints=["http://127.0.0.1:23456/hooks/dev"],
        transport=NeverSendTransport(), retry_seed=17)


@pytest.mark.parametrize("ui_scopes", [None, "", [], ["unknown:scope"], {"workorders:read": True}])
def test_composition_requires_explicit_valid_ui_scopes(api, tmp_path, ui_scopes):
    with pytest.raises(ValueError, match="explicit_ui_scopes_required"):
        compose(api, tmp_path, ui_scopes=ui_scopes)


def test_composition_failed_schema_activation_cannot_leave_ready_owner(api, tmp_path, monkeypatch):
    components = compose(api, tmp_path)
    original = components.authority.initialize

    def fail_auth_schema():
        raise RuntimeError("injected_authorization_migration_failure")

    monkeypatch.setattr(components.authority, "initialize", fail_auth_schema)
    with pytest.raises(RuntimeError, match="injected_authorization_migration_failure"):
        components.initialize()
    with pytest.raises(RuntimeError, match="startup_recovery_requires_initialized"):
        components.recover_startup()
    with pytest.raises(RuntimeError, match="explicit_schema_and_startup_recovery_required"):
        components.dispatch_due()
    monkeypatch.setattr(components.authority, "initialize", original)
    components.initialize()
    assert components.recover_startup() == 0
    with pytest.raises(RuntimeError, match="schema_already_initialized"):
        components.initialize()
    with pytest.raises(RuntimeError, match="startup_recovery_requires_initialized"):
        components.recover_startup()
