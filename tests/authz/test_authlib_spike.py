"""Bounded in-process Authlib compatibility DEVELOPMENT spike; no sockets."""

from urllib.parse import parse_qs, urlsplit

import pytest

from scoped_agent_api.authz.app import create_app
from scoped_agent_api.host.policy import DomainError

from conftest import pkce_challenge


def authorization(client, settings, **changes):
    query = {"response_type": "code", "client_id": "agent-client",
        "redirect_uri": "https://client.fixture.invalid/callback", "scope": "workorders:read workorders:write webhooks:manage",
        "resource": settings["resource"], "state": "development-state", "code_challenge": pkce_challenge("v" * 64),
        "code_challenge_method": "S256", "consent_fixture_id": "development-allow"}
    query.update(changes)
    return client.get("/authorize", query_string=query, base_url=settings["issuer"])


def token_exchange(client, settings, code, **changes):
    form = {"grant_type": "authorization_code", "client_id": "agent-client", "code": code,
            "redirect_uri": "https://client.fixture.invalid/callback", "resource": settings["resource"],
            "code_verifier": "v" * 64}
    form.update(changes)
    return client.post("/token", data=form, base_url=settings["issuer"])


def get_code(client, settings):
    response = authorization(client, settings)
    assert response.status_code == 302
    callback = urlsplit(response.headers["Location"])
    assert callback.scheme == "https" and callback.netloc == "client.fixture.invalid"
    query = parse_qs(callback.query)
    assert query["state"] == ["development-state"]
    assert query["iss"] == [settings["issuer"]]
    assert len(query["code"]) == 1
    return query["code"][0]


def test_authlib_code_s256_resource_and_single_use(authorization_fixture):
    store, clock, settings, authority = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    client = app.test_client()
    code = get_code(client, settings)
    response = token_exchange(client, settings, code)
    assert response.status_code == 200
    result = response.get_json()
    principal = authority.authenticate(result["access_token"])
    assert principal.resource == settings["resource"]
    assert principal.actor_kind == "agent"
    assert result["token_type"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"
    assert token_exchange(client, settings, code).status_code == 400


@pytest.mark.parametrize("changes", [
    {"resource": "https://foreign.fixture.invalid"},
    {"code_verifier": "x" * 64},
    {"redirect_uri": "https://client.fixture.invalid/other"},
    {"client_id": "human-client"},
])
def test_code_exchange_binding_negatives(authorization_fixture, changes):
    store, clock, settings, _ = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    client = app.test_client()
    code = get_code(client, settings)
    response = token_exchange(client, settings, code, **changes)
    assert 400 <= response.status_code < 500
    with store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM oauth_tokens").fetchone()[0] == 0


@pytest.mark.parametrize("changes", [
    {"code_challenge_method": "plain"},
    {"scope": "workorders:approve"},
    {"consent_fixture_id": "development-refuse"},
    {"resource": "https://foreign.fixture.invalid"},
])
def test_authorization_denials_issue_no_grant(authorization_fixture, changes):
    store, clock, settings, _ = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    response = authorization(app.test_client(), settings, **changes)
    assert response.status_code in {302, 400, 403}
    if response.status_code == 302:
        assert "error" in parse_qs(urlsplit(response.headers["Location"]).query)
    with store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM oauth_grants").fetchone()[0] == 0


def test_expired_code_refused(authorization_fixture):
    store, clock, settings, _ = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    client = app.test_client()
    code = get_code(client, settings)
    clock.advance(60)
    assert token_exchange(client, settings, code).status_code == 400


def test_refresh_reuse_commits_family_and_grant_revocation(authorization_fixture):
    store, clock, settings, authority = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    client = app.test_client()
    issued = token_exchange(client, settings, get_code(client, settings)).get_json()
    principal = authority.authenticate(issued["access_token"])
    refresh_form = {"grant_type": "refresh_token", "client_id": "agent-client",
                    "resource": settings["resource"], "refresh_token": issued["refresh_token"]}
    rotated = client.post("/token", data=refresh_form, base_url=settings["issuer"])
    assert rotated.status_code == 200
    assert client.post("/token", data=refresh_form, base_url=settings["issuer"]).status_code == 400
    with pytest.raises(DomainError, match="invalid_token"):
        authority.authenticate(rotated.get_json()["access_token"])
    with store.transaction() as conn:
        assert conn.execute("SELECT revoked_at FROM oauth_grants WHERE id=?", (principal.grant_id,)).fetchone()[0] is not None
        assert conn.execute("SELECT count(*) FROM oauth_families WHERE revoked_at IS NULL").fetchone()[0] == 0
        assert conn.execute("SELECT event FROM oauth_security_events").fetchone()[0] == "refresh_reuse"


def test_default_authlib_gate_and_configured_metadata(authorization_fixture):
    store, clock, settings, _ = authorization_fixture
    settings = {**settings, "authlib_spike_approved": False}
    client = create_app(store, clock, settings).test_client()
    assert authorization(client, settings).status_code == 503
    response = client.get("/.well-known/oauth-authorization-server", base_url="https://untrusted.fixture.invalid")
    assert response.get_json()["issuer"] == settings["issuer"]


def test_refresh_no_scope_widening_and_rfc7009_revoke(authorization_fixture):
    store, clock, settings, authority = authorization_fixture
    app = create_app(store, clock, settings)
    app.testing = True
    client = app.test_client()
    issued = token_exchange(client, settings, get_code(client, settings)).get_json()
    response = client.post("/token", base_url=settings["issuer"], data={
        "grant_type": "refresh_token", "client_id": "agent-client", "resource": settings["resource"],
        "refresh_token": issued["refresh_token"], "scope": "workorders:read workorders:submit"})
    assert response.status_code == 400
    revoked = client.post("/revoke", base_url=settings["issuer"], data={
        "client_id": "agent-client", "token": issued["access_token"]})
    assert revoked.status_code == 200
    with pytest.raises(DomainError, match="invalid_token"):
        authority.authenticate(issued["access_token"])
    refresh = client.post("/token", base_url=settings["issuer"], data={
        "grant_type": "refresh_token", "client_id": "agent-client", "resource": settings["resource"],
        "refresh_token": issued["refresh_token"]})
    assert refresh.status_code in {400, 401}
