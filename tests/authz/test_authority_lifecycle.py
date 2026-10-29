"""Construction-exposed grant/cascade development regressions, no sockets."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier

import pytest

from scoped_agent_api.host.commands import CommandService
from scoped_agent_api.host.policy import DomainError
from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.outbox import enqueue
from scoped_agent_api.webhooks.subscriptions import SubscriptionService

from conftest import pkce_challenge


def issue(authority, settings):
    redirect = "https://client.fixture.invalid/callback"
    code = authority.authorize_code("agent-client", redirect, settings["resource"],
        "workorders:read workorders:write webhooks:manage", pkce_challenge("v" * 64), "development-allow")
    return authority.exchange_code(code, "agent-client", redirect, settings["resource"], "v" * 64)


def test_refresh_reuse_cancels_pending_and_suspends_original_subscription(authorization_fixture):
    store, clock, settings, authority = authorization_fixture
    tokens = issue(authority, settings)
    principal = authority.authenticate(tokens["access_token"])
    endpoint = "http://127.0.0.1:29001/hooks/development"
    subscriptions = SubscriptionService(store, clock, EndpointGuard((endpoint,)), authority.grant_is_active)
    subscriptions.create(principal, endpoint, ["work_order.created"], idempotency_key="sub-create")
    CommandService(store, clock).execute("create", principal, {"title": "Development order"}, "order-create")
    with store.transaction() as conn:
        assert enqueue(conn, clock.now()) == 1
    authority.refresh(tokens["refresh_token"], "agent-client", settings["resource"])
    with pytest.raises(DomainError, match="invalid_grant"):
        authority.refresh(tokens["refresh_token"], "agent-client", settings["resource"])
    with store.transaction() as conn:
        assert conn.execute("SELECT state FROM webhook_subscriptions").fetchone()[0] == "suspended"
        assert conn.execute("SELECT state FROM webhook_deliveries").fetchone()[0] == "cancelled"
        actions = {row[0] for row in conn.execute("SELECT action FROM webhook_audit")}
        assert {"subscription_suspended", "delivery_cancelled"} <= actions


def test_refresh_concurrent_reuse_revokes_the_family(authorization_fixture):
    store, _, settings, authority = authorization_fixture
    tokens = issue(authority, settings)
    start = Barrier(2)

    def rotate():
        start.wait(timeout=5)
        try:
            authority.refresh(tokens["refresh_token"], "agent-client", settings["resource"])
            return "rotated"
        except DomainError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(rotate) for _ in range(2)]
        outcomes = sorted(future.result(timeout=10) for future in futures)
    assert outcomes == ["invalid_grant", "rotated"]
    with store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM oauth_grants WHERE revoked_at IS NULL").fetchone()[0] == 0


def test_access_expiry_does_not_expire_grant_dispatch_authority(authorization_fixture):
    store, clock, settings, authority = authorization_fixture
    tokens = issue(authority, settings)
    principal = authority.authenticate(tokens["access_token"])
    clock.advance(300)
    with pytest.raises(DomainError, match="invalid_token"):
        authority.authenticate(tokens["access_token"])
    assert authority.grant_is_active(principal.grant_id, frozenset({"webhooks:manage"}))
    with store.transaction() as conn:
        assert authority.grant_validator_in_transaction(conn, principal.grant_id,
            frozenset({"webhooks:manage"}), clock.now())


def test_code_expiry_rechecked_after_writer_wait(authorization_fixture, monkeypatch):
    store, clock, settings, authority = authorization_fixture
    redirect = "https://client.fixture.invalid/callback"
    code = authority.authorize_code("agent-client", redirect, settings["resource"],
        "workorders:read", pkce_challenge("v" * 64), "development-allow")
    original = store.transaction

    @contextmanager
    def delayed_writer():
        with original() as conn:
            clock.advance(60)
            yield conn

    monkeypatch.setattr(store, "transaction", delayed_writer)
    with pytest.raises(DomainError, match="invalid_grant"):
        authority.exchange_code(code, "agent-client", redirect, settings["resource"], "v" * 64)


def test_request_proof_must_match_exact_authenticated_context(authorization_fixture):
    store, _, settings, authority = authorization_fixture
    first = issue(authority, settings)
    first_principal = authority.authenticate(first["access_token"])
    second = issue(authority, settings)
    authority.authenticate(second["access_token"])
    with store.transaction() as conn:
        with pytest.raises(DomainError, match="invalid_principal"):
            store.current_principal(conn, first_principal, authority.clock.now())
