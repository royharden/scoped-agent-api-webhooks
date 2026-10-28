"""Construction-exposed development fixtures, not independent study material."""

import base64
import hashlib
from datetime import UTC, datetime

import pytest

from scoped_agent_api.authz.authority import Authority
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.webhooks.schema import initialize


@pytest.fixture
def authorization_fixture(tmp_path):
    scopes = frozenset({"workorders:read", "workorders:write", "workorders:submit", "webhooks:manage"})
    settings = {"issuer": "https://issuer.fixture.invalid", "resource": "https://host.fixture.invalid",
        "clients": {"agent-client": {"actor_kind": "agent", "redirect_uris": ("https://client.fixture.invalid/callback",),
                                     "allowed_scopes": scopes},
                    "human-client": {"actor_kind": "human", "redirect_uris": ("https://human.fixture.invalid/callback",),
                                     "allowed_scopes": scopes | {"workorders:approve"}}},
        "consent_resolver": lambda fixture, client, requested, resource:
            {"allowed": fixture == "development-allow", "subject": "appr.sam" if client == "human-client" else "agent.dev"},
        "authlib_spike_approved": True}
    clock = VirtualClock(datetime(2026, 10, 28, tzinfo=UTC))
    store = Store(tmp_path / "auth-development.sqlite")
    store.initialize()
    authority = Authority(store, clock, settings)
    authority.initialize()
    store.set_principal_validator(authority.validate_principal)
    with store.transaction() as conn:
        initialize(conn)
    return store, clock, settings, authority


def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
