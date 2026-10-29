"""Original construction-exposed development fixtures. Never study oracle/production identity."""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .client import FixtureConsent
from .oauth import OAuthConfig, OAuthController


@dataclass(frozen=True)
class DevelopmentRegistry:
    issuer: str = "https://as.m14.invalid"
    resource: str = "https://api.m14.invalid"
    agent_client: str = "dev.agent"
    human_client: str = "dev.human"
    agent_redirect: str = "https://agent.m14.invalid/callback"
    human_redirect: str = "https://api.m14.invalid/ui/oauth/callback"
    consent_fixture_id: str = "development-explicit-consent"

    def clients(self) -> dict[str, dict[str, object]]:
        common = ["workorders:read", "workorders:write", "workorders:submit", "webhooks:manage"]
        return {self.agent_client: {"actor_kind": "agent", "redirect_uris": [self.agent_redirect],
                                    "allowed_scopes": common},
                self.human_client: {"actor_kind": "human", "redirect_uris": [self.human_redirect],
                                    "allowed_scopes": common + ["workorders:approve"]}}

    def consent_resolver(self, allowed: bool):
        if type(allowed) is not bool:
            raise ValueError("explicit_fixture_decision_required")
        clients = self.clients()

        def resolve(fixture_id: str, client_id: str, scopes: frozenset[str], resource: str) -> dict[str, object]:
            client = clients.get(client_id)
            accepted = (allowed and fixture_id == self.consent_fixture_id and resource == self.resource
                        and client is not None and scopes <= frozenset(client["allowed_scopes"]))
            return {"allowed": bool(accepted),
                    "subject": "appr.sam" if client_id == self.human_client else "agent.dev"}
        return resolve

    def oauth_config(self, actor_kind: str) -> OAuthConfig:
        if actor_kind not in {"human", "agent"}:
            raise ValueError("invalid_fixture_actor")
        identifier = self.human_client if actor_kind == "human" else self.agent_client
        client = self.clients()[identifier]
        return OAuthConfig(self.issuer, self.resource, identifier, client["redirect_uris"][0],
            frozenset(self.clients()), frozenset(client["redirect_uris"]),
            frozenset(client["allowed_scopes"]), self.consent_fixture_id, actor_kind)


@dataclass(frozen=True)
class DisposableLaunch:
    path: Path
    consent: FixtureConsent

    def validate(self, registry: DevelopmentRegistry) -> None:
        resolved = self.path.resolve()
        if ("onedrive" in str(resolved).lower() or not resolved.is_dir()
                or not self.consent.permits() or self.consent.workspace_id != resolved.name
                or self.consent.consent_fixture_id != registry.consent_fixture_id):
            raise ValueError("fixture_launch_consent_mismatch")
        facts = json.loads((resolved / "development-launch.json").read_text(encoding="utf-8"))
        expected = {"classification": "construction-exposed development", "workspace_id": resolved.name,
                    "issuer": registry.issuer, "resource": registry.resource,
                    "consent_fixture_id": registry.consent_fixture_id, "human_confirmed": True}
        if facts != expected:
            raise ValueError("fixture_launch_consent_mismatch")

    @classmethod
    def generate(cls, registry: DevelopmentRegistry, *, human_confirmed: bool,
                 parent: Path | None = None) -> DisposableLaunch:
        if human_confirmed is not True:
            raise ValueError("explicit_human_fixture_consent_required")
        base = (parent or Path(tempfile.gettempdir())).resolve()
        if "onedrive" in str(base).lower():
            raise ValueError("runtime_fixture_must_be_outside_onedrive")
        workspace = Path(tempfile.mkdtemp(prefix="m14-development-", dir=base))
        consent = FixtureConsent(workspace.name, registry.consent_fixture_id, True, True)
        # Public fictional launch facts only: no token, verifier, cookie or key.
        facts = {"classification": "construction-exposed development", "workspace_id": workspace.name,
                 "issuer": registry.issuer, "resource": registry.resource,
                 "consent_fixture_id": registry.consent_fixture_id, "human_confirmed": True}
        (workspace / "development-launch.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
        return cls(workspace, consent)


class Reply:
    def __init__(self, response: Any) -> None:
        self.status_code = response.status_code
        self.headers = response.headers
        self._response = response

    def json(self) -> object:
        return self._response.get_json()


class InProcessPublicTransport:
    """Actual Flask test-client dispatch only; never opens an HTTP socket."""
    def __init__(self, registry: DevelopmentRegistry) -> None:
        self.registry = registry
        self._apps: dict[str, Any] = {}

    def bind(self, authorization_app: Any, resource_app: Any) -> None:
        if self._apps:
            raise ValueError("fixture_transport_already_bound")
        self._apps = {self.registry.issuer: authorization_app, self.registry.resource: resource_app}

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                json: dict[str, object] | None = None, query: dict[str, str] | None = None,
                form: dict[str, str] | None = None) -> Reply:
        candidates = [(base, app) for base, app in self._apps.items()
                      if url == base or url.startswith(base + "/")]
        if len(candidates) != 1 or method not in {"GET", "POST", "PATCH"}:
            raise ValueError("unconfigured_fixture_destination")
        base, app = candidates[0]
        parsed = urlsplit(url)
        if parsed.fragment or parsed.username or parsed.password:
            raise ValueError("invalid_fixture_destination")
        if json is not None and form is not None:
            raise ValueError("ambiguous_fixture_body")
        path = url[len(base):] or "/"
        with app.test_client() as client:
            response = client.open(path, method=method, headers=headers,
                                   json=json, data=form, query_string=query, follow_redirects=False)
        return Reply(response)

    def consent_adapter(self, allowed: bool):
        if type(allowed) is not bool:
            raise ValueError("explicit_fixture_decision_required")

        def consent(url: str) -> str | None:
            if not allowed or not url.startswith(self.registry.issuer + "/authorize?"):
                return None
            response = self.request("GET", url)
            # Return only the real AS Location; never manufacture a code/callback.
            if response.status_code != 302:
                return None
            return response.headers.get("Location")
        return consent

    def ui_token_transport(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        if url != self.registry.issuer + "/token":
            raise ValueError("unconfigured_fixture_token_endpoint")
        response = self.request("POST", url, form=form)
        value = response.json()
        if response.status_code != 200 or not isinstance(value, dict) or "error" in value:
            raise RuntimeError("fixture_token_exchange_refused")
        return value


class NoDispatchTransport:
    """Fail-closed development composition input; no successful delivery is simulated."""
    follow_redirects = False
    trust_env = False
    total_timeout_seconds = 5.0

    def send(self, endpoint: str, body: bytes, headers: Mapping[str, str], *, timeout: float) -> Any:
        raise RuntimeError("delivery_not_activated_in_client_development_fixture")


def compose_development(launch: DisposableLaunch, registry: DevelopmentRegistry, clock: Any,
                        *, consent_allowed: bool):
    """Explicit future/test invocation: constructs real separate apps; gate stays false."""
    from ..api.composition import compose_fixture
    from ..host.store import Store

    launch.validate(registry)
    router = InProcessPublicTransport(registry)
    settings = {"issuer": registry.issuer, "resource": registry.resource, "clients": registry.clients(),
                "first_party_client_id": registry.human_client, "ui_redirect_uri": registry.human_redirect,
                "ui_scopes": ["workorders:read"], "fixture_consent_id": registry.consent_fixture_id,
                "consent_resolver": registry.consent_resolver(consent_allowed),
                "oauth_token_transport": router.ui_token_transport, "authlib_spike_approved": False}
    components = compose_fixture(Store(launch.path / "development.sqlite"), clock, settings,
        allowed_endpoints=("http://127.0.0.1:29999/hooks/development",),
        transport=NoDispatchTransport(), retry_seed=1)
    router.bind(components.authorization_app, components.resource_app)

    def controller_factory(actor_kind: str) -> OAuthController:
        return OAuthController(registry.oauth_config(actor_kind), router,
                               router.consent_adapter(consent_allowed), clock.now)

    return components, router, controller_factory
