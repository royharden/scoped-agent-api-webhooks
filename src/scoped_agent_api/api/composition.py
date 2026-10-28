"""Explicit future fixture composition. Importing this module has no app effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from random import Random
from threading import Lock
from typing import Any, Callable, Iterable, Mapping, Protocol


class BoundedTransport(Protocol):
    """Caller-owned adapter contract, to be proved in the later runtime phase.

    send MUST enforce an overall deadline, disable redirects and environment
    proxies, and never log credentials. Attribute declarations are fail-closed
    configuration checks, not proof that an arbitrary implementation obeys them.
    """

    follow_redirects: bool
    trust_env: bool
    total_timeout_seconds: float

    def send(self, endpoint: str, body: bytes, headers: Mapping[str, str], *,
             timeout: float) -> Any: ...


class GuardedTransport:
    def __init__(self, transport: BoundedTransport, guard: Any) -> None:
        self.transport, self.guard = transport, guard
        deadline = getattr(transport, "total_timeout_seconds", None)
        if (getattr(transport, "follow_redirects", None) is not False
                or getattr(transport, "trust_env", None) is not False
                or type(deadline) not in {int, float} or not 0 < deadline <= 5
                or not callable(getattr(transport, "send", None))):
            raise ValueError("bounded_no_proxy_no_redirect_transport_required")
        self.deadline = float(deadline)

    def send(self, endpoint: str, body: bytes, headers: Mapping[str, str], *,
             timeout: float) -> Any:
        self.guard.validate(endpoint)
        if type(timeout) not in {int, float} or not 0 < timeout <= 5:
            raise ValueError("bounded_transport_timeout_required")
        return self.transport.send(endpoint, body, headers, timeout=min(timeout, self.deadline))


@dataclass
class FixtureComponents:
    """One process/one lifecycle owner per fixture Store; starts nothing itself.

    Application objects and the worker are returned for a future owner, not
    mounted or dispatched here. The owner must not run a second worker/recovery
    owner against this Store or call worker methods around lifecycle guards.
    """

    store: Any
    clock: Any
    authority: Any
    authorization_app: Any
    resource_app: Any
    management: Any
    endpoint_guard: Any
    worker: Any
    _initialized: bool = field(default=False, init=False, repr=False)
    _recovered: bool = field(default=False, init=False, repr=False)
    _lifecycle: Any = field(default_factory=Lock, init=False, repr=False)

    def authenticated_session_factory(self, *, controller_factory: Callable[[str], Any],
                                      resource_transport: Any,
                                      initial_scopes: frozenset[str]) -> Any:
        """Bind DL4's public-HTTP-only factory without logging in or sending.

        The returned factory logs in only when a future CLI/task explicitly calls
        it. Consent and controller transports remain trusted caller-owned input.
        """
        from ..agent.bootstrap import AuthenticatedSessionFactory
        from ..agent.oauth import OAuthController
        from ..authz.authority import SCOPES

        if (not callable(controller_factory) or not callable(getattr(resource_transport, "request", None))
                or not isinstance(initial_scopes, frozenset) or not initial_scopes
                or not initial_scopes <= SCOPES):
            raise ValueError("explicit_public_client_factory_transport_scopes_required")

        def checked_controller(actor_kind: str) -> Any:
            controller = controller_factory(actor_kind)
            if not isinstance(controller, OAuthController):
                raise ValueError("owner_oauth_controller_required")
            config = controller.config
            registered = self.authority.client(config.client_id)
            if (config.issuer != self.authority.issuer or config.resource != self.authority.resource
                    or config.actor_kind != actor_kind or registered["actor_kind"] != actor_kind
                    or config.redirect_uri not in registered.get("redirect_uris", ())
                    or not config.allowed_scopes <= frozenset(registered.get("allowed_scopes", ()))):
                raise ValueError("client_controller_must_match_joined_authority")
            return controller

        return AuthenticatedSessionFactory(checked_controller, resource_transport, initial_scopes)

    def initialize(self) -> None:
        """Explicit, repeatable-on-failure schema activation before startup.

        Host.initialize owns its transaction, Authority.initialize owns a second
        transaction, webhook.initialize uses a third caller-held transaction.
        This is NOT one transaction across all schemas. Mark ready only after all
        succeed; existing rows are preserved by the owner idempotent migrations.
        """
        from ..webhooks.schema import initialize

        with self._lifecycle:
            if self._initialized or self._recovered:
                raise RuntimeError("schema_already_initialized")
            self.store.initialize()
            self.authority.initialize()
            with self.store.transaction() as conn:
                initialize(conn)
            self._initialized = True

    def recover_startup(self) -> int:
        """Explicit once-per-owner recovery, before any dispatch is allowed."""
        with self._lifecycle:
            if not self._initialized or self._recovered:
                raise RuntimeError("startup_recovery_requires_initialized_unstarted_owner")
            recovered = self.worker.recover_inflight()
            self._recovered = True
            return recovered

    def dispatch_due(self, *, limit: int = 100) -> int:
        """One explicit bounded future tick; no background loop or listener."""
        from ..webhooks.outbox import enqueue

        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("batch_limit_out_of_range")
        with self._lifecycle:
            if not self._initialized or not self._recovered:
                raise RuntimeError("explicit_schema_and_startup_recovery_required")
            with self.store.transaction() as conn:
                enqueue(conn, self.clock.now(), limit=limit)
            return self.worker.run_due(self.clock.now(), limit=limit)


def compose_fixture(store: Any, clock: Any, settings: Mapping[str, Any], *,
                    allowed_endpoints: Iterable[str], transport: BoundedTransport,
                    retry_seed: int) -> FixtureComponents:
    """Construct source-defined components, with no migrations/IO/listeners.

    Caller supplies fictional consent configuration and bounded transports.
    Factory construction does not authorize activating those transports or
    Authlib. The bounded spike gate remains false unless explicitly configured.
    """
    from ..authz.app import create_app as create_authorization_app
    from ..authz.authority import SCOPES
    from ..webhooks.endpoint_guard import EndpointGuard
    from ..webhooks.locks import GRANT_LOCKS
    from ..webhooks.retry_policy import RetryPolicy
    from ..webhooks.worker import DeliveryWorker
    from .app import create_app as create_resource_app

    if not callable(getattr(store, "transaction", None)) or not callable(getattr(clock, "now", None)):
        raise ValueError("caller_owned_store_and_clock_required")
    if type(retry_seed) is not int:
        raise ValueError("explicit_integer_retry_seed_required")
    configured = dict(settings)
    if not callable(configured.get("consent_resolver")) or not callable(configured.get("oauth_token_transport")):
        raise ValueError("trusted_fixture_consent_and_token_transport_required")
    ui_value = configured.get("ui_scopes")
    if isinstance(ui_value, str):
        ui_scopes = frozenset(ui_value.split())
    elif type(ui_value) in {list, tuple, set, frozenset} and all(isinstance(scope, str) for scope in ui_value):
        ui_scopes = frozenset(ui_value)
    else:
        raise ValueError("explicit_ui_scopes_required")
    if not ui_scopes or not ui_scopes <= SCOPES:
        raise ValueError("explicit_ui_scopes_required")
    configured["ui_scopes"] = ui_scopes
    # Composition must use its own joined authority/services, never a prebuilt
    # management service attached to a different Store or request-proof owner.
    if configured.get("webhooks_service") is not None:
        raise ValueError("composition_owns_joined_management_service")
    configured.setdefault("authlib_spike_approved", False)
    guard = EndpointGuard(allowed_endpoints)
    bounded_transport = GuardedTransport(transport, guard)
    configured["endpoint_guard"] = guard
    resource_app = create_resource_app(store, clock, configured)
    authority = resource_app.extensions["m14"]["authority"]
    client_id = configured["first_party_client_id"]
    client = authority.client(client_id)
    if (client["actor_kind"] != "human" or configured["ui_redirect_uri"] not in client.get("redirect_uris", ())
            or not ui_scopes <= frozenset(client.get("allowed_scopes", ()))):
        raise ValueError("registered_first_party_human_redirect_required")
    authorization_app = create_authorization_app(store, clock, configured)
    # Same owner objects as the HTTP route registration, not a parallel service
    # graph: resource factory exposes the exact selected service below.
    management = resource_app.extensions["m14"]["management"]
    worker = DeliveryWorker(store, clock, bounded_transport, guard,
        authority.grant_is_active, RetryPolicy(Random(retry_seed)),
        grant_validator_in_transaction=authority.grant_validator_in_transaction,
        grant_locks=GRANT_LOCKS)
    return FixtureComponents(store, clock, authority, authorization_app, resource_app,
                             management, guard, worker)
