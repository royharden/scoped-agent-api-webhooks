"""Construction-exposed developer fixtures; not study/scoring data."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from random import Random

import pytest

from scoped_agent_api.host.commands import CommandService
from scoped_agent_api.host.policy import DomainError, PrincipalContext
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.outbox import DeliveryService, enqueue
from scoped_agent_api.webhooks.retry_policy import RetryPolicy
from scoped_agent_api.webhooks.schema import initialize
from scoped_agent_api.webhooks.subscriptions import SubscriptionService
from scoped_agent_api.webhooks.worker import DeliveryWorker, TransportResponse

ENDPOINT = "http://127.0.0.1:23456/hooks/reference"


class RecordingTransport:
    """Pure in-process fake; cannot open a socket."""

    def __init__(self, responses=None, on_send=None):
        self.responses = list(responses or [TransportResponse(204, {})])
        self.calls = []
        self.on_send = on_send

    def send(self, endpoint, body, headers, *, timeout):
        self.calls.append((endpoint, body, dict(headers), timeout))
        if self.on_send is not None:
            self.on_send()
        response = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(response, BaseException):
            raise response
        return response


@dataclass
class Harness:
    store: Store
    clock: VirtualClock
    principal: PrincipalContext
    guard: EndpointGuard
    active: dict
    subscriptions: SubscriptionService

    def valid(self, grant_id, scopes):
        return bool(self.active["live"] and grant_id == self.principal.grant_id
                    and self.clock.now() < self.active["expires"] and scopes <= self.principal.scopes)

    def worker(self, transport, *, barrier=None, transactional=None):
        return DeliveryWorker(
            self.store, self.clock, transport, self.guard, self.valid, RetryPolicy(Random(1414)),
            grant_validator_in_transaction=transactional or (lambda conn, grant, scopes, now: self.valid(grant, scopes)),
            barrier=barrier)

    def transport(self, responses=None, on_send=None):
        return RecordingTransport(responses, on_send)

    def create_subscription(self, key="sub-key"):
        return self.subscriptions.create(self.principal, ENDPOINT, ["work_order.created"],
                                         idempotency_key=key)

    def create_event(self):
        self.clock.advance(1)
        result = CommandService(self.store, self.clock).execute(
            "create", self.principal, {"title": "Developer repair", "assignee": "fixture.worker"},
            "order-key")
        with self.store.transaction() as conn:
            row = conn.execute("SELECT id,body FROM domain_events WHERE resource_id=?", (result["id"],)).fetchone()
        return row["id"], bytes(row["body"])

    def queued(self):
        sub = self.create_subscription()
        event_id, body = self.create_event()
        with self.store.transaction() as conn:
            assert enqueue(conn, self.clock.now()) == 1
            delivery_id = conn.execute("SELECT id FROM webhook_deliveries").fetchone()[0]
        return sub, event_id, body, delivery_id

    def delivery(self, delivery_id):
        return DeliveryService(self.subscriptions).get(self.principal, delivery_id)


@pytest.fixture
def harness(tmp_path):
    clock = VirtualClock(datetime(2030, 1, 1, tzinfo=UTC))
    store = Store(tmp_path / "webhooks.sqlite")
    store.initialize()
    with store.transaction() as conn:
        initialize(conn)
    principal = PrincipalContext("fixture.user", "human", "fixture-client", "fixture-grant",
                                 frozenset({"workorders:read", "workorders:write", "webhooks:manage"}),
                                 "http://fixture.invalid/resource")
    active = {"live": True, "expires": clock.now() + timedelta(days=20)}
    guard = EndpointGuard([ENDPOINT])
    subject = Harness(store, clock, principal, guard, active, None)

    def validate(conn, context, now):
        # Explicit development-only authority fake; never application wiring.
        if context != principal or not subject.valid(context.grant_id, context.scopes):
            raise DomainError("invalid_token", 401)
        return context

    store.set_principal_validator(validate)
    subject.subscriptions = SubscriptionService(store, clock, guard, subject.valid)
    return subject
