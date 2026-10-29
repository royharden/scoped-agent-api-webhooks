"""Construction-exposed stdlib core regressions for partial ROUND2 environment.

Run ONLY this explicit unittest pattern while pytest/Flask/HTTPX are unavailable.
These are builder development checks, not independent conformance/study results.
"""

import base64
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random

from scoped_agent_api.host.commands import CommandService
from scoped_agent_api.host.policy import DomainError, PrincipalContext
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.receivers.inbox import ReceiverStore
from scoped_agent_api.receivers.reference import ReferenceReceiver
from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.locks import GRANT_LOCKS
from scoped_agent_api.webhooks.management import expire_results
from scoped_agent_api.webhooks.outbox import DeliveryService, enqueue
from scoped_agent_api.webhooks.retry_policy import RetryPolicy, retry_after
from scoped_agent_api.webhooks.schema import initialize
from scoped_agent_api.webhooks.signing import sign, verify
from scoped_agent_api.webhooks.subscriptions import SubscriptionService, active_secrets, suspend_grant
from scoped_agent_api.webhooks.worker import DeliveryWorker, TransportResponse

NOW = datetime(2030, 1, 1, tzinfo=UTC)
KEY = "whsec_" + base64.b64encode(b"stdlib-developer-key-material-0001").decode("ascii")
URL = "http://127.0.0.1:23456/hooks/reference"


def snapshot(version=1):
    return json.dumps({"schema_version": "m14.event.v1", "type": "work_order.updated",
        "timestamp": NOW.isoformat(), "resource_id": "dev-order", "resource_version": version,
        "data": {"id": "dev-order", "title": "Developer original repair", "status": "draft",
                 "assignee": "dev.worker", "version": version,
                 "created_at": NOW.isoformat(), "updated_at": NOW.isoformat()}},
        separators=(",", ":")).encode("utf-8")


class CoreDevelopment(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="m14-dl3-development-")
        self.addCleanup(self.scratch.cleanup)
        self.clock = VirtualClock(NOW)
        self.store = Store(Path(self.scratch.name) / "host.sqlite")
        self.store.initialize()
        with self.store.transaction() as conn:
            initialize(conn)
        self.principal = PrincipalContext("dev.user", "human", "dev-client", "dev-grant",
            frozenset({"workorders:read", "workorders:write", "webhooks:manage"}), "http://fixture.invalid")
        self.live = True
        self.store.set_principal_validator(self.current)
        self.guard = EndpointGuard([URL])
        self.subscriptions = SubscriptionService(self.store, self.clock, self.guard, self.active)

    def active(self, grant, scopes):
        return self.live and grant == self.principal.grant_id and scopes <= self.principal.scopes

    def current(self, conn, principal, now):
        # Explicit developer fake authority; never production authentication.
        if principal != self.principal or not self.live:
            raise DomainError("invalid_token", 401)
        return principal

    def queued(self):
        subscription = self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub")
        self.clock.advance(1)
        order = CommandService(self.store, self.clock).execute(
            "create", self.principal, {"title": "Developer repair", "assignee": "dev.worker"}, "order")
        with self.store.transaction() as conn:
            event = conn.execute("SELECT id,body FROM domain_events WHERE resource_id=?", (order["id"],)).fetchone()
            self.assertEqual(enqueue(conn, self.clock.now()), 1)
            self.assertEqual(enqueue(conn, self.clock.now()), 0)
            delivery = conn.execute("SELECT id FROM webhook_deliveries").fetchone()[0]
        return subscription, event[0], bytes(event[1]), delivery

    def worker(self, transport, **kwargs):
        return DeliveryWorker(self.store, self.clock, transport, self.guard, self.active,
            RetryPolicy(Random(1414)), grant_validator_in_transaction=kwargs.pop(
                "transactional", lambda conn, grant, scopes, now: self.active(grant, scopes)), **kwargs)

    def test_raw_signature_tamper_and_exact_tolerance(self):
        raw = snapshot()
        headers = sign(raw, "dev-event", NOW, [KEY])
        verify(raw, headers, [KEY], NOW + timedelta(seconds=300))
        with self.assertRaisesRegex(ValueError, "timestamp_tolerance"):
            verify(raw, headers, [KEY], NOW + timedelta(seconds=301))
        with self.assertRaisesRegex(ValueError, "invalid_signature"):
            verify(raw + b" ", headers, [KEY], NOW)

    def test_retry_clamp_malformed_and_original_horizon(self):
        self.assertEqual(retry_after("999999", NOW.timestamp()), (86400, None))
        self.assertEqual(retry_after("broken", NOW.timestamp()), (None, "retry_after_malformed"))
        decision = RetryPolicy(Random(1414)).after_failure(attempts=1,
            now=NOW.timestamp()+96*3600-1, event_created_at=NOW.timestamp(),
            status=429, retry_after_value="86400")
        self.assertIsNone(decision.due_at)
        self.assertEqual(decision.code, "retry_horizon_exceeded")

    def test_management_idempotency_auth_and_tombstone(self):
        first = self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub")
        self.assertEqual(first, self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub"))
        with self.assertRaisesRegex(DomainError, "idempotency_conflict"):
            self.subscriptions.create(self.principal, URL, ["work_order.updated"], idempotency_key="sub")
        self.live = False
        with self.assertRaisesRegex(DomainError, "invalid_token"):
            self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub")
        self.live = True
        self.clock.advance(8*86400)
        with self.store.transaction() as conn:
            self.assertEqual(expire_results(conn, self.clock.now()), 1)
        with self.assertRaisesRegex(DomainError, "idempotency_expired"):
            self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub")

    def test_management_response_write_failure_rolls_back_effect(self):
        with self.store.transaction() as conn:
            conn.execute("""CREATE TRIGGER dev_failure BEFORE INSERT ON webhook_management_keys
                BEGIN SELECT RAISE(ABORT,'developer failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.subscriptions.create(self.principal, URL, ["work_order.created"], idempotency_key="sub")
        with self.store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM webhook_subscriptions").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM webhook_audit").fetchone()[0], 0)

    def test_rotation_and_replay_boundaries(self):
        subscription, event, body, delivery = self.queued()
        rotated = self.subscriptions.rotate(self.principal, subscription["id"], idempotency_key="rotate")
        with self.store.transaction() as conn:
            row = dict(conn.execute("SELECT * FROM webhook_subscriptions").fetchone())
            conn.execute("UPDATE webhook_deliveries SET state='delivered'")
        at = self.clock.now().timestamp()
        self.assertEqual(set(active_secrets(row, at+3599)), {subscription["secret"], rotated["secret"]})
        self.assertEqual(active_secrets(row, at+3600), [rotated["secret"]])
        self.clock.advance(7*86400)
        service = DeliveryService(self.subscriptions)
        self.assertEqual(service.replay(self.principal, delivery, idempotency_key="at-boundary")["event_id"], event)
        with self.store.transaction() as conn:
            self.assertEqual(bytes(conn.execute("SELECT body FROM domain_events WHERE id=?", (event,)).fetchone()[0]), body)
            conn.execute("UPDATE webhook_deliveries SET state='delivered'")
        self.clock.advance(1)
        with self.assertRaisesRegex(DomainError, "replay_expired"):
            service.replay(self.principal, delivery, idempotency_key="too-late")

    def test_worker_raw_send_and_restart_unknown_result(self):
        subscription, event, body, delivery = self.queued()
        calls = []

        class Transport:
            crash = True
            def send(inner, endpoint, raw, headers, *, timeout):
                calls.append((raw, headers))
                if inner.crash:
                    raise SystemExit("developer crash before result commit")
                return TransportResponse(204, {})

        transport = Transport()
        worker = self.worker(transport)
        with self.assertRaises(SystemExit):
            worker.run_due(self.clock.now())
        self.assertEqual(worker.recover_inflight(), 1)
        transport.crash = False
        self.clock.advance(5)
        self.assertEqual(worker.run_due(self.clock.now()), 1)
        self.assertEqual(calls[0][0], calls[1][0])
        self.assertEqual(calls[1][0], body)
        self.assertEqual(calls[1][1]["webhook-id"], event)
        verify(body, calls[1][1], [subscription["secret"]], self.clock.now())
        with self.store.transaction() as conn:
            self.assertEqual(tuple(conn.execute("SELECT state,attempts FROM webhook_deliveries").fetchone()), ("delivered", 2))

    def test_expired_sameconn_check_never_records_or_sends(self):
        self.queued()
        class ForbiddenTransport:
            def send(inner, *args, **kwargs):
                self.fail("inactive grant reached transport")
        worker = self.worker(ForbiddenTransport(), transactional=lambda conn, grant, scopes, now: False)
        self.assertEqual(worker.run_due(self.clock.now()), 0)
        with self.store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM webhook_attempts").fetchone()[0], 0)

    def test_post_start_expiry_cancels_without_transmitting(self):
        self.queued()
        class ForbiddenTransport:
            def send(inner, *args, **kwargs):
                self.fail("expired grant reached transport")
        def barrier(point, grant):
            if point == "send_start":
                self.live = False
        self.assertEqual(self.worker(ForbiddenTransport(), barrier=barrier).run_due(self.clock.now()), 1)
        with self.store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT last_error FROM webhook_deliveries").fetchone()[0], "authority_expired_before_send")

    def test_revoke_cascade_leaves_no_due_attempt(self):
        self.queued()
        with GRANT_LOCKS.hold(self.principal.grant_id), self.store.transaction() as conn:
            self.live = False
            suspend_grant(conn, self.principal.grant_id, self.clock.now())
        class ForbiddenTransport:
            def send(inner, *args, **kwargs):
                self.fail("revoked subscription reached transport")
        self.assertEqual(self.worker(ForbiddenTransport()).run_due(self.clock.now()), 0)

    def test_receiver_restart_dedupe_version_and_completed_only_retention(self):
        store = ReceiverStore(Path(self.scratch.name) / "inbox.sqlite")
        store.initialize()
        receiver = ReferenceReceiver(store, lambda: [KEY])
        newest = snapshot(3)
        receiver.receive(newest, sign(newest, "dev-new", NOW, [KEY]), NOW)
        self.assertIsNone(store.resource("dev-order"))
        restarted = ReferenceReceiver(ReceiverStore(store.path), lambda: [KEY])
        self.assertTrue(restarted.receive(newest, sign(newest, "dev-new", NOW, [KEY]), NOW)["duplicate"])
        self.assertEqual(restarted.process_pending(NOW), 1)
        old = snapshot(2)
        restarted.receive(old, sign(old, "dev-old", NOW, [KEY]), NOW)
        restarted.process_pending(NOW)
        pending = snapshot(4)
        restarted.receive(pending, sign(pending, "dev-pending", NOW, [KEY]), NOW)
        self.assertEqual(store.counters()["applied"], 1)
        self.assertEqual(store.counters()["stale"], 1)
        self.assertEqual(store.prune(NOW+timedelta(days=8)), 0)
        self.assertEqual(store.prune(NOW+timedelta(days=8, seconds=1)), 2)
        with store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT event_id FROM receiver_inbox").fetchone()[0], "dev-pending")
        self.assertEqual(store.resource("dev-order")["version"], 3)


if __name__ == "__main__":
    unittest.main()
