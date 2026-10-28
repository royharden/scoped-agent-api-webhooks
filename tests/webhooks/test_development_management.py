"""Developer regressions for atomic management, queue and replay boundaries."""

import sqlite3

import pytest

from scoped_agent_api.host.policy import DomainError
from scoped_agent_api.webhooks.management import expire_results
from scoped_agent_api.webhooks.outbox import DeliveryService, enqueue
from scoped_agent_api.webhooks.subscriptions import active_secrets


def test_management_same_key_recovers_one_effect_and_changed_body_refuses(harness):
    first = harness.create_subscription()
    assert harness.create_subscription() == first
    with pytest.raises(DomainError, match="idempotency_conflict"):
        harness.subscriptions.create(harness.principal, first["endpoint"], ["work_order.updated"],
                                     idempotency_key="sub-key")
    with harness.store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM webhook_subscriptions").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM webhook_audit").fetchone()[0] == 1


def test_management_response_failure_rolls_back_subscription_and_audit(harness):
    with harness.store.transaction() as conn:
        conn.execute("""CREATE TRIGGER developer_failure BEFORE INSERT ON webhook_management_keys
            BEGIN SELECT RAISE(ABORT,'developer injected response failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        harness.create_subscription()
    with harness.store.transaction() as conn:
        for table in ("webhook_subscriptions", "webhook_audit", "webhook_management_keys"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_expired_management_key_remains_tombstone(harness):
    harness.create_subscription()
    harness.clock.advance(8 * 86400)
    with harness.store.transaction() as conn:
        assert expire_results(conn, harness.clock.now()) == 1
    with pytest.raises(DomainError, match="idempotency_expired"):
        harness.create_subscription()
    with harness.store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM webhook_subscriptions").fetchone()[0] == 1
        assert conn.execute("SELECT response FROM webhook_management_keys").fetchone()[0] is None


def test_current_auth_precedes_saved_management_success(harness):
    harness.create_subscription()
    harness.active["live"] = False
    with pytest.raises(DomainError, match="invalid_token"):
        harness.create_subscription()


def test_lost_wake_scan_preserves_event_id_body_and_unique_pair(harness):
    harness.create_subscription()
    event_id, body = harness.create_event()
    with harness.store.transaction() as conn:
        assert enqueue(conn, harness.clock.now()) == 1
        assert enqueue(conn, harness.clock.now()) == 0
        row = conn.execute("SELECT e.id,e.body FROM webhook_deliveries d JOIN domain_events e ON d.event_id=e.id").fetchone()
        assert (row[0], bytes(row[1])) == (event_id, body)


def test_rotation_dual_key_exact_one_hour_boundary(harness):
    sub = harness.create_subscription()
    rotated = harness.subscriptions.rotate(harness.principal, sub["id"], idempotency_key="rotate")
    with harness.store.transaction() as conn:
        row = dict(conn.execute("SELECT * FROM webhook_subscriptions").fetchone())
    assert set(active_secrets(row, harness.clock.now().timestamp() + 3599)) == {sub["secret"], rotated["secret"]}
    assert active_secrets(row, harness.clock.now().timestamp() + 3600) == [rotated["secret"]]
    with pytest.raises(DomainError, match="rotation_overlap_active"):
        harness.subscriptions.rotate(harness.principal, sub["id"], idempotency_key="second-rotate")


def test_replay_preserves_body_id_and_seven_day_boundary(harness):
    _, event_id, body, delivery_id = harness.queued()
    with harness.store.transaction() as conn:
        conn.execute("UPDATE webhook_deliveries SET state='delivered',attempts=1")
    harness.clock.advance(7 * 86400)
    service = DeliveryService(harness.subscriptions)
    result = service.replay(harness.principal, delivery_id, idempotency_key="replay-boundary")
    assert result["event_id"] == event_id and result["state"] == "pending"
    with harness.store.transaction() as conn:
        assert bytes(conn.execute("SELECT body FROM domain_events WHERE id=?", (event_id,)).fetchone()[0]) == body
        conn.execute("UPDATE webhook_deliveries SET state='delivered'")
    harness.clock.advance(1)
    with pytest.raises(DomainError, match="replay_expired"):
        service.replay(harness.principal, delivery_id, idempotency_key="replay-late")
