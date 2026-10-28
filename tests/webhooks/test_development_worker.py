"""Local development worker regressions using no HTTP/socket transport."""

from threading import Event, Thread

import pytest

from scoped_agent_api.webhooks.locks import GRANT_LOCKS
from scoped_agent_api.webhooks.outbox import enqueue
from scoped_agent_api.webhooks.signing import verify
from scoped_agent_api.webhooks.subscriptions import suspend_grant
from scoped_agent_api.webhooks.worker import TransportResponse


def test_worker_signs_original_event_and_records_actual_success(harness):
    sub, event_id, body, delivery_id = harness.queued()
    transport = harness.transport()
    assert harness.worker(transport).run_due(harness.clock.now()) == 1
    endpoint, sent_body, headers, timeout = transport.calls[0]
    assert sent_body == body and headers["webhook-id"] == event_id and timeout == 5
    verify(sent_body, headers, [sub["secret"]], harness.clock.now())
    assert harness.delivery(delivery_id)["state"] == "delivered"


@pytest.mark.parametrize("status", [302, 500])
def test_non_2xx_is_not_success(harness, status):
    _, _, _, delivery_id = harness.queued()
    transport = harness.transport([TransportResponse(status, {})])
    harness.worker(transport).run_due(harness.clock.now())
    result = harness.delivery(delivery_id)
    assert result["state"] == "pending" and result["attempts"] == 1
    assert 4.5 <= result["due_at"] - harness.clock.now().timestamp() <= 5.5


def test_gone_disables_subscription_and_cancels_pending(harness):
    sub, _, _, delivery_id = harness.queued()
    harness.worker(harness.transport([TransportResponse(410, {})])).run_due(harness.clock.now())
    assert harness.delivery(delivery_id)["state"] == "cancelled"
    assert harness.subscriptions.get(harness.principal, sub["id"])["state"] == "disabled"


def test_send_before_record_restart_keeps_raw_id_body(harness):
    _, event_id, body, delivery_id = harness.queued()
    first = harness.transport([SystemExit("developer crash after transmitted bytes")])
    with pytest.raises(SystemExit):
        harness.worker(first).run_due(harness.clock.now())
    assert harness.delivery(delivery_id)["state"] == "sending"
    harness.clock.advance(5)
    second = harness.transport()
    restarted = harness.worker(second)
    assert restarted.recover_inflight() == 1
    assert restarted.run_due(harness.clock.now()) == 1
    assert second.calls[0][1] == first.calls[0][1] == body
    assert second.calls[0][2]["webhook-id"] == event_id
    assert harness.delivery(delivery_id)["attempts"] == 2


def test_transaction_aware_expiry_blocks_attempt_record(harness):
    _, _, _, delivery_id = harness.queued()
    transport = harness.transport()
    assert harness.worker(transport, transactional=lambda conn, grant, scopes, now: False).run_due(harness.clock.now()) == 0
    assert transport.calls == []
    with harness.store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM webhook_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT state FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()[0] == "cancelled"


def test_expiry_at_send_barrier_never_transmits(harness):
    _, _, _, delivery_id = harness.queued()

    def barrier(point, grant):
        if point == "send_start":
            harness.active["expires"] = harness.clock.now()

    transport = harness.transport()
    assert harness.worker(transport, barrier=barrier).run_due(harness.clock.now()) == 1
    assert transport.calls == []
    with harness.store.transaction() as conn:
        row = conn.execute("SELECT state,last_error FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        assert tuple(row) == ("cancelled", "authority_expired_before_send")


def test_revoke_waits_for_started_send_and_prevents_later_start(harness):
    harness.queued()
    harness.create_subscription("second-subscription")
    with harness.store.transaction() as conn:
        assert enqueue(conn, harness.clock.now()) == 1
    send_entered, finish_send, lock_probed, revoke_returned = (Event() for _ in range(4))
    failures = []
    lock_was_available = []

    def block_send():
        send_entered.set()
        if not finish_send.wait(5):
            raise AssertionError("developer barrier was not released")

    transport = harness.transport(on_send=block_send)
    worker = harness.worker(transport)

    def dispatch():
        try:
            worker.run_due(harness.clock.now(), limit=1)
        except BaseException as error:
            failures.append(error)

    def revoke():
        try:
            # Decisive witness from another thread: inspect the SAME registry
            # lock, so mere thread-start scheduling cannot masquerade as fencing.
            with GRANT_LOCKS._guard:
                lock = GRANT_LOCKS._locks[harness.principal.grant_id]
            available = lock.acquire(blocking=False)
            lock_was_available.append(available)
            if available:
                lock.release()
            lock_probed.set()
            with GRANT_LOCKS.hold(harness.principal.grant_id), harness.store.transaction() as conn:
                harness.active["live"] = False
                suspend_grant(conn, harness.principal.grant_id, harness.clock.now())
            revoke_returned.set()
        except BaseException as error:
            failures.append(error)

    sender = Thread(target=dispatch)
    revoker = Thread(target=revoke)
    sender.start()
    try:
        assert send_entered.wait(5)
        revoker.start()
        assert lock_probed.wait(5)
        assert lock_was_available == [False]
        assert not revoke_returned.is_set()
    finally:
        finish_send.set()
        sender.join(5)
        if revoker.ident is not None:
            revoker.join(5)
    assert not sender.is_alive() and not revoker.is_alive()
    assert failures == [] and revoke_returned.is_set()
    assert worker.run_due(harness.clock.now()) == 0
    assert len(transport.calls) == 1
    with harness.store.transaction() as conn:
        states = [row[0] for row in conn.execute("SELECT state FROM webhook_deliveries ORDER BY state")]
        assert states == ["cancelled", "delivered"]
