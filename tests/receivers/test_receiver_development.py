"""Construction-exposed DEVELOPMENT regressions, not independent study data.

These tests use original fictional snapshots, disposable local signing material
and in-process Flask clients only. No socket/network transport is invoked.
"""

from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
import base64
import json
import sqlite3

import pytest

from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.receivers.http import create_receiver_app
from scoped_agent_api.receivers.inbox import ReceiverStore
from scoped_agent_api.receivers.reference import ReferenceReceiver
from scoped_agent_api.receivers.verify_only import VerifyOnlyReceiver
from scoped_agent_api.webhooks.signing import sign


NOW = datetime(2030, 1, 1, tzinfo=UTC)
# Public, disposable development material; never a real account credential.
KEY = "whsec_" + base64.b64encode(bytes(range(32))).decode("ascii")


def event(version=1, title="Repair fictional lantern"):
    stamp = NOW.isoformat()
    return json.dumps({
        "schema_version": "m14.event.v1", "type": "work_order.updated",
        "timestamp": stamp, "resource_id": "dev-order-1", "resource_version": version,
        "data": {"id": "dev-order-1", "title": title, "status": "draft",
                 "assignee": "dev.lee", "version": version,
                 "created_at": stamp, "updated_at": stamp},
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def headers(body, event_id="dev-event-1", now=NOW):
    return sign(body, event_id, now, [KEY])


@pytest.fixture
def storage(tmp_path):
    store = ReceiverStore(tmp_path / "receiver.sqlite3")
    store.initialize()
    return store


def receiver(store):
    return ReferenceReceiver(store, lambda: [KEY])


def inbox_rows(store):
    with store.transaction() as conn:
        return conn.execute("SELECT event_id,body,processed_at FROM receiver_inbox ORDER BY event_id").fetchall()


def test_ack_persists_raw_work_before_processing_and_restart_dedupes(storage):
    """An ACK must survive loss of the receiver object before its worker runs."""
    body = event(title="Repair café lantern")
    result = receiver(storage).receive(body, headers(body), NOW)
    assert result["status"] == 202
    restarted_store = ReceiverStore(storage.path)
    assert bytes(inbox_rows(restarted_store)[0]["body"]) == body
    assert inbox_rows(restarted_store)[0]["processed_at"] is None
    assert restarted_store.resource("dev-order-1") is None
    restarted = receiver(restarted_store)
    assert restarted.receive(body, headers(body), NOW)["duplicate"] is True
    assert restarted_store.counters()["inserted"] == 1
    assert restarted.process_pending(NOW) == 1
    assert restarted.process_pending(NOW) == 0
    assert restarted_store.resource("dev-order-1")["title"] == "Repair café lantern"
    assert restarted_store.counters()["applied"] == 1


def test_signed_id_body_conflict_preserves_original_work_and_durable_conflict(storage):
    original = event(title="Original task")
    changed = event(title="Changed bytes")
    current = receiver(storage)
    current.receive(original, headers(original), NOW)
    with pytest.raises(ValueError, match="digest conflict"):
        current.receive(changed, headers(changed), NOW)
    assert bytes(inbox_rows(storage)[0]["body"]) == original
    with storage.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM receiver_conflicts").fetchone()[0] == 1
    assert storage.counters()["conflicts"] == 1
    assert current.process_pending(NOW) == 1
    assert storage.resource("dev-order-1")["title"] == "Original task"


def test_unverified_malformed_bytes_never_reach_json_parser_or_inbox(storage, monkeypatch):
    import scoped_agent_api.receivers.reference as reference_module

    body = event()
    supplied = headers(body)
    called = []
    monkeypatch.setattr(reference_module, "parse", lambda raw: called.append(raw))
    with pytest.raises(ValueError, match="invalid_signature"):
        receiver(storage).receive(b"not-json", supplied, NOW)
    assert called == []
    assert inbox_rows(storage) == []
    assert storage.counters()["accepted"] == 0


def test_out_of_order_and_equal_versions_process_without_additional_effect(storage):
    current = receiver(storage)
    for event_id, version in (("dev-new", 3), ("dev-old", 2), ("dev-equal", 3)):
        body = event(version)
        current.receive(body, headers(body, event_id), NOW)
        assert current.process_pending(NOW) == 1
    assert storage.resource("dev-order-1")["version"] == 3
    counters = storage.counters()
    assert (counters["processed"], counters["applied"], counters["stale"]) == (3, 1, 2)


def test_apply_failure_rolls_back_effect_counter_and_processed_mark(storage, monkeypatch):
    """Crash during effect commit must leave durable work eligible on restart."""
    import scoped_agent_api.receivers.reference as reference_module

    body = event()
    current = receiver(storage)
    current.receive(body, headers(body), NOW)
    real_apply = reference_module.apply_snapshot

    def apply_then_fail(*args, **kwargs):
        real_apply(*args, **kwargs)
        raise RuntimeError("simulated process loss before commit")

    monkeypatch.setattr(reference_module, "apply_snapshot", apply_then_fail)
    with pytest.raises(RuntimeError, match="simulated process loss"):
        current.process_pending(NOW)
    assert storage.resource("dev-order-1") is None
    assert inbox_rows(storage)[0]["processed_at"] is None
    assert storage.counters()["applied"] == 0
    assert storage.counters()["processed"] == 0
    monkeypatch.setattr(reference_module, "apply_snapshot", real_apply)
    restarted = receiver(ReceiverStore(storage.path))
    assert restarted.process_pending(NOW) == 1
    assert restarted.process_pending(NOW) == 0
    assert storage.counters()["applied"] == 1


def test_receive_commit_failure_has_no_ack_or_partial_inbox(storage, monkeypatch):
    original_transaction = storage.transaction

    @contextmanager
    def fail_before_commit():
        with original_transaction() as conn:
            yield conn
            raise sqlite3.OperationalError("simulated inbox commit failure")

    body = event()
    monkeypatch.setattr(storage, "transaction", fail_before_commit)
    with pytest.raises(sqlite3.OperationalError, match="commit failure"):
        receiver(storage).receive(body, headers(body), NOW)
    monkeypatch.setattr(storage, "transaction", original_transaction)
    assert inbox_rows(storage) == []
    assert storage.counters()["accepted"] == 0
    assert storage.counters()["inserted"] == 0


def test_retention_prunes_only_completed_rows_and_preserves_lifetime_version(storage):
    current = receiver(storage)
    applied = event(4)
    pending = event(5)
    current.receive(applied, headers(applied, "dev-completed"), NOW)
    current.process_pending(NOW)
    current.receive(pending, headers(pending, "dev-pending"), NOW)
    assert storage.prune(NOW + timedelta(days=8)) == 0
    later = NOW + timedelta(days=8, seconds=1)
    assert storage.prune(later) == 1
    assert [row["event_id"] for row in inbox_rows(storage)] == ["dev-pending"]
    assert storage.resource("dev-order-1")["version"] == 4
    assert storage.counters()["applied"] == 1
    # Expired dedupe does not erase lifetime versions. Observe reinsertion and
    # processing separately from business effects; no second permanent guard.
    current.receive(applied, headers(applied, "dev-completed", later), later)
    assert storage.counters()["inserted"] == 3
    assert current.process_pending(later) == 2
    counters = storage.counters()
    assert storage.resource("dev-order-1")["version"] == 5
    assert (counters["processed"], counters["applied"], counters["stale"]) == (3, 2, 1)


def test_verify_only_repeats_and_reorders_effects_without_reference_guards(storage):
    current = VerifyOnlyReceiver(storage, lambda: [KEY])
    newer, older = event(3), event(2)
    for body in (newer, newer, older):
        assert current.receive(body, headers(body), NOW)["status"] == 200
    assert storage.resource("dev-order-1", "verify_only")["version"] == 2
    assert storage.counters("verify_only")["applied"] == 3
    assert inbox_rows(storage) == []


def test_http_ack_uses_injected_clock_and_persists_exact_raw_bytes(storage):
    body = event(title="Repair naïve café sign")
    clock = VirtualClock(NOW)
    app = create_receiver_app("dev-reference", receiver(storage), clock)
    response = app.test_client().post("/hooks/dev-reference", data=body, headers=headers(body))
    assert response.status_code == 202
    assert response.headers["Cache-Control"] == "no-store"
    assert bytes(inbox_rows(storage)[0]["body"]) == body
    assert storage.resource("dev-order-1") is None
    assert storage.counters()["processed"] == 0
    assert app.test_client().get("/static/anything").status_code == 404


@pytest.mark.parametrize("case,expected", [
    ("missing_signature", 400), ("tampered_body", 400),
    ("oversized", 413), ("query", 400), ("wrong_method", 405),
    ("raw_alias", 400), ("expired_signature", 400),
])
def test_http_refuses_bad_input_without_receiving_work(storage, case, expected):
    clock = VirtualClock(NOW)
    app = create_receiver_app("dev-reference", receiver(storage), clock)
    body = event()
    supplied = headers(body)
    url = "/hooks/dev-reference"
    options = {}
    if case == "missing_signature":
        supplied.pop("webhook-signature")
    elif case == "tampered_body":
        body = body.replace(b"lantern", b"changed")
    elif case == "oversized":
        body = b"x" * (32 * 1024 + 1)
    elif case == "query":
        url += "?unexpected=1"
    elif case == "raw_alias":
        options["environ_overrides"] = {"RAW_URI": "/hooks/%64ev-reference"}
    elif case == "expired_signature":
        clock.advance(301)
    client = app.test_client()
    response = client.get(url) if case == "wrong_method" else client.post(
        url, data=body, headers=supplied, **options)
    assert response.status_code == expected
    assert inbox_rows(storage) == []
    assert storage.counters()["accepted"] == 0


def test_http_database_failure_never_acknowledges_or_leaks_exception(storage, monkeypatch):
    current = receiver(storage)
    sensitive_text = "not-a-real-secret-sensitive-diagnostic"

    def unavailable(*_args, **_kwargs):
        raise sqlite3.OperationalError(sensitive_text)

    monkeypatch.setattr(current, "receive", unavailable)
    app = create_receiver_app("dev-reference", current, VirtualClock(NOW))
    body = event()
    response = app.test_client().post("/hooks/dev-reference", data=body, headers=headers(body))
    assert response.status_code == 503
    assert response.get_json() == {"code": "receiver_unavailable"}
    assert sensitive_text not in response.get_data(as_text=True)
    assert inbox_rows(storage) == []


def test_http_factory_and_request_do_not_implicitly_migrate(tmp_path):
    path = tmp_path / "not-initialized.sqlite3"
    store = ReceiverStore(path)
    app = create_receiver_app("dev-reference", receiver(store), VirtualClock(NOW))
    assert not path.exists()
    body = event()
    response = app.test_client().post("/hooks/dev-reference", data=body, headers=headers(body))
    assert response.status_code == 503
    with closing(sqlite3.connect(path)) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "receiver_inbox" not in tables
