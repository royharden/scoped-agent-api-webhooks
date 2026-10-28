"""Construction-exposed developer regressions, not independent study data.

Fictional principals and a test-owned authority map isolate the domain boundary.
They do not exercise OAuth, HTTP transports or the independent conformance matrix.
"""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from threading import Barrier
from typing import Any

import pytest

from scoped_agent_api.host import capabilities, idempotency
from scoped_agent_api.host.approvals import ApprovalService
from scoped_agent_api.host.commands import CommandService
from scoped_agent_api.host.policy import DomainError, PrincipalContext
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock


@dataclass
class DomainFixture:
    store: Store
    clock: VirtualClock
    commands: CommandService
    approvals: ApprovalService
    human: PrincipalContext
    agent: PrincipalContext
    authority: dict[str, PrincipalContext]

    def execute(self, action: str, arguments: dict[str, Any], key: str,
                principal: PrincipalContext | None = None, surface: str = "api") -> dict[str, Any]:
        return self.commands.execute(action, principal or self.human, arguments, key, surface)

    def submitted(self) -> dict[str, Any]:
        order = self.execute("create", {"title": "Inspect fictional pump", "assignee": "dev.lee"}, "create")
        return self.execute("submit", {"id": order["id"], "expected_version": 1}, "submit")

    def confirmed(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        order = self.submitted()
        challenge = self.approvals.challenge(self.agent, order["id"], "challenge")
        capability = self.approvals.confirm(self.human, challenge["id"], challenge["statement"],
                                            "confirm", confirmed=True)
        return order, challenge, capability

    def counts(self) -> tuple[int, int, int]:
        with self.store.transaction() as conn:
            return tuple(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                         for table in ("work_orders", "domain_audit", "domain_events"))


@pytest.fixture
def domain(tmp_path: Any) -> DomainFixture:
    store = Store(tmp_path / "development-domain.sqlite")
    store.initialize()
    clock = VirtualClock(datetime(2026, 1, 1, tzinfo=UTC))
    scopes = frozenset({"workorders:read", "workorders:write", "workorders:submit", "workorders:approve"})
    human = PrincipalContext("appr.sam", "human", "dev-human", "dev-human-grant", scopes, "urn:m14:dev")
    agent = PrincipalContext("dev.agent", "agent", "dev-agent", "dev-agent-grant",
                             scopes - {"workorders:approve"}, "urn:m14:dev")
    authority = {human.grant_id: human, agent.grant_id: agent}

    def validate(conn: sqlite3.Connection, principal: PrincipalContext, now: datetime) -> PrincipalContext:
        # Deliberately test-owned authority, not a production permissive callback.
        current = authority.get(principal.grant_id)
        if current != principal:
            raise DomainError("invalid_principal", 401)
        return current

    store.set_principal_validator(validate)
    return DomainFixture(store, clock, CommandService(store, clock), ApprovalService(store, clock),
                         human, agent, authority)


def assert_error(code: str, function: Any, *args: Any, **kwargs: Any) -> DomainError:
    with pytest.raises(DomainError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == code
    return caught.value


def test_lifecycle_snapshots_audit_and_events_increment_once(domain: DomainFixture) -> None:
    order, challenge, capability = domain.confirmed()
    approved = domain.execute("approve", {"id": order["id"], "expected_version": 2,
        "capability_id": capability["capability_id"], "statement": challenge["statement"]}, "approve")
    closed = domain.execute("close", {"id": order["id"], "expected_version": 3}, "close", surface="ui")
    assert (approved["status"], closed["status"], closed["version"]) == ("approved", "closed", 4)
    assert domain.counts() == (1, 4, 4)
    with domain.store.transaction() as conn:
        rows = conn.execute("SELECT resource_version,body,body_sha256 FROM domain_events ORDER BY resource_version").fetchall()
        assert [row[0] for row in rows] == [1, 2, 3, 4]
        for version, body, digest in rows:
            event = json.loads(body)
            assert hashlib.sha256(body).hexdigest() == digest
            assert event["resource_version"] == event["data"]["version"] == version
            assert "effect_ref" not in event["data"]
        assert conn.execute("SELECT surface FROM domain_audit WHERE resource_version=4").fetchone()[0] == "ui"
        assert conn.execute("SELECT consumed,consumed_at FROM approval_capabilities").fetchone()[0] == 1


@pytest.mark.parametrize("initial", ["draft", "submitted"])
def test_cancel_legal_sources_and_terminal_refusal(domain: DomainFixture, initial: str) -> None:
    order = domain.execute("create", {"title": "Cancel development order"}, "create")
    version = 1
    if initial == "submitted":
        order = domain.execute("submit", {"id": order["id"], "expected_version": 1}, "submit")
        version = 2
    cancelled = domain.execute("cancel", {"id": order["id"], "expected_version": version}, "cancel")
    before = domain.counts()
    assert cancelled["status"] == "cancelled"
    assert_error("invalid_transition", domain.execute, "edit",
                 {"id": order["id"], "expected_version": version + 1, "assignee": "dev.new"}, "edit")
    assert domain.counts() == before


def test_submitted_assignee_edit_but_no_title_edit(domain: DomainFixture) -> None:
    order = domain.submitted()
    edited = domain.execute("edit", {"id": order["id"], "expected_version": 2, "assignee": "dev.new"}, "edit")
    assert (edited["version"], edited["assignee"]) == (3, "dev.new")
    assert_error("submitted_title_immutable", domain.execute, "edit",
                 {"id": order["id"], "expected_version": 3, "title": "changed"}, "bad-edit")
    assert domain.counts() == (1, 3, 3)


def test_draft_edit_and_illegal_close_preserve_state(domain: DomainFixture) -> None:
    order = domain.execute("create", {"title": "Original draft"}, "create")
    edited = domain.execute("edit", {"id": order["id"], "expected_version": 1,
        "title": "Updated draft", "assignee": "dev.owner"}, "edit")
    assert (edited["title"], edited["assignee"], edited["version"]) == ("Updated draft", "dev.owner", 2)
    assert_error("invalid_transition", domain.execute, "close",
                 {"id": order["id"], "expected_version": 2}, "close")
    assert domain.counts() == (1, 2, 2)


def test_concurrent_same_base_edits_have_one_success(domain: DomainFixture) -> None:
    order = domain.execute("create", {"title": "Before race", "assignee": "dev.old"}, "create")
    ready = Barrier(2)

    def edit(index: int) -> dict[str, Any] | str:
        ready.wait(timeout=5)
        try:
            return domain.execute("edit", {"id": order["id"], "expected_version": 1,
                "title": f"Acknowledged {index}", "assignee": f"dev.{index}"}, f"edit-{index}")
        except DomainError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(edit, (1, 2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("version_conflict") == 1
    winner = next(result for result in results if isinstance(result, dict))
    current = domain.commands.execute("get", domain.human, {"id": order["id"]}, None)
    assert (current["title"], current["assignee"], current["version"]) == (winner["title"], winner["assignee"], 2)
    assert domain.counts() == (1, 2, 2)


def test_forced_event_failure_rolls_back_order_audit_and_capability(domain: DomainFixture) -> None:
    order, _, capability = domain.confirmed()
    with domain.store.transaction() as conn:
        conn.execute("CREATE TRIGGER development_abort BEFORE INSERT ON domain_events "
                     "BEGIN SELECT RAISE(ABORT,'development rollback'); END")
    with pytest.raises(sqlite3.IntegrityError, match="development rollback"):
        domain.execute("approve", {"id": order["id"], "expected_version": 2,
                                  "capability_id": capability["capability_id"]}, "approve")
    assert domain.counts() == (1, 2, 2)
    with domain.store.transaction() as conn:
        assert conn.execute("SELECT status,version FROM work_orders").fetchone()[:] == ("submitted", 2)
        assert conn.execute("SELECT consumed,consumed_at FROM approval_capabilities").fetchone()[:] == (0, None)
        assert conn.execute("SELECT count(*) FROM idempotency_keys WHERE action='approve'").fetchone()[0] == 0


def test_saved_success_cross_surface_and_changed_body(domain: DomainFixture) -> None:
    args = {"title": "One effect"}
    first = domain.execute("create", args, "same-key", surface="api")
    assert domain.execute("create", args, "same-key", surface="cli") == first
    assert_error("idempotency_conflict", domain.execute, "create", {"title": "Different"}, "same-key")
    assert domain.counts() == (1, 1, 1)


def test_current_authority_precedes_saved_success(domain: DomainFixture) -> None:
    args = {"title": "Before grant revocation"}
    domain.execute("create", args, "key")
    domain.authority.pop(domain.human.grant_id)
    assert_error("invalid_principal", domain.execute, "create", args, "key")
    assert domain.counts() == (1, 1, 1)


def test_current_narrow_scope_precedes_saved_success(domain: DomainFixture) -> None:
    args = {"title": "Created while write was granted"}
    domain.execute("create", args, "key")
    narrow = replace(domain.human, scopes=frozenset({"workorders:read"}))
    domain.authority[narrow.grant_id] = narrow
    error = assert_error("insufficient_scope", domain.execute, "create", args, "key", principal=narrow)
    assert error.required_scopes == ("workorders:write",)
    assert domain.counts() == (1, 1, 1)


def test_missing_validator_fails_closed(domain: DomainFixture) -> None:
    reopened = CommandService(Store(domain.store.path), domain.clock)
    assert_error("authentication_unavailable", reopened.execute, "list", domain.human, {}, None)


@pytest.mark.parametrize("namespace_change", ["subject", "grant"])
def test_key_namespaces_do_not_leak_saved_response(domain: DomainFixture, namespace_change: str) -> None:
    first = domain.execute("create", {"title": "First owner"}, "key")
    other = replace(domain.human, subject="dev.other") if namespace_change == "subject" else replace(domain.human, grant_id="dev.other-grant")
    domain.authority[other.grant_id] = other
    second = domain.execute("create", {"title": "Second owner"}, "key", principal=other)
    assert first["id"] != second["id"]
    assert domain.counts() == (2, 2, 2)


def test_result_expiry_tombstone_survives_prune_and_store_restart(domain: DomainFixture) -> None:
    args = {"title": "Permanent used key"}
    domain.execute("create", args, "key")
    domain.clock.advance(8 * 86400)
    assert_error("idempotency_expired", domain.execute, "create", args, "key")
    with domain.store.transaction() as conn:
        assert idempotency.expire_results(conn, domain.clock.now()) == 1
        assert conn.execute("SELECT count(*) FROM idempotency_keys").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM idempotency_results").fetchone()[0] == 0
    restarted = Store(domain.store.path)
    restarted.set_principal_validator(lambda conn, principal, now: domain.authority[principal.grant_id])
    assert_error("idempotency_expired", CommandService(restarted, domain.clock).execute,
                 "create", domain.human, args, "key")
    assert domain.counts() == (1, 1, 1)


def test_execution_denial_saved_without_domain_effect(domain: DomainFixture) -> None:
    order = domain.submitted()
    args = {"id": order["id"], "expected_version": 2, "title": "Forbidden edit"}
    assert_error("submitted_title_immutable", domain.execute, "edit", args, "bad")
    assert_error("submitted_title_immutable", domain.execute, "edit", args, "bad", surface="cli")
    assert domain.counts() == (1, 2, 2)
    with domain.store.transaction() as conn:
        assert conn.execute("SELECT count(*) FROM idempotency_results WHERE action='edit'").fetchone()[0] == 1


def test_agent_never_confirms_or_consumes_even_with_approve_scope(domain: DomainFixture) -> None:
    order, challenge, capability = domain.confirmed()
    overbroad = replace(domain.agent, scopes=domain.human.scopes)
    domain.authority[overbroad.grant_id] = overbroad
    assert_error("human_required", domain.approvals.confirm, overbroad, challenge["id"],
                 challenge["statement"], "agent-confirm", confirmed=True)
    assert_error("human_required", domain.execute, "approve", {"id": order["id"],
        "expected_version": 2, "capability_id": capability["capability_id"]}, "agent-approve", principal=overbroad)
    assert domain.counts() == (1, 2, 2)


def test_confirmation_requires_explicit_human_choice_and_current_challenge(domain: DomainFixture) -> None:
    order = domain.submitted()
    challenge = domain.approvals.challenge(domain.agent, order["id"], "challenge")
    assert_error("human_confirmation_required", domain.approvals.confirm, domain.human,
                 challenge["id"], challenge["statement"], "no-choice", confirmed=False)
    wrong_human = replace(domain.human, subject="dev.someone-else")
    domain.authority[wrong_human.grant_id] = wrong_human
    assert_error("wrong_executor", domain.approvals.confirm, wrong_human,
                 challenge["id"], challenge["statement"], "wrong-human", confirmed=True)
    domain.authority[domain.human.grant_id] = domain.human
    domain.clock.advance(300)
    assert_error("challenge_expired", domain.approvals.confirm, domain.human,
                 challenge["id"], challenge["statement"], "expired", confirmed=True)
    with domain.store.transaction() as conn:
        assert conn.execute("SELECT confirmed FROM approval_challenges").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM approval_capabilities").fetchone()[0] == 0


@pytest.mark.parametrize("field,value", [("subject", "dev.other"), ("grant_id", "dev.other-grant"),
                                       ("client_id", "dev.other-client"), ("resource", "urn:m14:other")])
def test_capability_wrong_executor_context_no_effect(domain: DomainFixture, field: str, value: str) -> None:
    order, _, capability = domain.confirmed()
    other = replace(domain.human, **{field: value})
    domain.authority[other.grant_id] = other
    assert_error("wrong_executor", domain.execute, "approve", {"id": order["id"],
        "expected_version": 2, "capability_id": capability["capability_id"]}, "wrong", principal=other)
    assert domain.counts() == (1, 2, 2)


def test_capability_stale_after_legal_edit_with_unchanged_statement(domain: DomainFixture) -> None:
    order, challenge, capability = domain.confirmed()
    domain.execute("edit", {"id": order["id"], "expected_version": 2, "assignee": "dev.new"}, "edit")
    assert_error("capability_stale", domain.execute, "approve", {"id": order["id"],
        "expected_version": 3, "capability_id": capability["capability_id"], "statement": challenge["statement"]}, "approve")
    assert domain.counts() == (1, 3, 3)


@pytest.mark.parametrize("problem", ["statement", "expiry", "requestor_binding"])
def test_capability_invalid_inputs_leave_consumed_false(domain: DomainFixture, problem: str) -> None:
    order, _, capability = domain.confirmed()
    args = {"id": order["id"], "expected_version": 2, "capability_id": capability["capability_id"]}
    if problem == "statement":
        args["statement"] = {"action": "approve", "decision": "refuse", "order_id": order["id"]}
        code = "statement_mismatch"
    elif problem == "expiry":
        domain.clock.advance(300)
        code = "capability_expired"
    else:
        with domain.store.transaction() as conn:
            conn.execute("UPDATE approval_capabilities SET requestor='dev.tampered'")
        code = "capability_binding"
    assert_error(code, domain.execute, "approve", args, "approve")
    with domain.store.transaction() as conn:
        assert conn.execute("SELECT consumed FROM approval_capabilities").fetchone()[0] == 0
    assert domain.counts() == (1, 2, 2)


def test_double_approve_restart_replay_and_durable_consumption(domain: DomainFixture) -> None:
    order, _, capability = domain.confirmed()
    args = {"id": order["id"], "expected_version": 2, "capability_id": capability["capability_id"]}
    ready = Barrier(2)

    def approve(index: int) -> dict[str, Any] | str:
        ready.wait(timeout=5)
        try:
            return domain.execute("approve", args, f"approve-{index}")
        except DomainError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, (1, 2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("version_conflict") == 1
    index, winner = next((index, result) for index, result in enumerate(results, 1) if isinstance(result, dict))
    restarted = Store(domain.store.path)
    restarted.set_principal_validator(lambda conn, principal, now: domain.authority[principal.grant_id])
    replay = CommandService(restarted, domain.clock).execute("approve", domain.human, args, f"approve-{index}")
    assert replay == winner
    with restarted.transaction() as conn:
        assert conn.execute("SELECT consumed FROM approval_capabilities").fetchone()[0] == 1
        # Direct consume probes the single-use guard separately from order CAS,
        # which otherwise masks this layer after the first approval.
        assert_error("capability_consumed", capabilities.consume, conn, domain.human, order, args, domain.clock.now())
    assert domain.counts() == (1, 3, 3)
