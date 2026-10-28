"""Dependency-free ROUND2 development checks; not an independent study.

These exercise the domain with fictional test-owned authority, not OAuth/HTTP.
Generated databases remain in the OS temp directory for failure inspection.
The wider parametrized developer suite still requires the pending pytest setup.
"""

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

from scoped_agent_api.host import capabilities, idempotency
from scoped_agent_api.host.approvals import ApprovalService
from scoped_agent_api.host.commands import CommandService
from scoped_agent_api.host.policy import DomainError, PrincipalContext
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock


class DomainDevelopmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="m14-dl1-development-"))
        self.store = Store(self.directory / "domain.sqlite")
        self.store.initialize()
        self.clock = VirtualClock(datetime(2026, 1, 1, tzinfo=UTC))
        self.human = PrincipalContext("appr.sam", "human", "dev-human", "human-grant",
            frozenset({"workorders:read", "workorders:write", "workorders:submit", "workorders:approve"}),
            "urn:m14:development")
        self.agent = PrincipalContext("dev.agent", "agent", "dev-agent", "agent-grant",
            self.human.scopes - {"workorders:approve"}, self.human.resource)
        self.authority = {self.human.grant_id: self.human, self.agent.grant_id: self.agent}
        self.store.set_principal_validator(self.validate)
        self.commands = CommandService(self.store, self.clock)
        self.approvals = ApprovalService(self.store, self.clock)

    def validate(self, conn, principal, now):
        # Authoritative map exists only inside this development fixture.
        if self.authority.get(principal.grant_id) != principal:
            raise DomainError("invalid_principal", 401)
        return self.authority[principal.grant_id]

    def execute(self, action, args, key, principal=None, surface="api"):
        return self.commands.execute(action, principal or self.human, args, key, surface)

    def assert_denied(self, code, operation, *args, **kwargs):
        with self.assertRaises(DomainError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def counts(self):
        with self.store.transaction() as conn:
            return tuple(conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
                         for name in ("work_orders", "domain_audit", "domain_events"))

    def submitted(self):
        order = self.execute("create", {"title": "Fictional developer order"}, "create")
        return self.execute("submit", {"id": order["id"], "expected_version": 1}, "submit")

    def confirmed(self):
        order = self.submitted()
        challenge = self.approvals.challenge(self.agent, order["id"], "challenge")
        capability = self.approvals.confirm(self.human, challenge["id"], challenge["statement"],
                                            "confirm", confirmed=True)
        return order, challenge, capability

    def test_legal_edit_and_terminal_transitions(self):
        order = self.submitted()
        edited = self.execute("edit", {"id": order["id"], "expected_version": 2, "assignee": "dev.new"}, "edit")
        self.assertEqual((edited["status"], edited["version"]), ("submitted", 3))
        self.assert_denied("submitted_title_immutable", self.execute, "edit",
                           {"id": order["id"], "expected_version": 3, "title": "Forbidden"}, "bad-edit")
        cancelled = self.execute("cancel", {"id": order["id"], "expected_version": 3}, "cancel")
        self.assertEqual((cancelled["status"], cancelled["version"]), ("cancelled", 4))
        self.assert_denied("invalid_transition", self.execute, "submit",
                           {"id": order["id"], "expected_version": 4}, "resubmit")
        self.assertEqual(self.counts(), (1, 4, 4))

    def test_rollback_includes_capability_and_audit(self):
        order, _, cap = self.confirmed()
        with self.store.transaction() as conn:
            conn.execute("CREATE TRIGGER development_abort BEFORE INSERT ON domain_events "
                         "BEGIN SELECT RAISE(ABORT,'development rollback'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "development rollback"):
            self.execute("approve", {"id": order["id"], "expected_version": 2,
                                      "capability_id": cap["capability_id"]}, "approve")
        self.assertEqual(self.counts(), (1, 2, 2))
        with self.store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT status,version FROM work_orders").fetchone()[:], ("submitted", 2))
            self.assertEqual(conn.execute("SELECT consumed,consumed_at FROM approval_capabilities").fetchone()[:], (0, None))

    def test_racing_cas_preserves_one_acknowledged_update(self):
        order = self.execute("create", {"title": "Before race"}, "create")
        barrier = Barrier(2)

        def edit(index):
            barrier.wait(timeout=5)
            try:
                return self.execute("edit", {"id": order["id"], "expected_version": 1,
                    "title": f"winner-{index}", "assignee": f"dev.{index}"}, f"edit-{index}")
            except DomainError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(edit, (1, 2)))
        winners = [result for result in results if isinstance(result, dict)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(results.count("version_conflict"), 1)
        current = self.commands.execute("get", self.human, {"id": order["id"]}, None)
        self.assertEqual((current["title"], current["assignee"]), (winners[0]["title"], winners[0]["assignee"]))
        self.assertEqual(self.counts(), (1, 2, 2))

    def test_current_auth_blocks_saved_success(self):
        args = {"title": "Single effect"}
        first = self.execute("create", args, "same")
        self.assertEqual(self.execute("create", args, "same", surface="cli"), first)
        self.authority.pop(self.human.grant_id)
        self.assert_denied("invalid_principal", self.execute, "create", args, "same")
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_expired_tombstone_after_prune_and_restart(self):
        args = {"title": "Used key"}
        self.execute("create", args, "used")
        self.clock.advance(8 * 86400)
        with self.store.transaction() as conn:
            self.assertEqual(idempotency.expire_results(conn, self.clock.now()), 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM idempotency_keys").fetchone()[0], 1)
        restarted = Store(self.store.path)
        restarted.set_principal_validator(self.validate)
        self.assert_denied("idempotency_expired", CommandService(restarted, self.clock).execute,
                           "create", self.human, args, "used")
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_capability_stale_with_current_expected_version(self):
        order, challenge, cap = self.confirmed()
        self.execute("edit", {"id": order["id"], "expected_version": 2, "assignee": "dev.new"}, "edit")
        self.assert_denied("capability_stale", self.execute, "approve", {"id": order["id"],
            "expected_version": 3, "capability_id": cap["capability_id"], "statement": challenge["statement"]}, "approve")
        self.assertEqual(self.counts(), (1, 3, 3))

    def test_tampered_requestor_binding_is_refused(self):
        order, _, cap = self.confirmed()
        with self.store.transaction() as conn:
            conn.execute("UPDATE approval_capabilities SET requestor_grant_id='development-mismatch'")
        self.assert_denied("capability_binding", self.execute, "approve", {"id": order["id"],
            "expected_version": 2, "capability_id": cap["capability_id"]}, "approve")
        self.assertEqual(self.counts(), (1, 2, 2))
        with self.store.transaction() as conn:
            self.assertEqual(conn.execute("SELECT consumed FROM approval_capabilities").fetchone()[0], 0)

    def test_double_approval_and_restart_replay_do_not_repeat_effect(self):
        order, _, cap = self.confirmed()
        args = {"id": order["id"], "expected_version": 2, "capability_id": cap["capability_id"]}
        barrier = Barrier(2)

        def approve(index):
            barrier.wait(timeout=5)
            try:
                return self.execute("approve", args, f"approve-{index}")
            except DomainError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve, (1, 2)))
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertEqual(results.count("version_conflict"), 1)
        index, winner = next((index, result) for index, result in enumerate(results, 1) if isinstance(result, dict))
        restarted = Store(self.store.path)
        restarted.set_principal_validator(self.validate)
        self.assertEqual(CommandService(restarted, self.clock).execute(
            "approve", self.human, args, f"approve-{index}"), winner)
        with restarted.transaction() as conn:
            self.assertEqual(conn.execute("SELECT consumed FROM approval_capabilities").fetchone()[0], 1)
            self.assert_denied("capability_consumed", capabilities.consume,
                               conn, self.human, order, args, self.clock.now())
        self.assertEqual(self.counts(), (1, 3, 3))


if __name__ == "__main__":
    unittest.main()
