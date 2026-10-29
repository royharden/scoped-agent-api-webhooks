"""Construction-exposed stdlib-only regressions; no Flask/Authlib/pytest import."""

import base64
import hashlib
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from scoped_agent_api.authz.authority import Authority
from scoped_agent_api.host.store import Store
from scoped_agent_api.ports.clock import VirtualClock
from scoped_agent_api.webhooks.schema import initialize


class WorkerAuthorityDevelopment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="m14-dl2-development-")
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "fixture.sqlite")
        self.clock = VirtualClock(datetime(2026, 10, 28, tzinfo=UTC))
        self.settings = {"issuer": "https://issuer.fixture.invalid", "resource": "https://host.fixture.invalid",
            "clients": {"human": {"actor_kind": "human", "redirect_uris": ("https://human.fixture.invalid/callback",),
                                    "allowed_scopes": frozenset({"workorders:read", "workorders:write"})}},
            "consent_resolver": lambda *_: {"allowed": True, "subject": "development.human"}}
        self.store.initialize()
        self.authority = Authority(self.store, self.clock, self.settings)
        self.authority.initialize()
        self.store.set_principal_validator(self.authority.validate_principal)
        with self.store.transaction() as conn:
            initialize(conn)
        verifier = "v" * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        code = self.authority.authorize_code("human", "https://human.fixture.invalid/callback",
            self.settings["resource"], "workorders:read workorders:write", challenge, "development-consent")
        self.tokens = self.authority.exchange_code(code, "human", "https://human.fixture.invalid/callback",
            self.settings["resource"], verifier)
        self.principal = self.authority.authenticate(self.tokens["access_token"])

    def test_worker_callback_uses_supplied_writer_and_current_time(self):
        with self.store.transaction() as conn:
            with patch.object(self.store, "transaction", side_effect=AssertionError("nested writer refused")):
                self.assertTrue(self.authority.grant_validator_in_transaction(conn,
                    self.principal.grant_id, frozenset({"workorders:read"}), self.clock.now()))
                self.clock.advance(86400)
                self.assertFalse(self.authority.grant_validator_in_transaction(conn,
                    self.principal.grant_id, frozenset({"workorders:read"}), self.clock.now()))

    def test_outside_callback_samples_time_after_writer_acquisition(self):
        transaction = self.store.transaction

        @contextmanager
        def delayed_writer():
            with transaction() as conn:
                self.clock.advance(86400)
                yield conn

        with patch.object(self.store, "transaction", delayed_writer):
            self.assertFalse(self.authority.grant_is_active(self.principal.grant_id,
                                                          frozenset({"workorders:read"})))

    def test_ui_session_preserves_narrowed_token_scopes(self):
        narrowed = self.authority.refresh(self.tokens["refresh_token"], "human",
                                          self.settings["resource"], "workorders:read")
        principal = self.authority.authenticate(narrowed["access_token"])
        session = self.authority.create_ui_session(principal)
        resolved, _ = self.authority.resolve_ui_session(session["session_id"])
        self.assertEqual(resolved.scopes, frozenset({"workorders:read"}))
        with self.store.transaction() as conn:
            current = self.store.current_principal(conn, resolved, self.clock.now())
            self.assertEqual(current.scopes, frozenset({"workorders:read"}))
