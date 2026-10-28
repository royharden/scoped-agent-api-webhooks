"""Construction-exposed developer checks executable with stdlib_ready only."""
import json
import secrets
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
import tempfile

from scoped_agent_api.agent.client import Session, ResponseError, FixtureConsent
from scoped_agent_api.agent.development import DevelopmentRegistry, DisposableLaunch
from scoped_agent_api.agent.oauth import OAuthController
from scoped_agent_api.cli.wo import main


class DevelopmentStdlibChecks(unittest.TestCase):
    def test_no_call_dryrun(self):
        def forbidden(actor):
            raise AssertionError("authorization attempted during dryrun")
        out = StringIO()
        status = main(["--json", "create"], stdout=out, session_factory=forbidden)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out.getvalue())["decision"], "dry_run")

    def test_malformed_refusal_stops_next_send(self):
        class Malformed:
            status_code = 401
            headers = {}
            def json(self):
                raise ValueError("development malformed")
        class Transport:
            calls = 0
            def request(self, *args, **kwargs):
                self.calls += 1
                return Malformed()
        transport = Transport()
        session = Session("https://api.m14.invalid", transport, lambda: secrets.token_urlsafe(24))
        with self.assertRaises(ResponseError):
            session.call("list", "GET", "/v1/work-orders")
        self.assertEqual(session.call("list", "GET", "/v1/work-orders").status, 403)
        self.assertEqual(transport.calls, 1)

    def test_consent_marker_tamper_refused(self):
        registry = DevelopmentRegistry()
        parent = Path(tempfile.mkdtemp(prefix="m14-stdlib-parent-"))
        launch = DisposableLaunch.generate(registry, human_confirmed=True, parent=parent)
        launch.validate(registry)
        marker = launch.path / "development-launch.json"
        facts = json.loads(marker.read_text(encoding="utf-8"))
        facts["human_confirmed"] = False
        marker.write_text(json.dumps(facts), encoding="utf-8")
        with self.assertRaises(ValueError):
            launch.validate(registry)

    def test_agent_scope_and_consent_refusal(self):
        registry = DevelopmentRegistry()
        resolve = registry.consent_resolver(True)
        result = resolve(registry.consent_fixture_id, registry.agent_client,
                         frozenset({"workorders:approve"}), registry.resource)
        self.assertFalse(result["allowed"])
        result = registry.consent_resolver(False)(registry.consent_fixture_id,
            registry.human_client, frozenset({"workorders:read"}), registry.resource)
        self.assertFalse(result["allowed"])

    def test_mutation_key_guard_before_factory(self):
        calls = []
        def forbidden(actor):
            calls.append(actor)
            raise AssertionError("key guard failed")
        consent = FixtureConsent("dev", "dev-consent", True, True)
        out = StringIO()
        status = main(["--json", "--apply-fixture", "create"], stdout=out, stderr=StringIO(),
                      consent=consent, session_factory=forbidden)
        self.assertEqual(status, 2)
        self.assertEqual(calls, [])

    def test_unavailable_protocol_permanently_closes_controller(self):
        class Unavailable:
            status_code = 503
            def json(self):
                raise AssertionError("unavailable body should not be read")
        class Transport:
            calls = 0
            def request(self, *args, **kwargs):
                self.calls += 1
                return Unavailable()
        transport = Transport()
        controller = OAuthController(DevelopmentRegistry().oauth_config("agent"), transport,
            lambda url: self.fail("unavailable discovery must not ask consent"),
            lambda: datetime(2026, 10, 27, tzinfo=timezone.utc))
        self.assertFalse(controller.login(frozenset({"workorders:read"})))
        self.assertFalse(controller.login(frozenset({"workorders:read"})))
        self.assertTrue(controller.stopped)
        self.assertEqual(transport.calls, 1)


if __name__ == "__main__":
    unittest.main()
