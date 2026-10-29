"""Construction-exposed DEVELOPMENT regressions; not independent study outcomes."""
from datetime import datetime, timezone
from io import StringIO
import json

import pytest

from scoped_agent_api.agent.development import DevelopmentRegistry, DisposableLaunch, compose_development
from scoped_agent_api.cli.wo import main
from scoped_agent_api.ports.clock import VirtualClock


def test_explicit_consent_and_disposable_launch(tmp_path):
    registry = DevelopmentRegistry()
    with pytest.raises(ValueError, match="explicit_human"):
        DisposableLaunch.generate(registry, human_confirmed=False, parent=tmp_path)
    launch = DisposableLaunch.generate(registry, human_confirmed=True, parent=tmp_path)
    facts = json.loads((launch.path / "development-launch.json").read_text())
    assert facts["classification"] == "construction-exposed development"
    assert launch.consent.permits()
    launch.validate(registry)
    facts["human_confirmed"] = False
    marker = launch.path / "development-launch.json"
    marker.write_text(json.dumps(facts), encoding="utf-8")
    with pytest.raises(ValueError, match="fixture_launch_consent_mismatch"):
        launch.validate(registry)
    facts["human_confirmed"] = True
    marker.write_text(json.dumps(facts), encoding="utf-8")
    assert not {"token", "secret", "verifier"} & facts.keys()
    resolver = registry.consent_resolver(True)
    assert resolver(registry.consent_fixture_id, registry.agent_client,
                    frozenset({"workorders:read"}), registry.resource)["allowed"] is True
    assert resolver(registry.consent_fixture_id, registry.agent_client,
                    frozenset({"workorders:approve"}), registry.resource)["allowed"] is False
    assert registry.consent_resolver(False)(registry.consent_fixture_id, registry.human_client,
                    frozenset({"workorders:read"}), registry.resource)["allowed"] is False


def test_actual_joined_routes_keep_authlib_gate_closed_and_dryrun_offline(tmp_path):
    registry = DevelopmentRegistry()
    launch = DisposableLaunch.generate(registry, human_confirmed=True, parent=tmp_path)
    clock = VirtualClock(datetime(2026, 10, 27, tzinfo=timezone.utc))
    components, router, controllers = compose_development(launch, registry, clock, consent_allowed=True)
    components.initialize()
    metadata = router.request("GET", registry.resource + "/.well-known/oauth-protected-resource")
    assert metadata.json()["authorization_servers"] == [registry.issuer]
    denied = router.request("POST", registry.resource + "/v1/work-orders", json={"title": "Inspect pump"})
    assert denied.status_code == 401
    authorize = router.request("GET", registry.issuer + "/authorize?response_type=code")
    assert authorize.status_code == 503
    assert authorize.json()["error"] == "authlib_spike_pending"
    controller = controllers("agent")
    assert controller.login(frozenset({"workorders:read"})) is False
    assert controller.stopped
    assert controller.scopes == frozenset()
    with pytest.raises(ValueError, match="unconfigured_fixture"):
        router.request("GET", "https://outside.invalid/metadata")
    factory = components.authenticated_session_factory(controller_factory=controllers,
        resource_transport=router, initial_scopes=frozenset({"workorders:read"}))
    out = StringIO()
    assert main(["--json", "create", "--arguments", json.dumps({"title":"Inspect pump"})],
                consent=launch.consent, session_factory=factory, stdout=out) == 0
    assert json.loads(out.getvalue())["dry_run"] is True
    out = StringIO()
    assert main(["--json", "list"], consent=launch.consent,
                session_factory=factory, stdout=out, stderr=StringIO()) == 3
    assert json.loads(out.getvalue())["decision"] == "deny"
