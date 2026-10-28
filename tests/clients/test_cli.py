"""Construction-exposed DEVELOPMENT CLI checks; no independent study labels."""
from __future__ import annotations

from dataclasses import dataclass, field
from io import StringIO
import json
import secrets

import pytest

from scoped_agent_api.agent.client import FixtureConsent, Session, run_task
from scoped_agent_api.cli.wo import main


@dataclass
class Reply:
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    value: object = field(default_factory=lambda: {"id": "development-order", "version": 1}, repr=False)
    malformed: bool = False

    def json(self) -> object:
        if self.malformed: raise ValueError("development malformed response")
        return self.value


class Recorder:
    def __init__(self, reply: Reply | None = None) -> None:
        self.reply = reply or Reply()
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, *, headers: dict[str, str], json: object) -> Reply:
        self.calls.append({"method": method, "url": url, "headers": headers, "json": json})
        return self.reply


def fixture_consent() -> FixtureConsent:
    return FixtureConsent("development-disposable-workspace", "development-consent", True, True)


def invoke(arguments: list[str], **kwargs: object) -> tuple[int, dict[str, object], str]:
    out, err = StringIO(), StringIO()
    status = main(arguments, stdout=out, stderr=err, **kwargs)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1
    value = json.loads(lines[0])
    assert value["schema_version"] == "m14.cli.v1" and value["exit_code"] == status
    return status, value, err.getvalue()


def test_mutation_dryrun_never_constructs_auth_or_calls_transport() -> None:
    factory_calls: list[str] = []
    def forbidden_factory(actor: str) -> Session:
        factory_calls.append(actor)
        raise AssertionError("dryrun attempted authorization")
    status, value, errors = invoke(["--json", "create", "--arguments", '{"title":"Inspect pump"}'],
                                   session_factory=forbidden_factory)
    assert status == 0 and value["decision"] == "dry_run" and value["dry_run"] is True
    assert not errors and not factory_calls


@pytest.mark.parametrize("operation,arguments,expected_path,actor", [
    ("challenge", {"id": "order1"}, "/v1/approval-challenges", "agent"),
    ("confirm", {"id": "challenge1", "statement": {"action": "approve"}, "confirmed": True},
     "/v1/approval-challenges/challenge1/confirm", "user"),
    ("recover", {"limit": 10}, "/v1/deliveries/recover", "agent"),
    ("replay", {"id": "delivery1"}, "/v1/deliveries/delivery1/replay", "agent"),
])
def test_applied_cli_forwards_exact_surface_key_and_route(operation: str, arguments: dict[str, object],
                                                        expected_path: str, actor: str) -> None:
    transport = Recorder()
    session = Session("https://api.development.invalid", transport, bearer=lambda: secrets.token_urlsafe(24))
    argv = ["--json", "--as", actor, "--apply-fixture", "--idempotency-key", "exact-development-key",
            operation, "--arguments", json.dumps(arguments)]
    status, value, errors = invoke(argv, session=session, consent=fixture_consent())
    assert status == 0 and value["decision"] == "allow" and not errors
    assert len(transport.calls) == 1
    request = transport.calls[0]
    assert request["url"] == "https://api.development.invalid" + expected_path
    assert request["headers"]["X-M14-Surface"] == "cli"
    assert request["headers"]["Idempotency-Key"] == "exact-development-key"
    assert request["method"] == "POST"
    if operation == "challenge": assert request["json"] == {"id": "order1"}
    if operation == "confirm": assert request["json"] == {"statement": {"action": "approve"}, "confirmed": True}


@pytest.mark.parametrize("guard,expected", [("consent", 3), ("key", 2), ("human_only", 3)])
def test_mutation_guards_run_before_lazy_factory(guard: str, expected: int) -> None:
    factory_calls: list[str] = []
    def forbidden_factory(actor: str) -> Session:
        factory_calls.append(actor)
        raise AssertionError("guard failed before auth")
    argv = ["--json", "--apply-fixture", "confirm" if guard == "human_only" else "create",
            "--arguments", '{"id":"challenge1"}' if guard == "human_only" else '{"title":"Inspect"}']
    kwargs = {"session_factory": forbidden_factory}
    if guard != "consent": kwargs["consent"] = fixture_consent()
    if guard != "key": argv += ["--idempotency-key", "development-key"]
    status, value, _ = invoke(argv, **kwargs)
    assert status == expected and not factory_calls
    assert value["decision"] != "allow"


def test_malformed_denial_uses_transport_exit_and_does_not_leak_error_text() -> None:
    transport = Recorder(Reply(status_code=401, malformed=True))
    session = Session("https://api.development.invalid", transport, bearer=lambda: secrets.token_urlsafe(24))
    status, value, errors = invoke(["--json", "list"], session=session)
    assert status == 5 and value["code"] == "transport_error" and session.stopped
    assert set(value["problem"]) == {"type", "title", "status", "code", "request_id"}
    assert "development malformed" not in errors
    status, value, _ = invoke(["--json", "list"], session=session)
    assert status == 3 and value["code"] == "session_stopped" and len(transport.calls) == 1


def test_task_dryrun_has_no_lazy_auth_and_agent_approval_stops_remaining_steps() -> None:
    calls: list[str] = []
    def forbidden_factory(actor: str) -> Session:
        calls.append(actor)
        raise AssertionError("dryrun attempted authorization")
    task = {"schema_version": "m14.task.v1", "task_id": "development-task", "consent_fixture_id": "development-consent",
            "steps": [{"operation": "create", "arguments": {"title": "Inspect"}, "idempotency_key": "dev-key"},
                      {"operation": "approve", "arguments": {"id": "order1"}},
                      {"operation": "list", "arguments": {}}]}
    result = run_task(task, session_factory=forbidden_factory)
    assert [item["decision"] for item in result] == ["dry_run", "denied"]
    assert result[-1]["code"] == "human_only" and not calls


def test_task_requires_matching_consent_before_any_request() -> None:
    task = {"schema_version": "m14.task.v1", "task_id": "development-task", "consent_fixture_id": "wrong-consent",
            "steps": [{"operation": "create", "arguments": {"title": "Inspect"}, "idempotency_key": "dev-key"}]}
    with pytest.raises(ValueError, match="consent"):
        run_task(task, apply_fixture=True, consent=fixture_consent())
