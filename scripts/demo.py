"""Source-only fixture journey entrypoint; deliberately requires injected authenticated session."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Callable
from scoped_agent_api.agent.client import FixtureConsent, Session, run_task


def journey(task_path: Path, session: Session | None = None, consent: FixtureConsent | None = None,
            *, apply_fixture: bool = False,
            session_factory: Callable[[str], Session] | None = None) -> list[dict[str, object]]:
    task = json.loads(task_path.read_text(encoding="utf-8"))
    return run_task(task, session, apply_fixture=apply_fixture, consent=consent, session_factory=session_factory)


if __name__ == "__main__":
    raise SystemExit("Source construction only: future fixture launcher must inject session/consent. Runtime unverified.")
