"""HTTP-only CLI. Tokens and fixture authority are injected in memory, never read from disk."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Callable, Sequence, TextIO
from scoped_agent_api.agent.bootstrap import AuthorizationDenied
from scoped_agent_api.agent.client import FixtureConsent, ResponseError, Session, problem as http_problem, route


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InputError(message)


def main(argv: Sequence[str] | None = None, *, session: Session | None = None,
         consent: FixtureConsent | None = None,
         session_factory: Callable[[str], Session] | None = None, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    out, err = stdout or sys.stdout, stderr or sys.stderr
    parser = Parser(prog="wo", description="Fixture HTTP client; mutations default to dry-run.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--as", dest="actor", choices=("agent", "user"), default="agent")
    parser.add_argument("--apply-fixture", action="store_true")
    parser.add_argument("--idempotency-key")
    parser.add_argument("operation")
    parser.add_argument("--arguments", default="{}", help="JSON object; no credentials")
    exit_code, decision, code, data, problem = 2, "error", "invalid_input", None, None
    try:
        options = parser.parse_args(argv)
        arguments = json.loads(options.arguments)
        if not isinstance(arguments, dict):
            raise InputError("arguments must be an object")
        if any(k.lower() in {"token", "access_token", "refresh_token", "authorization", "password"} for k in arguments):
            raise InputError("credentials are not command arguments")
        method, path, body = route(options.operation, arguments)
        if options.actor == "agent" and options.operation in {"approve", "confirm"}:
            exit_code, decision, code = 3, "deny", "human_only"
        elif method != "GET" and not options.apply_fixture:
            exit_code, decision, code = 0, "dry_run", "dry_run"
            data = {"method": method, "path": path}
        elif method != "GET" and (consent is None or not consent.permits()):
            exit_code, decision, code = 3, "deny", "fixture_consent_required"
        elif method != "GET" and not options.idempotency_key:
            raise InputError("mutation requires --idempotency-key")
        else:
            if session is None and session_factory is not None:
                session = session_factory(options.actor)
            if session is None:
                raise AuthorizationDenied("fixture session required")
            result = session.call(options.operation, method, path, body, options.idempotency_key, surface="cli")
            exit_code = 0 if result.ok else 3 if result.status in {401, 403} else 4 if result.status == 409 else 2 if result.status in {400, 404, 422} else 5
            decision = "allow" if result.ok else "deny" if exit_code == 3 else "error"
            if result.ok:
                code, data = str(result.data.get("code", "ok")), result.data
            else:
                problem = http_problem(result.status, result.data.get("code"))
                code = str(problem["code"])
    except AuthorizationDenied:
        exit_code, decision, code = 3, "deny", "fixture_session_required"
        print("Fixture authorization unavailable or refused.", file=err)
    except ResponseError:
        exit_code, decision, code = 5, "error", "transport_error"
        problem = http_problem(502, code)
        print("Public HTTP response was invalid.", file=err)
    except (ValueError, TypeError):
        print("Invalid command input.", file=err)
    except Exception:
        # Transport exceptions may contain request headers; never echo their text.
        exit_code, decision, code = 5, "error", "transport_error"
        problem = http_problem(502, code)
        print("Public HTTP request failed.", file=err)
    envelope = {"schema_version": "m14.cli.v1", "decision": decision, "code": code,
                "data": data, "problem": problem, "dry_run": decision == "dry_run", "exit_code": exit_code}
    print(json.dumps(envelope, separators=(",", ":")), file=out)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
