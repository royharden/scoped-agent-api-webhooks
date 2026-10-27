"""Explicit Flask factory; no listeners, migrations or external calls on import."""

from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from ..host.approvals import ApprovalService
from ..host.commands import CommandService
from ..host.policy import DomainError
from .problem import problem_response
from .routes_approvals import register_approvals
from .routes_orders import register_orders
from .routes_webhooks import register_webhooks


def _configured_url(settings: dict[str, Any], key: str) -> str:
    value = settings.get(key)
    if (not isinstance(value, str) or not value or any(ord(char) < 33 for char in value)
            or '"' in value or "\\" in value):
        raise ValueError(f"configured {key} URL required")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.fragment or parsed.username:
        raise ValueError(f"invalid configured {key} URL")
    return value


def create_app(store: Any, clock: Any, settings: dict[str, Any]) -> Any:
    from flask import Flask, g, jsonify
    from werkzeug.exceptions import HTTPException

    from ..authz import Authority
    from ..ui.oauth import register_oauth_login
    from ..ui.routes import register_ui

    issuer = _configured_url(settings, "issuer")
    resource = _configured_url(settings, "resource")
    metadata_url = _configured_url(
        {"metadata": settings.get("resource_metadata_url", resource.rstrip("/") +
                                  "/.well-known/oauth-protected-resource")}, "metadata")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    authority = Authority(store, clock, settings)
    store.set_principal_validator(authority.validate_principal)
    executor = settings.get("approval_executor_subject", "appr.sam")
    commands = CommandService(store, clock, executor_subject=executor)
    approvals = ApprovalService(store, clock, executor_subject=executor)
    app.extensions["m14"] = {"authority": authority, "commands": commands, "approvals": approvals}

    @app.before_request
    def request_context() -> None:
        authority.clear_proof()
        g.request_id = str(uuid4())

    @app.teardown_request
    def clear_authority(error: Any) -> None:
        authority.clear_proof()

    @app.after_request
    def response_headers(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Request-ID"] = g.request_id
        return response

    @app.errorhandler(DomainError)
    def domain_error(error: DomainError) -> Any:
        return problem_response(error, metadata_url)

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException) -> Any:
        return problem_response(DomainError("http_error", error.code or 500), metadata_url)

    @app.get("/.well-known/oauth-protected-resource")
    def metadata() -> Any:
        return jsonify({"resource": resource, "authorization_servers": [issuer],
                        "bearer_methods_supported": ["header"],
                        "scopes_supported": ["workorders:read", "workorders:write", "workorders:submit",
                                             "workorders:approve", "webhooks:manage"]})

    register_orders(app, authority, commands)
    register_approvals(app, authority, approvals)
    management = settings.get("webhooks_service")
    if management is None and settings.get("endpoint_guard") is not None:
        from .webhooks_adapter import build_webhooks_service
        management = build_webhooks_service(authority, settings["endpoint_guard"])
    register_webhooks(app, authority, management)
    register_ui(app, authority, commands, approvals, settings)
    register_oauth_login(app, authority, settings)
    return app
