"""Separate mock AS Flask application; never starts a listener or migration."""

from typing import Any
from uuid import uuid4

from ..host.policy import DomainError
from .authority import SCOPES


def create_blueprint(authority: Any, adapter: Any = None) -> Any:
    from flask import Blueprint, g, jsonify, request

    blueprint = Blueprint("mock_authorization_server", __name__)

    def protocol() -> Any:
        if adapter is None:
            raise DomainError("authlib_spike_pending", 503)
        return adapter

    @blueprint.get("/.well-known/oauth-authorization-server")
    def metadata() -> Any:
        issuer = authority.issuer
        base = issuer.rstrip("/")
        return jsonify({"issuer": issuer, "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token", "revocation_endpoint": base + "/revoke",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "authorization_response_iss_parameter_supported": True,
            "scopes_supported": sorted(SCOPES)})

    @blueprint.get("/authorize")
    def authorize() -> Any:
        return protocol().authorize_request()

    @blueprint.post("/token")
    def token() -> Any:
        return protocol().token_request()

    @blueprint.post("/revoke")
    def revoke() -> Any:
        if (request.mimetype != "application/x-www-form-urlencoded"
                or request.args or "Authorization" in request.headers
                or request.form.keys() - {"token", "client_id", "token_type_hint"}
                or any(len(request.form.getlist(key)) != 1 for key in request.form)):
            raise DomainError("invalid_request", 400)
        raw, client_id = request.form.get("token", ""), request.form.get("client_id", "")
        if not raw or not client_id:
            raise DomainError("invalid_request", 400)
        authority.revoke(raw, client_id)
        return "", 200

    @blueprint.errorhandler(DomainError)
    def oauth_error(error: DomainError) -> Any:
        # No credential values or exception traces in protocol responses.
        return jsonify({"error": error.code, "request_id": getattr(g, "request_id", str(uuid4()))}), error.status

    return blueprint


def create_app(store: Any, clock: Any, settings: dict[str, Any]) -> Any:
    from flask import Flask, g

    from .authlib_adapters import build_adapter
    from .authority import Authority

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    authority = Authority(store, clock, settings)
    adapter = build_adapter(app, authority)
    app.extensions["m14_authz"] = authority

    @app.before_request
    def context() -> None:
        g.request_id = str(uuid4())

    @app.after_request
    def response_headers(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.teardown_request
    def clear_context(error: Any) -> None:
        authority.clear_proof()

    app.register_blueprint(create_blueprint(authority, adapter))
    return app
