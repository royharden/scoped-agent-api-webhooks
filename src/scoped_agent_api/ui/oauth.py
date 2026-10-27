"""First-party human PKCE entry points with durable, cookie-bound login state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Protocol
from urllib.parse import urlencode

from ..host.policy import DomainError, PrincipalContext
from .routes import bind_verified_session

if TYPE_CHECKING:
    from flask import Flask, Response


LOGIN_COOKIE = "m14_ui_login"


class LoginAuthority(Protocol):
    def begin_ui_login(
        self, client_id: str, redirect_uri: str, scopes: frozenset[str]
    ) -> dict[str, str]: ...

    def finish_ui_login(
        self, login_id: str, state: str, issuer: str, code: str,
        transport: Callable[[str, dict[str, str]], dict[str, Any]],
    ) -> PrincipalContext: ...

    def create_ui_session(self, principal: PrincipalContext) -> dict[str, str]: ...

    def resolve_ui_session(self, session_id: str) -> tuple[PrincipalContext, str]: ...


def register_oauth_login(app: Flask, authority: LoginAuthority, settings: dict[str, Any]) -> None:
    """Register only configured first-party client login and exact callback.

    The opaque login cookie binds the browser to the durable state/verifier row;
    authority owns the one-use five-minute state and issuer/code validation.
    Exchange is through an injected token transport, never a browser token.
    """
    from flask import Blueprint, make_response, redirect, render_template, request

    issuer = settings["issuer"]
    client_id = settings["first_party_client_id"]
    redirect_uri = settings["ui_redirect_uri"]
    scope_value = settings.get("ui_scopes", ("workorders:read",))
    scopes = frozenset(scope_value.split() if isinstance(scope_value, str) else scope_value)
    if not all(isinstance(value, str) and value for value in (issuer, client_id, redirect_uri)):
        raise ValueError("configured issuer, first-party client and exact UI redirect are required")
    if not scopes or any(not isinstance(scope, str) or not scope or " " in scope for scope in scopes):
        raise ValueError("configured UI scopes must be explicit scope names")
    blueprint = Blueprint("human_oauth", __name__, url_prefix="/ui/oauth")

    def clear_login(response: Response) -> Response:
        response.delete_cookie(LOGIN_COOKIE, path="/ui/oauth", secure=True, httponly=True, samesite="Lax")
        return response

    def reject(code: str, status: int) -> Response:
        # Use the fixed error code only, never provider text, query strings,
        # authorization codes, tokens, callback URLs or exception messages.
        return clear_login(make_response(render_template("human_ui/error.html", code=code), status))

    @blueprint.before_request
    def reject_browser_credentials() -> Response | None:
        if "Authorization" in request.headers:
            return reject("ui_bearer_refused", 400)
        forbidden = {"access_token", "refresh_token", "token", "id_token"}
        if forbidden.intersection(request.args) or forbidden.intersection(request.form):
            return reject("ui_token_refused", 400)
        if any(len(request.args.getlist(key)) != 1 for key in request.args):
            return reject("invalid_oauth_callback", 400)
        return None

    @blueprint.after_request
    def no_cache(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @blueprint.get("/start")
    def start() -> Response:
        if request.args:
            return reject("invalid_arguments", 400)
        if not callable(settings.get("oauth_token_transport")):
            return reject("oauth_transport_unavailable", 503)
        try:
            login = authority.begin_ui_login(client_id, redirect_uri, scopes)
            parameters = {
                "response_type": "code", "client_id": client_id,
                "redirect_uri": redirect_uri, "scope": " ".join(sorted(scopes)),
                "resource": settings["resource"], "state": login["state"],
                "code_challenge": login["code_challenge"], "code_challenge_method": "S256",
            }
            consent_id = settings.get("fixture_consent_id")
            if consent_id is not None:
                parameters["consent_fixture_id"] = consent_id
            response = redirect(issuer.rstrip("/") + "/authorize?" + urlencode(parameters), code=303)
            response.set_cookie(
                LOGIN_COOKIE, login["login_id"], max_age=5 * 60,
                secure=True, httponly=True, samesite="Lax", path="/ui/oauth",
            )
            return response
        except DomainError as error:
            return reject(error.code, error.status)

    @blueprint.get("/callback")
    def callback() -> Response:
        allowed = {"code", "state", "iss", "error"}
        if request.args.keys() - allowed:
            return reject("invalid_oauth_callback", 400)
        login_id = request.cookies.get(LOGIN_COOKIE, "")
        state, returned_issuer = request.args.get("state", ""), request.args.get("iss", "")
        if not login_id or not state or returned_issuer != issuer:
            return reject("invalid_oauth_callback", 400)
        if "error" in request.args:
            return reject("oauth_authorization_refused", 403)
        code = request.args.get("code", "")
        if not code:
            return reject("invalid_oauth_callback", 400)
        transport = settings.get("oauth_token_transport")
        if not callable(transport):
            return reject("oauth_transport_unavailable", 503)
        try:
            principal = authority.finish_ui_login(login_id, state, returned_issuer, code, transport)
            if principal.actor_kind != "human":
                raise DomainError("human_required", 403)
            response = redirect("/ui/", code=303)
            bind_verified_session(response, authority, principal)
            return clear_login(response)
        except DomainError as error:
            return reject(error.code, error.status)

    app.register_blueprint(blueprint)
