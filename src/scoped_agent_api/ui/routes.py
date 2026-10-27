"""Cookie-authenticated human UI. Authentication never comes from posted authority."""

from __future__ import annotations

import secrets
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Protocol
from uuid import uuid4

from ..host.capabilities import approval_statement
from ..host.policy import DomainError, PrincipalContext

if TYPE_CHECKING:
    from flask import Flask, Response

    from ..host.approvals import ApprovalService
    from ..host.commands import CommandService


SESSION_COOKIE = "m14_ui_session"


class SessionAuthority(Protocol):
    def create_ui_session(self, principal: PrincipalContext) -> dict[str, str]: ...

    def resolve_ui_session(self, session_id: str) -> tuple[PrincipalContext, str]: ...


def bind_verified_session(
    response: Response, authority: SessionAuthority, principal: PrincipalContext
) -> Response:
    """OAuth callback hook: caller MUST supply its already-verified human context.

    This is deliberately not an HTTP endpoint and accepts no posted principal or
    bearer. Authority also checks the current grant before creating its durable
    session; only the opaque session ID reaches the browser cookie.
    """
    if principal.actor_kind != "human":
        raise DomainError("human_required", 403)
    session = authority.create_ui_session(principal)
    response.set_cookie(
        SESSION_COOKIE, session["session_id"], max_age=15 * 60,
        secure=True, httponly=True, samesite="Lax", path="/ui",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def register_ui(
    app: Flask,
    authority: SessionAuthority,
    commands: CommandService,
    approvals: ApprovalService,
    settings: dict[str, Any],
) -> None:
    """Register forms; configuration and verified OAuth completion belong to host.

    No UI endpoint accepts bearer authentication or issues a session from a
    subject, grant, scope, or client supplied by the browser.
    """
    from flask import Blueprint, g, make_response, redirect, render_template, request, url_for

    blueprint = Blueprint("human_ui", __name__, url_prefix="/ui", template_folder="templates")

    def render(name: str, **values: Any) -> str:
        return render_template(
            "human_ui/" + name, csrf_token=g.ui_csrf,
            idempotency_key=lambda: str(uuid4()), **values,
        )

    def guarded(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except DomainError as error:
                return render_template("human_ui/error.html", code=error.code), error.status
        return wrapper

    def fields(allowed: set[str]) -> dict[str, str]:
        if request.form.keys() - (allowed | {"csrf_token", "idempotency_key"}):
            raise DomainError("invalid_arguments", 400)
        if any(len(request.form.getlist(key)) != 1 for key in request.form):
            raise DomainError("invalid_arguments", 400)
        return {key: request.form[key] for key in allowed if key in request.form}

    def version(values: dict[str, str]) -> int:
        raw = values.get("expected_version", "")
        if not raw.isascii() or not raw.isdecimal() or not 1 <= len(raw) <= 18:
            raise DomainError("expected_version_required", 400)
        parsed = int(raw)
        if parsed < 1:
            raise DomainError("expected_version_required", 400)
        return parsed

    def key() -> str:
        value = request.form.get("idempotency_key", "")
        if not value or len(value) > 200:
            raise DomainError("idempotency_key_required", 400)
        return value

    @blueprint.before_request
    def require_human_session() -> Any:
        try:
            if "Authorization" in request.headers:
                raise DomainError("ui_bearer_refused", 400)
            forbidden = {"access_token", "refresh_token", "token"}
            if forbidden.intersection(request.args) or forbidden.intersection(request.form):
                raise DomainError("ui_token_refused", 400)
            session_id = request.cookies.get(SESSION_COOKIE, "")
            if not session_id:
                raise DomainError("ui_session_required", 401)
            principal, csrf = authority.resolve_ui_session(session_id)
            if principal.actor_kind != "human":
                raise DomainError("human_required", 403)
            g.ui_principal, g.ui_csrf = principal, csrf
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                provided = request.form.get("csrf_token", "")
                if (len(request.form.getlist("csrf_token")) != 1
                        or not provided.isascii()
                        or not secrets.compare_digest(csrf, provided)):
                    raise DomainError("csrf_invalid", 403)
        except DomainError as error:
            return render_template("human_ui/error.html", code=error.code), error.status
        return None

    @blueprint.after_request
    def prevent_caching(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @blueprint.get("/")
    @guarded
    def index() -> str:
        orders = commands.execute("list", g.ui_principal, {}, None, surface="ui")
        return render("index.html", orders=orders["items"])

    @blueprint.get("/work-orders/<order_id>")
    @guarded
    def detail(order_id: str) -> str:
        order = commands.execute("get", g.ui_principal, {"id": order_id}, None, surface="ui")
        return render("detail.html", order=order)

    @blueprint.post("/work-orders")
    @guarded
    def create() -> Any:
        values = fields({"title", "assignee"})
        result = commands.execute("create", g.ui_principal,
            {"title": values.get("title", ""), "assignee": values.get("assignee") or None}, key(), surface="ui")
        return redirect(url_for("human_ui.detail", order_id=result["id"]), code=303)

    @blueprint.post("/work-orders/<order_id>/edit")
    @guarded
    def edit(order_id: str) -> Any:
        values = fields({"expected_version", "title", "assignee"})
        arguments: dict[str, Any] = {"id": order_id, "expected_version": version(values)}
        if "title" in values:
            arguments["title"] = values["title"]
        if "assignee" in values:
            arguments["assignee"] = values["assignee"] or None
        commands.execute("edit", g.ui_principal, arguments, key(), surface="ui")
        return redirect(url_for("human_ui.detail", order_id=order_id), code=303)

    @blueprint.post("/work-orders/<order_id>/<action>")
    @guarded
    def transition(order_id: str, action: str) -> Any:
        if action not in {"submit", "close", "cancel"}:
            raise DomainError("unknown_operation", 404)
        values = fields({"expected_version"})
        commands.execute(action, g.ui_principal,
            {"id": order_id, "expected_version": version(values)}, key(), surface="ui")
        return redirect(url_for("human_ui.detail", order_id=order_id), code=303)

    @blueprint.post("/work-orders/<order_id>/challenge")
    @guarded
    def challenge(order_id: str) -> str:
        fields(set())
        result = approvals.challenge(g.ui_principal, order_id, key(), surface="ui")
        return render("challenge.html", challenge=result)

    @blueprint.get("/approval-handoff")
    @guarded
    def handoff() -> str:
        return render("handoff.html")

    @blueprint.post("/approval-handoff")
    @guarded
    def prepare_confirmation() -> str:
        values = fields({"challenge_id", "order_id"})
        # Identifiers select a challenge, never its authority. The domain service
        # rechecks executor, resource, exact statement, expiry and current state.
        challenge_id, order_id = values.get("challenge_id", ""), values.get("order_id", "")
        if not challenge_id or not order_id or max(len(challenge_id), len(order_id)) > 200:
            raise DomainError("invalid_arguments", 400)
        order = commands.execute("get", g.ui_principal, {"id": order_id}, None, surface="ui")
        return render("challenge.html", challenge={
            "id": challenge_id, "order_id": order_id, "statement": approval_statement(order_id),
            "resource_version": order["version"], "executor_subject": "The server-selected human executor",
            "expires_at": "Checked by the server on confirmation",
        })

    @blueprint.post("/approval-challenges/<challenge_id>/confirm")
    @guarded
    def confirm(challenge_id: str) -> str:
        values = fields({"order_id", "confirmed"})
        order_id = values.get("order_id", "")
        if not order_id:
            raise DomainError("invalid_arguments", 400)
        result = approvals.confirm(
            g.ui_principal, challenge_id, approval_statement(order_id), key(),
            confirmed=values.get("confirmed") == "yes", surface="ui",
        )
        return render("capability.html", capability=result)

    @blueprint.post("/work-orders/<order_id>/approve")
    @guarded
    def approve(order_id: str) -> Any:
        values = fields({"expected_version", "capability_id"})
        commands.execute("approve", g.ui_principal, {
            "id": order_id, "expected_version": version(values),
            "capability_id": values.get("capability_id", ""),
            "statement": approval_statement(order_id),
        }, key(), surface="ui")
        return redirect(url_for("human_ui.detail", order_id=order_id), code=303)

    @blueprint.post("/logout")
    @guarded
    def logout() -> Response:
        fields(set())
        response = make_response(render_template("human_ui/error.html", code="ui_signed_out"))
        response.delete_cookie(SESSION_COOKIE, path="/ui", secure=True, httponly=True, samesite="Lax")
        # Session authority owns expiry/revocation. Cookie deletion does not claim
        # to revoke the underlying grant or invalidate other browser sessions.
        return response

    app.register_blueprint(blueprint)
