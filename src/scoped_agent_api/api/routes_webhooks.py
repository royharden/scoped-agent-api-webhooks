"""Management HTTP endpoints with an explicit injectable service boundary."""

from typing import Any

from ..host.policy import DomainError
from .resource_server import authenticate_request, idempotency_key, json_object, pagination, surface

_REQUIRED = ("workorders:read", "webhooks:manage")


def register_webhooks(app: Any, authority: Any, service: Any) -> None:
    from flask import jsonify, request

    def dispatch(action: str, arguments: dict[str, Any], *, mutation: bool) -> Any:
        principal = authenticate_request(authority)
        if not set(_REQUIRED).issubset(principal.scopes):
            raise DomainError("insufficient_scope", 403, _REQUIRED)
        if service is None:
            raise DomainError("webhooks_unavailable", 503)
        # The service owns transaction-local current-principal validation and
        # idempotency before management effects. No direct storage shortcut here.
        result = service.execute(action, principal, arguments,
                                 idempotency_key() if mutation else None, surface=surface())
        return jsonify(result)

    @app.route("/v1/subscriptions", methods=["GET", "POST"])
    def subscriptions() -> Any:
        if request.method == "GET":
            return dispatch("subscriptions.list", pagination(), mutation=False)
        body = json_object({"endpoint", "event_types"}, required={"endpoint", "event_types"})
        return dispatch("subscriptions.create", body, mutation=True)

    @app.get("/v1/subscriptions/<subscription_id>")
    def subscription(subscription_id: str) -> Any:
        if request.args:
            raise DomainError("invalid_arguments", 400)
        return dispatch("subscriptions.get", {"id": subscription_id}, mutation=False)

    @app.post("/v1/subscriptions/<subscription_id>/<operation>")
    def subscription_change(subscription_id: str, operation: str) -> Any:
        if operation not in {"disable", "enable"}:
            raise DomainError("not_found", 404)
        body = json_object(set())
        return dispatch(f"subscriptions.{operation}", {**body, "id": subscription_id}, mutation=True)

    @app.get("/v1/deliveries")
    def deliveries() -> Any:
        return dispatch("deliveries.list", pagination(), mutation=False)

    @app.get("/v1/deliveries/<delivery_id>")
    def delivery(delivery_id: str) -> Any:
        if request.args:
            raise DomainError("invalid_arguments", 400)
        return dispatch("deliveries.get", {"id": delivery_id}, mutation=False)

    @app.post("/v1/deliveries/<delivery_id>/replay")
    def replay(delivery_id: str) -> Any:
        json_object(set())
        return dispatch("deliveries.replay", {"id": delivery_id}, mutation=True)

    @app.post("/v1/deliveries/recover")
    @app.post("/recover")
    def recover() -> Any:
        body = json_object({"limit", "since"})
        limit = body.get("limit", 100)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise DomainError("invalid_limit", 400)
        return dispatch("deliveries.recover", {**body, "limit": limit}, mutation=True)
