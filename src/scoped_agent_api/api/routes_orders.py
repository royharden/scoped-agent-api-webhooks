"""Work-order HTTP transport; every effect enters CommandService."""

from typing import Any

from ..host.policy import DomainError
from .resource_server import authenticate_request, idempotency_key, json_object, pagination, surface


def register_orders(app: Any, authority: Any, commands: Any) -> None:
    from flask import jsonify, request

    @app.route("/v1/work-orders", methods=["GET", "POST"])
    def orders() -> Any:
        principal = authenticate_request(authority)
        if request.method == "GET":
            return jsonify(commands.execute("list", principal, pagination(), None, surface()))
        body = json_object({"title", "assignee"}, required={"title"})
        return jsonify(commands.execute("create", principal, body, idempotency_key(), surface()))

    @app.route("/v1/work-orders/<order_id>", methods=["GET", "PATCH"])
    def order(order_id: str) -> Any:
        principal = authenticate_request(authority)
        if request.method == "GET":
            if request.args:
                raise DomainError("invalid_arguments", 400)
            return jsonify(commands.execute("get", principal, {"id": order_id}, None, surface()))
        body = json_object({"expected_version", "title", "assignee"}, required={"expected_version"})
        return jsonify(commands.execute("edit", principal, {**body, "id": order_id},
                                        idempotency_key(), surface()))

    @app.post("/v1/work-orders/<order_id>/<operation>")
    def transition(order_id: str, operation: str) -> Any:
        principal = authenticate_request(authority)
        if operation not in {"submit", "approve", "close", "cancel"}:
            raise DomainError("not_found", 404)
        allowed = {"expected_version"}
        if operation == "approve":
            allowed |= {"capability_id", "statement"}
        body = json_object(allowed, required={"expected_version"})
        return jsonify(commands.execute(operation, principal, {**body, "id": order_id},
                                        idempotency_key(), surface()))
