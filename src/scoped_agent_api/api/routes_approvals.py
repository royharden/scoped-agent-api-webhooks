"""Human confirmation and agent-to-human challenge handoff."""

from typing import Any

from ..host.policy import DomainError
from .resource_server import authenticate_request, idempotency_key, json_object, surface


def register_approvals(app: Any, authority: Any, approvals: Any) -> None:
    from flask import jsonify

    @app.post("/v1/approval-challenges")
    def challenge() -> Any:
        principal = authenticate_request(authority)
        body = json_object({"id"}, required={"id"})
        if not isinstance(body["id"], str) or not body["id"]:
            raise DomainError("invalid_arguments", 400)
        return jsonify(approvals.challenge(principal, body["id"], idempotency_key(), surface()))

    @app.post("/v1/approval-challenges/<challenge_id>/confirm")
    def confirm(challenge_id: str) -> Any:
        principal = authenticate_request(authority)
        body = json_object({"statement", "confirmed"}, required={"statement", "confirmed"})
        if not isinstance(body["statement"], dict) or type(body["confirmed"]) is not bool:
            raise DomainError("invalid_arguments", 400)
        return jsonify(approvals.confirm(principal, challenge_id, body["statement"],
                                        idempotency_key(), confirmed=body["confirmed"], surface=surface()))
