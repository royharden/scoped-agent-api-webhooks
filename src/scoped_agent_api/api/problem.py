"""Consistent, secret-free RFC 9457 problem responses."""

from typing import Any
from uuid import uuid4

from ..host.policy import DomainError


def problem_response(error: DomainError, metadata_url: str) -> Any:
    from flask import g, jsonify

    request_id = getattr(g, "request_id", None) or str(uuid4())
    response = jsonify({
        "type": "about:blank",
        "title": error.code.replace("_", " "),
        "status": error.status,
        "code": error.code,
        "request_id": request_id,
    })
    response.status_code = error.status
    response.content_type = "application/problem+json"
    response.headers["Cache-Control"] = "no-store"
    if error.status == 401:
        response.headers["WWW-Authenticate"] = (
            f'Bearer resource_metadata="{metadata_url}"'
        )
    elif error.status == 403 and error.required_scopes:
        required = " ".join(error.required_scopes)
        response.headers["WWW-Authenticate"] = (
            f'Bearer error="insufficient_scope", scope="{required}"'
        )
    return response
