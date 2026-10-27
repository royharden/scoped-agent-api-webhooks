"""Bearer transport and strict JSON input boundaries."""

import re
from typing import Any, Protocol

from ..host.policy import DomainError, PrincipalContext

_BEARER = re.compile(r"Bearer ([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)
_TOKEN_FIELDS = frozenset({"access_token", "refresh_token", "id_token", "token"})


class TokenAuthority(Protocol):
    def authenticate(self, access_token: str) -> PrincipalContext: ...


def authenticate_request(authority: TokenAuthority) -> PrincipalContext:
    from flask import request

    # OAuth credentials are never accepted in URLs/forms or from API cookies.
    if _TOKEN_FIELDS.intersection(request.args) or _TOKEN_FIELDS.intersection(request.form):
        raise DomainError("invalid_token_transport", 400)
    header = request.headers.get("Authorization", "")
    match = _BEARER.fullmatch(header)
    if match is None:
        raise DomainError("invalid_token", 401)
    return authority.authenticate(match.group(1))


def json_object(allowed: set[str], *, required: set[str] | None = None) -> dict[str, Any]:
    from flask import request

    if not request.is_json:
        raise DomainError("json_required", 415)
    value = request.get_json(silent=True)
    if not isinstance(value, dict) or value.keys() - allowed:
        raise DomainError("invalid_arguments", 400)
    if required and required - value.keys():
        raise DomainError("invalid_arguments", 400)
    return value


def idempotency_key() -> str:
    from flask import request

    value = request.headers.get("Idempotency-Key", "")
    if not value or len(value) > 200 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise DomainError("idempotency_key_required", 400)
    return value


def surface() -> str:
    from flask import request

    value = request.headers.get("X-M14-Surface", "api")
    if value not in {"api", "cli"}:
        raise DomainError("invalid_surface", 400)
    return value


def pagination() -> dict[str, int]:
    from flask import request

    if request.args.keys() - {"limit", "offset"}:
        raise DomainError("invalid_arguments", 400)
    values = {}
    for key, default in (("limit", 100), ("offset", 0)):
        raw = request.args.get(key)
        if raw is None:
            values[key] = default
        elif not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
            raise DomainError("invalid_pagination", 400)
        else:
            values[key] = int(raw)
    if not 1 <= values["limit"] <= 100 or values["offset"] < 0:
        raise DomainError("invalid_pagination", 400)
    return values
