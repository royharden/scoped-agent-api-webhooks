"""Operation policy. Authentication must supply an authoritative current context."""

from dataclasses import dataclass


class DomainError(Exception):
    def __init__(self, code: str, status: int, required_scopes: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.required_scopes = required_scopes


@dataclass(frozen=True)
class PrincipalContext:
    subject: str
    actor_kind: str
    client_id: str
    grant_id: str
    scopes: frozenset[str]
    resource: str


_SCOPES: dict[str, tuple[str, ...]] = {
    "list": ("workorders:read",), "get": ("workorders:read",),
    "create": ("workorders:write",), "edit": ("workorders:write",),
    "close": ("workorders:write",), "cancel": ("workorders:write",),
    "submit": ("workorders:submit",), "approve": ("workorders:approve",),
    "challenge": ("workorders:read",), "confirm": ("workorders:approve",),
}


def authorize(context: PrincipalContext, action: str) -> None:
    if action not in _SCOPES:
        raise DomainError("unknown_operation", 400)
    if (not context.subject or not context.client_id or not context.grant_id
            or not context.resource or context.actor_kind not in {"human", "agent"}):
        raise DomainError("invalid_principal", 401)
    if action in {"approve", "confirm"} and context.actor_kind != "human":
        raise DomainError("human_required", 403)
    required = _SCOPES[action]
    if not set(required).issubset(context.scopes):
        raise DomainError("insufficient_scope", 403, required)
