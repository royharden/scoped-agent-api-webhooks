"""Pure work-order validation/transitions shared by command surfaces."""

from typing import Any

from .policy import DomainError

_TRANSITIONS = {
    "submit": ({"draft"}, "submitted"), "approve": ({"submitted"}, "approved"),
    "close": ({"approved"}, "closed"), "cancel": ({"draft", "submitted"}, "cancelled"),
}


def text(value: object, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise DomainError("invalid_" + field, 400)
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise DomainError("invalid_" + field, 400) from exc
    return value


def transition(order: dict[str, Any], action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = dict(order)
    if action == "edit":
        if order["status"] not in {"draft", "submitted"}:
            raise DomainError("invalid_transition", 409)
        if order["status"] == "submitted" and "title" in arguments:
            raise DomainError("submitted_title_immutable", 409)
        if not ({"title", "assignee"} & arguments.keys()):
            raise DomainError("empty_edit", 400)
        if "title" in arguments:
            result["title"] = text(arguments["title"], "title")
        if "assignee" in arguments:
            result["assignee"] = text(arguments["assignee"], "assignee", nullable=True)
    elif action in _TRANSITIONS:
        allowed, status = _TRANSITIONS[action]
        if order["status"] not in allowed:
            raise DomainError("invalid_transition", 409)
        result["status"] = status
    else:
        raise DomainError("unknown_operation", 400)
    result["version"] += 1
    return result
