"""HTTP facade over DL3-owned atomic management operations, never direct writes."""

from datetime import datetime, timezone
from typing import Any

from ..host.policy import DomainError, PrincipalContext


class WebhookManagement:
    def __init__(self, subscriptions: Any, deliveries: Any) -> None:
        self.subscriptions, self.deliveries = subscriptions, deliveries

    def execute(self, action: str, principal: PrincipalContext, arguments: dict[str, Any],
                idempotency_key: str | None, surface: str = "api") -> dict[str, Any]:
        try:
            return self._execute(action, principal, arguments, idempotency_key, surface)
        except ValueError:
            # DL3 endpoint and canonical encoders report invalid user values as
            # ValueError (including UnicodeError). Service transactions have
            # already rolled back; convert only this documented input boundary.
            # Never expose the refused URL/value or turn it into an HTTP 500.
            raise DomainError("invalid_arguments", 400) from None

    def _execute(self, action: str, principal: PrincipalContext, arguments: dict[str, Any],
                 idempotency_key: str | None, surface: str) -> dict[str, Any]:
        if surface not in {"api", "cli"}:
            raise DomainError("invalid_surface", 400)
        if action.endswith(".list"):
            if arguments.get("offset", 0) != 0:
                # DL3's bounded source list reads at most 100. Do not silently
                # promise arbitrary pagination that its service cannot supply.
                raise DomainError("pagination_unsupported", 400)
            service = self.subscriptions if action == "subscriptions.list" else self.deliveries
            items = service.list(principal)
            limit = arguments.get("limit", 100)
            return {"items": items[:limit], "limit": limit, "offset": 0}
        item_id = arguments.get("id")
        if action.endswith(".get"):
            if not isinstance(item_id, str) or not item_id:
                raise DomainError("invalid_arguments", 400)
            service = self.subscriptions if action == "subscriptions.get" else self.deliveries
            return service.get(principal, item_id)
        if not idempotency_key:
            raise DomainError("idempotency_key_required", 400)
        if action == "subscriptions.create":
            endpoint, events = arguments.get("endpoint"), arguments.get("event_types")
            if (not isinstance(endpoint, str) or not isinstance(events, list) or not events
                    or any(not isinstance(event, str) for event in events)):
                raise DomainError("invalid_arguments", 400)
            return self.subscriptions.create(principal, endpoint, events, idempotency_key=idempotency_key)
        if action in {"subscriptions.enable", "subscriptions.disable", "deliveries.replay"}:
            if not isinstance(item_id, str) or not item_id:
                raise DomainError("invalid_arguments", 400)
            if action == "deliveries.replay":
                return self.deliveries.replay(principal, item_id, idempotency_key=idempotency_key)
            return self.subscriptions.set_enabled(principal, item_id, action.endswith(".enable"),
                                                   idempotency_key=idempotency_key)
        if action == "deliveries.recover":
            # A fixed default keeps retry body digests stable. DL3 clips to the
            # seven-day event horizon inside its effect/idempotency transaction.
            since = datetime(1970, 1, 1, tzinfo=timezone.utc)
            raw_since = arguments.get("since")
            if raw_since is not None:
                if not isinstance(raw_since, str):
                    raise DomainError("invalid_since", 400)
                try:
                    since = datetime.fromisoformat(raw_since)
                except ValueError:
                    raise DomainError("invalid_since", 400) from None
                if since.tzinfo is None:
                    raise DomainError("invalid_since", 400)
            limit = arguments.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 100:
                raise DomainError("invalid_limit", 400)
            return {"items": self.deliveries.recover(principal, since, limit,
                                                     idempotency_key=idempotency_key)}
        raise DomainError("unknown_operation", 400)


def build_webhooks_service(authority: Any, endpoint_guard: Any) -> WebhookManagement:
    from ..webhooks.outbox import DeliveryService
    from ..webhooks.subscriptions import SubscriptionService

    subscriptions = SubscriptionService(authority.store, authority.clock, endpoint_guard,
                                         authority.grant_is_active)
    return WebhookManagement(subscriptions, DeliveryService(subscriptions))
