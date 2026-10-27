"""HTTP/UI approval facade; authority and storage stay in CommandService."""

from typing import Any

from ..ports.clock import Clock
from .commands import CommandService
from .policy import PrincipalContext
from .store import Store


class ApprovalService:
    def __init__(self, store: Store, clock: Clock, *, executor_subject: str = "appr.sam") -> None:
        self.commands = CommandService(store, clock, executor_subject=executor_subject)

    def challenge(self, principal: PrincipalContext, order_id: str, idempotency_key: str,
                  surface: str = "api") -> dict[str, Any]:
        return self.commands.execute("challenge", principal, {"id": order_id}, idempotency_key, surface)

    def confirm(self, principal: PrincipalContext, challenge_id: str, statement: dict[str, Any],
                idempotency_key: str, *, confirmed: bool, surface: str = "api") -> dict[str, Any]:
        return self.commands.execute("confirm", principal,
            {"id": challenge_id, "statement": statement, "confirmed": confirmed},
            idempotency_key, surface)
