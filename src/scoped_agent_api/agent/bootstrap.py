"""Trusted in-memory fixture composition. No files, environment, listeners or AS fallback."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from .client import Session, Transport
from .oauth import OAuthController, OAuthError


class AuthorizationDenied(RuntimeError):
    """Closed local failure, safe for CLI denial mapping without exception text."""


@dataclass
class AuthenticatedSessionFactory:
    controller_factory: Callable[[str], OAuthController] = field(repr=False)
    resource_transport: Transport = field(repr=False)
    initial_scopes: frozenset[str]

    def __call__(self, actor_kind: str) -> Session:
        if actor_kind not in {"agent", "user"}:
            raise AuthorizationDenied("invalid fixture actor")
        protocol_actor = "human" if actor_kind == "user" else "agent"
        controller = self.controller_factory(protocol_actor)
        if controller.config.actor_kind != protocol_actor:
            raise AuthorizationDenied("fixture actor mismatch")
        if not controller.login(self.initial_scopes):
            raise AuthorizationDenied("fixture authorization refused")
        session = Session(controller.config.resource, self.resource_transport,
                          bearer=lambda: "", scopes=controller.scopes)

        def bearer() -> str:
            try:
                return controller.bearer()
            except OAuthError:
                session.stopped = True
                raise AuthorizationDenied("fixture authorization unavailable") from None

        def step_up(scopes: frozenset[str]) -> bool:
            allowed = controller.step_up(scopes)
            if not allowed:
                session.stopped = True
            return allowed

        session.bearer = bearer
        session.step_up = step_up
        return session
