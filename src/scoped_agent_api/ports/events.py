"""Immutable snapshot event wire contract, with no policy or scoring logic."""

from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes


@dataclass(frozen=True)
class EventEnvelope:
    type: str
    timestamp: str
    resource_id: str
    resource_version: int
    data: dict[str, Any]
    schema_version: str = "m14.event.v1"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "type": self.type,
            "timestamp": self.timestamp, "resource_id": self.resource_id,
            "resource_version": self.resource_version, "data": dict(self.data),
        }

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.as_dict())
