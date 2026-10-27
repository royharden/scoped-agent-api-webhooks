"""Explicit real and fixture clocks; no application startup side effects."""

from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("clock must return an aware UTC datetime")
    return value.astimezone(UTC)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class VirtualClock:
    """Fixture-only clock. Advancing this clock never sleeps."""

    def __init__(self, instant: datetime) -> None:
        self._instant = utc(instant)

    def now(self) -> datetime:
        return self._instant

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("clock cannot move backwards")
        self._instant = utc(self._instant + timedelta(seconds=seconds))
