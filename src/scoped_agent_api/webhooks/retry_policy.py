"""Finite automatic delivery schedule and absolute original-event horizon."""

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from math import isfinite
from random import Random


ATTEMPT_DELAYS = (0, 5, 300, 1800, 7200, 18000, 36000, 50400, 72000, 86400)
MAX_ATTEMPTS = len(ATTEMPT_DELAYS)
AUTOMATIC_HORIZON_SECONDS = 96 * 60 * 60
REPLAY_WINDOW_SECONDS = 7 * 24 * 60 * 60
MAX_RETRY_AFTER_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class RetryDecision:
    due_at: float | None
    cooldown_until: float
    code: str


def retry_after(value: str | None, now: float) -> tuple[float | None, str | None]:
    """Parse delta seconds or HTTP-date, returning a clamped delay and code."""
    if value is None:
        return None, None
    try:
        stripped = value.strip()
        if stripped.isascii() and stripped.isdecimal():
            delay = float(int(stripped))
        else:
            parsed = parsedate_to_datetime(stripped)
            if parsed.tzinfo is None:
                raise ValueError("timezone_missing")
            delay = parsed.timestamp() - now
        if not isfinite(delay):
            raise ValueError("nonfinite_delay")
    except (ValueError, TypeError, OverflowError):
        return None, "retry_after_malformed"
    return min(MAX_RETRY_AFTER_SECONDS, max(0.0, delay)), None


class RetryPolicy:
    """Ten total automatic attempts, including the initial immediate attempt.

    Jitter is explicit and seeded by the caller. A replay starts a new bounded
    delivery sequence; its absolute cutoff is the seven-day replay window.
    """

    def __init__(self, random: Random) -> None:
        self.random = random

    def after_failure(
        self,
        *,
        attempts: int,
        now: float,
        event_created_at: float,
        status: int | None,
        retry_after_value: str | None,
        cooldown_until: float = 0,
        replay: bool = False,
    ) -> RetryDecision:
        horizon = REPLAY_WINDOW_SECONDS if replay else AUTOMATIC_HORIZON_SECONDS
        cutoff = event_created_at + horizon
        if attempts >= MAX_ATTEMPTS or now > cutoff:
            return RetryDecision(None, cooldown_until, "attempt_limit_or_horizon")
        if attempts < 1:
            raise ValueError("attempts_must_include_failed_attempt")
        delay = ATTEMPT_DELAYS[attempts] * self.random.uniform(0.9, 1.1)
        parsed_delay, parse_code = retry_after(retry_after_value, now)
        due = now + delay
        if parsed_delay is not None:
            due = max(due, now + parsed_delay)
        if status in {429, 502, 504}:
            cooldown_until = max(cooldown_until, due)
        due = max(due, cooldown_until)
        if due > cutoff:
            return RetryDecision(None, cooldown_until, "retry_horizon_exceeded")
        return RetryDecision(due, cooldown_until, parse_code or "retry_scheduled")


def utc_timestamp(now: datetime) -> float:
    if now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValueError("utc_datetime_required")
    value = now.timestamp()
    if not isfinite(value):
        raise ValueError("finite_time_required")
    return value
