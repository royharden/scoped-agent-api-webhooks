"""Construction-exposed developer checks, never independent interoperability."""

import base64
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from random import Random

import pytest

from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.retry_policy import RetryPolicy, retry_after
from scoped_agent_api.webhooks.signing import sign, verify

SECRET = "whsec_" + base64.b64encode(b"d" * 32).decode("ascii")
NOW = datetime(2030, 1, 1, tzinfo=UTC)


def test_raw_bytes_tamper_and_timestamp_tolerance():
    body = b'{"developer":"original raw bytes"}'
    headers = sign(body, "developer-event", NOW, [SECRET])
    verify(body, headers, [SECRET], NOW + timedelta(seconds=300))
    with pytest.raises(ValueError, match="timestamp_tolerance"):
        verify(body, headers, [SECRET], NOW + timedelta(seconds=301))
    with pytest.raises(ValueError, match="invalid_signature"):
        verify(body + b" ", headers, [SECRET], NOW)


@pytest.mark.parametrize("value,expected,code", [
    ("120", 120, None), ("999999", 86400, None),
    ("not-a-date", None, "retry_after_malformed"),
])
def test_retry_after_seconds_malformed_and_clamp(value, expected, code):
    assert retry_after(value, NOW.timestamp()) == (expected, code)


def test_retry_after_http_date_and_horizon_do_not_escape():
    date = format_datetime(NOW + timedelta(seconds=123), usegmt=True)
    assert retry_after(date, NOW.timestamp()) == (123, None)
    policy = RetryPolicy(Random(1414))
    result = policy.after_failure(attempts=1, now=NOW.timestamp()+96*3600-1,
        event_created_at=NOW.timestamp(), status=429, retry_after_value="86400")
    assert result.due_at is None and result.code == "retry_horizon_exceeded"


def test_ten_total_attempts_and_seeded_first_retry_jitter():
    kwargs = dict(attempts=1, now=NOW.timestamp(), event_created_at=NOW.timestamp(),
                  status=500, retry_after_value=None)
    first = RetryPolicy(Random(1414)).after_failure(**kwargs)
    assert first == RetryPolicy(Random(1414)).after_failure(**kwargs)
    assert 4.5 <= first.due_at - NOW.timestamp() <= 5.5
    assert RetryPolicy(Random(1414)).after_failure(**(kwargs | {"attempts": 10})).due_at is None


@pytest.mark.parametrize("url", [
    "http://localhost:23456/hooks/reference", "http://127.0.0.2:23456/hooks/reference",
    "http://127.0.0.1:23456/hooks/reference?x=1", "http://127.0.0.1:23456/hooks/%72eference",
    "http://user@127.0.0.1:23456/hooks/reference", "http://127.0.0.1:23456/hooks/reference#x",
    "http://[::1]:23456/hooks/reference",
])
def test_endpoint_aliases_refused_without_network(url):
    guard = EndpointGuard(["http://127.0.0.1:23456/hooks/reference"])
    with pytest.raises(ValueError):
        guard.validate(url)
