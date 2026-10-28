"""HTTPX fake-only developer checks; zero listener or socket calls."""

import asyncio
import base64
import socket
from datetime import UTC, datetime

import httpx
import pytest

from scoped_agent_api.webhooks.endpoint_guard import EndpointGuard
from scoped_agent_api.webhooks.signing import sign
from scoped_agent_api.webhooks.transport import DeliveryTransportError, HttpxDeliveryTransport

URL = "http://127.0.0.1:23456/hooks/reference"
SECRET = "whsec_" + base64.b64encode(b"t" * 32).decode("ascii")


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("developer test attempted forbidden socket/DNS")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def fake_client(monkeypatch, *, hang=False, fail=False):
    observations = {"clients_closed": 0, "responses_closed": 0, "cancelled": False, "calls": []}

    class Response:
        status_code = 302
        headers = {"retry-after": "10"}

        async def __aenter__(self):
            if fail:
                raise RuntimeError("DO_NOT_EXPOSE_PRIVATE_SIGNATURE")
            if hang:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    observations["cancelled"] = True
                    raise
            return self

        async def __aexit__(self, *args):
            observations["responses_closed"] += 1

    class Client:
        def __init__(self, **kwargs):
            observations["settings"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            observations["clients_closed"] += 1

        def stream(self, method, endpoint, **kwargs):
            observations["calls"].append((method, endpoint, kwargs))
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    return observations


def arguments():
    body = b'{"developer":"raw unchanged"}'
    return body, sign(body, "developer-event", datetime(2030, 1, 1, tzinfo=UTC), [SECRET])


def test_actual_adapter_uses_one_bounded_operation_and_preserves_raw_values(monkeypatch):
    observations = fake_client(monkeypatch)
    body, headers = arguments()
    adapter = HttpxDeliveryTransport(EndpointGuard([URL]))
    result = adapter.send(URL, body, headers)
    assert result.status == 302 and result.headers == {"retry-after": "10"}
    assert observations["settings"]["trust_env"] is False
    assert observations["settings"]["follow_redirects"] is False
    assert observations["settings"]["timeout"] is None
    method, endpoint, request = observations["calls"][0]
    assert (method, endpoint, request["content"], request["headers"]) == ("POST", URL, body, headers)
    assert request["follow_redirects"] is False
    assert observations["responses_closed"] == observations["clients_closed"] == 1
    assert adapter.total_timeout_seconds == 5 and adapter.trust_env is adapter.follow_redirects is False


def test_total_deadline_cancels_hanging_fake_and_closes_client(monkeypatch):
    observations = fake_client(monkeypatch, hang=True)
    body, headers = arguments()
    with pytest.raises(DeliveryTransportError, match="delivery_total_deadline"):
        HttpxDeliveryTransport(EndpointGuard([URL])).send(URL, body, headers, timeout=0.01)
    assert observations["cancelled"] and observations["clients_closed"] == 1
    # __aenter__ did not finish: the stream context owns its cancellation cleanup;
    # no fake/background task remains after asyncio.run returned.


def test_adapter_refuses_running_loop_without_constructing_client(monkeypatch):
    observations = fake_client(monkeypatch)
    body, headers = arguments()

    async def probe():
        with pytest.raises(DeliveryTransportError, match="running_loop_unsupported"):
            HttpxDeliveryTransport(EndpointGuard([URL])).send(URL, body, headers)

    asyncio.run(probe())
    assert "settings" not in observations and observations["calls"] == []


def test_adapter_refuses_alias_and_authority_header_before_client(monkeypatch):
    observations = fake_client(monkeypatch)
    adapter = HttpxDeliveryTransport(EndpointGuard([URL]))
    body, headers = arguments()
    with pytest.raises(DeliveryTransportError, match="endpoint_refused"):
        adapter.send(URL + "?redirect=1", body, headers)
    with pytest.raises(DeliveryTransportError, match="headers_invalid"):
        adapter.send(URL, body, headers | {"Host": "other.invalid"})
    assert "settings" not in observations


def test_adapter_never_reflects_dependency_failure_text(monkeypatch):
    observations = fake_client(monkeypatch, fail=True)
    body, headers = arguments()
    with pytest.raises(DeliveryTransportError) as error:
        HttpxDeliveryTransport(EndpointGuard([URL])).send(URL, body, headers)
    assert str(error.value) == "delivery_transport_failed"
    assert observations["clients_closed"] == 1
