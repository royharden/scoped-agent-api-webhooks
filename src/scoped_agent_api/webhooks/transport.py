"""Future HTTP adapter: exact loopback egress and one cancellable total deadline.

Nothing opens a socket or constructs a client on import or construction. Actual
timing/cancellation behavior needs runtime validation after Dirty Mode closes.
"""

import asyncio
from collections.abc import Mapping
from math import isfinite
from time import monotonic
from typing import ClassVar, Literal

from .endpoint_guard import EndpointGuard
from .envelope import MAX_BODY
from .worker import TransportResponse

_SIGNATURE_HEADERS = frozenset({"webhook-id", "webhook-timestamp", "webhook-signature"})


class DeliveryTransportError(RuntimeError):
    """Fixed diagnostic codes only; never wraps a URL, payload or signature."""


class HttpxDeliveryTransport:
    """Synchronous worker bridge over a per-send asynchronous HTTPX client.

    This bridge explicitly refuses an already-running event loop on the calling
    thread. It never spawns a timeout thread or leaves a background send running.
    asyncio.timeout covers connection, headers, request bytes, response headers
    and resource cleanup as one operation, rather than five seconds per phase.
    Cancellation cannot recall bytes already transmitted. Cooperative dependency
    cleanup and actual wall-clock bounds remain unverified until runtime checks.
    """

    # Composition admission checks inspect these configuration declarations.
    # They describe enforced source settings, never measured timing evidence.
    follow_redirects: ClassVar[Literal[False]] = False
    trust_env: ClassVar[Literal[False]] = False
    total_timeout_seconds: ClassVar[float] = 5.0

    def __init__(self, endpoint_guard: EndpointGuard) -> None:
        self.endpoint_guard = endpoint_guard

    @staticmethod
    def _inputs(body: bytes, headers: Mapping[str, str], timeout: float) -> float:
        if not isinstance(body, bytes) or len(body) > MAX_BODY:
            raise DeliveryTransportError("delivery_body_invalid")
        if type(timeout) not in {int, float} or not isfinite(timeout) or not 0 < timeout <= 5:
            raise DeliveryTransportError("delivery_deadline_invalid")
        # Refuse Host/authority/proxy headers and ambiguous repeated variants.
        # The signer supplies exactly these three headers; retain their names
        # and values unchanged rather than regenerating signatures or JSON.
        names = []
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise DeliveryTransportError("delivery_headers_invalid")
            if any(ord(char) < 32 or ord(char) > 126 for char in value):
                raise DeliveryTransportError("delivery_headers_invalid")
            names.append(name.lower())
        if len(names) != 3 or frozenset(names) != _SIGNATURE_HEADERS:
            raise DeliveryTransportError("delivery_headers_invalid")
        return float(timeout)

    def send(self, endpoint: str, body: bytes, headers: Mapping[str, str], *,
             timeout: float = 5.0) -> TransportResponse:
        try:
            self.endpoint_guard.validate(endpoint)
        except ValueError:
            raise DeliveryTransportError("delivery_endpoint_refused") from None
        duration = self._inputs(body, headers, timeout)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            # Do this before creating a coroutine: no unawaited object and no
            # nested event-loop workaround when called from an async context.
            raise DeliveryTransportError("delivery_running_loop_unsupported")
        try:
            deadline = monotonic() + duration
            return asyncio.run(self._send(endpoint, body, dict(headers), deadline))
        except TimeoutError:
            raise DeliveryTransportError("delivery_total_deadline") from None
        except DeliveryTransportError:
            raise
        except Exception:
            # Never preserve HTTPX exception text or request/response objects.
            raise DeliveryTransportError("delivery_transport_failed") from None

    async def _send(self, endpoint: str, body: bytes, headers: Mapping[str, str],
                    deadline: float) -> TransportResponse:
        # Dependency import is deferred until explicitly invoked, not imported
        # for syntax checks or object construction in source-only workflows.
        import httpx

        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError
        async with asyncio.timeout(remaining):
            self.endpoint_guard.validate(endpoint)
            async with httpx.AsyncClient(
                    trust_env=False, follow_redirects=False, timeout=None,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)) as client:
                # Stream only through response headers; arbitrary response bodies
                # are neither buffered nor parsed. Contexts close both objects
                # on success, timeout, error and cancellation. Redirect status
                # is returned unchanged for the worker's explicit failure path.
                async with client.stream("POST", endpoint, content=body, headers=headers,
                                         follow_redirects=False) as response:
                    return TransportResponse(status=response.status_code,
                                             headers=dict(response.headers))
