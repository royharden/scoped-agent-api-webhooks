"""Exact fixture-loopback endpoint admission without DNS resolution."""

import re
from collections.abc import Iterable
from urllib.parse import urlsplit


_ENDPOINT = re.compile(
    r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/hooks/([A-Za-z0-9_-]+)\Z"
)


class EndpointGuard:
    """Only launch-created literal URLs may reach an injected transport.

    The transport must disable environment proxies and redirects. This mock's
    plain loopback HTTP is an explicit fixture exception, not production TLS.
    """

    def __init__(self, allowed_endpoints: Iterable[str]) -> None:
        allowed = frozenset(allowed_endpoints)
        if not allowed:
            raise ValueError("endpoint_allowlist_required")
        for endpoint in allowed:
            self._validate_shape(endpoint)
        self.allowed_endpoints = allowed

    @staticmethod
    def _validate_shape(endpoint: str) -> None:
        if not isinstance(endpoint, str):
            raise ValueError("endpoint_refused")
        match = _ENDPOINT.fullmatch(endpoint)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("endpoint_refused")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("endpoint_refused")

    def validate(self, endpoint: str) -> str:
        self._validate_shape(endpoint)
        if endpoint not in self.allowed_endpoints:
            raise ValueError("endpoint_not_allowlisted")
        return endpoint
