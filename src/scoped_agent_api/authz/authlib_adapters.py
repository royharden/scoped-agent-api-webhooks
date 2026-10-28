"""Authlib protocol bridge over M14's transactional Authority.

Activation is refused until the separately authorized bounded Authlib spike has
approved this adapter. No handwritten protocol fallback is selected. Authlib hook
signatures and extension behavior below are construction assumptions, not an
interoperability verdict. In particular, the spike must exercise required S256,
code resource binding, refresh reuse, and error response handling on the pinned
Authlib version before enabling the factory in a running application.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..host.policy import DomainError
from ..ports.clock import utc
from .authority import digest, scope_set


@dataclass(frozen=True)
class AuthorizationCode:
    """Read-only Authlib credential view; Authority owns the consume transaction."""

    code: str
    row: dict[str, Any]
    grant: dict[str, Any]

    def get_redirect_uri(self) -> str:
        return str(self.row["redirect_uri"])

    def get_scope(self) -> str:
        return str(self.grant["scopes"])

    def get_code_challenge(self) -> str:
        return str(self.row["challenge"])

    def get_code_challenge_method(self) -> str:
        return "S256"

    @property
    def code_challenge(self) -> str:
        return self.get_code_challenge()

    @property
    def code_challenge_method(self) -> str:
        return self.get_code_challenge_method()


@dataclass(frozen=True)
class RefreshCredential:
    """Used refresh credentials remain visible to the atomic reuse detector."""

    raw: str
    row: dict[str, Any]

    def get_scope(self) -> str:
        return str(self.row["scopes"])

    def check_client(self, client: Any) -> bool:
        return self.row["client_id"] == client.get_client_id()


class DeferredAdapter:
    def authorize_request(self) -> Any:
        raise DomainError("authlib_spike_pending", 503)

    def token_request(self) -> Any:
        raise DomainError("authlib_spike_pending", 503)


def build_adapter(app: Any, authority: Any) -> Any:
    """Wire Authlib only after explicit spike approval; never initialize storage."""
    if authority.settings.get("authlib_spike_approved") is not True:
        return DeferredAdapter()

    # Imports stay inside explicit activation so source inspection/factory import
    # neither requires installed Authlib nor silently chooses another AS basis.
    from authlib.common.urls import add_params_to_uri
    from authlib.integrations.flask_oauth2 import AuthorizationServer
    from authlib.oauth2.rfc6749 import grants
    from authlib.oauth2.rfc6749.errors import InvalidScopeError
    from authlib.oauth2.rfc7636 import CodeChallenge
    from flask import request

    class Client:
        def __init__(self, client_id: str, data: dict[str, Any]) -> None:
            self.client_id, self.data = client_id, data

        def get_client_id(self) -> str:
            return self.client_id

        def get_default_redirect_uri(self) -> str | None:
            redirects = self.data.get("redirect_uris", ())
            return str(redirects[0]) if len(redirects) == 1 else None

        def check_redirect_uri(self, redirect_uri: str) -> bool:
            return redirect_uri in self.data.get("redirect_uris", ())

        def check_client_secret(self, client_secret: str) -> bool:
            return False

        def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
            return endpoint == "token" and method == "none"

        def check_response_type(self, response_type: str) -> bool:
            return response_type == "code"

        def check_grant_type(self, grant_type: str) -> bool:
            return grant_type in {"authorization_code", "refresh_token"}

        def get_allowed_scope(self, scope: str) -> str:
            try:
                requested = scope_set(scope)
            except DomainError as exc:
                raise InvalidScopeError() from exc
            if (not requested <= frozenset(self.data.get("allowed_scopes", ()))
                    or (self.data["actor_kind"] == "agent" and "workorders:approve" in requested)):
                raise InvalidScopeError()
            # Never silently narrow consent or grant an agent human-only scope.
            return " ".join(sorted(requested))

    def query_client(client_id: str) -> Client | None:
        try:
            return Client(client_id, authority.client(client_id))
        except DomainError:
            return None

    def save_token(token: dict[str, Any], oauth_request: Any) -> None:
        # Every registered grant below overrides token creation and persists its
        # Authority-issued token atomically. An unexpected default Authlib path
        # must fail rather than emit an unpersisted bearer token.
        raise DomainError("unexpected_authlib_token_path", 503)

    server = AuthorizationServer(app, query_client=query_client, save_token=save_token)

    class CodeGrant(grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

        def generate_authorization_code(self) -> str:
            return authority.authorize_code(
                self.request.client.get_client_id(), self.request.redirect_uri,
                request.args["resource"], self.request.scope,
                request.args["code_challenge"], str(self.request.user),
            )

        def save_authorization_code(self, code: str, oauth_request: Any) -> None:
            # generate_authorization_code already persisted the 60-second code
            # and the exact consented grant in one Authority transaction.
            return None

        def query_authorization_code(self, code: str, client: Client) -> AuthorizationCode | None:
            with authority.store.transaction() as conn:
                row = conn.execute("SELECT * FROM oauth_codes WHERE digest=?", (digest(code),)).fetchone()
                now = utc(authority.clock.now())
                if (row is None or row["client_id"] != client.get_client_id()
                        or row["consumed_at"] is not None
                        or now >= datetime.fromisoformat(row["expires_at"])):
                    return None
                grant = authority._grant(conn, row["grant_id"], now)
                return AuthorizationCode(code, dict(row), dict(grant))

        def authenticate_user(self, authorization_code: AuthorizationCode) -> str:
            return str(authorization_code.grant["subject"])

        def delete_authorization_code(self, authorization_code: AuthorizationCode) -> None:
            # No deletion: Authority's CAS-consumed tombstone is the replay guard.
            return None

        def create_authorization_response(self, redirect_uri: str, grant_user: Any) -> Any:
            status, body, headers = super().create_authorization_response(redirect_uri, grant_user)
            # RFC9207: configured issuer is carried on the authorization response.
            result_headers = []
            for name, value in headers:
                if name.lower() == "location":
                    value = add_params_to_uri(value, [("iss", authority.issuer)])
                result_headers.append((name, value))
            return status, body, result_headers

        def create_token_response(self) -> Any:
            # Authlib has already parsed/authenticated/validated the grant and
            # run the required CodeChallenge extension. Authority repeats exact
            # redirect/resource/S256/expiry checks and consumes in one transaction.
            token = authority.exchange_code(
                request.form["code"], self.request.client.get_client_id(),
                request.form["redirect_uri"], request.form["resource"],
                request.form["code_verifier"],
            )
            return 200, token, [("Cache-Control", "no-store"), ("Pragma", "no-cache")]

    class RefreshGrant(grants.RefreshTokenGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

        def authenticate_refresh_token(self, refresh_token: str) -> RefreshCredential | None:
            with authority.store.transaction() as conn:
                row = conn.execute("SELECT t.*,g.client_id FROM oauth_tokens t "
                                   "JOIN oauth_grants g ON g.id=t.grant_id "
                                   "WHERE t.digest=? AND t.kind='refresh'",
                                   (digest(refresh_token),)).fetchone()
                # Do not filter used_at here: a reused token must reach Authority
                # so it revokes the family, grant and subscriptions before error.
                return None if row is None else RefreshCredential(refresh_token, dict(row))

        def authenticate_user(self, refresh_token: RefreshCredential) -> str | None:
            with authority.store.transaction() as conn:
                row = conn.execute("SELECT subject,client_id FROM oauth_grants WHERE id=?",
                                   (refresh_token.row["grant_id"],)).fetchone()
                if row is None or row["client_id"] != self.request.client.get_client_id():
                    return None
                return str(row["subject"])

        def revoke_old_credential(self, refresh_token: RefreshCredential) -> None:
            # Authority performs used_at + replacement token creation atomically.
            return None

        def create_token_response(self) -> Any:
            token = authority.refresh(
                request.form["refresh_token"], self.request.client.get_client_id(),
                request.form["resource"], request.form.get("scope"),
            )
            return 200, token, [("Cache-Control", "no-store"), ("Pragma", "no-cache")]

    server.register_grant(CodeGrant, [CodeChallenge(required=True)])
    server.register_grant(RefreshGrant)

    def exact_fields(values: Any, allowed: set[str], required: set[str]) -> None:
        if (values.keys() - allowed or required - values.keys()
                or any(len(values.getlist(key)) != 1 for key in values)):
            raise DomainError("invalid_request", 400)

    class Adapter:
        def authorize_request(self) -> Any:
            if request.method != "GET":
                raise DomainError("invalid_request", 400)
            required = {"response_type", "client_id", "redirect_uri", "scope", "resource", "state",
                        "code_challenge", "code_challenge_method", "consent_fixture_id"}
            exact_fields(request.args, required, required)
            if (request.args["response_type"] != "code"
                    or request.args["code_challenge_method"] != "S256"
                    or request.args["resource"] != authority.resource
                    or not 1 <= len(request.args["state"]) <= 512
                    or not 1 <= len(request.args["consent_fixture_id"]) <= 200):
                raise DomainError("invalid_request", 400)
            # Authlib validates client, exact redirect and requested scope before
            # Authority resolves the explicit server-owned mock consent fixture.
            return server.create_authorization_response(grant_user=request.args["consent_fixture_id"])

        def token_request(self) -> Any:
            if request.method != "POST" or request.mimetype != "application/x-www-form-urlencoded":
                raise DomainError("invalid_request", 400)
            if request.args or request.headers.get("Authorization"):
                raise DomainError("invalid_request", 400)
            grant_type = request.form.get("grant_type")
            if grant_type == "authorization_code":
                required = {"grant_type", "client_id", "code", "redirect_uri", "resource", "code_verifier"}
                exact_fields(request.form, required, required)
            elif grant_type == "refresh_token":
                required = {"grant_type", "client_id", "refresh_token", "resource"}
                exact_fields(request.form, required | {"scope"}, required)
            else:
                raise DomainError("unsupported_grant_type", 400)
            if request.form["resource"] != authority.resource:
                raise DomainError("invalid_request", 400)
            return server.create_token_response()

    return Adapter()
