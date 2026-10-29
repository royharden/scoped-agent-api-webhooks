# Mock authorization and integration

Source construction only. No runtime or Authlib interoperability result is claimed.
Two distinct Flask factories share a configured `Store` and clock:
`authz.app.create_app(store, clock, settings)` is the AS; `api.app.create_app`
is the resource server and human UI. Neither factory migrates or listens.
Activate `Store.initialize()` and `Authority.initialize()` explicitly in a later
authorized runtime phase, along with DL3's webhook schema. No public introspection.

`settings` contains exact `issuer`, `resource`, preregistered `clients` mapping
client IDs to `actor_kind`, exact `redirect_uris` and explicit `allowed_scopes`.
`consent_resolver(fixture_id, client_id, requested_scopes, resource)` is a trusted,
fixture-only callable returning `{allowed: bool, subject: str}`. It must use
preauthorized fictional fixture consent; posted principal, grant or scopes never
establish identity. Agent approval scope is rejected even if misconfigured as an
allowed scope. The mock is not production identity authentication.

The Authlib adapter contains public-client, authorization-code, required S256 and
refresh grant source. `/authorize` and `/token` fail 503 by default until the
bounded runtime spike validates hooks, resource binding and refresh cascade.
`authlib_spike_approved=True` is a later operator activation input, never inferred
from source existence. There is no alternate AS fallback or claimed spike pass.
Dependency/source/license pins, independent client checks and rights stay pending.

Authority persists only digests for access/refresh/code/session handles. PKCE login
verifiers and CSRF secrets remain in the private fixture database. Code lifetime
60 seconds, access 5 minutes, grants/families 24 hours, sessions 15 minutes,
login state 5 minutes. Explicit fixture `grant_lifetime_seconds` can extend
grants/families up to eight days plus one hour for long replay scenarios. Result
objects containing OAuth tokens must never be logged or rendered.

`authenticate(token)` and `resolve_ui_session(cookie)` install a request-local
proof; `validate_principal(conn, principal, now)` rechecks that exact proof inside
the host command transaction. It validates token/session expiry, grant, issuer,
resource and scope equality before idempotency lookup. Context objects alone
cannot authorize commands. UI session scopes preserve the authenticated token's
scope set without widening to the grant's set. Request teardown clears proof.

Revocation and refresh reuse use exactly DL3 `GRANT_LOCKS.hold(grant_id)` and
`suspend_grant(conn, grant_id, now)`, in the same transaction as grant/family/token/
session invalidation and security audit. Missing DL3 integration fails 503;
there is no local substitute lock or silent skipped cascade. A reused refresh
token commits revocation before emitting the protocol error. Already-sent bytes
may arrive later; no distributed fencing claim. `grant_is_active(grant_id,scopes)`
is DL3's uncached dispatch check and deliberately ignores access-token expiry.
For the worker's last check after acquiring the SQLite writer, supply
`authority.grant_validator_in_transaction(conn, grant_id, required_scopes, now)`
to the identically named DeliveryWorker constructor keyword. It uses only that
connection and the worker's current aware UTC; it never opens a nested writer,
locks, commits, or consults HTTP request proof. Keep `authority.grant_is_active`
for the separate outside-writer eligibility and immediately-before-send checks.

UI configuration: `first_party_client_id`, `ui_redirect_uri`, explicit `ui_scopes`,
`fixture_consent_id`, and injected `oauth_token_transport(url, form)->dict`.
The future transport must be bounded, contact only the supplied configured issuer
endpoint, refuse redirects, avoid logs, and return parsed OAuth JSON. Callback
requires issuer, one-use state and its browser login cookie, then creates a human
session from the verified returned token. Secure cookies require an appropriate
fixture HTTPS/browser arrangement in later validation; no insecure-cookie mode
is silently enabled.

Deferred: Authlib bounded spike/signatures/extension ordering; code and refresh
races; independent PKCE/refresh/RFC7009 client; DB restart/rollback; UI session
expiry/revocation/CSRF and rendered forms; API/CLI/UI parity; webhook cascade and
dispatch race; HTTP management facade; installation, package-data inclusion,
strict lint/types, full runtime tests and independent evaluation. P2 admission,
rights, held-out custody, pre-code provenance and GO remain pending with Roy.
