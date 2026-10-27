# Human work-order UI — source construction

`register_ui(app, authority, commands, approvals, settings)` registers cookie-only
human forms beneath `/ui`. Every request resolves the opaque `m14_ui_session`
through authority's durable session store; authority must enforce the 15-minute
expiry and current underlying human grant. Mutations compare the session CSRF
token and enter the same `CommandService`/`ApprovalService` path with `surface=ui`.
No posted subject, scopes, client, grant or executor is accepted as authority.
Bearer headers and token parameters are refused. Templates use Jinja escaping;
responses are not cached, and forms contain no access or refresh tokens.

The verified first-party OAuth completion path calls `bind_verified_session` with
its already-verified human `PrincipalContext`. It sets only an opaque Secure,
HttpOnly, SameSite=Lax session cookie, scoped to `/ui`; the UI exposes no endpoint
that exchanges a posted principal or bearer for a session. Cookie Secure requires
the eventual fixture environment to supply a compatible secure browser context.
No OAuth runtime interoperability is claimed by this helper.

Routes: list/create at `/ui/` and `/ui/work-orders`; detail and draft/submitted
edits at `/ui/work-orders/<id>` and `/edit`; submit/close/cancel at matching action
paths. Submitted title fields are omitted. Challenge and approval forms use
`/challenge` and `/approve`. `/ui/approval-handoff` lets a human review identifiers
handed off by an agent or another requester. The resulting exact approval
statement is generated server-side. `/ui/approval-challenges/<id>/confirm` invokes
the human confirmation facade; its checks bind the real challenge executor,
requestor, grant, resource, statement, version and expiry. Capability consumption
is a distinct approve command, never an agent command. Every mutation form carries
a fresh idempotency key, preserved by the browser on request retry.

Sign-out deletes this browser cookie only; it does not claim to revoke the grant
or other sessions. Authority-owned session expiration remains authoritative.

Deferred: rendered Flask/Jinja forms, browser cookie/session expiry and grant
revocation, CSRF/malformed/duplicate fields, escaped attacker text, all successful
and denied operations, human handoff and capability races/restart/staleness,
API/CLI/UI parity, OAuth callback integration, strict typing/lint and packaging.
No application, server, test, network or template renderer was executed in Dirty
Mode. Static Python AST parse and manual path/authority inspection are the checks.

## First-party human OAuth completion

`register_oauth_login(app, authority, settings)` adds `/ui/oauth/start` and
`/ui/oauth/callback`. Its separate opaque `m14_ui_login` cookie is Secure,
HttpOnly, SameSite=Lax, scoped to `/ui/oauth`, and expires after five minutes.
`begin_ui_login(client_id, redirect_uri, scopes)` owns durable login ID/state/
S256-verifier storage. Start uses only configured `issuer`, `resource`,
`first_party_client_id`, exact registered `ui_redirect_uri`, and `ui_scopes`.
Optional `fixture_consent_id` is sent as the fixture `consent_fixture_id` parameter.
The browser cannot select authority, redirect URI, client, scopes or resource.

Callback checks exact configured `iss`, requires the secret login cookie plus
returned state, rejects unknown/duplicate/token parameters, and delegates the
one-use five-minute login-row validation and code exchange to
`finish_ui_login(login_id, state, issuer, code, transport)`. The injected
`settings['oauth_token_transport'](url, form) -> dict` is required and remains
unexecuted during construction. Authority must authenticate the exchanged access
credential and return its current human principal. Only then does the callback
create the durable UI session through `bind_verified_session`; no access or refresh
credential appears in HTML or response URLs. The temporary login cookie is cleared
on callback success or failure. Errors expose fixed codes only; OAuth endpoints
are no-store and suppress referrers.

Deferred OAuth checks: durable login-state consumption/replay/expiry, S256 verifier
and exact redirect/resource binding, wrong issuer/state/missing cookie, token
exchange transport failures and malicious returned credentials, human-only session
creation, and end-to-end authorization server interoperability. No network or
application execution was performed.
