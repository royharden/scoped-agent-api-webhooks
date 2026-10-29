# Resource server construction

`create_app(store, clock, settings)` is explicit. It never creates a database, runs
migrations, starts a listener or contacts an authority. `issuer` and `resource` are
required configured absolute URLs; challenges and discovery never use Host headers.
The authority's uncached validator is installed on the host Store so every command
checks current authority inside its transaction before idempotent response lookup.

All `/v1` operations require an Authorization bearer header. Query/form token fields
are refused and a cookie alone cannot authenticate. Mutations require JSON objects
and `Idempotency-Key`. Item route IDs come from the path; posted identity, grant,
scope, resource or item-ID overrides are rejected. Approval challenge input is
`{id: <order-id>}`; confirmation is `{confirmed: true, statement: <exact-statement>}`.
Approve consumes `capability_id` with the current `expected_version` through host
CommandService. List pagination is bounded to 100 items.

`X-M14-Surface: api|cli` selects stored transport attribution only; it never changes
authentication or operation policy. Default is `api`; the CLI must send `cli`.
Human UI uses its own session/CSRF adapter and invokes the same command facade.
This header is a self-declared transport label, not authenticated proof of a CLI
process. Actual surface provenance needs the future invocation observer; no
verified parity/attribution claim follows from the header or stored label alone.

Webhook management uses a provisional injected `settings['webhooks_service']`
object: `execute(action, principal, arguments, idempotency_key, surface='api')`.
Actions are `subscriptions.create/list/get/disable/enable` and
`deliveries.list/get/replay/recover`. Both read and manage scopes are required.
The service must revalidate current authority and idempotency inside its effect
transaction. An absent adapter fails 503; no fabricated management success is used.
Recovery is exposed at `/v1/deliveries/recover` and `/recover`, bounded to 100.
`api.webhooks_adapter.WebhookManagement` maps routes to DL3 SubscriptionService
and DeliveryService methods with keyword `idempotency_key`; DL3 owns each effect,
current-authority check and saved response in one writer transaction. Configure
`endpoint_guard` to build this facade with Authority.grant_is_active, or inject
an already-composed `webhooks_service`. Never use a route-level SQL precheck.
Recover accepts optional timezone-aware ISO `since`; omitted since maps to a
fixed epoch while the service clips event age to seven days, keeping replay
request digests stable. Management lists currently refuse nonzero offsets because
DL3 lists only the first 100 rows; arbitrary pagination is not yet supplied.

This is source construction only. Flask route registration, HTTP requests, OAuth
interoperability, UI rendering, metadata URL deployment mapping, concurrent revoke,
management adapter reconciliation, installed CLI attribution, response challenges
and strict type/lint checks remain runtime/tooling validation work. No tests or
application imports were run for this package.

## Explicit future fixture composition

`api.composition.compose_fixture(store, clock, settings, *, allowed_endpoints,
transport, retry_seed)` constructs separate AS/resource Flask apps, exposes the
resource proof Authority and exact HTTP management service, and constructs a
DeliveryWorker with both bound authority callbacks and DL3's single GRANT_LOCKS.
No module import or factory call initializes a DB, sends requests, starts a
listener/thread/browser, or dispatches a delivery. No default ports are selected.
Future listeners must separately follow agent-ports during authorized activation.

Caller supplies existing Store/Clock and settings from authz README: exact
issuer/resource, preregistered clients/first-party human redirect, explicit UI
scopes, trusted fictional consent resolver and in-memory token transport. No
prebuilt webhooks_service is accepted here, since it might reference a different
Store or proof Authority. Both AS/resource Authority objects use the same Store,
clock and settings; Store.current_principal is wired only to the RESOURCE
Authority, exposed as `components.authority`. The AS Authority owns issuance;
it never replaces that request-proof validator. Authlib gate defaults false.

Webhook transport must expose `follow_redirects=False`, `trust_env=False`,
`total_timeout_seconds` in (0,5], and `send(endpoint,body,headers,*,timeout)`.
The composition guard rejects missing/permissive declarations, revalidates exact
allowlisted loopback endpoints before send and clamps the supplied timeout to
the declared total bound. These declarations are an injected-adapter contract;
an arbitrary implementation still requires later deadline/redirect/proxy runtime
validation. No default network client is created. The UI token transport remains
a separate trusted configured endpoint-only callable as specified in authz README.

Explicit lifecycle, for a later authorized owner (not executed here):

1. `components.initialize()` calls Store.initialize (host-owned transaction),
   Authority.initialize (separate authz-owned transaction), then webhook schema
   initialize inside a third Store.transaction. No global atomic-schema claim;
   failures propagate and startup is unready until all schemas complete.
   Retry after a failed first initialization is explicit; a second initialization
   after success is refused before doing any schema work. There is no stale-ready
   flag from a partially attempted reinitialization.
2. `components.recover_startup()` invokes recover_inflight explicitly once before
   dispatch. Caller owns exclusive fixture lifecycle/one worker for this Store;
   never run recovery concurrently with any other existing worker/process.
3. `components.dispatch_due(limit<=100)` discovers missing durable event pairs
   and makes one bounded worker tick. A lifecycle mutex serializes these wrapper
   methods; there is no scheduler. Returned raw worker/app references are for the
   future owner and must not bypass the startup/exclusive-ownership contract.

Client integration belongs to DL4: inject its OAuth controller/session factory
with a public HTTP transport targeting these configured AS/resource addresses.
Client bearer callbacks must NOT call Authority.authenticate/current_principal
directly or query SQLite: all client operations remain public HTTP. Explicit
fixture consent selects an existing trusted fictional ID; never accept posted
subject/grant/scopes as authentication. No composition source manufactures a
successful OAuth exchange or toggles the Authlib gate.
`components.authenticated_session_factory(controller_factory=...,
resource_transport=...,initial_scopes=frozenset(...))` now returns DL4's actual
AuthenticatedSessionFactory. This construction performs no login/HTTP. On a
future explicit factory call it checks the returned OAuthController against the
joined issuer/resource, registered client actor/redirect/scope envelope, then
DL4 performs its real fixture OAuth login. CLI user maps human and tasks map
agent in the owner factory. No direct bearer, Authority or database shortcut.

There is not yet a complete keyless launcher: original trusted consent/client/
fictional subject registry, bounded webhook/token/public-HTTP transport adapters,
receiver startup and receiver schema lifecycle, and secure UI fixture hosting
remain caller-owned activation inputs. Existing developer tasks and M20 stub are
not executed host results. No joined runtime/demo readiness is claimed. Deferred:
three-schema activation/failure/restart, template/schema package data, real AS/
resource mounts, Authlib spike, two-callback worker/revoke/expiry races, transport
restrictions, startup exclusivity and DL4 client/controller joined behavior.
