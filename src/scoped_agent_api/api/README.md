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
