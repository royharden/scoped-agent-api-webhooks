# Host integration seam

Construction source only; no runtime check has run. Initialize `Store(path)` explicitly
using `initialize()`, then install the AS's uncached validator with
`store.set_principal_validator(callback)`. Callback signature is
`(sqlite3.Connection, PrincipalContext, aware_utc_now) -> PrincipalContext`; it must
check current token/grant/family activity, expiry, issuer, configured resource and
scopes from authoritative rows, raising `DomainError` on denial. It runs inside
the command transaction before authorization and idempotent recovery. A missing
callback fails closed with `authentication_unavailable` (503). Do not replace it
with an identity callback in an application. The context deliberately contains
no bearer token; API authentication must validate token transport/lifetime too.

`CommandService(store,clock).execute(action,principal,arguments,idempotency_key,
surface='api')` returns a snapshot dictionary with `effect_ref` for mutations,
the snapshot for get, or `{items,limit,offset}` for list. Reads accept `None` as
the idempotency key. Every other operation requires a key. Supported actions:
create/edit/submit/approve/close/cancel/get/list/challenge/confirm. No caller can
supply a principal, resource, executor or scope through command arguments.
Scope names are nonhierarchical. UI agent use is refused. Surface attribution
must be selected by authenticated adapters, never a posted client field.

`host.approvals.ApprovalService(store,clock)` delegates to the same commands:
`challenge(principal,order_id,key,surface='api')` and
`confirm(principal,challenge_id,statement,key,confirmed=bool,surface='api')`.
Adapters must pass explicit human confirmation; the facade never invents it.

Challenge: arguments `{id: order_id}`, read scope. Executor is configured by the
server (fixture default `appr.sam`). Returns challenge `id`, `statement`, bound
`resource_version`, executor and expiry. Confirm: human approve scope, arguments
`{id: challenge_id, confirmed:true, statement: exact_returned_statement}`; returns
`capability_id`. Approve: `{id,expected_version,capability_id,statement?}`; omitted
statement uses the fixed human approval statement. Capability binds original
requestor/grant, human approver and consuming subject/client/grant/resource,
action/order/version/statement, random nonce and five-minute expiry. Challenge
and confirmation make no domain audit/event; consume and order mutation share
one transaction. Capability ID is the opaque lookup handle; nonce remains durable
server state. A current-version approval with an older capability is stale even
with unchanged statement. Same-key replay returns its saved result before consume.

DL3 outbox producer contract: immutable `domain_events(id,event_type,resource_id,
resource_version,occurred_at,body BLOB,body_sha256)` inserted with each mutation,
one audit and event per version. `body` is the exact canonical full snapshot
`m14.event.v1`; `id` is the stable webhook ID. Delivery rows are DL3-owned and may
reference these rows. Do not UPDATE events to track delivery. Outbox scanning
must durably enqueue each event/subscription exactly once; the domain transaction
is the durable source of truth even if process wakeup is lost. Subscription
eligibility timing and replay reconciliation remain DL3-owned.

Idempotency namespace `(subject,grant_id,action,key)`, surface excluded. Request
digest covers the exact accepted arguments. Successful response retention eight
days. `expire_results(conn, now)` removes bodies and preserves workspace-lifetime
used-key tombstones; expired keys refuse mutation. Current auth always runs
before recovery. Failed commands roll back capability/domain/audit/event/result
writes. Deterministic execution denials are saved after rolling back a savepoint,
so same-body retries recover the original denial. Authentication/authorization
and idempotency-lookup errors remain current decisions and are never cached.

Canonical encoder supports the integer/string JSON subset used here, orders
keys by UTF-16 code units, rejects surrogates and floats and restricts integers
to the interoperable range. General RFC 8785 number serialization is deferred;
no claim of full arbitrary-number JCS support. Namespace packaging and migration
SQL wheel inclusion need packaging verification by INT.

Deferred: syntax/type/lint beyond available tools, state sequences, rollback and
CAS races, revoked replay, retention/tombstone restart, capability double-consume,
stale/wrong binding/expiry, schema initialization/WAL behavior and packaging,
AS current-principal wiring, DL3 enqueue integration and all API/UI journeys.
