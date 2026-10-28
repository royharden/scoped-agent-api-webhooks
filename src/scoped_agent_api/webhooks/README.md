# Webhook construction interfaces

Source construction only. No runtime, network, database, race, security or
interoperability check has run. This is a single-process fictional fixture host;
the locks do not provide distributed fencing or exactly-once transport.

Explicit initialization after `Store.initialize()`:
`with store.transaction() as conn: webhooks.schema.initialize(conn)`.
The delivery schema references host-owned immutable `domain_events`;
`outbox.enqueue(conn, aware_utc_now, limit=100)` durably discovers missing
event/subscription pairs. Domain mutations persist the source event in their
own transaction, so a lost wake hint does not lose work. Subscription creation
defines the start of eligibility; new subscriptions do not backfill older events.
The event timestamp is host ISO UTC text; delivery timestamps are epoch seconds.
`UNIQUE(event_id, subscription_id)` is the durable enqueue guard. Replay updates
that delivery row, preserving source ID/body and retaining all attempt/audit rows.

`SubscriptionService(store, clock, endpoint_guard, grant_validator)` provides
`create(principal, endpoint, event_types)`, `get(principal,id)`, `list(principal)`,
`set_enabled(principal,id,bool)` and fixture `rotate(principal,id)`. All mutations
require keyword `idempotency_key`. Creation and rotation return a disposable
signing key to the creator (and same-key recovery). Lists, audits and delivery views
exclude signing keys. These keys are application-generated fixture material;
there are no provisioned credentials or external accounts.
Each operation calls `store.current_principal` within its transaction and
requires read+manage; row ownership is original subject+grant. Suspended
subscriptions cannot be rebound by re-grant. `DeliveryService(subscriptions)`
provides get/list/replay and `recover(principal,since,limit<=100)`. Replay
requires original live grant/family/subscription, event age <=7 days and no
in-progress delivery. API adapters own bearer transport, route input validation
and passing the actual Idempotency-Key header. Service management mutations
acquire the shared grant lock and one Store transaction, read the clock after
both locks, revalidate current authority before idempotency lookup, mutate, audit
and save the response in that SAME transaction. The namespace is subject/grant/
action/key; canonical request digest detects changed bodies. Results expire at8d,
then used-key tombstones permanently refuse another mutation.
`management.expire_results(conn,now)` removes saved response bodies only.

The authoritative injected `grant_validator(grant_id, required_scopes)->bool`
checks current grant/family activity, expiry and scopes without cached success.
It runs outside the SQLite writer transaction, while the process-owned grant
lock remains held. No permissive default exists. It must use the same clock as
the rest of the fixture. Access-token expiry alone does not expire callbacks.

DL2 revocation must acquire `webhooks.locks.GRANT_LOCKS.hold(grant_id)`, then
begin its Store transaction, invalidate grant/tokens/family and call
`webhooks.subscriptions.suspend_grant(conn, grant_id, now)` in that transaction.
The cascade suspends only subscriptions on that grant, cancels pending work and
audits changes, without committing independently. Revoke returns after the lock
is released. The worker uses the SAME registry and holds it through send and
result recording. Already-sent bytes can arrive after revocation returns.

`DeliveryWorker(store,clock,transport,endpoint_guard,grant_validator,retry_policy)`
additionally requires keyword
`grant_validator_in_transaction(conn,grant_id,required_scopes,now)->bool`.
This callback uses the caller's existing connection, never opens another writer
or commits. After SQLite writer acquisition the worker reads a fresh clock and
validates current grant/family/scopes before recording `attempt_started`; this
closes the writer-wait expiry gap. The outside-writer validator and clock are
checked again after the send barrier immediately before sending, with a fresh
signature timestamp/key overlap decision. Callback ownership is the authority
adapter; the two callbacks are distinct and neither has a permissive default.
The worker uses `run_due(now,limit<=100)`; startup-only `recover_inflight()` changes unknown
send results back to pending while preserving attempt count. Startup recovery
must precede any worker, never race another dispatcher. Due rows are durable;
there are no sleeps, timer threads or required wake queues. A crash after send
can produce a duplicate with the same event ID/body. Ten total attempts include
the initial immediate send; the following nine delays are 5s through24h with
seeded jitter. Ordinary automatic work expires at original event+96h. Explicit
replay sequences expire at original event+7d, with a new bounded attempt count.
Retry-After seconds/HTTP-date clamps to24h; malformed input has a named code.
Only2xx succeeds,3xx is never followed,410 disables/cancels;429/502/504 apply
endpoint-wide cooldown. Replay re-signs stable bytes using the current clock.

Only exact launch-created `http://127.0.0.1:<port>/hooks/<receiver-id>` endpoints
pass `EndpointGuard`; no listener is started here. The injected transport MUST
disable proxies/environment trust and redirects and enforce a five-second total
deadline. Phase-only HTTP timeouts are insufficient. Construction defines that
adapter requirement; it does not prove or implement an external HTTP runtime.

Raw signing uses Standard Webhooks v1 HMAC over `id.timestamp.body`. Verification
checks signature and +/-300s before parsing, and caller-supplied keyrings are
never updated from payloads. Rotation emits old+new for one hour, then new-only;
another rotation during overlap is refused so an old key is not retired early.
Bodies are bounded to32KiB, snapshots bind resource ID/version, duplicate JSON
keys are refused. `receivers.ReferenceReceiver` commits its durable inbox before
ACK and processes each row atomically, applying only increasing resource
versions. Dedupe rows expire after8d only if processed; lifetime versions and
counters remain. Verify-only applies each verified arrival. The deliberately
unsafe repository-root `demo_insecure` arm is not imported by production modules
and lies outside the product wheel's `src/scoped_agent_api` allowlist.

Deferred activation checks: host/auth schema initialization; HTTP management
key forwarding, atomic idempotency recovery and error mapping; uncached validator wiring and same-lock revoke
cascade; total-deadline/proxy/redirect/SSRF adapter behavior; external wall-time
Standard Webhooks verifier and tamper negatives; retry/jitter/cooldown/rotation/
replay/tolerance boundaries; restart and every crash point; duplicate/conflict/
stale counters; receiver pruning and lifetime versions; installed-wheel demo
exclusion; typing/lint and all runtime tests. Independent oracle, blind studies
and license admission remain pending under their separate owners.

## Joined construction recipe (not executed)

The following is a source-level composition recipe for a later authorized
activation. It has not been run and starts no listener in the example. DL2's
current `Authority` source supplies both worker callbacks with the exact
signatures shown. Its outside-writer method reads time after writer acquisition;
its transaction-aware method reads only the supplied connection. Keep the same
Store, clock, configured issuer/resource and grant-lock singleton throughout.
Do not install a second Authority instance as the Store principal validator:
the resource-server factory binds the request's proof to its own instance.

```python
from random import Random

from scoped_agent_api.api.app import create_app as create_resource_app
from scoped_agent_api.authz.app import create_app as create_authorization_app
from scoped_agent_api.webhooks.locks import GRANT_LOCKS
from scoped_agent_api.webhooks.outbox import DeliveryService, enqueue
from scoped_agent_api.webhooks.retry_policy import RetryPolicy
from scoped_agent_api.webhooks.schema import initialize as initialize_webhooks
from scoped_agent_api.webhooks.subscriptions import SubscriptionService
from scoped_agent_api.webhooks.worker import DeliveryWorker


def compose_fixture(store, clock, settings, endpoint_guard, transport):
    # Inputs are explicit fixture objects; no credential or environment loading.
    # Leave Authlib spike activation false until the required future spike passes.
    config = dict(settings)
    config["endpoint_guard"] = endpoint_guard
    # Use the factory's own management builder so request-local authority proof
    # and Store.current_principal are tied to the same Authority instance.
    if config.get("webhooks_service") is not None:
        raise ValueError("this recipe requires the factory-owned management facade")
    resource_app = create_resource_app(store, clock, config)
    authority = resource_app.extensions["m14"]["authority"]
    authorization_app = create_authorization_app(store, clock, config)

    # Explicit lifecycle work, not an import/factory side effect. These calls are
    # deferred under Dirty Mode; host must exist before either owner migration.
    store.initialize()
    authority.initialize()
    with store.transaction() as conn:
        initialize_webhooks(conn)

    subscriptions = SubscriptionService(
        store, clock, endpoint_guard, authority.grant_is_active)
    deliveries = DeliveryService(subscriptions)
    worker = DeliveryWorker(
        store, clock, transport, endpoint_guard,
        authority.grant_is_active, RetryPolicy(Random(1414)),
        grant_validator_in_transaction=authority.grant_validator_in_transaction,
        grant_locks=GRANT_LOCKS)
    # Startup-only, before any dispatcher starts. Never race a live worker.
    worker.recover_inflight()
    return resource_app, authorization_app, subscriptions, deliveries, worker


def dispatch_tick(store, clock, worker):
    # Source events are already committed with the domain mutation. A lost wake
    # is harmless: scanning derives missing delivery pairs from durable rows.
    with store.transaction() as conn:
        queued = enqueue(conn, clock.now(), limit=100)
    started = worker.run_due(clock.now(), limit=100)
    return queued, started
```

Factories return objects only; a future lifecycle runner must create the
disposable database/fixture settings, exact claimed loopback endpoint allowlist,
bounded transport adapter and receiver stores, then orchestrate startup, ticks,
faults, recovery and shutdown. No listener, timer or loop is supplied by this
recipe. Repeat bounded ticks while work remains; do not assume a single100-row
enqueue covers a larger backlog. Direct management calls require an actual
request-local bearer/session proof established by this SAME resource Authority;
passing a hand-built PrincipalContext to these objects does not authorize it.
Receiver stores initialize separately using `ReceiverStore(path).initialize()`;
reference receipt and inbox processing remain distinct lifecycle steps.

Composition ownership: DL2 owns API factory/Authority/HTTP facade and its two
grant callbacks; DL1 owns Store/domain event production; DL3 owns the exact
worker/service/schema/scan contract above. The executable fixture lifecycle is
assigned to DL2 by INT; source for the actual transport adapter and receiver HTTP
factory is now provided below. Actual activation remains deferred. This document
does not claim that an HTTP factory itself starts delivery, applies migrations,
seeds grants or runs the receiver inbox. All joined behavior remains unverified.

## Actual HTTP adapter source (not exercised)

`webhooks.transport.HttpxDeliveryTransport(endpoint_guard)` implements the
worker's synchronous `send(endpoint,body,headers,timeout=5.0)->TransportResponse`.
Construction stores configuration only; it does not create a client, app,
listener or request. Inject this object as the `transport` in the recipe above.
Composition configuration declarations are `follow_redirects=False`,
`trust_env=False` and `total_timeout_seconds=5.0`; these describe the source's
fixed controls and maximum budget, not measured deadline proof. An individual
send may request a shorter positive timeout but cannot request more than5s.
Only exact launch-created EndpointGuard URLs pass both admission and dispatch;
no DNS names, alternate addresses, redirects or environment proxy trust are
accepted. Only the signer's three unambiguous webhook headers are accepted and
passed unchanged with the immutable raw body. Header authority overrides are
refused. HTTPX streams through response headers without buffering response
bodies; actual statuses, including3xx, return unchanged to the worker.

Each explicit send uses one fresh async HTTPX client with `trust_env=False`,
`follow_redirects=False`, phase timeout disabled and a single `asyncio.timeout`
covering the remaining TOTAL operation budget. A monotonic deadline is anchored
before the synchronous `asyncio.run` bridge; setup/import elapsed time is deducted
before network work. Deadline exhaustion raises a fixed diagnostic, never a
fabricated status. Client/response async contexts close on success/error/timeout.
No detached timeout thread or background send is used. A running event loop on
the caller thread is explicitly unsupported and refused before a coroutine is
created; a synchronous worker must be invoked from a synchronous caller.

Cancellation and cleanup are cooperative dependency behavior, not a measured
hard real-time bound. Source requests a total maximum of5s, but actual elapsed
time, dependency cancellation/cleanup and event-loop shutdown require runtime
proof. Blocking import/setup cannot be preempted; if it consumes the deadline,
the adapter refuses all network work. Bytes already transmitted before timeout
cannot be recalled and may arrive after cancellation/revoke. Fixed failure codes
contain no URL, event body, signing header or dependency exception text. No
HTTPX client, request, timing check or cancellation experiment has been executed.

Receiver source: `receivers.http.create_receiver_app(receiver_id,receiver,clock)`
wraps an existing ReferenceReceiver or VerifyOnlyReceiver at its configured
hook path. See receivers/README.md for raw bounds, neutral error mapping and
explicit initialization/processing/recovery lifecycle. The factory neither
initializes an inbox nor starts listeners or processes rows; reference ACK still
follows the existing committed inbox insertion. Its injected clock preserves the
virtual fixture epoch. Root demo_insecure remains outside this product factory.
