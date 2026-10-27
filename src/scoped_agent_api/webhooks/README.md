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
