# Receiver HTTP source

`receivers.http.create_receiver_app(receiver_id, receiver, clock)` returns a Flask
application around an existing `ReferenceReceiver` or `VerifyOnlyReceiver` and
the caller's injected UTC clock. The only registered operation is POST on the
exact configured `/hooks/<receiver_id>` path; IDs contain only ASCII letters,
digits, `_` and `-`. Query strings and raw request-target aliases are refused
when the WSGI server exposes the raw target. Fragments are not sent over HTTP.

The caller explicitly initializes `ReceiverStore(path)` before use. This factory
does not migrate, create a store, listen, construct secrets or schedule work.
For the reference arm, `receiver.process_pending(clock.now(), limit=100)` and
`receiver.store.prune(clock.now())` remain separate caller-owned lifecycle steps.
Startup/restart opens the same caller-selected durable store; there is no second
inbox or permanent dedupe guard in the HTTP layer.

The handler caps bodies at32KiB using Flask's maximum length and a bounded raw
stream read. It passes those exact bytes and signing-header values to the
existing implementation, which verifies before parsing. Missing, repeated or
malformed signing headers are refused; ordinary WSGI comma-joined duplicates are
also refused by the strict v1 signature grammar. WSGI servers can normalize
headers/paths before the application sees them, so wire-level duplicate and raw
target preservation remain server-specific runtime checks. Valid dual rotation
signatures use a single space-separated v1 header.

The handler acknowledges only after the existing receiver returns from its
committed inbox/effect transaction. It does not invoke reference processing;
distinct accepted/inserted/processed/applied/stale counters remain in the existing
receiver. Invalid signatures/snapshots receive a neutral400, oversize413, durable
database failures503 and unexpected failures500. No payload, signing header,
keyring or exception text enters application error responses/log messages.

ROUND2's construction-exposed stdlib development suite exercises local durable
receipt/restart/dedupe, version guarding and completed-only pruning. These are
builder regressions, not an independent study. The authored pytest receiver
tests await the shared dependency environment. No HTTP factory/socket, WSGI body
cap, independent signature interoperability, real crash/ACK path, error mapping
or installed-wheel check has run. Product code never
imports the deliberately insecure root demo arm.
