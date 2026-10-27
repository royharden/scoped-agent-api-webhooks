# Proposed M14 v1 syntax contracts

Read INTERFACE.json before consuming. Accept only the exact supported major; unknown major versions fail closed. Readiness is stub_only and producer_commit is null because this packet has not been validated against a real host. Digests describe these source bytes only.

JSON Schema describes wire syntax; it does not decide authorization, snapshot equality, state transitions, signatures, oracle answers or scores. Consumers enforce those separately. No OpenAPI or scenario/oracle formats are asserted complete in this increment.

Digest maps hash UTF-8 bytes after CRLF-to-LF normalization, matching committed Git blobs and portable checkouts. Normalize line endings before checking hashes; readiness remains stub_only.
