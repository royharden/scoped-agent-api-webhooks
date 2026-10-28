# Scoped agent API and webhook delivery reference

M14 is a fictional Fixit Works work-order host with scoped mock OAuth, human approval, and durable webhook delivery. Local Dirty construction is in progress: runtime unverified. No measured conformance or security claims.

Source integrated so far includes transactional domain/storage/approval, HTTP client/CLI, and provisional contracts. CLI defaults to a no-call dry-run; authenticated mutations require an in-memory Session and trusted disposable fixture consent from a future launcher. See docs/CLIENT-USAGE.md. Mock OAuth client discovery/PKCE/refresh/revoke and lazy Session factory source are integrated; no successful end-to-end journey exists yet. Authorization-server/API/UI and delivery/receiver source are integrated; joined composition and transport/receiver factories remain under construction. All services and Authlib interoperability remain unexecuted.

contracts/v1 and fixtures/m20-stub hold original syntax contracts/development transcripts. Readiness is stub_only; delivery examples are unsigned and unexecuted. Developer fixtures are not independent evaluation data. See docs/DEFERRED-VALIDATION.md and DEPENDENCY-STATUS.md for limits. No installation, runtime test, network call or infrastructure has been performed by this run. Product/fixture licensing and independent evaluation admission remain pending; no LICENSE adoption or independent verification claim.

Authoritative plan remains privately at ../planning/promoted/PLAN-M14-v1.md; original source SHA256604b6c4c07e4dcc623f0ed45bf1b441e6ff0ddf747ada8b9f18faa4da27649d6. Private coordination and transcripts stay outside this product repository.
