CREATE TABLE IF NOT EXISTS work_orders (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL
 CHECK(status IN ('draft','submitted','approved','closed','cancelled')),
 assignee TEXT, version INTEGER NOT NULL CHECK(version >= 1),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_audit (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES work_orders(id),
 principal TEXT NOT NULL, actor_kind TEXT NOT NULL, client_id TEXT NOT NULL,
 grant_id TEXT NOT NULL, action TEXT NOT NULL, surface TEXT NOT NULL,
 resource_version INTEGER NOT NULL, occurred_at TEXT NOT NULL,
 UNIQUE(order_id, resource_version)
);
CREATE TABLE IF NOT EXISTS domain_events (
 id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
 resource_id TEXT NOT NULL REFERENCES work_orders(id), resource_version INTEGER NOT NULL,
 occurred_at TEXT NOT NULL, body BLOB NOT NULL, body_sha256 TEXT NOT NULL,
 UNIQUE(resource_id, resource_version)
);
CREATE TRIGGER IF NOT EXISTS domain_events_immutable_update
 BEFORE UPDATE ON domain_events BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
CREATE TRIGGER IF NOT EXISTS domain_events_immutable_delete
 BEFORE DELETE ON domain_events BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
CREATE TABLE IF NOT EXISTS idempotency_keys (
 principal TEXT NOT NULL, grant_id TEXT NOT NULL, action TEXT NOT NULL,
 key TEXT NOT NULL, request_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL, PRIMARY KEY(principal, grant_id, action, key)
);
CREATE TABLE IF NOT EXISTS idempotency_results (
 principal TEXT NOT NULL, grant_id TEXT NOT NULL, action TEXT NOT NULL,
 key TEXT NOT NULL, response TEXT NOT NULL,
 PRIMARY KEY(principal, grant_id, action, key),
 FOREIGN KEY(principal,grant_id,action,key)
 REFERENCES idempotency_keys(principal,grant_id,action,key)
);
CREATE TABLE IF NOT EXISTS approval_challenges (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES work_orders(id),
 resource_version INTEGER NOT NULL, requestor TEXT NOT NULL,
 requestor_kind TEXT NOT NULL, requestor_client_id TEXT NOT NULL,
 requestor_grant_id TEXT NOT NULL, resource TEXT NOT NULL,
 executor_subject TEXT NOT NULL, action TEXT NOT NULL CHECK(action='approve'),
 statement BLOB NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0,1))
);
CREATE TABLE IF NOT EXISTS approval_capabilities (
 id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL UNIQUE REFERENCES approval_challenges(id),
 order_id TEXT NOT NULL REFERENCES work_orders(id), resource_version INTEGER NOT NULL,
 requestor TEXT NOT NULL, requestor_grant_id TEXT NOT NULL,
 approver TEXT NOT NULL, executor_subject TEXT NOT NULL, executor_client_id TEXT NOT NULL,
 executor_grant_id TEXT NOT NULL, resource TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action='approve'), statement BLOB NOT NULL,
 nonce TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)), consumed_at TEXT
);
