CREATE TABLE IF NOT EXISTS oauth_grants (
 id TEXT PRIMARY KEY, subject TEXT NOT NULL, actor_kind TEXT NOT NULL CHECK(actor_kind IN ('human','agent')),
 client_id TEXT NOT NULL, issuer TEXT NOT NULL, resource TEXT NOT NULL, scopes TEXT NOT NULL,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_codes (
 digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
 client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, resource TEXT NOT NULL,
 challenge TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_families (
 id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
 expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
 digest TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
 grant_id TEXT NOT NULL REFERENCES oauth_grants(id), family_id TEXT NOT NULL REFERENCES oauth_families(id),
 scopes TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens(grant_id);
CREATE TABLE IF NOT EXISTS oauth_ui_sessions (
 digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
 scopes TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_ui_logins (
 digest TEXT PRIMARY KEY, state_digest TEXT NOT NULL, verifier TEXT NOT NULL,
 client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scopes TEXT NOT NULL,
 expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_security_events (
 id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, event TEXT NOT NULL, occurred_at TEXT NOT NULL
);
