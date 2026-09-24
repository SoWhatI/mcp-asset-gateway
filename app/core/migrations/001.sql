CREATE TABLE assets (
 id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
 type TEXT NOT NULL CHECK(type IN ('mysql','ssh','filebrowser','mcp')),
 connection_json TEXT NOT NULL CHECK(json_valid(connection_json)),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE accounts (
 id TEXT PRIMARY KEY NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
 name TEXT NOT NULL, config_json TEXT NOT NULL CHECK(json_valid(config_json)),
 credential_ciphertext TEXT, credential_key_id TEXT,
 policy_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(policy_json)),
 tool_catalog_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(tool_catalog_json)),
 catalog_refreshed_at INTEGER, note TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE clients (
 id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 token_tail TEXT NOT NULL, token_expires_at INTEGER,
 compatibility_mode TEXT NOT NULL DEFAULT 'native' CHECK(compatibility_mode IN ('native','legacy_mysql')),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE grants (
 id TEXT PRIMARY KEY NOT NULL, client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 tools_json TEXT NOT NULL CHECK(json_valid(tools_json)),
 tool_versions_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(tool_versions_json)),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(client_id, account_id)
);
CREATE TABLE audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL UNIQUE, ts INTEGER NOT NULL,
 completed_at INTEGER, source TEXT NOT NULL CHECK(source IN ('mcp','ui','system')),
 event TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT, client_id TEXT, asset_id TEXT,
 account_id TEXT, tool TEXT, token_tail TEXT,
 snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(snapshot_json)),
 detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json)),
 status TEXT NOT NULL CHECK(status IN ('started','ok','error','denied','timeout','interrupted')),
 row_count INTEGER, output_bytes INTEGER, truncated INTEGER NOT NULL DEFAULT 0,
 elapsed_ms INTEGER, error_code TEXT
);
CREATE TABLE admin_users (
 id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE admin_sessions (
 id TEXT PRIMARY KEY NOT NULL, admin_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE, csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
 last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE settings (
 key TEXT PRIMARY KEY NOT NULL, value_json TEXT NOT NULL CHECK(json_valid(value_json)),
 revision INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL
);
CREATE INDEX idx_accounts_asset ON accounts(asset_id);
CREATE INDEX idx_grants_account ON grants(account_id);
CREATE INDEX idx_audit_ts ON audit_log(ts DESC,id DESC);
CREATE INDEX idx_audit_client_ts ON audit_log(client_id,ts DESC);
CREATE INDEX idx_audit_asset_ts ON audit_log(asset_id,ts DESC);
CREATE INDEX idx_audit_tool_ts ON audit_log(tool,ts DESC);
CREATE INDEX idx_audit_status_ts ON audit_log(status,ts DESC);
CREATE INDEX idx_sessions_expiry ON admin_sessions(expires_at);
