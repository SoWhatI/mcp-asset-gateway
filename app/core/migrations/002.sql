-- 授权模型改为多对多：一条 grants 记录通过 grant_targets 关联多组客户端-账号映射；
-- tool_versions_json 升级为按账号嵌套 {account_id: {tool_name: spec_hash}}。
CREATE TABLE grants_v2 (
 id TEXT PRIMARY KEY NOT NULL,
 tools_json TEXT NOT NULL CHECK(json_valid(tools_json)),
 tool_versions_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(tool_versions_json)),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO grants_v2(id,tools_json,tool_versions_json,enabled,revision,created_at,updated_at)
 SELECT id,tools_json,tool_versions_json,enabled,revision,created_at,updated_at FROM grants;
CREATE TABLE grant_targets (
 grant_id TEXT NOT NULL REFERENCES grants_v2(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 PRIMARY KEY(grant_id, client_id, account_id)
);
INSERT INTO grant_targets(grant_id,client_id,account_id) SELECT id,client_id,account_id FROM grants;
UPDATE grants_v2 SET tool_versions_json = json_object((SELECT account_id FROM grant_targets WHERE grant_id=grants_v2.id LIMIT 1), json(tool_versions_json)) WHERE tool_versions_json != '{}';
DROP TABLE grants;
ALTER TABLE grants_v2 RENAME TO grants;
CREATE UNIQUE INDEX idx_grant_targets_pair ON grant_targets(client_id, account_id);
CREATE INDEX idx_grant_targets_account ON grant_targets(account_id);
