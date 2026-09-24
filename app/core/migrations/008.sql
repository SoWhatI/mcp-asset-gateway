-- 008: 新增 Jenkins 原生资产，保留所有历史资产与引用。
-- @foreign-keys-off
CREATE TABLE assets_v2 (
  id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('mysql','ssh','filebrowser','mcp','redis','kubernetes','gitrepo','jenkins')),
  connection_json TEXT NOT NULL CHECK(json_valid(connection_json)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO assets_v2(id,name,type,connection_json,enabled,revision,created_at,updated_at)
  SELECT id,name,type,connection_json,enabled,revision,created_at,updated_at FROM assets;
DROP TABLE assets;
ALTER TABLE assets_v2 RENAME TO assets;
