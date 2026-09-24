-- 006: 资产类型新增 gitrepo。
-- SQLite 无法直接修改 CHECK 约束，需重建 assets 表；重建期间关闭外键（迁移器识别下方指令），
-- 提交前由迁移器执行 PRAGMA foreign_key_check 验证 accounts.asset_id 引用完整性。
-- @foreign-keys-off
CREATE TABLE assets_v2 (
  id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('mysql','ssh','filebrowser','mcp','redis','kubernetes','gitrepo')),
  connection_json TEXT NOT NULL CHECK(json_valid(connection_json)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO assets_v2(id,name,type,connection_json,enabled,revision,created_at,updated_at)
  SELECT id,name,type,connection_json,enabled,revision,created_at,updated_at FROM assets;
DROP TABLE assets;
ALTER TABLE assets_v2 RENAME TO assets;
