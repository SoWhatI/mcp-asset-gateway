-- 009: 资产类型改为登记表外键，解除固定枚举；新增插件运行时表。
-- @foreign-keys-off
CREATE TABLE asset_types (
  type_id TEXT PRIMARY KEY NOT NULL,
  plugin_id TEXT,
  display_name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT 'Connection',
  schemas_json TEXT CHECK(schemas_json IS NULL OR json_valid(schemas_json)),
  capabilities_json TEXT CHECK(capabilities_json IS NULL OR json_valid(capabilities_json)),
  source TEXT NOT NULL CHECK(source IN ('builtin','plugin')),
  available INTEGER NOT NULL DEFAULT 1 CHECK(available IN (0,1)),
  artifact_hash TEXT,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
INSERT INTO asset_types(type_id,display_name,icon,source,created_at,updated_at) VALUES
  ('mysql','MySQL 数据库','Coin','builtin',0,0),
  ('ssh','SSH 主机','Monitor','builtin',0,0),
  ('filebrowser','SFTP 文件目录','FolderOpened','builtin',0,0),
  ('mcp','上游 MCP 服务','Connection','builtin',0,0),
  ('redis','Redis 缓存','DataLine','builtin',0,0),
  ('kubernetes','Kubernetes 集群','Platform','builtin',0,0),
  ('gitrepo','Git 代码仓库','Document','builtin',0,0),
  ('jenkins','Jenkins 持续集成','VideoPlay','builtin',0,0);
CREATE TABLE assets_v2 (
  id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
  type TEXT NOT NULL REFERENCES asset_types(type_id),
  connection_json TEXT NOT NULL CHECK(json_valid(connection_json)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO assets_v2(id,name,type,connection_json,enabled,revision,created_at,updated_at)
  SELECT id,name,type,connection_json,enabled,revision,created_at,updated_at FROM assets;
DROP TABLE assets;
ALTER TABLE assets_v2 RENAME TO assets;
CREATE TABLE plugins (
  id TEXT PRIMARY KEY NOT NULL,
  publisher TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  expected_state TEXT NOT NULL DEFAULT 'disabled' CHECK(expected_state IN ('enabled','disabled')),
  current_version_id TEXT,
  revision INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE plugin_versions (
  id TEXT PRIMARY KEY NOT NULL,
  plugin_id TEXT NOT NULL REFERENCES plugins(id),
  version TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  path TEXT NOT NULL,
  manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
  sdk_protocol INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('installed','active','retired')),
  installed_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(plugin_id, version)
);
CREATE TABLE plugin_jobs (
  id TEXT PRIMARY KEY NOT NULL,
  plugin_id TEXT NOT NULL,
  version TEXT,
  action TEXT NOT NULL CHECK(action IN ('install','upgrade','rollback','uninstall','enable','disable')),
  status TEXT NOT NULL CHECK(status IN ('pending','running','done','failed')),
  progress INTEGER NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100),
  detail_json TEXT CHECK(detail_json IS NULL OR json_valid(detail_json)),
  error_json TEXT CHECK(error_json IS NULL OR json_valid(error_json)),
  actor_id TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
ALTER TABLE grants ADD COLUMN code_versions_json TEXT NOT NULL DEFAULT '{}';
