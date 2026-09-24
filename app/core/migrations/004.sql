-- 004: 授权组成员下沉为"资产账号-工具"条目。
-- 每个账号成员携带独立的工具白名单；旧组级白名单平铺复制到每个成员，保持既有权限不变。
ALTER TABLE grant_accounts ADD COLUMN tools_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(tools_json));
UPDATE grant_accounts
 SET tools_json=(SELECT g.tools_json FROM grants g WHERE g.id=grant_accounts.grant_id);
