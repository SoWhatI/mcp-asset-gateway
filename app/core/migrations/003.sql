-- 授权组独立维护客户端与账号成员；允许跨组重复授权，也允许先创建空组。
ALTER TABLE grants ADD COLUMN name TEXT NOT NULL DEFAULT '未命名授权组'
 CHECK(length(trim(name)) BETWEEN 1 AND 100);
WITH numbered AS (
 SELECT id, row_number() OVER (ORDER BY created_at,id) AS ordinal FROM grants
)
UPDATE grants SET name='迁移授权组 ' || (SELECT ordinal FROM numbered WHERE numbered.id=grants.id);

CREATE TABLE grant_clients (
 grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
 PRIMARY KEY(grant_id,client_id)
);
CREATE INDEX idx_grant_clients_client ON grant_clients(client_id);
CREATE TABLE grant_accounts (
 grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
 PRIMARY KEY(grant_id,account_id)
);
CREATE INDEX idx_grant_accounts_account ON grant_accounts(account_id);
INSERT INTO grant_clients SELECT DISTINCT grant_id,client_id FROM grant_targets;
INSERT INTO grant_accounts SELECT DISTINCT grant_id,account_id FROM grant_targets;
DROP TABLE grant_targets;
