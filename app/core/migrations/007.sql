-- 参数黑白名单按授权组、账号、工具独立存储；旧工具授权默认不增加参数限制。
ALTER TABLE grant_accounts ADD COLUMN parameter_rules_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(parameter_rules_json) AND json_type(parameter_rules_json)='object');

-- 旧 SSH 账号非空命令白名单迁入各个现存授权条目，不扩大历史权限。
UPDATE grant_accounts
SET parameter_rules_json = json_object('exec_command', json_object('cmd', json_object('allow', json((
    SELECT json_group_array(json_object('match', 'exact', 'value', legacy_ssh_command(command.value)))
    FROM accounts a, json_each(a.policy_json, '$.command_allowlist') command
    WHERE a.id=grant_accounts.account_id
)))))
WHERE account_id IN (
    SELECT a.id FROM accounts a JOIN assets s ON s.id=a.asset_id
    WHERE s.type='ssh' AND json_array_length(a.policy_json, '$.command_allowlist')>0
) AND EXISTS(SELECT 1 FROM json_each(tools_json) WHERE value='exec_command');

-- 旧空白名单原本不能执行命令：移除该工具授权，后续可由管理员显式重新勾选。
UPDATE grant_accounts
SET tools_json=(SELECT json_group_array(value) FROM json_each(tools_json) WHERE value!='exec_command')
WHERE account_id IN (
    SELECT a.id FROM accounts a JOIN assets s ON s.id=a.asset_id
    WHERE s.type='ssh' AND COALESCE(json_array_length(a.policy_json, '$.command_allowlist'),0)=0
);

UPDATE grants
SET tools_json=(SELECT json_group_array(value) FROM (
    SELECT DISTINCT t.value FROM grant_accounts ga, json_each(ga.tools_json) t
    WHERE ga.grant_id=grants.id ORDER BY t.value
)), revision=revision+1
WHERE id IN (
    SELECT ga.grant_id FROM grant_accounts ga JOIN accounts a ON a.id=ga.account_id
    JOIN assets s ON s.id=a.asset_id WHERE s.type='ssh'
);

UPDATE accounts SET policy_json=json_remove(policy_json, '$.command_allowlist'), revision=revision+1
WHERE asset_id IN (SELECT id FROM assets WHERE type='ssh');
