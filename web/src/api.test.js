import test from "node:test";
import assert from "node:assert/strict";
import { catalogNeedsRefresh, displayText, displayValue, groupsFor, groupTools, grantEntryPayload, matchesAccount, matchesGrant, trimStrings } from "./api.js";

const entities = {
  assets: [{ id: "asset-123456789abc", name: "订单库" }],
  accounts: [{ id: "acct-123456789abc", name: "只读账号", asset_id: "asset-123456789abc" }, { id: "legacy", name: "旧账号" }],
  clients: [{ id: "cli-123456789abc", name: "查询助手" }],
  grants: [],
};

test("提示和协议工具名显示名称，未知对象不回退内部标识", () => {
  assert.equal(displayText("删除 asset-123456789abc", entities), "删除 订单库");
  assert.equal(displayText("acct-123456789abc__lookup", entities), "只读账号 · lookup");
  assert.equal(displayText("legacy__lookup", entities), "旧账号 · lookup");
  assert.equal(displayText("cli-ffffffffffff", entities), "已删除对象");
});

test("审计和 schema 递归转换不改动原始协议参数，历史名称优先", () => {
  const value = { id: "hidden", actor_id: "hidden", client_id: "cli-123456789abc",
    asset_id: "asset-123456789abc", account_id: "acct-123456789abc",
    snapshot: { client: "历史助手" }, schema: { enum: ["acct-123456789abc", "legacy"] } };
  const before = structuredClone(value);
  const named = displayValue(value, entities);
  assert.equal(named.客户端, "历史助手");
  assert.equal(named.资产, "订单库");
  assert.equal(named.账号, "只读账号");
  assert.deepEqual(named.schema.enum, ["只读账号", "旧账号"]);
  assert.ok(!("id" in named) && !("actor_id" in named));
  assert.deepEqual(value, before);
  assert.equal(displayValue({ account_id: "deleted" }, entities).账号, "已删除对象");
});

test("矩阵资产和账号关键字按 AND 匹配，空维度不绕过过滤", () => {
  const account = entities.accounts[0];
  assert.ok(matchesAccount(account, entities.assets, { asset: "订单", account: "" }));
  assert.ok(!matchesAccount(account, entities.assets, { asset: "不存在", account: "" }));
  assert.ok(!matchesAccount(account, entities.assets, { asset: "订单", account: "不存在" }));
  assert.ok(matchesAccount(account, entities.assets, { asset: " 订单 ", account: "只读" }));
});

test("授权组列表按客户端、资产、账号独立维度过滤，空维度不旁路", () => {
  const group = {
    client_ids: ["cli-123456789abc"],
    entries: [{ account_id: "acct-123456789abc", tools: ["read"] }],
  };
  const clean = { client: "", asset: "", account: "" };
  assert.ok(matchesGrant(group, entities, clean));
  assert.ok(matchesGrant(group, entities, { ...clean, client: "查询" }));
  assert.ok(matchesGrant(group, entities, { ...clean, asset: "订单" }));
  assert.ok(matchesGrant(group, entities, { ...clean, account: "只读" }));
  assert.ok(!matchesGrant(group, entities, { ...clean, client: "不存在" }));
  assert.ok(!matchesGrant(group, entities, { ...clean, asset: "不存在" }));
  assert.ok(!matchesGrant(group, entities, { ...clean, account: "不存在" }));
  // 维度之间 AND，关键字首尾空白不影响匹配。
  assert.ok(matchesGrant(group, entities, { client: " 查询 ", asset: "订单", account: "只读" }));
  assert.ok(!matchesGrant(group, entities, { client: "查询", asset: "订单", account: "不存在" }));
  // 已删除对象按空名处理，不匹配任何非空关键字。
  assert.ok(
    !matchesGrant(
      { client_ids: [], entries: [{ account_id: "gone", tools: [] }] },
      entities,
      { ...clean, account: "只读" },
    ),
  );
});

test("单元格保留所有组，工具按启用组该账号条目并集去重，其它账号条目不生效", () => {
  const group = { client_ids: ["client"], entries: [{ account_id: "account", tools: ["read"] }], enabled: true };
  const grants = [
    group,
    { ...group, entries: [{ account_id: "account", tools: ["read", "list"] }] },
    { ...group, entries: [{ account_id: "account", tools: ["write"] }], enabled: false },
    { ...group, entries: [{ account_id: "other-account", tools: ["scan"] }] },
    { ...group, entries: [] },
  ];
  assert.equal(groupsFor(grants, "client", "account").length, 3);
  assert.deepEqual(groupTools(grants, "client", "account"), ["read", "list"]);
  assert.deepEqual(groupTools(grants, "client", "other-account"), ["scan"]);
  assert.deepEqual(groupTools(grants, "other", "account"), []);
});

test("MCP 目录为空或过期时需要自动发现，其它类型与新鲜目录跳过", () => {
  const empty = { tools: [], stale: true };
  const stale = { tools: [{ name: "lookup" }], stale: true };
  const fresh = { tools: [{ name: "lookup" }], stale: false };
  assert.ok(catalogNeedsRefresh("mcp", empty));
  assert.ok(catalogNeedsRefresh("mcp", stale));
  assert.ok(!catalogNeedsRefresh("mcp", fresh));
  assert.ok(!catalogNeedsRefresh("mysql", empty));
});

test("授权参数规则保存回填保留空白并过滤取消勾选的工具", () => {
  const entry = { account_id: "account", tools: ["run"], parameter_rules: {
    run: { cmd: { allow: [{ match: "exact", value: " id " }], deny: [{ match: "regex", value: " .*blocked.* " }] } },
    removed: { arg: { allow: [{ match: "exact", value: "test" }] } },
  } };
  const value = grantEntryPayload(entry);
  assert.deepEqual(value.parameter_rules, { run: entry.parameter_rules.run });
  value.parameter_rules.run.cmd.allow[0].value = "changed";
  assert.equal(entry.parameter_rules.run.cmd.allow[0].value, " id ");
  assert.deepEqual(grantEntryPayload({ ...entry, tools: [] }).parameter_rules, {});
  assert.deepEqual(grantEntryPayload({ account_id: "account", tools: ["run"] }).parameter_rules, {});
  assert.deepEqual(grantEntryPayload({ ...entry, parameter_rules: {} }).parameter_rules, {});
});

test("提交前递归清理非凭据字段首尾空白且不改动原对象", () => {
  const connection = {
    url: "  https://k8s.example.test:6443  ",
    port: 6443,
    kinds: [" pods ", "services"],
    nested: { path: "/etc/kubernetes/ca.crt\n", enabled: true },
  };
  const before = structuredClone(connection);
  assert.deepEqual(trimStrings(connection), {
    url: "https://k8s.example.test:6443",
    port: 6443,
    kinds: ["pods", "services"],
    nested: { path: "/etc/kubernetes/ca.crt", enabled: true },
  });
  assert.deepEqual(connection, before);
  assert.equal(trimStrings("  a b  "), "a b");
  assert.equal(trimStrings(null), null);
});
