<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  ArrowRight,
  Coin,
  Connection,
  DataAnalysis,
  DataLine,
  Document,
  FolderOpened,
  Grid,
  Key,
  Lock,
  Minus,
  Monitor,
  Platform,
  Plus,
  Refresh,
  Search,
  Setting,
  SwitchButton,
  Tickets,
  User,
  VideoPlay,
} from "@element-plus/icons-vue";
import { api, all, catalogNeedsRefresh, defaults, displayText, displayValue, groupsFor, groupTools, grantEntryPayload, matchesAccount, matchesGrant, trimStrings } from "./api";
import SchemaForm from "./SchemaForm.vue";
import ToolRules from "./ToolRules.vue";

const menu = [
  {
    id: "dashboard",
    name: "概览",
    caption: "整个网关，一目了然",
    icon: DataAnalysis,
  },
  {
    id: "assets",
    name: "资产管理",
    caption: "连接分散的资源，建立统一的访问入口",
    icon: Grid,
  },
  {
    id: "accounts",
    name: "账号与凭据",
    caption: "凭据由网关托管，不向智能体暴露",
    icon: Key,
  },
  {
    id: "clients",
    name: "客户端",
    caption: "为每个智能体建立独立身份",
    icon: Connection,
  },
  {
    id: "grants",
    name: "授权矩阵",
    caption: "通过授权组关联客户端与资产账号，工具权限取并集，参数黑名单优先",
    icon: Lock,
  },
  {
    id: "audit",
    name: "审计日志",
    caption: "每次访问、每次变更，都有迹可循",
    icon: Tickets,
  },
  {
    id: "debug",
    name: "工具调试台",
    caption: "使用真实授权链路，验证工具行为",
    icon: VideoPlay,
  },
  {
    id: "settings",
    name: "系统设置",
    caption: "资源限制、数据保留与安全设置",
    icon: Setting,
  },
];
const kindIcons = {
  mysql: Coin,
  ssh: Monitor,
  filebrowser: FolderOpened,
  mcp: Connection,
  redis: DataLine,
  kubernetes: Platform,
  gitrepo: Document,
  jenkins: VideoPlay,
};
const kindColors = {
  mysql: "blue",
  ssh: "violet",
  filebrowser: "amber",
  mcp: "green",
  redis: "red",
  kubernetes: "cyan",
  gitrepo: "orange",
  jenkins: "red",
};
const kindNames = { filebrowser: "SFTP", kubernetes: "K8S", gitrepo: "Git", jenkins: "Jenkins" };
const kindLabel = (kind) => kindNames[kind] || kind.toUpperCase();
const active = ref("dashboard");
const user = ref(null),
  booting = ref(true),
  busy = ref(false);
const loginForm = reactive({ username: "", password: "" });
const entities = reactive({
  assets: [],
  accounts: [],
  clients: [],
  grants: [],
});
const types = ref([]),
  dashboard = ref({ counts: {}, statuses: {}, calls: { statuses: {} }, daily: [], top_tools: [], top_clients: [] }),
  settings = ref([]);
const query = ref(""),
  kindFilter = ref(""),
  page = ref(1),
  pageSize = ref(10),
  matrixPage = ref(1),
  matrixMode = ref(false);
const matrixFilter = reactive({ client: "", asset: "", account: "" });
const current = computed(
  () => menu.find((m) => m.id === active.value) || menu[0],
);
const crud = computed(() =>
  ["assets", "accounts", "clients", "grants"].includes(active.value),
);
const filtered = computed(() =>
  (entities[active.value] || []).filter(
    (row) =>
      JSON.stringify(displayValue(row, entities)).toLowerCase().includes(query.value.trim().toLowerCase()) &&
      (!kindFilter.value || row.type === kindFilter.value) &&
      (active.value !== "grants" || matchesGrant(row, entities, matrixFilter)),
  ),
);
const visible = computed(() =>
  filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value),
);
const matrixSearching = computed(() =>
  Boolean(matrixFilter.client || matrixFilter.asset || matrixFilter.account),
);
const contains = (value, keyword) =>
  String(value || "")
    .toLowerCase()
    .includes(keyword.trim().toLowerCase());
const matrixClients = computed(() =>
  entities.clients.filter(
    (client) =>
      contains(client.name, matrixFilter.client),
  ),
);
const matrixAccounts = computed(() =>
  entities.accounts.filter((account) => matchesAccount(account, entities.assets, matrixFilter)),
);
const matrixRows = computed(() =>
  matrixClients.value.slice(
    (matrixPage.value - 1) * pageSize.value,
    matrixPage.value * pageSize.value,
  ),
);
// 任一列表或矩阵过滤条件变化后回到第一页。
const resetPages = () => {
  page.value = 1;
  matrixPage.value = 1;
};
const endpoint = `${window.location.origin}/mcp`;
const editOpen = ref(false),
  editTable = ref("assets"),
  original = ref(null),
  form = ref({}),
  credential = ref({}),
  replaceCredential = ref(false);
const grantCatalog = ref([]),
  catalogStale = ref(false),
  catalogReady = ref(false);
let catalogRequest = 0;
const cellOpen = ref(false), cellClient = ref(null), cellAccount = ref(null);
const cellGroups = computed(() => groupsFor(entities.grants, cellClient.value?.id, cellAccount.value?.id));
const unlistedEntries = computed(() =>
  (form.value.entries || []).map((entry) => ({
    ...entry,
    unlisted: entry.tools.filter(
      (name) => !grantCatalog.value.some((tool) => tool.accountId === entry.account_id && tool.name === name),
    ),
  })),
);
const token = ref(""),
  tokenName = ref(""),
  tokenOpen = ref(false),
  detail = ref(null),
  detailOpen = ref(false);
const auditRows = ref([]),
  auditCursor = ref(null),
  auditHistory = ref([]);
const auditFilter = reactive({
  client_id: "",
  asset_id: "",
  tool: "",
  status: "",
  event: "",
  source: "",
  start: "",
  end: "",
});
const debugClient = ref(""),
  debugTools = ref([]),
  debugTool = ref(""),
  debugArguments = ref("{}"),
  debugTarget = ref(""),
  debugResult = ref(null);
const selectedDebug = computed(() =>
  debugTools.value.find((t) => t.name === debugTool.value),
);
const debugTargets = computed(() => {
  const target = selectedDebug.value?.inputSchema?.properties?.target;
  return target?.enum?.every((id) => entities.accounts.some((account) => account.id === id)) ? target.enum : [];
});
const passwordOpen = ref(false),
  passwords = reactive({ old_password: "", new_password: "" });
const selectedType = computed(() => {
  const type =
    editTable.value === "assets"
      ? form.value.type
      : entities.assets.find((a) => a.id === form.value.asset_id)?.type;
  return types.value.find((t) => t.type_id === type);
});
const accountKind = (id) =>
  entities.assets.find(
    (a) => a.id === entities.accounts.find((x) => x.id === id)?.asset_id,
  )?.type;
const label = (table, id) =>
  entities[table].find((x) => x.id === id)?.name || "已删除对象";
const text = (value) => displayText(value, entities);
const named = (value) => displayValue(value, entities);
const date = (value) =>
  value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const addressOf = (row) => {
  if (row.connection.url) return row.connection.url;
  const port =
    row.connection.port ||
    types.value.find((t) => t.type_id === row.type)?.default_port;
  return port ? `${row.connection.host}:${port}` : row.connection.host;
};
const pretty = (value) => JSON.stringify(value, null, 2);
const accountLabel = (id) => {
  const account = entities.accounts.find((x) => x.id === id);
  if (!account) return "账号已删除";
  const asset = entities.assets.find((a) => a.id === account.asset_id);
  return asset ? `${asset.name} · ${account.name}` : account.name;
};
const auditClientName = (row) =>
  row.snapshot?.client ||
  entities.clients.find((c) => c.id === row.client_id)?.name ||
  (row.client_id ? "客户端已删除" : "—");
const mcpConfig = computed(() => {
  const name = tokenName.value || "资产网关客户端";
  return pretty({
    mcpServers: {
      [name]: {
        url: `${window.location.origin}/mcp`,
        headers: { Authorization: `Bearer ${token.value}` },
      },
    },
  });
});
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    ElMessage.success("已复制到剪贴板");
  } catch {
    ElMessage.error("复制失败，请手动选择复制");
  }
}
const totalCalls = computed(() =>
  Object.values(dashboard.value.statuses).reduce((a, b) => a + b, 0),
);
const statusLabels = {
  ok: "成功", error: "错误", denied: "拒绝", timeout: "超时", interrupted: "中断", started: "执行中",
};
const callFailures = computed(() =>
  ["error", "denied", "timeout", "interrupted"].reduce((sum, status) => sum + (dashboard.value.calls.statuses[status] || 0), 0),
);
async function inspectCalls(filters = {}) {
  Object.keys(auditFilter).forEach((key) => { auditFilter[key] = ""; });
  Object.assign(auditFilter, { event: "tools.call", start: dashboard.value.start, end: dashboard.value.end }, filters);
  await navigate("audit");
}

async function run(fn) {
  busy.value = true;
  try {
    return await fn();
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(text(error.message || "操作失败"));
  } finally {
    busy.value = false;
  }
}
async function refreshBase() {
  const values = await Promise.all(
    ["assets", "accounts", "clients", "grants"].map(all),
  );
  Object.keys(entities).forEach((key, index) => {
    entities[key] = values[index];
  });
  dashboard.value = await api("/dashboard");
}
async function navigate(id) {
  active.value = id;
  query.value = "";
  kindFilter.value = "";
  resetPages();
  Object.assign(matrixFilter, { client: "", asset: "", account: "" });
  await run(async () => {
    if (id === "audit") {
      auditHistory.value = [];
      await loadAudit();
    } else if (id === "settings") settings.value = await api("/settings");
    else await refreshBase();
  });
}
async function login() {
  await run(async () => {
    user.value = await api("/auth/login", { method: "POST", body: loginForm });
    loginForm.password = "";
    types.value = await api("/types");
    await refreshBase();
  });
}
function expired() {
  user.value = null;
  token.value = "";
  tokenName.value = "";
  tokenOpen.value = false;
  editOpen.value = false;
  cellOpen.value = false;
  toolOpen.value = false;
  catalogRequest++;
  grantCatalog.value = [];
  credential.value = {};
  passwordOpen.value = false;
  passwords.old_password = "";
  passwords.new_password = "";
  detailOpen.value = false;
  detail.value = null;
  debugResult.value = null;
  debugArguments.value = "{}";
  debugTools.value = [];
  debugTool.value = "";
  debugClient.value = "";
  auditRows.value = [];
  Object.keys(entities).forEach((key) => {
    entities[key] = [];
  });
}
async function logout() {
  await run(async () => {
    await api("/auth/logout", { method: "POST", body: {} });
    expired();
  });
}
function typeChanged() {
  form.value.connection = defaults(selectedType.value?.connection_schema);
}
function accountAssetChanged() {
  form.value.config = defaults(selectedType.value?.account_schema);
  form.value.policy = defaults(selectedType.value?.policy_schema);
  credential.value = {};
}
async function loadGrantCatalog(refresh = false) {
  const request = ++catalogRequest;
  const accountIds = [
    ...new Set((form.value.entries || []).map((entry) => entry.account_id).filter(Boolean)),
  ];
  grantCatalog.value = [];
  catalogStale.value = false;
  catalogReady.value = !accountIds.length;
  if (!accountIds.length) return;
  await run(async () => {
    const results = [];
    for (const accountId of accountIds) {
      const kind = accountKind(accountId);
      let result;
      if (kind === "mcp" && refresh) {
        result = await api(`/accounts/${accountId}/refresh-tools`, { method: "POST", body: {} });
      } else {
        result = await api(`/accounts/${accountId}/tools`);
        if (catalogNeedsRefresh(kind, result)) {
          // 缓存为空或过期时自动发现一次，授权界面无需手动刷新即可选择工具。
          try {
            result = await api(`/accounts/${accountId}/refresh-tools`, { method: "POST", body: {} });
          } catch {
            // 自动发现失败时静默保留缓存结果；可点击“刷新上游目录”查看具体错误。
          }
        }
      }
      if (request !== catalogRequest || !editOpen.value) return;
      results.push({ accountId, ...result });
    }
    if (request !== catalogRequest) return;
    grantCatalog.value = results.flatMap((result) => result.tools.map((tool) => ({ ...tool, accountId: result.accountId })));
    catalogStale.value = results.some((result) => result.stale);
    catalogReady.value = true;
  });
}
async function openEdit(row = null, table = active.value) {
  catalogRequest++;
  catalogReady.value = !row;
  editTable.value = table;
  original.value = row;
  grantCatalog.value = [];
  catalogStale.value = false;
  replaceCredential.value = false;
  credential.value = {};
  const data = row
    ? JSON.parse(JSON.stringify(row))
    : { name: "", enabled: true };
  if (table === "assets" && !row) {
    data.type = "mysql";
    data.connection = defaults(
      types.value.find((t) => t.type_id === "mysql")?.connection_schema,
    );
  }
  if (table === "accounts" && !row) {
    data.asset_id = "";
    data.config = {};
    data.policy = {};
    data.note = "";
  }
  if (table === "clients") data.token_expires_at ??= null;
  if (table === "grants") {
    data.entries = (data.entries || []).map(grantEntryPayload);
    if (!row) {
      data.client_ids = [];
      delete data.id;
    }
    Object.assign(grantSearch, { client: "", account: "" });
    Object.assign(pendingGrant, { client: "", account: "" });
    toolOpen.value = false;
  }
  data.enabled = Boolean(data.enabled);
  form.value = data;
  editOpen.value = true;
  if (table === "grants" && row) await loadGrantCatalog();
}
async function save() {
  await run(async () => {
    const table = editTable.value,
      value = form.value;
    let payload = { enabled: value.enabled };
    if (original.value) payload.revision = original.value.revision;
    payload.name = value.name;
    if (!value.name?.trim()) throw new Error(table === "grants" ? "请填写授权组名称" : "请填写显示名称");
    if (table === "assets")
      Object.assign(payload, {
        type: value.type,
        connection: trimStrings(value.connection),
      });
    if (table === "accounts") {
      Object.assign(payload, {
        asset_id: value.asset_id,
        config: trimStrings(value.config),
        policy: trimStrings(value.policy),
        note: value.note || "",
      });
      if (!original.value || replaceCredential.value)
        payload.credential = credential.value;
    }
    if (table === "clients")
      payload.token_expires_at = value.token_expires_at
        ? Number(value.token_expires_at)
        : null;
    if (table === "grants") {
      payload.client_ids = value.client_ids || [];
      payload.entries = (value.entries || [])
        .filter((entry) => entry.account_id)
        .map(grantEntryPayload);
      if (new Set(payload.entries.map((entry) => entry.account_id)).size !== payload.entries.length)
        throw new Error("同一资产账号在组内只能有一条配置，请合并后重试");
      if (
        payload.entries.some((entry) => entry.tools.length) &&
        (!catalogReady.value || unlistedEntries.value.some((entry) => entry.unlisted.length))
      )
        throw new Error("请加载工具目录并移除已不可用的工具后再保存");
      payload.tool_versions = {};
      for (const item of grantCatalog.value) {
        const entry = payload.entries.find((row) => row.account_id === item.accountId);
        if (entry?.tools.includes(item.name) && item.spec_hash) {
          payload.tool_versions[item.accountId] ||= {};
          payload.tool_versions[item.accountId][item.name] = item.spec_hash;
        }
      }
      if (Object.keys(payload.tool_versions).length)
        await ElMessageBox.confirm(
          "确认已查看选中工具的描述与 schema，并批准当前定义版本？上游工具可能有外部副作用。",
          "确认工具版本",
          { type: "warning" },
        );
    }
    const saved = await api(
      `/${table}${original.value ? `/${original.value.id}` : ""}`,
      { method: original.value ? "PATCH" : "POST", body: payload },
    );
    editOpen.value = false;
    credential.value = {};
    ElMessage.success("已保存，新请求立即使用最新配置");
    if (saved.token) {
      token.value = saved.token;
      tokenName.value = saved.name;
      tokenOpen.value = true;
    }
    await refreshBase();
  });
}
async function remove(row) {
  await run(async () => {
    await ElMessageBox.confirm(
      active.value === "grants"
        ? `删除授权组「${row.name || '未命名授权组'}」？本组全部关联将解除，其它组的重复授权继续生效；删除本组黑名单可能放宽权限。历史审计会保留。`
        : `删除「${row.name || '该对象'}」？存在引用时需要先解除关联。历史审计会保留。`,
      "确认删除",
      { type: "warning" },
    );
    await api(`/${active.value}/${row.id}?revision=${row.revision}`, {
      method: "DELETE",
    });
    ElMessage.success("已删除");
    await refreshBase();
  });
}
async function toggle(row) {
  await run(async () => {
    await api(`/${active.value}/${row.id}`, {
      method: "PATCH",
      body: { revision: row.revision, enabled: !row.enabled },
    });
    await refreshBase();
  });
}
async function rotate(row) {
  await run(async () => {
    await ElMessageBox.confirm(
      "轮换后旧 token 立即失效。请同时更新客户端认证头。",
      "轮换 token",
      { type: "warning" },
    );
    const data = await api(`/clients/${row.id}/rotate-token`, {
      method: "POST",
      body: { revision: row.revision },
    });
    token.value = data.token;
    tokenName.value = row.name;
    tokenOpen.value = true;
    await refreshBase();
  });
}
async function testAccount(row) {
  await run(async () => {
    await api(`/accounts/${row.id}/test`, { method: "POST", body: {} });
    ElMessage.success("连接验证成功");
  });
}
function showDetail(value) {
  detail.value = named(value);
  detailOpen.value = true;
}
function auditParams() {
  return new URLSearchParams(
    Object.entries(auditFilter).filter(([, value]) => value),
  ).toString();
}
async function loadAudit(cursor = null) {
  const data = await api(
    `/audit?limit=20&${auditParams()}${cursor ? `&cursor=${cursor}` : ""}`,
  );
  auditRows.value = data.items;
  auditCursor.value = data.next_cursor;
}
async function nextAudit() {
  const cursor = auditCursor.value;
  auditHistory.value.push(cursor);
  await run(() => loadAudit(cursor));
}
async function prevAudit() {
  auditHistory.value.pop();
  await run(() => loadAudit(auditHistory.value.at(-1)));
}
async function exportAudit() {
  await run(async () => {
    const blob = await api(`/audit/export?${auditParams()}`, { blob: true });
    const url = URL.createObjectURL(blob),
      a = document.createElement("a");
    a.href = url;
    a.download = "gateway-audit.csv";
    a.click();
    URL.revokeObjectURL(url);
  });
}
async function getDebugTools() {
  debugTools.value = [];
  debugTool.value = "";
  debugResult.value = null;
  await run(async () => {
    debugTools.value = (
      await api("/debug/tools-list", {
        method: "POST",
        body: { client_id: debugClient.value },
      })
    ).tools;
  });
}
function selectDebug() {
  debugArguments.value = pretty(defaults(selectedDebug.value?.inputSchema));
  debugTarget.value = "";
  debugResult.value = null;
}
async function executeDebug() {
  await run(async () => {
    const argumentsValue = JSON.parse(debugArguments.value);
    if (debugTargets.value.length) {
      if (!debugTarget.value) throw new Error("请选择目标资产账号");
      argumentsValue.target = debugTarget.value;
    }
    await ElMessageBox.confirm(
      "即将通过真实授权链路调用远端工具。SSH、Kubernetes exec 和 MCP 工具可能有副作用；超时不代表未执行。",
      "确认执行",
      { type: "warning" },
    );
    debugResult.value = await api("/debug/tools-call", {
      method: "POST",
      body: {
        client_id: debugClient.value,
        name: debugTool.value,
        arguments: argumentsValue,
        confirm: true,
      },
    });
  });
}
const grantsFor = (client, account) => groupTools(entities.grants, client, account);
const grantSearch = reactive({ client: "", account: "" });
const pendingGrant = reactive({ client: "", account: "" });
const toolOpen = ref(false), toolIndex = ref(-1);
const toolEntry = computed(() => form.value.entries?.[toolIndex.value] || null);
const toolUnlisted = computed(() => unlistedEntries.value[toolIndex.value]?.unlisted || []);
const grantClientRows = computed(() =>
  (form.value.client_ids || [])
    .map((id) => ({ id, name: label("clients", id) }))
    .filter((row) => contains(row.name, grantSearch.client)),
);
const availableGrantClients = computed(() =>
  entities.clients.filter(
    (client) => !(form.value.client_ids || []).includes(client.id),
  ),
);
const grantEntryRows = computed(() =>
  (form.value.entries || [])
    .map((entry, index) => ({
      index,
      label: accountLabel(entry.account_id),
      tools: entry.tools.length,
      unlisted: unlistedEntries.value[index]?.unlisted.length || 0,
    }))
    .filter((row) => contains(row.label, grantSearch.account)),
);
const availableGrantAccounts = computed(() =>
  entities.accounts.filter(
    (account) =>
      !(form.value.entries || []).some(
        (entry) => entry.account_id === account.id,
      ),
  ),
);
function addGrantClient() {
  if (!pendingGrant.client) return;
  form.value.client_ids ||= [];
  if (
    !form.value.client_ids.includes(pendingGrant.client) &&
    form.value.client_ids.length < 50
  )
    form.value.client_ids.push(pendingGrant.client);
  pendingGrant.client = "";
}
function removeGrantClient(id) {
  form.value.client_ids = (form.value.client_ids || []).filter(
    (item) => item !== id,
  );
}
function addGrantEntry() {
  if (!pendingGrant.account) return;
  form.value.entries ||= [];
  if (
    form.value.entries.length >= 50 ||
    form.value.entries.some((entry) => entry.account_id === pendingGrant.account)
  )
    return;
  form.value.entries.push({ account_id: pendingGrant.account, tools: [], parameter_rules: {} });
  pendingGrant.account = "";
  loadGrantCatalog();
}
function removeGrantEntry(index) {
  form.value.entries.splice(index, 1);
  if (toolOpen.value && toolIndex.value === index) toolOpen.value = false;
  else if (toolOpen.value && toolIndex.value > index) toolIndex.value -= 1;
  loadGrantCatalog();
}
function openToolDialog(index) {
  toolIndex.value = index;
  toolOpen.value = true;
}
function editClosed() {
  credential.value = {};
  toolOpen.value = false;
  grantSearch.client = "";
  grantSearch.account = "";
  pendingGrant.client = "";
  pendingGrant.account = "";
}
const entryCatalog = (entry) =>
  entry ? grantCatalog.value.filter((tool) => tool.accountId === entry.account_id) : [];
async function openGrantCell(client, account) {
  cellClient.value = client;
  cellAccount.value = account;
  if (!groupsFor(entities.grants, client.id, account.id).length) {
    await newCellGroup();
    return;
  }
  cellOpen.value = true;
}
async function newCellGroup() {
  cellOpen.value = false;
  await openEdit(null, "grants");
  form.value.client_ids = [cellClient.value.id];
  form.value.entries = [{ account_id: cellAccount.value.id, tools: [], parameter_rules: {} }];
  await loadGrantCatalog();
}
async function editCellGroup(group) {
  cellOpen.value = false;
  await openEdit(group, "grants");
}
onMounted(async () => {
  window.addEventListener("session-expired", expired);
  try {
    user.value = await api("/auth/me");
    types.value = await api("/types");
    await refreshBase();
  } catch {
    user.value = null;
  } finally {
    booting.value = false;
  }
});
onUnmounted(() => window.removeEventListener("session-expired", expired));
</script>

<template>
  <div v-if="booting" class="boot-screen">
    <div class="brand-symbol"><Connection /></div>
    <p>正在连接资产网关…</p>
  </div>
  <div v-else-if="!user" class="login-page">
    <section class="login-story">
      <div class="brand">
        <div class="brand-symbol"><Connection /></div>
        <span>MCP 资产网关</span>
      </div>
      <div class="story-body">
        <span class="eyebrow">ONE GATEWAY. EVERY ASSET.</span>
        <h1>连接你的资产，<br />掌握每一次访问。</h1>
        <p>
          数据库、主机、远程文件与 MCP 服务。<br />统一连接，按需授权，全程可追溯。
        </p>
        <div class="orbit">
          <div v-for="(icon, kind) in kindIcons" :key="kind" class="orbit-item">
            <component :is="icon" /><span>{{ kindLabel(kind) }}</span>
          </div>
        </div>
      </div>
      <small>集中托管 · 最小权限 · 全量审计</small>
    </section>
    <section class="login-panel">
      <div class="login-form">
        <span class="eyebrow">管理控制台</span>
        <h2>欢迎回来</h2>
        <p class="muted">使用管理员账号，进入你的资产工作空间。</p>
        <el-form label-position="top" @submit.prevent="login"
          ><el-form-item label="用户名"
            ><el-input
              v-model="loginForm.username"
              size="large"
              placeholder="请输入管理员用户名"
              autocomplete="username"
              :prefix-icon="User" /></el-form-item
          ><el-form-item label="密码"
            ><el-input
              v-model="loginForm.password"
              size="large"
              type="password"
              placeholder="请输入密码"
              show-password
              autocomplete="current-password"
              :prefix-icon="Lock" /></el-form-item
          ><el-button
            class="login-button"
            type="primary"
            size="large"
            native-type="submit"
            :loading="busy"
            >登录控制台 <el-icon><ArrowRight /></el-icon></el-button
        ></el-form>
        <div class="login-note">
          <el-icon><Lock /></el-icon
          ><span
            >首次使用？请通过容器或本地 CLI 初始化管理员。<code
              >python -m app.cli init-admin</code
            ></span
          >
        </div>
      </div>
      <small class="login-copyright">MCP Asset Gateway · v2.0</small>
    </section>
  </div>
  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-symbol"><Connection /></div>
        <div><strong>MCP 资产网关</strong><small>ASSET GATEWAY</small></div>
      </div>
      <div class="workspace-tag">
        <span class="workspace-dot"></span> 默认工作空间
        <span class="tag-mini">LOCAL</span>
      </div>
      <p class="nav-caption">工作空间</p>
      <nav>
        <button
          v-for="(item, index) in menu"
          :key="item.id"
          :aria-label="item.name"
          :title="item.name"
          :class="{ active: active === item.id, 'nav-separated': index === 5 }"
          @click="navigate(item.id)"
        >
          <el-icon><component :is="item.icon" /></el-icon
          ><span>{{ item.name }}</span
          ><span v-if="item.id === 'assets'" class="nav-count">{{
            entities.assets.length
          }}</span>
        </button>
      </nav>
      <div class="sidebar-bottom">
        <div class="secure-note">
          <el-icon><Lock /></el-icon>
          <div>
            <strong>最小权限，默认拒绝</strong><small>凭据始终留在网关侧</small>
          </div>
        </div>
        <button class="profile" @click="passwordOpen = true">
          <span class="avatar">{{
            user.username.slice(0, 1).toUpperCase()
          }}</span
          ><span
            ><strong>{{ user.username }}</strong
            ><small>工作空间管理员</small></span
          ><el-icon><Setting /></el-icon>
        </button>
      </div>
    </aside>
    <div class="main-shell">
      <header class="topbar">
        <div class="breadcrumb">
          工作空间 <span>/</span> <strong>{{ current.name }}</strong>
        </div>
        <div class="top-actions">
          <span class="runtime-badge"><i></i> 单实例 · SQLite WAL</span
          ><el-button text :icon="SwitchButton" @click="logout">退出</el-button>
        </div>
      </header>
      <main>
        <section class="page-heading">
          <div>
            <span class="eyebrow">{{
              active === "dashboard" ? "WORKSPACE OVERVIEW" : "ASSET GATEWAY"
            }}</span>
            <h1>{{ current.name }}</h1>
            <p>{{ current.caption }}</p>
          </div>
          <div class="heading-actions">
            <el-button :icon="Refresh" :loading="busy" @click="navigate(active)"
              >刷新</el-button
            ><el-button
              v-if="crud"
              type="primary"
              :icon="Plus"
              @click="openEdit()"
              >{{
                {
                  assets: "添加资产",
                  accounts: "添加账号",
                  clients: "创建客户端",
                  grants: "创建授权组",
                }[active]
              }}</el-button
            >
          </div>
        </section>
        <template v-if="active === 'dashboard'">
          <div class="welcome-banner">
            <div>
              <span class="banner-label"><span></span> 统一资产访问入口</span>
              <h2>让工具访问安全、有序、可见。</h2>
              <p>从登记第一个资产开始，为你的智能体建立可控的数据连接。</p>
              <el-button @click="navigate('assets')"
                >管理资产 <el-icon><ArrowRight /></el-icon
              ></el-button>
            </div>
            <div class="gateway-graphic">
              <div class="graphic-core"><Connection /></div>
              <span class="graphic-node n1"><Coin /></span
              ><span class="graphic-node n2"><Monitor /></span
              ><span class="graphic-node n3"><FolderOpened /></span
              ><span class="graphic-node n4"><Connection /></span>
            </div>
          </div>
          <div class="stats-grid">
            <div
              v-for="(card, i) in [
                {
                  name: '已登记资产',
                  value: entities.assets.length,
                  note: '四种资产类型',
                  icon: Grid,
                },
                {
                  name: '托管账号',
                  value: entities.accounts.length,
                  note: '凭据加密存储',
                  icon: Key,
                },
                {
                  name: '业务客户端',
                  value: entities.clients.length,
                  note: '独立 token 身份',
                  icon: Connection,
                },
                {
                  name: '近期审计事件',
                  value: totalCalls,
                  note: '最近 24 小时',
                  icon: Tickets,
                },
              ]"
              :key="card.name"
              class="stat-card"
            >
              <div class="stat-top">
                <span>{{ card.name }}</span>
                <div
                  :class="[
                    'stat-icon',
                    ['violet', 'blue', 'green', 'amber'][i],
                  ]"
                >
                  <component :is="card.icon" />
                </div>
              </div>
              <strong>{{ card.value }}</strong
              ><small>{{ card.note }}</small>
            </div>
          </div>
          <div class="dashboard-grid">
            <section class="panel">
              <div class="panel-header">
                <div>
                  <h3>资产类型</h3>
                  <p>一个入口，连接不同的资源</p>
                </div>
                <span class="tag-mini">{{ types.length }} TYPES</span>
              </div>
              <div class="type-grid">
                <button
                  v-for="type in types"
                  :key="type.type_id"
                  class="type-tile"
                  @click="
                    navigate('assets');
                    kindFilter = type.type_id;
                  "
                >
                  <span :class="['type-icon', kindColors[type.type_id]]"
                    ><component :is="kindIcons[type.type_id]" /></span
                  ><strong>{{ type.display_name }}</strong
                  ><span
                    >{{
                      entities.assets.filter((a) => a.type === type.type_id)
                        .length
                    }}
                    个资产</span
                  ><el-icon><ArrowRight /></el-icon>
                </button>
              </div>
            </section>
            <section class="panel">
              <div class="panel-header">
                <div>
                  <h3>访问活动</h3>
                  <p>最近 7 个自然日的工具调用（UTC，含今天）</p>
                </div>
                <el-icon class="muted"><DataAnalysis /></el-icon>
              </div>
              <div v-if="dashboard.daily.some((day) => day.total)" class="mini-chart">
                <div
                  v-for="day in dashboard.daily"
                  :key="day.day"
                  class="chart-column"
                >
                  <strong>{{ day.total }}</strong
                  ><i
                    :style="{
                      height: `${Math.max(2, (day.total / Math.max(1, ...dashboard.daily.map((d) => d.total))) * 90)}px`,
                    }"
                  ></i
                  ><span>{{ day.day.slice(5) }}</span>
                </div>
              </div>
              <div v-else class="activity-empty">
                <span class="empty-circle"><DataAnalysis /></span
                ><strong>还没有工具调用</strong>
                <p>连接客户端后，访问活动会显示在这里。</p>
              </div>
            </section>
          </div>
          <section class="panel audit-overview">
            <div class="panel-header">
              <div><h3>工具调用概况</h3><p>最近 24 小时 · 仅 tools.call（含管理调试）；成功率不含执行中调用</p></div>
              <el-button link type="primary" @click="inspectCalls()">查看调用审计</el-button>
            </div>
            <div class="stats-grid call-metrics">
              <div v-for="metric in [
                { name: '调用次数', value: dashboard.calls.total ?? 0 },
                { name: '已完成成功率', value: dashboard.calls.success_rate == null ? '—' : `${dashboard.calls.success_rate}%` },
                { name: '异常与拒绝', value: callFailures },
                { name: '平均耗时（ms）', value: dashboard.calls.average_elapsed_ms ?? '—' },
              ]" :key="metric.name" class="stat-card">
                <span class="muted">{{ metric.name }}</span><strong>{{ metric.value }}</strong>
              </div>
            </div>
            <div class="status-summary">
              <el-button v-for="(text, status) in statusLabels" :key="status" plain size="small" @click="inspectCalls({ status })">
                {{ text }} {{ dashboard.calls.statuses[status] || 0 }}
              </el-button>
            </div>
          </section>
          <div class="dashboard-grid">
            <section v-for="ranking in [
              { title: '热门工具', field: 'tool', rows: dashboard.top_tools },
              { title: '活跃客户端', field: 'client_id', rows: dashboard.top_clients },
            ]" :key="ranking.field" class="panel ranking-panel">
              <div class="panel-header"><div><h3>{{ ranking.title }}</h3><p>最近 24 小时 · 前 5 名 · 点击名称查看审计</p></div></div>
              <el-table :data="ranking.rows" empty-text="暂无工具调用">
                <el-table-column label="名称" min-width="170"><template #default="{ row }">
                  <el-button link type="primary" @click="inspectCalls({ [ranking.field]: row.name })">{{ ranking.field === 'client_id' ? label('clients', row.name) : text(row.name) }}</el-button>
                </template></el-table-column>
                <el-table-column prop="total" label="调用" width="90" />
                <el-table-column prop="failures" label="异常" width="90" />
              </el-table>
            </section>
          </div>
          <section class="panel connect-panel">
            <div class="connect-icon"><Connection /></div>
            <div>
              <h3>准备好连接你的智能体了吗？</h3>
              <p>
                创建客户端并配置授权，然后将统一 MCP 地址添加到 FastGPT
                或其他客户端。
              </p>
              <code>{{ endpoint }}</code>
            </div>
            <el-button type="primary" plain @click="navigate('clients')"
              >创建客户端 <el-icon><ArrowRight /></el-icon
            ></el-button>
          </section>
        </template>
        <section v-else-if="crud" class="panel table-panel" v-loading="busy">
          <div class="table-toolbar">
            <div v-if="!(active === 'grants' && matrixMode)" class="toolbar-filters">
              <el-input
                v-model="query"
                placeholder="搜索名称或关联对象…"
                :prefix-icon="Search"
                clearable
                @input="resetPages"
              /><el-select
                v-if="active === 'assets'"
                v-model="kindFilter"
                placeholder="所有资产类型"
                clearable
                @change="page = 1"
                ><el-option
                  v-for="type in types"
                  :key="type.type_id"
                  :label="type.display_name"
                  :value="type.type_id"
              /></el-select>
              <template v-if="active === 'grants'">
                <el-input
                  v-model="matrixFilter.client"
                  class="filter-input"
                  placeholder="按客户端搜索"
                  :prefix-icon="Search"
                  clearable
                  @input="resetPages"
                /><el-input
                  v-model="matrixFilter.asset"
                  class="filter-input"
                  placeholder="按资产搜索"
                  :prefix-icon="Search"
                  clearable
                  @input="resetPages"
                /><el-input
                  v-model="matrixFilter.account"
                  class="filter-input"
                  placeholder="按账号搜索"
                  :prefix-icon="Search"
                  clearable
                  @input="resetPages"
                />
              </template>
            </div>
            <el-switch
              v-if="active === 'grants'"
              v-model="matrixMode"
              active-text="矩阵视图"
              @change="matrixPage = 1"
            /><span v-else class="muted">共 {{ filtered.length }} 条记录</span>
          </div>
          <div v-if="active === 'grants' && matrixMode" class="matrix-wrap">
            <div class="matrix-toolbar">
              <el-input
                v-model="matrixFilter.client"
                placeholder="按客户端搜索"
                :prefix-icon="Search"
                clearable
                @input="matrixPage = 1"
              /><el-input
                v-model="matrixFilter.asset"
                placeholder="按资产搜索"
                :prefix-icon="Search"
                clearable
                @input="matrixPage = 1"
              /><el-input
                v-model="matrixFilter.account"
                placeholder="按账号搜索"
                :prefix-icon="Search"
                clearable
                @input="matrixPage = 1"
              />
            </div>
            <p class="matrix-help">格内展示启用组为该账号配置的工具并集；实际调用还受参数黑白名单、资产类型、启用状态和目录版本限制，可在调试台确认。</p>
            <table class="matrix">
              <thead>
                <tr>
                  <th>客户端 / 资产账号</th>
                  <th v-for="account in matrixAccounts" :key="account.id">
                    {{ account.name
                    }}<small>{{ label("assets", account.asset_id) }}</small>
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="client in matrixRows" :key="client.id">
                  <th>{{ client.name }}</th>
                  <td
                    v-for="account in matrixAccounts"
                    :key="account.id"
                    class="matrix-cell"
                    title="查看关联授权组或创建新的授权组"
                    @click="openGrantCell(client, account)"
                  >
                    <el-tag
                      v-for="name in grantsFor(client.id, account.id)"
                      :key="name"
                      size="small"
                      >{{ text(name) }}</el-tag
                    ><span
                      v-if="!grantsFor(client.id, account.id).length"
                      class="muted"
                      >未授权</span
                    >
                    <small class="matrix-group-count">{{ groupsFor(entities.grants, client.id, account.id).length }} 个关联组 · 点击管理</small>
                  </td>
                </tr>
              </tbody>
            </table>
            <el-empty
              v-if="!matrixClients.length || !matrixAccounts.length"
              :description="
                matrixSearching
                  ? '没有匹配的客户端或资产账号'
                  : '先创建客户端和资产账号，再建立授权'
              "
            />
          </div>
          <el-table v-else :data="visible" row-key="id" style="width: 100%">
            <el-table-column
              :label="active === 'grants' ? '授权组名称' : '名称'"
              min-width="230"
              ><template #default="{ row }"
                ><div class="name-cell">
                  <span
                    v-if="active === 'assets'"
                    :class="['type-icon small', kindColors[row.type]]"
                    ><component :is="kindIcons[row.type]"
                  /></span>
                  <div>
                    <strong>{{ row.name }}</strong>
                  </div>
                </div></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'assets'"
              label="类型"
              min-width="130"
              ><template #default="{ row }"
                ><el-tag effect="plain">{{
                  row.type.toUpperCase()
                }}</el-tag></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'assets'"
              label="连接地址"
              min-width="200"
              ><template #default="{ row }"
                ><code>{{ addressOf(row) }}</code></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'accounts'"
              label="所属资产"
              min-width="160"
              ><template #default="{ row }">{{
                label("assets", row.asset_id)
              }}</template></el-table-column
            >
            <el-table-column
              v-if="active === 'accounts'"
              label="凭据状态"
              min-width="120"
              ><template #default="{ row }"
                ><span class="credential-badge"
                  ><el-icon><Lock /></el-icon
                  >{{
                    row.credential_present ? "已加密托管" : "无需凭据"
                  }}</span
                ></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'clients'"
              label="Token"
              min-width="150"
              ><template #default="{ row }"
                ><code>tok_•••• {{ row.token_tail }}</code></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'clients'"
              label="有效期"
              min-width="175"
              ><template #default="{ row }">{{
                row.token_expires_at ? date(row.token_expires_at) : "无到期时间"
              }}</template></el-table-column
            >
            <el-table-column
              v-if="active === 'grants'"
              label="客户端"
              min-width="150"
              ><template #default="{ row }"
                ><div class="tool-tags">
                  <el-tag
                    v-for="id in row.client_ids"
                    :key="id"
                    size="small"
                    effect="plain"
                    >{{ label("clients", id) }}</el-tag
                  ><span v-if="!row.client_ids?.length" class="muted">—</span>
                </div></template
              ></el-table-column
            >
            <el-table-column
              v-if="active === 'grants'"
              label="资产账号"
              min-width="200"
              ><template #default="{ row }"
                ><div class="tool-tags">
                  <el-tag
                    v-for="id in row.account_ids"
                    :key="id"
                    size="small"
                    effect="plain"
                    >{{ accountLabel(id) }}</el-tag
                  ><span v-if="!row.account_ids?.length" class="muted">—</span>
                </div></template
              ></el-table-column
            >
            <el-table-column label="状态" width="100"
              ><template #default="{ row }"
                ><span
                  :class="['status-pill', row.enabled ? 'enabled' : 'disabled']"
                  ><i></i>{{ row.enabled ? "已启用" : "已禁用" }}</span
                ></template
              ></el-table-column
            >
            <el-table-column
              label="操作"
              :min-width="
                active === 'accounts' || active === 'clients' ? 255 : 180
              "
              fixed="right"
              ><template #default="{ row }"
                ><el-button link type="primary" @click="openEdit(row)"
                  >编辑</el-button
                ><el-button
                  v-if="active === 'accounts'"
                  link
                  type="primary"
                  @click="testAccount(row)"
                  >测试连接</el-button
                ><el-button
                  v-if="active === 'clients'"
                  link
                  type="primary"
                  @click="rotate(row)"
                  >轮换</el-button
                ><el-button link @click="toggle(row)">{{
                  row.enabled ? "禁用" : "启用"
                }}</el-button
                ><el-button link type="danger" @click="remove(row)"
                  >删除</el-button
                ></template
              ></el-table-column
            >
            <template #empty
              ><div class="table-empty">
                <span class="empty-circle"
                  ><component :is="current.icon"
                /></span>
                <h3>
                  {{
                    query || ((active === 'grants' && matrixSearching) || kindFilter)
                      ? "没有找到匹配的记录"
                      : `还没有${current.name === "授权矩阵" ? "授权关系" : current.name.replace("管理", "")}`
                  }}
                </h3>
                <p>
                  {{
                    query || ((active === 'grants' && matrixSearching) || kindFilter)
                      ? "尝试更换搜索条件。"
                      : "点击右上角按钮，开始建立你的资产访问体系。"
                  }}
                </p>
                <el-button
                  v-if="!query && !((active === 'grants' && matrixSearching) || kindFilter)"
                  type="primary"
                  plain
                  :icon="Plus"
                  @click="openEdit()"
                  >添加第一条记录</el-button
                >
              </div></template
            >
          </el-table>
          <div class="table-footer">
            <span>更改保存后，对新的工具请求即时生效</span>
            <el-pagination
              v-if="!(active === 'grants' && matrixMode)"
              v-model:current-page="page"
              v-model:page-size="pageSize"
              :page-sizes="[10, 20, 50]"
              :total="filtered.length"
              layout="total, sizes, prev, pager, next"
              @size-change="page = 1"
            />
            <el-pagination
              v-else
              v-model:current-page="matrixPage"
              v-model:page-size="pageSize"
              :page-sizes="[10, 20, 50]"
              :total="matrixClients.length"
              layout="total, sizes, prev, pager, next"
              @size-change="matrixPage = 1"
            />
          </div>
        </section>
        <section
          v-else-if="active === 'audit'"
          class="panel table-panel"
          v-loading="busy"
        >
          <div class="audit-filters">
            <el-select v-model="auditFilter.asset_id" clearable placeholder="所有资产">
              <el-option v-for="asset in entities.assets" :key="asset.id" :label="asset.name" :value="asset.id" />
            </el-select>
            <el-select v-model="auditFilter.source" clearable placeholder="所有来源">
              <el-option v-for="source in ['mcp', 'ui', 'system']" :key="source" :label="source" :value="source" />
            </el-select>
            <el-input v-model="auditFilter.event" clearable placeholder="事件名称" />
            <el-select
              v-model="auditFilter.client_id"
              clearable
              placeholder="所有客户端"
              ><el-option
                v-for="client in entities.clients"
                :key="client.id"
                :label="client.name"
                :value="client.id" /></el-select
            ><el-select
              v-model="auditFilter.status"
              clearable
              placeholder="所有状态"
              ><el-option
                v-for="status in [
                  'ok',
                  'error',
                  'denied',
                  'timeout',
                  'interrupted',
                  'started',
                ]"
                :key="status"
                :label="status"
                :value="status" /></el-select
            ><el-input
              v-model="auditFilter.tool"
              placeholder="工具名称"
              clearable
            /><el-date-picker
              v-model="auditFilter.start"
              type="datetime"
              value-format="x"
              placeholder="开始时间"
            /><el-date-picker
              v-model="auditFilter.end"
              type="datetime"
              value-format="x"
              placeholder="结束时间"
            /><el-button
              type="primary"
              @click="
                auditHistory = [];
                run(() => loadAudit());
              "
              >查询</el-button
            ><el-button @click="exportAudit">导出 CSV</el-button>
          </div>
          <el-table :data="auditRows"
            ><el-table-column label="时间" min-width="190"
              ><template #default="{ row }">{{
                date(row.ts)
              }}</template></el-table-column
            ><el-table-column
              prop="event"
              label="事件"
              min-width="170" /><el-table-column
              prop="source"
              label="来源"
              width="90" /><el-table-column label="客户端" min-width="140"
              ><template #default="{ row }">{{
                auditClientName(row)
              }}</template></el-table-column
            ><el-table-column label="工具" min-width="160">
              <template #default="{ row }">{{ text(row.tool) }}</template>
            </el-table-column><el-table-column label="状态" width="110"
              ><template #default="{ row }"
                ><el-tag
                  :type="
                    row.status === 'ok'
                      ? 'success'
                      : row.status === 'started'
                        ? 'info'
                        : 'warning'
                  "
                  size="small"
                  >{{ row.status }}</el-tag
                ></template
              ></el-table-column
            ><el-table-column label="耗时" width="100"
              ><template #default="{ row }"
                >{{ row.elapsed_ms ?? "—" }} ms</template
              ></el-table-column
            ><el-table-column width="80"
              ><template #default="{ row }"
                ><el-button link type="primary" @click="showDetail(row)"
                  >详情</el-button
                ></template
              ></el-table-column
            ><template #empty
              ><el-empty description="所选范围内暂无审计事件" /></template
          ></el-table>
          <div class="table-footer">
            <span>只保存脱敏参数摘要，不保存工具返回正文</span>
            <div>
              <el-button :disabled="!auditHistory.length" @click="prevAudit"
                >上一页</el-button
              ><el-button :disabled="!auditCursor" @click="nextAudit"
                >下一页</el-button
              >
            </div>
          </div>
        </section>
        <template v-else-if="active === 'debug'"
          ><el-alert
            title="真实调用，真实授权。执行前请确认影响范围；网关不会自动重试工具调用。"
            type="warning"
            :closable="false"
            show-icon
          />
          <div class="debug-grid">
            <section class="panel">
              <div class="panel-header">
                <h3>调用配置</h3>
                <span class="tag-mini">MCP</span>
              </div>
              <el-form label-position="top" class="padded-form"
                ><el-form-item label="模拟客户端"
                  ><el-select
                    v-model="debugClient"
                    placeholder="选择客户端"
                    @change="getDebugTools"
                    ><el-option
                      v-for="client in entities.clients.filter(
                        (c) => c.enabled,
                      )"
                      :key="client.id"
                      :label="client.name"
                      :value="client.id" /></el-select></el-form-item
                ><el-form-item label="已授权工具"
                  ><el-select
                    v-model="debugTool"
                    placeholder="选择工具"
                    @change="selectDebug"
                    ><el-option
                      v-for="item in debugTools"
                      :key="item.name"
                      :label="text(item.name)"
                      :value="item.name"
                  /></el-select>
                  <p
                    v-if="debugClient && !debugTools.length"
                    class="field-hint"
                  >
                    当前客户端没有可用工具。请检查授权、账号状态与上游目录。
                  </p></el-form-item
                >
                <p class="muted">{{ text(selectedDebug?.description) }}</p>
                <el-form-item v-if="debugTargets.length" label="目标资产账号" required>
                  <el-select v-model="debugTarget" placeholder="选择目标资产账号">
                    <el-option v-for="id in debugTargets" :key="id" :label="accountLabel(id)" :value="id" />
                  </el-select>
                </el-form-item>
                <el-form-item label="参数（JSON）"
                  ><el-input
                    v-model="debugArguments"
                    type="textarea"
                    :rows="10"
                    class="code-input" /></el-form-item
                ><el-collapse v-if="selectedDebug"
                  ><el-collapse-item title="查看工具输入 schema">
                    <pre>{{ pretty(named(selectedDebug.inputSchema)) }}</pre>
                  </el-collapse-item></el-collapse
                ><el-button
                  class="execute-button"
                  type="primary"
                  :icon="VideoPlay"
                  :loading="busy"
                  :disabled="!debugTool"
                  @click="executeDebug"
                  >执行工具</el-button
                ></el-form
              >
            </section>
            <section class="panel debug-output">
              <div class="panel-header">
                <h3>调用结果</h3>
                <el-tag
                  v-if="debugResult"
                  :type="debugResult.isError ? 'warning' : 'success'"
                  >{{ debugResult.isError ? "执行失败" : "执行完成" }}</el-tag
                >
              </div>
              <pre v-if="debugResult">{{ pretty(debugResult) }}</pre>
              <div v-else class="activity-empty">
                <span class="empty-circle"><Document /></span
                ><strong>等待工具执行</strong>
                <p>结果将在这里显示，并生成审计记录。</p>
              </div>
            </section>
          </div></template
        >
        <template v-else-if="active === 'settings'"
          ><div class="settings-grid">
            <section class="panel">
              <div class="panel-header">
                <div>
                  <h3>资源与保留策略</h3>
                  <p>账号可覆盖为更严格的上限</p>
                </div>
              </div>
              <el-form label-position="top" class="padded-form"
                ><el-form-item
                  v-for="item in settings"
                  :key="item.key"
                  :label="
                    {
                      query_timeout_seconds: '工具调用总期限（秒）',
                      connect_timeout_seconds: '连接超时（秒）',
                      max_result_rows: '查询结果最大行数',
                      max_output_bytes: '工具输出字节上限',
                      max_cell_chars: '单元格最大字符数',
                      audit_retention_days: '审计保留天数',
                    }[item.key]
                  "
                  ><el-input-number
                    v-model="item.value"
                    :min="1"
                    controls-position="right" /></el-form-item
                ><el-button
                  type="primary"
                  :loading="busy"
                  @click="
                    run(async () => {
                      settings = await api('/settings', {
                        method: 'PATCH',
                        body: settings,
                      });
                      ElMessage.success('设置已保存');
                    })
                  "
                  >保存设置</el-button
                ></el-form
              >
            </section>
            <div>
              <section class="panel safety-card">
                <span class="type-icon violet"><Lock /></span>
                <h3>安全，从默认配置开始</h3>
                <p>
                  凭据经 Fernet
                  加密后入库。令牌只保存摘要，无法从控制台恢复原值。
                </p>
                <ul>
                  <li>主密钥必须与数据库独立备份</li>
                  <li>出站目标通过部署环境允许列表配置</li>
                  <li>远程访问请启用 TLS 与防火墙</li>
                  <li>SQLite 数据卷仅支持单运行实例</li>
                </ul>
              </section>
              <section class="panel safety-card">
                <h3>备份与恢复</h3>
                <p>
                  运行期间自动保留 7 份日备份、4 份周备份。也可使用 CLI
                  创建一致备份：
                </p>
                <code>python -m app.cli backup backups/manual.sqlite</code>
                <p>
                  恢复前停止应用，并核对镜像版本、数据库与主密钥。不要直接复制活跃的
                  WAL 数据库。
                </p>
              </section>
            </div>
          </div></template
        >
        <footer class="page-footer">
          <span>MCP Asset Gateway <span class="muted">/</span> v0.1.0</span
          ><span>统一连接 · 精确授权 · 可追溯访问</span>
        </footer>
      </main>
    </div>
  </div>
  <el-dialog
    v-model="editOpen"
    :title="`${original ? '编辑' : '新建'}${{ assets: '资产', accounts: '账号', clients: '客户端', grants: '授权组' }[editTable]}`"
    :width="editTable === 'grants' ? '960px' : '680px'"
    :close-on-click-modal="false"
    @closed="editClosed"
  >
    <el-form label-position="top" @submit.prevent="save">
      <div class="form-grid">
        <el-form-item :label="editTable === 'grants' ? '授权组名称' : '显示名称'" required
          ><el-input v-model="form.name" maxlength="100" /></el-form-item
      ></div>
      <template v-if="editTable === 'assets'"
        ><el-form-item label="资产类型"
          ><el-select
            v-model="form.type"
            :disabled="Boolean(original)"
            @change="typeChanged"
            ><el-option
              v-for="type in types"
              :key="type.type_id"
              :label="type.display_name"
              :value="type.type_id" /></el-select></el-form-item
        ><el-alert
          title="连接参数中不要填入密码；目标地址需可由本网关正常访问。"
          type="info"
          :closable="false" /><SchemaForm
          v-if="selectedType"
          v-model="form.connection"
          :schema="selectedType.connection_schema"
      /></template>
      <template v-if="editTable === 'accounts'"
        ><el-form-item label="所属资产" required
          ><el-select
            v-model="form.asset_id"
            :disabled="Boolean(original)"
            placeholder="选择资产"
            @change="accountAssetChanged"
            ><el-option
              v-for="asset in entities.assets"
              :key="asset.id"
              :label="`${asset.name} · ${asset.type}`"
              :value="asset.id" /></el-select></el-form-item
        ><template v-if="selectedType"
          ><h4>账号配置</h4>
          <SchemaForm
            v-model="form.config"
            :schema="selectedType.account_schema" />
          <h4>
            托管凭据
            <el-switch
              v-if="original"
              v-model="replaceCredential"
              active-text="替换凭据"
            />
          </h4>
          <el-alert
            v-if="original && !replaceCredential"
            title="凭据不会回读。开启「替换凭据」后填写新的完整认证信息。"
            type="info"
            :closable="false" /><SchemaForm
            v-else
            v-model="credential"
            :schema="selectedType.credential_schema" />
          <h4>访问策略</h4>
          <SchemaForm
            v-model="form.policy"
            :schema="selectedType.policy_schema" /><el-alert
            v-if="selectedType.type_id === 'filebrowser'"
            title="强路径隔离依赖远端 chroot 与低权限账号，路径检查不能替代文件系统沙箱。"
            type="warning"
            :closable="false" /><el-alert
            v-if="selectedType.type_id === 'ssh'"
            title="初版仅开放 uname / uptime / df / free / id / whoami / ps 的固定绝对路径命令；每行一个完整命令，默认全拒。"
            type="info"
            :closable="false" /></template
        ><el-form-item label="账号说明"
          ><el-input
            v-model="form.note"
            type="textarea"
            maxlength="500" /></el-form-item
      ></template>
      <template v-if="editTable === 'clients'"
        ><el-form-item label="令牌到期时间（可选）"
          ><el-date-picker
            v-model="form.token_expires_at"
            type="datetime"
            value-format="x"
            placeholder="不设置则无固定有效期" /></el-form-item
        ><el-alert
          title="新客户端默认没有任何资产权限。令牌只展示一次，请保存后继续配置授权。"
          type="info"
          :closable="false"
      /></template>
      <template v-if="editTable === 'grants'">
        <div class="grant-board">
          <div class="grant-board-list">
            <div class="grant-panel">
              <div class="grant-panel-head">
                <h4>客户端</h4>
                <el-input
                  v-model="grantSearch.client"
                  size="small"
                  clearable
                  placeholder="搜索客户端"
                  class="grant-search"
                  ><template #prefix><el-icon><Search /></el-icon></template></el-input
                >
              </div>
              <el-table
                :data="grantClientRows"
                size="small"
                max-height="240"
                empty-text="尚未添加客户端"
              >
                <el-table-column prop="name" label="客户端" />
                <el-table-column label="操作" width="72" align="center">
                  <template #default="{ row }"
                    ><el-button
                      type="danger"
                      :icon="Minus"
                      circle
                      size="small"
                      :disabled="busy"
                      @click="removeGrantClient(row.id)"
                  /></template>
                </el-table-column>
              </el-table>
              <p class="grant-total">共 {{ grantClientRows.length }} 条</p>
            </div>
            <div class="grant-panel">
              <div class="grant-panel-head">
                <h4>资产账号-工具</h4>
                <div class="header-actions">
                  <el-input
                    v-model="grantSearch.account"
                    size="small"
                    clearable
                    placeholder="搜索账号"
                    class="grant-search"
                    ><template #prefix><el-icon><Search /></el-icon></template></el-input
                  ><el-button
                    v-if="form.entries?.some((entry) => accountKind(entry.account_id) === 'mcp')"
                    size="small"
                    :loading="busy"
                    @click="loadGrantCatalog(true)"
                    >刷新上游目录</el-button
                  >
                </div>
              </div>
              <el-table
                :data="grantEntryRows"
                size="small"
                max-height="260"
                empty-text="尚未添加资产账号"
              >
                <el-table-column prop="label" label="资产账号" />
                <el-table-column label="工具" width="130"
                  ><template #default="{ row }"
                    ><el-tag v-if="row.unlisted" type="danger" size="small"
                      >{{ row.tools }} 个 · {{ row.unlisted }} 个已失效</el-tag
                    ><el-tag v-else-if="!row.tools" type="info" size="small">未配置</el-tag
                    ><el-tag v-else type="success" size="small">{{ row.tools }} 个</el-tag></template
                  ></el-table-column
                >
                <el-table-column label="操作" width="96" align="center">
                  <template #default="{ row }"
                    ><el-button
                      :icon="Setting"
                      circle
                      size="small"
                      :disabled="busy"
                      title="配置工具"
                      @click="openToolDialog(row.index)"
                    /><el-button
                      type="danger"
                      :icon="Minus"
                      circle
                      size="small"
                      :disabled="busy"
                      @click="removeGrantEntry(row.index)"
                  /></template>
                </el-table-column>
              </el-table>
              <p class="grant-total">共 {{ grantEntryRows.length }} 条</p>
            </div>
            <el-alert
              v-if="original"
              title="修改成员、工具或参数规则会影响本组全部客户端。黑名单跨适用组优先；移除黑名单可能放宽权限。"
              type="info"
              :closable="false"
            /><el-alert
              v-if="catalogStale"
              title="上游目录已过期。请先刷新并确认工具定义后再授权。"
              type="warning"
              :closable="false"
            /><small class="muted"
              >没有勾选工具表示没有权限；新增工具不会自动进入白名单。可先创建空组再逐步关联，不同组允许重复关联，白名单按完整组条件取并集，黑名单跨适用组优先。</small
            >
          </div>
          <div class="grant-board-side">
            <div class="grant-add-card add-client">
              <div class="grant-add-head">
                <el-icon><Connection /></el-icon><span>添加客户端</span>
              </div>
              <div class="grant-add-body">
                <el-select
                  v-model="pendingGrant.client"
                  filterable
                  placeholder="请选择"
                  style="width: 100%"
                  ><el-option
                    v-for="client in availableGrantClients"
                    :key="client.id"
                    :label="client.name"
                    :value="client.id" /></el-select
                ><el-button
                  type="success"
                  :disabled="!pendingGrant.client"
                  @click="addGrantClient"
                  >添加</el-button
                >
              </div>
            </div>
            <div class="grant-add-card add-account">
              <div class="grant-add-head">
                <el-icon><Key /></el-icon><span>添加资产账号</span>
              </div>
              <div class="grant-add-body">
                <el-select
                  v-model="pendingGrant.account"
                  filterable
                  placeholder="请选择"
                  style="width: 100%"
                  ><el-option
                    v-for="account in availableGrantAccounts"
                    :key="account.id"
                    :label="accountLabel(account.id)"
                    :value="account.id" /></el-select
                ><el-button
                  type="primary"
                  :disabled="!pendingGrant.account"
                  @click="addGrantEntry"
                  >添加</el-button
                >
              </div>
            </div>
          </div>
        </div>
      </template>
      <el-form-item label="状态"
        ><el-switch
          v-model="form.enabled"
          active-text="启用"
          inactive-text="禁用"
      /></el-form-item> </el-form
    ><template #footer
      ><el-button @click="editOpen = false">取消</el-button
      ><el-button type="primary" :loading="busy" @click="save"
        >保存{{ editTable === "grants" ? "授权组" : "" }}</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="toolOpen"
    title="配置工具"
    width="720px"
    append-to-body
    :close-on-click-modal="false"
  >
    <template v-if="toolEntry">
      <p class="muted tool-dialog-title">{{ accountLabel(toolEntry.account_id) }}</p>
      <div class="grant-entry-tools">
        <el-button
          size="small"
          :disabled="!catalogReady || !entryCatalog(toolEntry).length"
          @click="toolEntry.tools = entryCatalog(toolEntry).map((tool) => tool.name)"
          >全选</el-button
        ><el-button
          size="small"
          :disabled="!toolEntry.tools.length"
          @click="toolEntry.tools = []"
          >取消全选</el-button
        >
      </div>
      <el-alert
        v-if="catalogStale"
        title="上游目录已过期。请先刷新并确认工具定义后再授权。"
        type="warning"
        :closable="false"
      />
      <el-checkbox-group v-model="toolEntry.tools" class="tool-options"
        ><div v-for="item in entryCatalog(toolEntry)" :key="item.name" class="tool-option">
          <el-checkbox :value="item.name">{{ text(item.name) }}</el-checkbox>
          <p>{{ text(item.description) }}</p>
          <ToolRules
            v-if="toolEntry.tools.includes(item.name)"
            :model-value="toolEntry.parameter_rules[item.name] || {}"
            :schema="item.inputSchema"
            @update:model-value="toolEntry.parameter_rules = { ...toolEntry.parameter_rules, [item.name]: $event }"
          />
          <el-tag
            v-if="
              original?.tool_versions?.[toolEntry.account_id]?.[item.name] &&
              original.tool_versions[toolEntry.account_id][item.name] !== item.spec_hash
            "
            type="warning"
            size="small"
            >定义已变化，需重新批准</el-tag
          >
          <el-collapse
            ><el-collapse-item title="查看 schema 与版本">
              <pre>{{
                pretty(
                  named({
                    inputSchema: item.inputSchema,
                    outputSchema: item.outputSchema,
                    spec_hash: item.spec_hash,
                  })
                )
              }}</pre>
            </el-collapse-item></el-collapse
          >
        </div></el-checkbox-group
      >
      <div v-if="toolUnlisted.length" class="tool-option">
        <p class="muted">以下已选工具不在该账号的目录中，请移除后保存：</p>
        <el-tag
          v-for="name in toolUnlisted"
          :key="name"
          size="small"
          closable
          @close="toolEntry.tools = toolEntry.tools.filter((tool) => tool !== name)"
          >{{ text(name) }}</el-tag
        >
      </div>
      <el-empty
        v-if="catalogReady && !entryCatalog(toolEntry).length"
        description="该账号暂无可用工具；MCP 账号请关闭后点击列表上方“刷新上游目录”重试"
      />
      <small class="muted"
        >没有勾选工具表示没有权限；新增工具不会自动进入白名单。</small
      >
    </template>
    <template #footer
      ><el-button type="primary" @click="toolOpen = false">完成</el-button></template
    >
  </el-dialog>
  <el-dialog v-model="cellOpen" title="关联授权组" width="680px">
    <p>{{ cellClient?.name }} × {{ accountLabel(cellAccount?.id) }}</p>
    <p class="muted">工具权限取启用组并集；参数黑名单优先，白名单按完整组条件取并集。可编辑指定组或创建新组。</p>
    <el-table :data="cellGroups" row-key="id">
      <el-table-column prop="name" label="授权组名称" />
      <el-table-column label="状态" width="80"><template #default="{ row }">{{ row.enabled ? '启用' : '禁用' }}</template></el-table-column>
      <el-table-column label="工具"><template #default="{ row }">{{ (row.entries?.find((entry) => entry.account_id === cellAccount?.id)?.tools || []).map(text).join("、") || "无工具权限" }}</template></el-table-column>
      <el-table-column width="80"><template #default="{ row }"><el-button link type="primary" @click="editCellGroup(row)">编辑</el-button></template></el-table-column>
    </el-table>
    <template #footer><el-button @click="cellOpen = false">关闭</el-button><el-button type="primary" @click="newCellGroup">创建授权组</el-button></template>
  </el-dialog>
  <el-dialog
    v-model="tokenOpen"
    title="请保存客户端令牌"
    width="620px"
    :close-on-click-modal="false"
    @closed="
      token = '';
      tokenName = '';
    "
    ><el-alert
      title="令牌仅展示这一次，关闭后无法找回。请勿发送到日志或代码仓库。"
      type="warning"
      :closable="false"
      show-icon
    />
    <p class="muted">
      将以下配置添加到 MCP 客户端（Claude、Cursor、FastGPT 等）即可接入：
    </p>
    <pre class="token-value">{{ mcpConfig }}</pre>
    <template #footer
      ><el-button @click="copyText(token)">复制令牌</el-button
      ><el-button @click="copyText(mcpConfig)">复制配置</el-button
      ><el-button type="primary" @click="tokenOpen = false"
        >我已安全保存</el-button
      ></template
    ></el-dialog
  >
  <el-drawer v-model="detailOpen" title="审计详情" size="min(650px, 95vw)">
    <pre>{{ pretty(detail) }}</pre>
  </el-drawer>
  <el-dialog
    v-model="passwordOpen"
    title="修改管理员密码"
    width="440px"
    @closed="
      passwords.old_password = '';
      passwords.new_password = '';
    "
    ><el-form label-position="top"
      ><el-form-item label="原密码"
        ><el-input
          v-model="passwords.old_password"
          type="password"
          show-password /></el-form-item
      ><el-form-item label="新密码（12～72 个 UTF-8 字节）"
        ><el-input
          v-model="passwords.new_password"
          type="password"
          show-password /></el-form-item></el-form
    ><template #footer
      ><el-button
        type="primary"
        :loading="busy"
        @click="
          run(async () => {
            await api('/auth/password', { method: 'PATCH', body: passwords });
            passwordOpen = false;
            passwords.old_password = '';
            passwords.new_password = '';
            expired();
            ElMessage.success('密码已更新，请重新登录');
          })
        "
        >更新并退出登录</el-button
      ></template
    ></el-dialog
  >
</template>
