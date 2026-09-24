export async function api(path, options = {}) {
  const csrf =
    document.cookie
      .split("; ")
      .find((value) => value.startsWith("gateway_csrf="))
      ?.split("=")
      .slice(1)
      .join("=") || "";
  const response = await fetch(`/api${path}`, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": decodeURIComponent(csrf),
      ...options.headers,
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401 && path !== "/auth/login")
      window.dispatchEvent(new Event("session-expired"));
    throw new Error(
      `${payload.error?.message || "请求失败"}${payload.request_id ? `（${payload.request_id.slice(0, 8)}）` : ""}`,
    );
  }
  if (options.blob) return response.blob();
  return (await response.json()).data;
}

export async function all(table) {
  let offset = 0;
  const items = [];
  do {
    const page = await api(`/${table}?limit=100&offset=${offset}`);
    items.push(...page.items);
    offset = page.next_cursor;
  } while (offset !== null && items.length < 10000);
  return items;
}

export function entityName(entities, table, id) {
  return entities[table]?.find((row) => row.id === id)?.name || "已删除对象";
}

export function displayText(value, entities) {
  let text = String(value ?? "");
  for (const account of entities.accounts || []) {
    text = text.replaceAll(`${account.id}__`, `${account.name} · `);
  }
  return text.replace(/(?:asset|acct|cli)-[a-f0-9]{12}(?=__|\b)/g, (id) => {
    const table = id.startsWith("asset-") ? "assets" : id.startsWith("acct-") ? "accounts" : "clients";
    return entityName(entities, table, id);
  });
}

export function displayValue(value, entities) {
  if (Array.isArray(value)) return value.map((item) => displayValue(item, entities));
  if (value && typeof value === "object") {
    const fields = {
      client_id: ["客户端", "clients", "client"], asset_id: ["资产", "assets", "asset"],
      account_id: ["账号", "accounts", "account"], grant_id: ["授权组", "grants", "grant"],
      client_ids: ["客户端", "clients"], account_ids: ["资产账号", "accounts"],
    };
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !["id", "actor_id", "session_id"].includes(key))
      .map(([key, item]) => {
        if (fields[key]) {
          const [title, table, snapshot] = fields[key];
          const name = (id) => id ? entityName(entities, table, id) : "—";
          return [title, Array.isArray(item) ? item.map(name) : value.snapshot?.[snapshot] || name(item)];
        }
        if (typeof item === "string") {
          const entity = Object.values(entities).flat().find((row) => row.id === item);
          if (entity) return [key, entity.name];
        }
        return [displayText(key, entities), displayValue(item, entities)];
      }));
  }
  if (typeof value !== "string") return value;
  const entity = Object.values(entities).flat().find((row) => row.id === value);
  return entity?.name || displayText(value, entities);
}

export function groupsFor(grants, client, account) {
  return grants.filter(
    (group) =>
      group.client_ids?.includes(client) &&
      group.entries?.some((entry) => entry.account_id === account),
  );
}

export function groupTools(grants, client, account) {
  return [
    ...new Set(
      groupsFor(grants, client, account)
        .filter((group) => group.enabled)
        .flatMap((group) =>
          group.entries
            .filter((entry) => entry.account_id === account)
            .flatMap((entry) => entry.tools),
        ),
    ),
  ];
}

export function grantEntryPayload(entry) {
  return {
    account_id: entry.account_id,
    tools: [...entry.tools],
    // 规则文本保留空白；取消授权的工具不携带残留规则，空对象显式清除规则。
    parameter_rules: JSON.parse(JSON.stringify(Object.fromEntries(
      Object.entries(entry.parameter_rules || {}).filter(([name]) => entry.tools.includes(name)),
    ))),
  };
}

export function catalogNeedsRefresh(kind, result) {
  return kind === "mcp" && (!result.tools.length || result.stale);
}

export function matchesAccount(account, assets, filter) {
  const includes = (text, keyword) => String(text || "").toLowerCase().includes(keyword.trim().toLowerCase());
  const asset = assets.find((row) => row.id === account.asset_id);
  return includes(account.name, filter.account) && includes(asset?.name, filter.asset);
}

// 授权组列表按客户端/资产/账号维度过滤；各维度独立判断后 AND，空维度不旁路其它条件。
export function matchesGrant(grant, entities, filter) {
  const includes = (text, keyword) => String(text || "").toLowerCase().includes(keyword.trim().toLowerCase());
  const entries = (grant.entries || []).map((entry) => {
    const account = (entities.accounts || []).find((row) => row.id === entry.account_id);
    return {
      account: account?.name,
      asset: (entities.assets || []).find((row) => row.id === account?.asset_id)?.name,
    };
  });
  return (
    (!filter.client ||
      (grant.client_ids || []).some((id) =>
        includes((entities.clients || []).find((row) => row.id === id)?.name, filter.client),
      )) &&
    (!filter.asset || entries.some((item) => includes(item.asset, filter.asset))) &&
    (!filter.account || entries.some((item) => includes(item.account, filter.account)))
  );
}

export function defaults(schema) {
  return Object.fromEntries(
    Object.entries(schema?.properties || {})
      .filter(([, value]) => value.default !== undefined)
      .map(([key, value]) => [key, structuredClone(value.default)]),
  );
}

// 提交前清理非凭据字段的首尾空白（粘贴常见），凭据对象不经过此函数。
export function trimStrings(value) {
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) return value.map(trimStrings);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, trimStrings(item)]),
    );
  return value;
}
