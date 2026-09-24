"""授权组成员、重叠权限、撤权和目录版本的隔离回归。"""

import json
from unittest.mock import AsyncMock

import pytest
from conftest import rpc

from app.asset_types.base import result
from app.asset_types.mcp import tool_hash
from app.core.db import dumps, now


def test_empty_group_and_independent_members(admin, seeded):
    group = seeded["save"]("grants", {"name": "  待配置组  "})
    path = "/api/grants/" + group["id"]
    assert group["name"] == "待配置组"
    assert group["client_ids"] == group["account_ids"] == group["entries"] == group["tools"] == []
    response = admin.patch(path, json={"revision": 1, "client_ids": ["agent"]})
    assert response.status_code == 200
    assert response.json()["data"]["client_ids"] == ["agent"]
    assert response.json()["data"]["entries"] == []
    # 旧平铺格式仍可提交：工具白名单平铺到每个账号成员。
    assert admin.patch(path, json={"revision": 2, "account_ids": ["ro"], "tools": ["list_tables"]}).status_code == 200
    before = admin.get(path).json()["data"]
    assert before["entries"] == [{"account_id": "ro", "tools": ["list_tables"]}]
    for payload, status in [
        ({"client_ids": ["agent", "agent"]}, 422),
        ({"entries": [{"account_id": "missing", "tools": []}]}, 404),
        ({"entries": [{"account_id": "ro", "tools": ["list_tables", "not_a_tool"]}]}, 422),
        ({"entries": [{"account_id": "ro", "tools": []}, {"account_id": "ro", "tools": []}]}, 422),
        ({"name": " "}, 422),
        ({"revision": 1, "name": "冲突"}, 409),
    ]:
        response = admin.patch(path, json={"revision": 3, **payload})
        assert response.status_code == status, response.text
        assert admin.get(path).json()["data"] == before
    assert admin.patch(path, json={"revision": 3, "entries": []}).status_code == 200
    assert admin.get(path).json()["data"]["client_ids"] == ["agent"]
    assert admin.get(path).json()["data"]["entries"] == []


def test_many_members_union_dedup_and_revocation(admin, app, seeded, monkeypatch):
    save = seeded["save"]
    other = save("clients", {"id": "other", "name": "另一个客户端"})
    isolated = save("clients", {"id": "isolated", "name": "隔离客户端"})
    save(
        "accounts",
        {
            "id": "ro2",
            "name": "第二账号",
            "asset_id": "db",
            "config": {"username": "reader2", "database": "demo"},
            "credential": {"password": "test-only"},
        },
    )
    group = save(
        "grants",
        {
            "name": "共享只读组",
            "client_ids": ["agent", "other"],
            "entries": [
                {"account_id": "ro", "tools": ["list_tables", "describe_table"]},
                {"account_id": "ro2", "tools": ["list_tables"]},
            ],
        },
    )
    duplicate = save(
        "grants",
        {"name": "冗余保障组", "client_ids": ["other"], "entries": [{"account_id": "ro", "tools": ["list_tables"]}]},
    )
    gateway = app.state.gateway
    calls = []

    def execute(name, args, ctx):
        calls.append((name, ctx.account["id"]))
        return result({"ok": True})

    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", execute)
    for token in (seeded["client"]["token"], other["token"]):
        tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
        table = next(t for t in tools if t["name"] == "list_tables")
        assert table["inputSchema"]["properties"]["target"]["enum"] == ["ro", "ro2"]
        assert "只读账号（ro）" in table["description"] and "第二账号（ro2）" in table["description"]
        assert "target 参数请填上述资产账号 ID" in table["description"]
        assert len({t["name"] for t in tools}) == len(tools)
    assert rpc(admin, isolated["token"], "tools/list").json()["result"]["tools"] == []
    response = rpc(admin, other["token"], "tools/call", {"name": "list_tables", "arguments": {"target": "ro"}})
    assert not response.json()["result"].get("isError")
    assert calls == [("list_tables", "ro")]
    with gateway.store.connect() as conn:
        snapshot = json.loads(
            conn.execute("SELECT snapshot_json FROM audit_log WHERE event='tools.call'").fetchone()[0]
        )
        assert {g["name"] for g in snapshot["grant_groups"]} == {group["name"], duplicate["name"]}
    assert admin.delete(f"/api/grants/{group['id']}?revision=1").status_code == 200
    tools = rpc(admin, other["token"], "tools/list").json()["result"]["tools"]
    assert [t["name"] for t in tools] == ["list_tables"]
    assert "target" not in tools[0]["inputSchema"].get("required", [])
    assert not rpc(admin, other["token"], "tools/call", {"name": "list_tables"}).json()["result"].get("isError")
    assert admin.patch(f"/api/grants/{duplicate['id']}", json={"revision": 1, "enabled": False}).status_code == 200
    assert rpc(admin, other["token"], "tools/list").json()["result"]["tools"] == []
    assert rpc(admin, other["token"], "tools/call", {"name": "list_tables"}).json()["result"]["isError"]
    assert len(calls) == 2


@pytest.mark.parametrize("table,identity", [("assets", "db"), ("accounts", "ro"), ("clients", "agent")])
def test_overlap_cannot_bypass_disabled_entities(admin, seeded, table, identity):
    seeded["save"](
        "grants",
        {"name": "重复组", "client_ids": ["agent"], "entries": [{"account_id": "ro", "tools": ["list_tables"]}]},
    )
    assert admin.patch(f"/api/{table}/{identity}", json={"revision": 1, "enabled": False}).status_code == 200
    response = rpc(admin, seeded["client"]["token"], "tools/list")
    if table == "clients":
        assert response.status_code == 401
    else:
        assert response.json()["result"]["tools"] == []


def test_per_account_tool_entries(admin, app, seeded, monkeypatch):
    """同组内每个资产账号条目只生效自己的工具白名单。"""
    save = seeded["save"]
    # 独立客户端避免与 seeded 组的权限并集干扰断言。
    scoped = save("clients", {"id": "scoped", "name": "条目验证客户端"})
    save(
        "accounts",
        {
            "id": "ro2",
            "name": "第二账号",
            "asset_id": "db",
            "config": {"username": "reader2", "database": "demo"},
            "credential": {"password": "test-only"},
        },
    )
    group = save(
        "grants",
        {
            "name": "差异化条目组",
            "client_ids": ["scoped"],
            "entries": [
                {"account_id": "ro", "tools": ["list_tables"]},
                {"account_id": "ro2", "tools": ["describe_table"]},
            ],
        },
    )
    assert group["account_ids"] == ["ro", "ro2"]
    assert group["tools"] == ["describe_table", "list_tables"]
    gateway = app.state.gateway
    token = scoped["token"]
    tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
    assert sorted(t["name"] for t in tools) == ["describe_table", "list_tables"]
    table_tool = next(t for t in tools if t["name"] == "list_tables")
    describe_tool = next(t for t in tools if t["name"] == "describe_table")
    # 条目各自的工具只暴露对应账号：单账号不生成 target 枚举。
    assert "target" not in table_tool["inputSchema"]["properties"]
    assert "target" not in describe_tool["inputSchema"]["properties"]
    assert "只读账号（ro）" in table_tool["description"] and "第二账号（ro2）" in describe_tool["description"]
    calls = []

    def execute(name, args, ctx):
        calls.append((name, ctx.account["id"]))
        return result({"ok": True})

    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", execute)
    # ro 条目没有 describe_table：指定 target=ro 应被拒绝。
    denied = rpc(admin, token, "tools/call", {"name": "describe_table", "arguments": {"target": "ro"}}).json()["result"]
    assert denied.get("isError")
    assert calls == []
    assert not rpc(admin, token, "tools/call", {"name": "list_tables", "arguments": {}}).json()["result"].get("isError")
    assert calls == [("list_tables", "ro")]
    # 条目互换工具后权限立即跟随。
    admin.patch(
        f"/api/grants/{group['id']}",
        json={
            "revision": 1,
            "entries": [
                {"account_id": "ro", "tools": ["describe_table"]},
                {"account_id": "ro2", "tools": ["list_tables"]},
            ],
        },
    )
    tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
    swapped_table = next(t for t in tools if t["name"] == "list_tables")
    swapped_describe = next(t for t in tools if t["name"] == "describe_table")
    assert "target" not in swapped_table["inputSchema"]["properties"]
    assert "target" not in swapped_describe["inputSchema"]["properties"]
    assert "第二账号（ro2）" in swapped_table["description"] and "只读账号（ro）" in swapped_describe["description"]


async def test_mcp_overlap_versions_and_refresh_dedup(admin, app, seeded, monkeypatch):
    save, gateway = seeded["save"], app.state.gateway
    save(
        "assets",
        {"id": "upstream", "name": "上游", "type": "mcp", "connection": {"url": "https://mcp.example.test/mcp"}},
    )
    save("accounts", {"id": "up", "name": "上游账号", "asset_id": "upstream", "config": {"auth_mode": "none"}})
    spec = {"name": "lookup", "description": "第一版", "inputSchema": {"type": "object", "properties": {}}}

    def catalog():
        spec["spec_hash"] = tool_hash(spec)
        with gateway.store.connect(write=True) as conn:
            conn.execute(
                "UPDATE accounts SET tool_catalog_json=?,catalog_refreshed_at=? WHERE id='up'", (dumps([spec]), now())
            )

    catalog()
    payload = {
        "name": "上游组",
        "client_ids": ["agent"],
        "entries": [{"account_id": "up", "tools": ["lookup"]}],
    }
    for missing in ({}, {"tool_versions": {}}, {"tool_versions": {"up": {}}}):
        assert admin.post("/api/grants", json={**payload, **missing}).status_code == 409
    first = save("grants", {**payload, "tool_versions": {"up": {"lookup": spec["spec_hash"]}}})
    second = save("grants", {**payload, "tool_versions": {"up": {"lookup": spec["spec_hash"]}}})
    client = gateway.manager.client(token=seeded["client"]["token"])
    assert len(gateway.entries(client)["up__lookup"]) == 1
    assert len(gateway.entries(client)["up__lookup"][0]["grants"]) == 2
    spec["description"] = "第二版"
    catalog()
    assert "up__lookup" not in gateway.entries(client)
    path = f"/api/grants/{first['id']}"
    assert admin.patch(path, json={"revision": 1, "enabled": True}).status_code == 409
    assert admin.patch(path, json={"revision": 1, "name": "改名不批准"}).status_code == 200
    assert "up__lookup" not in gateway.entries(client)
    assert (
        admin.patch(path, json={"revision": 2, "tool_versions": {"up": {"lookup": spec["spec_hash"]}}}).status_code
        == 200
    )
    assert [g["id"] for g in gateway.entries(client)["up__lookup"][0]["grants"]] == [first["id"]]
    execute = AsyncMock(return_value=result({"ok": True}))
    monkeypatch.setattr(gateway.types["mcp"], "execute", execute)
    assert not (await gateway.call(client, "up__lookup", {})).get("isError")
    execute.assert_awaited_once()
    with gateway.store.connect(write=True) as conn:
        conn.execute("UPDATE accounts SET catalog_refreshed_at=1 WHERE id='up'")
    refresh = AsyncMock()
    monkeypatch.setattr(gateway, "refresh", refresh)
    await gateway.ensure_catalogs(client)
    refresh.assert_awaited_once_with("up", None, force=False)
    assert admin.patch(f"/api/grants/{second['id']}", json={"revision": 1, "enabled": False}).status_code == 200


async def test_catalog_refresh_failure_is_isolated(admin, app, seeded, monkeypatch):
    """单个上游目录刷新失败只暂停该账号的过期目录，不影响其它工具的列表与调用。"""
    save, gateway = seeded["save"], app.state.gateway
    save(
        "assets",
        {"id": "upstream", "name": "上游", "type": "mcp", "connection": {"url": "https://mcp.example.test/mcp"}},
    )
    save("accounts", {"id": "up", "name": "上游账号", "asset_id": "upstream", "config": {"auth_mode": "none"}})
    spec = {"name": "lookup", "description": "上游工具", "inputSchema": {"type": "object", "properties": {}}}
    spec["spec_hash"] = tool_hash(spec)
    with gateway.store.connect(write=True) as conn:
        conn.execute(
            "UPDATE accounts SET tool_catalog_json=?,catalog_refreshed_at=? WHERE id='up'", (dumps([spec]), now())
        )
    save(
        "grants",
        {
            "name": "上游组",
            "client_ids": ["agent"],
            "entries": [{"account_id": "up", "tools": ["lookup"]}],
            "tool_versions": {"up": {"lookup": spec["spec_hash"]}},
        },
    )
    token = seeded["client"]["token"]

    def names():
        return [t["name"] for t in rpc(admin, token, "tools/list").json()["result"]["tools"]]

    assert "up__lookup" in names()

    async def broken(ctx):
        raise RuntimeError("upstream unreachable")

    monkeypatch.setattr(gateway.types["mcp"], "discover", broken)
    with gateway.store.connect(write=True) as conn:
        conn.execute("UPDATE accounts SET catalog_refreshed_at=1 WHERE id='up'")
    assert "up__lookup" not in names()
    assert "list_tables" in names()
    calls = []

    def execute(name, args, ctx):
        calls.append(name)
        return result({"tables": []})

    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", execute)
    call = rpc(admin, token, "tools/call", {"name": "list_tables", "arguments": {}})
    assert not call.json()["result"].get("isError")
    assert calls == ["list_tables"]

    async def healthy(ctx):
        return [spec]

    monkeypatch.setattr(gateway.types["mcp"], "discover", healthy)
    assert "up__lookup" in names()
