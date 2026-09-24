"""参数黑白名单、默认值、跨组隔离及统一执行鉴权。"""

import time
from unittest.mock import AsyncMock

import pytest
from conftest import rpc

from app.asset_types.base import result
from app.asset_types.mcp import tool_hash
from app.core.db import dumps, now
from app.core.security import GatewayError
from app.core.tool_rules import argument_text, enforce_rules, validate_rules


def exact(value):
    return {"match": "exact", "value": value}


def pattern(value):
    return {"match": "regex", "value": value}


def grant(parameters):
    return {"parameter_rules": {"run": parameters}}


def test_rules_full_match_whitespace_and_json():
    rules = [grant({"cmd": {"allow": [exact(" id "), pattern("uname( -a)?")]}})]
    for cmd in (" id ", "uname", "uname -a"):
        enforce_rules(rules, "run", {"cmd": cmd}, {})
    for cmd in ("id", "uname -a; id", "uname\n"):
        with pytest.raises(GatewayError, match="白名单"):
            enforce_rules(rules, "run", {"cmd": cmd}, {})
    assert argument_text(["uname", "-a"]) == '["uname","-a"]'
    assert argument_text({"b": 1, "a": True}) == '{"a":true,"b":1}'
    assert argument_text(None) == "null"
    enforce_rules([{}], "run", {}, {"properties": {"any": True}})


def test_rules_whole_group_union_and_global_deny():
    groups = [
        grant({"x": {"allow": [exact("1")]}, "y": {"allow": [exact("2")]}}),
        grant({"x": {"allow": [exact("3")]}, "y": {"allow": [exact("4")]}}),
    ]
    enforce_rules(groups, "run", {"x": 1, "y": 2}, {})
    enforce_rules(groups, "run", {"x": 3, "y": 4}, {})
    with pytest.raises(GatewayError):
        enforce_rules(groups, "run", {"x": 1, "y": 4}, {})
    groups.append(grant({"x": {"allow": [exact("9")], "deny": [exact("1")]}}))
    with pytest.raises(GatewayError, match="黑名单"):
        enforce_rules([{}, *groups], "run", {"x": 1, "y": 2}, {})


def test_default_and_missing_arguments_cannot_bypass_rules():
    groups = [grant({"limit": {"deny": [exact("10")]}})]
    with pytest.raises(GatewayError, match="显式"):
        enforce_rules(groups, "run", {}, {})
    with pytest.raises(GatewayError, match="黑名单"):
        enforce_rules(groups, "run", {}, {"properties": {"limit": {"default": 10}}})
    args = {}
    enforce_rules(groups, "run", args, {"properties": {"limit": {"default": 5}}})
    assert args == {"limit": 5}
    with pytest.raises(GatewayError, match="白名单"):
        enforce_rules([grant({"missing": {"allow": [exact("anything")]}})], "run", {}, {})
    enforce_rules([grant({"missing": {"allow": [], "deny": []}})], "run", {}, {})


@pytest.mark.parametrize(
    "rules",
    [
        None,
        [],
        {"other": {}},
        {"run": {"unknown": {}}},
        {"run": {"cmd": {"other": []}}},
        {"run": {"cmd": {"allow": "id"}}},
        {"run": {"cmd": {"allow": [pattern("[")]}}},
        {"run": {"cmd": {"allow": [exact("a" * 4097)]}}},
        {"run": {"cmd": {"deny": [{"match": "substring", "value": "x"}]}}},
        {"run": {"cmd": {"deny": [exact("x")] * 51}}},
    ],
)
def test_invalid_rules(rules):
    with pytest.raises(GatewayError) as exc:
        validate_rules(rules, ["run"], {"run": {"inputSchema": {"properties": {"cmd": {}}}}})
    assert exc.value.code == "RULE_INVALID"


def test_regex_timeout_fails_closed():
    started = time.monotonic()
    with pytest.raises(GatewayError) as exc:
        enforce_rules([grant({"cmd": {"allow": [pattern("(a+)+$")]}})], "run", {"cmd": "a" * 100000 + "!"}, {})
    assert exc.value.code == "RULE_TIMEOUT"
    assert time.monotonic() - started < 2


def create_ssh(seeded):
    save = seeded["save"]
    save(
        "assets",
        {
            "id": "shell",
            "name": "SSH",
            "type": "ssh",
            "connection": {"host": "ssh.example.test", "host_key_sha256": "SHA256:" + "A" * 43},
        },
    )
    for identity in ("shell-one", "shell-two"):
        save(
            "accounts",
            {
                "id": identity,
                "name": identity,
                "asset_id": "shell",
                "config": {"username": "reader"},
                "credential": {"password": "test-only"},
            },
        )
    return save("clients", {"id": "shell-client", "name": "SSH 客户端"})


def test_rule_crud_legacy_preservation_and_target_isolation(admin, app, seeded, monkeypatch):
    client = create_ssh(seeded)
    rules = {"exec_command": {"cmd": {"allow": [exact(" id "), pattern("uname( -a)?")], "deny": [exact("uname -a")]}}}
    entries = [
        {"account_id": "shell-one", "tools": ["exec_command"], "parameter_rules": rules},
        {"account_id": "shell-two", "tools": ["exec_command"]},
    ]
    group = seeded["save"]("grants", {"name": "命令规则", "client_ids": [client["id"]], "entries": entries})
    path = f"/api/grants/{group['id']}"
    assert admin.get(path).json()["data"]["entries"][0]["parameter_rules"] == rules
    listed = admin.get("/api/grants").json()["data"]["items"]
    assert next(item for item in listed if item["id"] == group["id"])["entries"][0]["parameter_rules"] == rules
    calls = []
    monkeypatch.setattr(
        app.state.gateway.types["ssh"],
        "execute_sync",
        lambda name, args, ctx: calls.append((ctx.account["id"], args["cmd"])) or result({"ok": True}),
    )

    def call(cmd, target="shell-one"):
        return rpc(
            admin, client["token"], "tools/call", {"name": "exec_command", "arguments": {"cmd": cmd, "target": target}}
        ).json()["result"]

    assert not call(" id ")["isError"]
    assert not call("uname")["isError"]
    assert call("uname -a")["isError"]
    assert call("id")["isError"]
    assert not call("id", "shell-two")["isError"]
    assert len(calls) == 3
    response = admin.patch(
        path, json={"revision": 1, "account_ids": ["shell-one", "shell-two"], "tools": ["exec_command"]}
    )
    assert response.status_code == 200
    assert response.json()["data"]["entries"][0]["parameter_rules"] == rules
    assert call("id")["isError"]
    entries[0]["parameter_rules"] = {}
    assert admin.patch(path, json={"revision": 2, "entries": entries}).status_code == 200
    assert not call("id")["isError"]
    with app.state.gateway.store.connect() as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM audit_log WHERE status='denied' AND error_code='ARGUMENT_DENIED'"
            ).fetchone()[0]
            == 3
        )


def test_deny_across_groups_debug_and_disable(admin, app, seeded, monkeypatch):
    client = create_ssh(seeded)
    entry = {"account_id": "shell-one", "tools": ["exec_command"]}
    seeded["save"]("grants", {"client_ids": [client["id"]], "entries": [entry]})
    denied = seeded["save"](
        "grants",
        {
            "client_ids": [client["id"]],
            "entries": [{**entry, "parameter_rules": {"exec_command": {"cmd": {"deny": [pattern(".*blocked.*")]}}}}],
        },
    )
    calls = []
    monkeypatch.setattr(
        app.state.gateway.types["ssh"],
        "execute_sync",
        lambda name, args, ctx: calls.append(args) or result({"ok": True}),
    )
    body = {"client_id": client["id"], "name": "exec_command", "arguments": {"cmd": "echo blocked"}, "confirm": True}
    response = admin.post("/api/debug/tools-call", json=body)
    assert response.json()["data"]["isError"]
    assert calls == []
    assert admin.patch(f"/api/grants/{denied['id']}", json={"revision": 1, "enabled": False}).status_code == 200
    assert not admin.post("/api/debug/tools-call", json=body).json()["data"]["isError"]
    assert len(calls) == 1


def test_rule_api_rejects_unknown_parameter_and_invalid_regex(admin, seeded):
    create_ssh(seeded)
    for rules in (
        {"exec_command": {"wrong": {"allow": [exact("id")]}}},
        {"exec_command": {"cmd": {"deny": [pattern("[")]}}},
    ):
        response = admin.post(
            "/api/grants",
            json={"entries": [{"account_id": "shell-one", "tools": ["exec_command"], "parameter_rules": rules}]},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "RULE_INVALID"


async def test_mcp_parameter_rules_enforced_before_proxy(admin, app, seeded, monkeypatch):
    save, gateway = seeded["save"], app.state.gateway
    save(
        "assets", {"id": "proxy", "name": "上游", "type": "mcp", "connection": {"url": "https://mcp.example.test/mcp"}}
    )
    save("accounts", {"id": "up", "name": "上游账号", "asset_id": "proxy", "config": {"auth_mode": "none"}})
    spec = {
        "name": "lookup",
        "description": "查询",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 5}}},
    }
    spec["spec_hash"] = tool_hash(spec)
    with gateway.store.connect(write=True) as conn:
        conn.execute(
            "UPDATE accounts SET tool_catalog_json=?,catalog_refreshed_at=? WHERE id='up'", (dumps([spec]), now())
        )
    save(
        "grants",
        {
            "client_ids": ["agent"],
            "entries": [
                {
                    "account_id": "up",
                    "tools": ["lookup"],
                    "parameter_rules": {"lookup": {"limit": {"allow": [exact("5")]}}},
                }
            ],
            "tool_versions": {"up": {"lookup": spec["spec_hash"]}},
        },
    )
    execute = AsyncMock(return_value=result({"ok": True}))
    monkeypatch.setattr(gateway.types["mcp"], "execute", execute)
    client = gateway.manager.client(identity="agent")
    assert (await gateway.call(client, "up__lookup", {"limit": 6}))["isError"]
    execute.assert_not_called()
    assert not (await gateway.call(client, "up__lookup", {}))["isError"]
    assert execute.await_args.args[1] == {"limit": 5}


def test_k8s_exec_explicit_grant_namespace_and_rules(admin, app, seeded, monkeypatch):
    save = seeded["save"]
    save(
        "assets",
        {"id": "cluster", "name": "集群", "type": "kubernetes", "connection": {"url": "https://k8s.example.test:6443"}},
    )
    for identity, namespace in (("locked", "prod"), ("unlocked", "")):
        save(
            "accounts",
            {
                "id": identity,
                "name": identity,
                "asset_id": "cluster",
                "config": {"auth_mode": "token", "namespace": namespace},
                "credential": {"token": "test-only"},
                "policy": {"kinds": ["pods"]},
            },
        )
    group = save(
        "grants", {"client_ids": ["agent"], "entries": [{"account_id": "locked", "tools": ["k8s_list_resources"]}]}
    )
    assert "k8s_exec" not in [
        item["name"] for item in rpc(admin, seeded["client"]["token"], "tools/list").json()["result"]["tools"]
    ]
    entries = [
        {
            "account_id": identity,
            "tools": ["k8s_exec"],
            "parameter_rules": {"k8s_exec": {"command": {"allow": [exact('["uname","-a"]')]}}},
        }
        for identity in ("locked", "unlocked")
    ]
    assert admin.patch(f"/api/grants/{group['id']}", json={"revision": 1, "entries": entries}).status_code == 200
    tools = rpc(admin, seeded["client"]["token"], "tools/list").json()["result"]["tools"]
    spec = next(item for item in tools if item["name"] == "k8s_exec")
    assert "namespace" in spec["inputSchema"]["properties"]
    assert "namespace" not in spec["inputSchema"]["required"]
    assert not spec["annotations"]["readOnlyHint"]
    execute = AsyncMock(return_value=result({"ok": True}))
    monkeypatch.setattr(app.state.gateway.types["kubernetes"], "execute", execute)
    for target, extra, error in (
        ("locked", {}, False),
        ("locked", {"namespace": "dev"}, True),
        ("unlocked", {}, True),
        ("unlocked", {"namespace": "dev"}, False),
    ):
        args = {"target": target, "pod": "app", "command": ["uname", "-a"], **extra}
        value = rpc(admin, seeded["client"]["token"], "tools/call", {"name": "k8s_exec", "arguments": args}).json()[
            "result"
        ]
        assert value["isError"] is error
    assert execute.await_count == 2
