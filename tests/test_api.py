import csv
import io
import re
import sqlite3

import pytest
from conftest import rpc
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.asset_types.base import result
from app.asset_types.kubernetes import KINDS
from app.core.config import Config
from app.core.db import dumps, now
from app.core.manager import audit
from app.main import create_app


def test_health_and_auth_boundaries(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/ready").status_code == 200
    assert client.get("/api/assets").status_code == 401
    assert client.get("/health", headers={"Host": "evil.test"}).status_code == 403
    assert client.get("/health", headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.post("/api/auth/login", json={}).status_code == 403
    assert client.post("/mcp", json={}).status_code == 401


def test_admin_csrf_and_cookie_isolation(admin):
    assert admin.get("/api/types").status_code == 200
    assert admin.post("/api/clients", json={"id": "x", "name": "x"}, headers={"X-CSRF-Token": ""}).status_code == 403
    assert admin.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}).status_code == 401
    assert admin.post("/api/auth/logout", json={}).status_code == 200
    assert admin.get("/api/auth/me").status_code == 401


def test_credentials_tokens_and_audit_are_redacted(admin, app, seeded):
    token = seeded["client"]["token"]
    for path in ("/api/accounts", "/api/clients", "/api/audit"):
        text = admin.get(path).text
        assert "remote-test-password" not in text
        assert token not in text
        assert "credential_ciphertext" not in text
        assert "token_hash" not in text
    with app.state.gateway.store.connect() as conn:
        row = conn.execute("SELECT * FROM accounts").fetchone()
        assert "remote-test-password" not in row["credential_ciphertext"]
        assert (
            app.state.gateway.vault.decrypt(row["credential_ciphertext"], row["credential_key_id"])["password"]
            == "remote-test-password"
        )
    admin.cookies.clear()
    assert admin.get("/api/assets", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert (
        rpc(admin, token, "initialize", {"protocolVersion": "2025-03-26"}).json()["result"]["protocolVersion"]
        == "2025-03-26"
    )


def test_target_exact_authorization_and_immediate_revoke(admin, app, seeded, monkeypatch):
    gateway = app.state.gateway
    invoked = []
    monkeypatch.setattr(
        gateway.types["mysql"],
        "execute_sync",
        lambda name, args, ctx: invoked.append(ctx.account["id"]) or result({"ok": True}),
    )
    token = seeded["client"]["token"]
    tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
    assert {t["name"] for t in tools} == {"list_tables", "execute_query"}
    assert "target" not in tools[0]["inputSchema"]["properties"]
    assert rpc(admin, token, "tools/call", {"name": "list_tables"}).json()["result"]["isError"] is False
    assert (
        rpc(admin, token, "tools/call", {"name": "describe_table", "arguments": {"table": "secret"}}).json()["result"][
            "isError"
        ]
        is True
    )
    seeded["save"](
        "accounts",
        {
            "id": "ro2",
            "name": "第二账号",
            "asset_id": "db",
            "config": {"username": "reader2", "database": "demo"},
            "credential": {"password": "other-test-only"},
        },
    )
    seeded["save"]("grants", {"client_ids": ["agent"], "account_ids": ["ro2"], "tools": ["list_tables"]})
    tools = rpc(admin, token, "tools/list").json()["result"]["tools"]
    schemas = {t["name"]: t["inputSchema"] for t in tools}
    assert set(schemas["list_tables"]["properties"]["target"]["enum"]) == {"ro", "ro2"}
    assert "target" not in schemas["execute_query"]["properties"]
    descriptions = {t["name"]: t["description"] for t in tools}
    assert "只读账号（ro）" in descriptions["list_tables"] and "第二账号（ro2）" in descriptions["list_tables"]
    assert "target 参数请填上述资产账号 ID" in descriptions["list_tables"]
    assert rpc(admin, token, "tools/call", {"name": "list_tables"}).json()["result"]["isError"] is True
    assert (
        rpc(admin, token, "tools/call", {"name": "list_tables", "arguments": {"target": "ro2"}}).json()["result"][
            "isError"
        ]
        is False
    )
    assert invoked == ["ro", "ro2"]
    assert admin.patch("/api/accounts/ro2", json={"revision": 1, "enabled": False}).status_code == 200
    assert (
        rpc(admin, token, "tools/call", {"name": "list_tables", "arguments": {"target": "ro2"}}).json()["result"][
            "isError"
        ]
        is True
    )
    rotated = admin.post("/api/clients/agent/rotate-token", json={"revision": 1}).json()["data"]["token"]
    assert rpc(admin, token, "tools/list").status_code == 401
    assert rpc(admin, rotated, "tools/list").status_code == 200


def test_no_execution_without_initial_audit(admin, app, seeded, monkeypatch):
    gateway = app.state.gateway
    invoked = []
    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", lambda *args: invoked.append(True))

    def unavailable(*args):
        raise sqlite3.OperationalError("simulated disk full")

    monkeypatch.setattr(gateway, "prepare", unavailable)
    response = rpc(admin, seeded["client"]["token"], "tools/call", {"name": "list_tables"})
    assert response.status_code == 503
    assert not invoked
    assert gateway.audit_failed
    assert admin.get("/ready").status_code == 503


def test_final_audit_failure_is_not_retryable_http_error(admin, app, seeded, monkeypatch):
    gateway = app.state.gateway
    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", lambda *args: result({"ok": True}))

    def unavailable(*args):
        raise sqlite3.OperationalError("simulated disk full")

    monkeypatch.setattr(gateway, "finish", unavailable)
    response = rpc(admin, seeded["client"]["token"], "tools/call", {"name": "list_tables"})
    assert response.status_code == 200
    assert response.json()["result"]["isError"] is True
    assert "AUDIT_UNCONFIRMED" in response.text


@pytest.mark.parametrize(
    "table,payload",
    [
        ("assets", {"id": "x", "name": "x", "type": "mysql"}),
        ("assets", {"id": "x", "name": "x", "type": []}),
        ("clients", {"id": 1, "name": "x"}),
        ("grants", {"client_ids": [], "account_ids": {}}),
    ],
)
def test_malformed_crud_is_client_error(admin, table, payload):
    assert 400 <= admin.post("/api/" + table, json=payload).status_code < 500


@pytest.mark.parametrize("payload", [[None], [True], ["key"], [{"key": [], "value": 1}]])
def test_malformed_settings_is_client_error(admin, payload):
    assert 400 <= admin.patch("/api/settings", json=payload).status_code < 500


def test_revision_reference_and_reserved_id(admin, seeded):
    assert admin.patch("/api/clients/agent", json={"revision": 9, "enabled": False}).status_code == 409
    assert admin.delete("/api/assets/db?revision=1").status_code == 409
    seeded["save"]("clients", {"id": "temporary", "name": "temporary"})
    assert admin.delete("/api/clients/temporary?revision=1").status_code == 200
    assert admin.post("/api/clients", json={"id": "temporary", "name": "temporary"}).status_code == 409
    assert (
        admin.post(
            "/api/grants",
            json={"name": "重复授权组", "client_ids": ["agent"], "account_ids": ["ro"], "tools": ["list_tables"]},
        ).status_code
        == 200
    )
    seeded["save"](
        "accounts",
        {
            "id": "ro3",
            "name": "第三账号",
            "asset_id": "db",
            "config": {"username": "reader3", "database": "demo"},
            "credential": {"password": "third-test-only"},
        },
    )
    assert (
        admin.post(
            "/api/grants",
            json={"client_ids": ["agent"], "account_ids": ["ro3"], "tools": ["*"]},
        ).status_code
        == 422
    )


def test_entity_ids_auto_generated(admin, seeded):
    asset = admin.post(
        "/api/assets",
        json={"name": "自动 ID 资产", "type": "mysql", "connection": {"host": "db.example.test"}},
    )
    assert asset.status_code == 200, asset.text
    account = admin.post(
        "/api/accounts",
        json={
            "name": "自动 ID 账号",
            "asset_id": asset.json()["data"]["id"],
            "config": {"username": "reader", "database": "demo"},
            "credential": {"password": "remote-test-password"},
            "policy": {},
        },
    )
    assert account.status_code == 200, account.text
    agent = admin.post("/api/clients", json={"name": "自动 ID 客户端"})
    assert agent.status_code == 200, agent.text
    assert re.fullmatch(r"asset-[0-9a-f]{12}", asset.json()["data"]["id"])
    assert re.fullmatch(r"acct-[0-9a-f]{12}", account.json()["data"]["id"])
    assert re.fullmatch(r"cli-[0-9a-f]{12}", agent.json()["data"]["id"])
    grant = admin.post(
        "/api/grants",
        json={
            "client_ids": [agent.json()["data"]["id"]],
            "account_ids": [account.json()["data"]["id"]],
            "tools": ["list_tables"],
        },
    )
    assert grant.status_code == 200, grant.text


def test_redis_asset_account_and_catalog(admin, seeded):
    types = {item["type_id"]: item for item in admin.get("/api/types").json()["data"]}
    assert types["redis"]["default_port"] == 6379 and types["redis"]["available"] is True
    cache = admin.post(
        "/api/assets",
        json={"name": "缓存集群", "type": "redis", "connection": {"host": "cache.example.test", "port": 6379}},
    )
    assert cache.status_code == 200, cache.text
    assert (
        admin.post(
            "/api/assets",
            json={
                "name": "非法模式",
                "type": "redis",
                "connection": {"host": "cache.example.test", "tls_mode": "STRICT"},
            },
        ).status_code
        == 422
    )
    assert (
        admin.post(
            "/api/assets",
            json={"name": "未登记主机", "type": "redis", "connection": {"host": "unknown.example.test"}},
        ).status_code
        == 403
    )
    account = admin.post(
        "/api/accounts",
        json={
            "name": "缓存只读",
            "asset_id": cache.json()["data"]["id"],
            "config": {"username": "", "database": 0},
            "credential": {"password": "redis-test-only"},
            "policy": {"key_allowlist": ["app:*"], "max_scan_keys": 100},
        },
    )
    assert account.status_code == 200, account.text
    catalog = admin.get(f"/api/accounts/{account.json()['data']['id']}/tools").json()["data"]
    assert {spec["name"] for spec in catalog["tools"]} == {
        "redis_scan_keys",
        "redis_read_key",
        "redis_key_info",
        "redis_server_info",
    }
    assert catalog["stale"] is False
    assert (
        admin.post(
            "/api/accounts",
            json={
                "name": "缺少白名单",
                "asset_id": cache.json()["data"]["id"],
                "config": {"username": "", "database": 0},
                "credential": {"password": "redis-test-only"},
                "policy": {},
            },
        ).status_code
        == 422
    )


def test_kubernetes_asset_account_and_catalog(admin, seeded):
    types = {item["type_id"]: item for item in admin.get("/api/types").json()["data"]}
    assert types["kubernetes"]["default_port"] is None
    cluster = admin.post(
        "/api/assets",
        json={"name": "测试集群", "type": "kubernetes", "connection": {"url": "https://k8s.example.test:6443"}},
    )
    assert cluster.status_code == 200, cluster.text
    assert (
        admin.post(
            "/api/assets",
            json={"name": "明文地址", "type": "kubernetes", "connection": {"url": "http://k8s.example.test:6443"}},
        ).status_code
        == 422
    )
    account = admin.post(
        "/api/accounts",
        json={
            "name": "集群只读",
            "asset_id": cluster.json()["data"]["id"],
            "config": {"auth_mode": "token", "namespace": "prod"},
            "credential": {"token": "test-only-token"},
            "policy": {"kinds": ["pods"]},
        },
    )
    assert account.status_code == 200, account.text
    assert (
        admin.post(
            "/api/accounts",
            json={
                "name": "缺少令牌",
                "asset_id": cluster.json()["data"]["id"],
                "config": {"auth_mode": "token", "namespace": "prod"},
                "credential": {},
                "policy": {"kinds": ["pods"]},
            },
        ).status_code
        == 422
    )
    catalog = admin.get(f"/api/accounts/{account.json()['data']['id']}/tools").json()["data"]
    narrowed = [spec for spec in catalog["tools"] if "kind" in spec["inputSchema"]["properties"]]
    assert narrowed and all(spec["inputSchema"]["properties"]["kind"]["enum"] == ["pods"] for spec in narrowed)
    assert all("namespace" not in spec["inputSchema"]["properties"] for spec in catalog["tools"])
    unlocked = admin.post(
        "/api/accounts",
        json={
            "name": "跨命名空间只读",
            "asset_id": cluster.json()["data"]["id"],
            "config": {"auth_mode": "token"},
            "credential": {"token": "test-only-token"},
            "policy": {"kinds": ["pods"]},
        },
    )
    assert unlocked.status_code == 200, unlocked.text
    unlocked_tools = admin.get(f"/api/accounts/{unlocked.json()['data']['id']}/tools").json()["data"]["tools"]
    schemas = {spec["name"]: spec["inputSchema"] for spec in unlocked_tools}
    assert all("namespace" in schema["properties"] for schema in schemas.values())
    assert "namespace" in schemas["k8s_get_resource"]["required"]
    assert "namespace" not in schemas["k8s_list_resources"]["required"]
    # 策略省略或 kinds 留空表示不限制，目录覆盖全部内置资源类型。
    unrestricted = admin.post(
        "/api/accounts",
        json={
            "name": "全类型只读",
            "asset_id": cluster.json()["data"]["id"],
            "config": {"auth_mode": "token", "namespace": "prod"},
            "credential": {"token": "test-only-token"},
            "policy": {},
        },
    )
    assert unrestricted.status_code == 200, unrestricted.text
    full = admin.get(f"/api/accounts/{unrestricted.json()['data']['id']}/tools").json()["data"]["tools"]
    full_kinds = [spec for spec in full if "kind" in spec["inputSchema"]["properties"]]
    assert full_kinds and all(spec["inputSchema"]["properties"]["kind"]["enum"] == sorted(KINDS) for spec in full_kinds)


def test_kubernetes_accepts_uploaded_pem_material(admin):
    ca_pem = "-----BEGIN CERTIFICATE-----\nMIIB-test-ca\n-----END CERTIFICATE-----\n"
    # 非真实私钥，仅测试 PEM 字段接收和错位校验；不豁免秘密扫描。
    key_pem = "-----BEGIN {kind}-----\nMIIE-test\n-----END {kind}-----\n".format(kind="PRIVATE KEY")
    uploaded = admin.post(
        "/api/assets",
        json={
            "name": "上传CA集群",
            "type": "kubernetes",
            "connection": {"url": "https://k8s.example.test:6443", "ca_file": ca_pem},
        },
    )
    assert uploaded.status_code == 200, uploaded.text
    assert (
        admin.post(
            "/api/assets",
            json={
                "name": "无效CA集群",
                "type": "kubernetes",
                "connection": {"url": "https://k8s.example.test:6443", "ca_file": "ca.crt"},
            },
        ).status_code
        == 422
    )
    certificate = admin.post(
        "/api/accounts",
        json={
            "name": "证书认证",
            "asset_id": uploaded.json()["data"]["id"],
            "config": {"auth_mode": "client_certificate"},
            "credential": {
                "client_certificate_file": "-----BEGIN CERTIFICATE-----\nMIIB-test\n-----END CERTIFICATE-----\n",
                "client_key_file": key_pem,
            },
            "policy": {"kinds": ["pods"]},
        },
    )
    assert certificate.status_code == 200, certificate.text
    assert (
        admin.post(
            "/api/accounts",
            json={
                "name": "证书错位",
                "asset_id": uploaded.json()["data"]["id"],
                "config": {"auth_mode": "client_certificate"},
                "credential": {
                    "client_certificate_file": key_pem,
                    "client_key_file": key_pem,
                },
                "policy": {"kinds": ["pods"]},
            },
        ).status_code
        == 422
    )


def test_asset_validation_reports_offending_field_without_echo(admin):
    spaced = admin.post(
        "/api/assets",
        json={"name": "带空白地址", "type": "kubernetes", "connection": {"url": " https://k8s.example.test :6443 "}},
    )
    assert spaced.status_code == 422
    message = spaced.json()["error"]["message"]
    assert "字段类型、必填项或允许值不符合 schema" in message
    assert "API Server 地址（url）" in message and "pattern" in message
    assert "k8s.example.test" not in message  # 不回显入参
    missing = admin.post("/api/assets", json={"name": "缺少地址", "type": "kubernetes", "connection": {}})
    assert missing.status_code == 422
    assert "缺少必填字段 API Server 地址（url）" in missing.json()["error"]["message"]
    extra = admin.post(
        "/api/assets",
        json={
            "name": "多余字段",
            "type": "kubernetes",
            "connection": {"url": "https://k8s.example.test:6443", "host": "k8s.example.test"},
        },
    )
    assert extra.status_code == 422
    assert "包含不支持的字段 host" in extra.json()["error"]["message"]


def test_outbound_allowlist_null_allows_unregistered(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "data" / "gateway.db"))
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "null")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://testserver")
    config = Config.from_env()
    assert config.outbound_enforce is False
    app = create_app(config)
    with TestClient(app) as client:
        app.state.gateway.manager.init_admin("admin", "test-password-only-2026")
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-password-only-2026"},
            headers={"Origin": "http://testserver"},
        )
        assert login.status_code == 200, login.text
        client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": client.cookies["gateway_csrf"]})
        asset = client.post(
            "/api/assets",
            json={"name": "宽松模式资产", "type": "mysql", "connection": {"host": "unregistered.example.test"}},
        )
        assert asset.status_code == 200, asset.text
        assert re.fullmatch(r"asset-[0-9a-f]{12}", asset.json()["data"]["id"])
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", '[{"host":"db.example.test","port":3306}]')
    assert Config.from_env().outbound_enforce is True
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "[]")
    assert Config.from_env().outbound_enforce is False
    monkeypatch.delenv("OUTBOUND_ALLOWLIST")
    assert Config.from_env().outbound_enforce is False


def test_ssh_host_key_enforce_disabled_allows_asset_without_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "data" / "gateway.db"))
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "null")
    monkeypatch.setenv("SSH_HOST_KEY_ENFORCE", "false")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://testserver")
    config = Config.from_env()
    assert config.ssh_host_key_enforce is False
    app = create_app(config)
    with TestClient(app) as client:
        app.state.gateway.manager.init_admin("admin", "test-password-only-2026")
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-password-only-2026"},
            headers={"Origin": "http://testserver"},
        )
        assert login.status_code == 200, login.text
        client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": client.cookies["gateway_csrf"]})
        kinds = {item["type_id"]: item for item in client.get("/api/types").json()["data"]}
        assert kinds["ssh"]["connection_schema"]["required"] == ["host"]
        assert kinds["ssh"]["connection_schema"]["properties"]["host_key_sha256"]["x-hidden"] is True
        assert kinds["filebrowser"]["connection_schema"]["required"] == ["host"]
        asset = client.post(
            "/api/assets",
            json={"name": "无指纹 SSH", "type": "ssh", "connection": {"host": "192.0.2.10"}},
        )
        assert asset.status_code == 200, asset.text
        # 历史记录中已保存的指纹在该字段隐藏后仍可原样保存（重新开启校验后恢复生效）。
        pinned = "SHA256:" + "A" * 43
        legacy = client.post(
            "/api/assets",
            json={
                "name": "旧指纹 SSH",
                "type": "ssh",
                "connection": {"host": "192.0.2.11", "host_key_sha256": pinned},
            },
        )
        assert legacy.status_code == 200, legacy.text
        assert legacy.json()["data"]["connection"]["host_key_sha256"] == pinned
    monkeypatch.setenv("SSH_HOST_KEY_ENFORCE", "true")
    assert Config.from_env().ssh_host_key_enforce is True
    monkeypatch.delenv("SSH_HOST_KEY_ENFORCE")
    assert Config.from_env().ssh_host_key_enforce is False


def test_invalid_outbound_allowlist_rejected(monkeypatch):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OUTBOUND_ALLOWLIST", "[172.16.1.251:3304]")
    with pytest.raises(ValueError, match="OUTBOUND_ALLOWLIST"):
        Config.from_env()


def test_account_test_error_audit_shares_request_id(admin, seeded, app):
    tested = admin.post("/api/accounts/ro/test")
    assert tested.status_code == 502, tested.text
    payload = tested.json()
    assert payload["error"]["code"] == "DNS_FAILED"
    with app.state.gateway.store.connect() as conn:
        rows = conn.execute(
            "SELECT status,error_code FROM audit_log WHERE request_id=?", (payload["request_id"],)
        ).fetchall()
    assert [tuple(row) for row in rows] == [("error", "DNS_FAILED")]


def test_audit_pagination_and_password_revocation(admin, seeded):
    page1 = admin.get("/api/audit?limit=2").json()["data"]
    page2 = admin.get("/api/audit", params={"limit": 2, "cursor": page1["next_cursor"]}).json()["data"]
    assert not {r["id"] for r in page1["items"]} & {r["id"] for r in page2["items"]}
    assert admin.get("/api/audit/export").headers["content-type"].startswith("text/csv")
    assert (
        admin.patch(
            "/api/auth/password",
            json={"old_password": "test-password-only-2026", "new_password": "new-test-password-2026"},
        ).status_code
        == 200
    )
    assert admin.get("/api/auth/me").status_code == 401


def test_mcp_notifications_unknown_methods_and_limits(admin, app, seeded, monkeypatch):
    token = seeded["client"]["token"]
    assert rpc(admin, token, "resources/list").json()["error"]["code"] == -32601
    assert admin.get("/mcp").status_code == 405
    invoked = []
    monkeypatch.setattr(app.state.gateway.types["mysql"], "execute_sync", lambda *args: invoked.append(True))
    response = admin.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_tables"}},
    )
    assert response.status_code == 202
    assert not invoked
    assert (
        admin.post(
            "/mcp", headers={"Authorization": "Bearer " + token, "X-Agent-Token": "different"}, json={}
        ).status_code
        == 401
    )
    assert (
        admin.post("/api/clients", content="x" * 1048577, headers={"Content-Type": "application/json"}).status_code
        == 413
    )


def test_upstream_catalog_versions(admin, app, seeded):
    from app.asset_types.mcp import tool_hash

    seeded["save"](
        "assets",
        {"id": "upstream", "name": "上游", "type": "mcp", "connection": {"url": "https://mcp.example.test/mcp"}},
    )
    seeded["save"](
        "accounts", {"id": "upstream-ro", "name": "上游账号", "asset_id": "upstream", "config": {"auth_mode": "none"}}
    )
    spec = {
        "name": "lookup",
        "description": "first",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}},
    }
    spec["spec_hash"] = tool_hash(spec)
    with app.state.gateway.store.connect(write=True) as conn:
        conn.execute(
            "UPDATE accounts SET tool_catalog_json=?,catalog_refreshed_at=? WHERE id=?",
            (dumps([spec]), now(), "upstream-ro"),
        )
    grant = seeded["save"](
        "grants",
        {
            "client_ids": ["agent"],
            "account_ids": ["upstream-ro"],
            "tools": ["lookup"],
            "tool_versions": {"upstream-ro": {"lookup": spec["spec_hash"]}},
        },
    )
    tools = rpc(admin, seeded["client"]["token"], "tools/list").json()["result"]["tools"]
    upstream = next(t for t in tools if t["name"] == "upstream-ro__lookup")
    assert upstream["inputSchema"] == spec["inputSchema"]
    old_hash = spec["spec_hash"]
    spec["description"] = "changed"
    spec["spec_hash"] = tool_hash(spec)
    with app.state.gateway.store.connect(write=True) as conn:
        conn.execute("UPDATE accounts SET tool_catalog_json=? WHERE id=?", (dumps([spec]), "upstream-ro"))
    tools = rpc(admin, seeded["client"]["token"], "tools/list").json()["result"]["tools"]
    assert "upstream-ro__lookup" not in {t["name"] for t in tools}
    assert (
        admin.patch(
            "/api/grants/" + grant["id"],
            json={"revision": 1, "tools": ["lookup"], "tool_versions": {"upstream-ro": {"lookup": old_hash}}},
        ).status_code
        == 409
    )


def test_audit_export_escaping_filters_and_redaction(admin, app, seeded):
    tools = ["=1+1", " +SUM(1,2)", "-1", "@lookup", "\tvalue", "\rvalue", "\nvalue", '普通,"工具"\n名称']
    with app.state.gateway.store.connect(write=True) as conn:
        for tool in tools:
            audit(conn, "tools.call", source="mcp", tool=tool, status="denied", client_id="agent", asset_id="db")
        audit(conn, "tools.call", source="ui", tool="excluded", status="denied", client_id="agent", asset_id="db")
    filters = {"client_id": "agent", "asset_id": "db", "status": "denied", "source": "mcp", "event": "tools.call"}
    response = admin.get("/api/audit/export", params=filters)
    assert response.status_code == 200
    assert response.content.startswith(b"\xef\xbb\xbf")
    assert response.headers["content-disposition"] == 'attachment; filename="gateway-audit.csv"'
    assert response.headers["cache-control"] == "no-store"
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert len(rows) == len(tools)
    assert {row["tool"] for row in rows} == {"'" + tool for tool in tools[:-1]} | {tools[-1]}
    assert "detail" not in rows[0] and "snapshot" not in rows[0]
    assert seeded["client"]["token"] not in response.text
    assert "remote-test-password" not in response.text
    assert "credential_ciphertext" not in response.text
    assert len(admin.get("/api/audit", params=filters).json()["data"]["items"]) == len(tools)
    assert admin.get("/api/audit", params={"event": "audit.export"}).json()["data"]["items"]
    admin.cookies.clear()
    assert admin.get("/api/audit/export").status_code == 401


def test_audit_export_row_limit_and_rate_limit(admin, app):
    stamp = now()
    with app.state.gateway.store.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO audit_log(request_id,ts,source,event,actor_type,status) VALUES(?,?,'mcp','tools.call','client','ok')",
            [(f"export-{i}", stamp) for i in range(10001)],
        )
    response = admin.get("/api/audit/export", params={"event": "tools.call"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "EXPORT_LIMIT"
    with app.state.gateway.store.connect(write=True) as conn:
        conn.execute("DELETE FROM audit_log WHERE request_id='export-10000'")
    response = admin.get("/api/audit/export", params={"event": "tools.call"})
    assert response.status_code == 200
    assert len(list(csv.DictReader(io.StringIO(response.text.lstrip("\ufeff"))))) == 10000
    for _ in range(3):
        assert admin.get("/api/audit/export", params={"event": "missing"}).status_code == 200
    assert admin.get("/api/audit/export").status_code == 429


@pytest.mark.parametrize(
    "filters",
    [
        {"start": "bad"},
        {"end": "999999999999999999999999"},
        {"start": "-1"},
        {"start": "2", "end": "1"},
    ],
)
def test_audit_invalid_time_filters(admin, filters):
    for path in ("/api/audit", "/api/audit/export"):
        response = admin.get(path, params=filters)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "AUDIT_FILTER"


@pytest.mark.parametrize("cursor", ["bad", "1:2:3", "1:99999999999999999999", "1:-1"])
def test_audit_invalid_cursors(admin, cursor):
    assert admin.get("/api/audit", params={"cursor": cursor}).status_code == 400


def test_dashboard_call_aggregates_and_utc_days(admin, app, monkeypatch):
    import app.core.manager as manager_module

    stamp = 1798848000000  # 2027-01-02 00:00 UTC，覆盖跨年与午夜边界。
    monkeypatch.setattr(manager_module, "now", lambda: stamp)
    with app.state.gateway.store.connect(write=True) as conn:
        conn.execute("UPDATE admin_sessions SET last_seen_at=?,expires_at=?", (stamp, stamp + 28800000))
        for status, elapsed in [
            ("ok", 100),
            ("ok", 300),
            ("error", 200),
            ("denied", None),
            ("timeout", 400),
            ("interrupted", None),
            ("started", None),
        ]:
            audit(conn, "tools.call", source="mcp", status=status, tool="lookup", client_id="agent", elapsed_ms=elapsed)
        audit(conn, "auth.login", status="ok")
        for request_id, ts in [
            ("week-start", stamp - 6 * 86400000),
            ("too-old", stamp - 6 * 86400000 - 1),
            ("future", stamp + 1),
        ]:
            audit(conn, "tools.call", request_id=request_id, source="mcp", tool="old", client_id="old-agent")
            conn.execute("UPDATE audit_log SET ts=? WHERE request_id=?", (ts, request_id))
    response = admin.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["calls"] == {
        "total": 7,
        "completed": 6,
        "statuses": {"ok": 2, "error": 1, "denied": 1, "timeout": 1, "interrupted": 1, "started": 1},
        "success_rate": 33.3,
        "average_elapsed_ms": 250.0,
    }
    assert data["statuses"]["ok"] == 3
    assert data["timezone"] == "UTC"
    assert len(data["daily"]) == 7
    assert data["daily"][0] == {"day": "2026-12-27", "total": 1}
    assert data["daily"][-1] == {"day": "2027-01-02", "total": 7}
    assert all(day["total"] == 0 for day in data["daily"][1:-1])
    assert data["top_tools"] == [{"name": "lookup", "total": 7, "failures": 4}]
    assert data["top_clients"] == [{"name": "agent", "total": 7, "failures": 4}]
    rows = admin.get("/api/audit", params={"event": "tools.call", "start": data["start"], "end": data["end"]}).json()[
        "data"
    ]["items"]
    assert len(rows) == data["calls"]["total"]


def test_dashboard_empty_and_bounded_rankings(admin, app):
    data = admin.get("/api/dashboard").json()["data"]
    assert data["calls"]["total"] == 0
    assert data["calls"]["success_rate"] is None
    assert data["calls"]["average_elapsed_ms"] is None
    assert all(day["total"] == 0 for day in data["daily"])
    with app.state.gateway.store.connect(write=True) as conn:
        for i in range(8):
            audit(conn, "tools.call", source="mcp", tool=f"tool-{i}", client_id=f"client-{i}")
    data = admin.get("/api/dashboard").json()["data"]
    assert [row["name"] for row in data["top_tools"]] == [f"tool-{i}" for i in range(5)]
    assert len(data["top_clients"]) == 5
