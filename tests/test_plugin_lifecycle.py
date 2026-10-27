import base64
import io
import json
import time
import zipfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core.config import Config
from app.main import create_app

WORKER_SDK = Path(__file__).resolve().parents[1] / "app" / "plugins" / "sdk"

PLUGIN_CODE = """
import time

from mag_plugin import AssetType, Plugin, PluginError, ok

VERSION = "{version}"


class FakeType(AssetType):
    type_id = "{type_id}"
    display_name = "假插件资产"
    default_port = 3306

    def execute(self, tool, args, ctx):
        if tool == "echo":
            return ok({{"echo": args.get("value"), "plugin_version": VERSION,
                        "account_mode": ctx.account.get("mode")}})
        if tool == "fail":
            raise PluginError("FAKE_FAIL", "插件主动失败")
        raise PluginError("TOOL_MISSING", tool)

    def health(self, ctx):
        return {{"ok": True, "host": ctx.connection.get("host")}}


class FakePlugin(Plugin):
    asset_types = [FakeType]
"""

ECHO_TOOL = {
    "name": "echo",
    "description": "回声工具",
    "inputSchema": {
        "type": "object",
        "properties": {"value": {"type": "string", "title": "输入", "maxLength": 1024}},
        "required": [],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}
FAIL_TOOL = {
    "name": "fail",
    "description": "主动失败",
    "inputSchema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}


def plugin_manifest(version, type_id="acme.fake", plugin_id="acme.fake", tools=(ECHO_TOOL, FAIL_TOOL)):
    return {
        "id": plugin_id,
        "version": version,
        "publisher": plugin_id.rsplit(".", 1)[0],
        "name": "假插件",
        "description": "端到端测试插件",
        "sdk_protocol": 1,
        "entry": "fake_plugin:FakePlugin",
        "workers": 1,
        "capabilities": {"network": True, "credential": True, "write": False},
        "types": [
            {
                "type_id": type_id,
                "display_name": "假插件资产",
                "icon": "Box",
                "default_port": 3306,
                "connection_mode": "host_port",
                "dynamic_tools": False,
                "schemas": {
                    "connection": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "title": "主机", "minLength": 1},
                            "port": {
                                "type": "integer",
                                "title": "端口",
                                "minimum": 1,
                                "maximum": 65535,
                                "default": 3306,
                            },
                        },
                        "required": ["host"],
                        "additionalProperties": False,
                    },
                    "account": {
                        "type": "object",
                        "properties": {
                            "mode": {"type": "string", "title": "模式", "enum": ["ro", "rw"], "default": "ro"}
                        },
                        "required": [],
                        "additionalProperties": False,
                    },
                    "credential": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "string", "title": "令牌", "format": "password", "minLength": 1}
                        },
                        "required": ["token"],
                        "additionalProperties": False,
                    },
                    "policy": {
                        "type": "object",
                        "properties": {
                            "query_timeout_seconds": {
                                "type": "integer",
                                "title": "总期限（秒）",
                                "minimum": 1,
                                "maximum": 30,
                            }
                        },
                        "required": [],
                        "additionalProperties": False,
                    },
                },
                "tools": list(tools),
            }
        ],
    }


def artifact_zip(manifest, code):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False))
        bundle.writestr("fake_plugin/__init__.py", code)
        bundle.writestr("requirements.lock", "")
    return buffer.getvalue()


class Market:
    """构造签名静态市场：index.json + index.sig + artifacts/。"""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "artifacts").mkdir(exist_ok=True)
        self.private = Ed25519PrivateKey.generate()
        self.public_b64 = base64.b64encode(
            self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode()
        self.entries = {}

    def publish(self, manifest, code=None, tamper_hash=False):
        payload = artifact_zip(
            manifest, code or PLUGIN_CODE.format(version=manifest["version"], type_id=manifest["types"][0]["type_id"])
        )
        name = f"{manifest['id']}-{manifest['version']}.zip"
        (self.root / "artifacts" / name).write_bytes(payload)
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        if tamper_hash:
            digest = "0" * 64
        entry = {
            "version": manifest["version"],
            "artifact": f"artifacts/{name}",
            "sha256": digest,
            "size": len(payload),
            "sdk_protocol": manifest["sdk_protocol"],
            "gateway_compat": "",
            "published_at": int(time.time() * 1000),
            "changes": "测试版本",
            "types": [
                {
                    "type_id": t["type_id"],
                    "display_name": t["display_name"],
                    "tools": [tool["name"] for tool in t["tools"]],
                }
                for t in manifest["types"]
            ],
        }
        self.entries.setdefault(manifest["id"], []).append(entry)
        self.reindex()
        return entry

    def reindex(self):
        plugins = {}
        for plugin_id, versions in self.entries.items():
            plugins[plugin_id] = {
                "id": plugin_id,
                "publisher": plugin_id.rsplit(".", 1)[0],
                "name": plugin_id,
                "description": "假插件",
                "capabilities": {"network": True, "credential": True, "write": False},
                "versions": versions,
            }
        index = {
            "version": 1,
            "generated_at": int(time.time() * 1000),
            "expires_at": int(time.time() * 1000) + 3600_000,
            "plugins": list(plugins.values()),
        }
        payload = json.dumps(index, ensure_ascii=False).encode()
        (self.root / "index.json").write_bytes(payload)
        signature = self.private.sign(payload)
        (self.root / "index.sig").write_text(base64.b64encode(signature).decode())


@pytest.fixture
def stack(tmp_path):
    market = Market(tmp_path / "market")
    market.publish(plugin_manifest("1.0.0"))

    def make(remount=False):
        config = Config(
            database=str(tmp_path / "data" / "gateway.db"),
            master_key=Fernet.generate_key().decode() if remount else STACK_KEY[0],
            key_id="test-key",
            public_url="http://testserver",
            secure_cookie=False,
            hosts=("testserver", "127.0.0.1"),
            origins=("http://testserver",),
            outbound=({"host": "db.example.test", "port": 3306},),
            ssh_host_key_enforce=True,
            plugins_dir=str(tmp_path / "plugins"),
            plugin_market_url="file://" + str(market.root),
            plugin_market_key=market.public_b64,
        )
        return config

    STACK_KEY[:] = [Fernet.generate_key().decode()]
    return {"market": market, "config_factory": make, "tmp": tmp_path}


STACK_KEY = [""]


@pytest.fixture
def plugin_app(stack):
    app = create_app(stack["config_factory"]())
    with TestClient(app) as client:
        app.state.gateway.manager.init_admin("admin", "test-password-only-2026")
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-password-only-2026"},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200, response.text
        client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": client.cookies["gateway_csrf"]})
        client.app_state = app.state
        yield client


def wait_job(admin, job_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = admin.get(f"/api/plugins/jobs/{job_id}").json()["data"]
        if job["status"] in ("done", "failed"):
            return job
        time.sleep(0.2)
    pytest.fail("插件任务超时未完成")


def install_and_enable(admin, plugin_id="acme.fake", version="1.0.0", confirm=None):
    entry = next(p for p in admin.get("/api/plugins/market").json()["data"]["items"] if p["id"] == plugin_id)
    sha = confirm or next(v["sha256"] for v in entry["versions"] if v["version"] == version)
    job = admin.post(
        "/api/plugins/install", json={"plugin_id": plugin_id, "version": version, "confirm_hash": sha}
    ).json()["data"]
    job = wait_job(admin, job["id"])
    assert job["status"] == "done", job
    response = admin.post(f"/api/plugins/{plugin_id}/enable")
    assert response.status_code == 200, response.text
    return job


def create_asset_and_grant(admin, plugin_type="acme.fake", tools=("echo",)):
    asset = admin.post(
        "/api/assets",
        json={"id": "fake", "name": "假插件资产", "type": plugin_type, "connection": {"host": "db.example.test"}},
    ).json()["data"]
    account = admin.post(
        "/api/accounts",
        json={
            "id": "fakeacct",
            "name": "假插件账号",
            "asset_id": "fake",
            "config": {"mode": "ro"},
            "credential": {"token": "secret-token"},
            "policy": {},
        },
    ).json()["data"]
    client_row = admin.post("/api/clients", json={"id": "agent", "name": "测试客户端"}).json()["data"]
    # 创建插件授权即批准当前代码版本：显式提交制品哈希（对齐 tool_versions 的确认语义）。
    plugin_hash = next(t for t in admin.get("/api/types").json()["data"] if t["type_id"] == plugin_type)["plugin"][
        "artifact_hash"
    ]
    grant = admin.post(
        "/api/grants",
        json={
            "name": "插件授权",
            "client_ids": ["agent"],
            "entries": [{"account_id": "fakeacct", "tools": list(tools)}],
            "code_versions": {plugin_type: plugin_hash},
        },
    ).json()["data"]
    return asset, account, client_row, grant


def test_market_endpoint_lists_signed_plugins(plugin_app):
    items = plugin_app.get("/api/plugins/market").json()["data"]["items"]
    assert [item["id"] for item in items] == ["acme.fake"]
    assert items[0]["versions"][0]["version"] == "1.0.0"
    detail = plugin_app.get("/api/plugins/market/acme.fake").json()["data"]
    assert detail["latest_version"] == "1.0.0"


def test_full_chain_install_enable_asset_grant_and_call(plugin_app):
    install_and_enable(plugin_app)
    types = {t["type_id"]: t for t in plugin_app.get("/api/types").json()["data"]}
    assert types["acme.fake"]["display_name"] == "假插件资产"
    assert types["acme.fake"]["available"] is True
    assert types["acme.fake"]["plugin"]["id"] == "acme.fake"

    asset, account, client_row, grant = create_asset_and_grant(plugin_app)
    assert grant["code_versions"] == {"acme.fake": types["acme.fake"]["plugin"]["artifact_hash"]}

    token = client_row["token"]
    listed = plugin_app.post(
        "/mcp", headers={"Authorization": "Bearer " + token}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    ).json()
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert names == {"fakeacct__echo"}

    called = plugin_app.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "fakeacct__echo", "arguments": {"value": "你好"}},
        },
    ).json()
    payload = json.loads(called["result"]["content"][0]["text"])
    assert payload == {"echo": "你好", "plugin_version": "1.0.0", "account_mode": "ro"}

    health = plugin_app.post("/api/accounts/fakeacct/test").json()["data"]
    assert health["ok"] is True

    runtime = plugin_app.get("/api/plugins/acme.fake/runtime").json()["data"]
    assert runtime["running"] is True and runtime["pool"]["workers"]


def test_disable_keeps_assets_but_blocks_calls(plugin_app):
    install_and_enable(plugin_app)
    _, _, client_row, _ = create_asset_and_grant(plugin_app)
    response = plugin_app.post("/api/plugins/acme.fake/disable")
    assert response.status_code == 200, response.text

    types = {t["type_id"]: t for t in plugin_app.get("/api/types").json()["data"]}
    assert types["acme.fake"]["available"] is False
    assert types["acme.fake"]["plugin_missing"] is True

    token = client_row["token"]
    listed = plugin_app.post(
        "/mcp", headers={"Authorization": "Bearer " + token}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    ).json()
    assert listed["result"]["tools"] == []
    # 资产与账号记录仍在，只是类型不可用。
    assert len(plugin_app.get("/api/assets").json()["data"]["items"]) == 1


def test_upgrade_invalidates_grants_until_reapproved(plugin_app, stack):
    install_and_enable(plugin_app)
    _, _, client_row, grant = create_asset_and_grant(plugin_app)
    token = client_row["token"]
    old_hash = grant["code_versions"]["acme.fake"]

    # 发布 v2（行为变化：plugin_version 返回 2.0.0），市场重新签名。
    stack["market"].publish(plugin_manifest("2.0.0"), code=PLUGIN_CODE.format(version="2.0.0", type_id="acme.fake"))

    job = plugin_app.post("/api/plugins/acme.fake/upgrade", json={"version": "2.0.0"}).json()["data"]
    job = wait_job(plugin_app, job["id"])
    assert job["status"] == "done", job

    detail = plugin_app.get("/api/plugins/acme.fake").json()["data"]
    assert detail["current_version"] == "2.0.0"
    assert detail["artifact_hash"] != old_hash

    # 升级后旧授权失效：工具不再放行。
    listed = plugin_app.post(
        "/mcp", headers={"Authorization": "Bearer " + token}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    ).json()
    assert listed["result"]["tools"] == []

    # 不带新哈希确认的保存被拒绝。
    saved = plugin_app.patch(
        f"/api/grants/{grant['id']}",
        json={
            "revision": grant["revision"],
            "name": "插件授权",
            "client_ids": ["agent"],
            "entries": [{"account_id": "fakeacct", "tools": ["echo"]}],
        },
    )
    assert saved.status_code == 409
    assert saved.json()["error"]["code"] == "CODE_CHANGED"

    # 带新哈希确认后恢复，且执行的是新版本代码。
    new_hash = detail["artifact_hash"]
    saved = plugin_app.patch(
        f"/api/grants/{grant['id']}",
        json={
            "revision": grant["revision"],
            "name": "插件授权",
            "client_ids": ["agent"],
            "entries": [{"account_id": "fakeacct", "tools": ["echo"]}],
            "code_versions": {"acme.fake": new_hash},
        },
    )
    assert saved.status_code == 200, saved.text
    called = plugin_app.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "fakeacct__echo", "arguments": {}}},
    ).json()
    assert json.loads(called["result"]["content"][0]["text"])["plugin_version"] == "2.0.0"

    # 回滚到 1.0.0：授权同样需要重新确认（哈希切回旧值）。
    rolled = plugin_app.post("/api/plugins/acme.fake/rollback", json={"version": "1.0.0"})
    assert rolled.status_code == 200, rolled.text
    listed = plugin_app.post(
        "/mcp", headers={"Authorization": "Bearer " + token}, json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    ).json()
    assert listed["result"]["tools"] == []


def test_uninstall_blocked_while_assets_exist(plugin_app):
    install_and_enable(plugin_app)
    create_asset_and_grant(plugin_app)
    blocked = plugin_app.post("/api/plugins/acme.fake/uninstall")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "PLUGIN_IN_USE"

    # 移除资产后可卸载，类型随之消失。
    grant = plugin_app.get("/api/grants").json()["data"]["items"][0]
    plugin_app.delete(f"/api/grants/{grant['id']}?revision={grant['revision']}")
    account = plugin_app.get("/api/accounts").json()["data"]["items"][0]
    plugin_app.delete(f"/api/accounts/{account['id']}?revision={account['revision']}")
    asset = plugin_app.get("/api/assets").json()["data"]["items"][0]
    plugin_app.delete(f"/api/assets/{asset['id']}?revision={asset['revision']}")
    done = plugin_app.post("/api/plugins/acme.fake/uninstall")
    assert done.status_code == 200, done.text
    assert plugin_app.get("/api/plugins").json()["data"]["items"] == []
    assert "acme.fake" not in {t["type_id"] for t in plugin_app.get("/api/types").json()["data"]}


def test_tampered_artifact_rejected(plugin_app, stack):
    stack["market"].publish(plugin_manifest("9.9.9"), tamper_hash=True)
    entry = next(p for p in plugin_app.get("/api/plugins/market").json()["data"]["items"] if p["id"] == "acme.fake")
    sha = next(v["sha256"] for v in entry["versions"] if v["version"] == "9.9.9")
    job = plugin_app.post(
        "/api/plugins/install", json={"plugin_id": "acme.fake", "version": "9.9.9", "confirm_hash": sha}
    ).json()["data"]
    job = wait_job(plugin_app, job["id"])
    assert job["status"] == "failed"
    assert job["error"]["code"] == "HASH_MISMATCH"


def test_built_in_type_conflict_rejected(plugin_app, stack):
    # 内置类型名不带发布者前缀，无法通过 manifest 校验——覆盖内置类型的包在安装期被拒。
    manifest = plugin_manifest("3.0.0", type_id="mysql")
    stack["market"].publish(manifest)
    entry = next(p for p in plugin_app.get("/api/plugins/market").json()["data"]["items"] if p["id"] == "acme.fake")
    sha = next(v["sha256"] for v in entry["versions"] if v["version"] == "3.0.0")
    job = plugin_app.post(
        "/api/plugins/install", json={"plugin_id": "acme.fake", "version": "3.0.0", "confirm_hash": sha}
    ).json()["data"]
    job = wait_job(plugin_app, job["id"])
    assert job["status"] == "failed"
    assert job["error"]["code"] == "MANIFEST_INVALID"


def test_missing_files_after_restart_show_placeholder(stack):
    # 独立管理两个网关生命周期：第一个退出释放数据目录锁后再启动第二个。
    with TestClient(create_app(stack["config_factory"]())) as first:
        first.app.state.gateway.manager.init_admin("admin", "test-password-only-2026")
        response = first.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-password-only-2026"},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200, response.text
        first.headers.update({"Origin": "http://testserver", "X-CSRF-Token": first.cookies["gateway_csrf"]})
        install_and_enable(first)
        create_asset_and_grant(first)
        plugin_root = first.app.state.gateway.plugins.root / "acme.fake"
        import shutil

        shutil.rmtree(plugin_root)
    with TestClient(create_app(stack["config_factory"]())) as rebooted:
        # 同一数据目录重启：沿用第一个实例创建的管理员。
        response = rebooted.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-password-only-2026"},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200, response.text
        rebooted.headers.update({"Origin": "http://testserver", "X-CSRF-Token": rebooted.cookies["gateway_csrf"]})
        types = {t["type_id"]: t for t in rebooted.get("/api/types").json()["data"]}
        assert types["acme.fake"]["available"] is False
        assert types["acme.fake"]["plugin_missing"] is True
        # 资产记录保留，内置类型照常。
        assert len(rebooted.get("/api/assets").json()["data"]["items"]) == 1
        assert types["mysql"]["available"] is True


# ---------- 离线安装 ----------


def offline_upload(admin, filename, payload, confirm=None):
    data = {"confirm": "true"} if confirm else None
    return admin.post(
        "/api/plugins/install-offline",
        files={"file": (filename, payload, "application/zip")},
        data=data,
    )


def test_offline_install_unverified_requires_explicit_confirm(plugin_app):
    """官方市场不存在的制品：预检必须标记未验证，未 confirm 不创建任务。"""
    manifest = plugin_manifest("3.0.0")
    payload = artifact_zip(manifest, PLUGIN_CODE.format(version="3.0.0", type_id="acme.fake"))
    response = offline_upload(plugin_app, "acme.fake-3.0.0.zip", payload)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["require_confirm"] is True
    assert data["verified"] is False
    assert data["verify_note"]
    assert data["plugin_id"] == "acme.fake" and data["version"] == "3.0.0"
    assert data["sha256"]
    # 未 confirm 时不得产生任何安装任务。
    jobs = plugin_app.get("/api/plugins/jobs").json()["data"]["items"]
    assert not [job for job in jobs if job["plugin_id"] == "acme.fake" and job["version"] == "3.0.0"]


def test_offline_install_market_verified_then_confirmed(plugin_app, stack):
    """官方市场已发布的制品：预检 verified=true，confirm 后安装成功。"""
    stack["market"].publish(plugin_manifest("4.0.0"), code=PLUGIN_CODE.format(version="4.0.0", type_id="acme.fake"))
    payload = (stack["market"].root / "artifacts" / "acme.fake-4.0.0.zip").read_bytes()
    preview = offline_upload(plugin_app, "acme.fake-4.0.0.zip", payload).json()["data"]
    assert preview["require_confirm"] is True and preview["verified"] is True
    job = offline_upload(plugin_app, "acme.fake-4.0.0.zip", payload, confirm=True).json()["data"]
    result = wait_job(plugin_app, job["id"])
    assert result["status"] == "done", result
    installed = plugin_app.get("/api/plugins").json()["data"]["items"]
    assert any(item["id"] == "acme.fake" for item in installed)


def test_offline_install_rejects_same_version_conflict(plugin_app, stack):
    """同版本号不同内容：即使显式 confirm 也拒绝覆盖。"""
    stack["market"].publish(plugin_manifest("5.0.0"), code=PLUGIN_CODE.format(version="5.0.0", type_id="acme.fake"))
    payload = artifact_zip(plugin_manifest("5.0.0"), PLUGIN_CODE.format(version="5.0.0", type_id="acme.fake"))
    job = offline_upload(plugin_app, "acme.fake-5.0.0.zip", payload, confirm=True).json()["data"]
    assert wait_job(plugin_app, job["id"])["status"] == "done"
    tampered = artifact_zip(
        plugin_manifest("5.0.0"), PLUGIN_CODE.format(version="5.0.0", type_id="acme.fake") + "\n# tampered"
    )
    response = offline_upload(plugin_app, "acme.fake-5.0.0.zip", tampered, confirm=True)
    assert response.json()["error"]["code"] == "VERSION_CONFLICT"


def test_offline_install_rejects_invalid_zip(plugin_app):
    response = offline_upload(plugin_app, "broken.zip", b"PK\x03\x04-not-a-real-zip")
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "OFFLINE_ARTIFACT"
