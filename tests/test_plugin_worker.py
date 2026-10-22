import json
import shutil
import sys
from pathlib import Path

import pytest

from app.asset_types.base import Context
from app.core.security import GatewayError, NetworkPolicy
from app.plugins.bridge import PluginAssetType
from app.plugins.process import PROTOCOL, PluginProcessPool

SDK_SOURCE = Path(__file__).resolve().parents[1] / "app/plugins/sdk"

FAKE_CODE = """
import os
import time

from mag_plugin import AssetType, Plugin, PluginError, ok


class FakeType(AssetType):
    type_id = "acme.fake"
    display_name = "假插件资产"
    default_port = 4000
    connection_schema = {
        "type": "object",
        "properties": {"host": {"type": "string", "title": "主机"}, "port": {"type": "integer", "title": "端口"}},
        "required": ["host"],
        "additionalProperties": False,
    }
    tools = [
        {
            "name": "echo",
            "description": "回声",
            "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}, "required": [],
                            "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        }
    ]

    def execute(self, tool, args, ctx):
        if tool == "echo":
            return ok({"echo": args.get("value"), "user": ctx.credential.get("user")})
        if tool == "env":
            return ok({"home": os.environ.get("HOME"), "has_master_key": "GATEWAY_MASTER_KEY" in os.environ})
        if tool == "fail":
            raise PluginError("FAKE_FAIL", "插件主动失败")
        if tool == "crash":
            os._exit(1)
        if tool == "slow":
            time.sleep(10)
            return ok({"slept": True})
        if tool == "print_pollution":
            print("pollution-to-stdout")
            return ok({"printed": True})
        raise PluginError("TOOL_MISSING", tool)

    def health(self, ctx):
        return {"ok": True, "host": ctx.connection.get("host")}

    def validate_config(self, ctx, connection, account, policy, credential):
        if account.get("user") == "bad":
            raise PluginError("USER_INVALID", "账号不允许为 bad")


class FakePlugin(Plugin):
    asset_types = [FakeType]
"""


def build_plugin(root, code=FAKE_CODE, manifest=None):
    root.mkdir(parents=True)
    # 安装器约定：SDK 拷贝到 <插件目录>/sdk/mag_plugin，worker 把 sdk/ 加入 sys.path。
    shutil.copytree(SDK_SOURCE, root / "sdk" / "mag_plugin")
    (root / "fake_plugin").mkdir()
    (root / "fake_plugin" / "__init__.py").write_text(code, encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps(
            manifest
            or {
                "id": "acme.fake",
                "version": "1.0.0",
                "publisher": "acme",
                "entry": "fake_plugin:FakePlugin",
                "sdk_protocol": 1,
            }
        ),
        encoding="utf-8",
    )
    return root


async def make_pool(tmp_path, **kwargs):
    root = build_plugin(tmp_path / "plugin")
    pool = PluginProcessPool("acme.fake", root, sys.executable, **kwargs)
    descriptor = await pool.start()
    return pool, descriptor


def base_params(**extra):
    return {
        "type_id": "acme.fake",
        "connection": {"host": "db.example.test", "port": 4000},
        "account": {"user": "demo"},
        "policy": {},
        "credential": {"user": "demo", "password": "secret"},
        "limits": {"query_timeout_seconds": 10},
        "remaining_ms": 8000,
        **extra,
    }


async def test_handshake_returns_metadata_and_types(tmp_path):
    pool, descriptor = await make_pool(tmp_path)
    try:
        assert descriptor["protocol"] == PROTOCOL
        assert descriptor["plugin"]["id"] == "acme.fake"
        (kind,) = descriptor["asset_types"]
        assert kind["type_id"] == "acme.fake"
        assert kind["display_name"] == "假插件资产"
        assert kind["tools"][0]["name"] == "echo"
    finally:
        await pool.stop()


async def test_execute_and_health_roundtrip(tmp_path):
    pool, _ = await make_pool(tmp_path)
    try:
        value = await pool.request("execute", {**base_params(), "tool": "echo", "arguments": {"value": "你好"}})
        assert value["isError"] is False
        assert json.loads(value["content"][0]["text"])["echo"] == "你好"
        assert json.loads(value["content"][0]["text"])["user"] == "demo"
        health = await pool.request("health", base_params())
        assert health["ok"] is True and health["host"] == "db.example.test"
    finally:
        await pool.stop()


async def test_plugin_error_maps_to_gateway_error(tmp_path):
    pool, _ = await make_pool(tmp_path)
    try:
        with pytest.raises(GatewayError) as raised:
            await pool.request("execute", {**base_params(), "tool": "fail", "arguments": {}})
        assert raised.value.code == "FAKE_FAIL"
        with pytest.raises(GatewayError) as raised:
            await pool.request("validate_config", {**base_params(), "account": {"user": "bad"}})
        assert raised.value.code == "USER_INVALID"
    finally:
        await pool.stop()


async def test_timeout_kills_worker_and_pool_recovers(tmp_path):
    pool, _ = await make_pool(tmp_path)
    try:
        with pytest.raises(GatewayError) as raised:
            await pool.request("execute", {**base_params(), "tool": "slow", "arguments": {}}, timeout=0.5)
        assert raised.value.code == "TIMEOUT"
        assert pool.stats["timeouts"] == 1
        # 击杀后下一次调用自动重建 worker，且不重试上一次的写语义。
        value = await pool.request("execute", {**base_params(), "tool": "echo", "arguments": {}})
        assert value["isError"] is False
        assert pool.stats["spawns"] >= 2
    finally:
        await pool.stop()


async def test_crashed_worker_is_detected_and_replaced(tmp_path):
    pool, _ = await make_pool(tmp_path)
    try:
        with pytest.raises(GatewayError) as raised:
            await pool.request("execute", {**base_params(), "tool": "crash", "arguments": {}})
        assert raised.value.code == "PLUGIN_CRASHED"
        value = await pool.request("execute", {**base_params(), "tool": "echo", "arguments": {}})
        assert value["isError"] is False
        assert pool.stats["crashes"] == 1
    finally:
        await pool.stop()


async def test_worker_env_scrubs_gateway_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", "top-secret-key")
    monkeypatch.setenv("DATABASE_PATH", "/tmp/gateway.db")
    pool, _ = await make_pool(tmp_path)
    try:
        value = await pool.request("execute", {**base_params(), "tool": "env", "arguments": {}})
        payload = json.loads(value["content"][0]["text"])
        assert payload["has_master_key"] is False
        assert payload["home"].endswith("plugin")
    finally:
        await pool.stop()


async def test_plugin_print_does_not_corrupt_protocol_and_logs_go_to_file(tmp_path):
    pool, _ = await make_pool(tmp_path)
    try:
        value = await pool.request("execute", {**base_params(), "tool": "print_pollution", "arguments": {}})
        assert value["isError"] is False
        # print 被重定向进 stderr 日志，后续请求不受影响。
        value = await pool.request("execute", {**base_params(), "tool": "echo", "arguments": {}})
        assert value["isError"] is False
        logs = list((tmp_path / "plugin" / "logs").glob("worker-*.log"))
        assert logs and b"pollution-to-stdout" in logs[0].read_bytes()
    finally:
        await pool.stop()


async def test_bad_entry_reports_load_failure(tmp_path):
    root = build_plugin(
        tmp_path / "broken",
        manifest={
            "id": "acme.fake",
            "version": "1.0.0",
            "publisher": "acme",
            "entry": "fake_plugin:NoSuchClass",
            "sdk_protocol": 1,
        },
    )
    pool = PluginProcessPool("acme.fake", root, sys.executable)
    with pytest.raises(GatewayError) as raised:
        await pool.start()
    assert raised.value.code == "ENTRY_LOAD_FAILED"


async def test_handshake_rejects_wrong_plugin_identity(tmp_path):
    root = build_plugin(
        tmp_path / "liar",
        manifest={
            "id": "acme.other",
            "version": "1.0.0",
            "publisher": "acme",
            "entry": "fake_plugin:FakePlugin",
            "sdk_protocol": 1,
        },
    )
    pool = PluginProcessPool("acme.fake", root, sys.executable)
    with pytest.raises(GatewayError) as raised:
        await pool.start()
    assert raised.value.code == "PLUGIN_MISMATCH"


async def test_concurrent_requests_scale_to_worker_cap(tmp_path):
    pool, _ = await make_pool(tmp_path, max_workers=2)
    try:
        import asyncio

        async def echo(index):
            params = {**base_params(), "tool": "echo", "arguments": {"value": str(index)}}
            return await pool.request("execute", params)

        results = await asyncio.gather(*(echo(i) for i in range(4)))
        assert all(value["isError"] is False for value in results)
        assert len(pool.workers) == 2
    finally:
        await pool.stop()


async def test_drain_waits_for_inflight_and_closes(tmp_path):
    pool, _ = await make_pool(tmp_path)
    import asyncio

    inflight = asyncio.create_task(pool.request("execute", {**base_params(), "tool": "echo", "arguments": {}}))
    await asyncio.sleep(0.05)
    drainer = asyncio.create_task(pool.drain(grace=5))
    value = await inflight
    await drainer
    assert value["isError"] is False
    with pytest.raises(GatewayError) as raised:
        await pool.request("execute", {**base_params(), "tool": "echo", "arguments": {}})
    assert raised.value.code == "PLUGIN_DISABLED"


async def test_bridge_adapts_descriptor_and_validates(tmp_path, config):
    pool, descriptor = await make_pool(tmp_path)
    try:
        (kind_descriptor,) = descriptor["asset_types"]
        kind = PluginAssetType(kind_descriptor, pool, "acme.fake", "ver-1", "hash-1")
        assert kind.async_mode and kind.type_id == "acme.fake"
        assert kind.proxied is False
        assert kind.description()["plugin"] == {"id": "acme.fake", "version_id": "ver-1", "artifact_hash": "hash-1"}

        network = NetworkPolicy(config)
        # 本地出站校验：未登记主机被拒。
        with pytest.raises(GatewayError) as raised:
            kind.validate_connection(network, {"host": "unknown.example.test", "port": 4000})
        assert raised.value.code == "OUTBOUND_DENIED"
        # schema 校验：连接缺 host 被拒。
        with pytest.raises(GatewayError) as raised:
            kind.validate_config({}, {}, {}, {})
        assert raised.value.code == "VALIDATION"

        ctx = Context(
            {"connection": {"host": "db.example.test", "port": 4000}},
            {"config": {"user": "demo"}, "policy": {}},
            {"user": "demo", "password": "secret"},
            {
                "query_timeout_seconds": 10,
                "connect_timeout_seconds": 5,
                "max_result_rows": 100,
                "max_output_bytes": 65536,
                "max_cell_chars": 100,
            },
            network,
        )
        value = await kind.execute("echo", {"value": "bridge"}, ctx, kind.tools[0])
        assert json.loads(value["content"][0]["text"])["echo"] == "bridge"
        health = await kind.health(ctx)
        assert health["ok"] is True
    finally:
        await pool.stop()


async def test_bridge_discovery_stamps_spec_hash_and_rejects_duplicates(tmp_path, config):
    code = FAKE_CODE.replace(
        '        raise PluginError("TOOL_MISSING", tool)',
        """        raise PluginError("TOOL_MISSING", tool)

    def discover_tools(self, ctx):
        return [
            {"name": "up_one", "description": "一", "inputSchema": {"type": "object", "properties": {},
             "required": [], "additionalProperties": False}},
            {"name": "up_one", "description": "重复", "inputSchema": {"type": "object", "properties": {},
             "required": [], "additionalProperties": False}},
        ]""",
    )
    root = build_plugin(tmp_path / "dynamic", code=code)
    pool = PluginProcessPool("acme.fake", root, sys.executable)
    descriptor = await pool.start()
    try:
        (kind_descriptor,) = descriptor["asset_types"]
        kind = PluginAssetType(kind_descriptor, pool, "acme.fake", "ver-1", "hash-1")
        ctx = Context(
            {"connection": {"host": "db.example.test"}},
            {"config": {}, "policy": {}},
            {},
            {"query_timeout_seconds": 10},
            NetworkPolicy(config),
        )
        with pytest.raises(GatewayError) as raised:
            await kind.discover(ctx)
        assert raised.value.code == "DUPLICATE_TOOL"
    finally:
        await pool.stop()
