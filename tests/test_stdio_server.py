import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
STRAY = (
    "GATEWAY_MASTER_KEY",
    "GATEWAY_MASTER_KEY_ID",
    "GATEWAY_CLIENT_TOKEN",
    "DATABASE_PATH",
    "PUBLIC_BASE_URL",
    "OUTBOUND_ALLOWLIST",
    "ALLOWED_HOSTS",
    "ALLOWED_ORIGINS",
    "COOKIE_SECURE",
    "LEGACY_COMPAT",
    "SSH_HOST_KEY_ENFORCE",
)


def talk(env, messages, timeout=60):
    """启动 stdio 服务器，写入消息后关闭 stdin，收集全部响应。"""
    process = subprocess.Popen(
        [sys.executable, "-m", "app.stdio_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=ROOT,
        text=True,
    )
    out, err = process.communicate("".join(json.dumps(m) + "\n" for m in messages), timeout=timeout)
    responses = [json.loads(x) for x in out.splitlines() if x.strip()]
    return process.returncode, responses, err


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in STRAY}
    env["PYTHONPATH"] = str(ROOT)
    env.update(extra)
    return env


def test_bootstrap_mode_lists_no_tools_and_rejects_calls(tmp_path):
    code, responses, _ = talk(
        clean_env(),
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "x", "arguments": {}}},
        ],
    )
    assert code == 0
    init, tools, call = responses
    assert init["result"]["serverInfo"]["name"] == "mcp-asset-gateway"
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert tools["result"] == {"tools": []}
    assert call["error"]["code"] == -32000
    assert "UNAUTHORIZED" in call["error"]["message"]


def test_bootstrap_negotiates_unknown_protocol_version():
    code, responses, _ = talk(
        clean_env(),
        [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}],
    )
    assert code == 0
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"


def test_notifications_are_silently_ignored():
    code, responses, _ = talk(
        clean_env(),
        [
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        ],
    )
    assert code == 0
    assert [r["id"] for r in responses] == [1]


def test_invalid_json_yields_parse_error():
    process = subprocess.Popen(
        [sys.executable, "-m", "app.stdio_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env(),
        cwd=ROOT,
        text=True,
    )
    out, _ = process.communicate("{not json\n", timeout=60)
    responses = [json.loads(x) for x in out.splitlines() if x.strip()]
    assert responses[0]["error"]["code"] == -32700


def test_master_key_mode_uses_env_database(tmp_path):
    database = tmp_path / "gateway.db"
    code, responses, _ = talk(
        clean_env(
            GATEWAY_MASTER_KEY=Fernet.generate_key().decode(),
            GATEWAY_MASTER_KEY_ID="key-1",
            DATABASE_PATH=str(database),
        ),
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ],
    )
    assert code == 0
    assert responses[0]["result"]["serverInfo"]["name"] == "mcp-asset-gateway"
    # 走常规配置分支：库建在 DATABASE_PATH 而非临时目录。
    assert database.exists()
    assert responses[1]["result"] == {"tools": []}


def test_invalid_client_token_fails_fast(tmp_path):
    code, responses, err = talk(
        clean_env(
            GATEWAY_MASTER_KEY=Fernet.generate_key().decode(),
            DATABASE_PATH=str(tmp_path / "gateway.db"),
            GATEWAY_CLIENT_TOKEN="invalid-token",
        ),
        [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
    )
    assert code == 1
    assert responses == []
    assert "UNAUTHORIZED" in err
