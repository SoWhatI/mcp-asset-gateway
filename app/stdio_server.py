"""自举 stdio MCP 服务器。

镜像默认入口在缺少 GATEWAY_MASTER_KEY 时进入本模式：用一次性主密钥与临时
数据库自举启动，通过 stdio 传输（按行分隔的 JSON-RPC）提供 MCP 协议——这
是目录检查（Glama 等）与本地直连场景的标准形态。

- 未提供客户端令牌：工具列表为空、工具调用被拒绝（未接入授权组的真实状态）。
- 设置 GATEWAY_CLIENT_TOKEN：与部署一致的主密钥 + 有效客户端令牌，工具列表
  与调用行为同 HTTP 端点，可用于把网关作为本地 stdio 服务器接入 AI 客户端。
- 部署形态不受影响：compose 经 env_file 提供 GATEWAY_MASTER_KEY，镜像入口
  判断后仍启动 uvicorn HTTP 服务。
"""

import asyncio
import json
import os
import sys
import tempfile

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from app.core.config import Config
from app.core.gateway import Gateway
from app.core.security import GatewayError
from app.main import VERSIONS

SERVER_INFO = {"name": "mcp-asset-gateway", "version": "0.1.0"}


def load_config():
    """有主密钥时按常规配置启动；否则生成一次性密钥与临时库自举。"""
    load_dotenv()
    if os.getenv("GATEWAY_MASTER_KEY"):
        return Config.from_env()
    base = os.getenv("PUBLIC_BASE_URL", "http://localhost:8303").rstrip("/")
    return Config(
        database=os.path.join(tempfile.mkdtemp(prefix="gateway-stdio-"), "gateway.db"),
        master_key=Fernet.generate_key().decode(),
        key_id="bootstrap",
        public_url=base,
        secure_cookie=False,
        hosts=("localhost", "127.0.0.1"),
        origins=(base,),
        outbound=(),
    )


def error_payload(identity, error):
    return {
        "jsonrpc": "2.0",
        "id": identity,
        "error": {"code": -32000, "message": f"{error.code}: {error.message}"},
    }


async def handle(gateway, client, message):
    """处理单条 JSON-RPC 消息，返回响应 dict；通知返回 None。"""
    identity, method = message.get("id"), message.get("method")
    if (
        message.get("jsonrpc") != "2.0"
        or not isinstance(method, str)
        or ("id" in message and type(identity) not in (str, int))
    ):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in message:
        # 通知不执行任何操作，避免无回应的副作用调用。
        return None
    params = message.get("params", {})
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid params"}}
    try:
        if method == "initialize":
            value = {
                "protocolVersion": params.get("protocolVersion")
                if params.get("protocolVersion") in VERSIONS
                else VERSIONS[0],
                "serverInfo": SERVER_INFO,
                "capabilities": {"tools": {"listChanged": False}},
            }
        elif method == "ping":
            value = {}
        elif method == "tools/list":
            if params.get("cursor") is not None:
                return {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid cursor"}}
            if client is None:
                value = {"tools": []}
            else:
                value = await gateway.tools_list(client)
        elif method == "tools/call":
            if client is None:
                raise GatewayError("UNAUTHORIZED", "未配置 GATEWAY_CLIENT_TOKEN，工具调用不可用", 401)
            if not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
                return {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid params"}}
            value = await gateway.call(client, params.get("name"), params.get("arguments", {}))
        else:
            return {"jsonrpc": "2.0", "id": identity, "error": {"code": -32601, "message": "Method not found"}}
    except GatewayError as error:
        return error_payload(identity, error)
    return {"jsonrpc": "2.0", "id": identity, "result": value}


async def loop():
    config = load_config()
    gateway = Gateway(config)
    token = os.getenv("GATEWAY_CLIENT_TOKEN", "")
    try:
        await gateway.start()
        if token:
            client = await gateway.db(gateway.manager.client, None, token)
            print("stdio: 客户端令牌校验通过。", file=sys.stderr)
        else:
            client = None
            print(
                "stdio: 自举模式（未配置主密钥，使用一次性密钥与临时数据库）；"
                "工具列表为空。部署请通过 compose 提供 GATEWAY_MASTER_KEY。",
                file=sys.stderr,
            )
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            try:
                message = json.loads(line)
            except ValueError:
                print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}))
                continue
            if not isinstance(message, dict):
                print(
                    json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
                )
                continue
            response = await handle(gateway, client, message)
            if response is not None:
                print(json.dumps(response), flush=True)
    finally:
        await gateway.stop()


if __name__ == "__main__":
    try:
        asyncio.run(loop())
    except GatewayError as error:
        # 如 GATEWAY_CLIENT_TOKEN 无效等启动期失败：直接退出，避免空转。
        print(f"stdio: 启动失败 {error.code}: {error.message}", file=sys.stderr)
        raise SystemExit(1) from error
