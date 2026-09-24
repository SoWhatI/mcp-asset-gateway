"""隔离验收使用的真实 Streamable HTTP MCP 服务，不替换网关传输层。"""

import asyncio

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

server = FastMCP(
    "本地验收上游",
    host="0.0.0.0",
    port=8000,
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(allowed_hosts=["upstream:8000", "127.0.0.1:8000"]),
)


@server.tool()
def echo(message: str) -> str:
    """返回输入，验证真实上游调用和命名空间隔离。"""
    return "真实上游：" + message


@server.tool()
async def slow(seconds: float = 1) -> str:
    """有界延迟，用于验收取消与超时。"""
    await asyncio.sleep(max(0, min(seconds, 35)))
    return "完成"


@server.tool()
def fail() -> str:
    """返回上游工具错误，验证审计与错误传播。"""
    raise ValueError("验收预期错误")


if __name__ == "__main__":
    server.run(transport="streamable-http")
