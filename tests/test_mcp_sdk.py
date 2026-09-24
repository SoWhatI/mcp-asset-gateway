import asyncio
import json
import socket
import threading
from dataclasses import replace

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.asset_types.base import Context, result
from app.asset_types.mcp import MCPProxyAssetType
from app.asset_types.pinned import PinnedTransport
from app.core.config import DEFAULTS
from app.core.security import NetworkPolicy
from app.main import create_app


async def test_downstream_official_sdk(config, monkeypatch):
    app = create_app(config)
    gateway = app.state.gateway
    async with app.router.lifespan_context(app):
        manager, actor = gateway.manager, {"id": "test"}
        manager.save(
            "assets", {"id": "db", "name": "db", "type": "mysql", "connection": {"host": "db.example.test"}}, actor
        )
        manager.save(
            "accounts",
            {
                "id": "ro",
                "name": "ro",
                "asset_id": "db",
                "config": {"username": "reader", "database": "demo"},
                "credential": {"password": "test-only"},
            },
            actor,
        )
        identity = manager.save("clients", {"id": "agent", "name": "agent"}, actor)
        manager.save("grants", {"client_ids": ["agent"], "account_ids": ["ro"], "tools": ["list_tables"]}, actor)
        monkeypatch.setattr(gateway.types["mysql"], "execute_sync", lambda *args: result({"tables": []}))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), headers={"Authorization": "Bearer " + identity["token"]}
        ) as client:
            async with streamable_http_client("http://testserver/mcp", http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    initialized = await session.initialize()
                    assert initialized.serverInfo.name == "mcp-asset-gateway"
                    tools = await session.list_tools()
                    assert [t.name for t in tools.tools] == ["list_tables"]
                    response = await session.call_tool("list_tables", arguments={})
                    assert response.isError is False
                    assert json.loads(response.content[0].text) == {"tables": []}
                    await session.send_ping()


@pytest.mark.parametrize("use_sse", [False, True])
async def test_upstream_sdk_pagination_headers_and_results(config, monkeypatch, use_sse):
    upstream, observed, calls = FastAPI(), [], []

    @upstream.api_route("/mcp", methods=["GET", "POST", "DELETE"])
    async def endpoint(request: Request):
        if request.method != "POST":
            return Response(status_code=405)
        observed.append(dict(request.headers))
        message = await request.json()
        if "id" not in message:
            return Response(status_code=202)
        method = message["method"]
        if method == "initialize":
            value = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-upstream", "version": "1"},
            }
        elif method == "tools/list":
            second = bool(message.get("params", {}).get("cursor"))
            value = {
                "tools": [
                    {
                        "name": "second" if second else "first",
                        "description": "测试工具",
                        "inputSchema": {"type": "object"},
                    }
                ]
            }
            if not second:
                value["nextCursor"] = "page2"
        elif method == "tools/call":
            calls.append(message["params"])
            value = {"content": [{"type": "text", "text": "upstream-result"}], "isError": True}
        else:
            value = {}
        payload = {"jsonrpc": "2.0", "id": message["id"], "result": value}
        if use_sse:
            return Response(
                "event: message\ndata: " + json.dumps(payload) + "\n\n",
                media_type="text/event-stream",
                headers={"Mcp-Session-Id": "test-session"},
            )
        return JSONResponse(payload, headers={"Mcp-Session-Id": "test-session"})

    original = PinnedTransport.__init__

    def init(self, ctx, maximum):
        original(self, ctx, maximum)
        self.inner = httpx.ASGITransport(upstream)

    monkeypatch.setattr(PinnedTransport, "__init__", init)
    network = NetworkPolicy(config)
    monkeypatch.setattr(network, "resolve", lambda *args: "192.0.2.1")

    def context():
        return Context(
            {"connection": {"url": "https://mcp.example.test/mcp"}},
            {"config": {"auth_mode": "bearer"}},
            {"token": "upstream-test-token"},
            dict(DEFAULTS),
            network,
        )

    kind = MCPProxyAssetType()
    tools = await kind.discover(context())
    assert [t["name"] for t in tools] == ["first", "second"]
    assert all(t["spec_hash"] for t in tools)
    response = await kind.execute("first", {"x": 1}, context(), tools[0])
    assert response["isError"] is True
    assert response["content"][0]["text"] == "upstream-result"
    assert len(calls) == 1
    assert calls[0]["name"] == "first"
    assert calls[0]["arguments"] == {"x": 1}
    assert all(h["authorization"] == "Bearer upstream-test-token" for h in observed)
    assert all(h["host"] == "mcp.example.test" for h in observed)
    assert any(h.get("mcp-session-id") == "test-session" for h in observed)


async def test_upstream_sse_transport(config, monkeypatch):
    """SSE 传输端到端：官方 FastMCP SSE 上游跑真实 uvicorn，DNS 解析 mock 到 127.0.0.1。"""
    from mcp.server.fastmcp import FastMCP
    from mcp.server.transport_security import TransportSecuritySettings

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    upstream = FastMCP(
        "sse-upstream",
        host="127.0.0.1",
        port=port,
        transport_security=TransportSecuritySettings(allowed_hosts=[f"mcp.example.test:{port}"]),
    )

    @upstream.tool()
    def first(x: int) -> str:
        """测试工具"""
        return "upstream-result:" + str(x)

    observed = []

    def wrap(app):
        async def middleware(scope, receive, send):
            if scope["type"] == "http":
                observed.append(dict(scope["headers"]))
            await app(scope, receive, send)

        return middleware

    server_config = uvicorn.Config(wrap(upstream.sse_app()), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(server_config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:  # pragma: no cover
        await asyncio.sleep(0.02)

    # 出站登记用替换后的配置副本（测试基线没有该随机端口，明文目标显式 allow_http）；
    # DNS 解析 mock 到 127.0.0.1，PinnedTransport 保持真实传输层。
    network = NetworkPolicy(replace(config, outbound=({"host": "mcp.example.test", "port": port, "allow_http": True},)))
    monkeypatch.setattr(network, "resolve", lambda *args: "127.0.0.1")

    def context():
        return Context(
            {"connection": {"url": f"http://mcp.example.test:{port}/sse", "transport": "sse"}},
            {"config": {"auth_mode": "bearer"}},
            {"token": "upstream-test-token"},
            dict(DEFAULTS),
            network,
        )

    kind = MCPProxyAssetType()
    try:
        tools = await kind.discover(context())
        assert [t["name"] for t in tools] == ["first"]
        assert all(t["spec_hash"] for t in tools)
        response = await kind.execute("first", {"x": 1}, context(), tools[0])
        assert response["isError"] is False
        assert response["content"][0]["text"] == "upstream-result:1"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert observed
    assert all(h[b"authorization"] == b"Bearer upstream-test-token" for h in observed)
    assert all(h[b"host"] == f"mcp.example.test:{port}".encode() for h in observed)
