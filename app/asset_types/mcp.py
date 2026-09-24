import asyncio
import hashlib
import json
import re
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

from app.asset_types.base import AssetType, obj, text
from app.asset_types.pinned import PinnedTransport
from app.core.db import dumps
from app.core.security import GatewayError, check_schema, validate


def tool_hash(spec):
    approved = {k: spec.get(k) for k in ("name", "description", "inputSchema", "outputSchema", "annotations")}
    return hashlib.sha256(json.dumps(approved, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def public_name(account, upstream):
    prefix = account + "__"
    if re.fullmatch(r"[A-Za-z0-9_-]+", upstream) and len(prefix + upstream) <= 64:
        return prefix + upstream
    suffix = "_" + hashlib.sha256(upstream.encode()).hexdigest()[:12]
    clean = re.sub(r"[^A-Za-z0-9_-]", "_", upstream)
    return prefix + clean[: 64 - len(prefix) - len(suffix)] + suffix


class MCPProxyAssetType(AssetType):
    type_id, display_name, icon = "mcp", "上游 MCP 服务", "Connection"
    async_mode = True
    proxied = True
    connection_schema = obj(
        {
            "url": text("MCP URL", minLength=1),
            "transport": text("传输协议", enum=["streamable_http", "sse"], default="streamable_http"),
        },
        ["url"],
    )
    account_schema = obj(
        {
            "auth_mode": text("认证方式", enum=["none", "bearer", "header"], default="none"),
            "header_name": text("认证头名称", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$"),
        },
        ["auth_mode"],
    )
    credential_schema = obj({"token": text("上游认证值", format="password", maxLength=8192)})

    def validate_connection(self, network, connection):
        network.url(connection["url"])

    def catalog(self, account):
        return account["tool_catalog"]

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        if account["auth_mode"] != "none" and not credential.get("token"):
            raise GatewayError("CREDENTIAL_REQUIRED", "上游认证值不能为空")
        if "\n" in credential.get("token", "") or "\r" in credential.get("token", ""):
            raise GatewayError("HEADER_INVALID", "认证值不能包含换行")
        if account["auth_mode"] == "header":
            header = account.get("header_name", "").lower()
            if not header.startswith("x-") or header in ("x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"):
                raise GatewayError("HEADER_INVALID", "自定义认证头必须是非代理类 X- 前缀头")

    @asynccontextmanager
    async def session(self, ctx, maximum):
        cfg, credential = ctx.account["config"], ctx.credential
        headers = {}
        if cfg["auth_mode"] == "bearer":
            headers["Authorization"] = "Bearer " + credential["token"]
        elif cfg["auth_mode"] == "header":
            headers[cfg["header_name"]] = credential["token"]
        transport = PinnedTransport(ctx, maximum)
        connection = ctx.asset["connection"]
        async with AsyncExitStack() as stack:
            if connection.get("transport") == "sse":

                def factory(**kwargs):
                    return httpx.AsyncClient(
                        transport=transport, follow_redirects=False, trust_env=False, **kwargs
                    )

                # SSE 传输：GET /sse 建立事件流，POST 地址由上游 endpoint 事件给出。
                # httpx client 必须经 factory 注入 PinnedTransport，保证出站校验与来源固定同样生效。
                streams = await stack.enter_async_context(
                    sse_client(
                        connection["url"],
                        headers=headers,
                        timeout=ctx.remaining(),
                        httpx_client_factory=factory,
                    )
                )
            else:
                client = await stack.enter_async_context(
                    httpx.AsyncClient(
                        transport=transport,
                        headers=headers,
                        follow_redirects=False,
                        trust_env=False,
                        timeout=httpx.Timeout(ctx.remaining(), connect=5),
                    )
                )
                streams = await stack.enter_async_context(
                    streamable_http_client(connection["url"], http_client=client)
                )
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                yield session

    async def discover(self, ctx):
        async with asyncio.timeout(ctx.remaining()):
            async with self.session(ctx, 2 * 1024 * 1024) as session:
                tools, seen, cursor, size = [], set(), None, 0
                for _ in range(10):
                    page = await session.list_tools(cursor=cursor)
                    for item in page.tools:
                        spec = item.model_dump(by_alias=True, exclude_none=True)
                        if spec["name"] in seen:
                            raise GatewayError("DUPLICATE_TOOL", "上游目录包含重复工具名")
                        seen.add(spec["name"])
                        check_schema(spec["inputSchema"])
                        if spec.get("outputSchema"):
                            check_schema(spec["outputSchema"])
                        size += len(dumps(spec).encode())
                        if len(tools) >= 200 or size > 2 * 1024 * 1024:
                            raise GatewayError("CATALOG_LIMIT", "上游工具目录超过限制")
                        spec["spec_hash"] = tool_hash(spec)
                        tools.append(spec)
                    cursor = page.nextCursor
                    if not cursor:
                        return tools
                raise GatewayError("CATALOG_LIMIT", "上游目录分页超过限制")

    async def execute(self, name, args, ctx, spec):
        validate(spec["inputSchema"], args)
        async with asyncio.timeout(ctx.remaining()):
            async with self.session(ctx, ctx.limits["max_output_bytes"] + 65536) as session:
                response = await session.call_tool(name, arguments=args)
                value = response.model_dump(by_alias=True, exclude_none=True)
                value.pop("_meta", None)
                if len(dumps(value).encode()) > ctx.limits["max_output_bytes"]:
                    raise GatewayError("OUTPUT_LIMIT", "上游工具结果超过输出上限")
                return value

    async def health(self, ctx):
        async with asyncio.timeout(ctx.remaining()):
            async with self.session(ctx, 65536) as session:
                await session.send_ping()
                return {"reachable": True}
