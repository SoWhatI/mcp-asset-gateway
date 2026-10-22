"""插件类型桥接：把工作进程背后的插件实现适配为网关 AssetType 接口。

事务内安全：validate_connection/validate_config 只做本地 schema 与出站登记校验，
不发起 IPC；插件侧深度校验由 deep_validate_* 在写事务之外完成。
动态目录类型（dynamic_tools）完全复用现有 mcp 目录语义：
tool_catalog_json、catalog_refreshed_at、spec_hash 版本绑定与刷新机制。
"""

import json

from app.asset_types.base import AssetType, obj, tool_hash
from app.core.security import GatewayError, check_schema, validate

CATALOG_TOOLS_LIMIT = 200
CATALOG_BYTES_LIMIT = 2 * 1024 * 1024


class PluginAssetType(AssetType):
    async_mode = True
    # 插件工具统一按账号加前缀发布，与是否动态目录无关。
    account_scoped_names = True

    def __init__(self, descriptor, pool, plugin_id, version_id, artifact_hash):
        self.type_id = descriptor["type_id"]
        self.display_name = descriptor.get("display_name") or self.type_id
        self.icon = descriptor.get("icon") or "Connection"
        self.default_port = descriptor.get("default_port")
        self.connection_mode = descriptor.get("connection_mode") or "host_port"
        self.proxied = bool(descriptor.get("dynamic_tools"))
        self.connection_schema = descriptor.get("connection_schema") or obj({})
        self.account_schema = descriptor.get("account_schema") or obj({})
        self.credential_schema = descriptor.get("credential_schema") or obj({})
        self.policy_schema = descriptor.get("policy_schema") or obj({})
        self.tools = descriptor.get("tools") or []
        self.pool = pool
        self.plugin_id = plugin_id
        self.version_id = version_id
        self.artifact_hash = artifact_hash

    def description(self):
        value = super().description()
        value["plugin"] = {
            "id": self.plugin_id,
            "version_id": self.version_id,
            "artifact_hash": self.artifact_hash,
        }
        return value

    def _params(self, ctx, remaining_ms=None):
        return {
            "type_id": self.type_id,
            "connection": (ctx.asset or {}).get("connection") or {},
            "account": (ctx.account or {}).get("config") or {},
            "policy": (ctx.account or {}).get("policy") or {},
            "credential": ctx.credential or {},
            "limits": ctx.limits or {},
            "remaining_ms": remaining_ms if remaining_ms is not None else int(ctx.remaining() * 1000),
        }

    def validate_connection(self, network, connection):
        """本地出站登记校验（事务内安全）。"""
        if self.connection_mode == "host_port":
            network.require_registered(
                connection.get("host"),
                connection.get("port", self.default_port),
                "请先在 OUTBOUND_ALLOWLIST 登记主机与端口",
            )
        elif self.connection_mode == "url":
            network.url(connection["url"])

    def validate_config(self, connection, account, policy, credential):
        """本地 schema 校验（事务内安全）。"""
        validate(self.connection_schema, connection)
        validate(self.account_schema, account)
        validate(self.policy_schema, policy)
        validate(self.credential_schema, credential)

    async def deep_validate_connection(self, connection):
        """插件侧连接深度校验；必须由调用方在写事务之外执行。"""
        await self.pool.request(
            "validate_connection", {"type_id": self.type_id, "connection": connection, "remaining_ms": 15000}, 20
        )

    async def deep_validate_config(self, connection, account, policy, credential):
        """插件侧账号深度校验；必须由调用方在写事务之外执行。"""
        await self.pool.request(
            "validate_config",
            {
                "type_id": self.type_id,
                "connection": connection,
                "account": account,
                "policy": policy,
                "credential": credential,
                "remaining_ms": 15000,
            },
            20,
        )

    def catalog(self, account):
        return account["tool_catalog"] if self.proxied else self.tools

    async def discover(self, ctx):
        raw = await self.pool.request("discover_tools", self._params(ctx), max(5, ctx.remaining()))
        specs, seen, size = [], set(), 0
        for item in raw or []:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise GatewayError("PLUGIN_PROTOCOL", "插件返回的工具目录格式不正确", 502)
            if item["name"] in seen:
                raise GatewayError("DUPLICATE_TOOL", "插件目录包含重复工具名")
            seen.add(item["name"])
            check_schema(item.get("inputSchema") or {"type": "object"})
            if item.get("outputSchema"):
                check_schema(item["outputSchema"])
            spec = {
                k: item[k] for k in ("name", "description", "inputSchema", "outputSchema", "annotations") if k in item
            }
            spec["spec_hash"] = tool_hash(spec)
            size += len(json.dumps(spec, ensure_ascii=False).encode())
            if len(specs) >= CATALOG_TOOLS_LIMIT or size > CATALOG_BYTES_LIMIT:
                raise GatewayError("CATALOG_LIMIT", "插件工具目录超过限制")
            specs.append(spec)
        return specs

    async def execute(self, name, args, ctx, spec):
        params = self._params(ctx)
        params.update({"tool": name, "arguments": args})
        value = await self.pool.request("execute", params, max(5, ctx.remaining()))
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("content"), list)
            or not isinstance(value.get("isError"), bool)
        ):
            raise GatewayError("PLUGIN_PROTOCOL", "插件返回的结果不是 MCP 内容对象", 502)
        return value

    async def health(self, ctx):
        value = await self.pool.request("health", self._params(ctx), max(5, ctx.remaining()))
        return value if isinstance(value, dict) else {"value": value}
