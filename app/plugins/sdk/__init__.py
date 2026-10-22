"""mcp-asset-gateway 插件 SDK（纯标准库，无第三方依赖）。

插件作者通过 ``import mag_plugin`` 使用本包；安装器会把 SDK 拷贝进插件目录，
工作进程负责把它加入 sys.path。SDK 不得引入任何网关代码或第三方依赖。

最小示例::

    from mag_plugin import Plugin, AssetType, ok

    class Example(AssetType):
        type_id = "acme.example"
        display_name = "示例资产"
        connection_schema = {"type": "object", "properties": {}, "required": [],
                             "additionalProperties": False}
        tools = [{
            "name": "ping",
            "description": "回声工具",
            "inputSchema": {"type": "object", "properties": {}, "required": [],
                            "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        }]

        def execute(self, tool, args, ctx):
            return ok({"pong": True})

    class ExamplePlugin(Plugin):
        asset_types = [Example]
"""

import json
import time

PROTOCOL = 1

RESOURCE_SCHEMA = {
    "query_timeout_seconds": {"type": "integer", "title": "总期限（秒）", "minimum": 1, "maximum": 30},
    "max_result_rows": {"type": "integer", "title": "结果行上限", "minimum": 1, "maximum": 5000},
    "max_output_bytes": {"type": "integer", "title": "输出字节上限", "minimum": 1024, "maximum": 1048576},
    "max_cell_chars": {"type": "integer", "title": "单元格字符上限", "minimum": 1, "maximum": 10000},
}


class PluginError(Exception):
    """插件主动抛出的业务错误；code 会原样进入网关审计与调用结果。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


class Timeout(Exception):
    """调用期限已到；工作进程外的强杀由网关进程管理器负责。"""


def ok(data):
    """把任意 JSON 数据包装为 MCP 文本结果。"""
    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, default=str)}],
        "isError": False,
    }


def failure(code, message):
    """构造 MCP 错误结果。"""
    return {
        "content": [{"type": "text", "text": json.dumps({"code": code, "message": message}, ensure_ascii=False)}],
        "isError": True,
    }


class Context:
    """单次调用的上下文：连接、账号、策略、凭据、限额与出站网络助手。

    凭据只在需要的操作中出现，工作进程不得落盘；主进程不会下发主密钥等网关机密。
    """

    def __init__(self, connection, account, policy, credential, limits, deadline, network):
        self.connection = connection or {}
        self.account = account or {}
        self.policy = policy or {}
        self.credential = credential or {}
        self.limits = limits or {}
        self._deadline = deadline
        self.net = network

    def remaining(self):
        """剩余期限（秒）；到期后插件应停止后续动作。"""
        return self._deadline - time.monotonic()

    def check_deadline(self):
        if self.remaining() <= 0:
            raise Timeout()


class AssetType:
    """插件资产类型基类；子类声明元数据、Schema 与工具实现。"""

    type_id = ""
    display_name = ""
    icon = "Connection"
    # 网络直连型资产的默认端口；URL 型资产保持 None。
    default_port = None
    # 连接形态决定主进程的出站校验方式：host_port 用登记端口校验，url 用 URL 校验。
    connection_mode = "host_port"
    # True 表示工具目录来自上游（discover_tools 动态发现、工具名加账号前缀、版本绑定）。
    dynamic_tools = False
    connection_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    account_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    credential_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    policy_schema = RESOURCE_SCHEMA
    tools = []

    def describe(self):
        return {
            "type_id": self.type_id,
            "display_name": self.display_name,
            "icon": self.icon,
            "default_port": self.default_port,
            "connection_mode": self.connection_mode,
            "dynamic_tools": self.dynamic_tools,
            "connection_schema": self.connection_schema,
            "account_schema": self.account_schema,
            "credential_schema": self.credential_schema,
            "policy_schema": self.policy_schema,
            "tools": self.tools,
        }

    def validate_connection(self, ctx, connection):
        """连接配置深度校验（在网关写事务之外执行）；默认仅做出站登记校验。"""
        if self.connection_mode == "host_port":
            ctx.net.check(connection.get("host"), connection.get("port") or self.default_port)
        elif self.connection_mode == "url":
            ctx.net.check_url(connection.get("url"))

    def validate_config(self, ctx, connection, account, policy, credential):
        """账号配置深度校验；默认无额外语义。"""

    def health(self, ctx):
        """连接测试；返回值会被 ok() 包装。"""
        return {"ok": True}

    def discover_tools(self, ctx):
        """动态工具发现；返回工具 spec 列表。仅 dynamic_tools=True 时调用。"""
        return []

    def execute(self, tool, args, ctx):
        raise PluginError("TOOL_MISSING", f"工具未实现：{tool}")


class Plugin:
    """插件入口基类；entry 指向本类子类。"""

    asset_types = []

    def describe(self):
        return {"asset_types": [one.describe() for one in self.asset_types]}
