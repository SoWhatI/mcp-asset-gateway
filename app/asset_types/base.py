import asyncio
import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from app.core.security import GatewayError, validate


def obj(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def text(title, **kwargs):
    return {"type": "string", "title": title, "maxLength": 4096, **kwargs}


def upload_text(title, **kwargs):
    """可上传文件的文本字段：控制台展示上传按钮，文件内容直接作为字段值。"""
    return {**text(title, **kwargs), "x-upload": True}


def integer(title, minimum=1, maximum=2147483647, **kwargs):
    return {"type": "integer", "title": title, "minimum": minimum, "maximum": maximum, **kwargs}


def tool(name, description, properties, required=(), readonly=True):
    return {
        "name": name,
        "description": description,
        "inputSchema": obj(properties, required),
        "annotations": {"readOnlyHint": readonly, "destructiveHint": not readonly},
    }


def result(data):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, default=str)}], "isError": False}


def failed(code, message, request_id=None):
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps({"code": code, "message": message, "request_id": request_id}, ensure_ascii=False),
            }
        ],
        "isError": True,
    }


RESOURCE_SCHEMA = {
    "query_timeout_seconds": integer("总期限（秒）", 1, 30),
    "max_result_rows": integer("结果行上限", 1, 5000),
    "max_output_bytes": integer("输出字节上限", 1024, 1048576),
    "max_cell_chars": integer("单元格字符上限", 1, 10000),
}


@dataclass
class Context:
    asset: dict
    account: dict
    credential: dict
    limits: dict
    network: object
    legacy: bool = False
    enforce_host_key: bool = True
    deadline: float = 0
    cancelled: threading.Event = field(default_factory=threading.Event)
    closers: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    stats: dict = field(default_factory=dict)
    worker_future: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        self.deadline = time.monotonic() + self.limits["query_timeout_seconds"]

    def remaining(self):
        value = self.deadline - time.monotonic()
        if self.cancelled.is_set() or value <= 0:
            raise GatewayError("TIMEOUT", "调用超时；远端执行状态可能未知", 504)
        return value

    def add_closer(self, closer):
        with self.lock:
            if self.cancelled.is_set():
                closer()
            else:
                self.closers.append(closer)

    def close(self):
        with self.lock:
            closers, self.closers = self.closers, []
        for closer in reversed(closers):
            try:
                closer()
            except Exception:
                pass

    def cancel(self):
        self.cancelled.set()
        self.close()


class BlockingRunner:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="asset")
        self.slots = asyncio.Semaphore(16)

    async def run(self, ctx, fn):
        try:
            await asyncio.wait_for(self.slots.acquire(), 2)
        except TimeoutError:
            raise GatewayError("BUSY", "执行资源繁忙", 429) from None
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self.pool, fn)
        ctx.worker_future = future
        # 超时的阻塞线程仍占槽，避免超时风暴形成无限等待队列。
        future.add_done_callback(lambda _: self.slots.release())
        try:
            return await asyncio.wait_for(asyncio.shield(future), ctx.remaining())
        except (TimeoutError, asyncio.CancelledError, GatewayError):
            ctx.cancel()
            future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
            raise
        finally:
            if future.done():
                ctx.close()
            else:
                future.add_done_callback(lambda _: ctx.close())

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)


class AssetType:
    type_id = ""
    display_name = ""
    icon = "Connection"
    # 网络直连型资产的默认端口；URL 型资产（覆盖 validate_connection）保持 None。
    default_port = None
    # True 表示 execute/health/discover 为异步实现，不经 BlockingRunner 线程池。
    async_mode = False
    # True 表示工具目录来自上游（工具名需加前缀、刷新与版本校验走 mcp 目录语义）。
    proxied = False
    connection_schema = obj({})
    account_schema = obj({})
    credential_schema = obj({})
    policy_schema = obj(RESOURCE_SCHEMA)
    tools = []

    def description(self):
        return {
            "type_id": self.type_id,
            "display_name": self.display_name,
            "icon": self.icon,
            "default_port": self.default_port,
            "available": True,
            "connection_schema": self.connection_schema,
            "account_schema": self.account_schema,
            "credential_schema": self.credential_schema,
            "policy_schema": self.policy_schema,
            "tools": self.tools,
        }

    def validate_connection(self, network, connection):
        network.require_registered(
            connection["host"],
            connection.get("port", self.default_port),
            "请先在 OUTBOUND_ALLOWLIST 登记主机与端口",
        )

    def catalog(self, account):
        return self.tools

    def validate_config(self, connection, account, policy, credential):
        validate(self.connection_schema, connection)
        validate(self.account_schema, account)
        validate(self.policy_schema, policy)
        validate(self.credential_schema, credential)

    def validate_arguments(self, name, arguments):
        spec = next((t for t in self.tools if t["name"] == name), None)
        if not spec:
            raise GatewayError("TOOL_DENIED", "工具不存在或未授权", 403)
        validate(spec["inputSchema"], arguments)
        return copy.deepcopy(arguments)
