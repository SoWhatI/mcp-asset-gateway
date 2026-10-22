#!/usr/bin/env python3
"""插件工作进程入口（纯标准库；由插件 venv 的解释器运行，不依赖网关代码）。

协议：stdin/stdout 上的行分隔 JSON-RPC（带请求 ID），stderr 独立输出日志。
加载顺序：插件目录插入 sys.path 头部 → 读取 manifest.json → 按 entry 导入插件类。
插件代码的 print/write 会被重定向到 stderr，防止污染协议通道。
"""

import argparse
import importlib
import json
import sys
import time
import traceback
from pathlib import Path

PROTOCOL = 1
MAX_LINE = 16 * 1024 * 1024


def log(event, **fields):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    print(f"[{stamp}] event={event} " + " ".join(f"{k}={v}" for k, v in fields.items()), file=sys.stderr, flush=True)


class WorkerError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def load_plugin(plugin_dir):
    root = Path(plugin_dir)
    for candidate in (root / "sdk", root):
        if candidate.is_dir():
            sys.path.insert(0, str(candidate))
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest.get("entry", "")
    module, _, class_name = entry.partition(":")
    if not module or not class_name:
        raise WorkerError("ENTRY_INVALID", f"manifest entry 不合法：{entry!r}")
    try:
        plugin_class = getattr(importlib.import_module(module), class_name)
        plugin = plugin_class()
    except Exception as error:
        raise WorkerError("ENTRY_LOAD_FAILED", f"插件入口加载失败：{error}") from None
    types = {}
    for kind in getattr(plugin, "asset_types", []) or []:
        instance = kind() if isinstance(kind, type) else kind
        if not getattr(instance, "type_id", ""):
            raise WorkerError("TYPE_INVALID", "插件资产类型缺少 type_id")
        if instance.type_id in types:
            raise WorkerError("TYPE_INVALID", f"插件内类型重复：{instance.type_id}")
        types[instance.type_id] = instance
    if not types:
        raise WorkerError("TYPE_INVALID", "插件未提供任何资产类型")
    return manifest, plugin, types


def build_context(guard, params):
    from mag_plugin import Context

    remaining = params.get("remaining_ms")
    deadline = time.monotonic() + (max(0, remaining) / 1000.0 if isinstance(remaining, (int, float)) else 30.0)
    return Context(
        params.get("connection"),
        params.get("account"),
        params.get("policy"),
        params.get("credential"),
        params.get("limits"),
        deadline,
        guard,
    )


def call_guarded(function, *args):
    """执行插件方法并把异常翻译为结构化错误；日志进 stderr，不进协议通道。"""
    from mag_plugin import PluginError, Timeout
    from mag_plugin.net import OutboundError

    try:
        # 返回值原样透传；execute 的结果形状由 wrap_execute 归一为 MCP 内容对象。
        return {"result": function(*args)}
    except Timeout:
        return {"error": {"code": "TIMEOUT", "message": "插件调用超时或取消；远端状态可能未知"}}
    except WorkerError as error:
        return {"error": {"code": error.code, "message": error.message}}
    except PluginError as error:
        return {"error": {"code": error.code, "message": error.message}}
    except OutboundError as error:
        return {"error": {"code": error.code, "message": error.message}}
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        return {"error": {"code": "PLUGIN_ERROR", "message": f"插件执行异常：{type(error).__name__}"}}


def wrap_execute(value):
    """插件 execute 的返回必须是 MCP 结果对象；其他形状自动包装。"""
    if isinstance(value, dict) and isinstance(value.get("content"), list) and isinstance(value.get("isError"), bool):
        return value
    from mag_plugin import ok

    return ok(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-dir", required=True)
    arguments = parser.parse_args()
    protocol_out = sys.stdout
    # 插件代码（含 import 阶段）看到的 stdout 一律重定向到 stderr，协议通道独占真实 stdout。
    sys.stdout = sys.stderr
    try:
        manifest, plugin, types = load_plugin(arguments.plugin_dir)
    except WorkerError as error:
        log("load_failed", code=error.code, message=error.message)
        print(json.dumps({"error": {"code": error.code, "message": error.message}}), file=protocol_out, flush=True)
        return 1
    except Exception:
        traceback.print_exc(file=sys.stderr)
        print(
            json.dumps({"error": {"code": "ENTRY_LOAD_FAILED", "message": "插件入口加载失败"}}),
            file=protocol_out,
            flush=True,
        )
        return 1
    guard = None

    def reply(request_id, payload):
        message = {"id": request_id, **payload}
        print(json.dumps(message, ensure_ascii=False), file=protocol_out, flush=True)

    while True:
        line = sys.stdin.buffer.readline(MAX_LINE)
        if not line:
            return 0
        if len(line) >= MAX_LINE or not line.strip():
            log("protocol_violation", reason="empty_or_oversized_line")
            return 1
        try:
            message = json.loads(line)
        except ValueError:
            reply(None, {"error": {"code": "PROTOCOL", "message": "请求不是合法 JSON"}})
            continue
        request_id, method, params = message.get("id"), message.get("method", ""), message.get("params") or {}
        if method == "shutdown":
            reply(request_id, {"result": {"ok": True}})
            return 0
        if method == "initialize":
            from mag_plugin.net import NetworkGuard

            rules = params.get("network") or {}
            guard = NetworkGuard(rules.get("allowlist"), rules.get("enforce"))
            reply(
                request_id,
                {
                    "result": {
                        "protocol": PROTOCOL,
                        "plugin": {
                            "id": manifest.get("id", ""),
                            "version": manifest.get("version", ""),
                            "publisher": manifest.get("publisher", ""),
                        },
                        "asset_types": [instance.describe() for instance in types.values()],
                    }
                },
            )
            continue
        kind = types.get(params.get("type_id"))
        if kind is None:
            reply(request_id, {"error": {"code": "TYPE_UNKNOWN", "message": "插件不提供该资产类型"}})
            continue
        ctx = build_context(guard, params)
        if method == "describe":
            outcome = call_guarded(kind.describe)
        elif method == "validate_connection":
            outcome = call_guarded(kind.validate_connection, ctx, params.get("connection") or {})
        elif method == "validate_config":
            outcome = call_guarded(
                kind.validate_config,
                ctx,
                params.get("connection") or {},
                params.get("account") or {},
                params.get("policy") or {},
                params.get("credential") or {},
            )
        elif method == "health":
            if ctx.remaining() <= 0:
                outcome = {"error": {"code": "TIMEOUT", "message": "调用期限已到"}}
            else:
                outcome = call_guarded(kind.health, ctx)
        elif method == "discover_tools":
            if ctx.remaining() <= 0:
                outcome = {"error": {"code": "TIMEOUT", "message": "调用期限已到"}}
            else:
                outcome = call_guarded(kind.discover_tools, ctx)
                if "result" in outcome:
                    tools = outcome["result"]
                    if not isinstance(tools, list):
                        outcome = {"error": {"code": "PLUGIN_ERROR", "message": "discover_tools 必须返回列表"}}
        elif method == "execute":
            if ctx.remaining() <= 0:
                outcome = {"error": {"code": "TIMEOUT", "message": "调用期限已到"}}
            else:
                outcome = call_guarded(kind.execute, params.get("tool"), params.get("arguments") or {}, ctx)
                if "result" in outcome:
                    outcome["result"] = wrap_execute(outcome["result"])
        else:
            outcome = {"error": {"code": "METHOD_UNKNOWN", "message": f"未知方法：{method}"}}
        reply(request_id, outcome)
        log("handled", method=method, ok="error" not in outcome)


if __name__ == "__main__":
    sys.exit(main())
