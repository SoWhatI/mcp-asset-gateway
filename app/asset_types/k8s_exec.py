"""有界 Kubernetes remotecommand WebSocket 客户端；固定 IP、验证 TLS、不重试。"""

import asyncio
import contextlib
import json
from urllib.parse import urlencode, urlsplit

from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Ping, RejectConnection, Request, TextMessage
from wsproto.utilities import ProtocolError

from app.core.security import GatewayError

PROTOCOL = "v4.channel.k8s.io"


def exit_status(data):
    try:
        status = json.loads(data)
        if status.get("status") == "Success":
            return 0
        if status.get("reason") == "NonZeroExitCode":
            for cause in status.get("details", {}).get("causes", []):
                value = cause.get("message", "")
                if cause.get("reason") == "ExitCode" and isinstance(value, str) and value.isdecimal():
                    code = int(value)
                    if 0 < code <= 255:
                        return code
    except (ValueError, AttributeError, TypeError):
        pass
    raise GatewayError("K8S_EXEC_STATUS", "无法确认容器退出状态；远端状态可能未知，勿自动重试", 502)


async def exec_stream(ctx, path, command, container, headers, ssl_context):
    url = ctx.asset["connection"]["url"]
    host, port = ctx.network.url(url)
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise GatewayError("TLS_REQUIRED", "Kubernetes exec 必须使用 HTTPS", 403)
    tls = ssl_context
    params = [("command", value) for value in command]
    params += [("stdin", "false"), ("tty", "false"), ("stdout", "true"), ("stderr", "true")]
    if container:
        params.append(("container", container))
    target = parsed.path.rstrip("/") + path + "?" + urlencode(params)
    ws = WSConnection(ConnectionType.CLIENT)
    writer = None
    # MCP 文本结果还会再次 JSON 编码，预留控制字符转义与结果结构的空间。
    maximum = max(1, (ctx.limits["max_output_bytes"] - 600) // 12)
    streams = {1: bytearray(), 2: bytearray()}
    used = received = 0
    channel = None
    status_data = bytearray()
    exit_code = None
    accepted = closed = truncated = False
    handshake = bytearray()
    try:
        async with asyncio.timeout(ctx.remaining()):
            async with asyncio.timeout(min(ctx.remaining(), ctx.limits["connect_timeout_seconds"])):
                ip = await asyncio.to_thread(ctx.network.resolve, host, port)
                reader, writer = await asyncio.open_connection(ip, port, ssl=tls, server_hostname=host, limit=32768)
            ctx.add_closer(writer.close)
            writer.write(
                ws.send(
                    Request(
                        host=parsed.netloc,
                        target=target,
                        subprotocols=[PROTOCOL],
                        extra_headers=[(key.encode("ascii"), value.encode("utf-8")) for key, value in headers.items()],
                    )
                )
            )
            await writer.drain()
            while not closed and not truncated:
                ctx.remaining()
                data = await reader.read(16384)
                if not data:
                    break
                received += len(data)
                if received > ctx.limits["max_output_bytes"] * 4 + 65536:
                    truncated = True
                    break
                if not accepted:
                    handshake.extend(data)
                    end = handshake.find(b"\r\n\r\n")
                    if (end < 0 and len(handshake) > 16384) or end > 16384:
                        raise GatewayError("K8S_EXEC_PROTOCOL", "exec 握手响应过大；远端状态可能未知", 502)
                    if end < 0:
                        continue
                    data = bytes(handshake)
                    handshake.clear()
                ws.receive_data(data)
                for event in ws.events():
                    if isinstance(event, AcceptConnection):
                        if event.subprotocol != PROTOCOL:
                            raise GatewayError("K8S_EXEC_PROTOCOL", "服务端未协商 exec v4 协议；远端状态可能未知", 502)
                        accepted = True
                    elif isinstance(event, RejectConnection):
                        code, message = {
                            401: ("K8S_AUTH_FAILED", "Kubernetes 认证失败"),
                            403: ("K8S_FORBIDDEN", "请核对 pods/exec 的 RBAC 权限"),
                            404: ("K8S_NOT_FOUND", "目标 Pod 或 exec 接口不存在"),
                        }.get(event.status_code, ("K8S_EXEC_PROTOCOL", "服务端拒绝 WebSocket exec，请核对协议支持"))
                        if 300 <= event.status_code < 400:
                            code, message = "REDIRECT_DENIED", "exec 不允许重定向"
                        raise GatewayError(code, message, 502)
                    elif isinstance(event, Ping):
                        writer.write(ws.send(event.response()))
                        await writer.drain()
                    elif isinstance(event, TextMessage):
                        raise GatewayError("K8S_EXEC_PROTOCOL", "exec 返回了非二进制数据；远端状态可能未知", 502)
                    elif isinstance(event, BytesMessage):
                        chunk = bytes(event.data)
                        if channel is None:
                            if not chunk:
                                if event.message_finished:
                                    raise GatewayError("K8S_EXEC_PROTOCOL", "exec 通道消息为空；远端状态可能未知", 502)
                                continue
                            channel, chunk = chunk[0], chunk[1:]
                        if channel in streams:
                            take = min(len(chunk), maximum - used)
                            streams[channel].extend(chunk[:take])
                            used += take
                            if take < len(chunk):
                                truncated = True
                                break
                        elif channel == 3:
                            if len(status_data) + len(chunk) > 16384:
                                raise GatewayError("K8S_EXEC_STATUS", "exec 状态响应过大；远端状态可能未知", 502)
                            status_data.extend(chunk)
                        else:
                            raise GatewayError("K8S_EXEC_PROTOCOL", "exec 返回了未知通道；远端状态可能未知", 502)
                        if event.message_finished:
                            if channel == 3:
                                if exit_code is not None:
                                    raise GatewayError("K8S_EXEC_STATUS", "exec 返回了重复状态；远端状态可能未知", 502)
                                exit_code = exit_status(status_data)
                                status_data.clear()
                            channel = None
                    elif isinstance(event, CloseConnection):
                        writer.write(ws.send(event.response()))
                        await writer.drain()
                        closed = event.code == 1000
                        if not closed:
                            exit_code = None
                        break
                if ws.state.name == "CLOSED":
                    break
    except ProtocolError:
        raise GatewayError("K8S_EXEC_PROTOCOL", "exec 协议异常；远端状态可能未知，勿自动重试", 502) from None
    except TimeoutError:
        raise
    except OSError:
        if accepted:
            raise GatewayError("K8S_EXEC_DISCONNECTED", "exec 连接中断；远端状态可能未知，勿自动重试", 502) from None
        raise
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 0.2)
    unknown = truncated or exit_code is None or not closed or channel is not None
    ctx.stats["truncated"] = truncated
    return {
        "stdout": streams[1].decode("utf-8", "replace"),
        "stderr": streams[2].decode("utf-8", "replace"),
        "exit_code": None if unknown else exit_code,
        "truncated": truncated,
        "remote_completion_unknown": unknown,
    }
