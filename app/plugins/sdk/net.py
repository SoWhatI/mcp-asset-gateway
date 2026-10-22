"""插件出站网络助手：登记校验、DNS 固定与 TLS 验证（纯标准库）。

网关在握手时下发出站允许列表，本模块在插件进程内复刻主进程 NetworkPolicy 的核心语义：
登记匹配、解析拒绝回环/链路本地/组播地址、连接固定到解析出的 IP、TLS 校验主机名、
拒绝重定向、响应字节上限。HTTP 用 http.client（天然不跟随重定向）。
"""

import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit

DEFAULT_MAX_BYTES = 524288


class OutboundError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


class NetworkGuard:
    def __init__(self, allowlist=None, enforce=False):
        self.allowlist = list(allowlist or [])
        self.enforce = bool(enforce and self.allowlist)

    def _registered(self, host, port):
        return any(
            str(x.get("host", "")).lower() == str(host).lower() and x.get("port") == port for x in self.allowlist
        )

    def check(self, host, port):
        """登记校验：enforce 开启时 host/port 必须在允许列表内。"""
        if not host or type(port) is not int:
            raise OutboundError("OUTBOUND_INVALID", "目标主机或端口缺失")
        if self.enforce and not self._registered(host, port):
            raise OutboundError("OUTBOUND_DENIED", "目标未在出站允许列表中登记")

    def _http_allowed(self, host, port):
        return any(
            str(x.get("host", "")).lower() == str(host).lower()
            and x.get("port") == port
            and x.get("allow_http") is True
            for x in self.allowlist
        )

    def check_url(self, url):
        """URL 型登记校验；返回 (scheme, host, port)。"""
        parsed = urlsplit(url or "")
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
            raise OutboundError("OUTBOUND_INVALID", "目标必须为不含凭据的 HTTP(S) 地址")
        if parsed.query or parsed.fragment:
            raise OutboundError("OUTBOUND_INVALID", "目标不允许 query 或 fragment")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.check(parsed.hostname, port)
        if self.enforce and parsed.scheme == "http" and not self._http_allowed(parsed.hostname, port):
            raise OutboundError("TLS_REQUIRED", "明文目标必须在出站列表中显式设置 allow_http")
        return parsed.scheme, parsed.hostname, port

    def resolve(self, host, port):
        """DNS 解析并返回固定 IP；拒绝回环、链路本地、组播与未指定地址。"""
        try:
            results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            raise OutboundError("DNS_FAILED", "目标名称解析失败") from None
        addresses = list(dict.fromkeys(item[4][0] for item in results))
        if not addresses:
            raise OutboundError("DNS_FAILED", "没有可用的目标地址")
        for value in addresses:
            address = ipaddress.ip_address(value)
            if getattr(address, "ipv4_mapped", None):
                address = address.ipv4_mapped
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise OutboundError("OUTBOUND_DENIED", "禁止访问回环、链路本地或非单播地址")
        return addresses[0]

    def request(
        self,
        method,
        url,
        body=None,
        headers=None,
        timeout=10,
        max_bytes=DEFAULT_MAX_BYTES,
    ):
        """发起一次 HTTP 请求：固定 IP、验证 TLS、拒绝重定向、限制响应大小。

        返回 ``(status, headers, data_bytes)``；超限抛 OutboundError("RESPONSE_LIMIT")。
        """
        scheme, host, port = self.check_url(url)
        pinned = self.resolve(host, port)
        method, timeout = method.upper(), max(1, min(timeout, 60))

        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        connector = _PinnedHTTPS if scheme == "https" else _PinnedHTTP
        connection = connector(host, pinned, port, timeout)
        try:
            connection.request(method, url if url.startswith("/") else _path_of(url), body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise OutboundError("RESPONSE_LIMIT", "响应超过字节上限")
            return response.status, dict(response.getheaders()), data
        except ssl.SSLError as error:
            raise OutboundError("TLS_FAILED", f"TLS 校验失败：{error}") from None
        except (TimeoutError, ConnectionError, OSError) as error:
            raise OutboundError("UPSTREAM_UNREACHABLE", f"目标连接失败：{error}") from None
        finally:
            connection.close()


def _path_of(url):
    parsed = urlsplit(url)
    return parsed.path or "/"


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, pinned_ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        # 连接固定到解析出的 IP，Host 头仍用逻辑主机名。
        self._create_connection = lambda address, t, source_address: socket.create_connection(
            (pinned_ip, address[1]), t, source_address
        )


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, pinned_ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._create_connection = lambda address, t, source_address: socket.create_connection(
            (pinned_ip, address[1]), t, source_address
        )
