import asyncio

import httpx

from app.core.security import GatewayError


class LimitedStream(httpx.AsyncByteStream):
    def __init__(self, response, transport):
        self.response, self.transport = response, transport

    async def __aiter__(self):
        async for chunk in self.response.aiter_raw():
            self.transport.used += len(chunk)
            if self.transport.used > self.transport.maximum:
                raise GatewayError("UPSTREAM_SIZE", "上游累计响应超过上限", 502)
            self.transport.ctx.remaining()
            yield chunk

    async def aclose(self):
        await self.response.aclose()


class PinnedTransport(httpx.AsyncBaseTransport):
    """将请求固定到已校验的来源与解析后的 IP，拒绝跨来源、重定向与压缩响应。"""

    def __init__(self, ctx, maximum, ssl_context=None, accept_redirect=None):
        self.ctx, self.maximum, self.used = ctx, maximum, 0
        self.accept_redirect = accept_redirect
        # 只接受装配好的 SSLContext：客户端证书必须在 context 上预先加载，
        # httpx 的 verify 为路径字符串时会忽略同时传入的 cert（客户端证书静默丢失导致 401）。
        self.inner = httpx.AsyncHTTPTransport(retries=0, verify=ssl_context)
        self.origin = httpx.URL(ctx.asset["connection"]["url"])

    async def handle_async_request(self, request):
        if (request.url.scheme, request.url.host, request.url.port) != (
            self.origin.scheme,
            self.origin.host,
            self.origin.port,
        ):
            raise GatewayError("UPSTREAM_ORIGIN", "禁止跨来源上游请求", 403)
        # 出站校验只针对目标来源：业务 query（limit、tailLines 等）不参与固定 IP 与登记校验，
        # 否则 Kubernetes 列表/日志等自带 query 的合法请求会被 INVALID_URL 误拒。
        host, port = self.ctx.network.url(str(request.url.copy_with(query=None, fragment=None)))
        ip = await asyncio.to_thread(self.ctx.network.resolve, host, port)
        self.ctx.remaining()
        request.headers["host"] = self.origin.netloc.decode()
        request.headers["accept-encoding"] = "identity"
        request.extensions["sni_hostname"] = host
        logical_url = request.url
        request.url = request.url.copy_with(host=ip)
        try:
            response = await self.inner.handle_async_request(request)
        finally:
            # httpx 按逻辑来源提取 Cookie；固定 IP 不应改变 Cookie 的主机与路径归属。
            request.url = logical_url
        if response.status_code in (301, 302, 303, 307, 308):
            if not self.accept_redirect or not self.accept_redirect(request, response):
                await response.aclose()
                raise GatewayError("UPSTREAM_REDIRECT", "上游重定向被拒绝", 502)
        if response.headers.get("content-encoding", "identity") != "identity":
            await response.aclose()
            raise GatewayError("UPSTREAM_ENCODING", "上游必须返回未压缩响应", 502)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=LimitedStream(response, self),
            extensions=response.extensions,
        )

    async def aclose(self):
        await self.inner.aclose()
