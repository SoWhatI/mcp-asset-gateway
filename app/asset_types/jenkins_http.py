"""Jenkins 的有界、固定来源 HTTP 会话；写请求从不自动重试。"""

import json
import re
import ssl
from contextlib import asynccontextmanager
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit

import httpx

from app.asset_types.pinned import PinnedTransport
from app.core.security import GatewayError

DOCUMENT_LIMIT = 2 * 1024 * 1024


def root_url(value):
    try:
        parsed = urlsplit(value)
        decoded_path = parsed.path
        for _ in range(4):
            decoded_path = unquote(decoded_path)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or re.search(r"[\x00-\x20\x7f\\]", value)
            or re.search(r"[\x00-\x1f\x7f\\]", decoded_path)
            or any(p in (".", "..") for p in decoded_path.split("/"))
        ):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise GatewayError("INVALID_URL", "Jenkins 地址必须是不含凭据、查询、片段或路径穿越的 HTTP(S) 根地址") from None
    return value.rstrip("/") + "/"


def job_path(name):
    parts = name.split("/")
    for part in parts:
        decoded = part
        for _ in range(4):
            decoded = unquote(decoded)
        if not part or any(p in (".", "..") for p in decoded.split("/")) or re.search(r"[\x00-\x1f\x7f\\]", decoded):
            raise GatewayError("JENKINS_JOB_PATH", "任务全名含空路径、控制字符或路径穿越")
    # Jenkins 多分支名称中的斜杠本身存储为 %2F，必须再次编码为 %252F。
    return "".join("job/" + quote(part, safe="") + "/" for part in parts)


def tls_context(connection):
    ca = connection.get("ca_file")
    try:
        return (
            ssl.create_default_context(cadata=ca)
            if ca and "-----BEGIN" in ca
            else ssl.create_default_context(cafile=ca or None)
        )
    except (OSError, ValueError, ssl.SSLError):
        raise GatewayError("JENKINS_TLS", "Jenkins CA 无法加载，请检查 PEM 内容或容器内文件路径") from None


class JenkinsHTTP:
    def __init__(self, ctx):
        self.ctx = ctx
        self.root = root_url(ctx.asset["connection"]["url"])
        self.expected = None
        self.crumb_ready = False
        self.write_started = False
        maximum = ctx.account["policy"].get("max_log_scan_bytes", 8 * 1024 * 1024) + 8 * DOCUMENT_LIMIT
        self.transport = PinnedTransport(ctx, maximum, tls_context(ctx.asset["connection"]), self.accept_redirect)
        self.client = httpx.AsyncClient(
            transport=self.transport,
            auth=httpx.BasicAuth(ctx.account["config"]["username"], ctx.credential["api_token"]),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(ctx.remaining(), connect=min(5, ctx.remaining())),
        )

    async def __aenter__(self):
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *args):
        await self.client.__aexit__(*args)

    def location(self, request_url, value):
        if not value or re.search(r"[\x00-\x20\x7f\\]", value):
            return None
        try:
            target = httpx.URL(urljoin(str(request_url), value))
            origin = httpx.URL(self.root)
            if (
                (target.scheme, target.host, target.port) != (origin.scheme, origin.host, origin.port)
                or target.userinfo
                or target.query
                or target.fragment
            ):
                return None
            return target
        except (ValueError, httpx.InvalidURL):
            return None

    def accepted_location(self, request_url, value):
        target = self.location(request_url, value)
        if target is None or self.expected is None:
            return None
        path = target.raw_path.decode("ascii")
        if self.expected == "queue":
            prefix = httpx.URL(self.root + "queue/item/").raw_path.decode("ascii")
            if re.fullmatch(re.escape(prefix) + r"[1-9][0-9]*/?", path):
                return target
        elif path.rstrip("/") == httpx.URL(self.root + self.expected).raw_path.decode("ascii").rstrip("/"):
            return target
        return None

    def accept_redirect(self, request, response):
        return (
            request.method == "POST"
            and response.status_code in (302, 303)
            and self.accepted_location(request.url, response.headers.get("location")) is not None
        )

    def check(self, response, allowed=()):
        status = response.status_code
        if status in allowed or 200 <= status < 300:
            return
        if status == 401:
            raise GatewayError("JENKINS_AUTH", "Jenkins 认证失败，请检查用户名与 API Token", 502)
        if status == 403:
            crumb = b"crumb" in response.content.lower()
            raise GatewayError(
                "JENKINS_CSRF" if crumb else "JENKINS_FORBIDDEN",
                "Jenkins CSRF 校验失败" if crumb else "Jenkins 账号权限不足",
                403,
            )
        if status == 404:
            raise GatewayError("JENKINS_NOT_FOUND", "Jenkins 对象不存在或不可见", 404)
        if status == 409:
            raise GatewayError("JENKINS_CONFLICT", "任务当前不可构建或存在状态冲突", 409)
        raise GatewayError("JENKINS_UPSTREAM", f"Jenkins 返回异常 HTTP 状态 {status}", 502)

    @asynccontextmanager
    async def stream(self, path):
        self.ctx.remaining()
        try:
            async with self.client.stream("GET", self.root + path) as response:
                if response.status_code != 200:
                    await self.read_body(response, 65536)
                    self.check(response)
                yield response
        except (httpx.HTTPError, OSError) as error:
            code = (
                "JENKINS_TLS"
                if isinstance(error, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(error)
                else "JENKINS_NETWORK"
            )
            raise GatewayError(code, "Jenkins 连接、TLS 握手或读取失败", 502) from None

    async def read_body(self, response, maximum):
        chunks, total = [], 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > maximum:
                raise GatewayError("JENKINS_RESPONSE_LIMIT", "Jenkins 文档超过读取上限；未使用不完整内容", 502)
            chunks.append(chunk)
        response._content = b"".join(chunks)
        return response.content

    async def request(self, path, *, params=None, form=None, expected=None, allowed=(), maximum=DOCUMENT_LIMIT):
        self.ctx.remaining()
        method = "POST" if form is not None else "GET"
        if method == "POST":
            await self.crumb()
        self.expected = expected
        try:
            if method == "POST":
                self.write_started = True
            async with self.client.stream(
                method,
                self.root + path,
                params=params,
                content=urlencode(form, doseq=True).encode() if form is not None else None,
                headers={"Content-Type": "application/x-www-form-urlencoded"} if form is not None else None,
            ) as response:
                await self.read_body(response, maximum)
                self.check(response, allowed + ((302, 303) if expected else ()))
                return response
        except (httpx.HTTPError, OSError, TimeoutError) as error:
            if method == "POST":
                raise GatewayError(
                    "JENKINS_WRITE_UNKNOWN", "写请求未确认完成，远端状态可能未知；请查询状态，勿自动重试", 502
                ) from None
            code = (
                "JENKINS_TLS"
                if isinstance(error, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(error)
                else "JENKINS_NETWORK"
            )
            raise GatewayError(code, "Jenkins 连接、TLS 握手或读取失败", 502) from None
        finally:
            self.expected = None

    async def json(self, path, tree=None, allowed=()):
        response = await self.request(path, params={"tree": tree} if tree else None, allowed=allowed)
        if response.status_code in allowed:
            return None
        try:
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, RecursionError):
            raise GatewayError(
                "JENKINS_RESPONSE", "Jenkins 未返回有效 JSON 对象，可能被登录页面或代理拦截", 502
            ) from None

    async def crumb(self):
        if self.crumb_ready:
            return
        value = await self.json("crumbIssuer/api/json", allowed=(404,))
        if value:
            field, crumb = value.get("crumbRequestField", ""), value.get("crumb", "")
            if (
                not isinstance(field, str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", field)
                or field.lower()
                in {
                    "host",
                    "authorization",
                    "cookie",
                    "content-type",
                    "content-length",
                    "connection",
                    "transfer-encoding",
                }
                or not isinstance(crumb, str)
                or not re.fullmatch(r"[\x21-\x7e]{1,1024}", crumb)
            ):
                raise GatewayError("JENKINS_CSRF", "Jenkins crumb 响应不兼容", 502)
            self.client.headers[field] = crumb
        self.crumb_ready = True

    async def submit(self, path, form, expected):
        response = await self.request(path, form=form, expected=expected)
        if response.status_code not in (201, 302, 303):
            raise GatewayError("JENKINS_WRITE_UNKNOWN", "Jenkins 未返回可确认的提交响应；远端状态可能未知，勿重试", 502)
        self.expected = expected
        try:
            target = self.accepted_location(response.request.url, response.headers.get("location"))
        finally:
            self.expected = None
        if target is None:
            raise GatewayError(
                "JENKINS_WRITE_UNKNOWN", "Jenkins 提交响应缺少可信 Location；远端状态可能未知，勿重试", 502
            )
        if expected == "queue":
            return {
                "submitted": True,
                "queue_id": int(target.path.rstrip("/").split("/")[-1]),
                "queue_url": str(target),
            }
        return {
            "submitted": True,
            "queue_id": None,
            "reason": "Jenkins 表单仅返回目标页，未提供队列 ID",
            "url": str(target),
        }


def json_form(value):
    return {"json": json.dumps(value, ensure_ascii=False)}
