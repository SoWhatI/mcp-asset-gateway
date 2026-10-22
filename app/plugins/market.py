"""可信插件市场客户端：签名静态索引 + HTTPS 制品存储。

索引为 JSON 文档（含各版本制品相对路径与 sha256），签名是 ed25519；
信任公钥与来源由部署配置固定，索引自身不能引入新的信任根。
支持 http(s):// 与 file://（离线内网/测试场景），市场不可达不影响已启用插件。
"""

import base64

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.db import now
from app.core.security import GatewayError

MAX_INDEX_BYTES = 2 * 1024 * 1024
INDEX_TTL_MS = 24 * 3600 * 1000


def load_public_key(encoded):
    if not encoded:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise ValueError("PLUGIN_MARKET_PUBLIC_KEY 必须是 base64 编码的 ed25519 公钥") from None
    if len(raw) != 32:
        raise ValueError("PLUGIN_MARKET_PUBLIC_KEY 长度不正确（需要 32 字节 ed25519 公钥）")
    return Ed25519PublicKey.from_public_bytes(raw)


class MarketClient:
    def __init__(self, base_url, public_key, timeout=10):
        self.base_url = (base_url or "").rstrip("/")
        self.public_key = public_key
        self.timeout = timeout
        self._cached = None
        self._cached_at = 0

    @property
    def configured(self):
        return bool(self.base_url) and self.public_key is not None

    def index(self, refresh=False):
        """获取并验签市场索引；结果按 TTL 缓存，失败时沿用上次良好索引。"""
        if not self.configured:
            raise GatewayError("MARKET_UNCONFIGURED", "未配置插件市场来源或公钥", 503)
        if not refresh and self._cached and now() - self._cached_at < INDEX_TTL_MS:
            return self._cached
        payload = self._fetch_binary("index.json")
        signature_b64 = self._fetch_text("index.sig").strip()
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            self.public_key.verify(signature, payload)
        except (InvalidSignature, ValueError, TypeError):
            raise GatewayError("MARKET_SIGNATURE", "市场索引签名校验失败", 502) from None
        index = self._parse_index(payload)
        self._cached, self._cached_at = index, now()
        return index

    def _parse_index(self, payload):
        import json

        if len(payload) > MAX_INDEX_BYTES:
            raise GatewayError("MARKET_LIMIT", "市场索引超过大小上限", 502)
        try:
            index = json.loads(payload)
        except ValueError:
            raise GatewayError("MARKET_PROTOCOL", "市场索引不是合法 JSON", 502) from None
        if not isinstance(index, dict) or index.get("version") != 1 or not isinstance(index.get("plugins"), list):
            raise GatewayError("MARKET_PROTOCOL", "市场索引格式不正确", 502)
        expires = index.get("expires_at")
        if type(expires) is not int or not now() < expires:
            raise GatewayError("MARKET_EXPIRED", "市场索引已过期，请发布方更新", 502)
        return index

    def artifact_url(self, relative):
        if not isinstance(relative, str) or not relative or relative.startswith(("/", "..")) or "://" in relative:
            raise GatewayError("MARKET_PROTOCOL", "制品路径不合法", 502)
        if self.base_url.startswith("file://"):
            return self.base_url + "/" + relative
        return self.base_url + "/" + relative

    def download(self, relative, sink, max_bytes=200 * 1024 * 1024):
        """流式下载制品到 sink(bytes)；校验大小上限。"""
        url = self.artifact_url(relative)
        if url.startswith("file://"):
            payload = self._fetch_binary(relative)
            if len(payload) > max_bytes:
                raise GatewayError("DOWNLOAD_LIMIT", "制品超过下载大小上限", 502)
            sink(payload)
            return len(payload)
        total = 0
        try:
            with httpx.Client(verify=True, follow_redirects=False, trust_env=False, timeout=self.timeout) as client:
                with client.stream("GET", url) as response:
                    response.raise_for_status()
                    for chunk in response.iter_bytes(64 * 1024):
                        total += len(chunk)
                        if total > max_bytes:
                            raise GatewayError("DOWNLOAD_LIMIT", "制品超过下载大小上限", 502)
                        sink(chunk)
        except GatewayError:
            raise
        except (httpx.HTTPError, OSError) as error:
            raise GatewayError("MARKET_UNREACHABLE", f"制品下载失败：{error}", 502) from None
        return total

    def _fetch_text(self, relative):
        return self._fetch_binary(relative).decode()

    def _fetch_binary(self, relative):
        url = self.artifact_url(relative)
        if url.startswith("file://"):
            import pathlib

            path = pathlib.Path(url[len("file://") :])
            try:
                return path.read_bytes()
            except OSError as error:
                raise GatewayError("MARKET_UNREACHABLE", f"市场文件读取失败：{error}", 502) from None
        try:
            response = httpx.get(url, verify=True, follow_redirects=False, trust_env=False, timeout=self.timeout)
            response.raise_for_status()
        except (httpx.HTTPError, OSError) as error:
            raise GatewayError("MARKET_UNREACHABLE", f"市场不可达：{error}", 502) from None
        return response.content


def market_view(index, query=""):
    """把验签后的索引整理成控制台可用的插件列表（搜索按 id/名称/发布者）。"""
    terms = (query or "").lower().split()
    items = []
    for plugin in index.get("plugins", []):
        if not isinstance(plugin, dict) or not plugin.get("id"):
            continue
        versions = [v for v in plugin.get("versions", []) if isinstance(v, dict)]
        if not versions:
            continue
        latest = versions[0]
        text = " ".join(
            (plugin.get("id", ""), plugin.get("name", ""), plugin.get("publisher", ""), plugin.get("description", ""))
        ).lower()
        if terms and not all(term in text for term in terms):
            continue
        items.append(
            {
                "id": plugin["id"],
                "publisher": plugin.get("publisher", ""),
                "name": plugin.get("name", plugin["id"]),
                "description": plugin.get("description", ""),
                "capabilities": plugin.get("capabilities", {}),
                "latest_version": latest.get("version"),
                "versions": [
                    {
                        "version": v.get("version"),
                        "sha256": v.get("sha256"),
                        "size": v.get("size"),
                        "sdk_protocol": v.get("sdk_protocol"),
                        "gateway_compat": v.get("gateway_compat", ""),
                        "published_at": v.get("published_at"),
                        "changes": v.get("changes", ""),
                        "types": v.get("types", []),
                    }
                    for v in versions
                ],
            }
        )
    return items
