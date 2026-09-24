import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
from collections import OrderedDict
from urllib.parse import urlsplit

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


class GatewayError(Exception):
    def __init__(self, code, message, status=422):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def new_token():
    return "tok_" + secrets.token_urlsafe(32)


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password.encode()) <= 72:
        raise GatewayError("PASSWORD_LENGTH", "密码长度必须为 12～72 个 UTF-8 字节")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def password_check(password, hashed):
    if not isinstance(password, str) or len(password.encode()) > 72:
        return False
    return bcrypt.checkpw(password.encode(), hashed.encode())


class Vault:
    def __init__(self, key, key_id):
        self.fernet = Fernet(key.encode())
        self.key_id = key_id

    def encrypt(self, value):
        return self.fernet.encrypt(json.dumps(value).encode()).decode()

    def decrypt(self, value, key_id):
        if value is None:
            return {}
        if key_id != self.key_id:
            raise GatewayError("KEY_MISMATCH", "凭据密钥版本不匹配", 503)
        try:
            return json.loads(self.fernet.decrypt(value.encode()))
        except (InvalidToken, ValueError, TypeError):
            raise GatewayError("DECRYPT_FAILED", "凭据解密校验失败", 503) from None


def depth(value, level=0):
    if level > 32:
        raise GatewayError("TOO_DEEP", "JSON 嵌套层数超限")
    if isinstance(value, dict):
        for item in value.values():
            depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            depth(item, level + 1)


def check_schema(schema):
    depth(schema)

    def walk(item):
        if isinstance(item, dict):
            if "$ref" in item and (not isinstance(item["$ref"], str) or not item["$ref"].startswith("#/")):
                raise GatewayError("REMOTE_SCHEMA", "不允许外部 schema 引用")
            if any(k in item for k in ("$id", "$dynamicRef", "$recursiveRef")):
                raise GatewayError("UNSUPPORTED_SCHEMA", "不支持动态或重定位 schema 引用")
            for value in item.values():
                walk(value)
        elif isinstance(item, list):
            for value in item:
                walk(value)

    walk(schema)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        raise GatewayError("INVALID_SCHEMA", "工具 schema 无效") from None


def _field_label(schema, path):
    """字段可读描述：优先 schema 标题（无标题时回退字段键），并附带原始路径。"""
    raw = ".".join(str(step) for step in path)
    node, parts = schema, []
    for step in path:
        if not isinstance(node, dict):
            return raw
        if isinstance(step, int):
            node = node.get("items") if isinstance(node.get("items"), dict) else {}
            parts.append(f"第 {step + 1} 项")
            continue
        child = (node.get("properties") or {}).get(str(step))
        if not isinstance(child, dict):
            return raw
        node = child
        if child.get("title"):
            parts.append(str(child["title"]))
    label = " ".join(parts)
    if not label:
        return raw
    return f"{label}（{raw}）" if label != raw else label


def validate(schema, value):
    depth(value)
    try:
        Draft202012Validator(schema).validate(value)
    except RecursionError:
        raise GatewayError("VALIDATION", "字段类型、必填项或允许值不符合 schema") from None
    except ValidationError as error:
        # 不回显入参，尤其是密码字段；只提示首个不合规字段与约束，便于输入自查。
        path = list(error.absolute_path)
        missing = re.match(r"'(.+)' is a required property", error.message) if error.validator == "required" else None
        unexpected = (
            "、".join(re.findall(r"'(.+?)'", error.message)) if error.validator == "additionalProperties" else ""
        )
        if missing:
            detail = f"缺少必填字段 {_field_label(schema, path + [missing.group(1)])}"
        elif unexpected:
            prefix = ".".join(str(step) for step in path)
            detail = f"包含不支持的字段 {prefix + '.' if prefix else ''}{unexpected}"
        else:
            where = _field_label(schema, path)
            detail = (
                f"字段 {where} 未通过 {error.validator or '格式'} 校验"
                if where
                else f"未通过 {error.validator or '格式'} 校验"
            )
        raise GatewayError("VALIDATION", f"字段类型、必填项或允许值不符合 schema（{detail}）") from None


class RateLimit:
    def __init__(self):
        self.items = OrderedDict()
        self.lock = threading.Lock()

    def check(self, key, limit=60, window=60):
        with self.lock:
            ts = time.monotonic()
            start, count = self.items.pop(key, (ts, 0))
            if ts - start >= window:
                start, count = ts, 0
            self.items[key] = (start, count + 1)
            while len(self.items) > 10000:
                self.items.popitem(last=False)
            if count >= limit:
                raise GatewayError("RATE_LIMIT", "请求过于频繁，请稍后重试", 429)


class NetworkPolicy:
    def __init__(self, config):
        self.config = config

    def registered(self, host, port):
        return any(x["host"].lower() == host.lower() and x["port"] == port for x in self.config.outbound)

    def require_registered(self, host, port, message="目标未在出站允许列表中登记"):
        if self.config.outbound_enforce and not self.registered(host, port):
            raise GatewayError("OUTBOUND_DENIED", message, 403)

    def resolve(self, host, port):
        self.require_registered(host, port)
        try:
            results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            raise GatewayError("DNS_FAILED", "目标名称解析失败", 502) from None
        addresses = list(dict.fromkeys(item[4][0] for item in results))
        if not addresses:
            raise GatewayError("DNS_FAILED", "没有可用的目标地址", 502)
        for value in addresses:
            address = ipaddress.ip_address(value)
            if getattr(address, "ipv4_mapped", None):
                address = address.ipv4_mapped
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise GatewayError("OUTBOUND_DENIED", "禁止访问回环、链路本地或非单播地址", 403)
        return addresses[0]

    def url(self, url):
        parsed = urlsplit(url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
            raise GatewayError("INVALID_URL", "上游 URL 必须为不含凭据的 HTTP(S) 地址")
        if parsed.query or parsed.fragment:
            raise GatewayError("INVALID_URL", "上游 URL 不允许 query 或 fragment")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        public = urlsplit(self.config.public_url)
        public_port = public.port or (443 if public.scheme == "https" else 80)
        if parsed.hostname in self.config.hosts and port == public_port:
            raise GatewayError("PROXY_LOOP", "禁止代理本网关来源")
        self.require_registered(parsed.hostname, port)
        if (
            self.config.outbound_enforce
            and parsed.scheme == "http"
            and not any(
                x["host"].lower() == parsed.hostname.lower() and x["port"] == port and x.get("allow_http") is True
                for x in self.config.outbound
            )
        ):
            raise GatewayError("TLS_REQUIRED", "明文上游必须在出站列表中显式设置 allow_http")
        return parsed.hostname, port


def equal(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())
