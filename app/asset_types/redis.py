import base64
import re
import socket
import ssl
import time

import redis

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool
from app.core.security import GatewayError

WRITE_TOOLS = ("redis_set", "redis_delete", "redis_expire")
SCAN_TYPES = ["string", "list", "set", "zset", "hash", "stream"]
INFO_FIELDS = {
    "server": ("redis_version", "redis_mode", "os", "arch_bits", "uptime_in_seconds", "uptime_in_days", "tcp_port"),
    "clients": ("connected_clients", "blocked_clients", "tracking_clients"),
    "memory": (
        "used_memory",
        "used_memory_human",
        "used_memory_peak_human",
        "maxmemory_human",
        "mem_fragmentation_ratio",
    ),
    "stats": (
        "total_connections_received",
        "total_commands_processed",
        "instantaneous_ops_per_sec",
        "keyspace_hits",
        "keyspace_misses",
        "expired_keys",
        "evicted_keys",
    ),
    "replication": ("role", "connected_slaves", "master_host", "master_link_status", "master_repl_offset"),
}


def glob_regex(pattern):
    """将 Redis glob 模式（* ? [..] [^..] 与 \\ 转义）翻译为等价正则。"""
    parts, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            parts.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        elif char == "[":
            end = index + 1
            if end < len(pattern) and pattern[end] == "^":
                end += 1
            if end < len(pattern) and pattern[end] == "]":
                end += 1
            while end < len(pattern) and pattern[end] != "]":
                end += 1
            if end >= len(pattern):
                parts.append(re.escape("["))
            else:
                body = pattern[index + 1 : end]
                negate = body.startswith("^")
                if negate:
                    body = body[1:]
                if not body:
                    parts.append(re.escape("[]"))
                else:
                    parts.append("[" + ("^" if negate else "") + re.sub(r"([\\\]^])", r"\\\1", body) + "]")
                index = end + 1
                continue
        else:
            parts.append(re.escape(char))
        index += 1
    return "".join(parts)


def key_matches(key, pattern):
    try:
        return re.fullmatch(glob_regex(pattern), key, re.S) is not None
    except re.error:
        return False


def allowed_key(policy, key):
    if len(key.encode("utf-8", "replace")) > 1024:
        raise GatewayError("KEY_INVALID", "键名超过 1024 字节")
    if not any(key_matches(key, pattern) for pattern in policy["key_allowlist"]):
        raise GatewayError("KEY_DENIED", "键不在账号白名单中", 403)
    return key


def display(raw):
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def cell(value, ctx):
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "base64": base64.b64encode(value[:256]).decode(),
                "bytes": len(value),
                "truncated": len(value) > 256,
            }
    if isinstance(value, str) and len(value) > ctx.limits["max_cell_chars"]:
        value = value[: ctx.limits["max_cell_chars"]] + "…（已截断）"
        ctx.stats["truncated"] = True
    return value


def tls_failure(error):
    """沿异常链判断是否为 TLS 协商失败（自动模式回退明文使用）。"""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, ssl.SSLError) or "SSL" in str(error):
            return True
        error = error.__cause__ or error.__context__
    return False


def connect_error(error):
    text_value = str(error)
    if isinstance(error, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text_value:
        return GatewayError(
            "REDIS_TLS_FAILED",
            "TLS 证书验证失败：目标证书未受系统信任（常见于自签证书）。可将该资产 tls_mode 改为 REQUIRED，或配置 ca_file",
            502,
        )
    if tls_failure(error):
        return GatewayError(
            "REDIS_TLS_FAILED",
            "TLS 协商失败：目标可能未启用 TLS；可将该资产 tls_mode 改为 PREFERRED（自动回退明文）或 DISABLED",
            502,
        )
    if isinstance(error, redis.AuthenticationError):
        return GatewayError("REDIS_AUTH_FAILED", "Redis 认证失败：请核对账号用户名与密码", 502)
    if isinstance(error, redis.TimeoutError):
        return GatewayError("REDIS_TIMEOUT", "连接 Redis 超时：请检查目标可用性与网络策略", 502)
    return GatewayError("REDIS_UNREACHABLE", "无法建立 Redis 连接：请检查地址、端口与网络策略", 502)


def command_error(error):
    if isinstance(error, redis.TimeoutError):
        return GatewayError("REDIS_TIMEOUT", "命令执行超时：请缩小扫描或读取范围", 502)
    if isinstance(error, redis.ResponseError):
        return GatewayError("REDIS_COMMAND_FAILED", f"Redis 命令失败：{str(error)[:300]}", 502)
    if isinstance(error, redis.ConnectionError):
        return GatewayError("REDIS_TIMEOUT", "Redis 连接中断：请检查网络与服务器状态", 502)
    return GatewayError("REDIS_COMMAND_FAILED", "Redis 命令执行失败：请检查远端状态", 502)


def pinned_socket(ip, port, connect_timeout, socket_timeout, keepalive, keepalive_options):
    """按 redis-py 语义创建套接字后直连已校验的 IP，绕过连接期 DNS 重解析。"""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if keepalive:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for key, value in keepalive_options.items():
                sock.setsockopt(socket.IPPROTO_TCP, key, value)
        sock.settimeout(connect_timeout)
        sock.connect((ip, port))
        sock.settimeout(socket_timeout)
        return sock
    except OSError:
        sock.close()
        raise


def pinned_class(base, ctx, ip, port):
    """为本次调用生成连接子类；套接字注册到 ctx，超时取消时可立即解阻塞。"""

    def connect_socket(self):
        return pinned_socket(
            ip,
            port,
            min(ctx.remaining(), ctx.limits["connect_timeout_seconds"]),
            self.socket_timeout,
            self.socket_keepalive,
            self.socket_keepalive_options,
        )

    if issubclass(base, redis.SSLConnection):

        class PinnedSSL(base):
            def _connect(self):
                sock = connect_socket(self)
                try:
                    wrapped = self._wrap_socket_with_ssl(sock)
                except (OSError, redis.RedisError):
                    sock.close()
                    raise
                ctx.add_closer(wrapped.close)
                return wrapped

        return PinnedSSL

    class Pinned(base):
        def _connect(self):
            sock = connect_socket(self)
            ctx.add_closer(sock.close)
            return sock

    return Pinned


def scan_keys(client, ctx, args):
    policy = ctx.account["policy"]
    limit = min(args.get("limit", 100), ctx.limits["max_result_rows"])
    budget = min(policy.get("max_scan_keys", 1000), 100000)
    type_filter = args.get("type_filter") or None
    found, scanned = {}, 0
    for pattern in policy["key_allowlist"]:
        cursor, rounds = 0, 0
        while len(found) < limit and scanned < budget and rounds < 100:
            ctx.remaining()
            cursor, batch = client.scan(cursor=cursor, match=pattern, count=100, _type=type_filter)
            rounds += 1
            for raw in batch:
                scanned += 1
                if len(found) >= limit or scanned > budget:
                    break
                key = display(raw)
                if key_matches(key, pattern):
                    found.setdefault(key, None)
            if cursor == 0:
                break
    keys = list(found)
    return {
        "keys": keys,
        "count": len(keys),
        "scanned": scanned,
        "truncated": len(keys) >= limit or scanned >= budget,
    }


def read_key(client, ctx, args):
    policy = ctx.account["policy"]
    key = allowed_key(policy, args["key"])
    kind = display(client.type(key))
    limit = min(args.get("limit", 100), ctx.limits["max_result_rows"])
    offset, cursor = args.get("offset", 0), args.get("cursor", 0)
    payload = {"key": key, "type": kind, "count": 1, "truncated": False}
    if kind == "none":
        return payload
    if kind == "string":
        length = client.strlen(key)
        cap = min(limit, ctx.limits["max_cell_chars"])
        payload.update(
            value=cell(client.getrange(key, offset, offset + cap - 1), ctx),
            length=length,
            offset=offset,
            truncated=length > offset + cap,
        )
        return payload
    if kind == "list":
        length = client.llen(key)
        rows = client.lrange(key, offset, offset + limit - 1)
        payload.update(
            items=[cell(item, ctx) for item in rows],
            length=length,
            offset=offset,
            truncated=offset + len(rows) < length,
        )
    elif kind == "hash":
        length = client.hlen(key)
        next_cursor, data = client.hscan(key, cursor=cursor, count=limit)
        items = [{"field": cell(field, ctx), "value": cell(value, ctx)} for field, value in data.items()]
        payload.update(items=items, length=length, cursor=next_cursor, truncated=bool(next_cursor))
    elif kind == "set":
        length = client.scard(key)
        next_cursor, data = client.sscan(key, cursor=cursor, count=limit)
        payload.update(
            items=[cell(member, ctx) for member in data],
            length=length,
            cursor=next_cursor,
            truncated=bool(next_cursor),
        )
    elif kind == "zset":
        length = client.zcard(key)
        next_cursor, data = client.zscan(key, cursor=cursor, count=limit)
        items = [{"member": cell(member, ctx), "score": score} for member, score in data.items()]
        payload.update(items=items, length=length, cursor=next_cursor, truncated=bool(next_cursor))
    elif kind == "stream":
        length = client.xlen(key)
        entries = client.xrange(key, count=limit)
        items = [
            {"id": cell(entry_id, ctx), "fields": {cell(name, ctx): cell(value, ctx) for name, value in fields.items()}}
            for entry_id, fields in entries
        ]
        payload.update(items=items, length=length, truncated=length > len(items))
    else:
        payload["note"] = "未支持的类型，仅返回类型信息"
    payload["count"] = len(payload.get("items", []))
    return payload


def key_info(client, ctx, args):
    policy = ctx.account["policy"]
    key = allowed_key(policy, args["key"])
    kind = display(client.type(key))
    payload = {"key": key, "type": kind, "count": 1}
    if kind == "none":
        return payload
    lengths = {
        "string": client.strlen,
        "list": client.llen,
        "set": client.scard,
        "zset": client.zcard,
        "hash": client.hlen,
        "stream": client.xlen,
    }
    payload.update(
        ttl_ms=client.pttl(key),
        encoding=display(client.object("encoding", key) or ""),
        memory_bytes=client.memory_usage(key),
    )
    if kind in lengths:
        payload["length"] = lengths[kind](key)
    return payload


def server_info(client, ctx, args):
    section = args.get("section", "server")
    raw = client.info(section)
    ctx.remaining()
    if section == "keyspace":
        fields = {key: value for key, value in raw.items() if key.startswith("db")}
    else:
        fields = {key: raw[key] for key in INFO_FIELDS.get(section, ()) if key in raw}
    return {"section": section, "info": fields, "dbsize": client.dbsize(), "count": 1}


def write_set(client, ctx, args):
    key = allowed_key(ctx.account["policy"], args["key"])
    value = args["value"].encode("utf-8")
    written = client.set(key, value, ex=args.get("ttl_seconds"))
    return {
        "key": key,
        "written": bool(written),
        "bytes": len(value),
        "ttl_seconds": args.get("ttl_seconds"),
        "count": 1,
    }


def write_delete(client, ctx, args):
    key = allowed_key(ctx.account["policy"], args["key"])
    return {"key": key, "removed": client.delete(key), "count": 1}


def write_expire(client, ctx, args):
    key = allowed_key(ctx.account["policy"], args["key"])
    ttl = args["ttl_seconds"]
    if ttl == 0:
        return {"key": key, "persisted": bool(client.persist(key)), "ttl_seconds": None, "count": 1}
    return {"key": key, "expire_set": bool(client.expire(key, ttl)), "ttl_seconds": ttl, "count": 1}


HANDLERS = {
    "redis_scan_keys": scan_keys,
    "redis_read_key": read_key,
    "redis_key_info": key_info,
    "redis_server_info": server_info,
    "redis_set": write_set,
    "redis_delete": write_delete,
    "redis_expire": write_expire,
}


class RedisAssetType(AssetType):
    type_id, display_name, icon = "redis", "Redis 缓存", "DataLine"
    default_port = 6379
    connection_schema = obj(
        {
            "host": text("主机", maxLength=253, minLength=1),
            "port": integer("端口", 1, 65535, default=6379),
            "tls_mode": text(
                "TLS 模式",
                enum=["PREFERRED", "VERIFY_IDENTITY", "REQUIRED", "DISABLED"],
                default="PREFERRED",
                description="自动：优先加密连接，目标不支持 TLS 时回退明文（不校验证书）",
            ),
            "ca_file": text("容器内 CA 文件路径"),
        },
        ["host"],
    )
    account_schema = obj(
        {
            "username": text("ACL 用户名", description="Redis 6+ ACL 用户名，留空使用默认用户"),
            "database": integer("默认库号", 0, 127, default=0),
        }
    )
    credential_schema = obj({"password": text("密码", format="password")})
    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "key_allowlist": {
                "type": "array",
                "title": "键白名单（Redis glob 模式）",
                "items": {"type": "string", "minLength": 1, "maxLength": 256},
                "minItems": 1,
                "maxItems": 20,
                "uniqueItems": True,
            },
            "max_scan_keys": integer("单次调用扫描键数上限", 1, 100000, default=1000),
            "write_tools": {
                "type": "array",
                "title": "开启的写工具",
                "items": {"type": "string", "enum": list(WRITE_TOOLS)},
                "maxItems": len(WRITE_TOOLS),
                "uniqueItems": True,
            },
        },
        ["key_allowlist"],
    )
    tools = [
        tool(
            "redis_scan_keys",
            "在白名单模式范围内扫描键（SCAN），返回数量受限的键名列表。",
            {
                "type_filter": text(
                    "类型过滤",
                    enum=SCAN_TYPES,
                    description="留空返回全部类型；类型过滤需要 Redis 6.0+",
                ),
                "limit": integer("返回键数上限", 1, 500, default=100),
            },
        ),
        tool(
            "redis_read_key",
            "读取白名单键的值，按类型分页返回并有界裁剪。",
            {
                "key": text("键名", minLength=1, maxLength=1024),
                "cursor": integer("集合游标", 0, 2147483647, default=0, description="hash/set/zset 的 HSCAN 游标"),
                "offset": integer("偏移", 0, 2147483647, default=0, description="string 截取起点或 list 起始下标"),
                "limit": integer("元素上限", 1, 500, default=100),
            },
            ["key"],
        ),
        tool(
            "redis_key_info",
            "查看白名单键的类型、TTL、编码、长度与内存占用（近似值）。",
            {"key": text("键名", minLength=1, maxLength=1024)},
            ["key"],
        ),
        tool(
            "redis_server_info",
            "查看服务器指定信息节与当前库键数量。",
            {"section": text("信息节", enum=list(INFO_FIELDS) + ["keyspace"], default="server")},
        ),
        tool(
            "redis_set",
            "写入白名单键的字符串值（需账号策略开启 redis_set）。",
            {
                "key": text("键名", minLength=1, maxLength=1024),
                "value": text("值", maxLength=262144),
                "ttl_seconds": integer("过期秒数", 1, 604800, description="留空表示不过期"),
            },
            ["key", "value"],
            readonly=False,
        ),
        tool(
            "redis_delete",
            "删除白名单键（需账号策略开启 redis_delete）。",
            {"key": text("键名", minLength=1, maxLength=1024)},
            ["key"],
            readonly=False,
        ),
        tool(
            "redis_expire",
            "设置白名单键的过期时间（需账号策略开启 redis_expire）。",
            {
                "key": text("键名", minLength=1, maxLength=1024),
                "ttl_seconds": integer("过期秒数", 0, 604800, description="0 表示移除过期时间"),
            },
            ["key", "ttl_seconds"],
            readonly=False,
        ),
    ]

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        for pattern in policy["key_allowlist"]:
            if any(char.isspace() or char == "\x00" for char in pattern):
                raise GatewayError("KEY_PATTERN_INVALID", "键白名单模式不能包含空白或控制字符")

    def catalog(self, account):
        allowed = set(account["policy"].get("write_tools", []))
        return [spec for spec in self.tools if spec["name"] not in WRITE_TOOLS or spec["name"] in allowed]

    def dial(self, ctx, tls, mode):
        cfg, account = ctx.asset["connection"], ctx.account["config"]
        host, port = cfg["host"], cfg.get("port", 6379)
        ip = ctx.network.resolve(host, port)
        kwargs = {
            "host": host,
            "port": port,
            "db": account.get("database", 0),
            "username": account.get("username") or None,
            "password": ctx.credential.get("password") or None,
            "socket_timeout": ctx.limits["query_timeout_seconds"],
            "socket_connect_timeout": min(ctx.remaining(), ctx.limits["connect_timeout_seconds"]),
            "retry_on_timeout": False,
            "decode_responses": False,
            "protocol": 2,
            "driver_info": None,
            "client_name": "mcp-asset-gateway",
            "health_check_interval": 0,
        }
        if tls:
            kwargs["ssl_cert_reqs"] = "required" if mode == "VERIFY_IDENTITY" else "none"
            if cfg.get("ca_file"):
                kwargs["ssl_ca_certs"] = cfg["ca_file"]
        base = redis.SSLConnection if tls else redis.Connection
        pool = redis.ConnectionPool(connection_class=pinned_class(base, ctx, ip, port), max_connections=1, **kwargs)
        ctx.add_closer(pool.disconnect)
        client = redis.Redis(connection_pool=pool)
        ctx.remaining()
        client.ping()
        return client

    def connect(self, ctx):
        mode = ctx.asset["connection"].get("tls_mode", "PREFERRED")
        attempts = [True, False] if mode == "PREFERRED" else [mode != "DISABLED"]
        error = None
        for tls in attempts:
            try:
                return self.dial(ctx, tls, mode)
            except GatewayError:
                raise
            except redis.AuthenticationError as failure:
                raise connect_error(failure) from None
            except (redis.RedisError, OSError) as failure:
                error = failure
                # 自动模式：TLS 握手失败（常见于仅明文的服务端）时回退明文重试一次。
                if tls and mode == "PREFERRED" and tls_failure(failure):
                    continue
                raise connect_error(failure) from None
        raise connect_error(error)

    def execute_sync(self, name, args, ctx):
        start = time.monotonic()
        if name in WRITE_TOOLS and name not in ctx.account["policy"].get("write_tools", []):
            raise GatewayError("TOOL_DENIED", "写工具未在账号策略中开启", 403)
        handler = HANDLERS.get(name)
        if handler is None:
            raise GatewayError("TOOL_DENIED", "工具不存在", 403)
        client = self.connect(ctx)
        try:
            payload = handler(client, ctx, args)
            payload["elapsed_ms"] = int((time.monotonic() - start) * 1000)
            ctx.stats.update(row_count=payload.get("count"), truncated=bool(payload.get("truncated")))
            return result(payload)
        except (redis.RedisError, OSError) as failure:
            raise command_error(failure) from None
        finally:
            ctx.close()

    def health_sync(self, ctx):
        client = self.connect(ctx)
        try:
            return {"reachable": True, "version": client.info("server").get("redis_version")}
        finally:
            ctx.close()
