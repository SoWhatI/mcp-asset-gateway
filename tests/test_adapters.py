import asyncio
import datetime
import decimal
import ipaddress
import json
import os
import socket
import ssl
import stat
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pymysql
import pytest
import redis as redis_lib
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.asset_types import kubernetes, mysql
from app.asset_types import redis as redis_type
from app.asset_types.base import BlockingRunner, Context
from app.asset_types.filebrowser import SFTPAssetType, safe_path
from app.asset_types.mcp import public_name, tool_hash
from app.asset_types.mysql import MySQLAssetType, cell, connect_error, query_error, validate_sql
from app.asset_types.pinned import PinnedTransport
from app.asset_types.ssh import command
from app.core.config import DEFAULTS
from app.core.security import GatewayError, NetworkPolicy, Vault, check_schema


def context(config, **limits):
    return Context(
        {"connection": {"url": "https://mcp.example.test/mcp"}},
        {"config": {}, "policy": {}},
        {},
        {**DEFAULTS, **limits},
        NetworkPolicy(config),
    )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "select 'drop table x' AS label",
        "WITH q AS (SELECT 1 a) SELECT * FROM q",
        "SELECT 1 UNION SELECT 2",
        "SELECT * FROM (SELECT 1 LIMIT 1) q",
        "EXPLAIN SELECT 1",
        "SHOW TABLES",
        "SHOW COLUMNS FROM t",
        "DESC t",
        "SELECT count(*) FROM t",
    ],
)
def test_readonly_sql(sql):
    normalized, write = validate_sql(sql, 5)
    assert normalized and not write
    if "SELECT" in sql.upper():
        assert "LIMIT 6" in normalized


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM t",
        "SELECT 1; DROP TABLE t",
        'SELECT 1 INTO OUTFILE "/tmp/leak"',
        "SELECT SLEEP(10)",
        "SELECT BENCHMARK(10,1)",
        'SELECT LOAD_FILE("/etc/passwd")',
        'SELECT GET_LOCK("x",10)',
        "SELECT @x:=1",
        "SELECT @@global.version",
        "SELECT 1 FOR UPDATE",
        "SELECT evil_udf()",
        "SELECT demo.evil_udf()",
        "SELECT /*!50000 SLEEP(10) */ 1",
        "SELECT /*+ MAX_EXECUTION_TIME(0) */ 1",
        "EXPLAIN ANALYZE SELECT 1",
        "SHOW PROCESSLIST",
        "SET @x=1",
        "WITH q AS (SELECT 1) DELETE FROM t",
        "SELECT * FROM",
        "SELECT (",
    ],
)
def test_sql_rejections(sql):
    with pytest.raises(GatewayError):
        validate_sql(sql, 10)


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO t(a) VALUES (1)",
        "INSERT INTO t SELECT id FROM s WHERE x=1",
        "UPDATE t SET a=1 WHERE id=2",
        "UPDATE t1 JOIN t2 ON t1.id=t2.id SET t1.a=1 WHERE t2.b=2",
        "DELETE FROM t WHERE id=1",
    ],
)
def test_write_sql_allowed_when_policy_enables(sql):
    normalized, write = validate_sql(sql, 5, allow_write=True)
    assert write and normalized


@pytest.mark.parametrize("sql", ["UPDATE t SET a=1", "DELETE FROM t", "WITH c AS (SELECT 1) DELETE FROM t"])
def test_write_sql_requires_where(sql):
    with pytest.raises(GatewayError) as exc:
        validate_sql(sql, 5, allow_write=True)
    assert exc.value.code == "SQL_UNSAFE"


@pytest.mark.parametrize("sql", ["INSERT INTO t VALUES (1)", "UPDATE t SET a=1 WHERE id=2", "DELETE FROM t WHERE id=1"])
def test_write_sql_denied_without_policy(sql):
    with pytest.raises(GatewayError) as exc:
        validate_sql(sql, 5)
    assert exc.value.code == "TOOL_DENIED"


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE t2(id INT)",
        "DROP TABLE t",
        "TRUNCATE TABLE t",
        "SET @x=1",
        "USE other_db",
        "CALL do_x(1)",
        "REPLACE INTO t(a) VALUES (1)",
        "INSERT INTO t VALUES (1); DROP TABLE t",
    ],
)
def test_write_sql_never_expands_to_ddl_or_session(sql):
    with pytest.raises(GatewayError):
        validate_sql(sql, 5, allow_write=True)


def test_use_sql_reports_cross_database_guidance():
    with pytest.raises(GatewayError) as exc:
        validate_sql("USE other_db", 5)
    assert exc.value.code == "SQL_UNSAFE"
    assert "库名.表名" in exc.value.message and "database 参数" in exc.value.message


def test_mysql_execute_query_write_and_database_override(monkeypatch):
    state = fake_mysql(monkeypatch, cursor_rowcount=3)
    adapter = MySQLAssetType()
    outcome = adapter.execute_sync(
        "execute_query",
        {"sql": "UPDATE demo.t SET a=1 WHERE id=2", "database": "other_db"},
        mysql_context(policy={"allow_write": True}),
    )
    payload = json.loads(outcome["content"][0]["text"])
    assert payload["affected_rows"] == 3 and payload["row_count"] == 0 and payload["columns"] == []
    assert state["created"][0].kwargs["database"] == "other_db"
    assert state["statements"][-1].startswith("UPDATE")

    outcome = adapter.execute_sync(
        "execute_query", {"sql": "INSERT INTO t(a) VALUES (1)"}, mysql_context(policy={"allow_write": True})
    )
    payload = json.loads(outcome["content"][0]["text"])
    assert payload["affected_rows"] == 3
    assert state["created"][1].kwargs["database"] == "demo"


def test_mysql_execute_query_write_denied_before_connect(monkeypatch):
    state = fake_mysql(monkeypatch)
    with pytest.raises(GatewayError) as exc:
        MySQLAssetType().execute_sync("execute_query", {"sql": "UPDATE t SET a=1 WHERE id=2"}, mysql_context())
    assert exc.value.code == "TOOL_DENIED"
    assert not state["created"]


def test_outer_limit_and_cells(config):
    assert validate_sql("SELECT * FROM (SELECT 1 LIMIT 1) q LIMIT 999999", 7)[0].endswith("LIMIT 8")
    ctx = context(config, max_cell_chars=10)
    assert cell(None, ctx) is None
    assert cell(12, ctx) == 12
    assert cell(decimal.Decimal("1.20"), ctx) == "1.20"
    assert cell(b"abc", ctx)["base64"] == "YWJj"
    assert cell("long-value-over-limit", ctx).endswith("（已截断）")
    ctx.legacy = True
    assert cell(None, ctx) == "NULL"
    assert cell(12, ctx) == "12"
    assert cell("x\ty\n", ctx) == "x\\ty\\n"


@pytest.mark.parametrize(
    "value",
    [
        "uname -a",
        "/bin/sh -c id",
        "/usr/bin/uname; id",
        "/usr/bin/uname $(id)",
        "/usr/bin/uname | cat",
        "/usr/bin/uname\nid",
        "/usr/bin/python x",
    ],
)
def test_ssh_commands_are_controlled_by_grant_rules(value):
    assert command(value) == value


@pytest.mark.parametrize("value", [None, 1, "", "  ", "a\0b", "x" * 4097])
def test_ssh_invalid_command(value):
    with pytest.raises(GatewayError):
        command(value)


def test_ssh_command_preserves_exact_text():
    assert command(" /usr/bin/uname    -a ") == " /usr/bin/uname    -a "


class Files:
    def lstat(self, path):
        return SimpleNamespace(st_mode=stat.S_IFLNK if path.endswith("link") else stat.S_IFDIR)

    def normalize(self, path):
        return path


@pytest.mark.parametrize("path", ["../etc", "/etc/passwd", "a/../../x", "a\\b", "a\0b", "link/file"])
def test_sftp_path_escape(path):
    with pytest.raises(GatewayError):
        safe_path(Files(), "/srv/data", path)


def test_sftp_normal_path():
    assert safe_path(Files(), "/srv/data", "reports/today.txt") == "/srv/data/reports/today.txt"


def test_sftp_denied_message_explains_root_usage():
    with pytest.raises(GatewayError) as exc:
        safe_path(Files(), "/srv/data", "/")
    assert exc.value.code == "PATH_DENIED" and "“.”表示根目录" in exc.value.message


def test_sftp_tool_descriptions_explain_relative_paths():
    specs = {spec["name"]: spec for spec in SFTPAssetType().tools}
    for name in ("list_dir", "search_files", "read_file"):
        spec = specs[name]
        path = spec["inputSchema"]["properties"]["path"]
        assert "相对路径" in spec["description"] and "相对" in path["description"]
    # 目录型路径额外说明根目录写法
    for name in ("list_dir", "search_files"):
        path = specs[name]["inputSchema"]["properties"]["path"]
        assert "“.”" in path["description"]


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0", "224.0.0.1"]
)
def test_dns_ssrf(config, monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (ip, 3306))])
    with pytest.raises(GatewayError):
        NetworkPolicy(config).resolve("db.example.test", 3306)


def test_outbound_enforce_toggle(config):
    lax = NetworkPolicy(replace(config, outbound=()))
    assert lax.resolve("192.0.2.1", 3306) == "192.0.2.1"
    assert lax.url("http://192.0.2.5:8080") == ("192.0.2.5", 8080)
    with pytest.raises(GatewayError):
        lax.resolve("127.0.0.1", 3306)
    strict = NetworkPolicy(config)
    with pytest.raises(GatewayError):
        strict.resolve("192.0.2.1", 3306)
    with pytest.raises(GatewayError):
        strict.url("http://192.0.2.5:8080")


def test_vault_and_schema(config):
    vault = Vault(config.master_key, config.key_id)
    encrypted = vault.encrypt({"secret": "test-only"})
    assert vault.decrypt(encrypted, config.key_id) == {"secret": "test-only"}
    with pytest.raises(GatewayError):
        vault.decrypt(encrypted, "wrong-id")
    with pytest.raises(GatewayError):
        Vault(Fernet.generate_key().decode(), config.key_id).decrypt(encrypted, config.key_id)
    for schema in ({"$ref": "https://example.test/schema"}, {"$id": "https://example.test", "type": "object"}):
        with pytest.raises(GatewayError):
            check_schema(schema)


def test_namespace_and_definition_hash():
    assert public_name("account", "search") == "account__search"
    assert len(public_name("a" * 24, "中文" * 100)) <= 64
    assert public_name("a", "x/y") != public_name("a", "x?y")
    spec = {"name": "x", "description": "first", "inputSchema": {"type": "object"}}
    assert tool_hash(spec) != tool_hash({**spec, "description": "second"})


async def test_transport_pins_ip_and_rejects_redirect(config, monkeypatch):
    ctx = context(config)
    monkeypatch.setattr(ctx.network, "resolve", lambda *args: "192.0.2.1")
    transport = PinnedTransport(ctx, 1024)
    observed = []

    async def handle(request):
        assert request.url.host == "192.0.2.1"
        observed.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1"})

    transport.inner = httpx.MockTransport(handle)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(GatewayError, match="重定向"):
            await client.get("https://mcp.example.test/mcp")
    assert observed[0].url.host == "mcp.example.test"
    assert observed[0].headers["host"] == "mcp.example.test"
    assert observed[0].extensions["sni_hostname"] == "mcp.example.test"


async def test_transport_request_query_excluded_from_outbound_check(config, monkeypatch):
    """业务 query（limit 等）不参与出站校验：network.url 只收到去 query 的目标 URL，带 query 请求正常发出。"""
    ctx = context(config)
    seen = []
    real_url = ctx.network.url

    def url_watcher(value):
        seen.append(value)
        return real_url(value)

    monkeypatch.setattr(ctx.network, "url", url_watcher)
    monkeypatch.setattr(ctx.network, "resolve", lambda *args: "192.0.2.1")
    transport = PinnedTransport(ctx, 1024)

    async def handle(request):
        # MockTransport 的内存 Response（text=/json=）构造时即被标记为已消费，必须以流式返回，
        # 才能穿过 LimitedStream 包装（与生产真实网络传输的流式响应一致）。
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    transport.inner = httpx.MockTransport(handle)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://mcp.example.test/api/v1/pods", params={"limit": 100})
    assert response.status_code == 200
    assert seen == ["https://mcp.example.test/api/v1/pods"]


async def test_timeout_worker_retains_capacity(config):
    ctx = context(config, query_timeout_seconds=0.03)
    runner, release = BlockingRunner(), threading.Event()

    def work():
        release.wait(3)
        return None

    try:
        with pytest.raises(TimeoutError):
            await runner.run(ctx, work)
        assert runner.slots._value == 15
        assert not ctx.worker_future.done()
        release.set()
        await asyncio.wait_for(asyncio.shield(ctx.worker_future), 2)
        await asyncio.sleep(0)
        assert runner.slots._value == 16
    finally:
        release.set()
        runner.close()


def test_small_query_output_budget(config):
    class Cursor:
        description = [("n",)]

        def execute(self, *args):
            pass

        def __iter__(self):
            return iter([(1,), (2,)])

        def close(self):
            pass

    conn = SimpleNamespace(cursor=lambda: Cursor())
    columns, rows, cut = MySQLAssetType().query(conn, "SELECT n", None, context(config, max_output_bytes=1024), 10)
    assert rows == [[1], [2]]
    assert not cut


def test_mysql_connect_error_mapping():
    tls = connect_error(
        pymysql.err.OperationalError(
            2003,
            "Can't connect to MySQL server on 'h' ([SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain)",
        )
    )
    assert tls.code == "MYSQL_TLS_FAILED"
    assert "tls_mode" in tls.message
    legacy = connect_error(
        pymysql.err.OperationalError(
            2003,
            "Can't connect to MySQL server on 'h' ([SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1016))",
        )
    )
    assert legacy.code == "MYSQL_TLS_FAILED"
    assert "WRONG_VERSION_NUMBER" in legacy.message and "tls_mode" in legacy.message
    assert connect_error(ssl.SSLError(1, "[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED]")).code == "MYSQL_TLS_FAILED"
    assert connect_error(pymysql.err.OperationalError(1045, "Access denied")).code == "MYSQL_AUTH_FAILED"
    assert connect_error(pymysql.err.OperationalError(1049, "Unknown database 'x'")).code == "MYSQL_DATABASE_MISSING"
    assert connect_error(pymysql.err.OperationalError(2003, "Can't connect")).code == "MYSQL_UNREACHABLE"
    assert connect_error(pymysql.err.OperationalError(2013, "Lost connection")).code == "MYSQL_TIMEOUT"
    assert connect_error(TimeoutError()).code == "MYSQL_TIMEOUT"
    assert connect_error(ConnectionRefusedError()).code == "MYSQL_UNREACHABLE"


def test_mysql_query_error_mapping():
    syntax = query_error(pymysql.err.ProgrammingError(1064, "You have an error in your SQL syntax"))
    assert syntax.code == "MYSQL_QUERY_FAILED"
    assert "1064" in syntax.message
    missing = query_error(pymysql.err.ProgrammingError(1146, "Table 'db.t' doesn't exist"))
    assert missing.code == "MYSQL_QUERY_FAILED"
    assert "1146" in missing.message
    assert query_error(pymysql.err.OperationalError(2013, "Lost connection")).code == "MYSQL_TIMEOUT"
    assert query_error(pymysql.err.OperationalError(3024, "interrupted")).code == "MYSQL_TIMEOUT"
    assert query_error(TimeoutError()).code == "MYSQL_TIMEOUT"
    unknown = query_error(ValueError("boom"))
    assert unknown.code == "MYSQL_QUERY_FAILED"
    assert "远端对象权限" in unknown.message


TLS_HANDSHAKE_ERROR = pymysql.err.OperationalError(
    2003, "Can't connect to MySQL server on 'db' ([SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1016))"
)


def test_mysql_tls_failure_detection():
    assert mysql.tls_failure(TLS_HANDSHAKE_ERROR)
    assert mysql.tls_failure(ssl.SSLError(1, "[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED]"))
    assert not mysql.tls_failure(pymysql.err.OperationalError(1045, "Access denied"))
    assert not mysql.tls_failure(TimeoutError())


@pytest.mark.parametrize(
    ("version", "timeout"),
    [
        ("5.6.51-log", None),
        ("5.7.26-log", "SET SESSION MAX_EXECUTION_TIME=3500"),
        ("8.0.36", "SET SESSION MAX_EXECUTION_TIME=3500"),
        ("5.5.5-10.6.7-MariaDB", "SET SESSION max_statement_time=3.500"),
        ("10.11.6-MariaDB", "SET SESSION max_statement_time=3.500"),
        ("5.5.5-10.0.38-MariaDB", None),
        ("unknown", None),
        (None, None),
    ],
)
def test_mysql_statement_timeout_by_version(version, timeout):
    assert mysql.statement_timeout(version, 3.5) == timeout


def mysql_context(tls_mode="PREFERRED", policy=None, **limits):
    return Context(
        {"connection": {"host": "db.example.test", "port": 3306, "tls_mode": tls_mode}},
        {"config": {"username": "reader", "database": "demo"}, "policy": policy or {}},
        {"password": "remote-test-password"},
        {**DEFAULTS, **limits},
        SimpleNamespace(resolve=lambda host, port: "192.0.2.10"),
    )


def fake_mysql(monkeypatch, tls_error=None, plain_error=None, cursor_rowcount=-1):
    """替换 BoundedConnection 与底层 socket：可分别注入 TLS/明文连接失败。"""
    state = {"created": [], "statements": []}

    class FakeCursor:
        description = None
        rowcount = cursor_rowcount

        def execute(self, statement, parameters=None):
            state["statements"].append(statement)

        def close(self):
            pass

        def __iter__(self):
            return iter(())

    class FakeConnection:
        server_version = "5.7.26-log"

        def __init__(self, **kwargs):
            self.tls = kwargs.get("ssl") is not None
            self.kwargs = kwargs
            state["created"].append(self)

        def connect(self, sock=None):
            error = tls_error if self.tls else plain_error
            if error:
                raise error

        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr(mysql, "BoundedConnection", FakeConnection)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: SimpleNamespace(close=lambda: None))
    return state


def test_mysql_preferred_tls_falls_back_to_plaintext(monkeypatch):
    state = fake_mysql(monkeypatch, tls_error=TLS_HANDSHAKE_ERROR)
    conn = MySQLAssetType().connect(mysql_context("PREFERRED"))
    assert [item.tls for item in state["created"]] == [True, False]
    assert conn is state["created"][1]
    assert any(statement.startswith("SET SESSION sql_mode=") for statement in state["statements"])
    assert any(statement.startswith("SET SESSION MAX_EXECUTION_TIME=") for statement in state["statements"])


def test_mysql_preferred_fallback_reports_plaintext_error(monkeypatch):
    state = fake_mysql(
        monkeypatch, tls_error=TLS_HANDSHAKE_ERROR, plain_error=pymysql.err.OperationalError(1045, "Access denied")
    )
    with pytest.raises(GatewayError) as exc:
        MySQLAssetType().connect(mysql_context("PREFERRED"))
    assert exc.value.code == "MYSQL_AUTH_FAILED"
    assert len(state["created"]) == 2


def test_mysql_required_tls_does_not_fall_back(monkeypatch):
    state = fake_mysql(monkeypatch, tls_error=TLS_HANDSHAKE_ERROR)
    with pytest.raises(GatewayError) as exc:
        MySQLAssetType().connect(mysql_context("REQUIRED"))
    assert exc.value.code == "MYSQL_TLS_FAILED"
    assert [item.tls for item in state["created"]] == [True]


def test_mysql_disabled_tls_connects_plain(monkeypatch):
    state = fake_mysql(monkeypatch, tls_error=TLS_HANDSHAKE_ERROR)
    conn = MySQLAssetType().connect(mysql_context("DISABLED"))
    assert conn is state["created"][0] and not conn.tls


def redis_context(config, tls_mode="PREFERRED", allowlist=("app:*",), scan_budget=1000, write_tools=(), **limits):
    return Context(
        {"connection": {"host": "cache.example.test", "port": 6379, "tls_mode": tls_mode}},
        {
            "config": {"username": "", "database": 0},
            "policy": {
                "key_allowlist": list(allowlist),
                "max_scan_keys": scan_budget,
                "write_tools": list(write_tools),
            },
        },
        {"password": "remote-test-password"},
        {**DEFAULTS, **limits},
        SimpleNamespace(resolve=lambda host, port: "192.0.2.11"),
    )


CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIB-test-ca\n-----END CERTIFICATE-----\n"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB-test-cert\n-----END CERTIFICATE-----\n"
# 运行时组装非真实私钥测试样例，避免与发布秘密扫描的 PEM 规则冲突。
KEY_PEM = "-----BEGIN {kind}-----\nMIIE-test-key\n-----END {kind}-----\n".format(kind="PRIVATE KEY")


def k8s_context(config, kinds=("pods",), auth_mode="token", **limits):
    credential = (
        {"token": "test-only-token"}
        if auth_mode == "token"
        else {"client_certificate_file": "/etc/k8s/tls.crt", "client_key_file": "/etc/k8s/tls.key"}
    )
    return Context(
        {"connection": {"url": "https://k8s.example.test:6443"}},
        {
            "config": {"auth_mode": auth_mode, "namespace": "prod"},
            "policy": {"kinds": list(kinds), "max_log_lines": 500},
        },
        credential,
        {**DEFAULTS, **limits},
        SimpleNamespace(resolve=lambda host, port: "192.0.2.12"),
    )


@pytest.mark.parametrize(
    ("pattern", "key", "matched"),
    [
        ("app:*", "app:1", True),
        ("app:*", "app:", True),
        ("app:?", "app:1", True),
        ("app:?", "app:12", False),
        ("app:*", "other:1", False),
        ("ap[pq]:1", "app:1", True),
        ("ap[pq]:1", "apx:1", False),
        ("ap[^p]:1", "app:1", False),
        ("ap[^p]:1", "apx:1", True),
        ("app:\\*", "app:*", True),
        ("app:\\*", "app:1", False),
        ("a[", "a[", True),
        ("*", "any:key:here", True),
    ],
)
def test_redis_glob_semantics(pattern, key, matched):
    assert redis_type.key_matches(key, pattern) is matched


def test_redis_allowed_key_enforces_allowlist_and_size():
    policy = {"key_allowlist": ["app:*"]}
    assert redis_type.allowed_key(policy, "app:1") == "app:1"
    with pytest.raises(GatewayError) as exc:
        redis_type.allowed_key(policy, "other:1")
    assert (exc.value.code, exc.value.status) == ("KEY_DENIED", 403)
    with pytest.raises(GatewayError) as exc:
        redis_type.allowed_key(policy, "app:" + "长" * 400)
    assert exc.value.code == "KEY_INVALID"


def test_redis_catalog_respects_write_tools():
    kind = redis_type.RedisAssetType()
    readonly = {spec["name"] for spec in kind.catalog({"policy": {"write_tools": []}})}
    assert readonly == {"redis_scan_keys", "redis_read_key", "redis_key_info", "redis_server_info"}
    writable = {spec["name"] for spec in kind.catalog({"policy": {"write_tools": ["redis_set"]}})}
    assert writable == readonly | {"redis_set"}
    full = {spec["name"] for spec in kind.catalog({"policy": {"write_tools": list(redis_type.WRITE_TOOLS)}})}
    assert full == set(redis_type.HANDLERS)


def test_redis_scan_keys_filters_locally_and_counts_budget(config):
    class FakeClient:
        def __init__(self, batches):
            self.batches = list(batches)

        def scan(self, cursor=0, match=None, count=100, _type=None):
            return self.batches.pop(0) if self.batches else (0, [])

    ctx = redis_context(config)
    client = FakeClient([(5, [b"app:1", b"other:2"]), (0, [b"app:9"])])
    payload = redis_type.scan_keys(client, ctx, {"limit": 10})
    assert payload["keys"] == ["app:1", "app:9"]
    assert (payload["count"], payload["scanned"], payload["truncated"]) == (2, 3, False)
    # SCAN 的 MATCH 只是提示，服务端返回的键仍需按白名单本地复核；扫描预算耗尽即截断。
    budget = redis_context(config, scan_budget=2)
    client = FakeClient([(5, [b"app:1", b"other:2", b"app:3", b"app:4"])])
    payload = redis_type.scan_keys(client, budget, {"limit": 10})
    assert payload["keys"] == ["app:1"]
    assert (payload["scanned"], payload["truncated"]) == (3, True)


def test_redis_connect_error_mapping():
    tls = redis_type.connect_error(redis_lib.ConnectionError("[SSL: WRONG_VERSION_NUMBER] wrong version number"))
    assert tls.code == "REDIS_TLS_FAILED"
    verify = redis_type.connect_error(
        ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    )
    assert verify.code == "REDIS_TLS_FAILED" and "ca_file" in verify.message
    assert redis_type.connect_error(redis_lib.AuthenticationError("AUTH failed")).code == "REDIS_AUTH_FAILED"
    assert redis_type.connect_error(redis_lib.TimeoutError("timeout")).code == "REDIS_TIMEOUT"
    assert redis_type.connect_error(ConnectionRefusedError()).code == "REDIS_UNREACHABLE"
    assert redis_type.command_error(redis_lib.TimeoutError("timeout")).code == "REDIS_TIMEOUT"
    response = redis_type.command_error(redis_lib.ResponseError("WRONGTYPE Operation against a key"))
    assert response.code == "REDIS_COMMAND_FAILED" and "WRONGTYPE" in response.message
    assert redis_type.command_error(redis_lib.ConnectionError("broken")).code == "REDIS_TIMEOUT"


def test_redis_tls_failure_detection():
    assert redis_type.tls_failure(ssl.SSLError(1, "[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED]"))
    chained = redis_lib.ConnectionError("connection error")
    chained.__cause__ = ssl.SSLError(1, "handshake failure")
    assert redis_type.tls_failure(chained)
    assert not redis_type.tls_failure(redis_lib.AuthenticationError("AUTH failed"))


def test_redis_tls_mode_attempts(config, monkeypatch):
    kind = redis_type.RedisAssetType()

    def fallback_dial(self, ctx, tls, mode):
        if tls:
            raise redis_lib.ConnectionError("[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1016)")
        return "plain-client"

    monkeypatch.setattr(redis_type.RedisAssetType, "dial", fallback_dial)
    assert kind.connect(redis_context(config)) == "plain-client"

    attempts = []

    def strict_dial(self, ctx, tls, mode):
        attempts.append(tls)
        raise redis_lib.ConnectionError("[SSL: WRONG_VERSION_NUMBER] wrong version number")

    monkeypatch.setattr(redis_type.RedisAssetType, "dial", strict_dial)
    with pytest.raises(GatewayError) as exc:
        kind.connect(redis_context(config, tls_mode="REQUIRED"))
    assert exc.value.code == "REDIS_TLS_FAILED"
    assert attempts == [True]

    monkeypatch.setattr(redis_type.RedisAssetType, "dial", lambda self, ctx, tls, mode: f"tls={tls}")
    assert kind.connect(redis_context(config, tls_mode="DISABLED")) == "tls=False"


def test_redis_pinned_socket_uses_resolved_ip(monkeypatch):
    calls = []

    class FakeSocket:
        def __init__(self, family, kind):
            calls.append(("init", family, kind))

        def setsockopt(self, *args):
            calls.append(("setsockopt", args))

        def settimeout(self, value):
            calls.append(("settimeout", value))

        def connect(self, address):
            calls.append(("connect", address))

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(socket, "socket", FakeSocket)
    sock = redis_type.pinned_socket("192.0.2.11", 6379, 2.0, 5.0, True, {socket.IPPROTO_TCP: 1})
    assert isinstance(sock, FakeSocket)
    assert ("init", socket.AF_INET, socket.SOCK_STREAM) in calls
    assert ("connect", ("192.0.2.11", 6379)) in calls
    assert ("settimeout", 2.0) in calls and ("settimeout", 5.0) in calls
    assert ("setsockopt", (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)) in calls
    calls.clear()
    redis_type.pinned_socket("2001:db8::1", 6379, 2.0, 5.0, False, {})
    assert ("init", socket.AF_INET6, socket.SOCK_STREAM) in calls

    class RefusedSocket(FakeSocket):
        def connect(self, address):
            raise OSError("connection refused")

    monkeypatch.setattr(socket, "socket", RefusedSocket)
    calls.clear()
    with pytest.raises(OSError):
        redis_type.pinned_socket("192.0.2.11", 6379, 2.0, 5.0, False, {})
    assert calls[-1] == ("close",)


def test_redis_write_tools_gated_by_policy(config):
    ctx = redis_context(config)
    with pytest.raises(GatewayError) as exc:
        redis_type.RedisAssetType().execute_sync("redis_set", {"key": "app:1", "value": "x"}, ctx)
    assert (exc.value.code, exc.value.status) == ("TOOL_DENIED", 403)
    with pytest.raises(GatewayError) as exc:
        redis_type.RedisAssetType().execute_sync("redis_missing", {}, ctx)
    assert exc.value.code == "TOOL_DENIED"


def test_redis_key_pattern_validation():
    kind = redis_type.RedisAssetType()
    connection = {"host": "cache.example.test", "port": 6379}
    account = {"username": "", "database": 0}
    kind.validate_config(connection, account, {"key_allowlist": ["app:*"], "max_scan_keys": 100}, {"password": "test"})
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(
            connection, account, {"key_allowlist": ["app: 1"], "max_scan_keys": 100}, {"password": "test"}
        )
    assert exc.value.code == "KEY_PATTERN_INVALID"


def test_asset_type_metadata():
    redis_kind, k8s_kind = redis_type.RedisAssetType(), kubernetes.KubernetesAssetType()
    assert (redis_kind.type_id, redis_kind.default_port) == ("redis", 6379)
    assert redis_kind.description()["default_port"] == 6379
    assert (k8s_kind.type_id, k8s_kind.async_mode, k8s_kind.proxied) == ("kubernetes", True, False)
    assert k8s_kind.description()["default_port"] is None
    assert redis_type.WRITE_TOOLS == ("redis_set", "redis_delete", "redis_expire")


def test_k8s_api_paths():
    assert kubernetes.api_prefix("v1") == "/api/v1"
    assert kubernetes.api_prefix("apps/v1") == "/apis/apps/v1"
    assert kubernetes.collection_path("prod", "pods") == "/api/v1/namespaces/prod/pods"
    assert kubernetes.collection_path("prod", "deployments") == "/apis/apps/v1/namespaces/prod/deployments"
    assert kubernetes.collection_path("", "pods") == "/api/v1/pods"
    assert kubernetes.collection_path("", "deployments") == "/apis/apps/v1/deployments"
    assert "secrets" not in kubernetes.KINDS


def test_k8s_response_error_mapping():
    assert kubernetes.response_error(httpx.Response(401, json={"message": "Unauthorized"})).code == "K8S_AUTH_FAILED"
    forbidden = kubernetes.response_error(httpx.Response(403, json={"message": "pods is forbidden"}))
    assert forbidden.code == "K8S_FORBIDDEN" and "forbidden" in forbidden.message
    missing = kubernetes.response_error(httpx.Response(404, json={}))
    assert (missing.code, missing.status) == ("K8S_NOT_FOUND", 404)
    assert kubernetes.response_error(httpx.Response(429, json={})).code == "K8S_RATE_LIMITED"
    assert kubernetes.response_error(httpx.Response(500, text="boom")).code == "K8S_API_FAILED"


def test_k8s_transport_error_mapping():
    assert (
        kubernetes.transport_error(ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED]")).code
        == "K8S_TLS_FAILED"
    )
    assert kubernetes.transport_error(httpx.ConnectTimeout("slow")).code == "K8S_TIMEOUT"
    assert kubernetes.transport_error(FileNotFoundError("/etc/k8s/tls.crt")).code == "K8S_CERTIFICATE_MISSING"
    assert kubernetes.transport_error(httpx.ConnectError("refused")).code == "K8S_UNREACHABLE"
    assert kubernetes.transport_error(RuntimeError("boom")).code == "K8S_API_FAILED"


def test_k8s_brief_prune_and_clip(config):
    item = {
        "metadata": {
            "name": "web-1",
            "creationTimestamp": "2026-09-01T00:00:00Z",
            "labels": {"app": "web"},
            "managedFields": [{"manager": "kubectl"}],
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{" * 5000, "keep": "ok"},
        },
        "spec": {"replicas": 3},
        "status": {"phase": "Running", "readyReplicas": 2},
    }
    assert kubernetes.brief(item) == {
        "name": "web-1",
        "created": "2026-09-01T00:00:00Z",
        "labels": {"app": "web"},
        "phase": "Running",
        "ready": 2,
        "replicas": 3,
    }
    pruned = kubernetes.prune(item)
    assert "managedFields" not in pruned["metadata"]
    assert pruned["metadata"]["annotations"]["kubectl.kubernetes.io/last-applied-configuration"] == "…（已裁剪）"
    assert pruned["metadata"]["annotations"]["keep"] == "ok"
    assert item["metadata"]["managedFields"]
    ctx = k8s_context(config, max_cell_chars=50)
    clipped = kubernetes.clip({"a": ["x" * 500, {"b": "y" * 500}]}, ctx)
    assert clipped["a"][0] == "x" * 50 + "…（已截断）"
    assert clipped["a"][1]["b"] == "y" * 50 + "…（已截断）"
    assert ctx.stats["truncated"] is True


def test_k8s_catalog_narrows_kind_enum():
    kind = kubernetes.KubernetesAssetType()
    locked = kind.catalog({"config": {"namespace": "prod"}, "policy": {"kinds": ["pods"]}})
    with_kind = [spec for spec in locked if "kind" in spec["inputSchema"]["properties"]]
    assert with_kind and all(spec["inputSchema"]["properties"]["kind"]["enum"] == ["pods"] for spec in with_kind)
    # 锁定命名空间的账号不暴露 namespace 参数，避免调用方越界指定。
    assert all("namespace" not in spec["inputSchema"]["properties"] for spec in locked)
    assert all(
        spec["inputSchema"]["properties"]["kind"]["enum"] == sorted(kubernetes.KINDS)
        for spec in kind.tools
        if "kind" in spec["inputSchema"]["properties"]
    )


def test_k8s_catalog_unlocked_adds_namespace_parameter():
    kind = kubernetes.KubernetesAssetType()
    unlocked = kind.catalog({"config": {}, "policy": {"kinds": ["pods"]}})
    schemas = {spec["name"]: spec["inputSchema"] for spec in unlocked}
    assert set(schemas) == {"k8s_list_resources", "k8s_get_resource", "k8s_pod_logs", "k8s_exec"}
    assert all("namespace" in schema["properties"] for schema in schemas.values())
    # 列表留空=全部命名空间；读资源与日志必须指定。
    assert "namespace" not in schemas["k8s_list_resources"]["required"]
    assert "namespace" in schemas["k8s_get_resource"]["required"]
    assert "namespace" in schemas["k8s_pod_logs"]["required"]
    assert schemas["k8s_list_resources"]["properties"]["namespace"]["pattern"] == kubernetes.DNS_LABEL


def test_k8s_validate_config_token_and_certificate():
    kind = kubernetes.KubernetesAssetType()
    connection = {"url": "https://k8s.example.test:6443"}
    policy = {"kinds": ["pods"]}
    token = {"auth_mode": "token", "namespace": "prod"}
    kind.validate_config(connection, token, policy, {"token": "test-only-token"})
    # 命名空间选填：缺省或空串表示不锁定。
    kind.validate_config(connection, {"auth_mode": "token"}, policy, {"token": "test-only-token"})
    kind.validate_config(connection, {"auth_mode": "token", "namespace": ""}, policy, {"token": "test-only-token"})
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(connection, {"auth_mode": "token", "namespace": "Bad_Name"}, policy, {"token": "x"})
    assert exc.value.code == "VALIDATION"
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(connection, token, policy, {})
    assert exc.value.code == "CREDENTIAL_REQUIRED"
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(connection, token, policy, {"token": "bad\ntoken"})
    assert exc.value.code == "HEADER_INVALID"
    certificate = {"auth_mode": "client_certificate", "namespace": "prod"}
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(connection, certificate, policy, {"client_certificate_file": "/etc/k8s/tls.crt"})
    assert exc.value.code == "CREDENTIAL_REQUIRED"
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(
            connection,
            certificate,
            policy,
            {"client_certificate_file": "relative.crt", "client_key_file": "/etc/k8s/tls.key"},
        )
    assert exc.value.code == "CREDENTIAL_INVALID"
    kind.validate_config(
        connection,
        certificate,
        policy,
        {"client_certificate_file": "/etc/k8s/tls.crt", "client_key_file": "/etc/k8s/tls.key"},
    )
    # 上传/粘贴的 PEM 内容同样有效；把私钥当证书上传会被拒绝。
    kind.validate_config(
        connection, certificate, policy, {"client_certificate_file": CERT_PEM, "client_key_file": KEY_PEM}
    )
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(
            connection, certificate, policy, {"client_certificate_file": KEY_PEM, "client_key_file": KEY_PEM}
        )
    assert exc.value.code == "CREDENTIAL_INVALID"


def test_k8s_headers_and_certificate_selection(config):
    kind = kubernetes.KubernetesAssetType()
    token_ctx = k8s_context(config)
    assert kind.certificate(token_ctx) is None
    assert kind.headers(token_ctx) == {"Authorization": "Bearer test-only-token"}
    cert_ctx = k8s_context(config, auth_mode="client_certificate")
    assert kind.certificate(cert_ctx) == ("/etc/k8s/tls.crt", "/etc/k8s/tls.key")
    assert kind.headers(cert_ctx) == {}


def test_k8s_resource_kind_gate(config):
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, kinds=["pods"])
    assert kind.resource_kind(ctx, "pods") == "pods"
    for denied in ("deployments", "secrets"):
        with pytest.raises(GatewayError) as exc:
            kind.resource_kind(ctx, denied)
        assert (exc.value.code, exc.value.status) == ("KIND_DENIED", 403)


def test_k8s_policy_without_kinds_means_unrestricted(config):
    kind = kubernetes.KubernetesAssetType()
    # 策略省略或 kinds 留空都表示不限制，仅受固定资源类型表约束。
    for policy in ({}, {"kinds": []}):
        allowed = {spec["name"]: spec for spec in kind.catalog({"config": {}, "policy": policy})}
        assert all(
            spec["inputSchema"]["properties"]["kind"]["enum"] == sorted(kubernetes.KINDS)
            for spec in allowed.values()
            if "kind" in spec["inputSchema"]["properties"]
        )
    ctx = k8s_context(config, kinds=[])
    assert kind.resource_kind(ctx, "pods") == "pods"
    assert kind.resource_kind(ctx, "deployments") == "deployments"
    with pytest.raises(GatewayError) as exc:
        kind.resource_kind(ctx, "secrets")
    assert exc.value.code == "KIND_DENIED"


async def test_k8s_list_resources_and_pod_logs(config, monkeypatch):
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, kinds=["pods"])
    captured = {}

    async def fake_request(self, ctx, path, params=None, maximum=None):
        captured.update(path=path, params=params)
        if path.endswith("/log"):
            return httpx.Response(200, text="line-1\nline-2\n")
        return httpx.Response(
            200,
            json={
                "metadata": {"continue": "next-page"},
                "items": [
                    {"metadata": {"name": "web-1", "labels": {"app": "web"}}, "status": {"phase": "Running"}},
                    {"metadata": {"name": "web-2"}, "status": {}},
                ],
            },
        )

    monkeypatch.setattr(kubernetes.KubernetesAssetType, "request", fake_request)
    listed = await kind.execute(
        "k8s_list_resources", {"kind": "pods", "label_selector": "app=web", "limit": 1}, ctx, None
    )
    payload = json.loads(listed["content"][0]["text"])
    assert captured == {"path": "/api/v1/namespaces/prod/pods", "params": {"limit": 1, "labelSelector": "app=web"}}
    assert (payload["count"], payload["truncated"]) == (1, True)
    assert payload["items"] == [{"name": "web-1", "created": None, "labels": {"app": "web"}, "phase": "Running"}]
    logs = await kind.execute("k8s_pod_logs", {"pod": "web-1", "container": "app", "tail_lines": 9000}, ctx, None)
    log_payload = json.loads(logs["content"][0]["text"])
    assert captured == {
        "path": "/api/v1/namespaces/prod/pods/web-1/log",
        "params": {"tailLines": 500, "container": "app"},
    }
    assert (log_payload["count"], log_payload["logs"]) == (2, "line-1\nline-2\n")


async def test_k8s_list_and_logs_survive_pinned_transport_query_check(config, monkeypatch):
    """端到端回归：list/logs 自带的 limit/tailLines query 不再被 PinnedTransport 的 URL 校验拒绝。

    此前仅 mock 掉 request 层，未覆盖真实出站校验路径，导致生产上这两个工具恒报 INVALID_URL。"""
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, kinds=["pods"])
    ctx.network = NetworkPolicy(config)
    original_init = PinnedTransport.__init__

    def patched_init(self, inner_ctx, maximum, ssl_context=None):
        original_init(self, inner_ctx, maximum, ssl_context=ssl_context)

        async def handle(request):
            assert request.url.host == "192.0.2.12"
            assert request.headers["host"] == "k8s.example.test:6443"
            assert request.extensions["sni_hostname"] == "k8s.example.test"
            # 流式返回：内存 Response（text=/json=）构造时即被标记为已消费，无法穿过 LimitedStream。
            if request.url.path.endswith("/log"):
                return httpx.Response(200, stream=httpx.ByteStream(b"line-1\n"))
            items = [{"metadata": {"name": "web-1"}, "status": {"phase": "Running"}}]
            return httpx.Response(200, stream=httpx.ByteStream(json.dumps({"metadata": {}, "items": items}).encode()))

        self.inner = httpx.MockTransport(handle)

    monkeypatch.setattr(PinnedTransport, "__init__", patched_init)
    monkeypatch.setattr(ctx.network, "resolve", lambda *args: "192.0.2.12")
    listed = await kind.execute("k8s_list_resources", {"kind": "pods", "limit": 1}, ctx, None)
    payload = json.loads(listed["content"][0]["text"])
    assert payload["count"] == 1 and payload["items"][0]["name"] == "web-1"
    logged = await kind.execute("k8s_pod_logs", {"pod": "web-1"}, ctx, None)
    assert json.loads(logged["content"][0]["text"])["logs"] == "line-1\n"


async def test_k8s_get_resource_prunes_and_clips(config, monkeypatch):
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, kinds=["deployments"], max_cell_chars=50)
    document = {
        "metadata": {
            "name": "web",
            "managedFields": [{"manager": "kubectl"}],
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "z" * 5000},
        },
        "spec": {"template": {"spec": {"containers": [{"name": "app", "env": [{"value": "y" * 400}]}]}}},
    }

    async def fake_request(self, ctx, path, params=None, maximum=None):
        assert path == "/apis/apps/v1/namespaces/prod/deployments/web"
        return httpx.Response(200, json=document)

    monkeypatch.setattr(kubernetes.KubernetesAssetType, "request", fake_request)
    response = await kind.execute("k8s_get_resource", {"kind": "deployments", "name": "web"}, ctx, None)
    resource = json.loads(response["content"][0]["text"])["resource"]
    assert "managedFields" not in resource["metadata"]
    assert resource["metadata"]["annotations"]["kubectl.kubernetes.io/last-applied-configuration"] == "…（已裁剪）"
    value = resource["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"]
    assert value == "y" * 50 + "…（已截断）"
    assert ctx.stats["truncated"] is True


def test_k8s_connection_ca_accepts_path_or_pem():
    kind = kubernetes.KubernetesAssetType()
    network = SimpleNamespace(url=lambda value: value)
    base = {"url": "https://k8s.example.test:6443"}
    kind.validate_connection(network, base)
    kind.validate_connection(network, {**base, "ca_file": "/etc/k8s/ca.crt"})
    kind.validate_connection(network, {**base, "ca_file": CA_PEM})
    with pytest.raises(GatewayError) as exc:
        kind.validate_connection(network, {**base, "ca_file": "ca.crt"})
    assert exc.value.code == "CONNECTION_INVALID"
    # 私钥被当作 CA 上传时同样拒绝。
    with pytest.raises(GatewayError) as exc:
        kind.validate_connection(network, {**base, "ca_file": KEY_PEM})
    assert exc.value.code == "CONNECTION_INVALID"


def _test_pki(tmp_path):
    """生成回环 TLS 测试用 PKI（EC P-256）：CA、客户端证书与带 127.0.0.1 SAN 的服务器证书。"""

    def issue(cn, key, issuer_key=None, issuer_cert=None, san_ip=None, eku=None):
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject if issuer_cert else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        )
        if issuer_cert is None:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        if san_ip:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]), critical=False
            )
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        certificate = builder.sign(issuer_key or key, hashes.SHA256())
        return (
            certificate.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        )

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_pem, ca_key_pem = issue("test-ca", ca_key)
    ca_cert = x509.load_pem_x509_certificate(ca_pem)
    client_pem, client_key_pem = issue(
        "test-client",
        ec.generate_private_key(ec.SECP256R1()),
        ca_key,
        ca_cert,
        eku=x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    server_pem, server_key_pem = issue(
        "test-server",
        ec.generate_private_key(ec.SECP256R1()),
        ca_key,
        ca_cert,
        san_ip="127.0.0.1",
        eku=x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
    )
    material = {
        "ca": ca_pem,
        "client_cert": client_pem,
        "client_key": client_key_pem,
        "server_cert": server_pem,
        "server_key": server_key_pem,
    }
    for name, content in material.items():
        (tmp_path / f"{name}.pem").write_bytes(content)
    return {name: tmp_path / f"{name}.pem" for name in material}


def test_k8s_tls_files_materialize_uploaded_pem_and_clean(config, tmp_path):
    kind = kubernetes.KubernetesAssetType()
    pki = _test_pki(tmp_path)
    ctx = k8s_context(config, auth_mode="client_certificate")
    ctx.credential.update(
        {
            "client_certificate_file": pki["client_cert"].read_text(encoding="utf-8"),
            "client_key_file": pki["client_key"].read_text(encoding="utf-8"),
        }
    )
    before = set(Path(tempfile.gettempdir()).glob("mcp-k8s-tls-*"))
    with kubernetes.tls_files(pki["ca"].read_text(encoding="utf-8"), kind.certificate(ctx)) as tls_context:
        assert isinstance(tls_context, ssl.SSLContext)
        created = set(Path(tempfile.gettempdir()).glob("mcp-k8s-tls-*")) - before
        assert len(created) == 1
        work = created.pop()
        assert (work / "ca.pem").read_text(encoding="utf-8") == pki["ca"].read_text(encoding="utf-8")
        assert stat.S_IMODE(os.stat(work / "ca.pem").st_mode) == 0o600
        assert (work / "cert.pem").exists() and (work / "key.pem").exists()
    assert not work.exists()
    # 容器内路径取值原样透传，不落地临时文件。
    paths_ctx = k8s_context(config, auth_mode="client_certificate")
    paths_ctx.credential.update(
        {"client_certificate_file": str(pki["client_cert"]), "client_key_file": str(pki["client_key"])}
    )
    before = set(Path(tempfile.gettempdir()).glob("mcp-k8s-tls-*"))
    with kubernetes.tls_files(str(pki["ca"]), kind.certificate(paths_ctx)) as tls_context:
        assert isinstance(tls_context, ssl.SSLContext)
        assert set(Path(tempfile.gettempdir()).glob("mcp-k8s-tls-*")) == before
    token_ctx = k8s_context(config)
    with kubernetes.tls_files("", kind.certificate(token_ctx)) as tls_context:
        assert isinstance(tls_context, ssl.SSLContext)


def test_k8s_tls_files_rejects_invalid_pem_material(config):
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, auth_mode="client_certificate")
    ctx.credential.update({"client_certificate_file": CERT_PEM, "client_key_file": KEY_PEM})
    with pytest.raises(GatewayError) as exc:
        with kubernetes.tls_files(CA_PEM, kind.certificate(ctx)):
            pass
    assert exc.value.code == "K8S_TLS_FAILED"


def test_k8s_tls_files_context_presents_client_certificate(config, tmp_path):
    """回环 TLS：服务器要求客户端证书，验证 context 确实携带了客户端证书（401 回归测试）。"""
    pki = _test_pki(tmp_path)
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, auth_mode="client_certificate")
    ctx.credential.update(
        {
            "client_certificate_file": pki["client_cert"].read_text(encoding="utf-8"),
            "client_key_file": pki["client_key"].read_text(encoding="utf-8"),
        }
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(pki["server_cert"]), str(pki["server_key"]))
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(str(pki["ca"]))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    seen = {}

    def serve():
        try:
            connection, _ = listener.accept()
            with server_context.wrap_socket(connection, server_side=True) as tls:
                seen["common_name"] = dict(item[0] for item in tls.getpeercert()["subject"]).get("commonName")
                tls.sendall(b"ok")
        except Exception as exc:  # noqa: BLE001
            seen["error"] = repr(exc)
        finally:
            listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    with kubernetes.tls_files(pki["ca"].read_text(encoding="utf-8"), kind.certificate(ctx)) as tls_context:
        with socket.create_connection(listener.getsockname(), timeout=10) as raw:
            with tls_context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                assert tls.recv(2) == b"ok"
    worker.join(timeout=10)
    assert "error" not in seen
    assert seen.get("common_name") == "test-client"


async def test_k8s_unlocked_namespace_listing_and_required(config, monkeypatch):
    kind = kubernetes.KubernetesAssetType()
    ctx = k8s_context(config, kinds=["pods"])
    ctx.account["config"].pop("namespace")
    captured = []

    async def fake_request(self, ctx, path, params=None, maximum=None):
        captured.append(path)
        return httpx.Response(200, json={"items": []})

    monkeypatch.setattr(kubernetes.KubernetesAssetType, "request", fake_request)
    payload = json.loads((await kind.execute("k8s_list_resources", {"kind": "pods"}, ctx, None))["content"][0]["text"])
    assert captured[-1] == "/api/v1/pods" and payload["namespace"] == "*"
    payload = json.loads(
        (await kind.execute("k8s_list_resources", {"kind": "pods", "namespace": "dev"}, ctx, None))["content"][0][
            "text"
        ]
    )
    assert captured[-1] == "/api/v1/namespaces/dev/pods" and payload["namespace"] == "dev"
    with pytest.raises(GatewayError) as exc:
        await kind.execute("k8s_get_resource", {"kind": "pods", "name": "web-1"}, ctx, None)
    assert exc.value.code == "NAMESPACE_REQUIRED"
    payload = json.loads(
        (await kind.execute("k8s_pod_logs", {"pod": "web-1", "namespace": "dev"}, ctx, None))["content"][0]["text"]
    )
    assert captured[-1] == "/api/v1/namespaces/dev/pods/web-1/log"
