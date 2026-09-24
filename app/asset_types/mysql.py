import base64
import datetime
import decimal
import re
import socket
import ssl
import time

import pymysql
import sqlglot
from sqlglot import ErrorLevel, exp

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool
from app.core.db import dumps
from app.core.security import GatewayError

FORBIDDEN = {
    "Insert",
    "Update",
    "Delete",
    "Create",
    "Drop",
    "Alter",
    "Into",
    "Lock",
    "Transaction",
    "Commit",
    "Rollback",
    "Set",
    "Command",
    "Execute",
    "Merge",
    "Grant",
    "Revoke",
    "Copy",
    "PropertyEQ",
    "SessionParameter",
    "Parameter",
}
BAD_FUNCTIONS = {
    "SLEEP",
    "BENCHMARK",
    "GET_LOCK",
    "RELEASE_LOCK",
    "RELEASE_ALL_LOCKS",
    "LOAD_FILE",
    "MASTER_POS_WAIT",
    "SOURCE_POS_WAIT",
    "WAIT_FOR_EXECUTED_GTID_SET",
    "LAST_INSERT_ID",
}
SAFE_ANONYMOUS = {"DATE_FORMAT", "TIMESTAMPDIFF", "TIMESTAMPADD", "IFNULL", "GROUP_CONCAT", "JSON_EXTRACT"}
WRITE_ROOTS = (exp.Insert, exp.Update, exp.Delete)


def validate_sql(sql, max_rows, allow_write=False):
    """校验并规范化单条 SQL，返回 (规范化 SQL, 是否写语句)。"""
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 65536:
        raise GatewayError("SQL_INVALID", "SQL 为空或超过 64 KiB")
    if "/*!" in sql or "/*M!" in sql or "/*+" in sql:
        raise GatewayError("SQL_UNSAFE", "不支持可执行注释或优化器提示")
    explain = bool(re.match(r"^\s*EXPLAIN\s+", sql, re.I))
    source = re.sub(r"^\s*EXPLAIN\s+", "", sql, count=1, flags=re.I) if explain else sql
    try:
        statements = [x for x in sqlglot.parse(source, read="mysql", error_level=ErrorLevel.RAISE) if x is not None]
    except Exception:
        raise GatewayError("SQL_INVALID", "SQL 语法无效或不受支持") from None
    if len(statements) != 1:
        raise GatewayError("SQL_UNSAFE", "只允许一条 SQL" if allow_write else "只允许一条只读 SQL")
    tree = statements[0]
    if isinstance(tree, exp.Show) and not explain:
        if str(tree.this).upper() not in {"TABLES", "COLUMNS", "INDEX", "INDEXES", "CREATE TABLE"}:
            raise GatewayError("SQL_UNSAFE", "该 SHOW 形式未开放")
    elif isinstance(tree, exp.Describe) and not explain:
        if not isinstance(tree.this, exp.Table):
            raise GatewayError("SQL_UNSAFE", "仅支持表结构描述")
    elif isinstance(tree, exp.Use):
        # 网关为单条语句模型且连接一次性使用，USE 没有生效空间；给出可行的替代方式。
        raise GatewayError(
            "SQL_UNSAFE",
            "不支持 USE 切换数据库：跨库请用「库名.表名」限定表名，或在 execute_query 传入 database 参数指定目标库",
        )
    elif isinstance(tree, WRITE_ROOTS):
        if not allow_write:
            raise GatewayError(
                "TOOL_DENIED",
                "该账号未开启写操作：需在账号策略开启 allow_write 后才能执行 INSERT/UPDATE/DELETE",
                403,
            )
        if isinstance(tree, (exp.Update, exp.Delete)) and tree.args.get("where") is None:
            raise GatewayError("SQL_UNSAFE", "UPDATE/DELETE 必须携带 WHERE 条件，防止全表更新或删除")
    elif not isinstance(tree, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
        raise GatewayError(
            "SQL_UNSAFE",
            "只允许 SELECT/WITH、受限 SHOW/DESC/EXPLAIN"
            + ("，以及策略开启后的 INSERT/UPDATE/DELETE" if allow_write else ""),
        )
    count = 0
    # allow_write 时仅放行已通过根节点校验的 Insert/Update/Delete，其余结构限制（Into/Set/Command 等）不变。
    forbidden = FORBIDDEN - {"Insert", "Update", "Delete"} if allow_write else FORBIDDEN
    for node in tree.walk():
        count += 1
        if count > 5000 or type(node).__name__ in forbidden:
            raise GatewayError("SQL_UNSAFE", "SQL 包含不允许的结构")
        if isinstance(node, exp.Dot) and isinstance(node.expression, exp.Func):
            raise GatewayError("SQL_UNSAFE", "禁止调用带 schema 的函数")
        if isinstance(node, exp.Func):
            name = node.name.upper() if isinstance(node, exp.Anonymous) else node.sql_name().upper()
            if name in BAD_FUNCTIONS or (isinstance(node, exp.Anonymous) and name not in SAFE_ANONYMOUS):
                raise GatewayError("SQL_UNSAFE", "SQL 函数不在安全范围")
        node.comments = None
    if isinstance(tree, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
        # 限制最外层结果集；内层 LIMIT 不影响外层强制上限。
        existing = tree.args.get("limit")
        if existing is None:
            tree = tree.limit(max_rows + 1)
        elif isinstance(existing.expression, exp.Literal) and not existing.expression.is_string:
            try:
                if int(existing.expression.this) > max_rows + 1:
                    tree = tree.limit(max_rows + 1)
            except ValueError:
                raise GatewayError("SQL_UNSAFE", "不支持动态 LIMIT") from None
        else:
            raise GatewayError("SQL_UNSAFE", "不支持动态 LIMIT")
    return (
        ("EXPLAIN " if explain else "") + tree.sql(dialect="mysql"),
        isinstance(tree, WRITE_ROOTS) and not explain,
    )


def cell(value, ctx):
    if ctx.legacy:
        if value is None:
            return "NULL"
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        value = str(value).replace("\\", "\\\\").replace("\x00", "\\0").replace("\t", "\\t").replace("\n", "\\n")
    elif isinstance(value, bytes):
        value = {"base64": base64.b64encode(value[:256]).decode(), "bytes": len(value), "truncated": len(value) > 256}
    elif isinstance(value, (datetime.date, datetime.time, datetime.timedelta, decimal.Decimal)):
        value = str(value)
    if isinstance(value, str) and len(value) > ctx.limits["max_cell_chars"]:
        value = value[: ctx.limits["max_cell_chars"]] + "…（已截断）"
        ctx.stats["truncated"] = True
    return value


class BoundedConnection(pymysql.connections.Connection):
    def _read_packet(self, *args, **kwargs):
        self._packet_remaining = self.packet_budget
        return super()._read_packet(*args, **kwargs)

    def _read_bytes(self, count):
        if count > self._packet_remaining:
            raise GatewayError("MYSQL_PACKET_LIMIT", "数据库单行或协议包超过内存上限")
        self._packet_remaining -= count
        return super()._read_bytes(count)


def tls_failure(error):
    """判断异常是否为 TLS 协商失败（自动模式回退与错误分类共用）。"""
    return isinstance(error, ssl.SSLError) or "SSL:" in str(error)


def parse_version(version):
    """解析服务端版本为 (major, minor, patch, 是否 MariaDB)；无法解析时返回 None。"""
    value = str(version or "").strip()
    mariadb = "mariadb" in value.lower()
    if mariadb and value.startswith("5.5.5-"):
        value = value[len("5.5.5-") :]
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", value)
    return (*map(int, match.groups()), mariadb) if match else None


def statement_timeout(version, seconds):
    """按服务端版本选择语句级超时：MySQL ≥5.7.8 用毫秒参数，MariaDB ≥10.1 用秒参数；不支持时返回 None。"""
    parsed = parse_version(version)
    if not parsed:
        return None
    major, minor, patch, mariadb = parsed
    if mariadb:
        return f"SET SESSION max_statement_time={seconds:.3f}" if (major, minor) >= (10, 1) else None
    return f"SET SESSION MAX_EXECUTION_TIME={int(seconds * 1000)}" if (major, minor, patch) >= (5, 7, 8) else None


def connect_error(error):
    text = str(error)
    if isinstance(error, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text:
        return GatewayError(
            "MYSQL_TLS_FAILED",
            "TLS 证书验证失败：目标证书未受系统信任（常见于自签证书）。可将该资产 tls_mode 改为 REQUIRED，或配置 ca_file",
            502,
        )
    if tls_failure(error):
        start = text.find("[SSL:")
        detail = text[start : text.find("]", start) + 1] if start >= 0 else text[:80]
        return GatewayError(
            "MYSQL_TLS_FAILED",
            f"TLS 协商失败（{detail}）：目标可能未正确启用 SSL，或仅支持过旧的 TLS 版本；"
            "可将该资产 tls_mode 改为 PREFERRED（自动回退明文）或 DISABLED，或升级目标 TLS 配置",
            502,
        )
    if isinstance(error, TimeoutError):
        return GatewayError("MYSQL_TIMEOUT", "连接 MySQL 超时：请检查目标可用性与网络策略", 502)
    if isinstance(error, pymysql.err.OperationalError) and error.args:
        code = error.args[0]
        if code == 1045:
            return GatewayError("MYSQL_AUTH_FAILED", "MySQL 认证失败：请核对用户名、密码以及来源主机授权", 502)
        if code == 1049:
            return GatewayError("MYSQL_DATABASE_MISSING", "默认数据库不存在：请检查账号配置中的 database", 502)
        if code == 2013:
            return GatewayError("MYSQL_TIMEOUT", "MySQL 连接中断或超时：请检查网络与服务器状态", 502)
    return GatewayError("MYSQL_UNREACHABLE", "无法建立 MySQL 连接：请检查地址、端口与网络策略", 502)


def query_error(error):
    if isinstance(error, TimeoutError):
        return GatewayError("MYSQL_TIMEOUT", "查询超时：请缩小查询范围或添加过滤条件", 502)
    if isinstance(error, pymysql.err.OperationalError) and error.args and error.args[0] in (2013, 3024):
        return GatewayError("MYSQL_TIMEOUT", "查询超时或连接中断：请缩小范围并检查网络", 502)
    if isinstance(error, pymysql.err.Error) and error.args:
        code = error.args[0]
        message = error.args[1] if len(error.args) > 1 else str(error)
        return GatewayError("MYSQL_QUERY_FAILED", f"SQL 执行失败（{code}）：{str(message)[:300]}", 502)
    return GatewayError("MYSQL_QUERY_FAILED", "SQL 执行失败：请检查语句与远端对象权限", 502)


class MySQLAssetType(AssetType):
    type_id, display_name, icon = "mysql", "MySQL 数据库", "Coin"
    default_port = 3306
    connection_schema = obj(
        {
            "host": text("主机", maxLength=253, minLength=1),
            "port": integer("端口", 1, 65535, default=3306),
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
        {"username": text("数据库用户", minLength=1), "database": text("默认数据库", minLength=1)},
        ["username", "database"],
    )
    credential_schema = obj({"password": text("密码", minLength=1, format="password")}, ["password"])
    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "allow_write": {
                "type": "boolean",
                "title": "允许写操作",
                "default": False,
                "description": "开启后 execute_query 支持 INSERT/UPDATE/DELETE；UPDATE/DELETE 必须带 WHERE，DDL 与 SET 等仍被拒绝",
            },
        }
    )
    tools = [
        tool(
            "list_tables",
            "列出获授权数据库中的表及注释。",
            {"pattern": text("LIKE 模式", pattern=r"^[A-Za-z0-9_%$]{1,128}$")},
        ),
        tool(
            "describe_table",
            "查看表字段、注释及索引。",
            {"table": text("表名", pattern=r"^[A-Za-z0-9_$]{1,64}$")},
            ["table"],
        ),
        tool(
            "execute_query",
            "执行一条 SQL 并返回结果：默认仅只读；账号策略开启 allow_write 后可执行 INSERT/UPDATE/DELETE"
            "（UPDATE/DELETE 必须带 WHERE，DDL/USE/SET 等仍被拒绝）。",
            {
                "sql": text("SQL 语句", minLength=1, maxLength=65536),
                "database": text(
                    "目标数据库",
                    pattern=r"^[A-Za-z0-9_$]{1,64}$",
                    description="留空使用账号默认数据库，仅对本次调用生效；跨库也可直接用「库名.表名」限定",
                ),
                "max_rows": integer("行数", default=100),
            },
            ["sql"],
        ),
    ]

    def connect(self, ctx, database=None):
        cfg, account = ctx.asset["connection"], ctx.account["config"]
        host, port = cfg["host"], cfg.get("port", 3306)
        ip = ctx.network.resolve(host, port)
        mode = cfg.get("tls_mode", "PREFERRED")
        tls = {"ssl_disabled": True}
        if mode != "DISABLED":
            ssl_context = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
            if mode in ("PREFERRED", "REQUIRED"):
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            tls = {"ssl": ssl_context}

        def dial(tls_args):
            # 失败时抛出原始异常，由调用方决定是否回退明文或映射错误码。
            ctx.remaining()
            try:
                sock = socket.create_connection((ip, port), min(ctx.remaining(), ctx.limits["connect_timeout_seconds"]))
            except TimeoutError:
                raise GatewayError("MYSQL_TIMEOUT", "连接 MySQL 超时：请检查目标可用性与网络策略", 502) from None
            except OSError:
                raise GatewayError(
                    "MYSQL_UNREACHABLE", "无法建立 MySQL 连接：请检查地址、端口与网络策略", 502
                ) from None
            ctx.add_closer(sock.close)
            conn = BoundedConnection(
                host=host,
                port=port,
                user=account["username"],
                password=ctx.credential["password"],
                database=database or account["database"],
                charset="utf8mb4",
                autocommit=True,
                read_timeout=ctx.limits["query_timeout_seconds"],
                write_timeout=5,
                cursorclass=pymysql.cursors.SSCursor,
                defer_connect=True,
                **tls_args,
            )
            conn.packet_budget = max(1048576, ctx.limits["max_output_bytes"] * 4)
            conn.connect(sock=sock)
            return conn

        try:
            conn = dial(tls)
        except (pymysql.err.Error, OSError) as error:
            if mode == "PREFERRED" and not tls.get("ssl_disabled") and tls_failure(error):
                # 自动模式：目标无法完成 TLS 握手（常见于仅支持旧版 TLS 的服务端）时，回退明文重试一次。
                try:
                    conn = dial({"ssl_disabled": True})
                except (pymysql.err.Error, OSError) as fallback_error:
                    raise connect_error(fallback_error) from None
            else:
                raise connect_error(error) from None

        # 不通过 cursor.close() 排空被截断的结果；直接关闭连接底层 socket。
        def close():
            raw = getattr(conn, "_sock", None)
            if raw:
                try:
                    raw.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            conn.close()

        ctx.add_closer(close)
        cursor = conn.cursor()
        try:
            cursor.execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'")
            timeout = statement_timeout(conn.server_version, ctx.remaining())
            if timeout:
                try:
                    cursor.execute(timeout)
                except pymysql.err.Error as error:
                    # 兼容实现可能存在版本号匹配但不支持该变量的情况，忽略未知变量的报错。
                    if not (error.args and error.args[0] == 1193):
                        raise
        except (pymysql.err.Error, OSError) as error:
            raise query_error(error) from None
        return conn

    def query(self, conn, sql, parameters, ctx, limit):
        ctx.remaining()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, parameters)
        except (pymysql.err.Error, OSError) as error:
            raise query_error(error) from None
        columns = [item[0] for item in (cursor.description or [])]
        rows, size, truncated = [], 0, False
        budget = max(0, (ctx.limits["max_output_bytes"] - 512) // 2 - len(dumps(columns).encode()))
        for raw in cursor:
            ctx.remaining()
            if len(rows) >= limit:
                truncated = True
                break
            row = [cell(value, ctx) for value in raw]
            size += len(dumps(row).encode())
            if size > budget:
                truncated = True
                break
            rows.append(row)
        # 本调用后若需继续查询，必须关闭截断连接，不能隐式消费剩余行。
        if truncated:
            ctx.close()
        else:
            cursor.close()
        ctx.stats.update(row_count=len(rows), truncated=truncated or ctx.stats.get("truncated", False))
        return columns, rows, truncated

    def execute_write(self, conn, sql, ctx):
        # 单语句写：连接 autocommit=True 即原子提交，且连接一次性使用，失败后直接丢弃、无状态泄漏。
        ctx.remaining()
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
            affected = cursor.rowcount
        except (pymysql.err.Error, OSError) as error:
            raise query_error(error) from None
        cursor.close()
        return max(affected, 0)

    def execute_sync(self, name, args, ctx):
        start = time.monotonic()
        sql, write = None, False
        if name == "execute_query":
            sql, write = validate_sql(
                args["sql"],
                min(args.get("max_rows", 100), ctx.limits["max_result_rows"]),
                allow_write=bool(ctx.account["policy"].get("allow_write")),
            )
        conn = self.connect(ctx, args.get("database") if name == "execute_query" else None)
        try:
            db = ctx.account["config"]["database"]
            if name == "execute_query":
                if write:
                    return result(
                        {
                            "columns": [],
                            "rows": [],
                            "row_count": 0,
                            "affected_rows": self.execute_write(conn, sql, ctx),
                            "truncated": False,
                            "elapsed_ms": int((time.monotonic() - start) * 1000),
                            "note": "写操作已执行（单语句自动提交）",
                        }
                    )
                cols, rows, cut = self.query(
                    conn, sql, None, ctx, min(args.get("max_rows", 100), ctx.limits["max_result_rows"])
                )
                return result(
                    {
                        "columns": cols,
                        "rows": rows,
                        "row_count": len(rows),
                        "truncated": cut or ctx.stats.get("truncated", False),
                        "elapsed_ms": int((time.monotonic() - start) * 1000),
                        "note": "专用账号查询",
                    }
                )
            if name == "list_tables":
                query = "SELECT TABLE_NAME,TABLE_COMMENT,TABLE_ROWS,CREATE_TIME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s"
                values = [db]
                if args.get("pattern"):
                    query += " AND TABLE_NAME LIKE %s"
                    values.append(args["pattern"])
                _, rows, cut = self.query(
                    conn, query + " ORDER BY TABLE_NAME", values, ctx, ctx.limits["max_result_rows"]
                )
                return result(
                    {
                        "database": db,
                        "count": len(rows),
                        "truncated": cut,
                        "tables": [
                            dict(zip(("table", "comment", "rows_estimate", "created"), row, strict=True))
                            for row in rows
                        ],
                    }
                )
            table = args["table"]
            _, header, _ = self.query(
                conn,
                "SELECT TABLE_COMMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                (db, table),
                ctx,
                1,
            )
            if not header:
                raise GatewayError("TABLE_NOT_FOUND", "表不存在或不可访问", 404)
            _, rows, cut = self.query(
                conn,
                "SELECT ORDINAL_POSITION,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,COLUMN_KEY,EXTRA,COLUMN_COMMENT "
                "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION",
                (db, table),
                ctx,
                500,
            )
            if cut:
                raise GatewayError("OUTPUT_LIMIT", "表结构超过输出限制")
            columns = [
                dict(zip(("pos", "name", "type", "nullable", "default", "key", "extra", "comment"), r, strict=True))
                for r in rows
            ]
            _, rows, cut = self.query(
                conn,
                "SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME FROM information_schema.STATISTICS "
                "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY INDEX_NAME,SEQ_IN_INDEX",
                (db, table),
                ctx,
                500,
            )
            indexes = {}
            for key, non_unique, _seq, column in rows:
                indexes.setdefault(key, {"name": key, "unique": str(non_unique) == "0", "columns": []})[
                    "columns"
                ].append(column)
            return result(
                {
                    "table": table,
                    "comment": header[0][0],
                    "columns": columns,
                    "indexes": list(indexes.values()),
                    "truncated": cut,
                }
            )
        finally:
            ctx.close()

    def health_sync(self, ctx):
        conn = self.connect(ctx)
        try:
            self.query(conn, "SELECT 1", None, ctx, 1)
            return {"reachable": True}
        finally:
            ctx.close()
