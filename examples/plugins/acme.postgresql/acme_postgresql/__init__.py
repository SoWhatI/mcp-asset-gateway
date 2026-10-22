"""PostgreSQL 插件实现（依赖 pg8000；出站走 SDK 的登记校验与 IP 固定）。

只读校验用语句首词白名单；写入要求账号策略 allow_write 且 UPDATE/DELETE 带 WHERE。
"""

import re

import pg8000.native
from mag_plugin import AssetType, Plugin, PluginError, ok

READ_ONLY_PREFIXES = ("select", "with", "show", "explain", "table")
WRITE_PREFIXES = ("insert", "update", "delete")


def clip(value, ctx):
    limit = ctx.limits.get("max_cell_chars", 1000)
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…（已截断）"
    return value


class PostgreSQLType(AssetType):
    type_id = "acme.postgresql"
    display_name = "PostgreSQL 数据库"
    icon = "Coin"
    default_port = 5432

    def connect(self, ctx):
        connection = ctx.connection
        account = ctx.account
        # 出站必须走 SDK：登记校验 + DNS 固定 IP，绕过会直接被网关语义拒绝。
        pinned_ip = ctx.net.resolve(connection["host"], connection.get("port", 5432))
        try:
            return pg8000.native.Connection(
                user=account["user"],
                database=account["database"],
                password=ctx.credential["password"],
                host=pinned_ip,
                port=connection.get("port", 5432),
                ssl_context=False if account.get("sslmode", "prefer") == "disable" else None,
                timeout=min(10, max(1, ctx.remaining())),
            )
        except Exception as error:
            raise PluginError("PG_CONNECT_FAILED", f"连接 PostgreSQL 失败：{error}") from None

    def validate_config(self, ctx, connection, account, policy, credential):
        if account.get("sslmode") not in (None, "prefer", "require", "verify-full", "disable"):
            raise PluginError("SSL_INVALID", "sslmode 不支持")
        if not credential.get("password"):
            raise PluginError("PASSWORD_REQUIRED", "必须提供数据库密码")

    def health(self, ctx):
        conn = self.connect(ctx)
        try:
            version = conn.run("SELECT version()")
            return {"ok": True, "version": str(version[0][0]) if version else "unknown"}
        finally:
            conn.close()

    def list_tables(self, ctx, arguments):
        schema = arguments.get("schema", "public")
        self._check_ident(schema, "schema")
        conn = self.connect(ctx)
        try:
            rows = conn.run(
                "SELECT c.relname, pg_get_userbyid(c.relowner), obj_description(c.oid, 'pg_class') "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :schema AND c.relkind IN ('r','p') ORDER BY c.relname LIMIT :limit",
                schema=schema,
                limit=ctx.limits.get("max_result_rows", 500),
            )
            return ok({"tables": [{"name": row[0], "owner": row[1], "comment": clip(row[2], ctx)} for row in rows]})
        finally:
            conn.close()

    def describe_table(self, ctx, arguments):
        schema, table = arguments.get("schema", "public"), arguments["table"]
        self._check_ident(schema, "schema")
        self._check_ident(table, "table")
        conn = self.connect(ctx)
        try:
            rows = conn.run(
                "SELECT a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, "
                "col_description(a.attrelid, a.attnum) "
                "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :schema AND c.relname = :table AND a.attnum > 0 AND NOT a.attisdropped "
                "ORDER BY a.attnum",
                schema=schema,
                table=table,
            )
            if not rows:
                raise PluginError("TABLE_NOT_FOUND", f"表不存在：{schema}.{table}")
            return ok(
                {
                    "columns": [
                        {"name": row[0], "type": str(row[1]), "nullable": bool(row[2]), "comment": clip(row[3], ctx)}
                        for row in rows
                    ]
                }
            )
        finally:
            conn.close()

    def sql_query(self, ctx, arguments):
        sql = arguments["sql"].strip().rstrip(";")
        self._require_readonly(sql)
        conn = self.connect(ctx)
        try:
            rows = conn.run(sql)
            limit = ctx.limits.get("max_result_rows", 500)
            truncated = len(rows) > limit
            keys = [column["name"] for column in conn.columns] if hasattr(conn, "columns") else []
            payload = [
                {keys[i] if i < len(keys) else f"col{i}": clip(value, ctx) for i, value in enumerate(row)}
                for row in rows[:limit]
            ]
            return ok({"rows": payload, "row_count": len(rows), "truncated": truncated})
        finally:
            conn.close()

    def sql_execute(self, ctx, arguments):
        sql = arguments["sql"].strip().rstrip(";")
        if not ctx.policy.get("allow_write"):
            raise PluginError("WRITE_DENIED", "账号策略未开启 allow_write，禁止写操作")
        first = sql.split(None, 1)[0].lower() if sql else ""
        if first not in WRITE_PREFIXES:
            raise PluginError("SQL_WRITE_ONLY", "sql_execute 只支持 INSERT/UPDATE/DELETE")
        if first in ("update", "delete") and not re.search(r"\bwhere\b", sql, re.IGNORECASE):
            raise PluginError("WHERE_REQUIRED", "UPDATE/DELETE 必须带 WHERE 条件")
        conn = self.connect(ctx)
        try:
            row_count = conn.run(sql)
            return ok({"row_count": int(row_count) if row_count is not None else 0})
        finally:
            conn.close()

    def execute(self, tool, args, ctx):
        ctx.check_deadline()
        handlers = {
            "list_tables": self.list_tables,
            "describe_table": self.describe_table,
            "sql_query": self.sql_query,
            "sql_execute": self.sql_execute,
        }
        handler = handlers.get(tool)
        if not handler:
            raise PluginError("TOOL_MISSING", tool)
        return handler(ctx, args)

    @staticmethod
    def _check_ident(value, what):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value or ""):
            raise PluginError("IDENT_INVALID", f"{what} 名不合法")

    @staticmethod
    def _require_readonly(sql):
        first = sql.split(None, 1)[0].lower() if sql else ""
        if first not in READ_ONLY_PREFIXES:
            raise PluginError("SQL_READONLY", "sql_query 只支持 SELECT/WITH/SHOW/EXPLAIN/TABLE")


class PostgreSQLPlugin(Plugin):
    asset_types = [PostgreSQLType]
