import csv
import io
import json
import logging
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.core.config import Config
from app.core.db import decode, now
from app.core.gateway import Gateway
from app.core.manager import TABLES, audit
from app.core.security import GatewayError, depth, equal

VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def create_app(config=None):
    if config is None:
        load_dotenv()
        config = Config.from_env()
    gateway = Gateway(config)

    @asynccontextmanager
    async def lifespan(app):
        await gateway.start()
        try:
            yield
        finally:
            await gateway.stop()

    app = FastAPI(title="MCP 资产网关", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway = gateway
    manager = gateway.manager

    def error_response(error, request):
        return JSONResponse(
            {
                "error": {"code": error.code, "message": error.message},
                "request_id": getattr(request.state, "request_id", None),
            },
            status_code=error.status,
        )

    @app.exception_handler(GatewayError)
    async def handle_gateway(request, error):
        return error_response(error, request)

    @app.exception_handler(sqlite3.IntegrityError)
    async def handle_integrity(request, error):
        return error_response(GatewayError("CONFLICT", "对象已存在或仍被引用，请先解除相关关联后重试", 409), request)

    @app.exception_handler(sqlite3.Error)
    async def handle_storage(request, error):
        gateway.audit_failed = True
        return error_response(GatewayError("STORAGE_UNAVAILABLE", "存储暂不可用", 503), request)

    @app.middleware("http")
    async def boundary(request, call_next):
        request.state.request_id = str(uuid.uuid4())
        try:
            host = urlsplit("//" + request.headers.get("host", "")).hostname
            if host not in config.hosts:
                raise GatewayError("HOST_DENIED", "Host 不在允许列表中", 403)
            origin = request.headers.get("origin")
            if origin is not None and origin not in config.origins:
                raise GatewayError("ORIGIN_DENIED", "Origin 不在允许列表中", 403)
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                if request.headers.get("content-encoding", "identity") != "identity":
                    raise GatewayError("ENCODING", "不接受压缩请求体", 415)
                data = bytearray()
                async for chunk in request.stream():
                    data.extend(chunk)
                    if len(data) > 1048576:
                        raise GatewayError("BODY_LIMIT", "请求体超过 1 MiB", 413)
                request._body = bytes(data)
            response = await call_next(request)
        except GatewayError as error:
            response = error_response(error, request)
        except (ValueError, json.JSONDecodeError):
            response = error_response(GatewayError("BAD_REQUEST", "请求格式无效", 400), request)
        except Exception:
            logging.getLogger("gateway").error("request_id=%s event=internal_error", request.state.request_id)
            response = error_response(GatewayError("INTERNAL", "内部错误，请使用请求编号联系管理员", 500), request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'"
        )
        if request.url.path.startswith(("/api", "/mcp")):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path in ("/", "/index.html"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    async def body(request, allow_array=False):
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            raise GatewayError("CONTENT_TYPE", "需要 application/json", 415)
        try:

            def invalid_constant(value):
                raise ValueError("非有限 JSON 数字")

            value = json.loads(await request.body(), parse_constant=invalid_constant)
            depth(value)
        except (ValueError, RecursionError):
            raise GatewayError("JSON_INVALID", "JSON 格式无效", 400) from None
        if not isinstance(value, (dict, list) if allow_array else dict):
            raise GatewayError("JSON_INVALID", "请求必须为 JSON 对象", 400)
        return value

    async def admin(request):
        write = request.method not in ("GET", "HEAD")
        if write and request.headers.get("origin") not in config.origins:
            raise GatewayError("CSRF", "管理写请求需要同源 Origin", 403)
        token = request.cookies.get("gateway_session", "")
        csrf = request.headers.get("x-csrf-token", "") if write else None
        return await gateway.db(manager.session, token, csrf)

    def ok(request, data):
        return {"data": data, "request_id": request.state.request_id}

    def clear_cookies(response):
        for name in ("gateway_session", "gateway_csrf"):
            response.delete_cookie(name, path="/", secure=config.secure_cookie, samesite="strict")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        if gateway.audit_failed:
            return JSONResponse({"status": "unavailable"}, 503)
        try:
            await gateway.db(gateway.store.settings)
        except Exception:
            return JSONResponse({"status": "unavailable"}, 503)
        return {"status": "ok"}

    @app.post("/api/auth/login")
    async def login(request: Request):
        if request.headers.get("origin") not in config.origins:
            raise GatewayError("CSRF", "登录需要同源 Origin", 403)
        payload = await body(request)
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or len(username) > 100 or not isinstance(password, str):
            raise GatewayError("VALIDATION", "用户名或密码格式不正确")
        ip = request.client.host if request.client else "unknown"
        gateway.rate.check("login-ip:" + ip, 30, 300)
        gateway.rate.check("login-user:" + username, 10, 300)
        user, token, csrf = await gateway.db(manager.login, username, password)
        response = JSONResponse(ok(request, user))
        response.set_cookie(
            "gateway_session",
            token,
            max_age=28800,
            httponly=True,
            secure=config.secure_cookie,
            samesite="strict",
            path="/",
        )
        response.set_cookie(
            "gateway_csrf",
            csrf,
            max_age=28800,
            httponly=False,
            secure=config.secure_cookie,
            samesite="strict",
            path="/",
        )
        return response

    @app.get("/api/auth/me")
    async def me(request: Request):
        actor = await admin(request)
        return ok(request, {"id": actor["id"], "username": actor["username"]})

    @app.post("/api/auth/logout")
    async def logout(request: Request):
        await gateway.db(manager.logout, await admin(request))
        response = JSONResponse(ok(request, {"ok": True}))
        clear_cookies(response)
        return response

    @app.patch("/api/auth/password")
    async def change_password(request: Request):
        actor, payload = await admin(request), await body(request)
        await gateway.db(manager.change_password, actor, payload.get("old_password"), payload.get("new_password"))
        response = JSONResponse(ok(request, {"ok": True}))
        clear_cookies(response)
        return response

    @app.get("/api/types")
    async def types(request: Request):
        await admin(request)
        return ok(request, [kind.description() for kind in gateway.types.values()])

    @app.get("/api/dashboard")
    async def dashboard(request: Request):
        await admin(request)
        return ok(request, await gateway.db(manager.dashboard))

    @app.get("/api/settings")
    async def settings(request: Request):
        await admin(request)
        return ok(request, await gateway.db(manager.settings))

    @app.patch("/api/settings")
    async def update_settings(request: Request):
        actor = await admin(request)
        return ok(request, await gateway.db(manager.update_settings, await body(request, allow_array=True), actor))

    @app.get("/api/audit/export")
    async def export(request: Request):
        actor = await admin(request)
        gateway.rate.check("export:" + actor["id"], 5, 60)
        result = await gateway.db(manager.audits, dict(request.query_params), 10000)
        if result["next_cursor"]:
            raise GatewayError("EXPORT_LIMIT", "超过 10,000 行，请缩小时间范围")
        output = io.StringIO()
        writer = csv.writer(output)
        keys = (
            "ts",
            "request_id",
            "source",
            "event",
            "actor_id",
            "client_id",
            "asset_id",
            "account_id",
            "tool",
            "status",
            "elapsed_ms",
            "error_code",
        )
        writer.writerow(keys)
        for row in result["items"]:
            values = []
            for key in keys:
                value = str(row[key]) if row.get(key) is not None else ""
                if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
                    value = "'" + value
                values.append(value)
            writer.writerow(values)

        def log_export():
            with gateway.store.connect(write=True) as conn:
                audit(conn, "audit.export", actor["id"])

        await gateway.db(log_export)
        return Response(
            "\ufeff" + output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="gateway-audit.csv"'},
        )

    @app.get("/api/audit")
    async def audits(request: Request, limit: int = 20, cursor: str | None = None):
        await admin(request)
        return ok(
            request, await gateway.db(manager.audits, dict(request.query_params), max(1, min(100, limit)), cursor)
        )

    @app.get("/api/audit/{identity}")
    async def audit_detail(identity: int, request: Request):
        await admin(request)

        def get():
            with gateway.store.connect() as conn:
                value = decode(conn.execute("SELECT * FROM audit_log WHERE id=?", (identity,)).fetchone())
                if not value:
                    raise GatewayError("NOT_FOUND", "审计记录不存在", 404)
                return value

        return ok(request, await gateway.db(get))

    @app.post("/api/accounts/{identity}/test")
    async def test_account(identity: str, request: Request):
        return ok(request, await gateway.test(identity, await admin(request), request.state.request_id))

    @app.get("/api/accounts/{identity}/tools")
    async def account_tools(identity: str, request: Request):
        await admin(request)
        asset, account, _ = await gateway.db(gateway.account_snapshot, identity)
        kind = gateway.types[asset["type"]]
        specs = kind.catalog(account)
        return ok(
            request,
            {
                "tools": specs,
                "refreshed_at": account["catalog_refreshed_at"],
                "stale": kind.proxied
                and (not account["catalog_refreshed_at"] or now() - account["catalog_refreshed_at"] > 300000),
            },
        )

    @app.post("/api/accounts/{identity}/refresh-tools")
    async def refresh_tools(identity: str, request: Request):
        actor = await admin(request)
        gateway.rate.check("refresh:" + actor["id"], 20)
        return ok(request, {"tools": await gateway.refresh(identity, actor, request_id=request.state.request_id)})

    @app.post("/api/clients/{identity}/rotate-token")
    async def rotate_token(identity: str, request: Request):
        actor, payload = await admin(request), await body(request)
        return ok(request, await gateway.db(manager.rotate, identity, payload.get("revision"), actor))

    @app.post("/api/debug/{operation}")
    async def debug(operation: str, request: Request):
        actor, payload = await admin(request), await body(request)
        client = await gateway.db(manager.client, payload.get("client_id"))
        if operation == "tools-list":

            def log_list():
                with gateway.store.connect(write=True) as conn:
                    audit(conn, "debug.tools-list", actor["id"], client_id=client["id"])

            await gateway.db(log_list)
            return ok(request, await gateway.tools_list(client))
        if operation == "tools-call":
            if payload.get("confirm") is not True:
                raise GatewayError("CONFIRM_REQUIRED", "调试调用必须显式确认执行")
            return ok(request, await gateway.call(client, payload.get("name"), payload.get("arguments", {}), actor))
        raise GatewayError("NOT_FOUND", "调试操作不存在", 404)

    @app.api_route("/api/{table}", methods=["GET", "POST"])
    async def collections(table: str, request: Request, limit: int = 20, offset: int = 0):
        actor = await admin(request)
        if table not in TABLES:
            raise GatewayError("NOT_FOUND", "接口不存在", 404)
        if request.method == "GET":
            return ok(request, await gateway.db(manager.list, table, limit, offset))
        return ok(request, await gateway.db(manager.save, table, await body(request), actor))

    @app.api_route("/api/{table}/{identity}", methods=["GET", "PATCH", "DELETE"])
    async def record(table: str, identity: str, request: Request, revision: int = 0):
        actor = await admin(request)
        if table not in TABLES:
            raise GatewayError("NOT_FOUND", "接口不存在", 404)
        if request.method == "GET":
            return ok(request, await gateway.db(manager.get, table, identity))
        if request.method == "DELETE":
            return ok(request, await gateway.db(manager.delete, table, identity, revision, actor))
        return ok(request, await gateway.db(manager.save, table, await body(request), actor, identity))

    @app.get("/mcp")
    async def mcp_get():
        return Response(status_code=405, headers={"Allow": "POST"})

    @app.post("/mcp")
    async def mcp(request: Request):
        gateway.rate.check("mcp-ip:" + (request.client.host if request.client else "unknown"), 300)
        authorization = request.headers.get("authorization", "")
        bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        custom = request.headers.get("x-agent-token", "")
        if bearer and custom and not equal(bearer, custom):
            raise GatewayError("UNAUTHORIZED", "两种认证头不一致", 401)
        token = custom or bearer
        if not token or len(token) > 4096:
            raise GatewayError("UNAUTHORIZED", "缺失有效客户端令牌", 401)
        try:
            client = await gateway.db(manager.client, None, token)
        except GatewayError:

            def log_denied():
                with gateway.store.connect(write=True) as conn:
                    audit(conn, "mcp.authenticate", source="mcp", status="denied", error_code="UNAUTHORIZED")

            await gateway.db(log_denied)
            raise
        try:
            message = await body(request, allow_array=True)
        except GatewayError as error:
            if error.code != "JSON_INVALID":
                raise
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
        if not isinstance(message, dict):
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
        identity, method = message.get("id"), message.get("method")
        if (
            message.get("jsonrpc") != "2.0"
            or not isinstance(method, str)
            or ("id" in message and type(identity) not in (str, int))
        ):
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
        params = message.get("params", {})
        if not isinstance(params, dict):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid params"}}
            )
        if "id" not in message:
            # 通知不能执行 tools/call，避免无回应的副作用调用。
            return Response(status_code=202)
        version = request.headers.get("mcp-protocol-version")
        if version and version not in VERSIONS:
            raise GatewayError("PROTOCOL_VERSION", "不支持该 MCP 协议版本", 400)
        if method == "initialize":
            value = {
                "protocolVersion": params.get("protocolVersion")
                if params.get("protocolVersion") in VERSIONS
                else VERSIONS[0],
                "serverInfo": {"name": "mcp-asset-gateway", "version": "0.1.0"},
                "capabilities": {"tools": {"listChanged": False}},
            }
        elif method == "ping":
            value = {}
        elif method == "tools/list":
            if params.get("cursor") is not None:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid cursor"}}
                )
            value = await gateway.tools_list(client)
        elif method == "tools/call":
            if not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": identity, "error": {"code": -32602, "message": "Invalid params"}}
                )
            value = await gateway.call(client, params.get("name"), params.get("arguments", {}))
        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": identity, "error": {"code": -32601, "message": "Method not found"}}
            )
        return JSONResponse({"jsonrpc": "2.0", "id": identity, "result": value})

    static = Path(__file__).resolve().parent.parent / "static"
    if static.is_dir():
        app.mount("/", StaticFiles(directory=static, html=True), name="ui")
    else:

        @app.get("/")
        async def unbuilt():
            return {"service": "mcp-asset-gateway", "message": "请先在 web 目录运行 npm ci && npm run build"}

    return app


def app_factory():
    return create_app()
