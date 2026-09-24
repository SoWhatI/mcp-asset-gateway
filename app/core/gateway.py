import asyncio
import copy
import datetime
import logging
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from app.asset_types.base import BlockingRunner, Context, failed
from app.asset_types.filebrowser import SFTPAssetType
from app.asset_types.gitrepo import GitRepoAssetType
from app.asset_types.jenkins import JenkinsAssetType
from app.asset_types.kubernetes import KubernetesAssetType
from app.asset_types.mcp import MCPProxyAssetType, public_name
from app.asset_types.mysql import MySQLAssetType
from app.asset_types.redis import RedisAssetType
from app.asset_types.ssh import SSHAssetType
from app.core.config import DEFAULTS
from app.core.db import Store, decode, dumps, now
from app.core.manager import Manager, audit, fetch
from app.core.security import GatewayError, NetworkPolicy, RateLimit, Vault, digest, equal, validate
from app.core.tool_rules import enforce_rules

logger = logging.getLogger("gateway")


class Gateway:
    def __init__(self, config):
        self.config = config
        self.store = Store(config.database)
        self.vault = Vault(config.master_key, config.key_id)
        self.network = NetworkPolicy(config)
        self.types = {
            t.type_id: t
            for t in (
                MySQLAssetType(),
                SSHAssetType(config.ssh_host_key_enforce),
                SFTPAssetType(config.ssh_host_key_enforce),
                MCPProxyAssetType(),
                RedisAssetType(),
                KubernetesAssetType(),
                GitRepoAssetType(config.data_dir, config.ssh_host_key_enforce),
                JenkinsAssetType(config.master_key),
            )
        }
        self.manager = Manager(self.store, self.vault, self.types, self.network)
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="database")
        self.db_slots = asyncio.Semaphore(64)
        self.runner = BlockingRunner()
        self.slots = asyncio.Semaphore(16)
        self.client_slots, self.refresh_locks, self.health_cache = {}, {}, {}
        self.rate = RateLimit()
        self.audit_failed = False
        self.contexts = []
        self.active_requests = set()
        self.maintenance_task = None

    async def db(self, fn, *args):
        try:
            await asyncio.wait_for(self.db_slots.acquire(), 2)
        except TimeoutError:
            raise GatewayError("DB_BUSY", "管理存储繁忙", 503) from None
        future = asyncio.get_running_loop().run_in_executor(self.pool, fn, *args)

        def completed(done):
            self.db_slots.release()
            if not done.cancelled():
                done.exception()

        future.add_done_callback(completed)
        return await asyncio.shield(future)

    def release_capacity(self, ctx, *semaphores):
        def release(_=None):
            for semaphore in semaphores:
                semaphore.release()

        if ctx and ctx.worker_future and not ctx.worker_future.done():
            ctx.worker_future.add_done_callback(release)
        else:
            release()

    async def start(self):
        self.store.acquire()
        try:
            await self.db(self.store.migrate)
            if self.config.legacy:
                from app.core.legacy import import_legacy

                await self.db(import_legacy, self)
            await self.db(self.manager.check_all_credentials)
            self.maintenance_task = asyncio.create_task(self.maintenance())
        except BaseException:
            self.store.release()
            raise

    async def stop(self):
        if self.maintenance_task:
            self.maintenance_task.cancel()
            await asyncio.gather(self.maintenance_task, return_exceptions=True)
        for ctx in list(self.contexts):
            ctx.cancel()
        self.runner.close()
        self.pool.shutdown(wait=True)
        self.store.release()

    def account_snapshot(self, identity):
        with self.store.connect() as conn:
            account = fetch(conn, "accounts", identity)
            asset = fetch(conn, "assets", account["asset_id"])
            if not account["enabled"] or not asset["enabled"]:
                raise GatewayError("DISABLED", "资产或账号已禁用", 403)
            return asset, account, self.store.settings(conn)

    def context(self, asset, account, settings, legacy=False):
        limits = {key: settings.get(key, value) for key, value in DEFAULTS.items()}
        for key in limits:
            if key in account["policy"]:
                limits[key] = min(limits[key], account["policy"][key])
        return Context(
            asset,
            account,
            self.vault.decrypt(account["credential_ciphertext"], account["credential_key_id"]),
            limits,
            self.network,
            legacy,
            enforce_host_key=self.config.ssh_host_key_enforce,
        )

    def entries(self, client, conn=None):
        if conn is None:
            with self.store.connect() as current:
                return self.entries(client, current)
        current = self.manager.client(identity=client["id"], conn=conn)
        if not equal(current["token_hash"], client["token_hash"]):
            raise GatewayError("UNAUTHORIZED", "客户端令牌已轮换", 401)
        entries, granted = {}, {}
        for grant_row in conn.execute(
            "SELECT g.*,gc.client_id,ga.account_id,ga.tools_json AS entry_tools_json,ga.parameter_rules_json FROM grants g "
            "JOIN grant_clients gc ON gc.grant_id=g.id JOIN grant_accounts ga ON ga.grant_id=g.id "
            "WHERE gc.client_id=? AND g.enabled=1 ORDER BY ga.account_id,g.id",
            (client["id"],),
        ):
            grant = decode(grant_row)
            entry_tools = grant.pop("entry_tools")
            account = fetch(conn, "accounts", grant["account_id"])
            asset = fetch(conn, "assets", account["asset_id"])
            if not account["enabled"] or not asset["enabled"]:
                continue
            kind = self.types[asset["type"]]
            specs = kind.catalog(account)
            for spec in specs:
                original = spec["name"]
                if original not in entry_tools:
                    continue
                if kind.proxied:
                    if not account["catalog_refreshed_at"] or now() - account["catalog_refreshed_at"] > 300000:
                        continue
                    if grant["tool_versions"].get(account["id"], {}).get(original) != spec["spec_hash"]:
                        continue
                name = public_name(account["id"], original) if kind.proxied else original
                key = (account["id"], original)
                if key in granted:
                    granted[key]["grants"].append(grant)
                    continue
                item = {"spec": spec, "account": account, "asset": asset, "grant": grant, "grants": [grant]}
                if kind.proxied and name in entries:
                    raise GatewayError("TOOL_COLLISION", "工具名称发生冲突", 503)
                granted[key] = item
                entries.setdefault(name, []).append(item)
        return entries

    async def ensure_catalogs(self, client):
        def targets():
            with self.store.connect() as conn:
                current = self.manager.client(identity=client["id"], conn=conn)
                if not equal(current["token_hash"], client["token_hash"]):
                    raise GatewayError("UNAUTHORIZED", "客户端令牌已轮换", 401)
                return [
                    r[0]
                    for r in conn.execute(
                        "SELECT DISTINCT a.id FROM accounts a JOIN assets s ON a.asset_id=s.id "
                        "JOIN grant_accounts ga ON ga.account_id=a.id JOIN grants g ON g.id=ga.grant_id "
                        "JOIN grant_clients gc ON gc.grant_id=g.id "
                        "WHERE gc.client_id=? AND g.enabled=1 AND a.enabled=1 AND s.enabled=1 AND s.type='mcp' AND g.tools_json!='[]' "
                        "AND (a.catalog_refreshed_at IS NULL OR a.catalog_refreshed_at<?)",
                        (client["id"], now() - 300000),
                    )
                ]

        try:
            async with asyncio.timeout(30):
                for identity in await self.db(targets):
                    try:
                        await self.refresh(identity, None, force=False)
                    except Exception as error:
                        # 单个上游目录刷新失败只影响该账号：过期目录仍不放行，其它工具照常。
                        code = error.code if isinstance(error, GatewayError) else type(error).__name__
                        logger.warning("event=catalog_refresh_failed account=%s code=%s", identity, code)
        except TimeoutError:
            logger.warning("event=catalog_refresh_timeout")

    async def tools_list(self, client):
        await self.ensure_catalogs(client)
        entries = await self.db(self.entries, client)
        result = []
        for name, candidates in entries.items():
            spec = copy.deepcopy(candidates[0]["spec"])
            spec.pop("spec_hash", None)
            spec["name"] = name
            if any(
                c["grants"] and any(g.get("parameter_rules", {}).get(c["spec"]["name"]) for g in c["grants"])
                for c in candidates
            ):
                spec["description"] += " 参数受授权组黑白名单约束：黑名单优先，正则全文匹配。"
            if candidates[0]["asset"]["type"] == "kubernetes" and len(candidates) > 1:
                # 混合锁定/未锁定命名空间账号时目录必须暴露参数，执行仍按所选账号严格校验。
                for candidate in candidates:
                    prop = candidate["spec"]["inputSchema"]["properties"].get("namespace")
                    if prop:
                        spec["inputSchema"]["properties"]["namespace"] = copy.deepcopy(prop)
                if any("namespace" not in c["spec"]["inputSchema"].get("required", []) for c in candidates):
                    spec["inputSchema"]["required"] = [
                        key for key in spec["inputSchema"].get("required", []) if key != "namespace"
                    ]
            if not self.types[candidates[0]["asset"]["type"]].proxied:
                spec["description"] += " 可访问账号：" + "、".join(
                    f"{v['asset']['name']} · {v['account']['name']}（{v['account']['id']}）" for v in candidates
                )
                if len(candidates) > 1:
                    spec["description"] += "；target 参数请填上述资产账号 ID"
                    spec["inputSchema"]["properties"]["target"] = {
                        "type": "string",
                        "description": "执行该调用的资产账号 ID（见工具描述中的可访问账号）",
                        "enum": [v["account"]["id"] for v in candidates],
                    }
                    spec["inputSchema"].setdefault("required", []).append("target")
            result.append(spec)
        if len(dumps(result).encode()) > 2 * 1024 * 1024:
            raise GatewayError("CATALOG_LIMIT", "授权工具目录过大，请拆分客户端", 503)
        return {"tools": result}

    def prepare(self, client, name, args, request_id, actor):
        with self.store.connect(write=True) as conn:
            if self.audit_failed:
                raise GatewayError("AUDIT_UNAVAILABLE", "审计存储不可用，执行已暂停", 503)
            entries = self.entries(client, conn)
            candidates = entries.get(name, [])
            if not candidates:
                raise GatewayError("TOOL_DENIED", "工具不存在或未授权", 403)
            chosen = candidates[0]
            arguments = copy.deepcopy(args)
            if not self.types[chosen["asset"]["type"]].proxied:
                target = arguments.pop("target", None)
                if target is None and len(candidates) != 1:
                    raise GatewayError("TARGET_REQUIRED", "多个账号可用，必须指定 target")
                if target is not None:
                    chosen = next((c for c in candidates if c["account"]["id"] == target), None)
                    if chosen is None:
                        raise GatewayError("TARGET_DENIED", "target 不存在或未授权", 403)
            validate(chosen["spec"]["inputSchema"], arguments)
            enforce_rules(chosen["grants"], chosen["spec"]["name"], arguments, chosen["spec"]["inputSchema"])
            validate(chosen["spec"]["inputSchema"], arguments)
            snapshot = {
                "asset": chosen["asset"]["name"],
                "account": chosen["account"]["name"],
                "client": client["name"],
                "grant_revision": chosen["grant"]["revision"],
                "grant_groups": [
                    {"id": grant["id"], "name": grant["name"], "revision": grant["revision"]}
                    for grant in chosen["grants"]
                ],
            }
            audit(
                conn,
                "tools.call",
                actor["id"] if actor else client["id"],
                source="ui" if actor else "mcp",
                status="started",
                request_id=request_id,
                client_id=client["id"],
                token_tail=client["token_tail"],
                asset_id=chosen["asset"]["id"],
                account_id=chosen["account"]["id"],
                tool=name,
                snapshot_json=dumps(snapshot),
                detail_json=dumps({"argument_keys": sorted(args), "argument_hash": digest(dumps(args))}),
            )
            return chosen, arguments, self.store.settings(conn)

    def finish(self, request_id, status, started, stats, code=None):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "UPDATE audit_log SET status=?,completed_at=?,elapsed_ms=?,row_count=?,output_bytes=?,truncated=?,error_code=? WHERE request_id=?",
                (
                    status,
                    now(),
                    int((time.monotonic() - started) * 1000),
                    stats.get("row_count"),
                    stats.get("output_bytes"),
                    int(stats.get("truncated", False)),
                    code,
                    request_id,
                ),
            )

    def denied(self, client, name, request_id, actor, code):
        with self.store.connect(write=True) as conn:
            audit(
                conn,
                "tools.call",
                actor["id"] if actor else client["id"],
                source="ui" if actor else "mcp",
                status="denied",
                request_id=request_id,
                client_id=client["id"],
                tool=name,
                error_code=code,
                snapshot_json=dumps({"client": client["name"]}),
            )

    async def call(self, client, name, args, actor=None):
        request_id, started = str(uuid.uuid4()), time.monotonic()
        if self.audit_failed:
            raise GatewayError("AUDIT_UNAVAILABLE", "审计存储不可用，执行已暂停", 503)
        if not isinstance(name, str) or len(name) > 64 or not isinstance(args, dict):
            raise GatewayError("ARGUMENTS", "工具名或参数格式不正确")
        local = self.client_slots.setdefault(client["id"], asyncio.Semaphore(4))
        acquired_global = acquired_local = started_audit = cancelled = False
        ctx, code, status, value, transport_error = None, None, "error", None, None
        self.active_requests.add(request_id)
        try:
            self.rate.check("call:" + client["id"], 120)
            await self.ensure_catalogs(client)
            await asyncio.wait_for(local.acquire(), 2)
            acquired_local = True
            await asyncio.wait_for(self.slots.acquire(), 2)
            acquired_global = True
            chosen, arguments, settings = await self.db(self.prepare, client, name, args, request_id, actor)
            started_audit = True
            ctx = self.context(
                chosen["asset"], chosen["account"], settings, client["compatibility_mode"] == "legacy_mysql"
            )
            self.contexts.append(ctx)
            kind = self.types[chosen["asset"]["type"]]
            if kind.async_mode:
                value = await kind.execute(chosen["spec"]["name"], arguments, ctx, chosen["spec"])
            else:
                value = await self.runner.run(ctx, lambda: kind.execute_sync(chosen["spec"]["name"], arguments, ctx))
            size = len(dumps(value).encode())
            if size > ctx.limits["max_output_bytes"]:
                raise GatewayError("OUTPUT_LIMIT", "工具结果超过输出上限")
            ctx.stats["output_bytes"] = size
            status = "error" if value.get("isError") else "ok"
            code = "UPSTREAM_ERROR" if value.get("isError") else None
        except (TimeoutError, asyncio.CancelledError) as error:
            cancelled = isinstance(error, asyncio.CancelledError)
            status, code = "timeout", "TIMEOUT"
            if ctx:
                ctx.cancel()
            if not started_audit and not cancelled:
                transport_error = GatewayError("BUSY", "执行资源繁忙，尚未执行", 429)
                code = "BUSY"
            value = failed(code, "调用超时或取消；远端状态可能未知，勿自动重试", request_id)
        except GatewayError as error:
            code = error.code
            status = "timeout" if code == "TIMEOUT" else "error"
            if not started_audit and error.status in (401, 429, 503):
                transport_error = error
            value = failed(code, error.message, request_id)
        except sqlite3.Error:
            self.audit_failed = True
            code = "AUDIT_UNAVAILABLE"
            if not started_audit:
                transport_error = GatewayError(code, "审计存储不可用，尚未执行", 503)
            value = failed(code, "审计存储异常；执行状态请由管理员确认", request_id)
        except Exception:
            logger.exception("request_id=%s event=tools.call", request_id)
            code = "ASSET_ERROR"
            value = failed(code, "目标连接或执行失败；请检查配置与远端权限", request_id)
        finally:
            if ctx:
                ctx.cancel()
                if ctx in self.contexts:
                    self.contexts.remove(ctx)
            semaphores = ([self.slots] if acquired_global else []) + ([local] if acquired_local else [])
            self.release_capacity(ctx, *semaphores)
        try:
            try:
                if started_audit:
                    await self.db(self.finish, request_id, status, started, ctx.stats if ctx else {}, code)
                else:
                    await self.db(self.denied, client, name, request_id, actor, code or "BUSY")
            except (sqlite3.Error, GatewayError):
                self.audit_failed = True
                if not started_audit:
                    transport_error = GatewayError("AUDIT_UNAVAILABLE", "审计不可用，尚未执行", 503)
                value = failed("AUDIT_UNCONFIRMED", "执行结果审计未确认，请勿自动重试", request_id)
            logger.info("request_id=%s event=tools.call status=%s", request_id, status)
            if cancelled:
                raise asyncio.CancelledError
            if transport_error:
                raise transport_error
            return value
        finally:
            self.active_requests.discard(request_id)

    async def account_operation(self, identity, actor, discover=False, request_id=None):
        if self.audit_failed:
            raise GatewayError("AUDIT_UNAVAILABLE", "审计存储不可用", 503)
        request_id = request_id or str(uuid.uuid4())
        started = time.monotonic()
        asset, account, settings = await self.db(self.account_snapshot, identity)
        ctx = self.context(asset, account, settings)
        kind = self.types[asset["type"]]

        def begin():
            with self.store.connect(write=True) as conn:
                if (
                    fetch(conn, "accounts", identity)["revision"] != account["revision"]
                    or fetch(conn, "assets", asset["id"])["revision"] != asset["revision"]
                ):
                    raise GatewayError("CONFLICT", "配置已变更，请重试", 409)
                audit(
                    conn,
                    "accounts.refresh" if discover else "accounts.test",
                    actor["id"] if actor else None,
                    source="ui" if actor else "system",
                    status="started",
                    request_id=request_id,
                    asset_id=asset["id"],
                    account_id=identity,
                    snapshot_json=dumps({"asset": asset["name"], "account": account["name"]}),
                )

        try:
            await asyncio.wait_for(self.slots.acquire(), 2)
        except TimeoutError:
            raise GatewayError("BUSY", "执行资源繁忙", 429) from None
        begun = False
        self.active_requests.add(request_id)
        try:
            await self.db(begin)
            begun = True
            self.contexts.append(ctx)
            if discover:
                value = await kind.discover(ctx)
            elif kind.async_mode:
                value = await kind.health(ctx)
            else:
                value = await self.runner.run(ctx, lambda: kind.health_sync(ctx))
            await self.db(self.finish, request_id, "ok", started, {})
            return value, asset, account
        except BaseException as error:
            if isinstance(error, sqlite3.Error) or (isinstance(error, GatewayError) and error.code == "DB_BUSY"):
                self.audit_failed = True
                raise GatewayError("AUDIT_UNAVAILABLE", "审计存储不可用；请核查执行状态", 503) from None
            if begun:
                code = error.code if isinstance(error, GatewayError) else "ASSET_ERROR"
                try:
                    await self.db(self.finish, request_id, "error", started, {}, code)
                except (sqlite3.Error, GatewayError):
                    self.audit_failed = True
            if isinstance(error, (GatewayError, asyncio.CancelledError)):
                raise
            logger.exception("request_id=%s event=%s", request_id, "accounts.refresh" if discover else "accounts.test")
            raise GatewayError("ASSET_ERROR", "连接检测或目录发现失败，请检查目标与权限", 502) from None
        finally:
            ctx.cancel()
            if ctx in self.contexts:
                self.contexts.remove(ctx)
            self.active_requests.discard(request_id)
            self.release_capacity(ctx, self.slots)

    async def refresh(self, identity, actor, force=True, request_id=None):
        lock = self.refresh_locks.setdefault(identity, asyncio.Lock())
        async with lock:
            asset, account, _ = await self.db(self.account_snapshot, identity)
            kind = self.types[asset["type"]]
            if not kind.proxied:
                return kind.catalog(account)
            if not force and account["catalog_refreshed_at"] and now() - account["catalog_refreshed_at"] < 300000:
                return account["tool_catalog"]
            value, asset, account = await self.account_operation(identity, actor, discover=True, request_id=request_id)
            names = [public_name(identity, t["name"]) for t in value]
            if len(names) != len(set(names)):
                raise GatewayError("TOOL_COLLISION", "上游工具发布名称冲突")

            def save():
                with self.store.connect(write=True) as conn:
                    if (
                        fetch(conn, "assets", asset["id"])["revision"] != asset["revision"]
                        or fetch(conn, "accounts", identity)["revision"] != account["revision"]
                    ):
                        raise GatewayError("CONFLICT", "目录刷新期间配置已变化", 409)
                    conn.execute(
                        "UPDATE accounts SET tool_catalog_json=?,catalog_refreshed_at=? WHERE id=?",
                        (dumps(value), now(), identity),
                    )

            await self.db(save)
            return value

    async def test(self, identity, actor, request_id=None):
        self.rate.check("test:" + actor["id"], 20)
        value, asset, account = await self.account_operation(identity, actor, request_id=request_id)
        self.health_cache[identity] = {
            **value,
            "checked_at": now(),
            "revision": account["revision"],
            "asset_revision": asset["revision"],
        }
        return value

    def maintain_db(self, active=()):
        with self.store.connect(write=True) as conn:
            if self.audit_failed:
                audit(conn, "audit.recovered", source="system")
                placeholders = ",".join("?" for _ in active) or "NULL"
                conn.execute(
                    f"UPDATE audit_log SET status='interrupted',completed_at=? WHERE status='started' "
                    f"AND request_id NOT IN ({placeholders})"
                    if active
                    else "UPDATE audit_log SET status='interrupted',completed_at=? WHERE status='started'",
                    (now(), *active),
                )
            cutoff = now() - self.store.settings(conn)["audit_retention_days"] * 86400000
            count = conn.execute(
                "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log WHERE ts<? AND status!='started' LIMIT 1000)",
                (cutoff,),
            ).rowcount
            conn.execute("DELETE FROM admin_sessions WHERE expires_at<? OR revoked_at IS NOT NULL", (now(),))
            if count:
                audit(conn, "audit.retention", source="system", detail_json=dumps({"removed": count}))
        self.audit_failed = False

    async def maintenance(self):
        while True:
            await asyncio.sleep(60)
            try:
                await self.db(self.maintain_db, tuple(self.active_requests))
                await self.db(self.daily_backup)
            except Exception:
                logger.warning("event=maintenance_failed")

    def daily_backup(self):
        today = datetime.datetime.now(datetime.UTC).date()
        folder = self.store.path.parent.parent / "backups"
        for kind, keep in (("daily", 7), ("weekly", 4)):
            if kind == "weekly" and today.weekday() != 0:
                continue
            path = folder / f"gateway-{kind}-{today}.sqlite"
            if not path.exists():
                self.store.backup(path)
            for old in sorted(folder.glob(f"gateway-{kind}-*.sqlite"), reverse=True)[keep:]:
                old.unlink()
