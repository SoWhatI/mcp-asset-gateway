"""插件生命周期服务：安装任务、启停、升级切换、回滚、卸载与运行状态。

关键不变量：
- 插件深度校验（IPC）一律在写事务之外执行；切换用短事务 + revision 提交校验。
- 授权绑定代码版本：注册表携带 artifact_hash，保存授权组时写入 grants.code_versions；
  升级/回滚后哈希变化，未重新确认的工具在 Gateway.entries 被跳过。
- 市场不可达或插件文件缺失不影响网关与其余类型。
"""

import asyncio
import logging
import shutil
import sys
import uuid
from pathlib import Path

from app.asset_types.placeholder import PlaceholderAssetType
from app.core.db import decode, dumps, now
from app.core.manager import audit
from app.core.manager import fetch as manager_fetch
from app.core.security import GatewayError
from app.plugins.bridge import PluginAssetType
from app.plugins.installer import Installer
from app.plugins.process import PluginProcessPool

logger = logging.getLogger("gateway.plugins")

DRAIN_GRACE_SECONDS = 30


class PluginService:
    def __init__(self, store, registry, db, plugins_root, market, network_rules, vault=None, python_exe=None):
        self.store = store
        self.registry = registry
        self.db = db
        self.root = Path(plugins_root)
        self.market = market
        self.network_rules = network_rules
        self.vault = vault
        self.python_exe = python_exe or sys.executable
        self.installer = Installer(self.root, market, registry, store, self.python_exe)
        # 每个插件同时只有一个活跃进程池（当前版本）；键为 plugin_id。
        self.pools = {}
        self.jobs = {}

    # ---------- 启动与停机 ----------

    async def start(self):
        """恢复期望启用的插件；单个失败只影响该插件（保留占位类型继续服务其余类型）。"""
        for row in await self.db(self._enabled_rows):
            try:
                await self._activate(row, actor=None)
            except Exception as error:
                code = error.code if isinstance(error, GatewayError) else type(error).__name__
                logger.warning("event=plugin_recover_failed plugin=%s code=%s", row["plugin_id"], code)

    async def stop(self):
        for task in list(self.jobs.values()):
            task.cancel()
        await asyncio.gather(*list(self.jobs.values()), return_exceptions=True)
        for pool in list(self.pools.values()):
            await pool.stop()
        self.pools.clear()

    def _enabled_rows(self):
        with self.store.connect() as conn:
            return [
                decode(row)
                for row in conn.execute(
                    "SELECT p.id AS plugin_id, p.revision AS plugin_revision, v.* FROM plugins p "
                    "JOIN plugin_versions v ON v.id=p.current_version_id WHERE p.expected_state='enabled'"
                )
            ]

    # ---------- 查询 ----------

    def listing(self):
        with self.store.connect() as conn:
            plugins = [decode(row) for row in conn.execute("SELECT * FROM plugins ORDER BY created_at DESC")]
            versions = {}
            for row in conn.execute("SELECT * FROM plugin_versions ORDER BY installed_at DESC"):
                versions.setdefault(row["plugin_id"], []).append(decode(row))
            counts = dict(
                conn.execute(
                    "SELECT a.plugin_id, count(*) FROM asset_types a JOIN assets s ON s.type=a.type_id "
                    "GROUP BY a.plugin_id"
                )
            )
        items = []
        for plugin in plugins:
            versions_of = versions.get(plugin["id"], [])
            current = next((v for v in versions_of if v["id"] == plugin.get("current_version_id")), None)
            # 尚未启用过（current_version_id 为空）时按最近安装的版本展示，与启用路径一致。
            if current is None and versions_of:
                current = versions_of[0]
            pool = self.pools.get(plugin["id"])
            items.append(
                {
                    "id": plugin["id"],
                    "publisher": plugin["publisher"],
                    "description": plugin["description"],
                    "expected_state": plugin["expected_state"],
                    "running": bool(pool and not pool.closed),
                    "current_version": current and current["version"],
                    "current_version_id": current and current["id"],
                    "artifact_hash": current and current["artifact_hash"],
                    "files_present": bool(current and Path(current["path"], "manifest.json").exists()),
                    "asset_count": counts.get(plugin["id"], 0),
                    "versions": [
                        {
                            "id": v["id"],
                            "version": v["version"],
                            "status": v["status"],
                            "artifact_hash": v["artifact_hash"],
                            "installed_at": v["installed_at"],
                            "files_present": Path(v["path"], "manifest.json").exists(),
                        }
                        for v in versions_of
                    ],
                }
            )
        return items

    def detail(self, plugin_id):
        found = next((item for item in self.listing() if item["id"] == plugin_id), None)
        if not found:
            raise GatewayError("NOT_FOUND", "插件不存在", 404)
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT v.manifest_json FROM plugins p JOIN plugin_versions v ON v.id=p.current_version_id "
                "WHERE p.id=?",
                (plugin_id,),
            ).fetchone()
        manifest = decode(row)["manifest"] if row else None
        if manifest:
            found["manifest"] = {
                "name": manifest.get("name"),
                "capabilities": manifest.get("capabilities", {}),
                "types": [
                    {
                        "type_id": t["type_id"],
                        "display_name": t["display_name"],
                        "icon": t["icon"],
                        "dynamic_tools": t.get("dynamic_tools", False),
                        "tools": [tool["name"] for tool in t.get("tools", [])],
                    }
                    for t in manifest.get("types", [])
                ],
            }
        return found

    def runtime(self, plugin_id):
        pool = self.pools.get(plugin_id)
        if not pool:
            raise GatewayError("NOT_FOUND", "插件不存在或未启用", 404)
        return {"plugin_id": plugin_id, "running": not pool.closed, "pool": pool.runtime()}

    def jobs_listing(self, limit=50):
        with self.store.connect() as conn:
            return [
                decode(row)
                for row in conn.execute(
                    "SELECT * FROM plugin_jobs ORDER BY created_at DESC LIMIT ?", (max(1, min(100, limit)),)
                )
            ]

    def job(self, job_id):
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM plugin_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise GatewayError("NOT_FOUND", "安装任务不存在", 404)
        return decode(row)

    # ---------- 安装与升级任务 ----------

    async def install(self, plugin_id, version, actor, confirm_hash=None, action="install"):
        """从市场安装指定版本；action=upgrade 时安装成功后自动切换当前版本。"""
        entry = self._market_version(plugin_id, version)
        if confirm_hash and confirm_hash != entry.get("sha256"):
            raise GatewayError("HASH_CONFIRM", "确认哈希与市场条目不一致，请刷新后重试", 409)
        job = {
            "id": str(uuid.uuid4()),
            "plugin_id": plugin_id,
            "version": version,
            "action": action,
            "status": "pending",
            "progress": 0,
            "detail_json": dumps({"sha256": entry.get("sha256"), "size": entry.get("size")}),
            "error_json": None,
            "actor_id": actor["id"] if actor else None,
        }
        await self.db(self._insert_job, job)
        self.jobs[job["id"]] = asyncio.create_task(self._run_install_job(job, entry))
        return job

    def _market_version(self, plugin_id, version):
        if not self.market.configured:
            raise GatewayError("MARKET_UNCONFIGURED", "未配置插件市场来源或公钥", 503)
        # 安装属低频管理操作：每次重新拉取并验签索引，避免使用过期缓存版本。
        for plugin in self.market.index(refresh=True).get("plugins", []):
            if plugin.get("id") != plugin_id:
                continue
            for entry in plugin.get("versions", []):
                if entry.get("version") == version:
                    return entry
        raise GatewayError("NOT_FOUND", "市场不存在该插件版本", 404)

    async def _run_install_job(self, job, entry):
        def progress(percent, detail):
            try:
                asyncio.get_running_loop().create_task(self.db(self._update_job_progress, job["id"], int(percent)))
            except RuntimeError:
                pass

        try:
            await self.db(self._mark_job, job["id"], "running", 1)
            manifest = await self.installer.run(
                job, progress, job["plugin_id"], job["version"], entry, expect_hash=entry.get("sha256")
            )
            await self.db(
                self._record_installed,
                job,
                manifest,
                entry.get("sha256"),
                self.root / job["plugin_id"] / job["version"],
            )
            if job["action"] == "upgrade" and await self.db(self._expected_state, job["plugin_id"]) == "enabled":
                await self._switch(job["plugin_id"], job["version"], actor=None, action="upgrade")
            await self.db(self._mark_job, job["id"], "done", 100)
            logger.info(
                "event=plugin_job_done plugin=%s version=%s action=%s", job["plugin_id"], job["version"], job["action"]
            )
        except GatewayError as error:
            await self.db(self._fail_job, job["id"], error.code, error.message)
        except asyncio.CancelledError:
            await self.db(self._fail_job, job["id"], "CANCELLED", "任务被取消")
            raise
        except Exception as error:
            logger.exception("event=plugin_job_failed plugin=%s", job["plugin_id"])
            await self.db(self._fail_job, job["id"], "INSTALL_ERROR", f"安装失败：{error}")
        finally:
            self.jobs.pop(job["id"], None)

    def _insert_job(self, job):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO plugin_jobs(id,plugin_id,version,action,status,progress,detail_json,error_json,"
                "actor_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job["id"],
                    job["plugin_id"],
                    job["version"],
                    job["action"],
                    job["status"],
                    job["progress"],
                    job["detail_json"],
                    job["error_json"],
                    job["actor_id"],
                    now(),
                    now(),
                ),
            )

    def _mark_job(self, job_id, status, progress):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "UPDATE plugin_jobs SET status=?,progress=?,updated_at=? WHERE id=?", (status, progress, now(), job_id)
            )

    def _update_job_progress(self, job_id, progress):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "UPDATE plugin_jobs SET progress=?,updated_at=? WHERE id=? AND status='running'",
                (progress, now(), job_id),
            )

    def _fail_job(self, job_id, code, message):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "UPDATE plugin_jobs SET status='failed',error_json=?,updated_at=? WHERE id=?",
                (dumps({"code": code, "message": message}), now(), job_id),
            )

    def _record_installed(self, job, manifest, artifact_hash, version_dir):
        with self.store.connect(write=True) as conn:
            conn.execute(
                "INSERT INTO plugins(id,publisher,description,expected_state,current_version_id,revision,"
                "created_at,updated_at) VALUES(?,?,?,'disabled',NULL,1,?,?) ON CONFLICT(id) DO NOTHING",
                (manifest["id"], manifest["publisher"], manifest.get("description", ""), now(), now()),
            )
            existing = conn.execute(
                "SELECT id FROM plugin_versions WHERE plugin_id=? AND version=?", (job["plugin_id"], job["version"])
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE plugin_versions SET artifact_hash=?,path=?,manifest_json=?,status='installed',"
                    "installed_at=? WHERE id=?",
                    (artifact_hash, str(version_dir), dumps(manifest), now(), existing["id"]),
                )
                version_row_id = existing["id"]
            else:
                version_row_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO plugin_versions(id,plugin_id,version,artifact_hash,path,manifest_json,"
                    "sdk_protocol,status,installed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        version_row_id,
                        job["plugin_id"],
                        job["version"],
                        artifact_hash,
                        str(version_dir),
                        dumps(manifest),
                        manifest.get("sdk_protocol", 1),
                        "installed",
                        now(),
                        now(),
                    ),
                )
            audit(
                conn,
                f"plugins.{job['action']}",
                job["actor_id"],
                detail_json=dumps({"plugin": job["plugin_id"], "version": job["version"]}),
            )
            return version_row_id

    # ---------- 启停 ----------

    async def enable(self, plugin_id, actor):
        row = await self.db(self._installable_row, plugin_id)
        if not row:
            raise GatewayError("NOT_FOUND", "插件不存在或尚未安装版本", 404)
        await self._activate(row, actor=actor)
        return {"id": plugin_id, "expected_state": "enabled"}

    async def disable(self, plugin_id, actor):
        row = await self.db(self._installable_row, plugin_id)
        if not row:
            raise GatewayError("NOT_FOUND", "插件不存在", 404)
        pool = self.pools.pop(plugin_id, None)
        if pool:
            await pool.drain(DRAIN_GRACE_SECONDS)
        for entry in row["manifest"]["types"]:
            self.registry.unregister(entry["type_id"])
            await self._restore_placeholder(entry["type_id"])
        await self.db(self._mark_disabled, row, actor)
        return {"id": plugin_id, "expected_state": "disabled"}

    def _installable_row(self, plugin_id):
        """当前版本行；无 current 时取最近安装的版本（首次启用）。"""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT p.id AS plugin_id, p.revision AS plugin_revision, v.* FROM plugins p "
                "JOIN plugin_versions v ON v.id=p.current_version_id WHERE p.id=?",
                (plugin_id,),
            ).fetchone()
            if not row:
                row = conn.execute(
                    "SELECT p.id AS plugin_id, p.revision AS plugin_revision, v.* FROM plugins p "
                    "JOIN plugin_versions v ON v.plugin_id=p.id WHERE p.id=? ORDER BY v.installed_at DESC LIMIT 1",
                    (plugin_id,),
                ).fetchone()
        return decode(row) if row else None

    async def _activate(self, row, actor):
        """启用指定版本：起进程池、握手、注册类型、写状态；失败回滚不留半启用状态。"""
        version_dir = Path(row["path"])
        manifest = row["manifest"]
        if not (version_dir / "manifest.json").exists():
            raise GatewayError("PLUGIN_MISSING", f"插件文件缺失：{version_dir}", 503)
        pool = PluginProcessPool(
            row["plugin_id"],
            version_dir,
            self._python_of(version_dir),
            max_workers=manifest.get("workers", 2),
            network_rules=self.network_rules(),
        )
        registered = []
        displaced = []
        try:
            descriptor = await pool.start()
            described = {t["type_id"]: t for t in descriptor.get("asset_types", [])}
            for entry in manifest["types"]:
                found = described.get(entry["type_id"])
                if not found:
                    raise GatewayError("MANIFEST_INVALID", f"握手缺少类型 {entry['type_id']}", 422)
                # 同插件旧版本类型先注销（升级切换）；其他插件的类型（含占位）必须拒绝。
                existing = self.registry.get(entry["type_id"])
                source = self.registry.source(entry["type_id"]) or {}
                if existing is not None:
                    if getattr(existing, "placeholder", False):
                        if existing.plugin_id != row["plugin_id"]:
                            raise GatewayError("TYPE_CONFLICT", f"类型 {entry['type_id']} 已属于其他插件", 409)
                        displaced.append((entry["type_id"], existing))
                        self.registry.unregister(entry["type_id"])
                    elif source.get("plugin_id") == row["plugin_id"]:
                        displaced.append((entry["type_id"], existing))
                        self.registry.unregister(entry["type_id"])
                    else:
                        raise GatewayError("TYPE_CONFLICT", f"类型 {entry['type_id']} 已属于其他插件", 409)
                kind = PluginAssetType(
                    {
                        **{k: entry.get(k) for k in ("type_id", "display_name", "icon", "default_port")},
                        **{
                            k: entry["schemas"].get(k[:-7])
                            for k in ("connection_schema", "account_schema", "credential_schema", "policy_schema")
                        },
                        "connection_mode": entry.get("connection_mode"),
                        "dynamic_tools": entry.get("dynamic_tools"),
                        "tools": entry.get("tools") or [],
                    },
                    pool,
                    row["plugin_id"],
                    row["id"],
                    row["artifact_hash"],
                )
                self.registry.register(
                    kind,
                    plugin_id=row["plugin_id"],
                    version_id=row["id"],
                    artifact_hash=row["artifact_hash"],
                    replace_placeholder=True,
                )
                registered.append(kind.type_id)
        except BaseException:
            await pool.stop()
            for type_id in registered:
                await self._restore_placeholder(type_id)
            # 恢复被切换挤出的旧类型（升级失败回到原版本继续服务）。
            for _, kind in reversed(displaced):
                self.registry.register(
                    kind,
                    plugin_id=kind.plugin_id,
                    version_id=kind.version_id,
                    artifact_hash=kind.artifact_hash,
                )
            raise
        old_pool = self.pools.get(row["plugin_id"])
        self.pools[row["plugin_id"]] = pool
        await self.db(self._mark_enabled, row, actor)
        if old_pool is not None and old_pool is not pool:
            await old_pool.drain(DRAIN_GRACE_SECONDS)

    def _python_of(self, version_dir):
        venv_python = version_dir / "venv" / "bin" / "python"
        return str(venv_python if venv_python.exists() else self.python_exe)

    def _mark_enabled(self, row, actor):
        with self.store.connect(write=True) as conn:
            current = conn.execute("SELECT revision FROM plugins WHERE id=?", (row["plugin_id"],)).fetchone()
            if not current or current["revision"] != row["plugin_revision"]:
                raise GatewayError("CONFLICT", "插件记录已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE plugins SET expected_state='enabled',current_version_id=?,revision=revision+1,updated_at=? "
                "WHERE id=?",
                (row["id"], now(), row["plugin_id"]),
            )
            conn.execute(
                "UPDATE plugin_versions SET status='retired' WHERE plugin_id=? AND id!=? AND status='active'",
                (row["plugin_id"], row["id"]),
            )
            conn.execute("UPDATE plugin_versions SET status='active' WHERE id=?", (row["id"],))
            for entry in row["manifest"]["types"]:
                conn.execute(
                    "INSERT INTO asset_types(type_id,plugin_id,display_name,icon,schemas_json,capabilities_json,"
                    "source,available,artifact_hash,revision,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,'plugin',1,?,1,?,?) "
                    "ON CONFLICT(type_id) DO UPDATE SET display_name=excluded.display_name,icon=excluded.icon,"
                    "schemas_json=excluded.schemas_json,capabilities_json=excluded.capabilities_json,available=1,"
                    "artifact_hash=excluded.artifact_hash,updated_at=excluded.updated_at",
                    (
                        entry["type_id"],
                        row["plugin_id"],
                        entry["display_name"],
                        entry.get("icon", "Connection"),
                        dumps(entry.get("schemas", {})),
                        dumps({"dynamic_tools": bool(entry.get("dynamic_tools"))}),
                        row["artifact_hash"],
                        now(),
                        now(),
                    ),
                )
            if actor:
                audit(
                    conn,
                    "plugins.enable",
                    actor["id"],
                    detail_json=dumps({"plugin": row["plugin_id"], "version": row["version"]}),
                )

    def _mark_disabled(self, row, actor):
        with self.store.connect(write=True) as conn:
            current = conn.execute("SELECT revision FROM plugins WHERE id=?", (row["plugin_id"],)).fetchone()
            if not current or current["revision"] != row["plugin_revision"]:
                raise GatewayError("CONFLICT", "插件记录已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE plugins SET expected_state='disabled',revision=revision+1,updated_at=? WHERE id=?",
                (now(), row["plugin_id"]),
            )
            conn.execute(
                "UPDATE plugin_versions SET status='installed' WHERE plugin_id=? AND status='active'",
                (row["plugin_id"],),
            )
            conn.execute("UPDATE asset_types SET available=0,updated_at=? WHERE plugin_id=?", (now(), row["plugin_id"]))
            if actor:
                audit(conn, "plugins.disable", actor["id"], detail_json=dumps({"plugin": row["plugin_id"]}))

    async def _restore_placeholder(self, type_id):
        def snapshot():
            with self.store.connect() as conn:
                row = conn.execute("SELECT * FROM asset_types WHERE type_id=?", (type_id,)).fetchone()
                return decode(row) if row else None

        row = await self.db(snapshot)
        if row:
            self.registry.register(PlaceholderAssetType(type_id, row["display_name"], row["schemas"], row["plugin_id"]))

    # ---------- 升级 / 回滚切换 ----------

    async def switch(self, plugin_id, version, actor):
        """切换当前版本（升级到已安装版本或回滚到保留版本）。"""
        return await self._switch(plugin_id, version, actor=actor, action="rollback")

    async def _switch(self, plugin_id, version, actor, action):
        target = await self.db(self._version_row, plugin_id, version)
        if not target:
            raise GatewayError("NOT_FOUND", f"版本 {version} 尚未安装", 404)
        if not Path(target["path"], "manifest.json").exists():
            raise GatewayError("PLUGIN_MISSING", "目标版本文件缺失，请重新安装", 503)
        current = await self.db(self._installable_row, plugin_id)
        if current and current["id"] == target["id"]:
            raise GatewayError("NOOP", "该版本已是当前版本", 409)
        if await self.db(self._expected_state, plugin_id) == "enabled":
            await self._precheck_accounts(target)
        row = await self.db(self._switch_version, target, actor, action)
        if await self.db(self._expected_state, plugin_id) == "enabled":
            await self._activate(row, actor=actor)
        return {"id": plugin_id, "version": version, "action": action}

    def _expected_state(self, plugin_id):
        with self.store.connect() as conn:
            row = conn.execute("SELECT expected_state FROM plugins WHERE id=?", (plugin_id,)).fetchone()
        return row["expected_state"] if row else None

    def _version_row(self, plugin_id, version):
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT p.id AS plugin_id, p.revision AS plugin_revision, v.* FROM plugins p "
                "JOIN plugin_versions v ON v.plugin_id=p.id WHERE p.id=? AND v.version=?",
                (plugin_id, version),
            ).fetchone()
        return decode(row) if row else None

    def _switch_version(self, target, actor, action):
        with self.store.connect(write=True) as conn:
            current = conn.execute("SELECT revision FROM plugins WHERE id=?", (target["plugin_id"],)).fetchone()
            if not current or current["revision"] != target["plugin_revision"]:
                raise GatewayError("CONFLICT", "插件记录已变化，请刷新后重试", 409)
            conn.execute(
                "UPDATE plugins SET current_version_id=?,revision=revision+1,updated_at=? WHERE id=?",
                (target["id"], now(), target["plugin_id"]),
            )
            conn.execute(
                "UPDATE plugin_versions SET status='retired' WHERE plugin_id=? AND status='active'",
                (target["plugin_id"],),
            )
            conn.execute("UPDATE plugin_versions SET status='active' WHERE id=?", (target["id"],))
            audit(
                conn,
                f"plugins.{action}",
                actor["id"] if actor else None,
                detail_json=dumps({"plugin": target["plugin_id"], "version": target["version"]}),
            )
            row = conn.execute(
                "SELECT p.id AS plugin_id, p.revision AS plugin_revision, v.* FROM plugins p "
                "JOIN plugin_versions v ON v.id=p.current_version_id WHERE p.id=?",
                (target["plugin_id"],),
            ).fetchone()
            return decode(row)

    async def _precheck_accounts(self, target):
        """对既有账号逐个 validate_config（事务外、无写操作）；失败则中止切换。"""
        type_ids = [entry["type_id"] for entry in target["manifest"]["types"]]
        accounts = await self.db(self._accounts_of_types, type_ids)
        if not accounts:
            return
        version_dir = Path(target["path"])
        pool = PluginProcessPool(
            target["plugin_id"],
            version_dir,
            self._python_of(version_dir),
            max_workers=1,
            network_rules=self.network_rules(),
        )
        try:
            await pool.start()
            for item in accounts:
                await pool.request("validate_config", {**item, "remaining_ms": 15000}, 20)
        finally:
            await pool.stop()

    def _accounts_of_types(self, type_ids):
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT s.type AS asset_type, a.id AS account_id FROM accounts a JOIN assets s ON a.asset_id=s.id "
                f"WHERE s.type IN ({','.join('?' for _ in type_ids)})",
                tuple(type_ids),
            ).fetchall()
            result = []
            for row in rows:
                account = manager_fetch(conn, "accounts", row["account_id"])
                asset = manager_fetch(conn, "assets", account["asset_id"])
                result.append(
                    {
                        "type_id": row["asset_type"],
                        "connection": asset.get("connection") or {},
                        "account": account.get("config") or {},
                        "policy": account.get("policy") or {},
                        "credential": (
                            self.vault.decrypt(account["credential_ciphertext"], account["credential_key_id"])
                            if account.get("credential_ciphertext") and self.vault
                            else {}
                        ),
                    }
                )
            return result

    # ---------- 卸载 ----------

    async def uninstall(self, plugin_id, actor):
        current = await self.db(self._installable_row, plugin_id)
        if not current:
            raise GatewayError("NOT_FOUND", "插件不存在", 404)
        await self.db(self._assert_no_assets, plugin_id)
        pool = self.pools.pop(plugin_id, None)
        if pool:
            await pool.stop()
        # 类型随插件删除：不注册占位（asset_types 行一并移除）。
        for entry in current["manifest"]["types"]:
            self.registry.unregister(entry["type_id"])
        await self.db(self._delete_plugin, plugin_id, actor)
        shutil.rmtree(self.root / plugin_id, ignore_errors=True)
        return {"id": plugin_id, "removed": True}

    def _assert_no_assets(self, plugin_id):
        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT count(*) FROM assets s JOIN asset_types t ON s.type=t.type_id WHERE t.plugin_id=?",
                (plugin_id,),
            ).fetchone()[0]
        if count:
            raise GatewayError("PLUGIN_IN_USE", f"仍有 {count} 个资产使用该插件，请先删除或迁移关联资产", 409)

    def _delete_plugin(self, plugin_id, actor):
        with self.store.connect(write=True) as conn:
            conn.execute("DELETE FROM plugin_jobs WHERE plugin_id=? AND status IN ('done','failed')", (plugin_id,))
            conn.execute("DELETE FROM plugin_versions WHERE plugin_id=?", (plugin_id,))
            conn.execute("DELETE FROM asset_types WHERE plugin_id=?", (plugin_id,))
            conn.execute("DELETE FROM plugins WHERE id=?", (plugin_id,))
            audit(conn, "plugins.uninstall", actor["id"] if actor else None, detail_json=dumps({"plugin": plugin_id}))
