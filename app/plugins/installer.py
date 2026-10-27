"""插件安装器：下载、验签、安全解包、独立环境与无凭据握手预检。

全程任务化：每个阶段把进度写入 plugin_jobs；同版本安装幂等；
暂存目录完成全部校验后原子改名入库，失败即整体丢弃，不影响已有版本。
"""

import asyncio
import hashlib
import io
import json
import shutil
import stat
import zipfile
from pathlib import Path

from app.core.security import GatewayError
from app.plugins.manifest import hydrate_schemas, lint_form_schema, validate_manifest
from app.plugins.process import PluginProcessPool

MAX_ARTIFACT_BYTES = 200 * 1024 * 1024
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
MAX_FILE_COUNT = 2000
MAX_WHEELHOUSE_WHEELS = 200

BUILTIN_IDS = {"mysql", "ssh", "filebrowser", "mcp", "redis", "kubernetes", "gitrepo", "jenkins"}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_offline_artifact(data):
    """预检离线制品：整体哈希 + 提取根级 manifest.json。

    只做轻校验（zip 结构、清单可解析、含 id/version）；解包安全、
    manifest 深度校验与握手预检仍由安装器的正式流程把关。
    """
    digest = hashlib.sha256(data).hexdigest()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            info = next(
                (item for item in bundle.infolist() if item.filename == "manifest.json" and not item.is_dir()), None
            )
            if info is None:
                raise GatewayError("OFFLINE_ARTIFACT", "制品内缺少根级 manifest.json（请上传插件市场原始 zip）", 422)
            if info.file_size > 8 * 1024 * 1024:
                raise GatewayError("OFFLINE_ARTIFACT", "manifest.json 超过大小上限", 422)
            try:
                manifest = json.loads(bundle.read(info).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise GatewayError("OFFLINE_ARTIFACT", f"manifest.json 解析失败：{error}", 422) from error
    except zipfile.BadZipFile as error:
        raise GatewayError("OFFLINE_ARTIFACT", "不是有效的 zip 制品", 422) from error
    if not isinstance(manifest, dict):
        raise GatewayError("OFFLINE_ARTIFACT", "manifest.json 必须是 JSON 对象", 422)
    if not isinstance(manifest.get("id"), str) or not isinstance(manifest.get("version"), str):
        raise GatewayError("OFFLINE_ARTIFACT", "manifest 缺少 id/version 字段", 422)
    return manifest, digest


def safe_unpack(archive, target):
    """受限解包：拒绝绝对路径、穿越、软链与特殊文件；限制数量与总大小。"""
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) > MAX_FILE_COUNT:
            raise GatewayError("UNPACK_LIMIT", "制品文件数量超过上限", 422)
        for info in bundle.infolist():
            parts = Path(info.filename).parts
            if info.filename.startswith("/") or ".." in parts:
                raise GatewayError("UNPACK_UNSAFE", f"制品包含不安全路径：{info.filename}", 422)
            if info.create_system == 3:
                # 只接受常规文件与目录；软链、字符设备等特殊条目一律拒绝。
                # 注意 stat.S_IFMT 在部分版本是函数，这里直接用掩码常量 0o170000。
                filetype = (info.external_attr >> 16) & 0o170000
                if filetype not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise GatewayError("UNPACK_UNSAFE", f"制品包含软链或特殊文件：{info.filename}", 422)
            if not info.filename.endswith("/"):
                total += info.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise GatewayError("UNPACK_LIMIT", "制品解包体积超过上限", 422)
        for info in bundle.infolist():
            if info.filename.endswith("/"):
                continue
            destination = target / info.filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, open(destination, "wb") as sink:
                shutil.copyfileobj(source, sink, 1024 * 1024)


class Installer:
    """执行一次安装任务；由 PluginService 以后台任务方式驱动。"""

    def __init__(self, plugins_root, market, registry, store, python_exe=None):
        self.root = Path(plugins_root)
        self.market = market
        self.registry = registry
        self.store = store
        self.python_exe = python_exe

    async def run(self, job, progress, plugin_id, version, market_version, expect_hash=None, source_bytes=None):
        """安装指定版本。progress(percent, detail) 负责更新任务表。

        source_bytes 提供时为离线安装：制品直接来自管理员上传，跳过市场下载；
        哈希校验、安全解包、独立环境与握手预检等后续流程完全一致。
        """
        expected = expect_hash or market_version.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise GatewayError("MARKET_PROTOCOL", "市场条目缺少有效的制品哈希", 502)
        plugin_root = self.root / plugin_id
        version_dir = plugin_root / version
        if (plugin_root / version / "manifest.json").exists():
            existing = self._installed_hash(plugin_id, version)
            if existing == expected:
                progress(100, "该版本已安装（幂等命中）")
                return json.loads((version_dir / "manifest.json").read_text(encoding="utf-8"))
            raise GatewayError("VERSION_CONFLICT", "同版本号制品与已安装内容不一致，禁止覆盖", 409)
        staging = self.root / ".staging" / f"{plugin_id}-{version}-{job['id']}"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        try:
            return await self._install(
                staging,
                plugin_root,
                version_dir,
                progress,
                plugin_id,
                version,
                market_version,
                expected,
                source_bytes=source_bytes,
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    async def _install(
        self,
        staging,
        plugin_root,
        version_dir,
        progress,
        plugin_id,
        version,
        market_version,
        expected,
        source_bytes=None,
    ):
        archive = staging / "artifact.zip"
        if source_bytes is not None:
            progress(10, "接收离线制品")
            await asyncio.to_thread(archive.write_bytes, source_bytes)
        else:
            progress(10, "下载制品")
            handle = None

            def sink(chunk):
                nonlocal handle
                if handle is None:
                    handle = open(archive, "wb")
                handle.write(chunk)

            try:
                await asyncio.to_thread(self.market.download, market_version.get("artifact"), sink, MAX_ARTIFACT_BYTES)
            finally:
                if handle is not None:
                    handle.close()
        progress(30, "校验制品哈希")
        actual = await asyncio.to_thread(sha256_file, archive)
        if actual != expected:
            raise GatewayError("HASH_MISMATCH", "制品哈希与市场索引不一致，可能被篡改", 422)

        progress(45, "安全解包")
        unpacked = staging / "unpacked"
        await asyncio.to_thread(safe_unpack, archive, unpacked)
        manifest = await self._load_manifest(unpacked, progress)
        lock = (
            (unpacked / "requirements.lock").read_text(encoding="utf-8").strip()
            if (unpacked / "requirements.lock").exists()
            else ""
        )
        wheelhouse = unpacked / "wheelhouse"
        if lock and not wheelhouse.is_dir():
            raise GatewayError("MANIFEST_INVALID", "声明了依赖但制品缺少 wheelhouse 目录", 422)

        progress(60, "准备独立运行环境")
        venv_dir = unpacked / "venv"
        if lock:
            await self._create_venv(venv_dir, with_pip=True)
            await self._pip_install(venv_dir, wheelhouse, unpacked / "requirements.lock")
            python = venv_dir / "bin" / "python"
        else:
            await self._create_venv(venv_dir, with_pip=False)
            python = venv_dir / "bin" / "python"

        progress(75, "写入 SDK")
        sdk_source = Path(__file__).parent / "sdk"
        await asyncio.to_thread(shutil.copytree, sdk_source, unpacked / "sdk" / "mag_plugin")

        progress(85, "无凭据握手预检")
        pool = PluginProcessPool(plugin_id, unpacked, str(python), max_workers=1)
        try:
            descriptor = await pool.start()
        finally:
            await pool.stop()
        self._cross_check(manifest, descriptor)

        progress(95, "提交安装")
        plugin_root.mkdir(parents=True, exist_ok=True)
        version_dir.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(shutil.move, str(unpacked), str(version_dir))
        progress(100, "安装完成（未启用）")
        return manifest

    async def _load_manifest(self, unpacked, progress):
        progress(50, "校验 manifest")
        import json as _json

        path = unpacked / "manifest.json"
        if not path.exists():
            raise GatewayError("MANIFEST_INVALID", "制品缺少 manifest.json", 422)
        try:
            raw = _json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            raise GatewayError("MANIFEST_INVALID", "manifest.json 不是合法 JSON", 422) from None
        raw = hydrate_schemas(raw, lambda relative: (unpacked / relative).read_text(encoding="utf-8"))
        # 占位类型代表"历史类型待恢复"，允许覆盖；实际类型冲突必须拒绝。
        # 占位类型代表"历史类型待恢复"，允许覆盖；同插件升级时自身类型也不算冲突。
        registered = {
            kind.type_id
            for kind in self.registry.values()
            if not getattr(kind, "placeholder", False) and getattr(kind, "plugin_id", None) != raw.get("id")
        }
        manifest = validate_manifest(raw, builtin_ids=BUILTIN_IDS, registered_ids=registered - BUILTIN_IDS)
        for entry in manifest["types"]:
            for key in ("connection", "account", "credential", "policy"):
                schema = entry["schemas"].get(key)
                if key == "policy" and not schema:
                    continue
                if not schema:
                    raise GatewayError("MANIFEST_INVALID", f"类型 {entry['type_id']} 缺少 {key} schema", 422)
                lint_form_schema(schema, f"{entry['type_id']}.{key}")
        return manifest

    async def _create_venv(self, venv_dir, with_pip):
        import sys

        command = [str(self.python_exe or sys.executable), "-m", "venv"]
        if not with_pip:
            command.append("--without-pip")
        command.append(str(venv_dir))
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise GatewayError("VENV_FAILED", f"创建插件虚拟环境失败：{stderr.decode(errors='replace')[:500]}", 502)

    async def _pip_install(self, venv_dir, wheelhouse, lock_path):
        wheels = [p for p in wheelhouse.iterdir() if p.suffix == ".whl"]
        if len(wheels) > MAX_WHEELHOUSE_WHEELS:
            raise GatewayError("UNPACK_LIMIT", "wheelhouse 内 wheel 数量超过上限", 422)
        python = venv_dir / "bin" / "python"
        process = await asyncio.create_subprocess_exec(
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            "--require-hashes",
            "-r",
            str(lock_path),
            "--find-links",
            str(wheelhouse),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise GatewayError("PIP_FAILED", f"插件依赖安装失败：{stderr.decode(errors='replace')[:500]}", 502)

    def _cross_check(self, manifest, descriptor):
        types = {t["type_id"]: t for t in descriptor.get("asset_types", [])}
        for entry in manifest["types"]:
            found = types.get(entry["type_id"])
            if not found:
                raise GatewayError("MANIFEST_INVALID", f"握手缺少类型 {entry['type_id']}", 422)
            if bool(found.get("dynamic_tools")) != bool(entry["dynamic_tools"]):
                raise GatewayError("MANIFEST_INVALID", f"类型 {entry['type_id']} 的动态目录声明与实现不一致", 422)
        if (descriptor.get("plugin") or {}).get("id") != manifest["id"]:
            raise GatewayError("MANIFEST_INVALID", "握手插件身份与 manifest 不一致", 422)

    def _installed_hash(self, plugin_id, version):
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT artifact_hash FROM plugin_versions WHERE plugin_id=? AND version=?", (plugin_id, version)
            ).fetchone()
        return row[0] if row else None
