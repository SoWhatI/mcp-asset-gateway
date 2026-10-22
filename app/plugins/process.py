"""插件工作进程池：启动、通信、超时击杀与退出回收。

每个启用中的插件版本对应一个池；池内 worker 串行处理请求，并发靠多 worker。
worker 崩溃或超时会被击杀并按需重建；击杀后调用方收到错误，不自动重试，
避免写操作在远端状态未知时被重复执行。
"""

import asyncio
import json
import logging
import os
import signal
import time
import uuid
from pathlib import Path

from app.core.security import GatewayError

logger = logging.getLogger("gateway.plugins")

PROTOCOL = 1
MAX_LINE = 16 * 1024 * 1024
MAX_LOG_BYTES = 5 * 1024 * 1024
HANDSHAKE_TIMEOUT = 20


def worker_env(plugin_dir):
    """工作进程环境白名单：主密钥等网关机密一律不进入插件进程。"""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(plugin_dir),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }


class WorkerProcess:
    """单个插件工作进程；同一进程的请求用锁串行，协议为行分隔 JSON-RPC。"""

    def __init__(self, name, python_exe, plugin_dir, log_dir, worker_script):
        self.name = name
        self.python_exe = str(python_exe)
        self.plugin_dir = str(plugin_dir)
        self.log_path = Path(log_dir) / f"worker-{name}.log"
        self.worker_script = str(worker_script)
        self.lock = asyncio.Lock()
        self.proc = None
        self._log = None

    @property
    def alive(self):
        return self.proc is not None and self.proc.returncode is None

    async def start(self):
        if self.alive:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists() and self.log_path.stat().st_size > MAX_LOG_BYTES:
            rotated = self.log_path.with_suffix(".log.1")
            rotated.unlink(missing_ok=True)
            self.log_path.rename(rotated)
        self._log = open(self.log_path, "ab")
        try:
            self.proc = await asyncio.create_subprocess_exec(
                self.python_exe,
                self.worker_script,
                "--plugin-dir",
                self.plugin_dir,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=self._log,
                env=worker_env(self.plugin_dir),
                cwd=self.plugin_dir,
                start_new_session=True,
            )
        except OSError as error:
            self._close_log()
            raise GatewayError("PLUGIN_START_FAILED", f"插件工作进程启动失败：{error}", 502) from None

    async def call(self, method, params, timeout):
        async with self.lock:
            if not self.alive:
                await self.start()
            rid = uuid.uuid4().hex
            line = json.dumps({"id": rid, "method": method, "params": params}, ensure_ascii=False) + "\n"
            try:
                self.proc.stdin.write(line.encode())
                await asyncio.wait_for(self.proc.stdin.drain(), timeout)
                raw = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
            except TimeoutError:
                await self.kill()
                raise GatewayError("TIMEOUT", "插件调用超时；远端状态可能未知，勿自动重试", 504) from None
            except (BrokenPipeError, ConnectionResetError):
                await self.kill()
                raise GatewayError("PLUGIN_CRASHED", "插件工作进程在通信中断开", 502) from None
            if not raw:
                await self.kill()
                raise GatewayError("PLUGIN_CRASHED", "插件工作进程已退出", 502)
            if len(raw) >= MAX_LINE:
                await self.kill()
                raise GatewayError("PLUGIN_RESPONSE_LIMIT", "插件响应超过通信上限", 502)
            try:
                message = json.loads(raw)
            except ValueError:
                await self.kill()
                raise GatewayError("PLUGIN_PROTOCOL", "插件响应不是合法 JSON", 502) from None
            # 错误载荷允许无请求 ID：worker 启动失败时在握手前就会输出错误并退出。
            if "error" in message and message.get("id") in (None, rid):
                error = message["error"] or {}
                raise GatewayError(error.get("code", "PLUGIN_ERROR"), error.get("message", "插件执行失败"), 502)
            if message.get("id") != rid:
                await self.kill()
                raise GatewayError("PLUGIN_PROTOCOL", "插件响应请求 ID 不匹配", 502)
            return message.get("result")

    async def kill(self):
        if self.proc is not None and self.proc.returncode is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                self.proc.kill()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except TimeoutError:
                pass
        self._close_log()

    async def shutdown(self):
        """优雅停机：发送 shutdown 后等待退出；超时则击杀。"""
        if self.proc is not None and self.proc.returncode is None:
            try:
                self.proc.stdin.write(b'{"id":"exit","method":"shutdown","params":{}}\n')
                await self.proc.stdin.drain()
                await asyncio.wait_for(self.proc.wait(), 10)
            except (TimeoutError, BrokenPipeError, ConnectionResetError, OSError):
                await self.kill()
                return
        self._close_log()

    def _close_log(self):
        if self._log is not None:
            try:
                self._log.close()
            except OSError:
                pass
            self._log = None


class PluginProcessPool:
    """一个插件版本的进程池；request() 自动选择空闲 worker 或扩容。"""

    def __init__(self, plugin_id, version_dir, python_exe, max_workers=2, network_rules=None):
        self.plugin_id = plugin_id
        self.version_dir = Path(version_dir)
        self.python_exe = python_exe
        self.max_workers = max(1, min(4, int(max_workers or 2)))
        self.network_rules = network_rules or {"allowlist": [], "enforce": False}
        self.worker_script = str(Path(__file__).parent / "worker.py")
        self.workers = []
        self.closed = False
        self.started_at = None
        self.descriptor = None
        self.stats = {"requests": 0, "errors": 0, "timeouts": 0, "crashes": 0, "spawns": 0}
        self.recent_errors = []

    async def start(self):
        """启动首个 worker 并完成握手；返回 initialize 的插件与类型描述。"""
        worker = await self._spawn()
        result = await self._handshake(worker)
        self.started_at = time.time()
        return result

    async def _spawn(self):
        worker = WorkerProcess(
            f"{len(self.workers)}-{uuid.uuid4().hex[:6]}",
            self.python_exe,
            self.version_dir,
            self.version_dir / "logs",
            self.worker_script,
        )
        await worker.start()
        self.workers.append(worker)
        self.stats["spawns"] += 1
        return worker

    def _pick(self):
        """同步选定 worker：检查与扩容之间没有 await，避免并发请求重复扩容。

        新 worker 只创建对象，真正的进程启动由 WorkerProcess.call 的锁内惰性完成。
        """
        worker = next((w for w in self.workers if w.alive and not w.lock.locked()), None)
        if worker is None and len(self.workers) < self.max_workers:
            worker = WorkerProcess(
                f"{len(self.workers)}-{uuid.uuid4().hex[:6]}",
                self.python_exe,
                self.version_dir,
                self.version_dir / "logs",
                self.worker_script,
            )
            self.workers.append(worker)
            self.stats["spawns"] += 1
        return worker or (self.workers[0] if self.workers else None)

    async def _handshake(self, worker):
        try:
            result = await worker.call(
                "initialize", {"protocol": PROTOCOL, "network": self.network_rules}, HANDSHAKE_TIMEOUT
            )
        except GatewayError:
            await worker.kill()
            self.workers.remove(worker)
            raise
        if not isinstance(result, dict) or result.get("protocol") != PROTOCOL:
            await worker.kill()
            self.workers.remove(worker)
            raise GatewayError("PLUGIN_PROTOCOL", f"插件 {self.plugin_id} 协议版本不兼容", 502)
        if (result.get("plugin") or {}).get("id") != self.plugin_id:
            await worker.kill()
            self.workers.remove(worker)
            raise GatewayError("PLUGIN_MISMATCH", f"插件 {self.plugin_id} 握手身份不匹配", 502)
        self.descriptor = result
        return result

    def _prune(self):
        self.workers = [w for w in self.workers if w.alive or w.lock.locked()]

    async def request(self, method, params, timeout=30):
        if self.closed:
            raise GatewayError("PLUGIN_DISABLED", f"插件 {self.plugin_id} 已停用或正在切换", 503)
        self._prune()
        worker = self._pick()
        if worker is None:
            raise GatewayError("PLUGIN_CRASHED", f"插件 {self.plugin_id} 没有可用工作进程", 502)
        self.stats["requests"] += 1
        try:
            return await worker.call(method, params, timeout)
        except GatewayError as error:
            self.stats["errors"] += 1
            if error.code == "TIMEOUT":
                self.stats["timeouts"] += 1
            if error.code in ("PLUGIN_CRASHED", "PLUGIN_PROTOCOL", "PLUGIN_RESPONSE_LIMIT"):
                self.stats["crashes"] += 1
            self._note_error(error)
            raise

    def _note_error(self, error):
        self.recent_errors.append({"ts": int(time.time() * 1000), "code": error.code, "message": error.message})
        del self.recent_errors[:-20]

    async def drain(self, grace=30):
        """停止接受新请求，等待在途调用结束后回收全部 worker。"""
        self.closed = True
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if not any(w.lock.locked() for w in self.workers):
                break
            await asyncio.sleep(0.2)
        await self.stop()

    async def stop(self):
        self.closed = True
        for worker in self.workers:
            await worker.shutdown()
        self.workers = []

    def runtime(self):
        return {
            "plugin_id": self.plugin_id,
            "workers": [{"name": w.name, "alive": w.alive, "busy": w.lock.locked()} for w in self.workers],
            "max_workers": self.max_workers,
            "started_at": self.started_at,
            "stats": dict(self.stats),
            "recent_errors": list(self.recent_errors),
        }
