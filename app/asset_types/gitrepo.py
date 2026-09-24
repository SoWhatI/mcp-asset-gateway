"""Git 代码仓库资产类型：网关托管只读代码副本，提供只读代码检索工具。

参考 code-search-server 的工具设计（search_code/read_file/git_log/git_diff/list_tree/list_branches），
副本维护在 {data_dir}/repos/{account_id}（单分支克隆，与开发工作区完全隔离）：
- 首次调用时后台克隆（前台短暂等待，未完成提示稍后重试，克隆与请求生命周期解耦）；
- 此后按 refresh_interval_seconds 过期触发后台 fetch + reset --hard 更新，本次调用继续用现有副本。

安全设计：
- SSH 私钥使用每次操作独立的 0700 临时目录与 0600 文件，准备失败和操作完成均清理；
- HTTP(S) 每次联网校验来源/DNS 并固定 IP，保留 Host/SNI、强制 TLS 校验并禁止重定向；
  令牌仅通过隔离环境提供给内联 credential helper，不落盘或进入命令参数；
- SSH 主机密钥经 paramiko 校验（受 SSH_HOST_KEY_ENFORCE 开关控制）后写入临时 known_hosts，
  并把连接固定到出站策略解析出的 IP；
- 路径参数统一做仓库内相对路径归一化与 realpath 越界校验，不跟随越界软链接；
- 子进程统一超时控制与输出上限（超限即终止），git 参数经格式白名单校验并用 "--" 分隔。
"""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import posixpath
import re
import select
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import paramiko

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool, upload_text
from app.core.security import GatewayError, equal

logger = logging.getLogger("gateway")

OUT_MAX_BYTES = 1048576  # 子进程 stdout 读取上限
ERR_MAX_BYTES = 65536  # 子进程 stderr 读取上限
SEARCH_CAP = 1048576  # 搜索原始输出上限
DIFF_CAP = 262144  # git_diff 输出上限
LOG_CAP = 524288  # git_log/list_branches 输出上限
MAX_TEXT_LINE = 500  # 单行搜索结果字符上限
TREE_MAX_LINES = 800  # 目录树输出行上限
BRANCH_MAX = 300  # 分支列表上限
GIT_TIMEOUT_CAP = 20  # 单次检索子进程超时上限（秒）
CLONE_WAIT_SECONDS = 8  # 前台等待克隆完成的窗口（秒）
FAIL_RETRY_MS = 60000  # 同步失败后的自动重试间隔
DEFAULT_BRANCH = "master"
DEFAULT_REFRESH = 3600  # 副本自动更新间隔（秒）
DEFAULT_SYNC_TIMEOUT = 600  # 克隆/拉取超时（秒）
DEFAULT_MAX_REPO_MB = 2048  # 副本大小上限（MB）
BASE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin"
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$")
SCP_RE = re.compile(r"(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9][A-Za-z0-9.-]*):(/?.{1,})")
RG_BIN = shutil.which("rg")


def now_ms():
    return int(time.time() * 1000)


def parse_repo_url(value):
    """解析仓库地址为 {scheme,user,host,port,path}；支持 scp-like 与标准 URL。"""
    if not isinstance(value, str) or not value or len(value) > 512 or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise GatewayError("REPO_URL_INVALID", "仓库地址格式不合法")
    if "://" not in value:
        match = SCP_RE.fullmatch(value)
        if not match:
            raise GatewayError(
                "REPO_URL_INVALID", "仓库地址需形如 git@host:group/repo.git 或 https://host/group/repo.git"
            )
        path = match.group(3)
        if re.match(r"^\d", path.lstrip("/")):
            raise GatewayError("REPO_URL_INVALID", "scp 语法不支持端口；请使用 ssh://user@host:port/path 形式")
        return {"scheme": "ssh", "user": match.group(1) or "git", "host": match.group(2), "port": 22, "path": path}
    try:
        parsed = urlsplit(value)
        host, port, user = parsed.hostname, parsed.port, parsed.username
    except ValueError:
        raise GatewayError("REPO_URL_INVALID", "仓库地址的主机或端口格式不合法") from None
    if parsed.scheme not in ("ssh", "https", "http"):
        raise GatewayError("REPO_URL_INVALID", "仅支持 ssh://、https:// 或 http:// 仓库地址")
    if (
        not host
        or port == 0
        or parsed.password is not None
        or (parsed.scheme != "ssh" and user is not None)
        or (user is not None and not re.fullmatch(r"[A-Za-z0-9._-]+", user))
        or parsed.query
        or parsed.fragment
    ):
        raise GatewayError("REPO_URL_INVALID", "仓库地址不合法；凭据请配置在账号中，而不是地址内")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
            raise GatewayError("REPO_URL_INVALID", "仓库主机名格式不合法") from None
    if not parsed.path or parsed.path == "/":
        raise GatewayError("REPO_URL_INVALID", "仓库地址缺少仓库路径")
    default_port = {"ssh": 22, "https": 443, "http": 80}[parsed.scheme]
    return {
        "scheme": parsed.scheme,
        "user": user or ("git" if parsed.scheme == "ssh" else ""),
        "host": host,
        "port": port or default_port,
        "path": parsed.path,
    }


def safe_rel(repo, value):
    """把用户传入的路径归一化为仓库内相对路径；越界或非法时拒绝。"""
    value = (value or "").strip()
    if not value:
        return "."
    if value.startswith("/") or value.startswith("-") or "\0" in value or "\\" in value:
        raise GatewayError("PATH_DENIED", "仅允许仓库内的相对路径", 403)
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../") or "/../" in normalized:
        raise GatewayError("PATH_DENIED", "路径超出仓库范围", 403)
    full = os.path.realpath(os.path.join(repo, normalized))
    if full != repo and not full.startswith(repo + os.sep):
        raise GatewayError("PATH_DENIED", "路径超出仓库范围", 403)
    return normalized


def is_repo(path):
    return os.path.isfile(os.path.join(path, ".git", "HEAD"))


def directory_size_mb(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total // (1024 * 1024)


def read_state(path):
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(path, value):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temp = f"{path}.tmp.{os.getpid()}"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(value, handle)
        os.replace(temp, path)
    except OSError:
        pass


def base_env(work_dir):
    """git 子进程环境：隔离全局配置、禁止交互提示、稳定输出编码。"""
    return {
        "PATH": BASE_PATH,
        "HOME": str(work_dir),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CEILING_DIRECTORIES": str(Path(work_dir).resolve().parent),
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C.UTF-8",
    }


def run_capped(args, cwd, env, timeout, cap):
    """执行子进程：stdout 至多读取 cap 字节（超限即终止进程），stderr 至多 ERR_MAX_BYTES。

    返回 (stdout, stderr, truncated, returncode)；超时抛出 GIT_TIMEOUT。
    """
    try:
        process = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise GatewayError("GIT_UNAVAILABLE", f"无法执行 {args[0]}：{error}", 503) from None
    out, err, truncated = bytearray(), bytearray(), False
    deadline = time.monotonic() + timeout
    streams = {process.stdout: (out, cap), process.stderr: (err, ERR_MAX_BYTES)}
    try:
        while streams:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise GatewayError("GIT_TIMEOUT", "命令执行超时", 504)
            ready, _, _ = select.select(list(streams), [], [], min(budget, 0.5))
            for stream in ready:
                chunk = stream.read1(65536)
                if not chunk:
                    stream.close()
                    streams.pop(stream, None)
                    continue
                target, limit = streams[stream]
                room = limit - len(target)
                if room > 0:
                    target += chunk[:room]
                if len(chunk) > room and stream is process.stdout:
                    # stdout 已到上限：后续内容不需要，终止进程以避免无界读取。
                    truncated = True
                    process.kill()
        process.wait(timeout=5)
    except GatewayError:
        process.kill()
        process.wait()
        raise
    return bytes(out), bytes(err), truncated, process.returncode


def classify_git_error(message):
    """按 stderr 摘要归类同步失败，便于前端与审计提示。"""
    lowered = message.lower()
    auth_hints = (
        "authentication failed",
        "permission denied",
        "could not read username",
        "access denied",
        "invalid username or password",
        "no such identity",
        "host key verification failed",
    )
    network_hints = (
        "could not resolve host",
        "connection refused",
        "connection timed out",
        "network is unreachable",
        "connection closed",
        "connection reset",
        "unable to connect",
        "timed out",
        "no route to host",
    )
    if any(hint in lowered for hint in auth_hints):
        return "GIT_AUTH_FAILED"
    if any(hint in lowered for hint in network_hints):
        return "GIT_UNREACHABLE"
    return "GIT_SYNC_FAILED"


def git_connection_schema(enforce=True):
    fingerprint = text(
        "SSH 主机指纹 SHA256:…",
        pattern=r"^(SHA256:[A-Za-z0-9+/]{43}=?)?$",
        description="填写 ssh 仓库的主机指纹（SSH_HOST_KEY_ENFORCE=true 时必填）；HTTPS 仓库留空",
        default="",
    )
    if not enforce:
        # 字段保留在 schema 中以兼容历史记录（重新开启后恢复校验），但创建/编辑表单不再展示。
        fingerprint["x-hidden"] = True
        fingerprint["description"] = (
            "当前已关闭指纹校验（SSH_HOST_KEY_ENFORCE=false）；历史值原样保留，重新开启后恢复校验"
        )
    return obj(
        {
            "repo_url": text(
                "仓库地址",
                minLength=1,
                maxLength=512,
                description="如 git@gitlab.example.com:group/repo.git 或 https://gitlab.example.com/group/repo.git",
            ),
            "branch": text(
                "基线分支",
                minLength=1,
                maxLength=200,
                default=DEFAULT_BRANCH,
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$",
            ),
            "host_key_sha256": fingerprint,
        },
        ["repo_url"],
    )


GIT_ACCOUNT = obj({})
GIT_CREDENTIAL = obj(
    {
        "private_key": upload_text("PEM 私钥（SSH 仓库）", maxLength=32768, format="password"),
        "passphrase": text("私钥口令（SSH 仓库）", format="password"),
        "token": text("HTTPS 访问令牌", maxLength=512, format="password"),
        "username": text("HTTPS 用户名", maxLength=128, description="留空默认 oauth2"),
    }
)
GIT_CREDENTIAL["oneOf"] = [
    {"required": ["private_key"], "not": {"required": ["token"]}},
    {"required": ["token"], "not": {"required": ["private_key"]}},
]


@dataclass
class SyncJob:
    """冻结的同步上下文；后台线程不依赖请求级 ctx（其 deadline 随请求结束失效）。"""

    account_id: str
    repo_url: str
    branch: str
    host_key: str
    credential: dict
    policy: dict
    network: object
    enforce_host_key: bool
    work_root: Path
    repo_dir: Path
    state_file: Path


def pin_host_key(job, parsed, ip):
    """连接目标 IP 校验 SSH 主机密钥并返回 known_hosts 行。"""
    try:
        sock = socket.create_connection((ip, parsed["port"]), timeout=10)
    except OSError as error:
        raise GatewayError("GIT_UNREACHABLE", f"无法连接 {parsed['host']}:{parsed['port']}：{error}", 502) from None
    try:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=10)
            key = transport.get_remote_server_key()
        finally:
            transport.close()
    except paramiko.SSHException as error:
        raise GatewayError("HOST_KEY_FAILED", f"SSH 主机密钥校验失败：{error}", 502) from None
    finally:
        sock.close()
    if job.enforce_host_key:
        pinned = (job.host_key or "").rstrip("=")
        if not pinned:
            raise GatewayError("HOST_KEY_MISSING", "资产未配置主机指纹；请补充指纹或关闭 SSH_HOST_KEY_ENFORCE", 403)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if not equal(fingerprint, pinned):
            raise GatewayError("HOST_KEY_MISMATCH", "SSH 主机密钥不匹配", 403)
    host = parsed["host"] if parsed["port"] == 22 else f"[{parsed['host']}]:{parsed['port']}"
    return f"{host} {key.get_name()} {key.get_base64()}"


def private_file(path, content):
    """创建即为 0600；写入失败也由外层临时目录作用域回收。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(content)


def prepare_git(job):
    """生成隔离的一次性环境；准备阶段抛错和执行结束都清理，支持并发健康检查。"""
    parsed = parse_repo_url(job.repo_url)
    host, port = parsed["host"], parsed["port"]
    if parsed["scheme"] == "ssh":
        if host.lower() in job.network.config.hosts:
            raise GatewayError("PROXY_LOOP", "禁止将本网关配置为 Git 上游", 403)
    else:
        job.network.url(job.repo_url)
    ip = str(ipaddress.ip_address(job.network.resolve(host, port)))
    job.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = tempfile.TemporaryDirectory(prefix="session-", dir=job.work_root)
    work = Path(temporary.name)
    try:
        env = base_env(work)
        env["GIT_ALLOW_PROTOCOL"] = parsed["scheme"]
        extra = ["-c", "core.hooksPath=" + os.devnull, "-c", "submodule.recurse=false"]
        if parsed["scheme"] == "ssh":
            known = pin_host_key(job, parsed, ip)
            key_file, known_hosts, config = work / "id_key", work / "known_hosts", work / "ssh_config"
            private_file(key_file, job.credential["private_key"])
            private_file(known_hosts, known + "\n")
            private_file(
                config,
                "\n".join(
                    [
                        f"Host {host}",
                        f"  HostName {ip}",
                        f"  HostKeyAlias {known.split()[0]}",
                        f"  Port {port}",
                        f"  User {parsed['user'] or 'git'}",
                        f'  IdentityFile "{key_file}"',
                        "  IdentitiesOnly yes",
                        f'  UserKnownHostsFile "{known_hosts}"',
                        "  GlobalKnownHostsFile " + os.devnull,
                        "  StrictHostKeyChecking yes",
                        "  BatchMode yes",
                        "  ConnectTimeout 15",
                        "",
                    ]
                ),
            )
            env["GIT_SSH_COMMAND"] = "ssh -F " + shlex.quote(str(config))
        else:
            # 不支持固定解析的 Git 必须拒绝，不能静默忽略安全配置后直接联网。
            help_text, _, truncated, code = run_capped(["git", "help", "--config"], str(work), env, 10, OUT_MAX_BYTES)
            if code or truncated or b"http.curloptResolve" not in help_text:
                raise GatewayError("GIT_UNSUPPORTED", "Git 不支持 http.curloptResolve，请升级 Git", 503)
            env["GIT_USER"] = job.credential.get("username") or "oauth2"
            env["GIT_TOKEN"] = job.credential["token"]
            extra += [
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "-c",
                "http.proxy=",
                "-c",
                "http.curloptResolve=",
                "-c",
                "credential.helper=",
                "-c",
                'credential.helper=!f() { printf "username=%s\\npassword=%s\\n" "$GIT_USER" "$GIT_TOKEN"; }; f',
            ]
            # URL 保留原始主机，TLS SNI/证书校验和 Host 不变；固定解析不带过期前缀。
            if ":" not in host:
                address = f"[{ip}]" if ":" in ip else ip
                extra += ["-c", f"http.curloptResolve={host}:{port}:{address}"]
        return env, extra, temporary.cleanup
    except BaseException:
        temporary.cleanup()
        raise


def validate_cached_remote(job, env):
    """缓存仅允许克隆生成的配置，拒绝改写 URL、代理、include、helper 或子模块配置。"""
    config = job.repo_dir / ".git" / "config"
    if config.is_symlink() or config.parent.is_symlink():
        raise GatewayError("REPO_CONFIG_UNSAFE", "代码副本配置异常，请重新准备副本", 403)
    out, _, truncated, code = run_capped(
        ["git", "config", "--file", str(config), "--no-includes", "--null", "--list"],
        env["HOME"],
        env,
        10,
        65536,
    )
    allowed = {
        "core.repositoryformatversion": {"0"},
        "core.filemode": {"true", "false"},
        "core.bare": {"false"},
        "core.logallrefupdates": {"true", "false"},
        "core.ignorecase": {"true", "false"},
        "core.precomposeunicode": {"true", "false"},
        "remote.origin.url": {job.repo_url},
        "remote.origin.fetch": {f"+refs/heads/{job.branch}:refs/remotes/origin/{job.branch}"},
        f"branch.{job.branch}.remote": {"origin"},
        f"branch.{job.branch}.merge": {f"refs/heads/{job.branch}"},
    }
    seen = set()
    for entry in out.decode("utf-8", "replace").split("\0"):
        if not entry:
            continue
        key, _, value = entry.partition("\n")
        if key in seen or value not in allowed.get(key, set()):
            raise GatewayError("REPO_CONFIG_UNSAFE", "代码副本配置或远端已变化，请重新准备副本", 403)
        seen.add(key)
    if code or truncated or "remote.origin.url" not in seen:
        raise GatewayError("REPO_CONFIG_UNSAFE", "无法确认代码副本远端配置", 403)


def sync_error(raw):
    """不将服务器可控的 stderr（可能包含凭据）带入日志、持久状态和 API。"""
    code = classify_git_error(raw)
    message = {
        "GIT_AUTH_FAILED": "Git 认证或主机密钥校验失败",
        "GIT_UNREACHABLE": "Git 目标不可达",
    }.get(code, "Git 操作失败，请核对远端地址、分支、TLS 和访问权限")
    return GatewayError(code, message, 502)


class GitRepoAssetType(AssetType):
    type_id, display_name, icon = "gitrepo", "Git 代码仓库", "Document"

    def __init__(self, data_dir, enforce_host_key=True):
        self.data_dir = Path(data_dir).resolve()
        self.enforce_host_key = enforce_host_key
        self.connection_schema = git_connection_schema(enforce_host_key)
        self._lock = threading.Lock()
        self._states = {}

    account_schema, credential_schema = GIT_ACCOUNT, GIT_CREDENTIAL

    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "refresh_interval_seconds": integer("副本自动更新间隔（秒，0=禁用）", 0, 86400, default=DEFAULT_REFRESH),
            "sync_timeout_seconds": integer("克隆/拉取超时（秒）", 30, 1800, default=DEFAULT_SYNC_TIMEOUT),
            "max_repo_mb": integer("副本大小上限（MB）", 16, 32768, default=DEFAULT_MAX_REPO_MB),
            "max_read_lines": integer("单次读取行数", 1, 2000, default=400),
            "max_read_bytes": integer("单次读取字节", 1024, 262144, default=65536),
        }
    )
    tools = [
        tool(
            "search_code",
            "在代码副本中按关键词或正则搜索，返回匹配文件、行号与内容（优先 ripgrep，回退 git grep）。"
            "排查具体实现、配置项与调用链时优先使用；引用结果时标注文件路径与行号。",
            {
                "pattern": text("搜索内容", minLength=1, maxLength=512),
                "regex": {"type": "boolean", "title": "正则模式", "default": False},
                "path": text("限定子目录（仓库相对路径）", default="", maxLength=512),
                "glob": text("文件名过滤（如 *.java）", default="", maxLength=128),
                "context": integer("命中行上下文行数", 0, 3, default=0),
                "max_results": integer("返回条数", 1, 200, default=50),
            },
            ["pattern"],
        ),
        tool(
            "read_file",
            "按行读取代码副本中的文本文件（带行号；单次最多 400 行 / 64KB，可在策略中调整）。",
            {
                "file": text("文件路径（仓库相对路径）", minLength=1, maxLength=1024),
                "start": integer("起始行号", 1, default=1),
                "end": integer("结束行号（含；默认读到文件末尾）", 1),
            },
            ["file"],
        ),
        tool(
            "git_log",
            "查看最近提交历史（哈希 / 日期 / 作者 / 说明）。",
            {
                "n": integer("条数", 1, 100, default=20),
                "branch": text(
                    "分支（默认基线分支）", maxLength=200, pattern=r"^$|^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$"
                ),
            },
        ),
        tool(
            "git_diff",
            "查看某次提交的改动（stat + patch 内容）。",
            {
                "commit": text(
                    "提交哈希或分支", maxLength=200, default="", pattern=r"^$|^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$"
                ),
                "file": text("仅查看该文件（仓库相对路径）", maxLength=1024, default=""),
            },
        ),
        tool(
            "list_tree",
            "查看目录树，快速了解工程结构。",
            {
                "path": text("起始目录（仓库相对路径）", maxLength=512, default=""),
                "depth": integer("递归深度", 1, 4, default=2),
            },
        ),
        tool("list_branches", "列出代码副本中的分支。", {}),
    ]

    # ---- 路径与状态 ----

    def repos_root(self):
        return self.data_dir / "repos"

    def repo_dir(self, account_id):
        return self.repos_root() / account_id

    def work_dir(self, account_id):
        return self.repos_root() / ".work" / account_id

    def state_path(self, account_id):
        return self.repos_root() / ".work" / f"{account_id}.json"

    def _state(self, account_id):
        with self._lock:
            return self._states.setdefault(account_id, {"thread": None, "error": None, "failed_at": 0})

    def _job(self, ctx):
        connection = ctx.asset["connection"]
        account_id = ctx.account["id"]
        return SyncJob(
            account_id=account_id,
            repo_url=connection["repo_url"],
            branch=connection.get("branch") or DEFAULT_BRANCH,
            host_key=connection.get("host_key_sha256", ""),
            credential=ctx.credential,
            policy=ctx.account["policy"],
            network=ctx.network,
            enforce_host_key=ctx.enforce_host_key,
            work_root=self.work_dir(account_id),
            repo_dir=self.repo_dir(account_id),
            state_file=self.state_path(account_id),
        )

    # ---- 配置校验 ----

    def validate_connection(self, network, connection):
        parsed = parse_repo_url(connection.get("repo_url"))
        host, port = parsed["host"], parsed["port"]
        if parsed["scheme"] in ("http", "https"):
            network.url(connection["repo_url"])
        else:
            network.require_registered(host, port, "请先在 OUTBOUND_ALLOWLIST 登记 Git 服务器主机与端口")
            if host.lower() in network.config.hosts:
                raise GatewayError("PROXY_LOOP", "禁止将本网关配置为 Git 上游")
        if parsed["scheme"] == "ssh" and self.enforce_host_key and not connection.get("host_key_sha256"):
            raise GatewayError("HOST_KEY_MISSING", "SSH 仓库需配置主机指纹；请补充指纹或关闭 SSH_HOST_KEY_ENFORCE", 403)

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        parsed = parse_repo_url(connection.get("repo_url"))
        if parsed["scheme"] == "ssh":
            if not credential.get("private_key"):
                raise GatewayError("CREDENTIAL_MISMATCH", "SSH 仓库的账号凭据须提供私钥", 403)
        elif not credential.get("token"):
            raise GatewayError("CREDENTIAL_MISMATCH", "HTTPS 仓库的账号凭据须提供访问令牌", 403)

    # ---- 副本准备 ----

    def ensure_repo(self, ctx):
        account_id = ctx.account["id"]
        repo, state = self.repo_dir(account_id), self._state(account_id)
        thread = state.get("thread")
        if thread is not None and thread.is_alive():
            self._await_preparing(ctx, state, thread, repo)
            return
        if is_repo(repo):
            self._maybe_refresh(ctx, repo, state)
            return
        failed_at = state.get("failed_at") or 0
        if failed_at and now_ms() - failed_at < FAIL_RETRY_MS:
            raise GatewayError(
                "REPO_SYNC_FAILED",
                f"代码副本克隆失败：{state.get('error') or '未知错误'}；稍后将自动重试",
                503,
            )
        self._start(ctx, state, "clone")
        self._await_preparing(ctx, state, state["thread"], repo)

    def _await_preparing(self, ctx, state, thread, repo):
        budget = min(CLONE_WAIT_SECONDS, ctx.remaining() - 2.5)
        if budget > 0.5:
            thread.join(budget)
        if thread.is_alive():
            raise GatewayError("REPO_PREPARING", "代码副本正在后台克隆，请稍后重试", 503)
        if not is_repo(repo):
            raise GatewayError("REPO_SYNC_FAILED", f"代码副本克隆失败：{state.get('error') or '未知错误'}", 503)

    def _maybe_refresh(self, ctx, repo, state):
        policy = ctx.account["policy"]
        interval = int(policy.get("refresh_interval_seconds", DEFAULT_REFRESH) or 0)
        if interval <= 0:
            return
        failed_at = state.get("failed_at") or 0
        if failed_at and now_ms() - failed_at < FAIL_RETRY_MS:
            return
        record = read_state(self.state_path(ctx.account["id"]))
        if now_ms() - int(record.get("last_sync_at") or 0) < interval * 1000:
            return
        thread = state.get("thread")
        if thread is not None and thread.is_alive():
            return
        self._start(ctx, state, "fetch")

    def _start(self, ctx, state, mode):
        job = self._job(ctx)
        state["error"] = None
        thread = threading.Thread(
            target=self._run_sync,
            args=(state, job, mode),
            daemon=True,
            name=f"gitrepo-{mode}-{job.account_id}",
        )
        state["thread"] = thread
        thread.start()

    def _run_sync(self, state, job, mode):
        try:
            self.sync(job, mode)
            state["error"], state["failed_at"] = None, 0
        except Exception as error:
            message = error.message if isinstance(error, GatewayError) else "Git 同步内部错误"
            state["error"], state["failed_at"] = message, now_ms()
            logger.warning("event=gitrepo_sync_failed account=%s mode=%s error=%s", job.account_id, mode, message)

    # ---- 克隆与更新 ----

    def sync(self, job, mode):
        env, extra, cleanup = prepare_git(job)
        try:
            if mode == "clone":
                self._clone(job, env, extra)
            else:
                self._fetch(job, env, extra)
            size_mb = directory_size_mb(job.repo_dir)
            limit_mb = int(job.policy.get("max_repo_mb", DEFAULT_MAX_REPO_MB))
            if size_mb > limit_mb:
                shutil.rmtree(job.repo_dir, ignore_errors=True)
                raise GatewayError("REPO_TOO_LARGE", f"副本大小 {size_mb}MB 超过上限 {limit_mb}MB，已清理副本", 507)
            write_state(job.state_file, {"last_sync_at": now_ms(), "head": self._head(job, env)})
        finally:
            cleanup()

    def _clone(self, job, env, extra):
        root = job.repo_dir.parent
        root.mkdir(parents=True, exist_ok=True)
        for stale in root.glob(f".{job.account_id}.staging-*"):
            shutil.rmtree(stale, ignore_errors=True)
        staging = root / f".{job.account_id}.staging-{uuid.uuid4().hex[:8]}"
        timeout = int(job.policy.get("sync_timeout_seconds", DEFAULT_SYNC_TIMEOUT))
        args = (
            ["git"]
            + extra
            + ["clone", "--quiet", "--single-branch", "--branch", job.branch, "--", job.repo_url, str(staging)]
        )
        try:
            code, message = self._sync_run(args, env["HOME"], env, timeout)
        except GatewayError as error:
            shutil.rmtree(staging, ignore_errors=True)
            raise GatewayError(error.code, f"克隆失败：{error.message}", error.status) from None
        if code != 0:
            shutil.rmtree(staging, ignore_errors=True)
            raise GatewayError(classify_git_error(message), f"克隆失败：{message or f'退出码 {code}'}", 502)
        shutil.rmtree(job.repo_dir, ignore_errors=True)
        os.replace(staging, job.repo_dir)

    def _fetch(self, job, env, extra):
        validate_cached_remote(job, env)
        timeout = int(job.policy.get("sync_timeout_seconds", DEFAULT_SYNC_TIMEOUT))
        refspec = f"+refs/heads/{job.branch}:refs/remotes/origin/{job.branch}"
        args = (
            ["git"]
            + extra
            + [
                "-C",
                str(job.repo_dir),
                "fetch",
                "--quiet",
                "--prune",
                "--no-recurse-submodules",
                "--",
                job.repo_url,
                refspec,
            ]
        )
        code, message = self._sync_run(args, env["HOME"], env, timeout)
        if code != 0:
            raise GatewayError(classify_git_error(message), f"拉取失败：{message or f'退出码 {code}'}", 502)
        reset = ["git", "-C", str(job.repo_dir), "reset", "--hard", "--quiet", f"origin/{job.branch}"]
        code, message = self._sync_run(reset, str(job.work_root), env, 120)
        if code != 0:
            raise GatewayError(classify_git_error(message), f"副本重置失败：{message or f'退出码 {code}'}", 502)

    def _sync_run(self, args, cwd, env, timeout):
        _, err, _, code = run_capped(args, cwd, env, timeout, ERR_MAX_BYTES * 8)
        if code:
            raise sync_error(err.decode("utf-8", "replace"))
        return code, ""

    def _head(self, job, env):
        """读取副本当前提交；失败或输出为空时返回空串，不阻断同步状态写入。"""
        try:
            out, _, _, code = run_capped(
                ["git", "-C", str(job.repo_dir), "rev-parse", "HEAD"],
                str(job.work_root),
                env,
                30,
                ERR_MAX_BYTES,
            )
        except GatewayError:
            return ""
        lines = out.decode("utf-8", "replace").splitlines()
        return lines[0].strip()[:12] if code == 0 and lines else ""

    # ---- 工具执行 ----

    def execute_sync(self, name, args, ctx):
        repo = str(self.repo_dir(ctx.account["id"]))
        self.ensure_repo(ctx)
        if name == "search_code":
            payload = self.search_code(ctx, args, repo)
        elif name == "read_file":
            payload = self.read_file(ctx, args, repo)
        elif name == "git_log":
            payload = self.git_log(ctx, args, repo)
        elif name == "git_diff":
            payload = self.git_diff(ctx, args, repo)
        elif name == "list_tree":
            payload = self.list_tree(ctx, args, repo)
        else:
            payload = self.list_branches(ctx, args, repo)
        return result(payload)

    def _ripgrep(self, ctx, args, repo, target):
        budget = min(ctx.remaining(), GIT_TIMEOUT_CAP)
        env = base_env(self.work_dir(ctx.account["id"]))
        pattern = args["pattern"]
        command = [RG_BIN, "--no-heading", "--line-number", "--color", "never", "--max-columns", "600"]
        if not args.get("regex"):
            command.append("-F")
        if args.get("glob"):
            command.append("--glob=" + args["glob"])
        if args.get("context"):
            command += ["-C", str(args["context"])]
        command += ["--", pattern]
        if target != ".":
            command.append(target)
        out, err, _, code = run_capped(command, repo, env, budget, SEARCH_CAP)
        if code not in (0, 1):
            message = err.decode("utf-8", "replace").strip()[:280]
            raise GatewayError("SEARCH_FAILED", f"搜索失败：{message or f'退出码 {code}'}", 502)
        return out

    def _git_grep(self, ctx, args, repo, target):
        budget = min(ctx.remaining(), GIT_TIMEOUT_CAP)
        env = base_env(self.work_dir(ctx.account["id"]))
        command = ["git", "grep", "-n", "-I", "-E" if args.get("regex") else "-F"]
        if args.get("context"):
            command += ["-C", str(args["context"])]
        command += ["-e", args["pattern"], "--", target]
        out, err, _, code = run_capped(command, repo, env, budget, SEARCH_CAP)
        if code not in (0, 1):
            message = err.decode("utf-8", "replace").strip()[:280]
            raise GatewayError("SEARCH_FAILED", f"搜索失败：{message or f'退出码 {code}'}", 502)
        return out

    def search_code(self, ctx, args, repo):
        target = safe_rel(repo, args.get("path"))
        limit = min(args.get("max_results", 50), ctx.limits["max_result_rows"], 200)
        raw = self._ripgrep(ctx, args, repo, target) if RG_BIN else self._git_grep(ctx, args, repo, target)
        text_limit = min(MAX_TEXT_LINE, ctx.limits["max_cell_chars"])
        matches = []
        # ripgrep/git grep 输出： file:line:text 为命中行，file-line-text 为上下文行。
        for line in raw.decode("utf-8", "replace").splitlines():
            found = re.match(r"^(.+?):(\d+):(.*)$", line)
            if found:
                matches.append(
                    {
                        "file": found.group(1),
                        "line": int(found.group(2)),
                        "text": found.group(3)[:text_limit],
                        "ctx": False,
                    }
                )
                continue
            found = re.match(r"^(.+?)-(\d+)-(.*)$", line)
            if found:
                matches.append(
                    {
                        "file": found.group(1),
                        "line": int(found.group(2)),
                        "text": found.group(3)[:text_limit],
                        "ctx": True,
                    }
                )
        total = len(matches)
        truncated = total > limit
        ctx.stats.update(row_count=min(total, limit), truncated=truncated)
        return {
            "pattern": args["pattern"],
            "path": target,
            "matches": matches[:limit],
            "total": total,
            "truncated": truncated,
        }

    def read_file(self, ctx, args, repo):
        rel = safe_rel(repo, args["file"])
        full = os.path.join(repo, rel)
        if not os.path.isfile(full):
            raise GatewayError("PATH_NOT_FOUND", f"文件不存在：{rel}", 404)
        with open(full, "rb") as probe:
            if b"\0" in probe.read(8192):
                raise GatewayError("BINARY_FILE", "不支持二进制文件")
        policy = ctx.account["policy"]
        max_lines = min(policy.get("max_read_lines", 400), 2000)
        max_bytes = min(policy.get("max_read_bytes", 65536), 262144, ctx.limits["max_output_bytes"] // 2)
        start = max(1, args.get("start", 1))
        end = args.get("end") or 0
        lines, size, total = [], 0, 0
        with open(full, encoding="utf-8", errors="replace") as handle:
            for index, raw in enumerate(handle, 1):
                total = index
                if index % 4096 == 0:
                    ctx.remaining()
                if index < start or (end and index > end):
                    continue
                if len(lines) >= max_lines or size >= max_bytes:
                    continue
                content = raw.rstrip("\n").rstrip("\r")
                lines.append(f"{index:5d}| {content}")
                size += len(raw)
        expected = (min(end or total, total) - start + 1) if total >= start else 0
        truncated = expected > len(lines)
        ctx.stats.update(row_count=len(lines), truncated=truncated)
        return {
            "file": rel,
            "start": start,
            "end": end or total,
            "total_lines": total,
            "returned_lines": len(lines),
            "content": "\n".join(lines),
            "truncated": truncated,
        }

    def _git(self, ctx, repo, args, cap=LOG_CAP):
        budget = min(ctx.remaining(), GIT_TIMEOUT_CAP)
        env = base_env(self.work_dir(ctx.account["id"]))
        out, err, truncated, code = run_capped(["git"] + args, repo, env, budget, cap)
        if code not in (0, 1) and not truncated:
            message = err.decode("utf-8", "replace").strip()[:280]
            raise GatewayError("GIT_FAILED", f"git 命令失败：{message or f'退出码 {code}'}", 502)
        return out.decode("utf-8", "replace"), truncated

    def git_log(self, ctx, args, repo):
        branch = args.get("branch") or ctx.asset["connection"].get("branch") or DEFAULT_BRANCH
        if not BRANCH_RE.fullmatch(branch):
            raise GatewayError("ARGUMENTS", "分支名格式不合法")
        count = min(args.get("n", 20), 100, ctx.limits["max_result_rows"])
        text_out, truncated = self._git(
            ctx,
            repo,
            ["-C", repo, "log", "-n", str(count), "--pretty=format:%h | %ad | %an | %s", "--date=short", branch],
        )
        commits = [line for line in text_out.splitlines() if line.strip()]
        ctx.stats.update(row_count=len(commits), truncated=truncated)
        return {"branch": branch, "commits": commits, "truncated": truncated}

    def git_diff(self, ctx, args, repo):
        commit = args.get("commit") or "HEAD"
        if not BRANCH_RE.fullmatch(commit):
            raise GatewayError("ARGUMENTS", "提交参数格式不合法")
        command = ["-C", repo, "show", commit, "--no-color", "--stat", "--patch"]
        if args.get("file"):
            command += ["--", safe_rel(repo, args["file"])]
        cap = min(DIFF_CAP, max(4096, ctx.limits["max_output_bytes"] // 2))
        text_out, truncated = self._git(ctx, repo, command, cap=cap)
        ctx.stats.update(row_count=1, truncated=truncated)
        return {"commit": commit, "truncated": truncated, "diff": text_out}

    def list_tree(self, ctx, args, repo):
        root_rel = safe_rel(repo, args.get("path"))
        root = os.path.join(repo, root_rel)
        if not os.path.isdir(root):
            raise GatewayError("PATH_NOT_FOUND", f"目录不存在：{root_rel}", 404)
        depth = min(args.get("depth", 2), 4)
        lines = []

        def walk(directory, prefix, level):
            if level > depth or len(lines) > TREE_MAX_LINES:
                return
            ctx.remaining()
            try:
                entries = sorted(os.scandir(directory), key=lambda item: (not item.is_dir(), item.name))
            except OSError:
                return
            for entry in entries:
                if entry.name == ".git" or len(lines) > TREE_MAX_LINES:
                    continue
                real = os.path.realpath(entry.path)
                inside = real == repo or real.startswith(repo + os.sep)
                is_dir = entry.is_dir()
                if is_dir and not inside:
                    continue
                lines.append(prefix + entry.name + ("/" if is_dir else ""))
                if is_dir:
                    walk(entry.path, prefix + "  ", level + 1)

        walk(root, "", 1)
        truncated = len(lines) > TREE_MAX_LINES
        ctx.stats.update(row_count=min(len(lines), TREE_MAX_LINES), truncated=truncated)
        return {
            "path": root_rel if root_rel != "." else "/",
            "depth": depth,
            "tree": "\n".join(lines[:TREE_MAX_LINES]),
            "truncated": truncated,
        }

    def list_branches(self, ctx, args, repo):
        text_out, truncated = self._git(ctx, repo, ["-C", repo, "branch", "-a", "--format=%(refname:short)"])
        branches = [line.strip() for line in text_out.splitlines() if line.strip()]
        overflow = len(branches) > BRANCH_MAX
        ctx.stats.update(row_count=min(len(branches), BRANCH_MAX), truncated=truncated or overflow)
        return {
            "total": len(branches),
            "branches": branches[:BRANCH_MAX],
            "truncated": overflow,
        }

    # ---- 健康检查 ----

    def health_sync(self, ctx):
        account_id = ctx.account["id"]
        record = read_state(self.state_path(account_id))
        job = self._job(ctx)
        env, extra, cleanup = prepare_git(job)
        try:
            timeout = min(ctx.remaining(), 15)
            out, err, _, code = run_capped(
                ["git"] + extra + ["ls-remote", "--heads", "--", job.repo_url, job.branch],
                env["HOME"],
                env,
                timeout,
                65536,
            )
        finally:
            cleanup()
        if code != 0:
            raise sync_error(err.decode("utf-8", "replace"))
        remote_head = out.decode("utf-8", "replace").split("\t", 1)[0].strip()[:12]
        return {
            "reachable": True,
            "remote_head": remote_head,
            "repo_ready": is_repo(job.repo_dir),
            "local_head": record.get("head") or "",
            "last_sync_at": record.get("last_sync_at"),
        }
