import base64
import hashlib
import io
import socket
import time

import paramiko

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool, upload_text
from app.core.security import GatewayError, equal


def ssh_connection_schema(enforce=True):
    """SSH/SFTP 连接 schema；关闭强制校验时指纹字段对表单隐藏且连接不再核对。"""
    fingerprint = text(
        "主机指纹 SHA256:…",
        pattern=r"^SHA256:[A-Za-z0-9+/]{43}=?$" if enforce else r"^(SHA256:[A-Za-z0-9+/]{43}=?)?$",
    )
    if not enforce:
        # 字段保留在 schema 中以兼容历史记录（重新开启后恢复校验），但创建/编辑表单不再展示。
        fingerprint["x-hidden"] = True
        fingerprint["description"] = (
            "当前已关闭指纹校验（SSH_HOST_KEY_ENFORCE=false）；历史值原样保留，重新开启后恢复校验"
        )
    return obj(
        {
            "host": text("主机", minLength=1, maxLength=253),
            "port": integer("端口", 1, 65535, default=22),
            "host_key_sha256": fingerprint,
        },
        ["host", "host_key_sha256"] if enforce else ["host"],
    )


SSH_ACCOUNT = obj({"username": text("登录用户", minLength=1)}, ["username"])
SSH_CREDENTIAL = obj(
    {
        "password": text("密码", format="password"),
        "private_key": upload_text("PEM 私钥", maxLength=32768, format="password"),
        "passphrase": text("私钥口令", format="password"),
    }
)
SSH_CREDENTIAL["oneOf"] = [
    {"required": ["password"], "not": {"required": ["private_key"]}},
    {"required": ["private_key"], "not": {"required": ["password"]}},
]


def command(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or "\0" in value:
        raise GatewayError("COMMAND_INVALID", "命令须为非空文本，最长 4096 字符且不能包含 NUL")
    # 保留原文，与授权组参数规则匹配的内容一致；由远端账号的 shell 执行。
    return value


def connect_ssh(ctx):
    cfg, credentials = ctx.asset["connection"], ctx.credential
    host, port = cfg["host"], cfg.get("port", 22)
    ip = ctx.network.resolve(host, port)
    sock = socket.create_connection((ip, port), min(ctx.remaining(), ctx.limits["connect_timeout_seconds"]))
    ctx.add_closer(sock.close)
    client = paramiko.SSHClient()
    ctx.add_closer(client.close)

    class PinnedKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if not ctx.enforce_host_key:
                # 开关关闭时接受任意主机密钥；已填写的指纹保留，重新开启后恢复校验。
                return
            pinned = cfg.get("host_key_sha256", "").rstrip("=")
            if not pinned:
                raise GatewayError("HOST_KEY_MISSING", "资产未配置主机指纹；请补充指纹或关闭 SSH_HOST_KEY_ENFORCE", 403)
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
            if not equal(fingerprint, pinned):
                raise GatewayError("HOST_KEY_MISMATCH", "SSH 主机密钥不匹配", 403)

    client.set_missing_host_key_policy(PinnedKey())
    private = None
    if credentials.get("private_key"):
        for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                private = kind.from_private_key(
                    io.StringIO(credentials["private_key"]), password=credentials.get("passphrase")
                )
                break
            except (paramiko.SSHException, ValueError):
                continue
        if private is None:
            raise GatewayError("PRIVATE_KEY_INVALID", "私钥格式或口令不正确")
    timeout = min(ctx.remaining(), ctx.limits["connect_timeout_seconds"])
    client.connect(
        host,
        port,
        username=ctx.account["config"]["username"],
        password=credentials.get("password"),
        pkey=private,
        sock=sock,
        allow_agent=False,
        look_for_keys=False,
        timeout=timeout,
        auth_timeout=timeout,
        banner_timeout=timeout,
        channel_timeout=timeout,
    )
    return client


class SSHAssetType(AssetType):
    type_id, display_name, icon = "ssh", "SSH 主机", "Monitor"
    default_port = 22
    account_schema, credential_schema = SSH_ACCOUNT, SSH_CREDENTIAL

    def __init__(self, enforce_host_key=True):
        self.enforce_host_key = enforce_host_key
        self.connection_schema = ssh_connection_schema(enforce_host_key)

    policy_schema = obj({**RESOURCE_SCHEMA})
    tools = [
        tool(
            "exec_command",
            "通过 SSH 非交互执行命令，返回 stdout、stderr 和退出码。"
            "命令由授权组参数黑白名单控制；未配置规则时不额外限制。"
            "命令可能修改远端数据，不提供 PTY 或交互输入；超时后远端状态可能未知，勿自动重试。",
            {
                "cmd": text(
                    "完整命令", minLength=1, maxLength=4096, description="远端 shell 命令原文，参数规则对该完整文本匹配"
                )
            },
            ["cmd"],
            readonly=False,
        )
    ]

    def execute_sync(self, name, args, ctx):
        normalized = command(args["cmd"])
        client = connect_ssh(ctx)
        channel = client.get_transport().open_session(timeout=ctx.remaining())
        ctx.add_closer(channel.close)
        channel.settimeout(min(ctx.remaining(), 5))
        channel.exec_command(normalized)
        stdout, stderr, total, cut = [], [], 0, False
        try:
            while True:
                ctx.remaining()
                for ready, read, chunks in (
                    (channel.recv_ready, channel.recv, stdout),
                    (channel.recv_stderr_ready, channel.recv_stderr, stderr),
                ):
                    if ready():
                        chunk = read(8192)
                        allowed = max(0, ctx.limits["max_output_bytes"] // 2 - total)
                        chunks.append(chunk[:allowed])
                        total += len(chunk)
                        if len(chunk) > allowed:
                            cut = True
                            break
                if cut or (
                    channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready()
                ):
                    break
                time.sleep(0.01)
            code = None if cut else channel.recv_exit_status()
            ctx.stats["truncated"] = cut
            return result(
                {
                    "stdout": b"".join(stdout).decode("utf-8", "replace"),
                    "stderr": b"".join(stderr).decode("utf-8", "replace"),
                    "exit_code": code,
                    "truncated": cut,
                    "remote_completion_unknown": cut,
                }
            )
        finally:
            ctx.close()

    def health_sync(self, ctx):
        client = connect_ssh(ctx)
        try:
            return {"reachable": client.get_transport().is_authenticated()}
        finally:
            ctx.close()
