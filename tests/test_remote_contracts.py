import base64
import hashlib
import io
import json
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.asset_types.base import Context
from app.asset_types.filebrowser import SFTPAssetType
from app.asset_types.mysql import BoundedConnection
from app.asset_types.ssh import SSHAssetType, connect_ssh
from app.core.config import DEFAULTS
from app.core.security import GatewayError, validate


def ctx(policy=None, **limits):
    return Context(
        {"connection": {}},
        {"config": {"username": "reader"}, "policy": policy or {}},
        {"password": "test-only"},
        {**DEFAULTS, **limits},
        SimpleNamespace(resolve=lambda *args: "192.0.2.1"),
    )


def unpack(value):
    return json.loads(value["content"][0]["text"])


class FakeSFTP:
    def __init__(self, content=b"abcdef", mode=stat.S_IFREG):
        self.content, self.mode, self.closed = content, mode, False

    def lstat(self, path):
        return SimpleNamespace(
            st_mode=self.mode if path == "/data/file.txt" else stat.S_IFDIR, st_size=len(self.content), st_mtime=1
        )

    def normalize(self, path):
        return path

    def get_channel(self):
        return SimpleNamespace(settimeout=lambda value: None)

    def open(self, *args, **kwargs):
        handle = io.BytesIO(self.content)
        handle.stat = lambda: self.lstat("/data/file.txt")
        return handle

    def listdir_iter(self, *args, **kwargs):
        for index in range(20):
            yield SimpleNamespace(filename=f"{index}.txt", st_mode=stat.S_IFREG, st_size=10, st_mtime=1)

    def close(self):
        self.closed = True


def mount_sftp(monkeypatch, sftp):
    monkeypatch.setattr(
        "app.asset_types.filebrowser.connect_ssh", lambda context: SimpleNamespace(open_sftp=lambda: sftp)
    )


def test_sftp_read_offset_and_truncation(monkeypatch):
    sftp = FakeSFTP()
    mount_sftp(monkeypatch, sftp)
    value = unpack(
        SFTPAssetType().execute_sync(
            "read_file", {"path": "file.txt", "offset": 1, "max_bytes": 3}, ctx({"root_dir": "/data"})
        )
    )
    assert value["text"] == "bcd"
    assert value["bytes"] == 3
    assert value["truncated"] is True
    assert sftp.closed


@pytest.mark.parametrize("content,mode", [(b"abc\0def", stat.S_IFREG), (b"abc", stat.S_IFIFO), (b"abc", stat.S_IFCHR)])
def test_sftp_reject_binary_and_special_files(monkeypatch, content, mode):
    sftp = FakeSFTP(content, mode)
    mount_sftp(monkeypatch, sftp)
    with pytest.raises(GatewayError):
        SFTPAssetType().execute_sync("read_file", {"path": "file.txt"}, ctx({"root_dir": "/data"}))
    assert sftp.closed


def test_sftp_global_count_limit(monkeypatch):
    sftp = FakeSFTP()
    mount_sftp(monkeypatch, sftp)
    value = unpack(
        SFTPAssetType().execute_sync("list_dir", {"limit": 100}, ctx({"root_dir": "/data"}, max_result_rows=2))
    )
    assert len(value["items"]) == 2
    assert value["truncated"] is True


def test_ssh_invalid_command_does_not_connect(monkeypatch):
    touched = []
    monkeypatch.setattr("app.asset_types.ssh.connect_ssh", lambda context: touched.append(True))
    with pytest.raises(GatewayError):
        SSHAssetType().execute_sync("exec_command", {"cmd": "invalid\0command"}, ctx())
    assert touched == []


def test_ssh_authorized_command_is_sent_unchanged_without_pty(monkeypatch):
    channel = Mock()
    channel.recv_ready.return_value = channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = True
    channel.recv_exit_status.return_value = 0
    client = Mock()
    client.get_transport.return_value.open_session.return_value = channel
    monkeypatch.setattr("app.asset_types.ssh.connect_ssh", lambda context: client)
    command_text = " printf hello; printf world "
    value = unpack(SSHAssetType().execute_sync("exec_command", {"cmd": command_text}, ctx()))
    channel.exec_command.assert_called_once_with(command_text)
    channel.get_pty.assert_not_called()
    channel.invoke_shell.assert_not_called()
    channel.close.assert_called_once()
    assert value["exit_code"] == 0 and not value["remote_completion_unknown"]
    assert "command_allowlist" not in SSHAssetType.policy_schema["properties"]


def mount_ssh_client(monkeypatch, key):
    monkeypatch.setattr(
        "app.asset_types.ssh.socket.create_connection", lambda *args: SimpleNamespace(close=lambda: None)
    )

    class Client:
        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, *args, **kwargs):
            assert kwargs["allow_agent"] is False
            assert kwargs["look_for_keys"] is False
            self.policy.missing_host_key(self, args[0], SimpleNamespace(asbytes=lambda: key))

        def close(self):
            pass

    monkeypatch.setattr("app.asset_types.ssh.paramiko.SSHClient", Client)
    return Client


@pytest.mark.parametrize("matching", [False, True])
def test_ssh_fingerprint_verification(monkeypatch, matching):
    key = b"test-host-key"
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    client_type = mount_ssh_client(monkeypatch, key)
    context = ctx()
    context.asset["connection"] = {
        "host": "ssh.example.test",
        "host_key_sha256": fingerprint if matching else "SHA256:wrong",
    }
    try:
        if matching:
            assert isinstance(connect_ssh(context), client_type)
        else:
            with pytest.raises(GatewayError, match="主机密钥不匹配"):
                connect_ssh(context)
    finally:
        context.close()


@pytest.mark.parametrize(
    "enforce,pinned,outcome",
    [
        (True, None, "missing"),
        (True, "SHA256:wrong", "mismatch"),
        (False, None, "accepted"),
        (False, "SHA256:wrong", "accepted"),
    ],
)
def test_ssh_host_key_enforce_switch(monkeypatch, enforce, pinned, outcome):
    client_type = mount_ssh_client(monkeypatch, b"test-host-key")
    context = ctx()
    context.enforce_host_key = enforce
    context.asset["connection"] = {"host": "ssh.example.test"}
    if pinned:
        context.asset["connection"]["host_key_sha256"] = pinned
    try:
        if outcome == "missing":
            with pytest.raises(GatewayError, match="未配置主机指纹"):
                connect_ssh(context)
        elif outcome == "mismatch":
            with pytest.raises(GatewayError, match="主机密钥不匹配"):
                connect_ssh(context)
        else:
            assert isinstance(connect_ssh(context), client_type)
    finally:
        context.close()


def test_ssh_connection_schema_follows_switch():
    assert SSHAssetType().connection_schema["required"] == ["host", "host_key_sha256"]
    optional = SSHAssetType(False).connection_schema
    assert optional["required"] == ["host"]
    # 关闭校验时指纹字段保留在 schema 中以兼容历史记录，但标记隐藏（创建/编辑表单不展示）。
    fingerprint = optional["properties"]["host_key_sha256"]
    assert fingerprint["x-hidden"] is True
    assert "已关闭指纹校验" in fingerprint["description"]
    validate(optional, {"host": "ssh.example.test"})
    validate(optional, {"host": "ssh.example.test", "host_key_sha256": "SHA256:" + "A" * 43})
    with pytest.raises(GatewayError):
        validate(SSHAssetType().connection_schema, {"host": "ssh.example.test"})
    assert SFTPAssetType(False).connection_schema["required"] == ["host"]


def test_mysql_packet_limit_before_allocation():
    conn = BoundedConnection(defer_connect=True, ssl_disabled=True)
    conn._packet_remaining = 1024
    with pytest.raises(GatewayError, match="内存上限"):
        conn._read_bytes(16777215)
