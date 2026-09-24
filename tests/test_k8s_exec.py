"""使用真实 wsproto 帧测试 remotecommand 的分片、状态与资源边界。"""

import asyncio
import json
import ssl
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit

import pytest
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    RejectConnection,
    Request,
    TextMessage,
)

from app.asset_types import k8s_exec, kubernetes
from app.asset_types.base import Context, result
from app.core.config import DEFAULTS
from app.core.security import GatewayError


def status(code=0):
    value = (
        {"status": "Success"}
        if code == 0
        else {
            "status": "Failure",
            "reason": "NonZeroExitCode",
            "details": {"causes": [{"reason": "ExitCode", "message": str(code)}]},
        }
    )
    return BytesMessage(data=b"\x03" + json.dumps(value).encode())


class Peer:
    def __init__(self, events, reject=None, protocol=k8s_exec.PROTOCOL, hang=False):
        self.ws = WSConnection(ConnectionType.SERVER)
        self.events = events
        self.reject = reject
        self.protocol = protocol
        self.hang = hang
        self.buffer = bytearray()
        self.request = None
        self.closed = False
        self.pongs = []
        self.ready = asyncio.Event()

    def write(self, data):
        self.ws.receive_data(data)
        for event in self.ws.events():
            if isinstance(event, Request):
                self.request = event
                response = (
                    RejectConnection(status_code=self.reject)
                    if self.reject
                    else AcceptConnection(subprotocol=self.protocol)
                )
                self.buffer.extend(self.ws.send(response))
                if not self.reject:
                    for outgoing in self.events:
                        self.buffer.extend(self.ws.send(outgoing))
                self.ready.set()
            elif isinstance(event, Pong):
                self.pongs.append(event.payload)

    async def drain(self):
        pass

    async def read(self, size):
        await self.ready.wait()
        if not self.buffer and self.hang:
            await asyncio.Event().wait()
        # 故意拆散 HTTP 头、WebSocket 帧和 UTF-8 字符。
        data = bytes(self.buffer[: min(size, 17)])
        del self.buffer[: len(data)]
        return data

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.fixture
def setup_exec(monkeypatch):
    def setup(events=(), **kwargs):
        ctx = Context(
            {"connection": {"url": "https://k8s.example.test:6443/prefix"}},
            {"config": {"namespace": "prod", "auth_mode": "token"}, "policy": {"kinds": ["pods"]}},
            {"token": "test-only"},
            dict(DEFAULTS),
            SimpleNamespace(url=Mock(return_value=("k8s.example.test", 6443)), resolve=Mock(return_value="192.0.2.12")),
        )
        peer = Peer(events, **kwargs)
        connect = AsyncMock(return_value=(peer, peer))
        tls = Mock(name="tls")
        monkeypatch.setattr(k8s_exec.asyncio, "open_connection", connect)
        return ctx, peer, connect, tls

    return setup


async def run(ctx, tls):
    return await k8s_exec.exec_stream(
        ctx,
        "/api/v1/namespaces/prod/pods/web/exec",
        ["printf", "hello & world"],
        "app",
        {"Authorization": "Bearer test-only"},
        tls,
    )


async def test_exec_fragmented_stdout_stderr_status_tls_and_pinned_ip(setup_exec):
    ctx, peer, connect, tls = setup_exec(
        [
            BytesMessage(data=b"\x01he", message_finished=False),
            Ping(payload=b"heartbeat"),
            BytesMessage(data="llo 世界".encode()),
            BytesMessage(data=b"\x02warning"),
            status(),
            CloseConnection(code=1000),
        ]
    )
    value = await run(ctx, tls)
    assert value == {
        "stdout": "hello 世界",
        "stderr": "warning",
        "exit_code": 0,
        "truncated": False,
        "remote_completion_unknown": False,
    }
    assert peer.closed and peer.pongs == [b"heartbeat"]
    connect.assert_awaited_once_with("192.0.2.12", 6443, ssl=tls, server_hostname="k8s.example.test", limit=32768)
    ctx.network.resolve.assert_called_once_with("k8s.example.test", 6443)
    assert peer.request.host == "k8s.example.test:6443"
    assert peer.request.subprotocols == [k8s_exec.PROTOCOL]
    parsed = urlsplit(peer.request.target)
    assert parsed.path == "/prefix/api/v1/namespaces/prod/pods/web/exec"
    assert parse_qs(parsed.query) == {
        "command": ["printf", "hello & world"],
        "container": ["app"],
        "stdin": ["false"],
        "tty": ["false"],
        "stdout": ["true"],
        "stderr": ["true"],
    }


@pytest.mark.parametrize(
    "events,unknown,code",
    [
        ([status(7), CloseConnection(code=1000)], False, 7),
        ([CloseConnection(code=1000)], True, None),
        ([status()], True, None),
        ([status(), CloseConnection(code=1011)], True, None),
    ],
)
async def test_exec_completion_status(setup_exec, events, unknown, code):
    ctx, peer, _, tls = setup_exec(events)
    value = await run(ctx, tls)
    assert value["remote_completion_unknown"] is unknown
    assert value["exit_code"] == code
    assert peer.closed


@pytest.mark.parametrize(
    "events,error",
    [
        ([BytesMessage(data=b"\x03not-json")], "K8S_EXEC_STATUS"),
        ([BytesMessage(data=b"\x03" + b"x" * 17000)], "K8S_EXEC_STATUS"),
        ([status(), status()], "K8S_EXEC_STATUS"),
        ([TextMessage(data="not-binary")], "K8S_EXEC_PROTOCOL"),
        ([BytesMessage(data=b"\x09invalid")], "K8S_EXEC_PROTOCOL"),
        ([BytesMessage(data=b"")], "K8S_EXEC_PROTOCOL"),
    ],
)
async def test_exec_rejects_malformed_messages(setup_exec, events, error):
    ctx, peer, _, tls = setup_exec(events)
    with pytest.raises(GatewayError) as exc:
        await run(ctx, tls)
    assert exc.value.code == error
    assert peer.closed


@pytest.mark.parametrize(
    "http,code",
    [
        (301, "REDIRECT_DENIED"),
        (401, "K8S_AUTH_FAILED"),
        (403, "K8S_FORBIDDEN"),
        (404, "K8S_NOT_FOUND"),
        (400, "K8S_EXEC_PROTOCOL"),
    ],
)
async def test_exec_handshake_refusal_no_retry(setup_exec, http, code):
    ctx, peer, connect, tls = setup_exec(reject=http)
    with pytest.raises(GatewayError) as exc:
        await run(ctx, tls)
    assert exc.value.code == code
    assert connect.await_count == 1 and peer.closed


async def test_exec_requires_negotiated_v4(setup_exec):
    ctx, peer, _, tls = setup_exec(protocol=None)
    with pytest.raises(GatewayError) as exc:
        await run(ctx, tls)
    assert exc.value.code == "K8S_EXEC_PROTOCOL" and peer.closed


async def test_exec_output_limit_marks_unknown_and_bounds_encoded_result(setup_exec):
    ctx, peer, _, tls = setup_exec([BytesMessage(data=b"\x01" + b"\0" * 2000), status(), CloseConnection(code=1000)])
    ctx.limits["max_output_bytes"] = 1024
    value = await run(ctx, tls)
    assert value["truncated"] and value["remote_completion_unknown"]
    assert value["exit_code"] is None and peer.closed
    assert len(json.dumps(result(value), ensure_ascii=False).encode()) < 1024


async def test_exec_timeout_closes_socket(setup_exec):
    ctx, peer, _, tls = setup_exec(hang=True)
    ctx.deadline = __import__("time").monotonic() + 0.05
    with pytest.raises(TimeoutError):
        await run(ctx, tls)
    assert peer.closed


async def test_exec_cancellation_closes_socket(setup_exec):
    ctx, peer, _, tls = setup_exec(hang=True)
    task = asyncio.create_task(run(ctx, tls))
    await peer.ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert peer.closed


async def test_exec_tls_verification_and_outbound_errors_not_retried(setup_exec):
    ctx, peer, connect, tls = setup_exec()
    connect.side_effect = ssl.SSLCertVerificationError("invalid certificate")
    with pytest.raises(ssl.SSLCertVerificationError):
        await run(ctx, tls)
    assert connect.await_count == 1 and peer.request is None
    connect.reset_mock()
    ctx.network.resolve.side_effect = GatewayError("OUTBOUND_DENIED", "拒绝", 403)
    with pytest.raises(GatewayError):
        await run(ctx, tls)
    connect.assert_not_called()


async def test_exec_adapter_preserves_connect_timeout(setup_exec):
    ctx, peer, connect, *_ = setup_exec()
    connect.side_effect = TimeoutError()
    with pytest.raises(TimeoutError):
        await kubernetes.KubernetesAssetType().execute("k8s_exec", {"pod": "web", "command": ["id"]}, ctx, None)
    assert connect.await_count == 1


async def test_exec_adapter_scope_and_error_flag(setup_exec):
    ctx, peer, *_ = setup_exec([status(2), CloseConnection(code=1000)])
    adapter = kubernetes.KubernetesAssetType()
    value = await adapter.execute("k8s_exec", {"pod": "web", "command": ["id"]}, ctx, None)
    assert value["isError"]
    assert json.loads(value["content"][0]["text"])["exit_code"] == 2
    assert peer.closed


@pytest.mark.parametrize(
    "args",
    [
        {"pod": "../escape", "command": ["id"]},
        {"pod": "web", "command": []},
        {"pod": "web", "command": [""]},
        {"pod": "web", "command": ["a\0b"]},
        {"pod": "web", "command": ["id"], "namespace": "other"},
        {"pod": "web", "command": ["id"], "tty": True},
    ],
)
async def test_exec_adapter_invalid_arguments_never_connect(setup_exec, args):
    ctx, peer, connect, *_ = setup_exec()
    with pytest.raises(GatewayError):
        await kubernetes.KubernetesAssetType().pod_exec(ctx, args)
    connect.assert_not_called()


async def test_exec_adapter_respects_resource_kind(setup_exec):
    ctx, peer, connect, *_ = setup_exec()
    ctx.account["policy"]["kinds"] = ["deployments"]
    with pytest.raises(GatewayError) as exc:
        await kubernetes.KubernetesAssetType().pod_exec(ctx, {"pod": "web", "command": ["id"]})
    assert exc.value.code == "KIND_DENIED"
    connect.assert_not_called()
