import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.core.config import Config
from app.main import create_app


@pytest.fixture
def config(tmp_path):
    # 测试基线走严格模式（出站登记非空 + 指纹校验开启）；生产默认值由 Config.from_env 决定。
    return Config(
        database=str(tmp_path / "data" / "gateway.db"),
        master_key=Fernet.generate_key().decode(),
        key_id="test-key",
        public_url="http://testserver",
        secure_cookie=False,
        hosts=("testserver", "127.0.0.1"),
        origins=("http://testserver",),
        outbound=(
            {"host": "db.example.test", "port": 3306},
            {"host": "ssh.example.test", "port": 22},
            {"host": "mcp.example.test", "port": 443},
            {"host": "cache.example.test", "port": 6379},
            {"host": "k8s.example.test", "port": 6443},
        ),
        ssh_host_key_enforce=True,
    )


@pytest.fixture
def app(config):
    return create_app(config)


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        app.state.gateway.manager.init_admin("admin", "test-password-only-2026")
        yield client


@pytest.fixture
def admin(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "test-password-only-2026"},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200, response.text
    client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": client.cookies["gateway_csrf"]})
    return client


@pytest.fixture
def seeded(admin, app):
    def save(table, value):
        response = admin.post("/api/" + table, json=value)
        assert response.status_code == 200, response.text
        return response.json()["data"]

    asset = save(
        "assets", {"id": "db", "name": "测试数据库", "type": "mysql", "connection": {"host": "db.example.test"}}
    )
    account = save(
        "accounts",
        {
            "id": "ro",
            "name": "只读账号",
            "asset_id": "db",
            "config": {"username": "reader", "database": "demo"},
            "credential": {"password": "remote-test-password"},
            "policy": {},
        },
    )
    identity = save("clients", {"id": "agent", "name": "测试智能体"})
    grant = save(
        "grants",
        {"client_ids": ["agent"], "account_ids": ["ro"], "tools": ["list_tables", "execute_query"]},
    )
    return {"asset": asset, "account": account, "client": identity, "grant": grant, "save": save}


def rpc(client, token, method, params=None, **extra):
    return client.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}, **extra},
    )
