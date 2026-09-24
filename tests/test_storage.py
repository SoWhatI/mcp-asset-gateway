import asyncio
import hashlib
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet

from app import cli
from app.core.config import Config
from app.core.db import Store, now
from app.core.gateway import Gateway
from app.core.legacy import import_legacy
from app.core.manager import audit
from app.core.security import GatewayError, Vault


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="显式设置 RUN_DOCKER_TESTS=1 才运行隔离容器验收")
def test_docker_container_lifecycle(tmp_path):
    """使用现有镜像及生产 Compose 安全参数，仅创建并清理本测试的独立资源。"""
    root = Path(__file__).resolve().parents[1]
    project = "gateway-smoke-" + secrets.token_hex(6)
    image = os.getenv("GATEWAY_TEST_IMAGE", "mcp-asset-gateway:0.1.0")
    master_key = Fernet.generate_key().decode()
    sensitive = [master_key]

    def command(args, check=True):
        completed = subprocess.run(args, capture_output=True, text=True, timeout=180, cwd=root)
        if check and completed.returncode:
            output = completed.stdout + completed.stderr
            for value in sensitive:
                output = output.replace(value, "[REDACTED]")
            output = re.sub(r"一次性初始密码：[^\r\n]+", "一次性初始密码：[REDACTED]", output)
            pytest.fail("容器验收命令失败：" + output[-3000:], pytrace=False)
        return completed

    model = json.loads(
        command(
            [
                "docker",
                "compose",
                "--env-file",
                os.devnull,
                "-f",
                str(root / "docker-compose.yml"),
                "config",
                "--format",
                "json",
                "--no-env-resolution",
            ]
        ).stdout
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    env_file = tmp_path / "docker.env"
    env_file.write_text(
        f"GATEWAY_MASTER_KEY={master_key}\nGATEWAY_MASTER_KEY_ID=smoke-key\n"
        f"PUBLIC_BASE_URL={url}\nALLOWED_ORIGINS={url}\nALLOWED_HOSTS=127.0.0.1,localhost\n"
        'COOKIE_SECURE=false\nLEGACY_COMPAT=false\nOUTBOUND_ALLOWLIST=[{"host":"db.example.test","port":3306}]\n'
    )
    env_file.chmod(0o600)
    model["name"] = project
    service = model["services"]["gateway"]
    service["image"] = image
    service.pop("build", None)
    service["restart"] = "no"
    service["env_file"] = [{"path": str(env_file), "required": True, "format": "raw"}]
    service["ports"] = [{"target": 8303, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"}]
    for section in ("volumes", "networks"):
        for name, definition in model.get(section, {}).items():
            definition["name"] = f"{project}_{name}"
    compose_file = tmp_path / "compose.json"
    compose_file.write_text(json.dumps(model))
    compose = ["docker", "compose", "-p", project, "-f", str(compose_file)]
    command([*compose, "config", "--quiet"])
    command(["docker", "image", "inspect", image])
    try:
        initialized = command(
            [
                *compose,
                "run",
                "--rm",
                "-T",
                "--no-deps",
                "gateway",
                "python",
                "-m",
                "app.cli",
                "init-admin",
                "--generate-password",
            ]
        )
        password = re.search(r"一次性初始密码：([^\r\n]+)", initialized.stdout).group(1)
        sensitive.append(password)
        command([*compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "90", "gateway"])
        container = command([*compose, "ps", "-q", "gateway"]).stdout.strip()
        inspect = json.loads(command(["docker", "inspect", container]).stdout)[0]
        host = inspect["HostConfig"]
        assert inspect["Config"]["User"] == "10001:10001"
        assert inspect["State"]["Health"]["Status"] == "healthy"
        assert host["ReadonlyRootfs"] and host["Init"]
        assert host["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in host["SecurityOpt"]
        assert host["Memory"] == 1073741824 and host["NanoCpus"] == 2000000000
        assert host["PidsLimit"] == 128
        assert "noexec" in host["Tmpfs"]["/tmp"]
        assert all(p["HostIp"] == "127.0.0.1" for p in host["PortBindings"]["8303/tcp"])
        assert all(m["Name"].startswith(project + "_") for m in inspect["Mounts"] if m["Type"] == "volume")
        probe = (
            "import os,errno; from pathlib import Path; "
            "assert os.getuid()==10001; assert not Path('/app/.env').exists(); "
            "assert os.stat('/app/data/gateway.db').st_mode & 0o077 == 0\n"
            "try:\n Path('/app/write-probe').write_text('test')\n"
            "except OSError as e:\n assert e.errno in (errno.EROFS,errno.EACCES)\n"
            "else:\n raise AssertionError('根文件系统可写')\n"
        )
        command([*compose, "exec", "-T", "gateway", "python", "-c", probe])
        locked = command(
            [
                *compose,
                "run",
                "--rm",
                "-T",
                "--no-deps",
                "gateway",
                "python",
                "-m",
                "app.cli",
                "migrate",
            ],
            check=False,
        )
        assert locked.returncode != 0 and "已有运行实例" in locked.stderr
        print("Docker 安全参数、健康检查、文件权限及维护锁：通过")

        with httpx.Client(base_url=url, headers={"Origin": url}, trust_env=False, timeout=15) as client:

            def login():
                response = client.post("/api/auth/login", json={"username": "admin", "password": password})
                assert response.status_code == 200
                client.headers["X-CSRF-Token"] = client.cookies["gateway_csrf"]

            def save(table, value):
                response = client.post("/api/" + table, json=value)
                assert response.status_code == 200
                return response.json()["data"]

            def rpc(token, method, params=None):
                return client.post(
                    "/mcp",
                    headers={"Authorization": "Bearer " + token},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": method,
                        "params": params or {},
                    },
                )

            for path in ("/", "/health", "/ready"):
                assert client.get(path).status_code == 200
            html = client.get("/").text
            assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
            assert assets
            assert all(client.get(path).status_code == 200 for path in assets)
            assert client.get("/api/assets").status_code == 401
            login()
            assert client.post("/api/clients", json={}, headers={"X-CSRF-Token": ""}).status_code == 403
            save("assets", {"id": "db", "name": "容器验收", "type": "mysql", "connection": {"host": "db.example.test"}})
            assert client.patch("/api/assets/db", json={"revision": 1, "name": "更新后的容器资产"}).status_code == 200
            save("clients", {"id": "temporary", "name": "临时客户端"})
            assert client.patch("/api/clients/temporary", json={"revision": 1, "enabled": False}).status_code == 200
            assert client.delete("/api/clients/temporary", params={"revision": 2}).status_code == 200
            assert client.get("/api/clients/temporary").status_code == 404
            credential = secrets.token_urlsafe(24)
            sensitive.append(credential)
            save(
                "accounts",
                {
                    "id": "reader",
                    "name": "只读账号",
                    "asset_id": "db",
                    "config": {"username": "reader", "database": "demo"},
                    "credential": {"password": credential},
                },
            )
            token = save("clients", {"id": "agent", "name": "授权客户端"})["token"]
            other = save("clients", {"id": "other", "name": "未授权客户端"})["token"]
            sensitive.extend((token, other))
            save("grants", {"client_ids": ["agent"], "account_ids": ["reader"], "tools": ["list_tables"]})
            assert (
                rpc(token, "initialize", {"protocolVersion": "2025-03-26"}).json()["result"]["protocolVersion"]
                == "2025-03-26"
            )
            assert [t["name"] for t in rpc(token, "tools/list").json()["result"]["tools"]] == ["list_tables"]
            assert rpc(other, "tools/list").json()["result"]["tools"] == []
            assert rpc(other, "tools/call", {"name": "list_tables"}).json()["result"]["isError"]
            assert client.get("/api/dashboard").json()["data"]["calls"]["statuses"]["denied"] == 1
            exported = client.get("/api/audit/export")
            assert exported.status_code == 200 and exported.content.startswith(b"\xef\xbb\xbf")
            for value in sensitive:
                assert value not in exported.text
            assert "credential_ciphertext" not in client.get("/api/accounts").text
            print("容器 HTTP、静态资源、登录/CSRF、CRUD、MCP 隔离与 CSV：通过")

            command(
                [*compose, "exec", "-T", "gateway", "python", "-m", "app.cli", "backup", "/app/backups/smoke.sqlite"]
            )
            backup_check = (
                "from app.core.db import Store; from app.core.config import Config; from app.core.security import Vault; "
                "s=Store('/app/backups/smoke.sqlite'); c=Config.from_env(); v=Vault(c.master_key,c.key_id)\n"
                "with s.connect() as db:\n"
                " assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'\n"
                " assert db.execute('SELECT count(*) FROM grants').fetchone()[0]==1\n"
                " row=db.execute('SELECT credential_ciphertext,credential_key_id FROM accounts').fetchone()\n"
                " assert v.decrypt(*row)['password']\n"
            )
            command([*compose, "exec", "-T", "gateway", "python", "-c", backup_check])
            save(
                "assets",
                {
                    "id": "after-backup",
                    "name": "备份后的标记",
                    "type": "mysql",
                    "connection": {"host": "db.example.test"},
                },
            )
            command(
                [*compose, "up", "-d", "--force-recreate", "--no-build", "--wait", "--wait-timeout", "90", "gateway"]
            )
            replacement = command([*compose, "ps", "-q", "gateway"]).stdout.strip()
            assert replacement != container
            client.cookies.clear()
            login()
            assert client.get("/api/assets/db").json()["data"]["name"] == "更新后的容器资产"
            assert client.get("/api/clients/temporary").status_code == 404
            assert client.get("/api/accounts/reader").json()["data"]["credential_present"]
            assert len(rpc(token, "tools/list").json()["result"]["tools"]) == 1
            assert rpc(other, "tools/list").json()["result"]["tools"] == []
            assert client.get("/api/audit", params={"event": "tools.call", "status": "denied"}).json()["data"]["items"]
            print("在线备份完整性/解密与重建容器后的账号、token、授权、审计持久化：通过")

        command([*compose, "stop", "gateway"])
        restored = json.loads(json.dumps(service))
        restored["volumes"] = [
            {"type": "volume", "source": "restore-data", "target": "/app/data"},
            {"type": "volume", "source": "gateway-backups", "target": "/source", "read_only": True},
        ]
        model["services"]["restored"] = restored
        model["volumes"]["restore-data"] = {"name": project + "_restore-data"}
        compose_file.write_text(json.dumps(model))
        copy_backup = (
            "import os,shutil; from pathlib import Path; "
            "assert not Path('/app/data/gateway.db').exists(); "
            "shutil.copyfile('/source/smoke.sqlite','/app/data/gateway.db'); "
            "os.chmod('/app/data/gateway.db',0o600)"
        )
        command([*compose, "run", "--rm", "-T", "--no-deps", "restored", "python", "-c", copy_backup])
        for _ in range(2):
            command([*compose, "run", "--rm", "-T", "--no-deps", "restored", "python", "-m", "app.cli", "migrate"])
        command([*compose, "up", "-d", "--no-deps", "--no-build", "--wait", "--wait-timeout", "90", "restored"])
        with httpx.Client(base_url=url, headers={"Origin": url}, trust_env=False, timeout=15) as client:
            login()
            assert client.get("/api/assets/db").json()["data"]["name"] == "更新后的容器资产"
            assert client.get("/api/assets/after-backup").status_code == 404
            assert client.get("/api/accounts/reader").json()["data"]["credential_present"]
            assert [t["name"] for t in rpc(token, "tools/list").json()["result"]["tools"]] == ["list_tables"]
            assert rpc(other, "tools/list").json()["result"]["tools"] == []
            assert client.get("/api/audit", params={"event": "tools.call", "status": "denied"}).json()["data"]["items"]
        command(
            [
                *compose,
                "exec",
                "-T",
                "restored",
                "python",
                "-c",
                backup_check.replace("/app/backups/smoke.sqlite", "/app/data/gateway.db"),
            ]
        )
        command([*compose, "stop", "restored"])
        print("独立空卷恢复备份、两次离线迁移、凭据解密与 HTTP/MCP 授权复验：通过")
        for setting, message in [
            ("GATEWAY_MASTER_KEY=", "必须配置 GATEWAY_MASTER_KEY"),
            ("GATEWAY_MASTER_KEY_ID=wrong-key", "凭据密钥版本不匹配"),
        ]:
            rejected = command([*compose, "run", "--rm", "-T", "--no-deps", "-e", setting, "gateway"], check=False)
            assert rejected.returncode != 0 and message in rejected.stdout + rejected.stderr
        print("容器缺失主密钥及错误密钥 ID 拒绝启动：通过")
    finally:
        command([*compose, "down", "--volumes", "--timeout", "45"])
        print("已清理本次独立 Compose 项目的容器、网络和临时数据卷；保留构建镜像")


def test_migrations_lock_and_restart(config):
    store = Store(config.database)
    store.acquire()
    try:
        store.migrate()
        with pytest.raises(RuntimeError, match="已有运行实例"):
            Store(config.database).acquire()
        with store.connect(write=True) as conn:
            audit(conn, "tools.call", source="mcp", status="started", request_id="interrupted-call")
        store.migrate()
        with store.connect() as conn:
            assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 8
            assert (
                conn.execute("SELECT status FROM audit_log WHERE request_id='interrupted-call'").fetchone()[0]
                == "interrupted"
            )
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with store.connect(write=True) as conn:
            conn.execute("INSERT INTO schema_migrations VALUES (999,'future',0)")
        with pytest.raises(RuntimeError, match="高于"):
            store.migrate()
    finally:
        store.release()


@pytest.mark.parametrize("start_version", [1, 2])
def test_grant_group_migration_preserves_members_and_permissions(tmp_path, start_version):
    folder = Path(__file__).resolve().parents[1] / "app/core/migrations"
    store = Store(tmp_path / "upgrade.sqlite")
    with closing(sqlite3.connect(store.path)) as conn:
        conn.executescript((folder / "001.sql").read_text())
        conn.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT,applied_at INTEGER)")
        conn.execute(
            "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at) VALUES('db','资产','mysql','{}',1,1)"
        )
        for member in ("first", "second"):
            conn.execute(
                "INSERT INTO clients(id,name,token_hash,token_tail,created_at,updated_at) VALUES(?,?,?,'tail',1,1)",
                (member, member, member),
            )
            conn.execute(
                "INSERT INTO accounts(id,asset_id,name,config_json,created_at,updated_at) VALUES(?,'db',?,'{}',1,1)",
                (member, member),
            )
        conn.execute(
            "INSERT INTO grants VALUES('historical','first','first','[\"lookup\"]','{\"lookup\":\"hash\"}',0,7,1,2)"
        )
        conn.commit()
        if start_version == 2:
            conn.executescript((folder / "002.sql").read_text())
            conn.execute("INSERT INTO grant_targets VALUES('historical','first','second')")
            conn.execute("INSERT INTO grant_targets VALUES('historical','second','first')")
            conn.execute("INSERT INTO grant_targets VALUES('historical','second','second')")
        for version in range(1, start_version + 1):
            checksum = hashlib.sha256((folder / f"{version:03}.sql").read_bytes()).hexdigest()
            conn.execute("INSERT INTO schema_migrations VALUES(?,?,1)", (version, checksum))
        conn.commit()
    store.migrate()
    store.migrate()
    with store.connect() as conn:
        group = dict(conn.execute("SELECT * FROM grants").fetchone())
        assert group["name"] == "迁移授权组 1"
        assert (group["revision"], group["enabled"], group["created_at"], group["updated_at"]) == (7, 0, 1, 2)
        assert json.loads(group["tools_json"]) == ["lookup"]
        assert json.loads(group["tool_versions_json"]) == {"first": {"lookup": "hash"}}
        expected = {"first", "second"} if start_version == 2 else {"first"}
        assert {r[0] for r in conn.execute("SELECT client_id FROM grant_clients")} == expected
        assert {r[0] for r in conn.execute("SELECT account_id FROM grant_accounts")} == expected
        # 004：组级工具白名单平铺复制到每个账号条目，权限保持不变。
        assert all(json.loads(r[0]) == ["lookup"] for r in conn.execute("SELECT tools_json FROM grant_accounts"))
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name='grant_targets'").fetchall()
    with store.connect(write=True) as conn:
        conn.execute("INSERT INTO grants(id,name,tools_json,created_at,updated_at) VALUES('overlap','重复组','[]',1,1)")
        conn.execute("INSERT INTO grant_clients(grant_id,client_id) VALUES('overlap','first')")
        conn.execute("INSERT INTO grant_accounts(grant_id,account_id,tools_json) VALUES('overlap','first','[]')")
        for table, columns, values in (
            ("grant_clients", "(grant_id,client_id)", "('overlap','first')"),
            ("grant_accounts", "(grant_id,account_id,tools_json)", "('overlap','first','[]')"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(f"INSERT INTO {table} {columns} VALUES{values}")
        for kind in ("clients", "accounts"):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(f"DELETE FROM {kind} WHERE id='first'")
        conn.execute("DELETE FROM grants WHERE id='historical'")
        assert conn.execute("SELECT count(*) FROM grant_clients").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM grant_accounts").fetchone()[0] == 1


def test_asset_type_migration_allows_new_kinds(tmp_path):
    folder = Path(__file__).resolve().parents[1] / "app/core/migrations"
    store = Store(tmp_path / "types.sqlite")
    with closing(sqlite3.connect(store.path)) as conn:
        conn.executescript((folder / "001.sql").read_text())
        conn.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT,applied_at INTEGER)")
        for version in range(2, 5):
            conn.executescript((folder / f"{version:03}.sql").read_text())
        for version in range(1, 5):
            checksum = hashlib.sha256((folder / f"{version:03}.sql").read_bytes()).hexdigest()
            conn.execute("INSERT INTO schema_migrations VALUES(?,?,1)", (version, checksum))
        conn.execute(
            "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at)"
            " VALUES('db','旧资产','mysql','{}',1,1)"
        )
        conn.execute(
            "INSERT INTO accounts(id,asset_id,name,config_json,created_at,updated_at)"
            " VALUES('acct','db','账号','{}',1,1)"
        )
        conn.commit()
    store.migrate()
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 8
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()
    with store.connect(write=True) as conn:
        # 005/006 重建 assets 后，accounts.asset_id 的外键仍指向重建后的表。
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM assets WHERE id='db'")
        for asset_id, kind in (("cache", "redis"), ("cluster", "kubernetes"), ("code", "gitrepo"), ("ci", "jenkins")):
            conn.execute(
                "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at) VALUES(?,?,?,'{}',1,1)",
                (asset_id, kind, kind),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at)"
                " VALUES('bad','非法','telnet','{}',1,1)"
            )


def test_ssh_parameter_rule_migration_does_not_expand_permissions(tmp_path):
    folder = Path(__file__).resolve().parents[1] / "app/core/migrations"
    store = Store(tmp_path / "ssh-upgrade.sqlite")
    with closing(sqlite3.connect(store.path)) as conn:
        conn.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT,applied_at INTEGER)")
        for version in range(1, 7):
            script = folder / f"{version:03}.sql"
            conn.executescript(script.read_text())
            conn.execute(
                "INSERT INTO schema_migrations VALUES(?,?,1)",
                (version, hashlib.sha256(script.read_bytes()).hexdigest()),
            )
            conn.commit()
        for kind in ("ssh", "mysql"):
            conn.execute(
                "INSERT INTO assets(id,name,type,connection_json,created_at,updated_at) VALUES(?,?,?,'{}',1,1)",
                (kind, kind, kind),
            )
        policies = {
            "fixed": {
                "command_allowlist": ["/usr/bin/id", "/bin/uname -a", " /usr/bin/ps    * ", "/usr/bin/ps ~"],
                "max_output_bytes": 2048,
            },
            "empty": {"command_allowlist": []},
            "missing": {},
            "mysql": {},
        }
        for identity, policy in policies.items():
            conn.execute(
                "INSERT INTO accounts(id,asset_id,name,config_json,policy_json,created_at,updated_at) VALUES(?,?,?,'{}',?,1,1)",
                (identity, "mysql" if identity == "mysql" else "ssh", identity, json.dumps(policy)),
            )
        for group, enabled in (("active", 1), ("disabled", 0)):
            conn.execute(
                "INSERT INTO grants(id,name,tools_json,enabled,revision,created_at,updated_at) VALUES(?,?,?, ?,4,1,1)",
                (group, group, '["exec_command","list_tables"]', enabled),
            )
            for identity in policies:
                tools = '["list_tables"]' if identity == "mysql" else '["exec_command"]'
                conn.execute(
                    "INSERT INTO grant_accounts(grant_id,account_id,tools_json) VALUES(?,?,?)", (group, identity, tools)
                )
        conn.commit()
    store.migrate()
    store.migrate()
    with store.connect() as conn:
        for row in conn.execute("SELECT * FROM grant_accounts"):
            rules = json.loads(row["parameter_rules_json"])
            if row["account_id"] == "fixed":
                assert rules == {
                    "exec_command": {
                        "cmd": {
                            "allow": [
                                {"match": "exact", "value": value}
                                for value in ["/usr/bin/id", "/bin/uname -a", "/usr/bin/ps '*'", "/usr/bin/ps '~'"]
                            ]
                        }
                    }
                }
                assert json.loads(row["tools_json"]) == ["exec_command"]
            else:
                assert rules == {}
                assert json.loads(row["tools_json"]) == (["list_tables"] if row["account_id"] == "mysql" else [])
        for row in conn.execute("SELECT * FROM accounts"):
            assert "command_allowlist" not in json.loads(row["policy_json"])
            assert row["revision"] == (1 if row["id"] == "mysql" else 2)
        assert json.loads(conn.execute("SELECT policy_json FROM accounts WHERE id='fixed'").fetchone()[0]) == {
            "max_output_bytes": 2048
        }
        assert all(row[0] == 5 for row in conn.execute("SELECT revision FROM grants"))
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()


def test_backup_roundtrip_and_missing_source(app, seeded, tmp_path):
    store = app.state.gateway.store
    backup = tmp_path / "backups" / "snapshot.sqlite"
    store.backup(backup)
    assert backup.stat().st_mode & 0o077 == 0
    with closing(sqlite3.connect(backup)) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT count(*) FROM grants").fetchone()[0] == 1
        row = conn.execute("SELECT credential_ciphertext,credential_key_id FROM accounts").fetchone()
        assert app.state.gateway.vault.decrypt(*row)["password"] == "remote-test-password"
    with pytest.raises(ValueError):
        store.backup(backup)
    missing = Store(tmp_path / "missing.sqlite")
    with pytest.raises(sqlite3.OperationalError):
        missing.backup(tmp_path / "bad-backup.sqlite")
    assert not missing.path.exists()


def test_recovery_does_not_interrupt_active_calls(app, seeded):
    gateway = app.state.gateway
    with gateway.store.connect(write=True) as conn:
        audit(conn, "tools.call", status="started", request_id="active")
        audit(conn, "tools.call", status="started", request_id="orphan")
    gateway.audit_failed = True
    gateway.maintain_db(("active",))
    with gateway.store.connect() as conn:
        statuses = dict(conn.execute("SELECT request_id,status FROM audit_log WHERE request_id IN ('active','orphan')"))
    assert statuses == {"active": "started", "orphan": "interrupted"}
    assert not gateway.audit_failed


def test_retention_is_bounded_and_preserves_started(app, seeded):
    gateway = app.state.gateway
    with gateway.store.connect(write=True) as conn:
        conn.execute("UPDATE settings SET value_json='1' WHERE key='audit_retention_days'")
        old = now() - 2 * 86400000
        conn.executemany(
            "INSERT INTO audit_log(request_id,ts,source,event,actor_type,status) VALUES(?,?,'mcp','tools.call','client','ok')",
            [(f"old-{i}", old) for i in range(1005)],
        )
        audit(conn, "tools.call", request_id="still-running", status="started")
        conn.execute("UPDATE audit_log SET ts=? WHERE request_id='still-running'", (old,))
        conn.execute("UPDATE admin_sessions SET expires_at=?", (old,))
    gateway.maintain_db(("still-running",))
    with gateway.store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM audit_log WHERE request_id LIKE 'old-%'").fetchone()[0] == 5
        assert conn.execute("SELECT status FROM audit_log WHERE request_id='still-running'").fetchone()[0] == "started"
        assert conn.execute("SELECT count(*) FROM admin_sessions").fetchone()[0] == 0
    gateway.maintain_db(("still-running",))
    with gateway.store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM audit_log WHERE request_id LIKE 'old-%'").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM audit_log WHERE event='audit.retention'").fetchone()[0] == 2


def test_recovery_write_failure_keeps_audit_latch(app, seeded, monkeypatch):
    gateway = app.state.gateway
    gateway.audit_failed = True

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("simulated disk full")

    with monkeypatch.context() as patch:
        patch.setattr(gateway.store, "connect", unavailable)
        with pytest.raises(sqlite3.OperationalError):
            gateway.maintain_db()
        assert gateway.audit_failed
    gateway.maintain_db()
    assert not gateway.audit_failed


async def test_cancelled_database_worker_retains_slot(config):
    gateway = Gateway(config)
    gate, entered = threading.Event(), threading.Event()

    def work():
        entered.set()
        gate.wait(3)

    task = asyncio.create_task(gateway.db(work))
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert gateway.db_slots._value == 63
        gate.set()
        for _ in range(100):
            if gateway.db_slots._value == 64:
                break
            await asyncio.sleep(0.01)
        assert gateway.db_slots._value == 64
    finally:
        gate.set()
        await gateway.stop()


@pytest.fixture
def rotation_case(app, seeded, config, tmp_path, monkeypatch):
    seeded["save"](
        "accounts",
        {
            "id": "ro2",
            "name": "禁用账号仍需轮换",
            "asset_id": "db",
            "enabled": False,
            "config": {"username": "reader", "database": "demo"},
            "credential": {"password": "second-test-only"},
        },
    )
    seeded["save"](
        "assets",
        {"id": "upstream", "name": "上游", "type": "mcp", "connection": {"url": "https://mcp.example.test/mcp"}},
    )
    seeded["save"](
        "accounts", {"id": "anonymous", "name": "无凭据", "asset_id": "upstream", "config": {"auth_mode": "none"}}
    )
    database = tmp_path / "offline.sqlite"
    app.state.gateway.store.backup(database)
    offline = replace(config, database=str(database))
    key = Fernet.generate_key().decode()
    key_file = tmp_path / "new.key"
    key_file.write_text(key)
    key_file.chmod(0o600)
    backup = tmp_path / "before.sqlite"
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    monkeypatch.setattr(Config, "from_env", classmethod(lambda cls: offline))
    monkeypatch.setattr(
        sys,
        "argv",
        ["gateway", "rotate-key", "--key-file", str(key_file), "--key-id", "next-key", "--backup", str(backup)],
    )
    return {"config": offline, "store": Store(database), "key": key, "file": key_file, "backup": backup}


async def test_key_rotation_roundtrip_and_backup(rotation_case, capsys):
    case = rotation_case
    cli.main()
    output = capsys.readouterr().out
    assert case["key"] not in output and case["config"].master_key not in output
    assert case["backup"].stat().st_mode & 0o077 == 0
    old = Vault(case["config"].master_key, case["config"].key_id)
    new = Vault(case["key"], "next-key")
    with case["store"].connect() as conn:
        rows = conn.execute("SELECT * FROM accounts WHERE credential_ciphertext IS NOT NULL ORDER BY id").fetchall()
        assert len(rows) == 2
        for row in rows:
            assert new.decrypt(row["credential_ciphertext"], row["credential_key_id"])["password"]
            assert row["revision"] == 2
            with pytest.raises(GatewayError):
                old.decrypt(row["credential_ciphertext"], row["credential_key_id"])
        assert conn.execute("SELECT credential_key_id FROM accounts WHERE id='anonymous'").fetchone()[0] is None
        assert conn.execute("SELECT count(*) FROM audit_log WHERE event='credentials.rotate-key'").fetchone()[0] == 1
    with Store(case["backup"]).connect() as conn:
        row = conn.execute("SELECT credential_ciphertext,credential_key_id FROM accounts WHERE id='ro'").fetchone()
        assert old.decrypt(*row)["password"] == "remote-test-password"
    gateway = Gateway(replace(case["config"], master_key=case["key"], key_id="next-key"))
    try:
        await gateway.start()
        gateway.manager.check_all_credentials()
    finally:
        await gateway.stop()


@pytest.mark.parametrize("failure", ["encrypt", "verify", "audit", "backup"])
def test_key_rotation_failure_rolls_back(rotation_case, monkeypatch, failure):
    case = rotation_case
    with case["store"].connect() as conn:
        before = [tuple(row) for row in conn.execute("SELECT * FROM accounts ORDER BY id")]
    original_encrypt, original_decrypt = Vault.encrypt, Vault.decrypt
    calls = []

    def encrypt(self, value):
        if self.key_id == "next-key":
            calls.append(True)
            if len(calls) == 2:
                raise RuntimeError("模拟第二条凭据加密失败")
        return original_encrypt(self, value)

    def decrypt(self, value, key_id):
        if self.key_id == "next-key":
            raise RuntimeError("模拟提交前复验失败")
        return original_decrypt(self, value, key_id)

    def fail(*args, **kwargs):
        raise RuntimeError("模拟持久化失败")

    if failure == "encrypt":
        monkeypatch.setattr(Vault, "encrypt", encrypt)
    elif failure == "verify":
        monkeypatch.setattr(Vault, "decrypt", decrypt)
    elif failure == "audit":
        monkeypatch.setattr(cli, "audit", fail)
    else:
        monkeypatch.setattr(Store, "backup", fail)
    with pytest.raises(RuntimeError, match="模拟"):
        cli.main()
    with case["store"].connect() as conn:
        assert [tuple(row) for row in conn.execute("SELECT * FROM accounts ORDER BY id")] == before
        assert conn.execute("SELECT count(*) FROM audit_log WHERE event='credentials.rotate-key'").fetchone()[0] == 0
    case["store"].acquire()
    case["store"].release()


@pytest.mark.parametrize(
    "invalid", ["permissions", "symlink", "directory", "format", "same-key", "same-id", "empty-id"]
)
def test_key_rotation_rejects_unsafe_inputs(rotation_case, monkeypatch, invalid):
    case = rotation_case
    if invalid == "permissions":
        case["file"].chmod(0o644)
    elif invalid == "symlink":
        link = case["file"].with_name("link.key")
        link.symlink_to(case["file"])
        monkeypatch.setattr(sys, "argv", [*sys.argv[:3], str(link), *sys.argv[4:]])
    elif invalid == "directory":
        monkeypatch.setattr(sys, "argv", [*sys.argv[:3], str(case["file"].parent), *sys.argv[4:]])
    elif invalid == "format":
        case["file"].write_text("invalid-key")
    elif invalid == "same-key":
        case["file"].write_text(case["config"].master_key)
    else:
        monkeypatch.setattr(
            sys, "argv", [*sys.argv[:5], case["config"].key_id if invalid == "same-id" else "", *sys.argv[6:]]
        )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert not case["backup"].exists()
    with case["store"].connect() as conn:
        assert (
            conn.execute("SELECT credential_key_id FROM accounts WHERE id='ro'").fetchone()[0] == case["config"].key_id
        )


def test_key_rotation_refuses_running_instance(rotation_case):
    store = rotation_case["store"]
    store.acquire()
    try:
        with pytest.raises(RuntimeError, match="已有运行实例"):
            cli.main()
        assert not rotation_case["backup"].exists()
    finally:
        store.release()


@pytest.mark.parametrize("wrong", ["key", "id", "ciphertext"])
async def test_startup_rejects_invalid_credentials(rotation_case, wrong):
    case = rotation_case
    config = case["config"]
    if wrong == "key":
        config = replace(config, master_key=Fernet.generate_key().decode())
    elif wrong == "id":
        config = replace(config, key_id="wrong-id")
    else:
        with case["store"].connect(write=True) as conn:
            conn.execute("UPDATE accounts SET credential_ciphertext='corrupt' WHERE id='ro'")
    gateway = Gateway(config)
    try:
        with pytest.raises(GatewayError):
            await gateway.start()
        assert gateway.store.lock is None
    finally:
        await gateway.stop()


def test_master_key_missing_or_malformed(config, monkeypatch):
    monkeypatch.delenv("GATEWAY_MASTER_KEY", raising=False)
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8303")
    with pytest.raises(ValueError, match="GATEWAY_MASTER_KEY"):
        Config.from_env()
    with pytest.raises(ValueError):
        Gateway(replace(config, master_key="invalid-key"))


async def test_legacy_import_once_and_no_token_resurrection(config, monkeypatch):
    for key, value in {
        "AGENT_TOKEN": "legacy-test-token-only",
        "DB_HOST": "db.example.test",
        "DB_NAME": "demo",
        "DB_USER": "reader",
        "DB_PASSWORD": "legacy-test-password-only",
    }.items():
        monkeypatch.setenv(key, value)
    gateway = Gateway(replace(config, legacy=True))
    await gateway.start()
    try:
        client = gateway.manager.client(token="legacy-test-token-only")
        assert client["compatibility_mode"] == "legacy_mysql"
        new = gateway.manager.rotate(client["id"], client["revision"], {"id": "test-admin"})
        import_legacy(gateway)
        with pytest.raises(GatewayError):
            gateway.manager.client(token="legacy-test-token-only")
        assert gateway.manager.client(token=new["token"])["id"] == client["id"]
    finally:
        await gateway.stop()


async def test_legacy_partial_import_rolls_back(config, monkeypatch):
    gateway = Gateway(config)
    await gateway.start()
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    try:
        with pytest.raises(GatewayError):
            import_legacy(gateway)
        with gateway.store.connect() as conn:
            assert conn.execute("SELECT count(*) FROM clients").fetchone()[0] == 0
            assert "legacy_import_completed" not in gateway.store.settings(conn)
    finally:
        await gateway.stop()


async def test_per_client_capacity_survives_timeout(config, monkeypatch):
    from app.asset_types.base import result

    gateway = Gateway(config)
    await gateway.start()
    actor = {"id": "test"}
    manager = gateway.manager
    manager.save(
        "assets", {"id": "db", "name": "db", "type": "mysql", "connection": {"host": "db.example.test"}}, actor
    )
    manager.save(
        "accounts",
        {
            "id": "ro",
            "name": "ro",
            "asset_id": "db",
            "config": {"username": "reader", "database": "demo"},
            "credential": {"password": "test-only"},
            "policy": {"query_timeout_seconds": 1},
        },
        actor,
    )
    created = manager.save("clients", {"id": "agent", "name": "agent"}, actor)
    manager.save("grants", {"client_ids": ["agent"], "account_ids": ["ro"], "tools": ["list_tables"]}, actor)
    client = manager.client(token=created["token"])
    gate = threading.Event()

    def work(*args):
        gate.wait(5)
        return result({})

    monkeypatch.setattr(gateway.types["mysql"], "execute_sync", work)
    try:
        responses = await asyncio.gather(*(gateway.call(client, "list_tables", {}) for _ in range(4)))
        assert all(r["isError"] for r in responses)
        assert gateway.client_slots["agent"]._value == 0
        assert gateway.slots._value == 12
        gate.set()
        for _ in range(100):
            if gateway.client_slots["agent"]._value == 4:
                break
            await asyncio.sleep(0.01)
        assert gateway.client_slots["agent"]._value == 4
        assert gateway.slots._value == 16
    finally:
        gate.set()
        await gateway.stop()
