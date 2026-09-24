"""显式开启的本地真实服务验收，不访问生产资源。"""

import concurrent.futures
import copy
import hashlib
import json
import os
import socket
import ssl
import statistics
import time

import httpx
import pytest
from local_stack import LocalStack, private_file

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LOCAL_E2E") != "1", reason="需要 RUN_LOCAL_E2E=1 和 LOCAL_E2E_STATE 指定隔离环境"
)


@pytest.fixture(scope="module")
def stack():
    value = LocalStack(os.environ["LOCAL_E2E_STATE"])
    assert value.state["project"].startswith("gateway-e2e-")
    return value


@pytest.fixture
def admin(stack):
    with stack.admin() as client:
        yield client


def rpc(stack, method, params=None, identity="agent-a", client=None):
    def send(current):
        response = current.post(
            "/mcp",
            headers={"Authorization": "Bearer " + stack.state["secrets"][identity]},
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        )
        assert response.status_code == 200, response.text
        value = response.json()
        assert "error" not in value, value
        return value["result"]

    if client is not None:
        return send(client)
    with stack.http() as current:
        return send(current)


def call(stack, name, arguments=None, identity="agent-a", client=None, error=False):
    value = rpc(stack, "tools/call", {"name": name, "arguments": arguments or {}}, identity, client)
    assert bool(value.get("isError")) == error, value
    text = value["content"][0]["text"]
    try:
        return json.loads(text)
    except ValueError:
        return text


def test_local_tls_and_management(stack):
    with pytest.raises(httpx.ConnectError):
        httpx.get(stack.url + "/ready", trust_env=False)
    with stack.http() as client:
        assert client.get("/ready").status_code == 200
        assert client.get("/api/assets").status_code == 401
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": stack.state["secrets"]["admin"]}
        )
        assert response.status_code == 200
        cookies = response.headers.get_list("set-cookie")
        assert len(cookies) == 2 and all("Secure" in cookie and "SameSite=strict" in cookie for cookie in cookies)
        assert "HttpOnly" in cookies[0]
        assert client.post("/api/clients", json={"id": "csrf-probe", "name": "拒绝"}).status_code == 403
        assert client.get("/ready", headers={"Host": "untrusted.invalid"}).status_code == 403
        assert client.get("/ready", headers={"Origin": "https://untrusted.invalid"}).status_code == 403
    redirect = httpx.get(f"http://127.0.0.1:{stack.state['ports']['http']}/mcp", trust_env=False)
    assert redirect.status_code == 308 and redirect.headers["location"] == stack.url + "/mcp"
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context = ssl.create_default_context(cafile=str(stack.folder / "tls/ca.pem"))
        context.minimum_version = context.maximum_version = version
        with socket.create_connection(("127.0.0.1", stack.state["ports"]["tls"])) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as stream:
                assert stream.version() == ("TLSv1.2" if version == ssl.TLSVersion.TLSv1_2 else "TLSv1.3")
    inspection = json.loads(stack.dc("ps", "--format", "json", "gateway").stdout)
    assert all(item["PublishedPort"] == 0 for item in inspection.get("Publishers", []))


def test_local_mysql_permissions_and_isolation(stack, admin):
    for identity in ("reader-a", "reader-b"):
        response = admin.post(f"/api/accounts/{identity}/test", json={})
        assert response.status_code == 200 and response.json()["data"]["reachable"], response.text
    assert call(stack, "list_tables")["tables"][0]["table"] == "records"
    assert call(stack, "list_tables", identity="agent-b")["tables"][0]["table"] == "secrets"
    assert call(stack, "describe_table", {"table": "records"})["columns"][0]["name"] == "id"
    query = call(stack, "execute_query", {"sql": "SELECT * FROM records ORDER BY id", "max_rows": 1})
    assert query["rows"] == [[1, "tenant-a"]] and query["truncated"]
    assert call(stack, "execute_query", {"sql": "SELECT * FROM tenant_b.secrets"}, error=True)
    assert call(stack, "execute_query", {"sql": "DELETE FROM records"}, error=True)
    assert call(stack, "execute_query", {"sql": "SELECT * FROM records", "target": "reader-b"}, error=True)
    assert rpc(stack, "tools/list", identity="agent-empty")["tools"] == []
    assert call(stack, "list_tables", identity="agent-empty", error=True)


def test_local_ssh_and_sftp(stack, admin):
    for identity in ("shell", "sftp"):
        response = admin.post(f"/api/accounts/{identity}/test", json={})
        assert response.status_code == 200 and response.json()["data"]["reachable"], response.text
    result = call(stack, "exec_command", {"cmd": "/usr/bin/id"})
    assert result["exit_code"] == 0 and "reader" in result["stdout"]
    assert call(stack, "exec_command", {"cmd": "/usr/bin/whoami"}, error=True)
    assert call(stack, "exec_command", {"cmd": "/usr/bin/id; uname"}, error=True)
    listing = call(stack, "list_dir")
    assert {row["path"] for row in listing["items"]} >= {"hello.txt", "binary.bin", "escape"}
    assert call(stack, "read_file", {"path": "hello.txt"})["text"].startswith("本地真实 SFTP")
    assert call(stack, "search_files", {"pattern": "*.txt"})["items"][0]["path"] == "hello.txt"
    for path in ("../etc/passwd", "escape", "binary.bin"):
        assert call(stack, "read_file", {"path": path}, error=True)
    asset = admin.get("/api/assets/host").json()["data"]
    original = asset["connection"]
    try:
        response = admin.patch(
            "/api/assets/host",
            json={"revision": asset["revision"], "connection": {**original, "host_key_sha256": "SHA256:" + "A" * 43}},
        )
        assert response.status_code == 200
        rejected = call(stack, "exec_command", {"cmd": "/usr/bin/id"}, error=True)
        assert rejected["code"] == "HOST_KEY_MISMATCH"
    finally:
        revision = admin.get("/api/assets/host").json()["data"]["revision"]
        assert admin.patch("/api/assets/host", json={"revision": revision, "connection": original}).status_code == 200


def test_local_upstream_and_audit(stack, admin):
    tools = rpc(stack, "tools/list")["tools"]
    names = {t["name"].split("__")[-1]: t["name"] for t in tools if t["name"].startswith("up__")}
    assert {"echo", "slow", "fail"} <= names.keys(), [t["name"] for t in tools]
    assert call(stack, names["echo"], {"message": "全链路验收"}) == "真实上游：全链路验收"
    assert call(stack, names["fail"], error=True)
    assert call(stack, names["echo"], {"message": "禁止"}, identity="agent-b", error=True)
    account = admin.get("/api/accounts/up").json()["data"]
    try:
        assert (
            admin.patch(
                "/api/accounts/up", json={"revision": account["revision"], "policy": {"query_timeout_seconds": 1}}
            ).status_code
            == 200
        )
        timeout = call(stack, names["slow"], {"seconds": 3}, error=True)
        assert timeout["code"] == "TIMEOUT"
    finally:
        current = admin.get("/api/accounts/up").json()["data"]
        assert (
            admin.patch(
                "/api/accounts/up", json={"revision": current["revision"], "policy": account["policy"]}
            ).status_code
            == 200
        )
    rows = admin.get("/api/audit", params={"event": "tools.call", "limit": 100}).json()["data"]["items"]
    assert {r["status"] for r in rows} >= {"ok", "error", "denied", "timeout"}
    exported = admin.get("/api/audit/export", params={"event": "tools.call"})
    assert exported.status_code == 200 and exported.content.startswith(b"\xef\xbb\xbf")
    assert all(secret not in exported.text for secret in stack.state["secrets"].values())


def test_local_deploy_upgrade(stack):
    before = stack.dc("ps", "-q", "gateway").stdout.strip()
    if image := os.getenv("GATEWAY_TEST_IMAGE"):
        model = json.loads((stack.folder / "docker-compose.yml").read_text())
        model["services"]["gateway"]["image"] = image
        private_file(stack.folder / "docker-compose.yml", json.dumps(model))
        stack.state["image"] = image
        stack.save()
    stack.run(["bash", str(stack.folder / "deploy.sh"), "--upgrade"])
    stack.dc("up", "-d", "--force-recreate", "--wait", "gateway")
    assert stack.dc("ps", "-q", "gateway").stdout.strip() != before
    # Nginx 在容器重建后重新解析上游 IP。
    stack.dc("restart", "tls")
    with stack.http() as client:
        stack.wait(lambda: client.get("/ready").status_code == 200)
    with stack.admin() as client:
        assert client.get("/api/assets").json()["data"]["total"] >= 4
    assert call(stack, "execute_query", {"sql": "SELECT message FROM records WHERE id=1"})["rows"] == [["tenant-a"]]
    checked = stack.python(
        "from pathlib import Path; import sqlite3; p=list(Path('/app/backups').glob('pre-upgrade-*.sqlite')); assert p; c=sqlite3.connect(p[-1]); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; print('备份完整性通过')"
    )
    assert "通过" in checked


def test_local_fastgpt(stack):
    base = f"http://127.0.0.1:{stack.state['ports']['fastgpt']}"
    with httpx.Client(base_url=base, trust_env=False, timeout=90) as client:
        prelogin = client.get("/api/support/user/account/preLogin", params={"username": "root"})
        assert prelogin.status_code == 200 and prelogin.json()["code"] == 200
        response = client.post(
            "/api/support/user/account/loginByPassword",
            json={
                "username": "root",
                "password": hashlib.sha256(stack.state["secrets"]["fastgpt"].encode()).hexdigest(),
                "code": prelogin.json()["data"]["code"],
            },
        )
        payload = response.json()
        assert response.status_code == 200 and payload.get("code") == 200, json.dumps(payload, ensure_ascii=False)
        client.headers["token"] = payload["data"]["token"]

        def request(operation, identity="agent-a", **params):
            reply = client.post(
                "/api/core/app/mcpTools/" + operation,
                json={
                    "url": "https://gateway.test/mcp",
                    "headerSecret": {"Authorization": {"value": "Bearer " + stack.state["secrets"][identity]}},
                    **params,
                },
            )
            data = reply.json()
            assert reply.status_code == 200 and data.get("code") == 200, data
            return data.get("data")

        tools_a = request("getTools")
        tools_b = request("getTools", "agent-b")
        assert {t["name"] for t in tools_a} >= {"list_tables", "exec_command", "read_file", "up__echo"}
        assert {t["name"] for t in tools_b} == {"list_tables", "execute_query"}
        assert request("getTools", "agent-empty") == []
        for identity, query, marker in (
            ("agent-a", "SELECT message FROM records", "tenant-a"),
            ("agent-b", "SELECT message FROM secrets", "tenant-b-private"),
        ):
            result = request("runTool", identity, toolName="execute_query", params={"sql": query})
            assert marker in json.dumps(result)
        denied = request("runTool", "agent-b", toolName="read_file", params={"path": "hello.txt"})
        assert "TOOL_DENIED" in json.dumps(denied)
        app_id = request("create", name="本地网关验收工具集", toolList=tools_a)
        children = client.get("/api/core/app/mcpTools/getChildren", params={"id": app_id}).json()
        assert children["code"] == 200 and len(children["data"]) == len(tools_a)
        stack.state["fastgpt_app_id"] = app_id
        stack.save()
        private_file(
            stack.folder / "fastgpt-result.json",
            json.dumps(
                {
                    "image": "ghcr.io/labring/fastgpt:v4.14.31",
                    "endpoint": "https://gateway.test/mcp",
                    "tools_a": sorted(t["name"] for t in tools_a),
                    "tools_b": sorted(t["name"] for t in tools_b),
                    "checks": ["预登录与密码登录", "三客户端目录隔离", "两租户真实查询", "越权拒绝", "工具集持久化"],
                },
                ensure_ascii=False,
            ),
        )


def test_local_disk_full_and_recovery(stack):
    model = json.loads((stack.folder / "docker-compose.yml").read_text())
    service = copy.deepcopy(model["services"]["gateway"])
    service.pop("volumes")
    disk_url = f"http://127.0.0.1:{stack.state['ports']['disk']}"
    service["environment"].update(PUBLIC_BASE_URL=disk_url, ALLOWED_ORIGINS=disk_url, COOKIE_SECURE="false")
    service["tmpfs"] = [
        "/tmp:rw,noexec,nosuid,size=8m",
        "/app/data:rw,nosuid,size=16m,uid=10001,gid=10001",
        "/app/backups:rw,nosuid,size=16m,uid=10001,gid=10001",
    ]
    service["ports"] = [f"127.0.0.1:{stack.state['ports']['disk']}:8303"]
    service["mem_limit"] = "128m"
    model["services"]["disk"] = service
    backup = f"/app/backups/disk-{time.time_ns()}.sqlite"
    stack.execute("gateway", "python", "-m", "app.cli", "backup", backup)
    # 新 tmpfs 中先启动独立实例，再停进程外替换会破坏锁；用入口先复制一致备份再启动。
    service["entrypoint"] = [
        "python",
        "-c",
        (
            "import shutil,os; shutil.copyfile('/source/" + backup.rsplit("/", 1)[1] + "','/app/data/gateway.db'); "
            "os.chmod('/app/data/gateway.db',0o600); os.execvp('uvicorn',['uvicorn','app.main:app_factory','--factory',"
            "'--host','0.0.0.0','--port','8303','--workers','1','--no-access-log'])"
        ),
    ]
    service.pop("command", None)
    # 使用已有的逻辑卷名，避免 Compose 将物理卷名当作未声明卷。
    service["volumes"] = [{"type": "volume", "source": "gateway-backups", "target": "/source", "read_only": True}]
    private_file(stack.folder / "docker-compose.yml", json.dumps(model))
    try:
        stack.dc("up", "-d", "--wait", "disk")
        with httpx.Client(base_url=disk_url, trust_env=False, timeout=15) as client:
            assert call(stack, "list_tables", client=client)["tables"]
            stack.python(
                "import sqlite3; c=sqlite3.connect('/app/data/gateway.db'); c.execute('PRAGMA wal_checkpoint(TRUNCATE)'); c.close()",
                service="disk",
            )
            filled = stack.python(
                "import errno,os\nf=open('/app/data/ballast','wb',buffering=0)\ntry:\n while True: f.write(b'x'*4096)\n"
                "except OSError as e:\n assert e.errno==errno.ENOSPC; print('ENOSPC')\nfinally: f.close()",
                service="disk",
            )
            assert filled == "ENOSPC"
            response = client.post(
                "/mcp",
                headers={"Authorization": "Bearer " + stack.state["secrets"]["agent-a"]},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "list_tables", "arguments": {}},
                },
            )
            assert response.status_code == 503 and response.json()["error"]["code"] in {
                "AUDIT_UNAVAILABLE",
                "STORAGE_UNAVAILABLE",
            }
            assert client.get("/ready").status_code == 503
            assert client.get("/health").status_code == 200
            stack.python("open('/app/data/ballast','wb').close()", service="disk")
            stack.wait(lambda: client.get("/ready").status_code == 200, seconds=85)
            assert call(stack, "list_tables", client=client)["tables"]
            assert (
                stack.python(
                    "import sqlite3; c=sqlite3.connect('/app/data/gateway.db'); assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'; assert c.execute(\"SELECT count(*) FROM audit_log WHERE event='audit.recovered'\").fetchone()[0]>0; print('恢复通过')",
                    service="disk",
                )
                == "恢复通过"
            )
    finally:
        stack.dc("stop", "disk")


def test_local_sustained_load(stack):
    seconds = int(os.getenv("LOCAL_SOAK_SECONDS", "1800"))
    assert seconds >= 120, "稳定性验收至少运行 120 秒；完整本地验收默认 30 分钟"
    started, latencies, samples = time.monotonic(), [], []
    operations = [
        ("list_tables", {}),
        ("exec_command", {"cmd": "/usr/bin/id"}),
        ("read_file", {"path": "hello.txt"}),
        ("up__echo", {"message": "稳定性验收"}),
    ]
    with stack.http() as client, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        batch = 0
        while time.monotonic() - started < seconds:
            cycle = time.monotonic()

            def invoke(item):
                before = time.monotonic()
                call(stack, item[0], item[1], client=client)
                return (time.monotonic() - before) * 1000

            latencies.extend(pool.map(invoke, operations))
            assert client.get("/ready").status_code == 200
            if batch % 15 == 0:
                sample = json.loads(
                    stack.python(
                        "import json,os\n"
                        "pids=[]\n"
                        "for p in os.listdir('/proc'):\n"
                        " if not p.isdigit(): continue\n"
                        " try: args=open('/proc/'+p+'/cmdline','rb').read().split(b'\\0')\n"
                        " except (FileNotFoundError,ProcessLookupError): continue\n"
                        " if any(a.endswith(b'/uvicorn') or a==b'uvicorn' for a in args[:2]) and b'app.main:app_factory' in args: pids.append(p)\n"
                        "assert len(pids)==1,pids\n"
                        "pid=pids[0]; d=dict(line.split(':',1) for line in open('/proc/'+pid+'/status') if ':' in line)\n"
                        "print(json.dumps({'pid':int(pid),'rss_kib':int(d['VmRSS'].split()[0]),'threads':int(d['Threads']),'fds':len(os.listdir('/proc/'+pid+'/fd'))}))"
                    )
                )
                sample["elapsed_seconds"] = round(time.monotonic() - started, 2)
                samples.append(sample)
                print(json.dumps(sample), flush=True)
            batch += 1
            time.sleep(max(0, 4 - (time.monotonic() - cycle)))
    assert len(samples) >= 2
    assert len({sample["pid"] for sample in samples}) == 1
    assert max(sample["rss_kib"] for sample in samples) - samples[0]["rss_kib"] < 64 * 1024
    assert max(sample["fds"] for sample in samples) - samples[0]["fds"] < 12
    assert max(sample["threads"] for sample in samples) <= samples[0]["threads"] + 4
    report = {
        "seconds": round(time.monotonic() - started, 2),
        "calls": len(latencies),
        "errors": 0,
        "p50_ms": round(statistics.median(latencies), 2),
        "p95_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 2),
        "samples": samples,
    }
    private_file(stack.folder / "soak-result.json", json.dumps(report, ensure_ascii=False))
    print(json.dumps({k: v for k, v in report.items() if k != "samples"}, ensure_ascii=False))
