"""本地全链路验收环境；仅管理随机命名的独立 Compose 资源。"""

import argparse
import datetime
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def private_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(content)


class LocalStack:
    def __init__(self, folder):
        self.folder = Path(folder).resolve()
        self.state = json.loads((self.folder / "state.json").read_text())
        self.compose = ["docker", "compose", "-p", self.state["project"], "-f", str(self.folder / "docker-compose.yml")]

    def save(self):
        private_file(self.folder / "state.json", json.dumps(self.state, ensure_ascii=False))

    def run(self, args, *, check=True, input=None, timeout=240):
        result = subprocess.run(args, capture_output=True, text=True, input=input, timeout=timeout, cwd=ROOT)
        if check and result.returncode:
            output = result.stdout + result.stderr
            for value in self.state.get("secrets", {}).values():
                output = output.replace(value, "[REDACTED]")
            output = re.sub(r"一次性初始密码：[^\r\n]+", "一次性初始密码：[REDACTED]", output)
            raise RuntimeError(output[-6000:])
        return result

    def dc(self, *args, **kwargs):
        return self.run([*self.compose, *args], **kwargs)

    def execute(self, service, *args, **kwargs):
        return self.dc("exec", "-T", service, *args, **kwargs)

    def python(self, code, service="gateway"):
        return self.execute(service, "python", "-c", code).stdout.strip()

    @property
    def url(self):
        return self.state["url"]

    def http(self):
        return httpx.Client(
            base_url=self.url,
            verify=ssl.create_default_context(cafile=str(self.folder / "tls/ca.pem")),
            trust_env=False,
            timeout=45,
            headers={"Origin": self.url},
        )

    @contextmanager
    def admin(self):
        with self.http() as client:
            response = client.post(
                "/api/auth/login", json={"username": "admin", "password": self.state["secrets"]["admin"]}
            )
            assert response.status_code == 200, response.text
            client.headers["X-CSRF-Token"] = client.cookies["gateway_csrf"]
            yield client

    def wait(self, probe, seconds=120):
        deadline = time.monotonic() + seconds
        error = None
        while time.monotonic() < deadline:
            try:
                if probe():
                    return
            except (httpx.HTTPError, RuntimeError, AssertionError) as exc:
                error = exc
            time.sleep(2)
        raise RuntimeError("等待验收服务就绪超时") from error

    @classmethod
    def create(cls):
        base = ROOT / ".preview"
        base.mkdir(mode=0o700, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix="acceptance-", dir=base))
        ports = {name: free_port() for name in ("tls", "http", "fastgpt", "disk")}
        state = {
            "project": "gateway-e2e-" + secrets.token_hex(6),
            "ports": ports,
            "url": f"https://localhost:{ports['tls']}",
            "secrets": {
                name: secrets.token_hex(24) for name in ("mysql", "reader", "ssh", "fastgpt", "system", "token", "aes")
            },
            "image": os.getenv("GATEWAY_TEST_IMAGE", "mcp-asset-gateway:0.1.0"),
        }
        state["secrets"]["master"] = Fernet.generate_key().decode()
        private_file(folder / "state.json", json.dumps(state))
        stack = cls(folder)
        stack.configure()
        return stack

    def configure(self):
        folder, state = self.folder, self.state
        keys, ports = state["secrets"], state["ports"]
        tls = folder / "tls"
        tls.mkdir()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "网关本地验收 CA")])
        stamp = datetime.datetime.now(datetime.UTC)
        ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(stamp - datetime.timedelta(minutes=5))
            .not_valid_after(stamp + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(name)
            .public_key(leaf.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(stamp - datetime.timedelta(minutes=5))
            .not_valid_after(stamp + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("gateway.test"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        (tls / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (tls / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_file(
            tls / "server.key",
            leaf.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode(),
        )
        private_file(folder / ".env", f"GATEWAY_MASTER_KEY={keys['master']}\nGATEWAY_MASTER_KEY_ID=e2e-key\n")
        config = {
            "GATEWAY_MASTER_KEY": keys["master"],
            "GATEWAY_MASTER_KEY_ID": "e2e-key",
            "PUBLIC_BASE_URL": state["url"],
            "COOKIE_SECURE": "true",
            "LEGACY_COMPAT": "false",
            "SSH_HOST_KEY_ENFORCE": "true",
            "ALLOWED_HOSTS": "localhost,127.0.0.1,gateway,gateway.test",
            "ALLOWED_ORIGINS": state["url"],
            "OUTBOUND_ALLOWLIST": json.dumps(
                [
                    {"host": "mysql", "port": 3306},
                    {"host": "ssh", "port": 2222},
                    {"host": "upstream", "port": 8000, "allow_http": True},
                ]
            ),
            "DATABASE_PATH": "/app/data/gateway.db",
        }
        model = json.loads(
            self.run(
                [
                    "docker",
                    "compose",
                    "--env-file",
                    os.devnull,
                    "-f",
                    str(ROOT / "docker-compose.yml"),
                    "config",
                    "--format",
                    "json",
                    "--no-env-resolution",
                ]
            ).stdout
        )
        gateway = model["services"]["gateway"]
        gateway.pop("build", None)
        gateway.pop("ports", None)
        gateway.pop("env_file", None)
        gateway.update(image=state["image"], restart="no", environment=config)
        for section in ("volumes", "networks"):
            for resource, definition in model.get(section, {}).items():
                definition["name"] = f"{state['project']}_{resource}"
        model["name"] = state["project"]
        fixture = folder / "files"
        fixture.mkdir()
        (fixture / "hello.txt").write_text("本地真实 SFTP 验收\nabcdef\n")
        (fixture / "binary.bin").write_bytes(b"abc\x00def")
        (fixture / "escape").symlink_to("/etc/passwd")
        private_file(
            folder / "mysql.sql",
            f"""
CREATE DATABASE tenant_a;
CREATE DATABASE tenant_b;
CREATE TABLE tenant_a.records(id INT PRIMARY KEY, message VARCHAR(100));
CREATE TABLE tenant_b.secrets(id INT PRIMARY KEY, message VARCHAR(100));
INSERT INTO tenant_a.records VALUES(1,'tenant-a'),(2,'second-row');
INSERT INTO tenant_b.secrets VALUES(1,'tenant-b-private');
CREATE USER 'reader_a'@'%' IDENTIFIED BY '{keys["reader"]}';
CREATE USER 'reader_b'@'%' IDENTIFIED BY '{keys["reader"]}';
GRANT SELECT ON tenant_a.* TO 'reader_a'@'%';
GRANT SELECT ON tenant_b.* TO 'reader_b'@'%';
""",
        )
        nginx = f"""events {{}}
http {{
  server {{ listen 80; return 308 https://localhost:{ports["tls"]}$request_uri; }}
  server {{
    listen 443 ssl;
    ssl_certificate /tls/server.pem;
    ssl_certificate_key /tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 1m;
    location / {{
      proxy_pass http://gateway:8303;
      proxy_set_header Host $http_host;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 45s;
      proxy_send_timeout 45s;
    }}
  }}
}}
"""
        (folder / "nginx.conf").write_text(nginx)
        services = model["services"]
        services.update(
            {
                "mysql": {
                    "image": "mysql:8.4",
                    "environment": {"MYSQL_ROOT_PASSWORD": keys["mysql"]},
                    "command": ["--innodb-buffer-pool-size=64M", "--performance-schema=OFF", "--max-connections=40"],
                    "volumes": [f"{folder / 'mysql.sql'}:/docker-entrypoint-initdb.d/01.sql:ro"],
                    "mem_limit": "512m",
                },
                "ssh": {
                    "image": "lscr.io/linuxserver/openssh-server:latest",
                    "mem_limit": "128m",
                    "environment": {
                        "PUID": "1000",
                        "PGID": "1000",
                        "USER_NAME": "reader",
                        "USER_PASSWORD": keys["ssh"],
                        "PASSWORD_ACCESS": "true",
                        "SUDO_ACCESS": "false",
                    },
                    "volumes": [f"{fixture}:/fixtures:ro"],
                },
                "upstream": {
                    "image": state["image"],
                    "command": ["python", "/fixture/upstream.py"],
                    "volumes": [f"{ROOT / 'tests/local_upstream.py'}:/fixture/upstream.py:ro"],
                    "healthcheck": {"disable": True},
                    "mem_limit": "128m",
                },
                "tls": {
                    "image": "nginx:1.28-alpine",
                    "mem_limit": "64m",
                    "volumes": [f"{folder / 'nginx.conf'}:/etc/nginx/nginx.conf:ro", f"{tls}:/tls:ro"],
                    "ports": [f"127.0.0.1:{ports['tls']}:443", f"127.0.0.1:{ports['http']}:80"],
                    "networks": {"default": {"aliases": ["gateway.test"]}},
                },
                "mongo": {
                    "image": "mongo:5.0.32",
                    "command": ["mongod", "--replSet", "rs0", "--bind_ip_all", "--wiredTigerCacheSizeGB", "0.25"],
                    "mem_limit": "512m",
                },
                "redis": {
                    "image": "redis:7.2-alpine",
                    "command": ["redis-server", "--maxmemory", "64mb"],
                    "mem_limit": "96m",
                },
                "pg": {
                    "image": "pgvector/pgvector:0.8.0-pg15",
                    "mem_limit": "192m",
                    "environment": {
                        "POSTGRES_USER": "fastgpt",
                        "POSTGRES_PASSWORD": keys["system"],
                        "POSTGRES_DB": "postgres",
                    },
                },
                "fastgpt": {
                    "image": "ghcr.io/labring/fastgpt:v4.14.31",
                    "mem_limit": "1536m",
                    "ports": [f"127.0.0.1:{ports['fastgpt']}:3000"],
                    "volumes": [f"{tls / 'ca.pem'}:/local-ca.pem:ro"],
                    "environment": {
                        "HOSTNAME": "0.0.0.0",
                        "DEFAULT_ROOT_PSW": keys["fastgpt"],
                        "ROOT_KEY": keys["system"],
                        "TOKEN_KEY": keys["token"],
                        "AES256_SECRET_KEY": keys["aes"],
                        "FILE_TOKEN_KEY": keys["token"],
                        "MONGODB_URI": "mongodb://mongo:27017/fastgpt?replicaSet=rs0",
                        "DB_MAX_LINK": "5",
                        "REDIS_URL": "redis://redis:6379",
                        "PG_URL": f"postgresql://fastgpt:{keys['system']}@pg:5432/postgres",
                        "NODE_EXTRA_CA_CERTS": "/local-ca.pem",
                        "CHECK_INTERNAL_IP": "false",
                        "SYNC_INDEX": "true",
                        "LOG_ENABLE_CONSOLE": "true",
                        "LOG_CONSOLE_LEVEL": "info",
                        "LOG_ENABLE_OTEL": "false",
                        "NODE_OPTIONS": "--max-old-space-size=1024",
                        "NO_PROXY": "*",
                        "no_proxy": "*",
                    },
                },
            }
        )
        for service in services.values():
            service.setdefault("restart", "no")
            service.setdefault("logging", {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}})
        private_file(folder / "docker-compose.yml", json.dumps(model))
        shutil.copy2(ROOT / "deploy.sh", folder / "deploy.sh")

    def initialize(self):
        self.dc("up", "-d", "--no-build", "mysql", "ssh", "upstream")
        self.wait(
            lambda: (
                self.execute(
                    "mysql",
                    "sh",
                    "-c",
                    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -e "SELECT COUNT(*) FROM tenant_a.records"',
                    check=False,
                ).returncode
                == 0
            )
        )
        result = self.run(["bash", str(self.folder / "deploy.sh"), "--init"])
        self.state["secrets"]["admin"] = re.search(r"一次性初始密码：([^\r\n]+)", result.stdout).group(1)
        self.save()
        self.dc("up", "-d", "--no-build", "tls")
        with self.http() as client:
            self.wait(lambda: client.get("/ready").status_code == 200)
        self.seed()

    def seed(self):
        fingerprint = self.execute(
            "ssh", "ssh-keygen", "-lf", "/config/ssh_host_keys/ssh_host_ed25519_key.pub", "-E", "sha256"
        ).stdout.split()[1]
        with self.admin() as client:

            def post(path, body):
                response = client.post("/api/" + path, json=body)
                assert response.status_code == 200, response.text
                return response.json()["data"]

            for kind, identity, connection in [
                ("mysql", "db", {"host": "mysql", "tls_mode": "DISABLED"}),
                ("ssh", "host", {"host": "ssh", "port": 2222, "host_key_sha256": fingerprint}),
                ("filebrowser", "files", {"host": "ssh", "port": 2222, "host_key_sha256": fingerprint}),
                ("mcp", "upstream", {"url": "http://upstream:8000/mcp"}),
            ]:
                post("assets", {"id": identity, "name": "本地验收 " + kind, "type": kind, "connection": connection})
            accounts = [
                (
                    "reader-a",
                    "db",
                    {"username": "reader_a", "database": "tenant_a"},
                    {"password": self.state["secrets"]["reader"]},
                    {},
                ),
                (
                    "reader-b",
                    "db",
                    {"username": "reader_b", "database": "tenant_b"},
                    {"password": self.state["secrets"]["reader"]},
                    {},
                ),
                (
                    "shell",
                    "host",
                    {"username": "reader"},
                    {"password": self.state["secrets"]["ssh"]},
                    {},
                ),
                (
                    "sftp",
                    "files",
                    {"username": "reader"},
                    {"password": self.state["secrets"]["ssh"]},
                    {"root_dir": "/fixtures"},
                ),
                ("up", "upstream", {"auth_mode": "none"}, {}, {}),
            ]
            for identity, asset, config, credential, policy in accounts:
                post(
                    "accounts",
                    {
                        "id": identity,
                        "name": "验收 " + identity,
                        "asset_id": asset,
                        "config": config,
                        "credential": credential,
                        "policy": policy,
                    },
                )
            catalog = post("accounts/up/refresh-tools", {})["tools"]
            for identity in ("agent-a", "agent-b", "agent-empty"):
                result = post("clients", {"id": identity, "name": "验收 " + identity})
                self.state["secrets"][identity] = result["token"]
            for account, tools in [
                ("reader-a", ["list_tables", "describe_table", "execute_query"]),
                ("shell", ["exec_command"]),
                ("sftp", ["list_dir", "search_files", "read_file"]),
                ("up", [t["name"] for t in catalog]),
            ]:
                post(
                    "grants",
                    {
                        "client_ids": ["agent-a"],
                        "entries": [
                            {
                                "account_id": account,
                                "tools": tools,
                                "parameter_rules": {
                                    "exec_command": {
                                        "cmd": {
                                            "allow": [
                                                {"match": "exact", "value": "/usr/bin/id"},
                                                {"match": "exact", "value": "/bin/uname -a"},
                                            ]
                                        }
                                    }
                                }
                                if account == "shell"
                                else {},
                            }
                        ],
                        "tool_versions": {"up": {t["name"]: t["spec_hash"] for t in catalog}}
                        if account == "up"
                        else {},
                    },
                )
            post(
                "grants",
                {
                    "client_ids": ["agent-b"],
                    "account_ids": ["reader-b"],
                    "tools": ["list_tables", "execute_query"],
                },
            )
        self.save()

    def fastgpt(self):
        model = json.loads((self.folder / "docker-compose.yml").read_text())
        environment = model["services"]["fastgpt"]["environment"]
        environment.update(
            {
                "LOG_CONSOLE_LEVEL": "info",
                "STORAGE_VENDOR": "minio",
                "STORAGE_REGION": "us-east-1",
                "STORAGE_ACCESS_KEY_ID": "local-acceptance",
                "STORAGE_SECRET_ACCESS_KEY": self.state["secrets"]["system"],
                "STORAGE_PUBLIC_BUCKET": "fastgpt-public",
                "STORAGE_PRIVATE_BUCKET": "fastgpt-private",
                "STORAGE_S3_ENDPOINT": "http://minio:9000",
                "STORAGE_EXTERNAL_ENDPOINT": "http://minio:9000",
                "STORAGE_S3_FORCE_PATH_STYLE": "true",
                "STORAGE_S3_MAX_RETRIES": "3",
            }
        )
        model["services"]["minio"] = {
            "image": "registry.cn-hangzhou.aliyuncs.com/fastgpt/minio:RELEASE.2025-09-07T16-13-09Z",
            "command": ["server", "/data"],
            "environment": {
                "MINIO_ROOT_USER": "local-acceptance",
                "MINIO_ROOT_PASSWORD": self.state["secrets"]["system"],
            },
            "mem_limit": "256m",
            "restart": "no",
        }
        environment.update(PLUGIN_BASE_URL="http://plugin:3000", PLUGIN_TOKEN=self.state["secrets"]["system"])
        model["services"]["plugin"] = {
            "image": "ghcr.io/labring/fastgpt-plugin:v0.6.2",
            "environment": {
                **{key: value for key, value in environment.items() if key.startswith(("STORAGE_", "LOG_"))},
                "MONGODB_URI": environment["MONGODB_URI"],
                "REDIS_URL": environment["REDIS_URL"],
                "AUTH_TOKEN": self.state["secrets"]["system"],
                "NO_PROXY": "*",
                "no_proxy": "*",
            },
            "mem_limit": "512m",
            "restart": "no",
        }
        private_file(self.folder / "docker-compose.yml", json.dumps(model))
        self.dc("up", "-d", "mongo", "redis", "pg", "minio")
        self.wait(
            lambda: (
                self.execute(
                    "mongo", "mongo", "--quiet", "--eval", "db.adminCommand('ping').ok", check=False
                ).returncode
                == 0
            )
        )
        self.execute(
            "mongo",
            "mongo",
            "--quiet",
            "--eval",
            'if (rs.status().ok !== 1) { rs.initiate({_id:"rs0",members:[{_id:0,host:"mongo:27017"}]}) }',
        )
        self.wait(
            lambda: "true" in self.execute("mongo", "mongo", "--quiet", "--eval", "db.isMaster().ismaster").stdout
        )
        self.dc("up", "-d", "plugin")
        self.wait(
            lambda: self.execute("plugin", "curl", "-fsS", "http://localhost:3000/health", check=False).returncode == 0
        )
        self.dc("up", "-d", "fastgpt")
        with httpx.Client(trust_env=False, timeout=10) as client:
            self.wait(
                lambda: client.get(f"http://127.0.0.1:{self.state['ports']['fastgpt']}/login").status_code == 200,
                seconds=240,
            )

    def ui(self):
        # 独立副本通过回环 HTTP 验收交互；TLS 安全由主实例单独验证。
        import copy

        model = json.loads((self.folder / "docker-compose.yml").read_text())
        self.state["ports"].setdefault("ui", free_port())
        url = f"http://localhost:{self.state['ports']['ui']}"
        backup = f"ui-{time.time_ns()}.sqlite"
        self.execute("gateway", "python", "-m", "app.cli", "backup", "/app/backups/" + backup)
        service = copy.deepcopy(model["services"]["gateway"])
        service["image"] = os.getenv("GATEWAY_TEST_IMAGE", self.state["image"])
        service["environment"].update(PUBLIC_BASE_URL=url, ALLOWED_ORIGINS=url, COOKIE_SECURE="false")
        service["ports"] = [f"127.0.0.1:{self.state['ports']['ui']}:8303"]
        service["volumes"] = ["ui-data:/app/data", "gateway-backups:/source:ro", "ui-backups:/app/backups"]
        service["entrypoint"] = [
            "python",
            "-c",
            (
                "import shutil,os; from pathlib import Path; p=Path('/app/data/gateway.db'); "
                "shutil.copyfile('/source/" + backup + "',p) if not p.exists() else None; "
                "os.chmod(p,0o600); os.execvp('uvicorn',['uvicorn','app.main:app_factory','--factory',"
                "'--host','0.0.0.0','--port','8303','--workers','1','--no-access-log'])"
            ),
        ]
        service.pop("command", None)
        model["services"]["ui"] = service
        for volume in ("ui-data", "ui-backups"):
            model["volumes"][volume] = {"name": self.state["project"] + "_" + volume}
        private_file(self.folder / "docker-compose.yml", json.dumps(model))
        self.save()
        self.dc("up", "-d", "--wait", "ui")
        print("浏览器交互验收地址：" + url, flush=True)

    def down(self):
        assert self.state["project"].startswith("gateway-e2e-")
        self.dc("down", "--volumes", "--timeout", "45", timeout=180)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["up", "fastgpt", "ui", "down"])
    parser.add_argument("--state", type=Path)
    args = parser.parse_args()
    if args.operation == "up":
        stack = LocalStack.create()
        print("验收状态目录：" + str(stack.folder), flush=True)
        try:
            stack.initialize()
        except BaseException:
            stack.down()
            raise
        print("HTTPS 验收地址：" + stack.url, flush=True)
    else:
        if args.state is None:
            parser.error("需要 --state 指定本次验收目录")
        stack = LocalStack(args.state)
        getattr(stack, args.operation)()
