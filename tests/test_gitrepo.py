"""gitrepo 资产类型测试：URL 解析、路径校验、凭证 schema、克隆链路、状态机与 6 个工具。"""

import base64
import datetime
import hashlib
import io
import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import replace
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.asset_types import gitrepo
from app.asset_types.base import Context
from app.asset_types.gitrepo import (
    GIT_CREDENTIAL,
    GitRepoAssetType,
    SyncJob,
    base_env,
    classify_git_error,
    directory_size_mb,
    is_repo,
    parse_repo_url,
    run_capped,
    safe_rel,
)
from app.asset_types.ssh import connect_ssh
from app.core.config import DEFAULTS
from app.core.security import GatewayError, NetworkPolicy, validate

GIT_OPTS = [
    "-c",
    "user.email=test@example.test",
    "-c",
    "user.name=测试用户",
    "-c",
    "init.defaultBranch=master",
    "-c",
    "commit.gpgsign=false",
]
FINGERPRINT = "SHA256:" + "A" * 43
FAKE_KEY = "\n".join(["-----BEGIN " + "OPENSSH PRIVATE KEY-----", "fake", "-----END OPENSSH PRIVATE KEY-----"])


def git(arguments, cwd):
    return subprocess.run(["git"] + GIT_OPTS + arguments, cwd=cwd, check=True, capture_output=True, text=True)


def make_source_repo(path):
    path.mkdir()
    git(["init", "--quiet"], path)
    (path / "app").mkdir()
    (path / "README.md").write_text("hello world\nsecond line\n", encoding="utf-8")
    (path / "app" / "main.py").write_text('def main():\n    print("hello")\n', encoding="utf-8")
    git(["add", "-A"], path)
    git(["commit", "--quiet", "-m", "初始化项目"], path)
    (path / "app" / "main.py").write_text('def main():\n    print("hello gateway")\n', encoding="utf-8")
    git(["add", "-A"], path)
    git(["commit", "--quiet", "-m", "调整输出"], path)
    return path


def context(config, **limits):
    asset = {"connection": {"repo_url": "https://git.example.test/group/repo.git", "branch": "master"}}
    account = {"id": "acct-1", "name": "代码仓库账号", "policy": {"refresh_interval_seconds": 0}}
    return Context(asset, account, {}, {**DEFAULTS, **limits}, NetworkPolicy(config))


def call(kind, name, arguments, ctx):
    value = kind.execute_sync(name, arguments, ctx)
    assert value["isError"] is False
    return json.loads(value["content"][0]["text"])


# ---- URL 解析与路径校验 ----


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            "git@gitlab.example.com:group/repo.git",
            {"scheme": "ssh", "user": "git", "host": "gitlab.example.com", "port": 22, "path": "group/repo.git"},
        ),
        (
            "gitlab.example.com:group/repo.git",
            {"scheme": "ssh", "user": "git", "host": "gitlab.example.com", "port": 22, "path": "group/repo.git"},
        ),
        (
            "ssh://git@gitlab.example.com:2222/group/repo.git",
            {"scheme": "ssh", "user": "git", "host": "gitlab.example.com", "port": 2222, "path": "/group/repo.git"},
        ),
        (
            "ssh://gitlab.example.com/group/repo.git",
            {"scheme": "ssh", "user": "git", "host": "gitlab.example.com", "port": 22, "path": "/group/repo.git"},
        ),
        (
            "https://gitlab.example.com/group/repo.git",
            {"scheme": "https", "user": "", "host": "gitlab.example.com", "port": 443, "path": "/group/repo.git"},
        ),
        (
            "http://gitlab.example.com/group/repo.git",
            {"scheme": "http", "user": "", "host": "gitlab.example.com", "port": 80, "path": "/group/repo.git"},
        ),
    ],
)
def test_parse_repo_url_ok(value, expected):
    assert parse_repo_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "git@host:2222/repo.git",
        "ssh://git@host:99999999/repo.git",
        "file:///tmp/repo.git",
        "https://" + "user:pass@host/repo.git",
        "https://host/repo.git?x=1",
        "https://host/repo.git#frag",
        "https://host/",
        "https:///repo.git",
        "git@host",
        "git@host:",
        "git clone repo",
        "https://host:0/repo.git",
        "https://[broken/repo.git",
        "https://user@host/repo.git",
        "ssh://" + "user:@host/repo.git",
        "ssh://user%0a@host/repo.git",
        "https://host\\evil/repo.git",
        "https://host/repo\n.git",
        "https://host/repo\x7f.git",
    ],
)
def test_parse_repo_url_rejected(value):
    with pytest.raises(GatewayError) as exc:
        parse_repo_url(value)
    assert exc.value.code == "REPO_URL_INVALID"


def test_safe_rel(tmp_path):
    repo = str(tmp_path)
    assert safe_rel(repo, "") == "."
    assert safe_rel(repo, "app/main.py") == "app/main.py"
    assert safe_rel(repo, "./app/../app/main.py") == "app/main.py"
    for value in ("..", "../etc/passwd", "app/../../etc", "/etc/passwd", "-rf", "a\\b", "x\0y"):
        with pytest.raises(GatewayError) as exc:
            safe_rel(repo, value)
        assert exc.value.code == "PATH_DENIED"


def test_classify_git_error():
    assert classify_git_error("fatal: Authentication failed for 'https://git.example.test/'") == "GIT_AUTH_FAILED"
    assert classify_git_error("Permission denied (publickey).") == "GIT_AUTH_FAILED"
    assert classify_git_error("ssh: connect to host git.example.test port 22: Connection refused") == "GIT_UNREACHABLE"
    assert classify_git_error("fatal: unable to access: Could not resolve host: git.example.test") == "GIT_UNREACHABLE"
    assert classify_git_error("fatal: early EOF") == "GIT_SYNC_FAILED"


# ---- 凭证 schema ----


def test_git_credential_schema():
    validate(GIT_CREDENTIAL, {"private_key": FAKE_KEY})
    validate(GIT_CREDENTIAL, {"private_key": "key", "passphrase": "secret"})
    validate(GIT_CREDENTIAL, {"token": "glpat-xxx"})
    validate(GIT_CREDENTIAL, {"token": "glpat-xxx", "username": "oauth2"})
    for value in ({}, {"private_key": "key", "token": "token"}, {"username": "oauth2"}, {"passphrase": "p"}):
        with pytest.raises(GatewayError):
            validate(GIT_CREDENTIAL, value)


# ---- 子进程输出控制 ----


def test_run_capped_truncates(tmp_path):
    env = base_env(tmp_path)
    out, _, truncated, code = run_capped(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 500000)"], str(tmp_path), env, 20, 4096
    )
    assert truncated is True and len(out) == 4096 and code != 0


def test_run_capped_timeout(tmp_path):
    env = base_env(tmp_path)
    with pytest.raises(GatewayError) as exc:
        run_capped([sys.executable, "-c", "import time; time.sleep(5)"], str(tmp_path), env, 0.5, 4096)
    assert exc.value.code == "GIT_TIMEOUT"


# ---- 克隆与更新（真实 git，本地源） ----


def make_job(kind, source, account_id="acct-1"):
    work_root = kind.work_dir(account_id)
    work_root.mkdir(parents=True, exist_ok=True)
    return SyncJob(
        account_id=account_id,
        repo_url=str(source),
        branch="master",
        host_key="",
        credential={},
        policy={"sync_timeout_seconds": 60, "max_repo_mb": 2048},
        network=None,
        enforce_host_key=False,
        work_root=work_root,
        repo_dir=kind.repo_dir(account_id),
        state_file=kind.state_path(account_id),
    )


def test_clone_fetch_and_reset(tmp_path):
    kind = GitRepoAssetType(tmp_path / "data")
    source = make_source_repo(tmp_path / "source")
    job = make_job(kind, source)
    env = base_env(job.work_root)
    kind._clone(job, env, [])
    assert is_repo(job.repo_dir)
    assert (job.repo_dir / "app" / "main.py").read_text(encoding="utf-8").endswith('print("hello gateway")\n')
    # 源仓库新增提交后，_fetch 通过 reset --hard 把副本对齐到远端基线分支。
    (source / "new.txt").write_text("new content\n", encoding="utf-8")
    git(["add", "-A"], source)
    git(["commit", "--quiet", "-m", "新增文件"], source)
    kind._fetch(job, env, [])
    assert (job.repo_dir / "new.txt").read_text(encoding="utf-8") == "new content\n"
    record = gitrepo.read_state(job.state_file)
    assert record == {}


def test_clone_replaces_stale_repo(tmp_path):
    kind = GitRepoAssetType(tmp_path / "data")
    source = make_source_repo(tmp_path / "source")
    job = make_job(kind, source)
    job.repo_dir.mkdir(parents=True, exist_ok=True)
    (job.repo_dir / "stale.txt").write_text("stale\n", encoding="utf-8")
    kind._clone(job, base_env(job.work_root), [])
    assert not (job.repo_dir / "stale.txt").exists()
    assert is_repo(job.repo_dir)


def test_sync_clone_records_state_head(tmp_path, monkeypatch):
    # sync() 完整链路：本地源仓库不经过 prepare_git 的 URL 解析与凭证注入。
    monkeypatch.setattr(gitrepo, "prepare_git", lambda job: (base_env(job.work_root), [], lambda: None))
    kind = GitRepoAssetType(tmp_path / "data")
    source = make_source_repo(tmp_path / "source")
    job = make_job(kind, source)
    kind.sync(job, "clone")
    assert is_repo(job.repo_dir)
    record = gitrepo.read_state(job.state_file)
    expected = git(["rev-parse", "HEAD"], source).stdout.strip()[:12]
    assert record["head"] == expected and record["last_sync_at"] > 0


def test_sync_fetch_updates_state_head(tmp_path, monkeypatch):
    monkeypatch.setattr(gitrepo, "prepare_git", lambda job: (base_env(job.work_root), [], lambda: None))
    kind = GitRepoAssetType(tmp_path / "data")
    source = make_source_repo(tmp_path / "source")
    job = make_job(kind, source)
    kind.sync(job, "clone")
    first = gitrepo.read_state(job.state_file)["head"]
    (source / "app" / "extra.py").write_text("value = 1\n", encoding="utf-8")
    git(["add", "-A"], source)
    git(["commit", "--quiet", "-m", "追加文件"], source)
    kind.sync(job, "fetch")
    record = gitrepo.read_state(job.state_file)
    assert record["head"] != first
    assert record["head"] == git(["rev-parse", "HEAD"], source).stdout.strip()[:12]


def test_directory_size_mb(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"x" * (2 * 1024 * 1024))
    assert directory_size_mb(tmp_path) >= 2


# ---- 副本状态机 ----


def test_ensure_repo_preparing(tmp_path, config):
    kind = GitRepoAssetType(tmp_path / "data")
    blocker = threading.Thread(target=time.sleep, args=(3,), daemon=True)
    blocker.start()
    kind._state("acct-1")["thread"] = blocker
    with pytest.raises(GatewayError) as exc:
        kind.execute_sync("search_code", {"pattern": "x"}, context(config, query_timeout_seconds=3.5))
    assert exc.value.code == "REPO_PREPARING"


def test_ensure_repo_sync_failed(tmp_path, config):
    kind = GitRepoAssetType(tmp_path / "data")
    kind._state("acct-1").update(failed_at=gitrepo.now_ms(), error="克隆失败：认证失败")
    with pytest.raises(GatewayError) as exc:
        kind.execute_sync("search_code", {"pattern": "x"}, context(config))
    assert exc.value.code == "REPO_SYNC_FAILED" and "认证失败" in exc.value.message


def test_ensure_repo_refresh_disabled(tmp_path, config):
    kind = GitRepoAssetType(tmp_path / "data")
    repo = kind.repo_dir("acct-1")
    repo.mkdir(parents=True)
    assert not is_repo(repo)
    # refresh_interval_seconds=0 时已有副本目录不再触发任何后台同步（仅检查状态）。
    kind._maybe_refresh(context(config), repo, kind._state("acct-1"))
    assert kind._state("acct-1")["thread"] is None


# ---- 工具执行 ----


@pytest.fixture
def git_kind(tmp_path):
    return GitRepoAssetType(tmp_path / "data")


@pytest.fixture
def repo_copy(git_kind, tmp_path):
    target = git_kind.repo_dir("acct-1")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(make_source_repo(tmp_path / "origin"), target, symlinks=True)
    return target


@pytest.mark.parametrize("ripgrep", [True, False])
def test_search_code(git_kind, repo_copy, config, monkeypatch, ripgrep):
    monkeypatch.setattr(gitrepo, "RG_BIN", gitrepo.RG_BIN if ripgrep else None)
    payload = call(git_kind, "search_code", {"pattern": "hello"}, context(config))
    files = {match["file"] for match in payload["matches"]}
    assert files == {"README.md", "app/main.py"}
    assert payload["total"] == 2 and payload["truncated"] is False
    hit = next(match for match in payload["matches"] if match["file"] == "README.md")
    assert (hit["line"], hit["text"], hit["ctx"]) == (1, "hello world", False)


@pytest.mark.parametrize("ripgrep", [True, False])
def test_search_code_scope_and_context(git_kind, repo_copy, config, monkeypatch, ripgrep):
    monkeypatch.setattr(gitrepo, "RG_BIN", gitrepo.RG_BIN if ripgrep else None)
    payload = call(git_kind, "search_code", {"pattern": "hello", "path": "app"}, context(config))
    assert {match["file"] for match in payload["matches"]} == {"app/main.py"}
    payload = call(git_kind, "search_code", {"pattern": "hello gate", "regex": False, "context": 1}, context(config))
    assert any(match["ctx"] for match in payload["matches"])
    payload = call(git_kind, "search_code", {"pattern": "print\\(.hello", "regex": True}, context(config))
    assert any(match["file"] == "app/main.py" for match in payload["matches"])
    payload = call(git_kind, "search_code", {"pattern": "hello", "max_results": 1}, context(config))
    assert payload["total"] == 2 and payload["truncated"] is True and len(payload["matches"]) == 1


def test_search_code_rejects_escape(git_kind, repo_copy, config):
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "search_code", {"pattern": "hello", "path": "../.."}, context(config))
    assert exc.value.code == "PATH_DENIED"


def test_read_file(git_kind, repo_copy, config):
    payload = call(git_kind, "read_file", {"file": "app/main.py"}, context(config))
    assert payload["content"].splitlines() == ["    1| def main():", '    2|     print("hello gateway")']
    assert payload["total_lines"] == 2 and payload["truncated"] is False
    payload = call(git_kind, "read_file", {"file": "app/main.py", "start": 2, "end": 2}, context(config))
    assert payload["content"] == '    2|     print("hello gateway")'
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "read_file", {"file": "missing.txt"}, context(config))
    assert exc.value.code == "PATH_NOT_FOUND"


def test_read_file_rejects_binary_and_escape(git_kind, repo_copy, config):
    (repo_copy / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "read_file", {"file": "blob.bin"}, context(config))
    assert exc.value.code == "BINARY_FILE"
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "read_file", {"file": "../../etc/passwd"}, context(config))
    assert exc.value.code == "PATH_DENIED"


def test_git_log_and_diff(git_kind, repo_copy, config):
    payload = call(git_kind, "git_log", {"n": 5}, context(config))
    assert len(payload["commits"]) == 2
    assert "调整输出" in payload["commits"][0] and "初始化项目" in payload["commits"][1]
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "git_log", {"branch": "-x"}, context(config))
    assert exc.value.code == "ARGUMENTS"
    payload = call(git_kind, "git_diff", {}, context(config))
    assert payload["commit"] == "HEAD" and "hello gateway" in payload["diff"]
    payload = call(git_kind, "git_diff", {"file": "app/main.py"}, context(config))
    assert "hello gateway" in payload["diff"]


def test_list_tree_and_branches(git_kind, repo_copy, config):
    payload = call(git_kind, "list_tree", {}, context(config))
    assert "README.md" in payload["tree"] and "app/" in payload["tree"]
    assert ".git" not in payload["tree"]
    payload = call(git_kind, "list_tree", {"path": "app", "depth": 1}, context(config))
    assert payload["tree"].strip() == "main.py"
    with pytest.raises(GatewayError) as exc:
        call(git_kind, "list_tree", {"path": "nope"}, context(config))
    assert exc.value.code == "PATH_NOT_FOUND"
    payload = call(git_kind, "list_branches", {}, context(config))
    assert "master" in payload["branches"]


# ---- 类型元数据与配置校验 ----


def test_gitrepo_metadata(tmp_path):
    kind = GitRepoAssetType(tmp_path / "data")
    assert (kind.type_id, kind.display_name, kind.default_port) == ("gitrepo", "Git 代码仓库", None)
    assert kind.proxied is False and kind.async_mode is False
    assert {item["name"] for item in kind.tools} == {
        "search_code",
        "read_file",
        "git_log",
        "git_diff",
        "list_tree",
        "list_branches",
    }
    assert all(item["annotations"]["readOnlyHint"] is True for item in kind.tools)
    assert kind.repo_dir("acct-1") == (tmp_path / "data" / "repos" / "acct-1").resolve()
    assert "x-hidden" not in kind.connection_schema["properties"]["host_key_sha256"]
    disabled = GitRepoAssetType(tmp_path / "data2", enforce_host_key=False)
    fingerprint = disabled.connection_schema["properties"]["host_key_sha256"]
    assert fingerprint["x-hidden"] is True
    assert "已关闭指纹校验" in fingerprint["description"]


def test_validate_connection(config, tmp_path):
    kind = GitRepoAssetType(tmp_path / "data")
    git_hosts = ({"host": "git.example.test", "port": 443}, {"host": "git.example.test", "port": 22})
    network = NetworkPolicy(replace(config, outbound=config.outbound + git_hosts))
    kind.validate_connection(network, {"repo_url": "https://git.example.test/group/repo.git"})
    kind.validate_connection(
        network, {"repo_url": "git@git.example.test:group/repo.git", "host_key_sha256": FINGERPRINT}
    )
    with pytest.raises(GatewayError) as exc:
        kind.validate_connection(network, {"repo_url": "git@git.example.test:group/repo.git"})
    assert exc.value.code == "HOST_KEY_MISSING"
    with pytest.raises(GatewayError) as exc:
        kind.validate_connection(
            network, {"repo_url": "ssh://git@unknown.example.test/group/repo.git", "host_key_sha256": FINGERPRINT}
        )
    assert exc.value.code == "OUTBOUND_DENIED"
    loop = NetworkPolicy(replace(config, outbound=config.outbound + ({"host": "testserver", "port": 22},)))
    with pytest.raises(GatewayError) as exc:
        kind.validate_connection(
            loop, {"repo_url": "ssh://git@testserver/group/repo.git", "host_key_sha256": FINGERPRINT}
        )
    assert exc.value.code == "PROXY_LOOP"


def test_validate_config(tmp_path):
    kind = GitRepoAssetType(tmp_path / "data")
    ssh_connection = {"repo_url": "git@git.example.test:group/repo.git", "branch": "master"}
    https_connection = {"repo_url": "https://git.example.test/group/repo.git", "branch": "master"}
    kind.validate_config(ssh_connection, {}, {}, {"private_key": "key"})
    kind.validate_config(https_connection, {}, {}, {"token": "glpat-x"})
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(ssh_connection, {}, {}, {"token": "glpat-x"})
    assert exc.value.code == "CREDENTIAL_MISMATCH"
    with pytest.raises(GatewayError) as exc:
        kind.validate_config(https_connection, {}, {}, {"private_key": "key"})
    assert exc.value.code == "CREDENTIAL_MISMATCH"


# ---- API 链路 ----


def test_types_endpoint_includes_gitrepo(admin):
    kinds = {item["type_id"]: item for item in admin.get("/api/types").json()["data"]}
    spec = kinds["gitrepo"]
    assert spec["display_name"] == "Git 代码仓库" and spec["default_port"] is None
    assert spec["connection_schema"]["required"] == ["repo_url"]
    assert {item["name"] for item in spec["tools"]} == {
        "search_code",
        "read_file",
        "git_log",
        "git_diff",
        "list_tree",
        "list_branches",
    }


def test_gitrepo_asset_account_and_grant(admin, seeded):
    token = seeded["client"]["token"]
    asset = admin.post(
        "/api/assets",
        json={
            "id": "git",
            "name": "代码仓库",
            "type": "gitrepo",
            "connection": {
                "repo_url": "git@ssh.example.test:group/repo.git",
                "branch": "master",
                "host_key_sha256": FINGERPRINT,
            },
        },
    )
    assert asset.status_code == 200, asset.text
    account = admin.post(
        "/api/accounts",
        json={
            "id": "gitacct",
            "name": "仓库账号",
            "asset_id": "git",
            "config": {},
            "credential": {"private_key": FAKE_KEY},
            "policy": {"refresh_interval_seconds": 0},
        },
    )
    assert account.status_code == 200, account.text
    missing = admin.post(
        "/api/assets",
        json={
            "id": "bad1",
            "name": "缺少指纹",
            "type": "gitrepo",
            "connection": {"repo_url": "git@ssh.example.test:group/repo.git"},
        },
    )
    assert missing.status_code == 403 and "HOST_KEY_MISSING" in missing.text
    denied = admin.post(
        "/api/assets",
        json={
            "id": "bad2",
            "name": "未登记主机",
            "type": "gitrepo",
            "connection": {"repo_url": "https://unknown.example.test/group/repo.git", "branch": "master"},
        },
    )
    assert denied.status_code == 403 and "OUTBOUND_DENIED" in denied.text
    blank = admin.post(
        "/api/accounts",
        json={"id": "bad3", "name": "无凭据", "asset_id": "git", "config": {}, "credential": {}, "policy": {}},
    )
    assert blank.status_code == 422
    mismatch = admin.post(
        "/api/accounts",
        json={
            "id": "bad4",
            "name": "凭据类型不匹配",
            "asset_id": "git",
            "config": {},
            "credential": {"token": "glpat-x"},
            "policy": {},
        },
    )
    assert mismatch.status_code == 403 and "CREDENTIAL_MISMATCH" in mismatch.text
    grant = admin.post(
        "/api/grants",
        json={
            "name": "代码检索",
            "client_ids": ["agent"],
            "account_ids": ["gitacct"],
            "tools": ["search_code", "read_file"],
        },
    )
    assert grant.status_code == 200, grant.text
    tools = admin.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    ).json()["result"]["tools"]
    spec = next(item for item in tools if item["name"] == "search_code")
    assert "可访问账号" in spec["description"] and "target" not in spec["inputSchema"]["properties"]
    assert "read_file" in {item["name"] for item in tools}


def test_gitrepo_tool_call_reports_sync_failure(admin, seeded, monkeypatch):
    token = seeded["client"]["token"]
    assert (
        admin.post(
            "/api/assets",
            json={
                "id": "git",
                "name": "代码仓库",
                "type": "gitrepo",
                "connection": {
                    "repo_url": "git@ssh.example.test:group/repo.git",
                    "branch": "master",
                    "host_key_sha256": FINGERPRINT,
                },
            },
        ).status_code
        == 200
    )
    assert (
        admin.post(
            "/api/accounts",
            json={
                "id": "gitacct",
                "name": "仓库账号",
                "asset_id": "git",
                "config": {},
                "credential": {"private_key": "fake-key"},
                "policy": {},
            },
        ).status_code
        == 200
    )
    assert (
        admin.post(
            "/api/grants",
            json={"name": "代码检索", "client_ids": ["agent"], "account_ids": ["gitacct"], "tools": ["search_code"]},
        ).status_code
        == 200
    )

    def offline(job):
        raise GatewayError("GIT_UNREACHABLE", "测试环境不可达", 502)

    # 阻断真实网络：后台克隆立即失败，请求应返回结构化的同步失败信息。
    monkeypatch.setattr(gitrepo, "prepare_git", offline)
    response = admin.post(
        "/mcp",
        headers={"Authorization": "Bearer " + token},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search_code", "arguments": {"pattern": "hello"}},
        },
    )
    value = response.json()["result"]
    assert value["isError"] is True and "REPO_SYNC_FAILED" in value["content"][0]["text"]


# ---- 发布安全：真实策略拒绝路径、凭据生命周期和真实 Git HTTP(S) 传输 ----


def network_job(tmp_path, config, url="https://git.example.test/repo.git"):
    parsed = parse_repo_url(url)
    network = NetworkPolicy(replace(config, outbound=({"host": parsed["host"], "port": parsed["port"]},)))
    kind = GitRepoAssetType(tmp_path / "data")
    ctx = context(config)
    ctx.asset["connection"]["repo_url"] = url
    ctx.network = network
    ctx.credential = {"token": "test-only-token", "private_key": FAKE_KEY}
    return kind, ctx, kind._job(ctx)


@pytest.mark.parametrize("mode", ["clone", "fetch", "health"])
@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "ff02::1", "0.0.0.0", "::ffff:127.0.0.1"])
def test_git_runtime_denies_unsafe_dns_before_subprocess(tmp_path, config, monkeypatch, address, mode):
    kind, ctx, job = network_job(tmp_path, config)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
    )
    monkeypatch.setattr(gitrepo, "run_capped", lambda *a: pytest.fail("不应启动 Git 子进程"))
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx) if mode == "health" else kind.sync(job, mode)
    assert exc.value.code == "OUTBOUND_DENIED"


@pytest.mark.parametrize("mode", ["clone", "fetch", "health"])
def test_git_runtime_rechecks_registration(tmp_path, config, monkeypatch, mode):
    kind, ctx, job = network_job(tmp_path, config)
    ctx.network.config = config  # 模拟保存资产后移除该主机登记。
    monkeypatch.setattr(gitrepo, "run_capped", lambda *a: pytest.fail("未登记目标不应启动 Git"))
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx) if mode == "health" else kind.sync(job, mode)
    assert exc.value.code == "OUTBOUND_DENIED"


def test_git_runtime_requires_http_permission(tmp_path, config):
    _, _, job = network_job(tmp_path, config, "http://git.example.test/repo.git")
    with pytest.raises(GatewayError) as exc:
        gitrepo.prepare_git(job)
    assert exc.value.code == "TLS_REQUIRED"
    _, _, loop = network_job(tmp_path, config, "http://testserver/repo.git")
    with pytest.raises(GatewayError) as exc:
        gitrepo.prepare_git(loop)
    assert exc.value.code == "PROXY_LOOP"


@pytest.mark.parametrize("address", ["192.0.2.20", "2001:db8::20"])
def test_git_pinning_preserves_hostname_and_isolates_environment(tmp_path, config, monkeypatch, address):
    _, _, job = network_job(tmp_path, config)
    monkeypatch.setattr(job.network, "resolve", lambda *a: address)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:8080")
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "true")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "100")
    env, extra, cleanup = gitrepo.prepare_git(job)
    session = Path(env["HOME"])
    try:
        resolved = f"[{address}]" if ":" in address else address
        assert f"http.curloptResolve=git.example.test:443:{resolved}" in extra
        assert "http.sslVerify=true" in extra and "http.followRedirects=false" in extra
        assert "http.proxy=" in extra and env["GIT_ALLOW_PROTOCOL"] == "https"
        assert not {"HTTPS_PROXY", "GIT_SSL_NO_VERIFY", "GIT_CONFIG_COUNT"} & env.keys()
        assert job.credential["token"] not in " ".join(extra)
        assert env["GIT_TOKEN"] == job.credential["token"]
        assert session.exists() and session.stat().st_mode & 0o777 == 0o700
    finally:
        cleanup()
    assert not session.exists()


def test_git_old_binary_fails_closed(tmp_path, config, monkeypatch):
    _, _, job = network_job(tmp_path, config)
    monkeypatch.setattr(job.network, "resolve", lambda *a: "192.0.2.20")
    calls = []

    def old_git(args, *a):
        calls.append(args)
        return b"http.followRedirects\n", b"", False, 0

    monkeypatch.setattr(gitrepo, "run_capped", old_git)
    with pytest.raises(GatewayError) as exc:
        gitrepo.prepare_git(job)
    assert exc.value.code == "GIT_UNSUPPORTED" and calls == [["git", "help", "--config"]]
    assert list(job.work_root.iterdir()) == []


@pytest.mark.parametrize("stage", ["host_key", "id_key", "known_hosts", "ssh_config"])
def test_git_ssh_preparation_failure_removes_partial_material(tmp_path, config, monkeypatch, stage):
    _, _, job = network_job(tmp_path, config, "git@git.example.test:repo.git")
    monkeypatch.setattr(job.network, "resolve", lambda *a: "192.0.2.20")
    original = gitrepo.private_file

    def fail_pin(*a):
        if stage == "host_key":
            raise GatewayError("HOST_KEY_MISMATCH", "测试指纹不匹配", 403)
        return "git.example.test ssh-ed25519 test-key"

    def fail_write(path, value):
        original(path, value)
        if path.name == stage:
            raise OSError("模拟写入后失败")

    monkeypatch.setattr(gitrepo, "pin_host_key", fail_pin)
    monkeypatch.setattr(gitrepo, "private_file", fail_write)
    with pytest.raises((GatewayError, OSError)):
        gitrepo.prepare_git(job)
    assert list(job.work_root.iterdir()) == []


def test_git_concurrent_preparations_have_independent_secrets(tmp_path, config, monkeypatch):
    _, _, job = network_job(tmp_path, config, "git@git.example.test:repo.git")
    monkeypatch.setattr(job.network, "resolve", lambda *a: "192.0.2.20")
    monkeypatch.setattr(gitrepo, "pin_host_key", lambda *a: "git.example.test ssh-ed25519 test-key")
    first, _, clean_first = gitrepo.prepare_git(job)
    second, _, clean_second = gitrepo.prepare_git(job)
    try:
        one, two = Path(first["HOME"]), Path(second["HOME"])
        assert one != two
        for folder in (one, two):
            assert (folder / "id_key").read_text() == FAKE_KEY
            assert all(path.stat().st_mode & 0o777 == 0o600 for path in folder.iterdir())
        clean_first()
        assert not one.exists() and (two / "id_key").exists()
    finally:
        clean_first()
        clean_second()
    assert list(job.work_root.iterdir()) == []


@pytest.mark.parametrize("mode", ["clone", "fetch", "health"])
def test_git_command_failure_cleans_secrets_and_redacts_stderr(tmp_path, config, monkeypatch, mode):
    kind, ctx, job = network_job(tmp_path, config)
    monkeypatch.setattr(job.network, "resolve", lambda *a: "192.0.2.20")
    monkeypatch.setattr(gitrepo, "validate_cached_remote", lambda *a: None)
    seen = []

    def fail(args, cwd, env, *a):
        if args == ["git", "help", "--config"]:
            return b"http.curloptResolve\n", b"", False, 0
        seen.append(Path(env["HOME"]))
        assert seen[-1].exists()
        return b"", b"fatal: Authentication failed test-only-token", False, 128

    monkeypatch.setattr(gitrepo, "run_capped", fail)
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx) if mode == "health" else kind.sync(job, mode)
    assert exc.value.code == "GIT_AUTH_FAILED"
    assert "test-only-token" not in str(exc.value)
    assert seen and all(not path.exists() for path in seen)


@pytest.mark.parametrize(
    "key,value",
    [
        ("remote.origin.url", "https://other.example.test/repo.git"),
        ("url.https://other.example.test/.insteadOf", "https://git.example.test/"),
        ("include.path", "/tmp/untrusted-git-config"),
        ("http.https://git.example.test/.sslVerify", "false"),
        ("http.proxy", "http://proxy.example.test:8080"),
        ("credential.helper", "untrusted-helper"),
        ("core.sshCommand", "untrusted-command"),
        ("remote.origin.vcs", "untrusted-helper"),
    ],
)
def test_fetch_rejects_modified_repo_config(tmp_path, key, value):
    kind = GitRepoAssetType(tmp_path / "data")
    job = make_job(kind, make_source_repo(tmp_path / "source"))
    env = base_env(job.work_root)
    kind._clone(job, env, [])
    git(["config", key, value], job.repo_dir)
    with pytest.raises(GatewayError) as exc:
        kind._fetch(job, env, [])
    assert exc.value.code == "REPO_CONFIG_UNSAFE"


@pytest.fixture(params=[False, True], ids=["http", "https"])
def git_http_server(tmp_path, request):
    source = make_source_repo(tmp_path / "source")
    root = tmp_path / "www"
    root.mkdir()
    git(["clone", "--bare", str(source), str(root / "repo.git")], tmp_path)
    git(["update-server-info"], root / "repo.git")
    events, server_names = [], []
    authorization = "Basic " + base64.b64encode(b"oauth2:test-only-token").decode()

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def log_message(self, *a):
            pass

        def do_GET(self):
            events.append((self.path, self.headers.get("Host"), self.headers.get("Authorization") == authorization))
            if self.server.redirect:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/escaped")
                self.end_headers()
                return
            if self.headers.get("Authorization") != authorization:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="test"')
                self.end_headers()
                return
            super().do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.redirect = False
    ca = None
    if request.param:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "git.example.test")])
        now = datetime.datetime.now(datetime.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("git.example.test")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        ca, key_path = tmp_path / "ca.pem", tmp_path / "tls.key"
        ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(ca, key_path)
        tls.set_servername_callback(lambda sock, name, ctx: server_names.append(name))
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scheme = "https" if request.param else "http"
        yield SimpleNamespace(
            url=f"{scheme}://git.example.test:{server.server_port}",
            root=root,
            source=source,
            events=events,
            server_names=server_names,
            ca=ca,
            listener=server,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def live_job(tmp_path, config, monkeypatch, server, path="/repo.git", trust=True):
    kind, ctx, job = network_job(tmp_path, config, server.url + path)
    ctx.network.config = replace(
        ctx.network.config, outbound=tuple({**v, "allow_http": True} for v in ctx.network.config.outbound)
    )
    # 只在隔离传输测试中将经过 URL 校验的目标固定到测试监听端口；生产拒绝路径另有真实策略测试。
    monkeypatch.setattr(ctx.network, "resolve", lambda host, port: "127.0.0.1")
    if server.ca and trust:
        original = gitrepo.prepare_git

        def prepared(job):
            env, extra, cleanup = original(job)
            return env, extra + ["-c", f"http.sslCAInfo={server.ca}"], cleanup

        monkeypatch.setattr(gitrepo, "prepare_git", prepared)
    return kind, ctx, job


@pytest.mark.parametrize("mode", ["clone", "fetch", "health"])
def test_git_does_not_inherit_parent_repository_config(tmp_path, config, monkeypatch, git_http_server, mode):
    server = git_http_server
    kind, ctx, job = live_job(tmp_path, config, monkeypatch, server)
    if mode == "fetch":
        kind.sync(job, "clone")
        server.events.clear()
    git(["init", "--quiet"], tmp_path)
    git(["config", "http.proxy", "http://unreachable.example.test:1"], tmp_path)
    git(["config", "url." + server.url + "/escaped/.insteadOf", server.url + "/"], tmp_path)
    kind.health_sync(ctx) if mode == "health" else kind.sync(job, mode)
    assert server.events and not any(path.startswith("/escaped") for path, _, _ in server.events)
    assert list(job.work_root.iterdir()) == []


def test_real_git_http_clone_fetch_health_pinned_and_authenticated(tmp_path, config, monkeypatch, git_http_server):
    server = git_http_server
    kind, ctx, job = live_job(tmp_path, config, monkeypatch, server)
    monkeypatch.setenv("HTTPS_PROXY", "http://unreachable.example.test:1")
    kind.sync(job, "clone")
    assert (job.repo_dir / "README.md").exists()
    (server.source / "new.txt").write_text("second revision")
    git(["add", "-A"], server.source)
    git(["commit", "-m", "update"], server.source)
    git(["push", str(server.root / "repo.git"), "master"], server.source)
    git(["update-server-info"], server.root / "repo.git")
    kind.sync(job, "fetch")
    assert (job.repo_dir / "new.txt").read_text() == "second revision"
    assert kind.health_sync(ctx)["reachable"]
    assert any(auth for _, _, auth in server.events)
    assert all(host == server.url.split("://", 1)[1] for _, host, _ in server.events)
    if server.ca:
        assert server.server_names and set(server.server_names) == {"git.example.test"}
    assert list(job.work_root.iterdir()) == []


@pytest.mark.parametrize("mode", ["clone", "fetch", "health"])
def test_real_git_refuses_redirect(tmp_path, config, monkeypatch, git_http_server, mode):
    server = git_http_server
    kind, ctx, job = live_job(tmp_path, config, monkeypatch, server)
    if mode == "fetch":
        kind.sync(job, "clone")
        server.events.clear()
    server.listener.redirect = True
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx) if mode == "health" else kind.sync(job, mode)
    assert exc.value.code == "GIT_SYNC_FAILED"
    assert server.events and all(path.startswith("/repo.git/") for path, _, _ in server.events)
    assert list(job.work_root.iterdir()) == []


def test_real_git_requires_trusted_tls(tmp_path, config, monkeypatch, git_http_server):
    server = git_http_server
    if not server.ca:
        return
    kind, ctx, job = live_job(tmp_path, config, monkeypatch, server, trust=False)
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx)
    assert exc.value.code == "GIT_SYNC_FAILED" and server.server_names
    assert not server.events and list(job.work_root.iterdir()) == []


def test_real_git_checks_tls_hostname(tmp_path, config, monkeypatch, git_http_server):
    server = git_http_server
    if not server.ca:
        return
    server.url = server.url.replace("git.example.test", "other.example.test")
    kind, ctx, job = live_job(tmp_path, config, monkeypatch, server)
    with pytest.raises(GatewayError) as exc:
        kind.health_sync(ctx)
    assert exc.value.code == "GIT_SYNC_FAILED" and server.server_names == ["other.example.test"]
    assert not server.events and list(job.work_root.iterdir()) == []


def test_real_git_refuses_http_alternate(tmp_path, config, monkeypatch, git_http_server):
    server = git_http_server
    kind, _, job = live_job(tmp_path, config, monkeypatch, server)
    objects = server.root / "repo.git" / "objects"
    head = git(["rev-parse", "HEAD"], server.source).stdout.strip()
    (objects / head[:2] / head[2:]).rename(server.root / "hidden-object")
    (objects / "info" / "http-alternates").write_text(server.url + "/escaped/objects\n")
    with pytest.raises(GatewayError) as exc:
        kind.sync(job, "clone")
    assert exc.value.code == "GIT_SYNC_FAILED"
    assert server.events and not any(path.startswith("/escaped") for path, _, _ in server.events)
    assert list(job.work_root.iterdir()) == []


@pytest.fixture
def git_ssh_server(tmp_path):
    """真实 Paramiko 服务端，提供 Git refs 和只读 SFTP 列表，密钥均现场生成。"""
    source = make_source_repo(tmp_path / "source")
    advertisement = subprocess.check_output(["git", "upload-pack", "--advertise-refs", str(source)])
    host_key, client_key = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    pem = io.StringIO()
    client_key.write_private_key(pem)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
    stopped, authenticated, commands, workers = threading.Event(), [], [], []

    class Server(paramiko.ServerInterface):
        def __init__(self):
            self.command_ready = threading.Event()

        def get_allowed_auths(self, username):
            return "publickey"

        def check_auth_publickey(self, username, key):
            if username == "git" and key == client_key:
                authenticated.append(username)
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            commands.append(command)
            self.command_ready.set()
            return command == b"git-upload-pack '/repo.git'"

    class Files(paramiko.SFTPServerInterface):
        def list_folder(self, path):
            item = paramiko.SFTPAttributes.from_stat((source / "README.md").stat())
            item.filename = "README.md"
            return [item]

    def serve(sock):
        with paramiko.Transport(sock) as transport:
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Files)
            handler = Server()
            try:
                transport.start_server(server=handler)
                channel = transport.accept(5)
                if channel is None:
                    return
                while transport.is_active() and not stopped.is_set():
                    if handler.command_ready.wait(0.05):
                        channel.sendall(advertisement)
                        channel.settimeout(5)
                        channel.recv(4)
                        channel.send_exit_status(0)
                        channel.close()
                        break
            except (EOFError, OSError, paramiko.SSHException):
                pass

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)

    def accept():
        while not stopped.is_set():
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            worker = threading.Thread(target=serve, args=(sock,), daemon=True)
            workers.append(worker)
            worker.start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(
            port=listener.getsockname()[1],
            fingerprint=fingerprint,
            private_key=pem.getvalue(),
            client_key=client_key,
            authenticated=authenticated,
            commands=commands,
        )
    finally:
        stopped.set()
        thread.join(2)
        listener.close()
        for worker in workers:
            worker.join(6)


@pytest.mark.parametrize("matches", [True, False])
def test_real_git_ssh_pinning_and_cleanup(tmp_path, config, monkeypatch, git_ssh_server, matches):
    server = git_ssh_server
    kind, ctx, job = network_job(tmp_path, config, f"ssh://git@git.example.test:{server.port}/repo.git")
    ctx.credential = {"private_key": server.private_key}
    ctx.asset["connection"]["host_key_sha256"] = server.fingerprint if matches else FINGERPRINT
    monkeypatch.setattr(ctx.network, "resolve", lambda *a: "127.0.0.1")
    if matches:
        assert kind.health_sync(ctx)["reachable"]
        assert server.authenticated and server.commands == [b"git-upload-pack '/repo.git'"]
    else:
        with pytest.raises(GatewayError) as exc:
            kind.health_sync(ctx)
        assert exc.value.code == "HOST_KEY_MISMATCH"
        assert not server.authenticated and not server.commands
    assert list(job.work_root.iterdir()) == []


@pytest.mark.parametrize("encrypted", [False, True])
def test_paramiko_ssh_sftp_key_compatibility(config, monkeypatch, git_ssh_server, encrypted):
    server = git_ssh_server
    ctx = context(config)
    ctx.asset["connection"] = {"host": "git.example.test", "port": server.port, "host_key_sha256": server.fingerprint}
    ctx.account["config"] = {"username": "git"}
    key = io.StringIO()
    server.client_key.write_private_key(key, password="test-passphrase" if encrypted else None)
    ctx.credential = {"private_key": key.getvalue(), "passphrase": "test-passphrase" if encrypted else None}
    monkeypatch.setattr(ctx.network, "resolve", lambda *a: "127.0.0.1")
    try:
        client = connect_ssh(ctx)
        assert client.get_transport().is_authenticated()
        with client.open_sftp() as sftp:
            assert sftp.listdir("/") == ["README.md"]
    finally:
        ctx.close()
