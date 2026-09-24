import subprocess

import pytest

from scripts.release_check import candidates, forbidden, scan_content


@pytest.mark.parametrize(
    "path", [".env", "data/gateway.db", ".preview/test.sqlite", "PROGRESS.md", "keys/private.pem", "cookies.txt"]
)
def test_release_rejects_private_paths(path):
    assert forbidden(path)


def test_release_allows_public_sources():
    assert not forbidden(".env.example")
    assert not forbidden("app/core/db.py")
    assert not forbidden("web/package-lock.json")


def test_release_scan_redacts_matches():
    token = "ghp_" + "x" * 36
    hits = scan_content("app/example.py", "token=" + token)
    assert len(hits) == 1 and "GitHub" in hits[0]
    assert token not in hits[0]
    address = ".".join(["172", "16", "10", "20"])
    assert scan_content("build.sh", address)
    assert not scan_content("tests/example.py", address)
    assert scan_content("tests/example.py", token)


@pytest.mark.parametrize(
    ("rule", "value"),
    [
        ("私钥内容", "-----BEGIN " + "PRIVATE KEY-----"),
        ("URL 内嵌凭据", "https://" + "user:password@example.test/repo.git"),
        ("GitHub 令牌", "ghp_" + "x" * 36),
    ],
)
def test_release_keeps_secret_rules_for_tests(rule, value):
    hits = scan_content("tests/example.py", value)
    assert hits == [f"tests/example.py:1: {rule}"]
    assert value not in hits[0]


def test_release_candidates_include_forced_private_files(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("test-only")
    (tmp_path / "README.md").write_text("说明")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-f", ".env"], check=True)
    paths, repository = candidates(tmp_path)
    assert repository and ".env" in paths
    paths, repository = candidates(tmp_path, staged=True)
    assert paths == [".env"]


def test_release_no_git_fallback_excludes_local_data(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/main.py").write_text("pass")
    (tmp_path / ".env").write_text("test-only")
    (tmp_path / "PROGRESS.md").write_text("本地记录")
    (tmp_path / "README.md").write_text("公开说明")
    (tmp_path / "USER_GUIDE.md").write_text("用户指南")
    paths, repository = candidates(tmp_path)
    assert not repository and paths == ["README.md", "USER_GUIDE.md", "app/main.py"]
    with pytest.raises(ValueError):
        candidates(tmp_path, staged=True)
