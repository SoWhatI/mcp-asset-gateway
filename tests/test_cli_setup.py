import os
import stat
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent.parent


def run_setup(cwd, *args, check=True):
    return subprocess.run(
        [sys.executable, "-m", "app.cli", "setup", *args],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        check=check,
    )


def parse_env(text):
    return dict(line.split("=", 1) for line in text.strip().splitlines())


def test_setup_stdout_outputs_env_only_and_key_is_valid(tmp_path):
    result = run_setup(tmp_path, "--output", "-")
    lines = parse_env(result.stdout)
    Fernet(lines["GATEWAY_MASTER_KEY"])
    assert lines["IMAGE_TAG"] == "0.1.0"
    assert lines["COOKIE_SECURE"] == "false"
    assert "chmod 600" in result.stderr
    assert "GATEWAY_MASTER_KEY=" not in result.stderr


def test_setup_stdout_https_derives_cookie_secure(tmp_path):
    result = run_setup(tmp_path, "--public-url", "https://gw.example.com", "--output", "-")
    lines = parse_env(result.stdout)
    assert lines["COOKIE_SECURE"] == "true"
    assert lines["PUBLIC_BASE_URL"] == "https://gw.example.com"


def test_setup_file_mode_writes_restricted_permissions(tmp_path):
    result = run_setup(tmp_path)
    target = tmp_path / ".env"
    assert target.is_file()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "已创建权限受限的 .env" in result.stdout
    second = run_setup(tmp_path, check=False)
    assert second.returncode != 0
