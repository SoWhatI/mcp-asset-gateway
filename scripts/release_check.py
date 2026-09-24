"""只读发布候选检查；只报告路径、行号和规则，不输出疑似秘密原文。"""

import argparse
import fnmatch
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = {
    ".git",
    ".env",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".preview",
    "data",
    "backups",
    "static",
    ".local",
    ".local-e2e",
    ".qoder",
    ".idea",
    ".vscode",
    "htmlcov",
    "playwright-report",
    "test-results",
    "dist",
}
PRIVATE_FILES = (
    ".env",
    ".env.*",
    "*.db*",
    "*.sqlite*",
    "*.pem",
    "*.key",
    "*.pyc",
    "*.log",
    "*.cookies",
    "*cookie*.jar",
    "cookies*.txt",
    ".verify_*",
    ".coverage*",
    ".DS_Store",
    "._*",
    "PROGRESS.md",
    "MCP资产网关设计文档.md",
)
ROOT_FILES = {
    ".gitignore",
    ".dockerignore",
    ".gitattributes",
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "pyproject.toml",
    "requirements.in",
    "requirements.lock",
    "requirements-dev.txt",
    "build-and-push.sh",
    "deploy.sh",
    "README.md",
    "USER_GUIDE.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
}
SOURCE_DIRS = {"app", "web", "tests", "scripts", ".github"}
RULES = {
    "私钥内容": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "GitHub 令牌": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "云访问密钥": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "URL 内嵌凭据": re.compile(r"[a-z]+://[^\s/:@{}]+:[^\s/@{}]+@", re.I),
    "硬编码主密钥": re.compile(r"GATEWAY_MASTER_KEY\s*[=:]\s*['\"]?[A-Za-z0-9_-]{43}="),
    "Fernet 密文": re.compile(r"\bgAAAAA[A-Za-z0-9_-]{70,}={0,2}"),
    "内网 IPv4": re.compile(r"(?<![\w.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\w.])"),
}


def forbidden(path):
    parts = Path(path).parts
    if path == ".env.example":
        return False
    return any(p in PRIVATE_DIRS or p.endswith(".egg-info") for p in parts) or any(
        fnmatch.fnmatch(parts[-1], pattern) for pattern in PRIVATE_FILES
    )


def scan_content(path, content):
    findings = []
    for number, line in enumerate(content.splitlines(), 1):
        for name, pattern in RULES.items():
            # 测试包含用于验证出站隔离的内网地址；令牌、密钥规则仍然生效。
            if name == "内网 IPv4" and path.startswith("tests/"):
                continue
            if pattern.search(line):
                findings.append(f"{path}:{number}: {name}")
    return findings


def git(*args, root=ROOT):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True).stdout


def candidates(root, staged=False):
    try:
        top = Path(git("rev-parse", "--show-toplevel", root=root).decode().strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        top = None
    if top == root.resolve():
        args = (
            ("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
            if staged
            else ("ls-files", "--cached", "--others", "--exclude-standard", "-z")
        )
        return sorted(set(git(*args, root=root).decode().split("\0")) - {""}), True
    if staged:
        raise ValueError("项目根目录尚未初始化 Git，无法检查暂存内容")
    paths = []
    for current, dirs, files in os.walk(root):
        relative = Path(current).relative_to(root)
        dirs[:] = [
            d
            for d in dirs
            if d not in PRIVATE_DIRS and not d.endswith(".egg-info") and (relative != Path(".") or d in SOURCE_DIRS)
        ]
        for name in files:
            path = (relative / name).as_posix()
            if not forbidden(path) and (relative != Path(".") or name in ROOT_FILES):
                paths.append(path)
    return sorted(paths), False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="检查暂存的确切内容，不检查工作区替代内容")
    args = parser.parse_args()
    try:
        paths, repository = candidates(ROOT, args.staged)
    except ValueError as error:
        parser.error(str(error))
    findings = []
    for path in paths:
        file = ROOT / path
        if forbidden(path):
            findings.append(f"{path}: 禁止发布的运行数据或本地文件")
            continue
        if args.staged:
            mode = git("ls-files", "--stage", "--", path).decode().split()[0]
            if mode not in {"100644", "100755"}:
                findings.append(f"{path}: 请人工核对非普通文件")
                continue
            content = git("show", ":" + path)
        else:
            if file.is_symlink():
                findings.append(f"{path}: 不允许发布符号链接")
                continue
            if not file.exists():
                continue
            content = file.read_bytes()
        if len(content) > 2 * 1024 * 1024 or b"\0" in content:
            findings.append(f"{path}: 请人工核对二进制或大文件")
            continue
        try:
            findings.extend(scan_content(path, content.decode("utf-8")))
        except UnicodeDecodeError:
            findings.append(f"{path}: 请人工核对非 UTF-8 文件")
    scope = "Git 暂存内容" if args.staged else "Git 工作区候选" if repository else "工作区源码白名单（尚无 Git）"
    print(f"已检查 {len(paths)} 个文件：{scope}；未扫描历史提交。")
    if findings:
        print("\n".join(findings))
        raise SystemExit(1)
    print("未发现上述规则命中；这不是无秘密保证。公开前仍须人工检查、完整历史秘密扫描和依赖审计。")


if __name__ == "__main__":
    main()
