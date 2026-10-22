"""构建 PostgreSQL 示例插件制品并产出签名市场目录。

用法（在仓库根目录）：
    python examples/plugins/acme.postgresql/build.py --out dist/market [--key <base64-ed25519-私钥>]

步骤：下载依赖 wheel（含哈希锁定）→ 打包 ZIP → 计算 sha256 → 写市场索引并用
ed25519 私钥签名。私钥可用 PLUGIN_SIGN_KEY 环境变量传入；未提供时自动生成
并打印公钥（仅适合本地演示，正式发布应在受控环境保管私钥）。
"""

import argparse
import base64
import hashlib
import io
import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
DEPS = {"pg8000": "1.30.1"}


def pip_download(wheelhouse):
    """下载完整依赖树（含传递依赖），安装器按 lock 哈希离线装入插件 venv。"""
    wheelhouse.mkdir(parents=True, exist_ok=True)
    for package, version in DEPS.items():
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                f"{package}=={version}",
                "--only-binary=:all:",
                "-d",
                str(wheelhouse),
            ],
            check=True,
        )


def lockfile(wheelhouse):
    lines = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        # 从文件名解析 name-version（wheel 命名规范：name-version-py3-none-any.whl）。
        stem = wheel.stem
        name, version = stem.split("-", 2)[:2]
        lines.append(f"{name}=={version} --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def build_artifact():
    manifest = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(SOURCE / "manifest.json", "manifest.json")
        for schema in sorted((SOURCE / "schemas").glob("*.json")):
            bundle.write(schema, f"schemas/{schema.name}")
        for module in sorted((SOURCE / "acme_postgresql").rglob("*.py")):
            bundle.write(module, str(module.relative_to(SOURCE)))
        wheelhouse = SOURCE / "wheelhouse"
        if wheelhouse.is_dir():
            bundle.writestr("requirements.lock", lockfile(wheelhouse))
            for wheel in sorted(wheelhouse.glob("*.whl")):
                bundle.write(wheel, f"wheelhouse/{wheel.name}")
        else:
            bundle.writestr("requirements.lock", "")
    return manifest, buffer.getvalue()


def load_or_create_key(encoded):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if encoded:
        raw = base64.b64decode(encoded)
        return Ed25519PrivateKey.from_private_bytes(raw)
    private = Ed25519PrivateKey.generate()
    print("未提供签名私钥，已生成一次性密钥（仅限本地演示）：")
    print(
        "PLUGIN_SIGN_KEY="
        + base64.b64encode(
            private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
        ).decode()
    )
    return private


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist/market", help="市场输出目录")
    parser.add_argument("--key", default=None, help="base64 ed25519 私钥")
    arguments = parser.parse_args()

    wheelhouse = SOURCE / "wheelhouse"
    if not wheelhouse.is_dir() or not list(wheelhouse.glob("*.whl")):
        print("下载依赖 wheel（需要网络）…")
        pip_download(wheelhouse)

    manifest, payload = build_artifact()
    out = Path(arguments.out)
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    artifact_name = f"{manifest['id']}-{manifest['version']}.zip"
    (out / "artifacts" / artifact_name).write_bytes(payload)

    entry = {
        "version": manifest["version"],
        "artifact": f"artifacts/{artifact_name}",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "sdk_protocol": manifest["sdk_protocol"],
        "gateway_compat": manifest.get("gateway_compat", ""),
        "published_at": int(time.time() * 1000),
        "changes": "首个版本：list_tables / describe_table / sql_query / sql_execute",
        "types": [
            {"type_id": t["type_id"], "display_name": t["display_name"], "tools": [tool["name"] for tool in t["tools"]]}
            for t in manifest["types"]
        ],
    }
    index = {
        "version": 1,
        "generated_at": int(time.time() * 1000),
        "expires_at": int(time.time() * 1000) + 7 * 24 * 3600 * 1000,
        "plugins": [
            {
                "id": manifest["id"],
                "publisher": manifest["publisher"],
                "name": manifest["name"],
                "description": manifest["description"],
                "capabilities": manifest["capabilities"],
                "versions": [entry],
            }
        ],
    }
    payload_index = json.dumps(index, ensure_ascii=False).encode()
    (out / "index.json").write_bytes(payload_index)
    private = load_or_create_key(arguments.key)
    (out / "index.sig").write_text(base64.b64encode(private.sign(payload_index)).decode(), encoding="utf-8")
    from cryptography.hazmat.primitives import serialization as _s

    public_b64 = base64.b64encode(private.public_key().public_bytes(_s.Encoding.Raw, _s.PublicFormat.Raw)).decode()
    print(f"市场目录已生成：{out.resolve()}")
    print("PLUGIN_MARKET_URL=file://" + str(out.resolve()))
    print("PLUGIN_MARKET_PUBLIC_KEY=" + public_b64)


if __name__ == "__main__":
    main()
