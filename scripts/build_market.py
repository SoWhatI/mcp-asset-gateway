"""官方插件市场聚合构建：打包全部插件、合并历史版本、签名索引并生成门户页。

用法（在仓库根目录）：
    python scripts/build_market.py --out dist/market \
        [--key <base64-ed25519-私钥>] [--merge-from <https://...|本地目录>] [--changes <说明>]

与单插件 build.py 的差异：
- 扫描 examples/plugins/*/manifest.json，一次产出多插件市场索引；
- 各插件目录可选 deps.txt（requirements 片段）声明第三方依赖，
  构建时下载 wheel 并生成 requirements.lock，与安装器离线装配约定一致；
- --merge-from 指向上一次发布（Pages URL 或本地目录）时，保留历史版本的
  制品与索引条目：同版本号且哈希相同视为幂等，同版本号不同哈希拒绝（防覆盖）；
- 索引有效期为 7 天，官方发布必须配 CI 定时重签（见 plugin-market workflow）。

签名私钥优先取 --key，其次 PLUGIN_SIGN_KEY 环境变量；两者皆缺时生成一次性
密钥并打印公钥（仅限本地演示，正式发布必须在受控环境保管私钥）。
"""

import argparse
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PLUGINS_SOURCE = Path(__file__).resolve().parent.parent / "examples" / "plugins"
INDEX_TTL_MS = 7 * 24 * 3600 * 1000

PORTAL_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MCP 资产网关 · 官方插件市场</title>
<style>
body{font-family:system-ui,-apple-system,"PingFang SC",sans-serif;margin:0;background:#f5f6fa;color:#1f2329}
header{background:#6558d3;color:#fff;padding:28px 32px}header h1{margin:0 0 6px;font-size:22px}header p{margin:0;opacity:.85;font-size:13px}
main{max-width:960px;margin:24px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:18px 20px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.card h2{margin:0 0 4px;font-size:17px}.card .id{color:#8a8f99;font-size:12px;margin-bottom:8px}
.card p{margin:6px 0;font-size:14px;line-height:1.6}
.versions{margin-top:10px}.ver{border-top:1px solid #f0f1f5;padding:8px 0;font-size:13px}
.ver b{color:#6558d3}.ver .sha{color:#8a8f99;font-family:ui-monospace,monospace;font-size:11px;word-break:break-all}
.tool{display:inline-block;background:#eef0ff;color:#4b41b8;border-radius:4px;padding:1px 8px;margin:2px 4px 2px 0;font-size:12px}
footer{max-width:960px;margin:24px auto;padding:0 16px;color:#8a8f99;font-size:12px}
</style></head><body>
<header><h1>MCP 资产网关 · 官方插件市场</h1><p>索引经 ed25519 签名；安装校验以网关内配置的公钥与制品哈希为准。</p></header>
<main id="list">加载中…</main>
<footer>接入方式：网关 .env 配置 PLUGIN_MARKET_URL 指向本站 + PLUGIN_MARKET_PUBLIC_KEY 为官方公钥，详见仓库 docs/plugins.md。</footer>
<script>
fetch('./index.json').then(r=>r.json()).then(index=>{
  const el=document.getElementById('list');
  el.innerHTML=index.plugins.map(p=>`<div class="card"><h2>${esc(p.name||p.id)}</h2>
  <div class="id">${esc(p.id)} · 发布者 ${esc(p.publisher||'-')}</div>
  <p>${esc(p.description||'')}</p>
  <div class="versions">${p.versions.map(v=>`<div class="ver"><b>v${esc(v.version)}</b>
   ${esc(v.changes||'')}<br>${(v.types||[]).map(t=>(t.tools||[]).map(x=>`<span class="tool">${esc(x)}</span>`).join('')).join('')}
   <div class="sha">sha256: ${esc(v.sha256||'')} · ${new Date(v.published_at).toLocaleString()}</div></div>`).join('')}</div></div>`).join('');
}).catch(e=>{document.getElementById('list').textContent='索引加载失败：'+e});
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
</script></body></html>
"""


def load_key(arguments):
    encoded = arguments.key or os.environ.get("PLUGIN_SIGN_KEY", "").strip()
    if encoded:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 32:
            raise SystemExit("签名私钥必须是 base64 编码的 32 字节 ed25519 私钥")
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


def lockfile(wheelhouse):
    lines = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        name, version = wheel.stem.split("-", 2)[:2]
        lines.append(f"{name}=={version} --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def build_plugin(source, workdir):
    """打包单个插件：返回 (manifest, 制品字节, sha256)。第三方依赖经 deps.txt 声明。"""
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    wheelhouse = workdir / "wheelhouse"
    lock = ""
    deps_file = source / "deps.txt"
    if deps_file.exists():
        requirements = [
            line.strip() for line in deps_file.read_text().splitlines() if line.strip() and not line.startswith("#")
        ]
        if requirements:
            wheelhouse.mkdir(parents=True, exist_ok=True)
            if any(wheelhouse.glob("*.whl")):
                # 插件源码已提交锁定 wheelhouse（与已发布制品一致）：跳过下载，
                # 避免 CI 重新解析传递依赖（如 pip 新增 tzdata）导致制品哈希漂移。
                print(
                    f"{manifest['id']}：使用锁定 wheelhouse（{len(list(wheelhouse.glob('*.whl')))} 个 wheel，跳过下载）"
                )
            else:
                for requirement in requirements:
                    subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "pip",
                            "download",
                            requirement,
                            "--only-binary=:all:",
                            "-d",
                            str(wheelhouse),
                        ],
                        check=True,
                    )
            lock = lockfile(wheelhouse)
    module = manifest["entry"].partition(":")[0]
    # 确定性打包：zip 内条目的时间戳与权限位必须固定，否则 CI 每次 checkout
    # 的 mtime 不同会导致同版本制品哈希漂移，触发防覆盖保护。
    fixed_time = (1980, 1, 1, 0, 0, 0)
    buffer = io.BytesIO()

    def add_member(data, name):
        info = zipfile.ZipInfo(name, date_time=fixed_time)
        info.external_attr = 0o100644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        buffer.seek(0)
        with zipfile.ZipFile(buffer, "a", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(info, data)

    add_member((source / "manifest.json").read_bytes(), "manifest.json")
    for schema in sorted((source / "schemas").glob("*.json")):
        add_member(schema.read_bytes(), f"schemas/{schema.name}")
    for code in sorted((source / module).rglob("*.py")):
        add_member(code.read_bytes(), str(code.relative_to(source)))
    add_member(lock.encode(), "requirements.lock")
    if lock:
        for wheel in sorted(wheelhouse.glob("*.whl")):
            add_member(wheel.read_bytes(), f"wheelhouse/{wheel.name}")
    payload = buffer.getvalue()
    return manifest, payload, hashlib.sha256(payload).hexdigest()


def fetch_previous(location):
    """读取上一次发布的索引；返回 dict 或 None（首次发布/不可达时为 None）。"""
    staged = Path(location).expanduser().resolve() if "://" not in location else None
    if staged is not None:
        index_path = staged / "index.json"
        if not index_path.exists():
            print(f"合并来源 {staged} 缺少 index.json，按首次发布处理")
            return None
        return json.loads(index_path.read_text(encoding="utf-8"))
    import httpx

    try:
        response = httpx.get(location.rstrip("/") + "/index.json", follow_redirects=False, timeout=15)
    except httpx.HTTPError:
        print(f"合并来源不可达（{location}），按首次发布处理")
        return None
    if response.status_code == 404:
        print("合并来源尚无索引（首次发布）")
        return None
    response.raise_for_status()
    return response.json()


def read_artifact(merge_from, relative):
    """搬运历史制品：本地目录直接读，https 用 httpx；缺失返回 None。"""
    if not relative or relative.startswith(("/", "..")) or "://" in relative:
        return None
    staged = Path(merge_from).expanduser().resolve() if "://" not in merge_from else None
    if staged is not None:
        path = staged / relative
        return path.read_bytes() if path.exists() else None
    import httpx

    try:
        response = httpx.get(merge_from.rstrip("/") + "/" + relative, follow_redirects=False, timeout=30)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    return response.content


def carry_history(previous, merge_from, artifacts_dir, fresh_entries):
    """把历史版本条目与制品并入本次发布；返回 {plugin_id: [历史版本条目]}。"""
    history = {}
    carried = 0
    for plugin in previous.get("plugins", []):
        plugin_id = plugin.get("id", "")
        keep = []
        for entry in plugin.get("versions", []):
            fresh_entry = next(
                (v for v in fresh_entries.get(plugin_id, []) if v["version"] == entry.get("version")), None
            )
            if fresh_entry is not None:
                if fresh_entry["sha256"] != entry.get("sha256"):
                    raise SystemExit(f"版本冲突：{plugin_id}@{entry['version']} 已以不同内容发布，禁止覆盖")
                continue  # 本次重新构建且内容一致：由新条目（新时间戳）替换
            relative = entry.get("artifact", "")
            data = read_artifact(merge_from, relative)
            if data is None:
                print(f"警告：历史制品不可达，跳过 {plugin_id}@{entry.get('version')}（{relative}）")
                continue
            (artifacts_dir / Path(relative).name).write_bytes(data)
            keep.append(entry)
            carried += 1
        if keep:
            history[plugin_id] = keep
    if carried:
        print(f"已保留 {carried} 个历史版本条目及其制品")
    return history


def resign_only(arguments, out, artifacts_dir, private):
    """纯重签：不重建制品，只搬运现有发布并延长索引有效期。

    cron 定时重签必须走此模式——重签 ≠ 重新构建。若在 CI 中重新打包，
    传递依赖（如 pip 新解析出的 wheel）会让制品哈希漂移，触发防覆盖保护；
    而放宽防覆盖又会允许同版本内容漂移，破坏供应链模型。
    """
    if not arguments.merge_from:
        raise SystemExit("--resign-only 必须配合 --merge-from（对哪次发布重签）")
    previous = fetch_previous(arguments.merge_from)
    if previous is None:
        raise SystemExit(f"重签来源不可用：{arguments.merge_from}")
    plugins = []
    for plugin in previous.get("plugins", []):
        versions = []
        for entry in plugin.get("versions", []):
            relative = entry.get("artifact", "")
            data = read_artifact(arguments.merge_from, relative)
            if data is None:
                print(f"警告：制品不可达，该版本将失去可安装性，跳过 {plugin.get('id')}@{entry.get('version')}")
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest != entry.get("sha256"):
                raise SystemExit(
                    f"制品哈希与索引不符：{relative}（索引 {str(entry.get('sha256'))[:16]}… != 实际 {digest[:16]}…）"
                )
            (artifacts_dir / Path(relative).name).write_bytes(data)
            versions.append(entry)
        if versions:
            plugins.append({**plugin, "versions": versions})
    index = {
        "version": previous.get("version", 1),
        "generated_at": int(time.time() * 1000),
        "expires_at": int(time.time() * 1000) + INDEX_TTL_MS,
        "plugins": plugins,
    }
    payload_index = json.dumps(index, ensure_ascii=False).encode()
    (out / "index.json").write_bytes(payload_index)
    (out / "index.sig").write_text(base64.b64encode(private.sign(payload_index)).decode(), encoding="utf-8")
    (out / "index.html").write_text(PORTAL_HTML, encoding="utf-8")
    print(f"已完成纯重签：{len(plugins)} 个插件，{sum(len(p['versions']) for p in plugins)} 个版本，索引有效期 7 天")


def generate_key_pair():
    """生成官方密钥对并打印：私钥进 CI Secret，公钥进 README 与部署配置。"""
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("PLUGIN_SIGN_KEY=" + base64.b64encode(raw).decode())
    print("PLUGIN_MARKET_PUBLIC_KEY=" + base64.b64encode(public).decode())
    print("私钥存入仓库 Actions Secret（不得入库/外发）；公钥写入 README 供自部署用户配置。")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--generate-key", action="store_true", help="生成官方密钥对后退出")
    parser.add_argument("--out", default="dist/market", help="市场输出目录")
    parser.add_argument("--key", default=None, help="base64 ed25519 私钥（缺省读 PLUGIN_SIGN_KEY 环境变量）")
    parser.add_argument("--merge-from", default=None, help="上一次发布位置（https URL 或本地目录），用于保留历史版本")
    parser.add_argument(
        "--resign-only", action="store_true", help="纯重签：不重建制品，仅延长现有索引有效期（cron 用）"
    )
    parser.add_argument("--changes", default="", help="本次发布变更说明")
    arguments = parser.parse_args()
    if arguments.generate_key:
        generate_key_pair()
        return

    out = Path(arguments.out)
    artifacts_dir = out / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    private = load_key(arguments)

    if arguments.resign_only:
        resign_only(arguments, out, artifacts_dir, private)
        return

    sources = sorted(path for path in PLUGINS_SOURCE.iterdir() if (path / "manifest.json").exists())
    if not sources:
        raise SystemExit("examples/plugins 下没有可发布的插件")

    published_at = int(time.time() * 1000)
    fresh = {}
    for source in sources:
        manifest, payload, digest = build_plugin(source, out.parent / ".build" / source.name)
        artifact_name = f"{manifest['id']}-{manifest['version']}.zip"
        (artifacts_dir / artifact_name).write_bytes(payload)
        fresh[manifest["id"]] = {
            "entry": {
                "version": manifest["version"],
                "artifact": f"artifacts/{artifact_name}",
                "sha256": digest,
                "size": len(payload),
                "sdk_protocol": manifest["sdk_protocol"],
                "gateway_compat": manifest.get("gateway_compat", ""),
                "published_at": published_at,
                "changes": arguments.changes or f"版本 {manifest['version']} 发布",
                "types": [
                    {
                        "type_id": t["type_id"],
                        "display_name": t["display_name"],
                        "tools": [tool["name"] for tool in t["tools"]],
                    }
                    for t in manifest["types"]
                ],
            },
            "plugin": {
                "id": manifest["id"],
                "publisher": manifest["publisher"],
                "name": manifest["name"],
                "description": manifest["description"],
                "capabilities": manifest["capabilities"],
            },
        }
        print(f"已打包 {manifest['id']}@{manifest['version']}（{len(payload)} 字节，sha256 {digest[:16]}…）")

    history = {}
    if arguments.merge_from:
        previous = fetch_previous(arguments.merge_from)
        if previous:
            history = carry_history(
                previous, arguments.merge_from, artifacts_dir, {pid: [v["entry"]] for pid, v in fresh.items()}
            )

    plugins = []
    for plugin_id, value in fresh.items():
        plugin = dict(value["plugin"])
        plugin["versions"] = [value["entry"]] + history.get(plugin_id, [])
        plugins.append(plugin)
    index = {
        "version": 1,
        "generated_at": int(time.time() * 1000),
        "expires_at": int(time.time() * 1000) + INDEX_TTL_MS,
        "plugins": plugins,
    }
    payload_index = json.dumps(index, ensure_ascii=False).encode()
    (out / "index.json").write_bytes(payload_index)
    (out / "index.sig").write_text(base64.b64encode(private.sign(payload_index)).decode(), encoding="utf-8")
    (out / "index.html").write_text(PORTAL_HTML, encoding="utf-8")

    public_b64 = base64.b64encode(
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    print(
        f"市场目录已生成：{out.resolve()}（{len(plugins)} 个插件，{sum(len(p['versions']) for p in plugins)} 个版本）"
    )
    print("PLUGIN_MARKET_PUBLIC_KEY=" + public_b64)


if __name__ == "__main__":
    main()
