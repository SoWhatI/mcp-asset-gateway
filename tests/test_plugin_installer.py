import base64
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.security import GatewayError
from app.plugins.installer import safe_unpack
from app.plugins.manifest import lint_form_schema, validate_manifest
from app.plugins.market import MarketClient


def zipped(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, payload in entries.items():
            bundle.writestr(name, payload)
    return buffer.getvalue()


def unpacked_with(archive_bytes, tmp_path):
    archive = tmp_path / "a.zip"
    archive.write_bytes(archive_bytes)
    safe_unpack(archive, tmp_path / "out")


def test_unpack_rejects_path_traversal(tmp_path):
    with pytest.raises(GatewayError) as raised:
        unpacked_with(zipped({"../escape.txt": "x"}), tmp_path)
    assert raised.value.code == "UNPACK_UNSAFE"
    assert not (tmp_path.parent / "escape.txt").exists()


def test_unpack_rejects_absolute_paths(tmp_path):
    with pytest.raises(GatewayError) as raised:
        unpacked_with(zipped({"/etc/passwd": "x"}), tmp_path)
    assert raised.value.code == "UNPACK_UNSAFE"


def test_unpack_rejects_symlink_entries(tmp_path):
    info = zipfile.ZipInfo("link.txt")
    # Unix 创建系统 + S_IFLNK 模式位模拟软链条目。
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr(info, "/etc/passwd")
    with pytest.raises(GatewayError) as raised:
        unpacked_with(buffer.getvalue(), tmp_path)
    assert raised.value.code == "UNPACK_UNSAFE"


def test_unpack_rejects_too_many_files(tmp_path):
    entries = {f"dir/file-{i}.txt": "x" for i in range(3000)}
    with pytest.raises(GatewayError) as raised:
        unpacked_with(zipped(entries), tmp_path)
    assert raised.value.code == "UNPACK_LIMIT"


def test_unpack_accepts_directories_and_normal_files(tmp_path):
    safe_archive = zipped({"manifest.json": "{}", "pkg/__init__.py": "x", "pkg/": ""})
    unpacked_with(safe_archive, tmp_path)
    assert (tmp_path / "out" / "manifest.json").read_text() == "{}"


def make_market(tmp_path, index=None, sign=True):
    private = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    payload = json.dumps(
        index
        or {
            "version": 1,
            "generated_at": 1,
            "expires_at": 4102444800000,
            "plugins": [{"id": "a.b", "versions": [{"version": "1.0.0", "artifact": "artifacts/x.zip"}]}],
        }
    ).encode()
    (tmp_path / "index.json").write_bytes(payload)
    if sign:
        (tmp_path / "index.sig").write_text(base64.b64encode(private.sign(payload)).decode())
    return MarketClient("file://" + str(tmp_path), MarketClient.__mro__ and _key(public_b64))


def _key(public_b64):
    from app.plugins.market import load_public_key

    return load_public_key(public_b64)


def test_market_rejects_bad_signature(tmp_path):
    market = make_market(tmp_path)
    market.public_key = _key(
        base64.b64encode(
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode()
    )
    with pytest.raises(GatewayError) as raised:
        market.index(refresh=True)
    assert raised.value.code == "MARKET_SIGNATURE"


def test_market_rejects_unsigned_index(tmp_path):
    market = make_market(tmp_path, sign=False)
    (tmp_path / "index.sig").write_text(base64.b64encode(b"\x00" * 64).decode())
    with pytest.raises(GatewayError) as raised:
        market.index(refresh=True)
    assert raised.value.code == "MARKET_SIGNATURE"


def test_market_rejects_expired_index(tmp_path):
    market = make_market(tmp_path, index={"version": 1, "generated_at": 1, "expires_at": 1, "plugins": []})
    with pytest.raises(GatewayError) as raised:
        market.index(refresh=True)
    assert raised.value.code == "MARKET_EXPIRED"


def test_market_rejects_unsafe_artifact_paths(tmp_path):
    market = make_market(tmp_path)
    with pytest.raises(GatewayError) as raised:
        market.artifact_url("../escape.zip")
    assert raised.value.code == "MARKET_PROTOCOL"
    with pytest.raises(GatewayError):
        market.artifact_url("https://evil.example/x.zip")


def test_schema_lint_rejects_unsupported_constructs():
    good = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "title": "主机", "minLength": 1},
            "tags": {"type": "array", "items": {"type": "string", "maxLength": 64}},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        },
        "required": ["host"],
        "additionalProperties": False,
    }
    lint_form_schema(good, "ok")
    with pytest.raises(GatewayError):
        lint_form_schema({**good, "properties": {"host": {"type": "string", "$ref": "#/x"}}}, "ref")
    with pytest.raises(GatewayError):
        lint_form_schema({**good, "properties": {"nested": {"type": "object"}}}, "object")
    with pytest.raises(GatewayError):
        lint_form_schema({**good, "properties": {"mode": {"type": "string", "format": "html"}}}, "format")
    with pytest.raises(GatewayError):
        lint_form_schema({**good, "additionalProperties": True}, "open")
    with pytest.raises(GatewayError):
        lint_form_schema(
            {**good, "properties": {"a": {"type": "string"}, "b": {"type": "string"}}, "oneOf": []}, "oneOf"
        )


def test_validate_manifest_enforces_publisher_prefix_and_protocol():
    base = {
        "id": "acme.demo",
        "version": "1.0.0",
        "publisher": "acme",
        "sdk_protocol": 1,
        "entry": "m:K",
        "types": [{"type_id": "acme.demo", "schemas": {}, "tools": []}],
    }
    manifest = validate_manifest(json.loads(json.dumps(base)))
    assert manifest["capabilities"] == {"network": True, "credential": True, "write": False}
    with pytest.raises(GatewayError):
        wrong_prefix = json.loads(json.dumps(base))
        wrong_prefix["types"][0]["type_id"] = "other.demo"
        validate_manifest(wrong_prefix)
    with pytest.raises(GatewayError):
        bad_protocol = json.loads(json.dumps(base))
        bad_protocol["sdk_protocol"] = 99
        validate_manifest(bad_protocol)
    with pytest.raises(GatewayError):
        bad_version = json.loads(json.dumps(base))
        bad_version["version"] = "latest"
        validate_manifest(bad_version)
