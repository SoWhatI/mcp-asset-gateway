"""manifest 校验与 Schema 表单子集 lint。

安装时静态校验：插件身份、协议兼容、入口、类型归属与能力声明；
四类 Schema 只允许控制台 SchemaForm 已支持的字段子集，
拒绝 $ref、嵌套对象、脚本注入等一切超集，插件不能借表单注入前端内容。
"""

import json
import re

from app.core.security import GatewayError

SDK_PROTOCOL = 1

PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}\.[a-z0-9][a-z0-9-]{0,30}$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(-[a-z0-9.-]+)?$")
ENTRY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")

ICON_ALLOWLIST = {
    "Connection",
    "Coin",
    "Monitor",
    "FolderOpened",
    "DataLine",
    "Platform",
    "Document",
    "VideoPlay",
    "Box",
    "Cpu",
    "Brush",
    "Lightning",
    "Link",
    "Cloudy",
    "MagicStick",
    "Compass",
    "Grid",
    "Histogram",
    "Key",
    "Lock",
    "Message",
    "Notification",
    "Odometer",
    "Picture",
    "Position",
    "Printer",
    "Search",
    "Setting",
    "Stamp",
    "Switch",
    "Timer",
    "TrendCharts",
    "Umbrella",
    "Watch",
}

SCALAR_TYPES = {"string", "integer", "number", "boolean"}
# SchemaForm 支持的字段约束关键字；出现其他关键字一律拒绝。
STRING_KEYWORDS = {"title", "description", "default", "enum", "minLength", "maxLength", "pattern", "format"}
NUMBER_KEYWORDS = {"title", "description", "default", "enum", "minimum", "maximum"}
SHARED_KEYWORDS = {"type", "x-hidden", "x-upload"}
MAX_TOOLS = 50
MAX_SCHEMA_BYTES = 64 * 1024


def _reject(code, message):
    raise GatewayError("MANIFEST_INVALID", f"{code}：{message}", 422)


def lint_form_schema(schema, where):
    """校验单个表单 Schema 只使用受支持的子集。"""
    if not isinstance(schema, dict):
        _reject(where, "必须是 JSON 对象")
    if len(json.dumps(schema, ensure_ascii=False).encode()) > MAX_SCHEMA_BYTES:
        _reject(where, "schema 超过大小上限")
    if set(schema) - {"type", "properties", "required", "additionalProperties"}:
        _reject(
            where,
            f"{where} 含不支持的关键字 {sorted(set(schema) - {'type', 'properties', 'required', 'additionalProperties'})}",
        )
    if schema.get("type") != "object":
        _reject(where, "顶层必须是 object")
    if schema.get("additionalProperties") is not False:
        _reject(where, "必须声明 additionalProperties:false")
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        _reject(where, "properties 必须是非空对象")
    if len(properties) > 64:
        _reject(where, "属性数量超过上限")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(k, str) for k in required):
        _reject(where, "required 必须是字符串数组")
    if set(required) - set(properties):
        _reject(where, "required 引用了不存在的属性")
    for key, field in properties.items():
        if not isinstance(key, str) or not 1 <= len(key) <= 64:
            _reject(where, "属性名长度必须为 1～64")
        _lint_field(field, f"{where}.{key}")


def _lint_field(field, where):
    if not isinstance(field, dict):
        _reject(where, "必须是对象")
    kind = field.get("type")
    if kind == "array":
        allowed = SHARED_KEYWORDS | {"items"}
        if set(field) - allowed:
            _reject(where, "数组字段含不支持的关键字")
        items = field.get("items")
        if not isinstance(items, dict) or items.get("type") != "string":
            _reject(where, "数组 items 只支持字符串")
        _lint_string_items(items, where)
        return
    if kind not in SCALAR_TYPES:
        _reject(where, "字段类型只支持 string/integer/number/boolean/array")
    keyword_pool = {
        "string": STRING_KEYWORDS,
        "integer": NUMBER_KEYWORDS,
        "number": NUMBER_KEYWORDS,
        "boolean": {"title", "description", "default"},
    }[kind]
    if set(field) - SHARED_KEYWORDS - keyword_pool:
        _reject(where, f"含不支持的关键字 {sorted(set(field) - SHARED_KEYWORDS - keyword_pool)}")
    if "enum" in field:
        enum = field["enum"]
        if not isinstance(enum, list) or not enum or len(enum) > 64 or len(set(map(str, enum))) != len(enum):
            _reject(where, "enum 必须是 1～64 个不重复值")
        if kind in ("integer", "number") and any(type(v) not in (int, float) for v in enum):
            _reject(where, "enum 值类型必须匹配字段类型")
        if kind == "string" and any(not isinstance(v, str) for v in enum):
            _reject(where, "enum 值必须是字符串")
    if kind == "string" and field.get("format") not in (None, "password"):
        _reject(where, "format 只支持 password")
    if "default" in field and kind == "integer" and type(field["default"]) is not int:
        _reject(where, "default 类型必须匹配字段类型")
    if "maxLength" in field and type(field["maxLength"]) is not int:
        _reject(where, "maxLength 必须是整数")


def _lint_string_items(items, where):
    if set(items) - (STRING_KEYWORDS | {"type"}):
        _reject(where, "数组 items 含不支持的关键字")


def lint_tool(spec, where):
    """静态工具 spec 校验：名称、schema 合法性与注解结构。"""
    from app.core.security import check_schema

    if not isinstance(spec, dict) or not isinstance(spec.get("name"), str):
        _reject(where, "工具必须包含字符串 name")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", spec["name"]):
        _reject(where, f"工具名 {spec['name']!r} 不合法")
    if not isinstance(spec.get("description"), str) or not 1 <= len(spec["description"]) <= 4096:
        _reject(where, "工具必须包含 1～4096 字符的 description")
    schema = spec.get("inputSchema")
    if not isinstance(schema, dict):
        _reject(where, "工具必须包含 inputSchema")
    check_schema(schema)
    annotations = spec.get("annotations", {})
    if annotations and not isinstance(annotations, dict):
        _reject(where, "annotations 必须是对象")
    allowed = {"name", "description", "inputSchema", "outputSchema", "annotations"}
    if set(spec) - allowed:
        _reject(where, f"工具 spec 含不支持的字段 {sorted(set(spec) - allowed)}")


def validate_manifest(manifest, builtin_ids=(), registered_ids=()):
    """校验并归一化 manifest；返回可直接入库的规范形态。

    builtin_ids/registered_ids 用于安装时检查类型冲突（禁止覆盖内置或其他插件类型）。
    """
    if not isinstance(manifest, dict):
        _reject("manifest", "必须是 JSON 对象")
    for key in ("id", "version", "publisher", "entry"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            _reject(key, "缺失或不是字符串")
    if not PLUGIN_ID_PATTERN.fullmatch(manifest["id"]):
        _reject("id", "必须是 发布者.名称 形式的小写标识")
    if not manifest["id"].startswith(manifest["publisher"] + "."):
        _reject("id", "必须以发布者前缀开头")
    if not VERSION_PATTERN.fullmatch(manifest["version"]):
        _reject("version", "必须是语义化版本（如 1.2.0）")
    if manifest.get("sdk_protocol") != SDK_PROTOCOL:
        _reject("sdk_protocol", f"SDK 协议版本不兼容（当前支持 {SDK_PROTOCOL}）")
    if not ENTRY_PATTERN.fullmatch(manifest["entry"]):
        _reject("entry", "必须是 模块:类 形式")
    if len(manifest.get("description", "")) > 2000:
        _reject("description", "说明超过 2000 字符")
    workers = manifest.get("workers", 2)
    if type(workers) is not int or not 1 <= workers <= 4:
        _reject("workers", "工作进程数必须是 1～4")
    capabilities = manifest.get("capabilities", {})
    if (
        not isinstance(capabilities, dict)
        or set(capabilities) - {"network", "credential", "write"}
        or any(type(v) is not bool for v in capabilities.values())
    ):
        _reject("capabilities", "只能是 network/credential/write 的布尔声明")

    types = manifest.get("types")
    if not isinstance(types, list) or not types:
        _reject("types", "插件必须声明至少一个资产类型")
    normalized, seen = [], set()
    for entry in types:
        if not isinstance(entry, dict) or not isinstance(entry.get("type_id"), str):
            _reject("types", "类型条目必须包含 type_id")
        type_id = entry["type_id"]
        if type_id in seen:
            _reject("types", f"类型重复：{type_id}")
        seen.add(type_id)
        if not type_id.startswith(manifest["publisher"] + "."):
            _reject("types", f"类型 {type_id} 必须以发布者前缀 {manifest['publisher']}. 开头")
        if type_id in builtin_ids or type_id in registered_ids:
            _reject("types", f"类型 {type_id} 与内置或其他插件类型冲突")
        if not PLUGIN_ID_PATTERN.fullmatch(type_id):
            _reject("types", f"类型标识 {type_id} 不合法")
        display_name = entry.get("display_name") or type_id
        if not isinstance(display_name, str) or not 1 <= len(display_name) <= 64:
            _reject("types", "显示名称长度必须为 1～64")
        icon = entry.get("icon", "Connection")
        if icon not in ICON_ALLOWLIST:
            _reject("types", f"图标 {icon!r} 不在允许清单内")
        if entry.get("connection_mode", "host_port") not in ("host_port", "url"):
            _reject("types", "connection_mode 只支持 host_port/url")
        tools = entry.get("tools", [])
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
            _reject("types", f"静态工具数量必须是 0～{MAX_TOOLS}")
        names = set()
        for spec in tools:
            lint_tool(spec, f"types[{type_id}].tools")
            if spec["name"] in names:
                _reject("types", f"工具名重复：{spec['name']}")
            names.add(spec["name"])
        normalized.append(
            {
                "type_id": type_id,
                "display_name": display_name,
                "icon": icon,
                "default_port": entry.get("default_port"),
                "connection_mode": entry.get("connection_mode", "host_port"),
                "dynamic_tools": bool(entry.get("dynamic_tools")),
                "schemas": entry.get("schemas") or {},
                "tools": tools,
            }
        )
    return {
        "id": manifest["id"],
        "version": manifest["version"],
        "publisher": manifest["publisher"],
        "name": manifest.get("name") or manifest["id"],
        "description": manifest.get("description", ""),
        "sdk_protocol": SDK_PROTOCOL,
        "gateway_compat": manifest.get("gateway_compat", ""),
        "python_compat": manifest.get("python_compat", ">=3.11"),
        "platforms": manifest.get("platforms") or [],
        "entry": manifest["entry"],
        "workers": workers,
        "capabilities": {"network": True, "credential": True, "write": False, **capabilities},
        "types": normalized,
    }


def hydrate_schemas(manifest, read_file):
    """把 schema_files 声明替换为文件内容；归一后的 manifest.types[].schemas 为内联 Schema。"""
    for entry in manifest.get("types", []):
        files = entry.pop("schema_files", None)
        if not files:
            continue
        if not isinstance(files, dict) or set(files) - {"connection", "account", "credential", "policy"}:
            _reject("schema_files", "只能声明 connection/account/credential/policy")
        schemas = entry.get("schemas") or {}
        for key, relative in files.items():
            if key in schemas:
                _reject("schema_files", f"{key} 同时存在内联声明与文件声明")
            try:
                schemas[key] = json.loads(read_file(relative))
            except (OSError, ValueError):
                _reject("schema_files", f"无法读取 {relative}")
        entry["schemas"] = schemas
    return manifest
