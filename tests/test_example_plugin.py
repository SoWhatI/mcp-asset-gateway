"""示例插件（acme.postgresql）静态契约：manifest 与 Schema 必须通过安装期校验。"""

import json
from pathlib import Path

import pytest

from app.plugins.installer import BUILTIN_IDS
from app.plugins.manifest import hydrate_schemas, lint_form_schema, validate_manifest

SOURCE = Path(__file__).resolve().parents[1] / "examples/plugins/acme.postgresql"


def test_example_manifest_passes_install_validation():
    raw = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    raw = hydrate_schemas(raw, lambda relative: (SOURCE / relative).read_text(encoding="utf-8"))
    manifest = validate_manifest(raw, builtin_ids=BUILTIN_IDS, registered_ids=set())
    (entry,) = manifest["types"]
    assert entry["type_id"] == "acme.postgresql"
    assert [tool["name"] for tool in entry["tools"]] == [
        "list_tables",
        "describe_table",
        "sql_query",
        "sql_execute",
    ]
    for key in ("connection", "account", "credential", "policy"):
        lint_form_schema(entry["schemas"][key], f"acme.postgresql.{key}")
    # 写操作能力与破坏性工具标注一致。
    sql_execute = next(tool for tool in entry["tools"] if tool["name"] == "sql_execute")
    assert sql_execute["annotations"]["destructiveHint"] is True
    assert manifest["capabilities"]["write"] is True


@pytest.mark.parametrize(
    "sql,allowed",
    [
        ("SELECT 1", True),
        ("with t as (select 1) select * from t", True),
        ("explain select 1", True),
        ("show server_version", True),
        ("INSERT INTO t VALUES (1)", False),
        ("DELETE FROM t", False),
        ("", False),
    ],
)
def test_readonly_prefix_rules(sql, allowed):
    """只读白名单规则在源码中静态可见；这里复刻校验逻辑避免漂移。"""
    import re

    source = (SOURCE / "acme_postgresql" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r"READ_ONLY_PREFIXES = (\([^)]*\))", source)
    assert match, "示例插件必须声明只读前缀白名单"
    prefixes = eval(match.group(1))  # noqa: S307 — 固定源码内常量
    first = sql.strip().split(None, 1)[0].lower() if sql.strip() else ""
    assert (first in prefixes) is allowed
