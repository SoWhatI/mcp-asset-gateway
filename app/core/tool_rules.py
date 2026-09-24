"""授权组内的工具参数规则：黑名单优先，白名单按完整授权组取并集。"""

import copy
import json
import time
from functools import lru_cache

import regex

from app.core.security import GatewayError

MAX_RULES = 200
MAX_PATTERN = 4096
MATCH_BUDGET = 0.1


@lru_cache(maxsize=512)
def compiled(pattern):
    return regex.compile(pattern)


def validate_rules(rules, tools, catalog=None):
    if not isinstance(rules, dict) or set(rules) - set(tools):
        raise GatewayError("RULE_INVALID", "参数规则只能绑定到本条目已授权的工具")
    count = 0
    for name, parameters in rules.items():
        if not isinstance(parameters, dict) or len(parameters) > 32:
            raise GatewayError("RULE_INVALID", "每个工具最多配置 32 个参数")
        properties = catalog[name]["inputSchema"].get("properties", {}) if catalog else None
        for parameter, lists in parameters.items():
            if not isinstance(parameter, str) or not 1 <= len(parameter) <= 128:
                raise GatewayError("RULE_INVALID", "参数名格式不正确")
            if properties is not None and parameter not in properties:
                raise GatewayError("RULE_INVALID", f"工具 {name} 不包含参数 {parameter}，请重新配置")
            if not isinstance(lists, dict) or set(lists) - {"allow", "deny"}:
                raise GatewayError("RULE_INVALID", "参数规则只支持 allow 白名单与 deny 黑名单")
            for items in lists.values():
                if not isinstance(items, list) or len(items) > 50:
                    raise GatewayError("RULE_INVALID", "每份黑白名单最多 50 条规则")
                for item in items:
                    count += 1
                    if count > MAX_RULES:
                        raise GatewayError("RULE_INVALID", "每个账号条目最多配置 200 条匹配规则")
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"match", "value"}
                        or item["match"] not in ("exact", "regex")
                        or not isinstance(item["value"], str)
                        or len(item["value"]) > MAX_PATTERN
                    ):
                        raise GatewayError("RULE_INVALID", "匹配规则须包含 exact/regex 类型与不超过 4096 字符的文本")
                    if item["match"] == "regex":
                        try:
                            compiled(item["value"])
                        except (regex.error, RecursionError, OverflowError):
                            raise GatewayError("RULE_INVALID", f"参数 {parameter} 的正则表达式无效") from None
    return copy.deepcopy(rules)


def argument_text(value):
    """字符串按原文；其它 JSON 值使用键排序、无空格的 JSON，避免类型隐式转换。"""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def enforce_rules(grants, tool, arguments, schema):
    deadline = time.monotonic() + MATCH_BUDGET
    effective = {
        key: copy.deepcopy(prop["default"])
        for key, prop in schema.get("properties", {}).items()
        if isinstance(prop, dict) and "default" in prop
    }
    effective.update(arguments)

    def matches(items, value):
        text = argument_text(value)
        for item in items:
            if time.monotonic() >= deadline:
                raise GatewayError("RULE_TIMEOUT", "参数规则匹配超时，调用已拒绝；请简化规则", 403)
            if item["match"] == "exact":
                if text == item["value"]:
                    return True
            else:
                try:
                    if compiled(item["value"]).fullmatch(text, timeout=max(0.001, deadline - time.monotonic())):
                        return True
                except TimeoutError:
                    raise GatewayError("RULE_TIMEOUT", "参数正则匹配超时，调用已拒绝；请简化表达式", 403) from None
                except (regex.error, RecursionError, OverflowError):
                    raise GatewayError("RULE_INVALID", "已保存的参数规则无效，调用已拒绝", 403) from None
        return False

    permitted = False
    for grant in grants:
        parameters = grant.get("parameter_rules", {}).get(tool, {})
        allowed = True
        for parameter, lists in parameters.items():
            allow, deny = lists.get("allow", []), lists.get("deny", [])
            if not allow and not deny:
                continue
            # 无可确定默认值时不允许省略受约束参数，避免上游默认行为绕过规则。
            if parameter not in effective:
                if deny:
                    raise GatewayError("ARGUMENT_DENIED", f"受黑名单约束的参数 {parameter} 必须显式提供", 403)
                allowed = False
                continue
            value = effective[parameter]
            if matches(deny, value):
                raise GatewayError("ARGUMENT_DENIED", f"参数 {parameter} 命中授权组黑名单", 403)
            if allow and not matches(allow, value):
                allowed = False
        permitted = permitted or allowed
    if not permitted:
        raise GatewayError("ARGUMENT_DENIED", "工具参数未满足任何授权组的完整白名单条件", 403)
    # 将参与匹配的默认值显式传给适配器/上游，保证校验值与实际执行值一致。
    for grant in grants:
        for parameter, lists in grant.get("parameter_rules", {}).get(tool, {}).items():
            if (lists.get("allow") or lists.get("deny")) and parameter not in arguments and parameter in effective:
                arguments[parameter] = effective[parameter]
