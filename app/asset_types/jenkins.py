"""原生 Jenkins 资产：HTTP API 与受限的 workflow-cps Replay 表单兼容。"""

import asyncio
import base64
import json
import re
import xml.etree.ElementTree as ET
from collections import deque
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

import httpx
import regex

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool, upload_text
from app.asset_types.jenkins_http import JenkinsHTTP, job_path, json_form, root_url
from app.asset_types.jenkins_logs import LogCursor, read_log, search_log
from app.core.security import GatewayError

JOB = {
    "jobFullName": text(
        "任务完整名称",
        minLength=1,
        maxLength=1024,
        description="文件夹用 / 分隔；多分支自身的斜杠用 Jenkins 名称中的 %2F 表示",
    )
}
BUILD = {**JOB, "buildNumber": integer("构建号（留空固定为本次调用开始时的最后构建）")}
PAGE = {"skip": integer("起始下标", 0, 100000, default=0), "limit": integer("返回数量", 1, 10, default=10)}
BOOL = {"type": "boolean"}
SCALAR = {"type": ["string", "boolean", "number"], "maxLength": 65536}
PARAMETERS = {
    "type": "object",
    "title": "构建参数",
    "maxProperties": 100,
    "propertyNames": {"minLength": 1, "maxLength": 256},
    "additionalProperties": {"anyOf": [SCALAR, {"type": "array", "items": SCALAR, "maxItems": 100}]},
}
BUILD_FIELDS = "_class,number,displayName,description,building,result,duration,estimatedDuration,timestamp,url,queueId"
JOB_FIELDS = "_class,name,fullName,displayName,description,url,buildable,inQueue,color,lastBuild[number,url],lastCompletedBuild[number,result],nextBuildNumber"
PARAM_FIELDS = "property[parameterDefinitions[_class,name,description,choices,defaultParameterValue[value]]]"
SIMPLE_JOB = "_class,name,fullName,displayName,url,color,lastBuild[number],lastCompletedBuild[result]"
WRITES = {"trigger_build", "update_build", "rebuild_build", "replay_build"}


def jtool(name, description, fields=None, required=()):
    return tool("jenkins_" + name, description, fields or {}, required, readonly=name not in WRITES)


def pick(value, fields):
    return {key: value[key] for key in fields.split(",") if key in value}


def unsupported(message, code="JENKINS_UNSUPPORTED"):
    raise GatewayError(code, message, 422)


def parameter_definitions(job):
    return [p for prop in job.get("property", []) for p in prop.get("parameterDefinitions", [])]


def parameter_kind(definition):
    return definition.get("_class", "").rsplit(".", 1)[-1]


def parameter_form(definitions, values, rebuild=False):
    known = {p["name"]: p for p in definitions}
    if set(values) - set(known):
        unsupported("构建参数不在可见参数定义中", "JENKINS_PARAMETER")
    pairs = []
    for name, definition in known.items():
        kind = parameter_kind(definition)
        supported = {
            "StringParameterDefinition",
            "TextParameterDefinition",
            "BooleanParameterDefinition",
            "ChoiceParameterDefinition",
            "PasswordParameterDefinition",
        }
        if kind not in supported or (rebuild and kind == "PasswordParameterDefinition"):
            unsupported(
                "文件、未知插件或无法恢复的密码参数不受支持",
                "JENKINS_REBUILD_UNSUPPORTED" if rebuild else "JENKINS_PARAMETER",
            )
        if name in values:
            value = values[name]
        elif (
            rebuild
            or kind == "PasswordParameterDefinition"
            or "value" not in (definition.get("defaultParameterValue") or {})
        ):
            unsupported(
                "缺少可恢复的参数值；不会静默使用未知默认值",
                "JENKINS_REBUILD_UNSUPPORTED" if rebuild else "JENKINS_PARAMETER",
            )
        else:
            value = definition["defaultParameterValue"]["value"]
        for item in value if isinstance(value, list) else [value]:
            if type(item) not in (str, bool, int, float):
                unsupported("构建参数必须为标量或标量数组", "JENKINS_PARAMETER")
            if kind == "BooleanParameterDefinition" and type(item) is not bool:
                unsupported("布尔参数必须使用 JSON true/false", "JENKINS_PARAMETER")
            rendered = ("true" if item else "false") if isinstance(item, bool) else str(item)
            if kind == "ChoiceParameterDefinition" and rendered not in definition.get("choices", []):
                unsupported("选项参数不在任务允许值中", "JENKINS_PARAMETER")
            pairs.append((name, rendered))
    return pairs


def parse_xml(content):
    try:
        value = content.decode("utf-8-sig")
        if re.search(r"<!\s*(DOCTYPE|ENTITY)", value, re.I) or "\x00" in value:
            raise ValueError
        return ET.fromstring(value)
    except (ValueError, ET.ParseError, RecursionError):
        raise GatewayError("JENKINS_XML", "Jenkins 配置 XML 不兼容或包含禁用的 DTD/实体", 502) from None


def safe_scm_url(value):
    # 不返回 URL 内嵌的用户密码、查询 Token 或片段；SCP 语法只保留仓库定位信息。
    if "://" not in value:
        return value.split("?", 1)[0].split("#", 1)[0]
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if ":" in host:
            host = "[" + host + "]"
        return f"{parsed.scheme}://{host}{':' + str(parsed.port) if parsed.port else ''}{parsed.path}"
    except ValueError:
        return "[无效仓库地址]"


def scm_config(content):
    root = parse_xml(content)
    scms = []
    for node in root.iter():
        kind = node.get("class", node.tag)
        if kind == "hudson.plugins.git.GitSCM":
            remotes = [
                {"url": safe_scm_url(e.findtext("url") or ""), "name": e.findtext("name") or "origin"}
                for e in node.findall("./userRemoteConfigs/*")
            ]
            branches = [e.text or "" for e in node.findall("./branches/*/name")]
            scms.append(
                {"type": "git", "remoteUrls": [r["url"] for r in remotes], "remotes": remotes, "branches": branches}
            )
        elif kind == "jenkins.plugins.git.GitSCMSource":
            remote = node.findtext("remote")
            if remote:
                scms.append(
                    {
                        "type": "git",
                        "remoteUrls": [safe_scm_url(remote)],
                        "remotes": [{"url": safe_scm_url(remote), "name": "origin"}],
                        "branches": [],
                        "dynamicBranches": True,
                    }
                )
    dynamic = root.tag.endswith("WorkflowJob") and root.find("definition") is not None and not scms
    return {"scms": scms, "partial": dynamic, "note": "仅包含可静态解析的 Git SCM，不代表任意运行时 checkout"}


def repository_key(value):
    value = safe_scm_url(value)
    if "://" not in value:
        matched = re.fullmatch(r"(?:[^@/:]+@)?([^/:]+):(.+)", value)
        if not matched:
            return value.removesuffix(".git").rstrip("/")
        host, path = matched.groups()
    else:
        parsed = urlsplit(value)
        host, path = parsed.hostname or "", parsed.path
    return host.lower() + "/" + path.strip("/").removesuffix(".git")


def branch_matches(pattern, branch, repository="origin"):
    if "$" in pattern or pattern == "":
        return True
    # 对齐 BranchSpec.matchesRepositoryBranch：保留分支路径，只去掉 Git ref 前缀。
    branch = re.sub(r"^refs/(?:heads|tags|remotes)/", "", branch)
    candidates = [branch, repository + "/" + branch]
    if pattern.startswith(":"):
        try:
            return any(regex.fullmatch(pattern[1:], value, timeout=0.02) for value in candidates)
        except (regex.error, TimeoutError):
            raise GatewayError("JENKINS_SCM_PATTERN", "SCM 分支模式无效或匹配超时", 502) from None
    pattern = re.sub(r"^refs/(?:heads|tags|remotes)/", "", pattern).removeprefix("remotes/")
    expression = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return any(re.fullmatch(expression, value) for value in candidates)


class ReplayHTML(HTMLParser):
    """保留 textarea 原文并验证表单字段；不执行 JS，不猜测未知页面结构。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "root", "attrs": {}, "children": [], "parent": None}
        self.stack = [self.root]
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        if len(self.nodes) >= 30000 or len(self.stack) > 100:
            unsupported("Replay 页面结构超限", "JENKINS_REPLAY_UNSUPPORTED")
        node = {"tag": tag, "attrs": dict(attrs), "children": [], "parent": self.stack[-1]}
        self.stack[-1]["children"].append(node)
        self.nodes.append(node)
        if tag not in {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                self.stack[index]["closed"] = True
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1]["children"].append(data)

    def inside(self, node, parent):
        while node:
            if node is parent:
                return True
            node = node["parent"]
        return False

    def node_text(self, node):
        return "".join(item if isinstance(item, str) else self.node_text(item) for item in node["children"])

    def scripts(self, http, page_path, content):
        try:
            self.feed(content.decode("utf-8", "strict"))
            self.close()
            if any(node["tag"] in ("form", "textarea") for node in self.stack):
                unsupported("Replay 表单未完整闭合，拒绝使用不完整源码", "JENKINS_REPLAY_UNSUPPORTED")
        except (UnicodeError, RecursionError):
            unsupported("Replay 页面编码或结构不兼容", "JENKINS_REPLAY_UNSUPPORTED")
        forms = {}
        for node in self.nodes:
            if node["tag"] == "form" and node["attrs"].get("method", "").lower() == "post":
                target = http.location(http.root + page_path, node["attrs"].get("action"))
                for action in ("run", "rebuild"):
                    if target is not None and str(target) == str(httpx.URL(http.root + page_path + action)):
                        if action in forms:
                            unsupported("Replay 页面包含重复提交表单", "JENKINS_REPLAY_UNSUPPORTED")
                        if not node.get("closed"):
                            unsupported("Replay 表单未完整闭合", "JENKINS_REPLAY_UNSUPPORTED")
                        forms[action] = node
        if "run" not in forms:
            if "rebuild" in forms:
                unsupported("该 Replay 页面仅允许原样重建，不允许读取或修改脚本", "JENKINS_REPLAY_FORBIDDEN")
            unsupported("Replay 页面不可用：缺插件、权限、原脚本或页面结构不兼容", "JENKINS_REPLAY_UNSUPPORTED")
        fields, loaded, mapping = {}, {}, {}
        for node in self.nodes:
            if node["tag"] != "textarea" or not self.inside(node, forms["run"]):
                continue
            field = node["attrs"].get("name", "").removeprefix("_.")
            if not field or field in fields or "disabled" in node["attrs"] or not node.get("closed"):
                unsupported("Replay 表单字段不兼容", "JENKINS_REPLAY_UNSUPPORTED")
            fields[field] = self.node_text(node)
            if field == "mainScript":
                continue
            ancestor = node["parent"]
            while ancestor and "jenkins-form-item" not in ancestor["attrs"].get("class", "").split():
                ancestor = ancestor["parent"]
            labels = [
                n
                for n in self.nodes
                if ancestor and self.inside(n, ancestor) and "jenkins-form-label" in n["attrs"].get("class", "").split()
            ]
            label = self.node_text(labels[0]).strip() if len(labels) == 1 else ""
            if (
                not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$]*", label)
                or label.replace(".", "_") != field
                or label in loaded
            ):
                unsupported("Replay 已加载脚本名称无法可靠映射", "JENKINS_REPLAY_UNSUPPORTED")
            loaded[label], mapping[label] = fields[field], field
        if "mainScript" not in fields or not fields["mainScript"]:
            unsupported("Replay 原始脚本不存在或已被清理", "JENKINS_REPLAY_UNSUPPORTED")
        return {"mainScript": fields["mainScript"], "loadedScripts": loaded}, mapping


class JenkinsAssetType(AssetType):
    type_id, display_name, icon = "jenkins", "Jenkins 持续集成", "VideoPlay"
    async_mode = True
    connection_schema = obj(
        {
            "url": text("Jenkins 根地址", minLength=1, description="支持 /jenkins 上下文路径；无需安装 MCP 插件"),
            "ca_file": upload_text("CA 证书（PEM 或容器内路径）", maxLength=262144),
        },
        ["url"],
    )
    account_schema = obj({"username": text("Jenkins 用户名", minLength=1, maxLength=256)}, ["username"])
    credential_schema = obj(
        {"api_token": text("API Token", minLength=1, maxLength=8192, format="password")}, ["api_token"]
    )
    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "max_log_scan_bytes": integer("日志扫描字节上限", 1024, 32 * 1024 * 1024, default=8 * 1024 * 1024),
            "max_scan_jobs": integer("SCM 搜索任务上限", 1, 1000, default=200),
        }
    )
    tools = [
        jtool("get_job", "查询任务配置摘要、参数定义和构建摘要。", JOB, ["jobFullName"]),
        jtool(
            "get_jobs",
            "按名称分页列出可见任务或文件夹；参数规则不自动过滤结果。",
            {**PAGE, "parentFullName": text("父文件夹全名", maxLength=1024)},
        ),
        jtool(
            "trigger_build",
            "触发普通或参数化构建；需显式授权，超时勿重试。",
            {**JOB, "parameters": PARAMETERS},
            ["jobFullName"],
        ),
        jtool(
            "get_queue_item", "查询队列项，区分等待、取消、已分配构建和记录过期。", {"id": integer("队列 ID")}, ["id"]
        ),
        jtool("get_build", "查询指定构建或本次固定的最后构建。", BUILD, ["jobFullName"]),
        jtool(
            "update_build",
            "仅更新构建名称和描述；未提供的字段保持原值。",
            {**BUILD, "displayName": text("显示名称", maxLength=1024), "description": text("描述", maxLength=65536)},
            ["jobFullName"],
        ),
        jtool(
            "get_build_log",
            "有界读取构建日志，支持负 skip 取尾部及网关专用签名 cursor。",
            {
                **BUILD,
                "skip": integer("跳过行数（负数取尾部）", -1000000, 1000000, default=0),
                "limit": integer("返回行数（负数向前取窗口，0 使用默认）", -5000, 5000, default=100),
                "cursor": text("续读游标", maxLength=4096),
            },
            ["jobFullName"],
        ),
        jtool(
            "search_build_log",
            "有界搜索日志；预算耗尽、长行裁剪会明确标记结果不完整。",
            {
                **BUILD,
                "pattern": text("搜索文本或正则", minLength=1, maxLength=1024),
                "useRegex": {**BOOL, "title": "正则搜索", "default": False},
                "ignoreCase": {**BOOL, "title": "忽略大小写", "default": False},
                "maxMatches": integer("最大匹配数", 1, 1000, default=100),
                "contextLines": integer("前后文行数", 0, 10, default=0),
            },
            ["jobFullName", "pattern"],
        ),
        jtool("rebuild_build", "原样重建：Pipeline 使用原脚本；其它任务仅恢复可验证参数。", BUILD, ["jobFullName"]),
        jtool(
            "get_replay_scripts",
            "读取 Pipeline 原始脚本，要求配置读取及 Replay 权限；不返回截断源码。",
            BUILD,
            ["jobFullName"],
        ),
        jtool(
            "replay_build",
            "用指定脚本重放 Pipeline；需 workflow-cps 与 Replay 权限，远端状态未知时不重试。",
            {
                **BUILD,
                "mainScript": text("主脚本", minLength=1, maxLength=262144),
                "loadedScripts": {
                    "type": "object",
                    "title": "已加载脚本",
                    "maxProperties": 100,
                    "additionalProperties": text("脚本", maxLength=262144),
                },
            },
            ["jobFullName", "mainScript"],
        ),
        jtool(
            "get_test_results",
            "读取测试报告，失败包含 FAILED 和 REGRESSION。",
            {**BUILD, "onlyFailingTests": {**BOOL, "title": "仅失败测试", "default": False}},
            ["jobFullName"],
        ),
        jtool("get_flaky_failures", "读取测试报告导出的 flakyFailures；版本不支持时明确失败。", BUILD, ["jobFullName"]),
        jtool("get_job_scm", "读取任务配置中的 Git SCM 白名单字段；不输出凭据 ID 或原始 XML。", JOB, ["jobFullName"]),
        jtool("get_build_scm", "读取历史构建 Git BuildData，绝不以当前配置冒充历史数据。", BUILD, ["jobFullName"]),
        jtool("get_build_change_sets", "读取构建提交及文件变更摘要。", BUILD, ["jobFullName"]),
        jtool(
            "find_jobs_with_scm_url",
            "按仓库和分支搜索可见任务，受遍历预算限制并标记部分结果。",
            {**PAGE, "scmUrl": text("Git 仓库地址", minLength=1), "branch": text("分支", maxLength=1024)},
            ["scmUrl"],
        ),
        jtool("who_am_i", "查询当前 Jenkins 身份，不将匿名 200 视为认证成功。"),
        jtool("get_status", "汇总可见队列和执行器状态；未导出的管理能力标记 unavailable。"),
    ]

    def __init__(self, cursor_key):
        self.cursor = LogCursor(cursor_key)

    def validate_connection(self, network, connection):
        network.url(root_url(connection["url"]))

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        root_url(connection["url"])
        if ":" in account["username"] or re.search(r"[\x00-\x1f\x7f]", account["username"] + credential["api_token"]):
            raise GatewayError("JENKINS_AUTH_CONFIG", "用户名不能含冒号，用户名和 API Token 不能含控制字符")

    async def health(self, ctx):
        async with asyncio.timeout(ctx.remaining()), JenkinsHTTP(ctx) as http:
            await self.identity(http)
            return {"reachable": True, "authenticated": True}

    async def identity(self, http):
        data = await http.json("whoAmI/api/json", "name,authenticated,anonymous,authorities")
        if data.get("authenticated") is not True or data.get("anonymous") is True or data.get("name") == "anonymous":
            raise GatewayError("JENKINS_AUTH", "Jenkins 返回匿名身份，请检查用户名与 API Token", 502)
        value = pick(data, "name,authenticated,anonymous,authorities")
        if data.get("name"):
            try:
                value["user"] = await http.json(
                    "user/" + quote(data["name"], safe="") + "/api/json", "id,fullName,description"
                )
            except GatewayError as error:
                if error.code not in ("JENKINS_FORBIDDEN", "JENKINS_NOT_FOUND"):
                    raise
                value["user"] = {"unavailable": True}
        return value

    async def build(self, http, args, job):
        number = args.get("buildNumber")
        if args.get("cursor"):
            number, _ = self.cursor.decode(args["cursor"], http.ctx, args["jobFullName"], number)
        if number is None:
            value = await http.json(job + "api/json", "lastBuild[number]")
            number = (value.get("lastBuild") or {}).get("number")
        if type(number) is not int or number < 1:
            raise GatewayError("JENKINS_NO_BUILD", "任务尚无可见构建", 404)
        return job + str(number) + "/", number

    async def execute(self, name, args, ctx, spec):
        args = self.validate_arguments(name, args)
        if args.get("jobFullName"):
            job_path(args["jobFullName"])
        if args.get("cursor") and args.get("skip", 0) != 0:
            raise GatewayError("JENKINS_CURSOR", "cursor 与非零 skip 不能同时使用")
        async with JenkinsHTTP(ctx) as http:
            try:
                async with asyncio.timeout(ctx.remaining()):
                    value = await self.dispatch(name.removeprefix("jenkins_"), args, ctx, http)
            except TimeoutError:
                raise GatewayError(
                    "JENKINS_WRITE_UNKNOWN" if http.write_started else "TIMEOUT",
                    "调用超时；已提交的远端状态可能未知，勿自动重试",
                    504,
                ) from None
        # 托管凭据从所有字符串值和键中脱敏。业务日志秘密仍需要 Jenkins 自身掩码。
        token = ctx.credential["api_token"]
        auth = base64.b64encode((ctx.account["config"]["username"] + ":" + token).encode()).decode()
        source = name == "jenkins_get_replay_scripts"
        clipped = False

        def clean(item, field=None):
            nonlocal clipped
            if isinstance(item, str):
                safe = item.replace(token, "[REDACTED]").replace(auth, "[REDACTED]")
                if source and safe != item:
                    raise GatewayError("JENKINS_SOURCE_REDACTED", "Replay 源码含托管凭据，拒绝返回修改后的源码")
                if len(safe) > ctx.limits["max_cell_chars"]:
                    if source or field == "nextCursor":
                        raise GatewayError("OUTPUT_LIMIT", "Replay 源码或日志游标超过字段限制，不能安全裁剪")
                    clipped = True
                    return safe[: ctx.limits["max_cell_chars"]]
                return safe
            if isinstance(item, list):
                if len(item) > ctx.limits["max_result_rows"]:
                    clipped = True
                return [clean(x) for x in item[: ctx.limits["max_result_rows"]]]
            if isinstance(item, dict):
                return {
                    k.replace(token, "[REDACTED]").replace(auth, "[REDACTED]"): clean(v, k) for k, v in item.items()
                }
            return item

        value = clean(value)
        if clipped or ctx.stats.get("truncated"):
            value["truncated"] = True
        ctx.stats["truncated"] = bool(value.get("truncated"))
        ctx.stats["row_count"] = sum(len(v) for v in value.values() if isinstance(v, list))
        output = result(value)
        if len(json.dumps(output, ensure_ascii=False).encode()) > ctx.limits["max_output_bytes"]:
            raise GatewayError("OUTPUT_LIMIT", "Jenkins 结果超过输出上限，请缩小查询范围")
        return output

    async def dispatch(self, name, args, ctx, http):
        job = job_path(args["jobFullName"]) if "jobFullName" in args else ""
        if name == "who_am_i":
            return await self.identity(http)
        if name == "get_status":
            return await self.status(http)
        if name == "get_jobs":
            parent = job_path(args["parentFullName"]) if args.get("parentFullName") else ""
            data = await http.json(parent + "api/json", f"jobs[{SIMPLE_JOB}]")
            jobs = sorted(data.get("jobs", []), key=lambda j: j.get("name", ""))
            skip, limit = args.get("skip", 0), min(args.get("limit", 10), ctx.limits["max_result_rows"])
            return {"jobs": jobs[skip : skip + limit], "total": len(jobs), "hasMore": len(jobs) > skip + limit}
        if name == "get_job":
            data = await http.json(
                job + "api/json", JOB_FIELDS + "," + PARAM_FIELDS + ",builds[number,result,url]{0,10}"
            )
            definitions = parameter_definitions(data)
            data.pop("property", None)
            data["parameters"] = [pick(p, "name,description,choices,_class") for p in definitions]
            return data
        if name == "get_queue_item":
            data = await http.json(
                f"queue/item/{args['id']}/api/json",
                "id,cancelled,blocked,buildable,stuck,why,inQueueSince,executable[number,url],task[name,url]",
                allowed=(404,),
            )
            if data is None:
                return {"id": args["id"], "state": "expired_or_not_visible"}
            data["state"] = (
                "cancelled" if data.get("cancelled") else "assigned" if data.get("executable") else "waiting"
            )
            return data
        if name == "get_job_scm":
            return scm_config((await http.request(job + "config.xml")).content)
        if name == "find_jobs_with_scm_url":
            return await self.find_scm(http, args, ctx)
        if name == "trigger_build":
            data = await http.json(job + "api/json", "buildable," + PARAM_FIELDS)
            return await self.trigger(http, job, data, args.get("parameters", {}))
        path, number = await self.build(http, args, job)
        if name == "get_build":
            return await http.json(path + "api/json", BUILD_FIELDS)
        if name == "get_build_log":
            return await read_log(http, ctx, args, path, number, self.cursor)
        if name == "search_build_log":
            return await search_log(http, ctx, args, path, number)
        if name == "update_build":
            if not any(key in args for key in ("displayName", "description")):
                raise GatewayError("JENKINS_PARAMETER", "至少提供 displayName 或 description")
            current = await http.json(path + "api/json", "displayName,description")
            fields = {key: args.get(key, current.get(key) or "") for key in ("displayName", "description")}
            value = await http.submit(path + "configSubmit", json_form(fields), path)
            return {"updated": True, "buildNumber": number, "url": value["url"]}
        if name in ("get_test_results", "get_flaky_failures"):
            return await self.tests(http, path, args, name)
        if name == "get_build_scm":
            data = await http.json(
                path + "api/json",
                "actions[_class,remoteUrls,lastBuiltRevision[SHA1,branch[name,SHA1]],buildsByBranchName[*]]",
            )
            scms = []
            for action in data.get("actions", []):
                if action.get("_class") == "hudson.plugins.git.util.BuildData":
                    revision = action.get("lastBuiltRevision") or {}
                    scms.append(
                        {
                            "remoteUrls": [safe_scm_url(u) for u in action.get("remoteUrls", [])],
                            "revision": revision.get("SHA1"),
                            "branches": revision.get("branch", []),
                        }
                    )
            return {"buildNumber": number, "scms": scms, "unavailable": not bool(scms)}
        if name == "get_build_change_sets":
            data = await http.json(
                path + "api/json",
                "changeSet[items[commitId,id,msg,timestamp,author[fullName],paths[editType,file]]],changeSets[items[commitId,id,msg,timestamp,author[fullName],paths[editType,file]]]",
            )
            sets = data.get("changeSets") or ([data["changeSet"]] if data.get("changeSet") else [])
            return {
                "buildNumber": number,
                "changes": [
                    pick(item, "commitId,id,msg,timestamp,author,paths")
                    for group in sets
                    for item in group.get("items", [])
                ],
            }
        if name == "rebuild_build":
            return await self.rebuild(http, job, path)
        if name in ("get_replay_scripts", "replay_build"):
            data = await http.json(path + "api/json", "_class")
            if data.get("_class") != "org.jenkinsci.plugins.workflow.job.WorkflowRun":
                unsupported("该构建不是 Pipeline", "JENKINS_REPLAY_UNSUPPORTED")
            # 读取配置仅用作权限校验，不向调用者输出原始 XML。
            await http.request(job + "config.xml")
            response = await http.request(path + "replay/", allowed=(404,))
            if response.status_code == 404:
                unsupported("Replay 插件、原脚本或入口不可用", "JENKINS_REPLAY_UNSUPPORTED")
            scripts, mapping = ReplayHTML().scripts(http, path + "replay/", response.content)
            if name == "get_replay_scripts":
                return {"buildNumber": number, **scripts}
            replacements = args.get("loadedScripts", {})
            if set(replacements) - set(mapping):
                unsupported("存在不属于该构建的已加载脚本名称", "JENKINS_REPLAY_UNSUPPORTED")
            fields = {
                "mainScript": args["mainScript"],
                **{field: replacements.get(key, scripts["loadedScripts"][key]) for key, field in mapping.items()},
            }
            return await http.submit(path + "replay/run", json_form(fields), job)
        raise GatewayError("TOOL_DENIED", "Jenkins 工具不存在", 403)

    async def trigger(self, http, job, data, values, rebuild=False):
        if data.get("buildable") is not True:
            unsupported("任务不可构建或其状态不可见", "JENKINS_CONFLICT")
        if not isinstance(data.get("property"), list):
            unsupported("任务未导出参数定义，不能可靠调度构建", "JENKINS_PARAMETER")
        definitions = parameter_definitions(data)
        form = parameter_form(definitions, values, rebuild)
        return await http.submit(job + ("buildWithParameters" if definitions else "build"), form, "queue")

    async def rebuild(self, http, job, path):
        original = await http.json(path + "api/json", "_class,actions[_class,parameters[_class,name,value]]")
        if original.get("_class") == "org.jenkinsci.plugins.workflow.job.WorkflowRun":
            # 服务端校验重建权限并保留原始脚本/SCM/参数；失败不降级为触发当前任务。
            try:
                return await http.submit(path + "replay/rebuild", {}, job)
            except GatewayError as error:
                if error.code == "JENKINS_NOT_FOUND":
                    unsupported("Pipeline 原样重建入口或原脚本不可用", "JENKINS_REBUILD_UNSUPPORTED")
                raise
        values = {}
        for action in original.get("actions", []):
            for parameter in action.get("parameters", []):
                kind = parameter.get("_class", "").rsplit(".", 1)[-1]
                if (
                    kind not in {"StringParameterValue", "BooleanParameterValue", "TextParameterValue"}
                    or "value" not in parameter
                ):
                    unsupported("原构建含隐藏、密码或未知参数，不能可靠重建", "JENKINS_REBUILD_UNSUPPORTED")
                key = parameter.get("name")
                if key in values:
                    unsupported("原构建参数重复，不能可靠重建", "JENKINS_REBUILD_UNSUPPORTED")
                values[key] = parameter["value"]
        data = await http.json(job + "api/json", "buildable," + PARAM_FIELDS)
        return await self.trigger(http, job, data, values, rebuild=True)

    async def tests(self, http, path, args, name):
        data = await http.json(
            path + "testReport/api/json",
            "failCount,passCount,skipCount,totalCount,suites[cases[className,name,status,duration,errorDetails,flakyFailures[*]]]",
            allowed=(404,),
        )
        if data is None:
            return {"reportAvailable": False, "tests": []}
        cases = [case for suite in data.get("suites", []) for case in suite.get("cases", [])]
        if name == "get_flaky_failures":
            if not cases or not all("flakyFailures" in case for case in cases):
                unsupported("当前 Jenkins/JUnit 未导出 flakyFailures 字段")
            cases = [pick(case, "className,name,status,flakyFailures") for case in cases if case["flakyFailures"]]
        elif args.get("onlyFailingTests"):
            cases = [case for case in cases if case.get("status") in ("FAILED", "REGRESSION")]
        return {"reportAvailable": True, **pick(data, "failCount,passCount,skipCount,totalCount"), "tests": cases}

    async def status(self, http):
        value = await http.json("api/json", "mode,nodeDescription,numExecutors,quietingDown")
        unavailable = ["administrativeMonitors", "clouds"]
        for key, path, tree in (
            ("queue", "queue/api/json", "items[id,why,blocked,buildable,stuck,task[name,url]]"),
            (
                "computer",
                "computer/api/json",
                "busyExecutors,totalExecutors,computer[displayName,offline,temporarilyOffline,numExecutors,idle]",
            ),
        ):
            try:
                value[key] = await http.json(path, tree)
            except GatewayError as error:
                if error.code not in ("JENKINS_FORBIDDEN", "JENKINS_NOT_FOUND"):
                    raise
                unavailable.append(key)
        return {**value, "unavailable": unavailable, "note": "仅表示账号可见数据，不代表完整管理健康状态"}

    async def find_scm(self, http, args, ctx):
        budget = ctx.account["policy"].get("max_scan_jobs", 200)
        folders, visited, matches = deque([""]), set(), []
        scanned, unreadable, partial = 0, 0, False
        wanted = repository_key(args["scmUrl"])
        while folders and scanned < budget:
            parent = folders.popleft()
            if parent in visited:
                continue
            visited.add(parent)
            try:
                data = await http.json(parent + "api/json", f"jobs[{SIMPLE_JOB}]")
            except GatewayError as error:
                if error.code not in ("JENKINS_FORBIDDEN", "JENKINS_NOT_FOUND"):
                    raise
                unreadable += 1
                continue
            for job in sorted(data.get("jobs", []), key=lambda j: j.get("name", "")):
                if scanned >= budget:
                    partial = True
                    break
                scanned += 1
                name = job.get("fullName")
                if not name:
                    unreadable += 1
                    continue
                path = job_path(name)
                kind = job.get("_class", "")
                if kind.endswith(("Folder", "MultiBranchProject", "OrganizationFolder")):
                    folders.append(path)
                    continue
                try:
                    scm = scm_config((await http.request(path + "config.xml")).content)
                except GatewayError as error:
                    if error.code not in ("JENKINS_FORBIDDEN", "JENKINS_NOT_FOUND", "JENKINS_XML"):
                        raise
                    unreadable += 1
                    continue
                partial |= scm["partial"]
                if any(
                    wanted == repository_key(remote["url"])
                    and (
                        not args.get("branch")
                        or any(branch_matches(b, args["branch"], remote["name"]) for b in source["branches"])
                    )
                    for source in scm["scms"]
                    for remote in source["remotes"]
                ):
                    matches.append(job)
        skip, limit = args.get("skip", 0), min(args.get("limit", 10), ctx.limits["max_result_rows"])
        return {
            "jobs": matches[skip : skip + limit],
            "matched": len(matches),
            "scanned": scanned,
            "unreadable": unreadable,
            "partial": partial or bool(folders) or unreadable > 0,
            "hasMore": len(matches) > skip + limit,
        }
