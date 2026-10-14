import asyncio
import contextlib
import copy
import json
import os
import re
import shutil
import ssl
import tempfile
from pathlib import Path

import httpx
import yaml

from app.asset_types.base import RESOURCE_SCHEMA, AssetType, integer, obj, result, text, tool, upload_text
from app.asset_types.k8s_exec import exec_stream
from app.asset_types.pinned import PinnedTransport
from app.core.security import GatewayError, validate

# 固定的资源类型表：仅命名空间内资源与只读动词，不含 Secret、子资源与集群级对象。
KINDS = {
    "pods": ("v1", "pods"),
    "services": ("v1", "services"),
    "configmaps": ("v1", "configmaps"),
    "persistentvolumeclaims": ("v1", "persistentvolumeclaims"),
    "events": ("v1", "events"),
    "deployments": ("apps/v1", "deployments"),
    "statefulsets": ("apps/v1", "statefulsets"),
    "daemonsets": ("apps/v1", "daemonsets"),
    "replicasets": ("apps/v1", "replicasets"),
    "jobs": ("batch/v1", "jobs"),
    "cronjobs": ("batch/v1", "cronjobs"),
    "ingresses": ("networking.k8s.io/v1", "ingresses"),
}
# k8s_apply 固定白名单：部署清单常用的工作负载与配套资源；Secret 不进入只读 KINDS 表，
# ServiceAccount/Role 等权限提升类与集群级对象一律拒绝，防止借用清单绕过 MCP 权限边界。
APPLY_KINDS = {
    "Secret": ("v1", "secrets"),
    "ConfigMap": ("v1", "configmaps"),
    "Service": ("v1", "services"),
    "PersistentVolumeClaim": ("v1", "persistentvolumeclaims"),
    "StatefulSet": ("apps/v1", "statefulsets"),
    "Deployment": ("apps/v1", "deployments"),
}
MAX_APPLY_DOCS = 20
APPLY_FIELD_MANAGER = "mcp-asset-gateway"
# Server-Side Apply 前剥离的服务端归属字段，避免旧 uid/resourceVersion 等造成冲突。
APPLY_STRIP_META = ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields", "selfLink")
DNS_LABEL = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
DNS_SUBDOMAIN = r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"
# 命名空间可留空：留空表示账号不锁定命名空间，工具将自动提供 namespace 参数。
NAMESPACE_OPTIONAL = r"^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$"
# 未锁定命名空间的账号，以下工具必须显式指定 namespace。
NAMESPACE_REQUIRED_TOOLS = {"k8s_get_resource", "k8s_pod_logs", "k8s_exec"}


def api_prefix(api):
    if "/" not in api:
        return "/api/" + api
    group, version = api.split("/", 1)
    return f"/apis/{group}/{version}"


def collection_path(namespace, kind_id):
    api, plural = KINDS[kind_id]
    if not namespace:
        return f"{api_prefix(api)}/{plural}"
    return f"{api_prefix(api)}/namespaces/{namespace}/{plural}"


def namespace_of(account):
    """账号锁定的命名空间；返回空串表示不限制。"""
    return ((account.get("config") or {}).get("namespace") or "").strip()


def target_namespace(ctx, args, required):
    """解析目标命名空间：账号已锁定时以账号配置为准，未锁定时取工具参数。"""
    locked = namespace_of(ctx.account)
    if locked:
        return locked
    value = (args.get("namespace") or "").strip()
    if value:
        return value
    if required:
        raise GatewayError("NAMESPACE_REQUIRED", "账号未锁定命名空间，调用时必须指定 namespace")
    return None


def parse_manifest(value):
    """解析 YAML 清单为文档列表；空文档跳过，文档数与基础结构在此把关。"""
    try:
        docs = [doc for doc in yaml.safe_load_all(value) if doc is not None]
    except yaml.YAMLError as error:
        raise GatewayError("MANIFEST_INVALID", f"YAML 解析失败：{str(error)[:200]}") from None
    if not docs:
        raise GatewayError("MANIFEST_INVALID", "清单为空：至少需要一个资源文档")
    if len(docs) > MAX_APPLY_DOCS:
        raise GatewayError("MANIFEST_INVALID", f"清单最多包含 {MAX_APPLY_DOCS} 个资源文档")
    return docs


def apply_target(doc, locked):
    """校验单个清单文档并归一为 (kind, namespace, collection 路径, 可应用对象)。"""
    if not isinstance(doc, dict):
        raise GatewayError("MANIFEST_INVALID", "清单文档必须是映射对象")
    kind = doc.get("kind")
    if kind not in APPLY_KINDS:
        raise GatewayError(
            "KIND_DENIED",
            "kind 不在 k8s_apply 白名单（" + "、".join(sorted(APPLY_KINDS)) + "）；"
            "ServiceAccount、Role 等权限提升类与集群级资源一律拒绝，防止绕过 MCP 权限边界",
            403,
        )
    api, plural = APPLY_KINDS[kind]
    if doc.get("apiVersion") != api:
        raise GatewayError("MANIFEST_INVALID", f"资源 {kind} 的 apiVersion 必须为 {api}")
    meta = doc.get("metadata")
    name = meta.get("name") if isinstance(meta, dict) else None
    if not isinstance(name, str) or not re.fullmatch(DNS_SUBDOMAIN, name):
        raise GatewayError("MANIFEST_INVALID", "清单文档缺少合法的 metadata.name（DNS 子域名）")
    namespace = locked or str(meta.get("namespace") or "").strip()
    if not namespace:
        raise GatewayError("NAMESPACE_REQUIRED", "账号未锁定命名空间，清单文档必须显式声明 metadata.namespace")
    if not re.fullmatch(DNS_LABEL, namespace):
        raise GatewayError("NAMESPACE_INVALID", f"命名空间 {namespace} 不符合 DNS 标签格式")
    meta = {key: value for key, value in meta.items() if key not in APPLY_STRIP_META}
    meta["namespace"] = namespace
    body = {key: value for key, value in doc.items() if key != "status"}
    body["metadata"] = meta
    # Server-Side Apply 的 PATCH 必须落在单个资源 URL 上：打到集合 URL（缺 /{name}）会 405。
    return kind, namespace, f"{api_prefix(api)}/namespaces/{namespace}/{plural}/{name}", body


def is_pem(value):
    return isinstance(value, str) and "-----BEGIN" in value


def check_tls_material(value, label, variant, code="CREDENTIAL_INVALID"):
    """证书/私钥取值：容器内绝对路径，或上传/粘贴的完整 PEM 内容。"""
    if is_pem(value):
        marker = "PRIVATE KEY" if variant == "key" else "BEGIN CERTIFICATE"
        if marker not in value or "-----END" not in value:
            expected = (
                "PEM 私钥（含 PRIVATE KEY 标记）" if variant == "key" else "PEM 证书（含 BEGIN CERTIFICATE 标记）"
            )
            raise GatewayError(code, f"{label}不是有效的{expected}")
        return
    if not value.startswith("/") or "\n" in value or "\r" in value:
        raise GatewayError(code, f"{label}必须为容器内绝对路径或完整 PEM 内容")


@contextlib.contextmanager
def tls_files(ca_value, cert_values):
    """上传的 PEM 内容临时落地为 0600 文件并组装 SSLContext；路径取值原样使用，用后即删。"""
    values = {"ca": ca_value or ""}
    if cert_values:
        values["cert"], values["key"] = cert_values
    work = None
    try:
        paths = {}
        for name, value in values.items():
            if is_pem(value):
                if work is None:
                    work = Path(tempfile.mkdtemp(prefix="mcp-k8s-tls-"))
                path = work / f"{name}.pem"
                path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")
                os.chmod(path, 0o600)
                paths[name] = str(path)
            else:
                paths[name] = value or None
        # 必须自行组装 context：httpx 在 verify 为路径字符串时会静默忽略同时传入的 cert，
        # 客户端证书会丢失导致认证 401；exec 的 WebSocket 路径同样复用该 context。
        try:
            context = ssl.create_default_context(cafile=paths["ca"])
            if paths.get("cert") and paths.get("key"):
                context.load_cert_chain(paths["cert"], paths["key"])
        except (ssl.SSLError, OSError, ValueError) as error:
            raise GatewayError(
                "K8S_TLS_FAILED",
                "TLS 材料加载失败：请核对 CA、客户端证书与私钥内容或容器内路径",
                400,
            ) from error
        yield context
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def transport_error(error):
    text_value = str(error)
    if isinstance(error, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text_value:
        return GatewayError(
            "K8S_TLS_FAILED",
            "TLS 证书验证失败：请核对资产 ca_file 与目标 API Server 证书",
            502,
        )
    if isinstance(error, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return GatewayError("K8S_TIMEOUT", "连接或读取 Kubernetes API 超时：请检查目标可用性与网络策略", 502)
    if isinstance(error, FileNotFoundError) or "No such file or directory" in text_value:
        return GatewayError(
            "K8S_CERTIFICATE_MISSING", "客户端证书或私钥文件不存在：请核对容器内路径，或改为上传 PEM 内容", 502
        )
    if isinstance(error, httpx.ConnectError):
        return GatewayError("K8S_UNREACHABLE", "无法连接 Kubernetes API：请检查地址、端口与网络策略", 502)
    return GatewayError("K8S_API_FAILED", "Kubernetes API 请求失败：请检查目标状态", 502)


def response_error(response):
    try:
        status = response.json()
        message = str(status.get("message", ""))[:300]
    except ValueError:
        message = ""
    if response.status_code == 401:
        return GatewayError("K8S_AUTH_FAILED", "Kubernetes 认证失败：请核对 Token 或客户端证书", 502)
    if response.status_code == 403:
        return GatewayError(
            "K8S_FORBIDDEN", f"服务端拒绝该操作：{message or '请核对 ServiceAccount 的 RBAC 授权'}", 502
        )
    if response.status_code == 404:
        return GatewayError("K8S_NOT_FOUND", f"资源不存在：{message or '请核对资源名称'}", 404)
    if response.status_code == 429:
        return GatewayError("K8S_RATE_LIMITED", "Kubernetes API 限流，请稍后重试", 429)
    return GatewayError(
        "K8S_API_FAILED", f"Kubernetes API 返回错误（HTTP {response.status_code}）：{message}"[:400], 502
    )


def brief(item):
    meta = item.get("metadata") or {}
    entry = {"name": meta.get("name"), "created": meta.get("creationTimestamp")}
    if meta.get("labels"):
        entry["labels"] = meta["labels"]
    status = item.get("status") or {}
    for source, target in (
        ("phase", "phase"),
        ("replicas", "replicas"),
        ("readyReplicas", "ready"),
        ("availableReplicas", "available"),
    ):
        if source in status:
            entry[target] = status[source]
    if "replicas" not in entry and isinstance(item.get("spec"), dict) and item["spec"].get("replicas") is not None:
        entry["replicas"] = item["spec"]["replicas"]
    return entry


def prune(item):
    item = dict(item)
    meta = dict(item.get("metadata") or {})
    meta.pop("managedFields", None)
    annotations = meta.get("annotations")
    if annotations and "kubectl.kubernetes.io/last-applied-configuration" in annotations:
        annotations = dict(annotations)
        annotations["kubectl.kubernetes.io/last-applied-configuration"] = "…（已裁剪）"
        meta["annotations"] = annotations
    item["metadata"] = meta
    return item


def clip(value, ctx, depth=0):
    if depth > 16:
        ctx.stats["truncated"] = True
        return "…（层级过深，已裁剪）"
    if isinstance(value, dict):
        return {key: clip(item, ctx, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [clip(item, ctx, depth + 1) for item in value]
    if isinstance(value, str) and len(value) > ctx.limits["max_cell_chars"]:
        ctx.stats["truncated"] = True
        return value[: ctx.limits["max_cell_chars"]] + "…（已截断）"
    return value


class KubernetesAssetType(AssetType):
    type_id, display_name, icon = "kubernetes", "Kubernetes 集群", "Platform"
    async_mode = True
    connection_schema = obj(
        {
            "url": text("API Server 地址", pattern=r"^https://\S{1,1024}$", minLength=10),
            "ca_file": upload_text(
                "CA 证书文件",
                maxLength=32768,
                description="上传 .crt/.pem 文件或填写容器内绝对路径；留空使用系统信任库",
            ),
        },
        ["url"],
    )
    account_schema = obj(
        {
            "auth_mode": text("认证方式", enum=["token", "client_certificate"], default="token"),
            "namespace": text(
                "命名空间",
                pattern=NAMESPACE_OPTIONAL,
                maxLength=63,
                description="留空表示不限制命名空间：工具自动提供 namespace 参数",
            ),
        },
        ["auth_mode"],
    )
    credential_schema = obj(
        {
            "token": text("ServiceAccount Token", format="password", maxLength=8192),
            "client_certificate_file": upload_text(
                "客户端证书文件",
                maxLength=32768,
                description="上传 .crt/.pem 文件或填写容器内绝对路径",
            ),
            "client_key_file": upload_text(
                "客户端私钥文件",
                maxLength=32768,
                description="上传 .key/.pem 文件或填写容器内绝对路径",
            ),
        }
    )
    policy_schema = obj(
        {
            **RESOURCE_SCHEMA,
            "kinds": {
                "type": "array",
                "title": "允许的资源类型",
                "items": {"type": "string", "enum": sorted(KINDS)},
                "uniqueItems": True,
                # 留空表示不限制：允许下方固定资源类型表中的全部类型。
                "description": "每行一项；留空表示不限制，允许全部内置资源类型",
            },
            "allow_apply": {
                "type": "boolean",
                "title": "允许应用清单",
                "default": False,
                "description": "开启后 k8s_apply 可创建/更新 Secret、ConfigMap、Service、PVC、StatefulSet、Deployment"
                "（固定白名单，仅限账号命名空间边界内；不包含 ServiceAccount/Role 等权限类资源）",
            },
            "max_log_lines": integer("日志行数上限", 1, 5000, default=500),
        }
    )
    tools = [
        tool(
            "k8s_list_resources",
            "列出命名空间内指定类型资源的核心字段（名称、标签、状态摘要）。",
            {
                "kind": text("资源类型", enum=sorted(KINDS)),
                "label_selector": text("标签选择器", maxLength=256, pattern=r"^[^\x00-\x1f]{1,256}$"),
                "limit": integer("数量上限", 1, 500, default=100),
            },
            ["kind"],
        ),
        tool(
            "k8s_get_resource",
            "读取命名空间内单个资源对象（已剪枝 managedFields 等大字段）。",
            {
                "kind": text("资源类型", enum=sorted(KINDS)),
                "name": text("资源名称", pattern=DNS_SUBDOMAIN, minLength=1, maxLength=253),
            },
            ["kind", "name"],
        ),
        tool(
            "k8s_pod_logs",
            "读取命名空间内 Pod 容器的近期日志尾部。",
            {
                "pod": text("Pod 名称", pattern=DNS_SUBDOMAIN, minLength=1, maxLength=253),
                "container": text("容器名", pattern=DNS_LABEL, maxLength=63),
                "tail_lines": integer("末尾行数", 1, 5000, default=100),
                "previous": {"type": "boolean", "title": "上一个实例日志", "default": False},
            },
            ["pod"],
        ),
        tool(
            "k8s_exec",
            "在指定 Pod 容器内非交互执行命令，返回 stdout、stderr 和退出码。"
            "需显式授权及 pods/exec RBAC 权限；参数受授权组黑白名单控制，未配置规则时不额外限制。"
            "不提供 stdin/TTY，命令可能修改数据；超时或截断后远端状态可能未知，勿自动重试。",
            {
                "pod": text("Pod 名称", pattern=DNS_SUBDOMAIN, minLength=1, maxLength=253),
                "container": text("容器名", pattern=DNS_LABEL, minLength=1, maxLength=63),
                "command": {
                    "type": "array",
                    "title": "命令及参数 argv",
                    "description": '逐项传递，不隐式使用 shell，例如 ["uname","-a"]；规则匹配紧凑 JSON 全文',
                    "items": text("参数", maxLength=4096, pattern=r"^[^\x00]*$"),
                    "minItems": 1,
                    "maxItems": 64,
                },
            },
            ["pod", "command"],
            readonly=False,
        ),
        tool(
            "k8s_apply",
            "以 Server-Side Apply 幂等创建或更新命名空间内资源，重复应用不产生副作用，不会删除未提及的资源。"
            "仅支持 Secret、ConfigMap、Service、PersistentVolumeClaim、StatefulSet、Deployment（固定白名单）；"
            "需账号策略开启 allow_apply，凭据需具备 patch/create RBAC 权限。"
            "manifest 为单个或多个 YAML 文档（--- 分隔），最多 20 个；"
            "账号已锁定命名空间时 metadata.namespace 被强制覆盖，未锁定时每个文档必须显式声明。",
            {
                "manifest": text("YAML 清单", minLength=1, maxLength=262144),
                "dry_run": {"type": "boolean", "title": "仅校验不落盘", "default": False},
            },
            ["manifest"],
            readonly=False,
        ),
    ]

    def validate_connection(self, network, connection):
        network.url(connection["url"])
        if connection.get("ca_file"):
            check_tls_material(connection["ca_file"], "CA 证书", "ca", code="CONNECTION_INVALID")

    def validate_config(self, connection, account, policy, credential):
        super().validate_config(connection, account, policy, credential)
        if account["auth_mode"] == "token":
            if not credential.get("token"):
                raise GatewayError("CREDENTIAL_REQUIRED", "Token 认证需要填写 ServiceAccount Token")
            if "\n" in credential["token"] or "\r" in credential["token"]:
                raise GatewayError("HEADER_INVALID", "Token 不能包含换行")
        else:
            for key, label, variant in (
                ("client_certificate_file", "客户端证书", "certificate"),
                ("client_key_file", "客户端私钥", "key"),
            ):
                value = credential.get(key, "")
                if not value:
                    raise GatewayError("CREDENTIAL_REQUIRED", "客户端证书认证需要上传或填写证书与私钥文件")
                check_tls_material(value, label, variant)

    def catalog(self, account):
        # 策略未配置或留空 kinds 时不做资源类型限制，仅受固定资源类型表约束。
        allowed = sorted(set(account["policy"].get("kinds") or KINDS))
        unlocked = not namespace_of(account)
        specs = []
        for spec in self.tools:
            spec = copy.deepcopy(spec)
            schema = spec["inputSchema"]
            properties = schema["properties"]
            if "kind" in properties:
                properties["kind"]["enum"] = allowed
            if unlocked and spec["name"] == "k8s_apply":
                spec["description"] += " 账号未锁定命名空间：清单文档必须显式声明 metadata.namespace。"
            elif unlocked:
                required = spec["name"] in NAMESPACE_REQUIRED_TOOLS
                properties["namespace"] = text(
                    "命名空间",
                    pattern=DNS_LABEL,
                    minLength=1,
                    maxLength=63,
                    description="账号未锁定命名空间，必须指定目标" if required else "留空列出全部命名空间",
                )
                if required:
                    schema["required"].append("namespace")
                spec["description"] += (
                    " 账号未锁定命名空间：必须通过 namespace 指定目标。"
                    if required
                    else " 账号未锁定命名空间：可用 namespace 限定范围，留空列出全部命名空间。"
                )
            specs.append(spec)
        return specs

    def headers(self, ctx):
        if (ctx.account["config"].get("auth_mode") or "token") == "token":
            return {"Authorization": "Bearer " + ctx.credential["token"]}
        return {}

    def certificate(self, ctx):
        if (ctx.account["config"].get("auth_mode") or "token") != "client_certificate":
            return None
        return (ctx.credential.get("client_certificate_file", ""), ctx.credential.get("client_key_file", ""))

    async def request(self, ctx, path, params=None, maximum=None, method="GET", content=None, content_type=None):
        cfg = ctx.asset["connection"]
        with tls_files(cfg.get("ca_file"), self.certificate(ctx)) as tls_context:
            transport = PinnedTransport(
                ctx,
                maximum or ctx.limits["max_output_bytes"] + 65536,
                ssl_context=tls_context,
            )
            timeout = httpx.Timeout(
                ctx.remaining(), connect=min(ctx.remaining(), ctx.limits["connect_timeout_seconds"])
            )
            headers = self.headers(ctx)
            if content_type:
                headers = {**headers, "Content-Type": content_type}
            async with httpx.AsyncClient(
                transport=transport,
                headers=headers,
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
            ) as client:
                response = await client.request(
                    method, cfg["url"].rstrip("/") + path, params=params, content=content
                )
        ctx.remaining()
        if response.status_code >= 400:
            raise response_error(response)
        return response

    def resource_kind(self, ctx, kind):
        if kind not in KINDS:
            raise GatewayError("KIND_DENIED", "资源类型不在账号策略中", 403)
        allowed = ctx.account["policy"].get("kinds")
        if allowed and kind not in set(allowed):
            raise GatewayError("KIND_DENIED", "资源类型不在账号策略中", 403)
        return kind

    async def list_resources(self, ctx, args):
        namespace = target_namespace(ctx, args, required=False)
        kind = self.resource_kind(ctx, args["kind"])
        limit = min(args.get("limit", 100), ctx.limits["max_result_rows"])
        params = {"limit": limit}
        if args.get("label_selector"):
            params["labelSelector"] = args["label_selector"]
        data = (await self.request(ctx, collection_path(namespace, kind), params=params)).json()
        items = [brief(item) for item in data.get("items") or []][:limit]
        return {
            "kind": kind,
            "namespace": namespace or "*",
            "items": items,
            "count": len(items),
            "truncated": bool((data.get("metadata") or {}).get("continue")) or len(items) >= limit,
        }

    async def get_resource(self, ctx, args):
        namespace = target_namespace(ctx, args, required=True)
        kind = self.resource_kind(ctx, args["kind"])
        path = collection_path(namespace, kind) + "/" + args["name"]
        data = (await self.request(ctx, path)).json()
        resource = clip(prune(data), ctx)
        return {
            "kind": kind,
            "namespace": namespace,
            "resource": resource,
            "count": 1,
            "truncated": bool(ctx.stats.get("truncated")),
        }

    async def pod_logs(self, ctx, args):
        namespace = target_namespace(ctx, args, required=True)
        policy = ctx.account["policy"]
        tail = min(args.get("tail_lines", 100), policy.get("max_log_lines", 500), 5000)
        params = {"tailLines": tail}
        if args.get("container"):
            params["container"] = args["container"]
        if args.get("previous"):
            params["previous"] = "true"
        path = f"/api/v1/namespaces/{namespace}/pods/{args['pod']}/log"
        response = await self.request(ctx, path, params=params)
        logs = response.text
        return {
            "pod": args["pod"],
            "container": args.get("container"),
            "tail_lines": tail,
            "logs": logs,
            "count": len(logs.splitlines()),
        }

    async def pod_exec(self, ctx, args):
        spec = next(item for item in self.catalog(ctx.account) if item["name"] == "k8s_exec")
        validate(spec["inputSchema"], args)
        self.resource_kind(ctx, "pods")
        if not args["command"][0] or sum(len(value) for value in args["command"]) > 8192:
            raise GatewayError("COMMAND_INVALID", "可执行程序不能为空，命令总长度不能超过 8192 字符")
        namespace = target_namespace(ctx, args, required=True)
        path = f"/api/v1/namespaces/{namespace}/pods/{args['pod']}/exec"
        with tls_files(ctx.asset["connection"].get("ca_file"), self.certificate(ctx)) as tls_context:
            return await exec_stream(ctx, path, args["command"], args.get("container"), self.headers(ctx), tls_context)

    async def apply_manifest(self, ctx, args):
        if not ctx.account["policy"].get("allow_apply"):
            raise GatewayError(
                "TOOL_DENIED", "该账号未开启清单应用：需在账号策略开启 allow_apply 后才能创建或更新资源", 403
            )
        locked = namespace_of(ctx.account)
        applied = []
        for index, doc in enumerate(parse_manifest(args["manifest"]), 1):
            kind, namespace, path, body = apply_target(doc, locked)
            params = {"fieldManager": APPLY_FIELD_MANAGER}
            if args.get("dry_run"):
                params["dryRun"] = "All"
            try:
                response = await self.request(
                    ctx,
                    path,
                    params=params,
                    method="PATCH",
                    content=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                    content_type="application/apply-patch+yaml",
                )
            except GatewayError as error:
                if applied:
                    raise GatewayError(
                        error.code,
                        f"第 {index} 个文档（{kind}）应用失败，之前 {len(applied)} 个已生效且不回滚：{error.message}",
                        error.status,
                    ) from None
                raise
            try:
                data = response.json()
                meta = data.get("metadata") or {}
            except ValueError:
                raise response_error(response) from None
            applied.append(
                {
                    "kind": kind,
                    "name": meta.get("name") or body["metadata"]["name"],
                    "namespace": namespace,
                    "created": response.status_code == 201,
                    "uid": meta.get("uid"),
                    "resource_version": meta.get("resourceVersion"),
                }
            )
        return {
            "namespace": locked or "*",
            "dry_run": bool(args.get("dry_run")),
            "applied": applied,
            "count": len(applied),
            "truncated": False,
        }

    async def execute(self, name, args, ctx, spec):
        async with asyncio.timeout(ctx.remaining()):
            try:
                if name == "k8s_list_resources":
                    payload = await self.list_resources(ctx, args)
                elif name == "k8s_get_resource":
                    payload = await self.get_resource(ctx, args)
                elif name == "k8s_pod_logs":
                    payload = await self.pod_logs(ctx, args)
                elif name == "k8s_exec":
                    payload = await self.pod_exec(ctx, args)
                elif name == "k8s_apply":
                    payload = await self.apply_manifest(ctx, args)
                else:
                    raise GatewayError("TOOL_DENIED", "工具不存在或未授权", 403)
            except GatewayError:
                raise
            except httpx.HTTPError as error:
                raise transport_error(error) from None
            except TimeoutError:
                raise
            except OSError as error:
                raise transport_error(error) from None
        ctx.stats.update(row_count=payload.get("count"), truncated=bool(payload.get("truncated")))
        value = result(payload)
        if name == "k8s_exec":
            value["isError"] = payload["remote_completion_unknown"] or payload["exit_code"] != 0
        return value

    async def health(self, ctx):
        async with asyncio.timeout(ctx.remaining()):
            try:
                data = (await self.request(ctx, "/version", maximum=65536)).json()
            except GatewayError:
                raise
            except httpx.HTTPError as error:
                raise transport_error(error) from None
            except OSError as error:
                raise transport_error(error) from None
        return {"reachable": True, "version": data.get("gitVersion")}
