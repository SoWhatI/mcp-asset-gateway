import asyncio
import contextlib
import copy
import os
import shutil
import ssl
import tempfile
from pathlib import Path

import httpx

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
            if unlocked:
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

    async def request(self, ctx, path, params=None, maximum=None):
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
            async with httpx.AsyncClient(
                transport=transport,
                headers=self.headers(ctx),
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
            ) as client:
                response = await client.get(cfg["url"].rstrip("/") + path, params=params)
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
