# Kubernetes 资产

Kubernetes 类型提供资源列表、单资源详情、Pod 日志、非交互 `k8s_exec` 与清单应用 `k8s_apply` 工具。接入与授权操作见 [用户指南](../USER_GUIDE.md)。

## 账号策略与认证

命名空间（留空表示不锁定，工具将提供 `namespace` 参数）、资源类型与日志行数在账号策略中限定；账号未锁定命名空间时资源列表可跨命名空间，否则仅限账号命名空间。支持 ServiceAccount Token 或客户端证书认证，CA/证书/私钥支持直接上传；客户端证书与私钥既可以容器内绝对路径引用（由部署方挂载保管），也可以上传 PEM 内容（随凭据加密托管，运行时临时落地、用后即删）。

## k8s_exec

`k8s_exec` 必须在授权组显式勾选，历史资源/日志授权不会自动获得执行权限。账号资源类型须允许 `pods`，集群 RBAC 须允许 `pods/exec`（WebSocket GET 通常需要 `get`，按集群策略配置）。

参数示例：`{"pod":"web-1","container":"app","namespace":"prod","command":["uname","-a"]}`。账号已锁定命名空间时不传 `namespace`；未锁定时必须传。`command` 是 argv 数组，不隐式使用 shell；不提供 stdin、TTY、attach 或端口转发。

仅支持 HTTPS WebSocket `v4.channel.k8s.io`，保持 TLS 验证、客户端证书和固定出站 IP，不跟随重定向、不使用环境代理、不重试。返回 `stdout`、`stderr`、`exit_code`；输出截断或未确认正常结束时标记 `remote_completion_unknown=true` 并返回错误，不能视为远端命令已停止。总超时沿用账号/全局资源限制。

## k8s_apply

`k8s_apply` 以 Server-Side Apply（`application/apply-patch+yaml`，fieldManager `mcp-asset-gateway`）幂等创建或更新命名空间内资源，重复应用不产生副作用，且**不会删除**清单未提及的资源。

- 能力开关：账号策略 `allow_apply` 默认关闭；开启后工具即可用，但仍须在授权组显式勾选。集群凭据需具备对应资源的 `patch`/`create` RBAC 权限。
- 资源白名单（固定，不可配置）：`Secret`、`ConfigMap`、`Service`、`PersistentVolumeClaim`、`StatefulSet`、`Deployment`；`ServiceAccount`、`Role`、`RoleBinding` 等权限提升类与集群级对象一律拒绝（`KIND_DENIED`），防止绕过 MCP 权限边界。
- 命名空间：账号已锁定时每个文档的 `metadata.namespace` 被强制覆盖为账号值；未锁定时每个文档必须显式声明，否则报 `NAMESPACE_REQUIRED`（不会默认投递到 `default`）。
- 清单：单个或多个 YAML 文档（`---` 分隔），最多 20 个，单次调用不超过 256 KiB；apply 前自动剥离 `metadata.uid/resourceVersion/creationTimestamp/generation/managedFields` 与顶层 `status`。
- `dry_run: true` 转为服务端 `dryRun=All`，仅校验不落盘；多文档部分失败时错误信息注明之前几个已生效（apply 语义不回滚）。返回每个文档的 `kind/name/namespace/uid/resource_version/created`。
