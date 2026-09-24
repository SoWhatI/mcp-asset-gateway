# Kubernetes 资产

Kubernetes 类型提供资源列表、单资源详情、Pod 日志与非交互 `k8s_exec` 工具。接入与授权操作见 [用户指南](../USER_GUIDE.md)。

## 账号策略与认证

命名空间（留空表示不锁定，工具将提供 `namespace` 参数）、资源类型与日志行数在账号策略中限定；账号未锁定命名空间时资源列表可跨命名空间，否则仅限账号命名空间。支持 ServiceAccount Token 或客户端证书认证，CA/证书/私钥支持直接上传；客户端证书与私钥既可以容器内绝对路径引用（由部署方挂载保管），也可以上传 PEM 内容（随凭据加密托管，运行时临时落地、用后即删）。

## k8s_exec

`k8s_exec` 必须在授权组显式勾选，历史资源/日志授权不会自动获得执行权限。账号资源类型须允许 `pods`，集群 RBAC 须允许 `pods/exec`（WebSocket GET 通常需要 `get`，按集群策略配置）。

参数示例：`{"pod":"web-1","container":"app","namespace":"prod","command":["uname","-a"]}`。账号已锁定命名空间时不传 `namespace`；未锁定时必须传。`command` 是 argv 数组，不隐式使用 shell；不提供 stdin、TTY、attach 或端口转发。

仅支持 HTTPS WebSocket `v4.channel.k8s.io`，保持 TLS 验证、客户端证书和固定出站 IP，不跟随重定向、不使用环境代理、不重试。返回 `stdout`、`stderr`、`exit_code`；输出截断或未确认正常结束时标记 `remote_completion_unknown=true` 并返回错误，不能视为远端命令已停止。总超时沿用账号/全局资源限制。
