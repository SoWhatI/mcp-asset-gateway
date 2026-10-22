# 变更记录

## 未发布

- 自举模式启动横幅动态报告目录预览工具数：原固定文案「工具列表为空」与目录预览行为不符，且让目录站构建日志无法区分新旧代码。
- 目录预览：自举 stdio 模式在未配置客户端令牌时返回各内置资产类型的静态工具目录（名称带 `类型__工具` 前缀、描述标注「目录预览」；k8s 呈现未锁定命名空间形态、Redis 呈现只读形态，不含任何账号数据与凭据），目录站（Glama 等）可据此完成工具定义质量评估，直连客户端也能先见目录再接授权组；工具调用仍被拒绝，需部署实例授权组放行。
- MySQL 修复：目标未启用 TLS 时，`tls_mode=PREFERRED` 资产不再误报 `MYSQL_UNREACHABLE` —— pymysql 2026（服务端握手包未声明 SSL 能力，错误文本不含 "SSL:"）此前未被识别为 TLS 失败，导致自动回退明文失效；现在回退明文正常生效，`REQUIRED` 模式对未启用 TLS 的目标报 `MYSQL_TLS_FAILED` 并给出 tls_mode 调整指引。
- 诊断增强：`TARGET_DENIED` 错误信息附带该工具实时已授权账号清单（资产 · 账号（ID）），并提示客户端工具目录可能过期，消除“目录声称可访问但调用被拒”的排查盲区（多实例同名工具配置时尤其常见）。
- MySQL 错误防误导：1142（命令被拒）提示“账号无权限时对不存在的表同样返回 1142 而非 1146，先用 list_tables 核实表名”；1044 补充 database 参数与授权范围核对指引。
- MySQL 结果集完整性：行宽与表头不一致时立即整体失败（`MYSQL_PROTOCOL_MISMATCH`），不再向客户端传递错位数据；`execute_query` 结果附带实际生效的 `database`，便于发现同一 SQL 在不同库上列集不一致。
- 资产类型插件系统：签名市场安装（ed25519 索引验签 + 制品哈希确认）、插件独立虚拟环境与 worker 进程池、插件中心控制台、代码版本绑定授权（升级需重新确认）。
- 官方插件市场 CI：GitHub Pages 发布（确定性打包、历史版本保留、同版本防覆盖）与每 5 天定时重签（索引 7 天有效期）。
- 容器入口自动分流：配置了 `GATEWAY_MASTER_KEY`（compose `env_file`）仍启动 HTTP 服务；未配置时进入自举 stdio 模式（`app/stdio_server.py`），以一次性密钥与临时数据库响应 MCP `initialize`/`tools/list`/`tools/call`——目录检查（Glama 等）可直接通过，也支持将网关作为本地 stdio 服务器接入 AI 客户端（`GATEWAY_CLIENT_TOKEN` 指定客户端令牌）。
- 健康检查区分运行模式（`app/healthcheck.py`）：stdio 自举模式视为健康，不再误报 unhealthy。
- 修复：`k8s_apply` 的 Server-Side Apply PATCH 原先误发到资源集合 URL（缺 `/{metadata.name}`），真实集群返回 HTTP 405；现已 PATCH 到单个资源 URL（`…/namespaces/{ns}/{plural}/{name}`，创建与更新统一入口）。
- Kubernetes 新增 `k8s_apply`：以 Server-Side Apply 幂等创建/更新命名空间内资源（Secret、ConfigMap、Service、PVC、StatefulSet、Deployment 固定白名单；ServiceAccount/Role 等权限类与集群级资源一律拒绝）。账号策略默认关闭，显式开启 `allow_apply` 后生效；锁定命名空间时文档 namespace 被强制覆盖，未锁定时文档必须声明；支持 `dry_run`，apply 前剥离 uid/resourceVersion/status，部分失败时报告已生效前缀且不回滚。

## 0.1.0（2026-09-24）

首次公开发布：为 AI 客户端提供统一 MCP 入口的自托管资产网关。

- 八类资产适配器：MySQL（默认只读，账号显式开启 `allow_write` 后支持受限写操作）、SSH 非交互执行、FileBrowser 只读目录、上游 MCP 转发、Redis 键扫描与读取、Kubernetes 资源/日志/`k8s_exec`、Git 代码仓库只读副本、Jenkins 原生 HTTP API（19 项工具）。
- 具名授权组：多个客户端与多个“账号-工具”条目关联，跨组权限取并集；工具参数黑白名单支持精确匹配与限时正则全文匹配。
- Web 管理控制台：授权矩阵多维搜索、组管理、工具全选、调试台与审计导出。
- 部署：官方多架构镜像（linux/amd64、linux/arm64）发布于 ghcr.io，`docker-compose.yml` + `.env` 三步部署，无需宿主机 Python（`app.cli setup --output -` 在容器内生成配置）。
- 安全基础：凭据 Fernet 加密、客户端令牌摘要存储、管理会话与 CSRF 防护、出站目标允许列表、SQLite 一致备份与主密钥轮换。
