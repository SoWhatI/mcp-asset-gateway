# 变更记录

## 未发布

- 容器入口自动分流：配置了 `GATEWAY_MASTER_KEY`（compose `env_file`）仍启动 HTTP 服务；未配置时进入自举 stdio 模式（`app/stdio_server.py`），以一次性密钥与临时数据库响应 MCP `initialize`/`tools/list`/`tools/call`——目录检查（Glama 等）可直接通过，也支持将网关作为本地 stdio 服务器接入 AI 客户端（`GATEWAY_CLIENT_TOKEN` 指定客户端令牌）。
- 健康检查区分运行模式（`app/healthcheck.py`）：stdio 自举模式视为健康，不再误报 unhealthy。

## 0.1.0（2026-09-24）

首次公开发布：为 AI 客户端提供统一 MCP 入口的自托管资产网关。

- 八类资产适配器：MySQL（默认只读，账号显式开启 `allow_write` 后支持受限写操作）、SSH 非交互执行、FileBrowser 只读目录、上游 MCP 转发、Redis 键扫描与读取、Kubernetes 资源/日志/`k8s_exec`、Git 代码仓库只读副本、Jenkins 原生 HTTP API（19 项工具）。
- 具名授权组：多个客户端与多个“账号-工具”条目关联，跨组权限取并集；工具参数黑白名单支持精确匹配与限时正则全文匹配。
- Web 管理控制台：授权矩阵多维搜索、组管理、工具全选、调试台与审计导出。
- 部署：官方多架构镜像（linux/amd64、linux/arm64）发布于 ghcr.io，`docker-compose.yml` + `.env` 三步部署，无需宿主机 Python（`app.cli setup --output -` 在容器内生成配置）。
- 安全基础：凭据 Fernet 加密、客户端令牌摘要存储、管理会话与 CSRF 防护、出站目标允许列表、SQLite 一致备份与主密钥轮换。
