# MCP Asset Gateway

简体中文 | [English](README.en.md)

为 AI 客户端提供统一 MCP 入口的自托管资产网关。通过 Web 控制台管理资产、账号凭据、客户端和授权组，并记录工具调用审计。

## 功能总览

| 类型 | 能力要点 |
|---|---|
| MySQL | 默认只读查询与结构读取；账号显式开启 `allow_write` 后支持受限 INSERT/UPDATE/DELETE，UPDATE/DELETE 强制 WHERE |
| SSH | 非交互命令执行，命令参数由授权组黑白名单控制；不提供 PTY 或交互输入 |
| FileBrowser | 基于 SFTP 的受限目录浏览与文件读取 |
| MCP | 转发上游工具，按账号批准工具定义版本 |
| Redis | 在白名单模式范围内扫描与读取键，写工具按账号策略显式开启 |
| Kubernetes | 资源列表、详情、Pod 日志与非交互 `k8s_exec`；Token 或客户端证书认证，详见 [Kubernetes 资产](docs/asset-kubernetes.md) |
| Git 仓库 | 网关托管只读代码副本：代码搜索、文件读取、提交历史、差异、目录树与分支列表 |
| Jenkins | 直接调用 Jenkins HTTP API，无需 MCP 插件；19 项任务、构建、日志、测试、SCM 与 Replay 工具，详见 [Jenkins 资产](docs/asset-jenkins.md) |
| 管理控制台 | 授权矩阵多维搜索、组管理、工具全选/取消全选、参数黑白名单（精确/正则）、调试和审计导出 |
| 安全基础 | 凭据 Fernet 加密、客户端令牌摘要存储、管理会话与 CSRF、出站目标允许列表、SQLite 一致备份 |

## 授权与安全模型

- 授权组关联多个客户端与多个资产账号，组内每个客户端获得每个账号上被选中的、实际存在的工具权限；多组取并集，同名工具不重复发布。完整规则见 [授权组与参数规则](docs/authorization.md)。
- 工具默认不授权；写操作与高危工具（MySQL `allow_write`、Jenkins 写工具、`k8s_exec` 等）必须在授权组显式勾选。
- 客户端令牌仅展示一次，凭据加密存储；主密钥与数据库分开保管。
- 可选出站登记约束网关可达目标，并始终禁止回环、链路本地、组播与云元数据地址；允许列表不能替代防火墙。

## 快速开始

推荐 Docker 部署，需要 Docker 与 Compose 2.30+；全程无需宿主机 Python：

```bash
mkdir mcp-asset-gateway && cd mcp-asset-gateway
curl -fsSLO https://raw.githubusercontent.com/SoWhatI/mcp-asset-gateway/main/docker-compose.yml
docker run --rm ghcr.io/sowhati/mcp-asset-gateway:0.1.0 \
  python -m app.cli setup --public-url https://gateway.example.com --output - > .env
chmod 600 .env
docker compose up -d
docker compose run --rm --no-deps gateway python -m app.cli init-admin --generate-password
```

`gateway.example.com` 是占位域名，替换为实际访问地址；本地评估使用 `http://localhost:8303`。打开控制台，使用管理员 `admin` 与一次性密码登录后修改密码；没有内置默认密码。镜像升级、反向代理、源码构建与备份恢复见 [部署与运维](docs/deployment.md)；安装、接入与配置核对见 [用户指南](USER_GUIDE.md)。

### 源码运行

环境：Python 3.11+、Node.js 22（最低 20.19）、Linux/macOS；Windows 使用 WSL2 或 Docker。使用 Git 资产还需支持 `http.curloptResolve` 的系统 Git 和 OpenSSH。当前采用 SQLite WAL 与进程文件锁，仅支持单实例、单 Uvicorn worker；数据库不要放在共享网络文件系统。

本地评估（在项目根目录执行）：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
npm ci --prefix web --no-audit --no-fund
npm run build --prefix web
python -m app.cli setup --public-url http://localhost:8303
python -m app.cli init-admin --generate-password
uvicorn app.main:app_factory --factory --host 127.0.0.1 --port 8303 --workers 1 --no-access-log
```

打开 http://localhost:8303，使用管理员 `admin` 与一次性密码登录后修改密码。`setup` 不覆盖已有 `.env`，支持 `--output -` 输出到 stdout 便于在容器内生成。

## 文档

| 文档 | 内容 |
|---|---|
| [用户指南](USER_GUIDE.md) | 安装、首次登录、资产接入、授权、MCP 配置、备份及常见问题 |
| [授权组与参数规则](docs/authorization.md) | 授权组模型与工具参数黑白名单 |
| [Kubernetes 资产](docs/asset-kubernetes.md) | 账号策略、认证与 `k8s_exec` 工具参考 |
| [Jenkins 资产](docs/asset-jenkins.md) | 原生 Jenkins 工具、权限与预算 |
| [部署与运维](docs/deployment.md) | Docker 构建/推送/升级、数据迁移、备份恢复 |
| [安全说明](SECURITY.md) | 安全边界、验证范围与私密漏洞报告 |
| [贡献指南](CONTRIBUTING.md) | 提交约定、验证命令与 GitHub 发布前清单 |
| [变更记录](CHANGELOG.md) | 版本历史 |

## 开发与测试

```bash
python -m pip install -r requirements-dev.txt
ruff check app tests scripts
ruff format --check app tests scripts
python -m pytest -q
npm test --prefix web
npm run build --prefix web
python scripts/release_check.py
```

默认测试不访问真实资产；远端契约、Docker 生命周期和真实浏览器验收需显式配置，默认跳过。隔离本地容器验收入口为 `python tests/local_stack.py --help`；不要给测试配置生产资产或凭据。

- `app/asset_types/`：八类资产适配器（MySQL、SSH、FileBrowser、MCP、Redis、Kubernetes、Git 仓库、Jenkins）。
- `app/core/`：存储迁移、授权、执行与安全基础设施。
- `app/main.py`、`app/cli.py`：HTTP/MCP 入口及维护命令。
- `web/src/`：Vue 管理界面；构建输出 `static/`，不提交产物。
- `tests/`：API、隔离、迁移和协议回归。

安全边界和漏洞反馈见 [SECURITY.md](SECURITY.md)，贡献说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 谁在使用？

如果你的公司或团队正在生产环境使用本网关，[欢迎登记](https://github.com/SoWhatI/mcp-asset-gateway/issues/new?template=used_by.yml)；经你确认后，使用案例将展示在这里。

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=SoWhatI/mcp-asset-gateway&type=Date" />
</picture>

## 许可

[MIT](LICENSE)
