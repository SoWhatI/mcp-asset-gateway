# 部署与运维

本文覆盖 Docker 部署、镜像构建推送、升级迁移与备份恢复。首次安装与配置核对见 [用户指南](../USER_GUIDE.md)，出站登记等安全配置见 [安全说明](../SECURITY.md)。

## Docker 部署

需要 Docker 和支持 `env_file.format: raw` 的 Compose 2.30+。在完成本地依赖安装后，用 CLI 生成 `.env`；容器内的数据目录由 Compose 单独指定。

```bash
python -m app.cli setup --public-url https://gateway.example.com
bash build-and-push.sh --build
bash deploy.sh --init
```

`gateway.example.com` 是占位域名，需替换为实际访问地址。如果已有 `.env`，跳过 `setup` 并手工核对参数。Compose 默认只绑定宿主机回环地址，通过反向代理提供 HTTPS。`PUBLIC_BASE_URL`、`ALLOWED_HOSTS`、`ALLOWED_ORIGINS` 应与访问域名一致；远程部署保持 `COOKIE_SECURE=true`。参考 [.env.example](../.env.example)。

容器以非 root 用户运行，根文件系统只读、移除 capabilities；数据库与备份分别使用命名卷。不要使用多副本访问同一个数据库。

## 构建、推送与升级

`build-and-push.sh` 默认仅本地构建；推送必须显式指定目标，脚本不登录仓库、不部署服务：

```bash
IMAGE_NAME=ghcr.io/your-owner/mcp-asset-gateway IMAGE_TAG=0.1.0 bash build-and-push.sh --push
```

`--remote` 还要求显式设置 `SERVER`、`REGISTRY`、`REMOTE_IMAGE`；可通过 `BASE_DIR` 设置构建目录，默认 `/opt/mcp-asset-gateway`。它会通过 SSH 上传构建上下文并构建/推送，请仅指向可信主机。每个标签使用独立目录，已有同标签目录会拒绝覆盖；不使用 `latest`。需要提前完成 SSH 和 registry 登录。

升级前先构建或拉取目标镜像，更新 `.env` 中的 `IMAGE_NAME` / `IMAGE_TAG`，再执行：

```bash
bash deploy.sh --upgrade
```

脚本先在线备份，再停止旧实例、执行迁移并启动新实例。迁移 `003.sql` 将旧授权转为具名组并拆分客户端、账号成员表，允许跨组重复授权；`005.sql` 与 `006.sql` 重建 `assets` 表以支持 `redis`、`kubernetes` 与 `gitrepo` 类型。`007.sql` 增加参数规则，并将旧 SSH 非空 `command_allowlist` 迁入所有现存授权条目的 `cmd` 精确白名单；空名单/未配置名单原本不可执行，因此移除对应 `exec_command` 授权，需管理员显式重新勾选。迁移使用旧分词/引用方式生成精确文本，保留通配符等字面量语义并移除账号旧字段；之后调用必须与迁移后的文本一致，空白/引号等变体不再自动归一化。`008.sql` 重建资产表以纳入 Jenkins，保留既有账号凭据、授权组及参数规则并复验外键。不要编辑已应用的迁移文件；不要用旧镜像直接打开升级后的数据库。

## 备份和恢复

```bash
python -m app.cli backup backups/manual.sqlite
# Docker 运行环境：
docker compose exec -T gateway python -m app.cli backup /app/backups/manual.sqlite
```

备份目标必须是新文件。运行期间自动保留 7 份日备份、4 份周备份；请另行配置异机备份。不要直接复制活跃的 WAL 数据库文件。

恢复或回滚前停止所有运行实例，使用与备份兼容的程序版本和匹配的主密钥，把一致备份恢复到独立数据目录，验证完整性与凭据解密后再切换。保留故障库用于核查，不要仅替换主数据库却遗留不匹配的 WAL 文件。主密钥丢失无法恢复加密凭据。
