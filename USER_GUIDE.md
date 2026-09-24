# 用户指南

本指南面向首次部署及日常使用 MCP Asset Gateway 的管理员。开发与版本信息见 [README](README.md)，漏洞反馈与部署边界见 [安全说明](SECURITY.md)。

> 以下步骤先在隔离环境评估，不代表你的部署已经过安全验收；试用不要连接生产资产或使用真实生产凭据。

## 1. 先理解四个对象

```text
AI / MCP 客户端 ── 客户端令牌 ──> 网关 /mcp
                                   │
                              授权组与参数规则
                                   │
                            资产账号 ──> 目标资产
```

| 对象 | 保存什么 | 示例 |
|---|---|---|
| 资产 | 类型和连接参数，不放密码 | 演示 MySQL 的主机、端口、TLS 配置 |
| 资产账号 | 所属资产、登录配置、托管凭据及资源限制 | 只读数据库用户、默认数据库 |
| 客户端 | 调用方身份、令牌、有效期及启用状态 | 一个开发助手或一套自动化应用 |
| 授权组 | 多个客户端与多个“账号-工具”条目的关联 | 开发助手只能使用演示账号的结构读取工具 |

管理员登录控制台使用用户名和密码；MCP 客户端使用单独签发的令牌。两者不能混用。对象 ID 自动生成；名称便于人阅读，协议使用稳定 ID。

## 2. 安装与首次登录

### 本地评估

需要 Python 3.11+、Node.js 22（最低 20.19）、Git，以及 Linux/macOS；Windows 使用 WSL2 或 Docker。在取得源码并进入项目根目录后执行：

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

1. `setup` 创建权限受限的 `.env` 和随机主密钥，不覆盖已有文件。
2. `init-admin` 仅用于首次初始化；安全保存终端显示的一次性密码，不要录屏或贴入 Issue。
3. 打开 http://localhost:8303，使用 `admin` 和生成的密码登录，按提示修改初始密码后重新登录。
4. 保存 `.env`，并将主密钥独立、安全备份。密钥丢失后无法恢复加密凭据。

只支持一个运行实例、一个 Uvicorn worker。不要使用共享网络文件系统存储 SQLite，不要让本地进程和容器同时打开同一数据库。

### Docker 评估与部署入口

需要 Docker 和 Compose 2.30+；官方多架构镜像（linux/amd64、linux/arm64）发布在 `ghcr.io/sowhati/mcp-asset-gateway`，部署无需宿主机 Python：

```bash
mkdir mcp-asset-gateway && cd mcp-asset-gateway
curl -fsSLO https://raw.githubusercontent.com/SoWhatI/mcp-asset-gateway/main/docker-compose.yml
docker run --rm ghcr.io/sowhati/mcp-asset-gateway:0.1.0 \
  python -m app.cli setup --public-url https://gateway.example.com --output - > .env
chmod 600 .env
docker compose up -d
docker compose run --rm --no-deps gateway python -m app.cli init-admin --generate-password
```

已有源码目录时也可直接执行 `bash deploy.sh --init`（需先自行生成 `.env` 与镜像）；`gateway.example.com` 是占位域名，需替换为自己的访问地址。已有 `.env` 时不要重复执行 `setup`，应核对其中的配置。`deploy.sh --init` 会初始化管理员；未使用该脚本时，执行上面的 `init-admin` 命令即可，不要对同一容器数据库重复初始化。

默认仅绑定宿主机 `127.0.0.1:8303`，需自行配置反向代理提供 HTTPS。代理应保留原始 Host，转发 `Authorization` 和 MCP 协议头；支持流式 HTTP，不缓冲 MCP 响应，并设置足够的读取超时。不要在代理访问日志中记录认证头、cookie 或完整请求体。

容器使用 UID/GID `10001:10001`，根文件系统只读；数据和备份分别在命名卷中。容器里的证书路径必须指向实际挂载、且该用户可读的文件，不能直接使用宿主机路径。

### 必须核对的配置

完整示例见 [.env.example](.env.example)。修改后需重启进程；Compose 使用 `docker compose up -d --force-recreate gateway` 重新加载容器环境，单纯 `restart` 不更新环境变量。

| 配置 | 含义与建议 |
|---|---|
| `GATEWAY_MASTER_KEY` / `GATEWAY_MASTER_KEY_ID` | 凭据加密密钥及其标识。不要随意改值；轮换需使用维护命令 |
| `PUBLIC_BASE_URL` | 实际访问的 HTTP(S) 来源，不带路径、查询参数或凭据 |
| `ALLOWED_HOSTS` | 允许的访问主机名，以逗号分隔，不使用通配符 |
| `ALLOWED_ORIGINS` | 允许的完整来源，如 `https://gateway.example.com` |
| `COOKIE_SECURE` | HTTPS 部署必须为 `true`；本地 HTTP 评估才使用 `false` |
| `OUTBOUND_ALLOWLIST` | 默认 `null`，不启用目标登记。非空 JSON 数组启用主机/端口登记 |
| `SSH_HOST_KEY_ENFORCE` | 默认 `false`，存在中间人风险；生产应设为 `true` 并核对指纹 |
| `DATABASE_PATH` | 本地默认为 `data/gateway.db`；Compose 固定为 `/app/data/gateway.db` |
| `IMAGE_NAME` / `IMAGE_TAG` | 运行镜像的名称与固定版本标签；默认官方镜像 `ghcr.io/sowhati/mcp-asset-gateway`，自建镜像时改为自己的地址 |

出站配置必须是合法 JSON，例如：

```dotenv
OUTBOUND_ALLOWLIST=[{"host":"db.example.com","port":3306},{"host":"ci.example.com","port":443}]
```

登记中的主机、端口须与资产一致。启用登记后，允许明文 HTTP 的目标还需 `"allow_http":true`；这不意味着明文传输安全。即使配置了允许列表，也必须使用防火墙限制网关的出站范围。Git 克隆、拉取和健康检查均执行运行期出站校验，HTTP(S) 固定解析 IP、保持 TLS 验证且不跟随重定向，详见 [安全说明](SECURITY.md#git-适配器)。登记列表非空即启用强制登记：经过网络策略的连接会拒绝未登记目标，并始终禁止回环、链路本地、组播与云元数据地址。

## 3. 跑通第一个只读工具

以下以演示 MySQL 为例。目标数据库须由网关所在主机或容器访问，不能填写 `localhost` 指代另一台服务器；应用会限制回环等目标。先准备一个仅有演示数据读取权限的远端账号。

### 第一步：创建资产

在资产管理中新建 MySQL 资产，填写名称、主机、端口和 TLS 设置。不要把用户名、密码拼进地址或显示名称。

MySQL 默认 `PREFERRED` 会在目标不支持 TLS 时回退明文；敏感环境应优先选择 `VERIFY_IDENTITY` 并配置可信 CA。不要为排障直接关闭证书验证。

### 第二步：创建资产账号

1. 选择刚创建的资产，填写账号名称、数据库用户名及默认数据库。
2. 在凭据区域填写密码；保存后不会回读明文。
3. 保持“允许写操作”关闭，并按实际需要限制返回行数、超时和输出大小。
4. 保存后点击“测试连接”。连接成功只代表连通与认证正常，不代表已经授权给客户端。

账号配置的默认数据库不是跨库安全边界。工具支持 `database` 参数或 `库名.表名`；真正的库表隔离必须由数据库账号权限实现。

### 第三步：创建客户端

新建一个评估客户端，设置名称及适当的令牌有效期。保存时只展示一次完整令牌，可复制令牌或 MCP 配置。令牌应放入客户端的秘密配置，不应提交到 Git。

### 第四步：建立授权组

1. 新建授权组并命名。
2. 在客户端区域选择刚创建的客户端，点击添加。
3. 在“资产账号-工具”区域选择演示账号并添加。
4. 点击该账号的“配置工具”，先仅勾选 `list_tables`、`describe_table`；确有需要再开放 `execute_query`。
5. 保存并确保客户端、资产、账号及授权组都处于启用状态。

每个客户端获得该组所有账号条目中所选工具的权限。空组或未选择工具的条目不会产生工具权限。不同组的工具授权取并集：删除一个组不一定撤销全部权限。

### 第五步：先在调试台验证

打开“工具调试台”，选择客户端、工具及相应账号，填写表单后执行。先尝试 `list_tables`，确认得到演示表名，再检查审计记录。

调试台使用真实授权链路和真实目标，不是模拟器。不要为试用勾选写工具、执行 shell 命令或触发构建。

## 4. 连接 AI / MCP 客户端

网关提供 Streamable HTTP 入口 `/mcp`，不是旧式 `/sse` 入口。可直接复制创建或轮换令牌时展示的配置，也可按客户端格式填写：

```json
{
  "mcpServers": {
    "asset-gateway": {
      "url": "https://gateway.example.com/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_WITH_CLIENT_TOKEN"
      }
    }
  }
}
```

- `REPLACE_WITH_CLIENT_TOKEN` 只是占位符，必须替换成网关签发的客户端令牌。
- FastGPT 等提供表单的客户端，选择支持 Streamable HTTP 的 MCP 连接方式，填写 URL 和认证 Header；具体字段以对应版本为准。
- 启用后刷新工具列表，再调用已经验证过的只读工具。
- 同名原生工具对应多个账号时，schema 会要求 `target`，应填写工具描述中列出的资产账号 ID，不是名称或资产 ID。
- 不支持远程 Streamable HTTP 或自定义认证头的客户端，不能直接使用上述配置。

任何返回给客户端的表数据、文件、日志或代码，都可能继续进入模型服务商的处理链路。仅授权允许外传的数据，并检查客户端/模型服务商的保留政策；网关不等于数据脱敏或防泄露系统。

## 5. 各类型的关键限制

| 类型 | 使用要点 |
|---|---|
| MySQL | 默认只读。`allow_write` 打开后，同一 `execute_query` 工具可执行 INSERT/UPDATE/DELETE；UPDATE/DELETE 要求 WHERE，但不保证条件只影响少量行。权限与备份仍由数据库侧控制 |
| SSH | 非交互命令执行。未配置参数规则时可执行任意非交互命令；使用精确白名单和远端最小权限账号，不提供 PTY/stdin |
| FileBrowser / SFTP | 账号限定只读根目录。`path` 是相对路径，根目录写 `.`；不要传 `/` 开头路径或 `..` |
| 上游 MCP | 先发现工具目录并审阅，再批准定义版本。描述/schema 变化后需重新确认，不自动批准新能力 |
| Redis | 配置键白名单模式（Redis glob），扫描与读取都有预算上限；写工具按账号策略显式开启。避免把整个缓存空间开放给客户端 |
| Kubernetes | Token 或客户端证书认证。命名空间留空表示不锁定：列表可跨命名空间，详情/日志/exec 须指定；资源类型留空表示全部内置类型，不包括 Secret 或任意集群级资源 |
| Git 仓库 | 维护网关自己的只读副本；首次准备可能返回 `REPO_PREPARING`，不是读取开发者的本地工作区。填写最终仓库 URL，不依赖重定向、环境代理或全局 Git 配置 |
| Jenkins | 使用根 URL、用户名和 API Token。四个写工具及 Replay 须明确授权；日志与脚本可能含秘密，远端须正确掩码，超时后不可盲目重发写操作 |

SSH/SFTP 主机指纹校验默认关闭（`SSH_HOST_KEY_ENFORCE=false`）：创建与编辑资产不展示指纹字段，连接接受任意主机密钥（存在中间人风险，仅限可信网络）；设为 `true` 后指纹字段恢复展示且必填，连接时校验，历史记录中已保存的指纹原样保留、重新开启后恢复生效。

Kubernetes `k8s_exec` 还要求账号允许 `pods` 和集群 RBAC 允许 `pods/exec`。`command` 为 argv 数组，例如 `["uname","-a"]`，不会隐式使用 shell；必须单独勾选该工具。上传 PEM 与填写容器内证书路径均可，内容须完整且证书与私钥匹配。

Git 仓库资产的凭证为 SSH 私钥或 HTTPS 令牌二选一；副本由网关维护在数据卷内，首次调用触发后台克隆，之后工具调用按 `refresh_interval_seconds` 检查并触发后台 fetch，设为 0 禁用自动刷新（不新增独立定时任务）。启用出站登记时，代码仓库地址与端口需先登记在 `OUTBOUND_ALLOWLIST`。

Git HTTP(S) 需要系统 Git 支持 `http.curloptResolve`，不支持会返回 `GIT_UNSUPPORTED`；子进程优先使用 `/usr/bin`、`/bin` 的 Git/OpenSSH。HTTPS 使用系统信任链，不支持关闭证书验证。缓存 `.git/config` 不可手工增加代理、helper 或 URL rewrite；修改资产仓库地址/分支后，需要在停机并保留备份的前提下重建该账号的网关副本，不能修改安全检查来放行旧配置。

Paramiko 5 不再支持 RSA SHA-1 签名、SHA-1 密钥交换等旧算法；SSH/SFTP/Git SSH 服务器需支持现代算法，RSA 密钥本身仍可配合 SHA-2 使用。升级前应核查旧版本 `repos/.work/` 可能遗留的临时私钥，详见安全说明。

## 6. 参数规则、撤权和轮换

在授权组的“配置工具”中展开“参数黑白名单”：

- `exact` 为原文精确匹配；`regex` 为全文匹配，不是“包含即可”。空白有意义。
- 同参数多条白名单取 OR，同组多个参数的白名单取 AND；跨组须满足至少一个组的完整白名单，任一适用组黑名单命中均拒绝。
- 数组/对象按紧凑 JSON 匹配，对象键排序。例如 exec 命令规则应写 `["uname","-a"]`，不是 `uname -a`。
- 规则只约束该账号工具的顶层入参，不过滤结果，不替代远端权限、shell 沙箱或网络隔离。

撤权时检查所有关联组；紧急处理可先禁用客户端或账号。删除含黑名单的组可能放宽其它组原本被阻止的调用。

丢失或疑似泄露客户端令牌时，在客户端列表点击“轮换”，旧令牌失效，再更新调用方配置。不要只删除本地配置文件；远端账号凭据泄露时还须在目标系统轮换密码/Token/私钥。

## 7. 审计、备份和升级

### 审计

在“审计日志”筛选事件、状态、客户端等，查看详情或导出 CSV。通过客户端名称、时间和请求标识关联问题，避免直接分享完整导出。

审计不是工具返回内容的完整录像，也不能作为业务数据备份。对象名称、参数名/摘要和访问元数据仍可能敏感；配置、日志、代码副本及备份均应按私有数据保管。

### 一致备份

```bash
# 本地运行环境，目标文件必须尚不存在：
python -m app.cli backup backups/manual.sqlite
# Docker 运行环境，备份位于容器的备份卷：
docker compose exec -T gateway python -m app.cli backup /app/backups/manual.sqlite
```

运行期间自动保留 7 份日备份、4 份周备份；需要另行安排异机副本和恢复演练。不要复制正在写入的 SQLite 主文件代替一致备份。主密钥与数据库应分开保管，并保留版本配对关系。

### 升级与恢复

1. 阅读 [CHANGELOG](CHANGELOG.md)，先在隔离环境验证迁移和恢复。
2. 拉取明确版本的目标镜像，更新 `.env` 中的 `IMAGE_TAG`（官方镜像无需改 `IMAGE_NAME`）。
3. 执行 `bash deploy.sh --upgrade`：脚本在线备份、停止旧实例、执行迁移并启动新实例。
4. 验证 `/ready`、登录、工具目录、只读调用和审计。

升级失败时保持停止状态，不要用旧程序直接打开已迁移数据库。恢复时停止所有实例，把一致备份放到独立数据目录，使用兼容的程序版本和匹配的主密钥，验证完整性与解密后再切换；勿遗留不匹配的 WAL 文件。

主密钥不能直接修改环境变量来“轮换”。离线维护入口为 `python -m app.cli rotate-key --help`：需停止服务、提供当前用户独占权限的新密钥文件和新 key ID；成功重加密后再更新部署配置。旧备份仍与旧主密钥配对保存。

## 8. 常见问题

| 现象 | 优先检查 |
|---|---|
| 登录后立即退出或来源被拒绝 | 实际域名与 Host/Origin 配置是否一致；HTTPS 与 `COOKIE_SECURE` 是否匹配；不要混用 localhost 和 IP 登录 |
| MCP 返回 401 | 是否使用客户端令牌而非管理员密码；是否过期、已轮换或客户端已禁用 |
| 工具列表为空 | 各对象是否启用、组是否关联该客户端与账号、是否勾选工具；上游 MCP 定义是否需重新批准 |
| `TARGET_REQUIRED` | 多个账号提供同名工具，按 schema 填写正确的资产账号 ID |
| 参数规则拒绝 | 精确文本、正则全文匹配、JSON 形式、默认值及其它组黑名单是否符合预期 |
| 连接被出站策略拒绝 | 从网关所在环境检查 DNS/端口；登记主机是否一致；目标是否为禁止的回环/元数据等地址 |
| `MYSQL_TLS_FAILED` | CA、主机名、服务端 TLS 版本和证书链；不要直接回退不安全模式作为生产修复 |
| `K8S_AUTH_FAILED` 或 403 | Token 有效期、证书私钥配对与信任链、RBAC 和命名空间；401 与无权限的 403 区分处理 |
| `PATH_DENIED` | SFTP/Git 路径是否是账号根目录内相对路径，不用绝对路径或 `..` |
| `REPO_PREPARING` | 等待后台副本准备再重试；不要无限重试连接配置错误 |
| `GIT_UNSUPPORTED` | 升级子进程实际使用的系统 Git，确认支持 `http.curloptResolve` |
| `REPO_CONFIG_UNSAFE` | 核对资产 URL/分支与副本是否一致，在停机备份后重建该账号副本；不要放宽配置校验 |
| 写请求超时或远端状态未知 | 先查目标系统是否已执行；中断客户端连接不代表远端操作已取消 |
| `/ready` 失败 | 检查磁盘、数据库/审计可写性及服务日志；`/health` 存活不等于业务就绪 |

提交问题前先替换真实主机、用户名、项目名和数据，仅保留最小复现及脱敏错误。不要粘贴 `.env`、认证头、cookie、数据库、备份、私钥或带令牌的 MCP 配置。安全问题使用 [私密报告渠道](SECURITY.md#漏洞反馈)。
