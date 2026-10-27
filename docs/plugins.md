# 插件系统（Plugin System）

插件让网关在不修改主项目、不重建镜像的情况下增加新的资产类型。第一版面向**自研或经过审核的插件**，配合你自建的签名插件市场使用。

## 使用流程

```
插件中心 → 浏览市场 → 选择版本 → 确认制品哈希并安装
                                    ↓
                               校验通过后手动启用
                                    ↓
资产管理 → 选择新增资产类型 → 配置连接、账号与凭据（Schema 自动生成表单）
                                    ↓
                        授权组分配工具 → MCP 调用
```

安装不会自动创建资产或授予工具权限；启停、升级后客户端需重新获取工具列表。

## 部署配置

| 变量 | 说明 |
|---|---|
| `PLUGINS_DIR` | 插件安装根目录；容器内由 compose 固定为 `/app/plugins`（独立可写卷 `gateway-plugins`） |
| `PLUGIN_MARKET_URL` | 市场索引来源，`http(s)://` 或内网 `file://` |
| `PLUGIN_MARKET_PUBLIC_KEY` | 市场 ed25519 公钥（base64，32 字节）；与 URL 同时配置后市场可用 |

市场是"签名静态索引 + 制品存储"，可放在对象存储或静态站点。索引 `index.json` 携带各版本制品的 sha256，签名文件 `index.sig` 覆盖索引全文；公钥只来自部署配置，索引自身不能引入新的信任根。市场不可达不影响网关启动与已启用插件。

参考实现见 `examples/plugins/acme.postgresql/build.py`：

```bash
python examples/plugins/acme.postgresql/build.py --out dist/market
# 输出市场目录与一次性签名密钥；正式发布请在受控环境保管私钥（PLUGIN_SIGN_KEY）
```

## 插件包结构

```
manifest.json          # 身份、协议兼容、类型声明、能力声明
schemas/*.json         # connection / account / credential / policy 表单 Schema
<模块>/                # 插件代码（entry 指向 模块:类）
requirements.lock      # 依赖锁定（带 --hash）
wheelhouse/*.whl       # 随制品携带的全部依赖 wheel
```

安装链路：下载（大小上限）→ 校验 sha256 → 受限解包（拒绝绝对路径、`..`、软链、特殊文件；限制文件数与总体积）→ manifest 校验 → 独立 venv + `pip install --no-index --no-deps --require-hashes`（只装平台匹配的 wheel，不执行安装脚本、不做在线解析）→ 无凭据握手预检 → 原子落盘为"已安装、未启用"。同版本制品不可覆盖；中断安装可重试。

## 插件开发（SDK）

插件入口继承 `mag_plugin.Plugin`，每个资产类型继承 `mag_plugin.AssetType`：

```python
from mag_plugin import AssetType, Plugin, ok

class PostgresType(AssetType):
    type_id = "acme.postgresql"        # 必须以发布者前缀开头
    display_name = "PostgreSQL 数据库"
    default_port = 5432                # host_port 型连接的默认端口
    dynamic_tools = False              # True 时通过 discover_tools 动态发现目录

    def validate_connection(self, ctx, connection): ...
    def validate_config(self, ctx, connection, account, policy, credential): ...
    def health(self, ctx): return {"ok": True}
    def discover_tools(self, ctx): ... # dynamic_tools=True 时实现
    def execute(self, tool, args, ctx): return ok({...})

class PostgreSQLPlugin(Plugin):
    asset_types = [PostgresType]
```

- `ctx.net` 提供出站网络助手：`check`/`check_url`（登记校验）、`resolve`（DNS 解析并固定 IP）、`request`（固定 IP、TLS 验证、拒绝重定向、响应大小上限的 HTTP）。
- `ctx.credential` 只包含本次操作所需的账号凭据；`ctx.check_deadline()` 用于在长操作前自查期限。
- 插件运行在独立 venv 的工作进程中：stdout 被重定向（协议通道独占），日志写 stderr 落盘到插件目录 `logs/`；进程环境经过白名单清洗，主密钥等网关机密不会进入插件进程。

表单 Schema 只允许控制台已支持的子集（string/integer/number/boolean/字符串数组、enum、password、x-upload 等）；`$ref`、嵌套对象等超集在安装校验时直接拒绝，插件不能借表单注入前端内容。

## 生命周期与授权规则

| 操作 | 行为 |
|---|---|
| 启用 | 启动工作进程、握手校验后注册类型；无需重启网关 |
| 停用 | 拒绝新调用，等待在途调用（上限 30 秒）；保留资产、凭据与授权记录 |
| 升级 | 新旧版本并存预检（对既有账号逐个 `validate_config`）后切换；失败保留旧版本继续服务 |
| 回滚 | 切回保留制品；授权不自动恢复 |
| 卸载 | 存在关联资产时拒绝 |
| 插件异常/文件缺失 | 对应类型标记不可用（占位），其余类型继续服务 |

**授权绑定代码版本**：插件工具授权同时绑定工具定义哈希（动态目录）与插件制品哈希。升级即使没有修改 Schema，也需要在授权组里重新确认（`CODE_CHANGED`），旧授权不会自动放行新代码。插件工具统一按账号加前缀发布（复用 MCP 代理的命名规则），内置工具名称保持不变。

## 安全边界

认证、授权、参数规则、凭据加密、调用前审计与输出限制仍由网关负责，插件只接收本次调用所需的账号信息与凭据。**独立进程和虚拟环境不是恶意代码沙箱**：与网关同用户运行的可信插件仍可能访问文件或网络。因此第一版只接受自研或审核过的插件；要支持任意第三方插件，需要另行增加容器级权限与网络隔离。

## 官方插件市场

官方市场部署在 GitHub Pages（`https://sowhati.github.io/mcp-asset-gateway/`），由 CI 流水线（`plugin-market.yml`）自动构建、签名与发布：插件源码变更时全量重打制品，每 5 天定时重签索引（索引自带 7 天有效期）。

自部署网关接入官方市场，在 `.env` 配置：

```
PLUGIN_MARKET_URL=https://sowhati.github.io/mcp-asset-gateway
PLUGIN_MARKET_PUBLIC_KEY=3L6Hk5796NEdgM9ZsrukI2834ICKPaHFuKfjHSc6c4c=
```

**发布与运维约定**：

- 签名私钥（`PLUGIN_SIGN_KEY`）只存在于仓库 Actions Secret，公钥随 README/文档分发；轮换密钥需同步更新所有部署的公钥配置。
- 制品哈希即审计锚点：索引中每个版本记录 sha256，官方 CI 确定性打包（zip 条目时间戳固定），同版本重签哈希不变；同版本号不同内容会被构建脚本拒绝（防覆盖）。
- 历史版本持续保留：发布时从线上索引合并历史条目并搬运全部历史制品，旧版本始终可安装、可回滚。
- 新插件上架 = 向 `examples/plugins/` 提交目录并通过审核合并，由 CI 自动发布；第三方依赖在插件目录 `deps.txt` 中声明，构建时下载 wheel 打包。

## 离线安装（上传制品）

网关与官方市场网络隔离时，管理员可在控制台「插件中心 → 插件市场 → 离线安装」直接上传制品 zip（或 `POST /api/plugins/install-offline`，multipart 字段 `file`）：

1. **预检**：网关解析 zip 内 manifest 并计算 sha256，与官方市场索引比对。响应携带 `verified`（是否通过官方验证）、`verify_note`（未验证原因：索引中不存在该版本 / 哈希不一致 / 市场不可用等）。
2. **确认**：`verified=false` 时控制台弹红色安全警告，管理员必须显式确认「我已确认来源可信」（API 传 `confirm=true`）才会创建安装任务；验证通过则走常规确认。
3. **安装**：后续哈希校验、安全解包、独立环境与握手预检与市场安装完全一致；同版本号不同内容的制品一律拒绝覆盖（`VERSION_CONFLICT`）。

**风险约定**：独立进程与虚拟环境不是沙箱，未通过验证的插件等同在网关宿主机运行不受信任代码，仅在制品来源可信（如内部构建系统直出）时使用该入口。
