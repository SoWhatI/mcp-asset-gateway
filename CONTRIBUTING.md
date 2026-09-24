# 贡献指南

欢迎提交可复现的问题和小范围改进。安全漏洞请先阅读 [SECURITY.md](SECURITY.md)。提交贡献表示你有权以项目 MIT 许可提供相应内容；第三方代码需保留其许可声明。

## 提交问题或功能建议

使用前先阅读 [用户指南](USER_GUIDE.md)。问题报告请提供：程序版本或提交号、部署方式、操作系统/浏览器、最小复现步骤、预期与实际结果，以及已脱敏的错误码和请求标识。说明是否使用模拟目标；不要附入真实业务数据。

功能建议请说明使用场景、现有方案的限制和期望行为。变更较大的授权、传输层、存储或 API 设计先讨论兼容性，再提交实现。

不要附入 `.env`、MCP 完整令牌配置、cookie、数据库/备份或原始生产日志；截图应遮蔽真实姓名、邮箱、资产地址和客户信息。涉及可利用漏洞时使用私密报告渠道，不发公开复现。

## 开发约定

- 按 README 安装锁定依赖；前端使用 Node.js 22，后端使用 Python 3.11+。
- 改动授权、凭据或执行链路时补充隔离和失败路径测试；不得依赖生产凭据。Git 传输回归使用本地 HTTP/HTTPS 与 SSH/SFTP 服务，测试所用系统 Git 须支持 `http.curloptResolve`，不要整体 mock 掉安全准备流程来制造通过。
- 数据库变更新增顺序编号迁移，不改动已有迁移内容；同时测试升级和备份恢复。
- API/MCP 稳定标识用于协议，界面名称用于展示，不能互换。
- 依赖更新同时维护锁文件。Python 运行依赖使用带哈希的 `requirements.lock`，可用 pip-tools 从 `requirements.in` 重新生成，复验 Python 3.11/3.12。
- 不提交 `.env`、cookie、数据库、备份、密钥、内部部署记录或构建产物。
- 安全负面测试只使用假值或临时生成的材料；PEM/凭据 URL 等假值可运行时组装，不能为消除误报而豁免整个测试目录，也不能用拼接隐藏真实秘密。
- 维护者提交统一使用公开的 SoWhatI <SoWhatI@users.noreply.github.com> 身份，不引入其他姓名或邮箱。

## 提交前验证

```bash
ruff format app tests scripts
ruff check app tests scripts
python -m pytest -q
npm test --prefix web
npm run build --prefix web
python scripts/release_check.py
python scripts/release_check.py --staged
```

`--staged` 仅检查待提交的确切内容，不能代替工作区或历史扫描。涉及 UI 的改动请附脱敏后的桌面和移动端验证结果。默认跳过的真实远端、Docker、浏览器测试不能视为已通过；请在 PR 中明确实际执行范围。

依赖审计与 CI 使用相同入口：

```bash
python -m pip install pip-audit==2.10.1
python -m pip_audit -r requirements.lock --no-deps --disable-pip
npm audit --prefix web --registry=https://registry.npmjs.org
```

当前安全基线与部署边界见 [SECURITY.md](SECURITY.md)。漏洞审计未通过时不能声称 CI 全绿；更新依赖需同步锁文件并做兼容性回归，不随意忽略公告。CI 在 push、PR、手动触发和每周定时运行，但不会自动部署。

PR 请写明变更目的、兼容性/迁移影响、测试结果及剩余风险。镜像推送、公开仓库和发布由维护者单独确认操作。

## GitHub 发布前清单

公开源码与发布可部署发行版是两道不同的验收门槛；以下各项未全部确认前不能视为已经完成。

### 源码公开前

- [ ] 确认有权以现有 [MIT 许可](LICENSE) 发布全部代码与文档，保留第三方许可声明。
- [ ] 不上传整个工作目录：`.env`、数据库、备份、私钥、cookie、预览截图和内部开发记录保持私有；构建与远程打包从干净的发布树执行。
- [ ] 运行 `python scripts/release_check.py`；暂存后运行 `python scripts/release_check.py --staged`，并人工检查 `git diff --cached`。空暂存区的通过不代表全项目通过。
- [ ] 用秘密扫描工具检查全部待发布 refs 的完整历史与候选文件，并人工复核命中项；发现真实秘密先轮换凭据，再处理历史。
- [ ] 人工检查截图、附件、日志、CI 产物和镜像，不包含真实租户名、资产地址、代码或业务数据。

### 发布前

- [ ] 通过 Python/前端测试、构建与漏洞审计；完成容器启动、迁移和恢复演练。
- [ ] 在干净环境按用户指南完整执行一次部署，并对默认跳过的集成测试（远端契约、全栈 e2e、真实浏览器、稳定性压测）单独验收。
- [ ] 从已审核提交生成固定版本标签、Release 说明和镜像；镜像通过手动触发 `publish-image` workflow（输入与仓库一致的版本号）发布到 ghcr.io，记录支持范围、升级步骤、已知限制及校验信息，不附入运行数据。

### GitHub 仓库设置

- [ ] 补充仓库 Description、Topics 与文档入口；确认对应版本的官方镜像已在 ghcr.io Packages 发布并拉取验证。
- [ ] 开启可用的 secret scanning / push protection、Dependabot alerts 和私密漏洞报告。
- [ ] 配置分支保护或 ruleset，要求 PR 与 `checks`、`dependency-audit` 通过；CI 使用只读权限，不向外部 PR 提供生产凭据。
- [ ] 核对每周依赖审计及 Dependabot 更新；本地新锁文件审计通过，远端 CI 状态须在提交后核实，不得忽略新公告或允许失败。`ci.yml` 不自动推送镜像、创建 Release 或部署；镜像发布仅由手动触发的 `publish-image` 执行。
