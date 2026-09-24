# Jenkins 原生资产

Jenkins 类型直接调用 Jenkins HTTP API，不代理插件 MCP 协议。接入与授权操作见 [用户指南](../USER_GUIDE.md)；四个写工具及 Replay 须在授权组显式勾选。

参考 [jenkinsci/mcp-server-plugin](https://github.com/jenkinsci/mcp-server-plugin) 的工具设计，新增独立 `jenkins` 类型。填写 Jenkins 根地址（如 `https://ci.example.com/jenkins`），账号填写用户名，凭据填写 API Token；Token 经 Vault 加密、不会回读。HTTPS 始终校验证书，可上传 PEM CA 或填写容器内 CA 路径，不支持跳过证书校验。HTTP 仅适合可信网络，启用出站登记时还需 `allow_http:true`。

工具名为 `jenkins_` 加下表名称，参数保留 `jobFullName`、`buildNumber` 等 camelCase：

| 范围 | 工具 |
|---|---|
| 任务、队列 | `get_job`、`get_jobs`、`trigger_build`、`get_queue_item` |
| 构建、日志 | `get_build`、`update_build`、`get_build_log`、`search_build_log` |
| Pipeline | `rebuild_build`、`get_replay_scripts`、`replay_build` |
| 测试报告 | `get_test_results`、`get_flaky_failures` |
| SCM | `get_job_scm`、`get_build_scm`、`get_build_change_sets`、`find_jobs_with_scm_url` |
| 身份、状态 | `who_am_i`、`get_status` |

- 权限：读工具需要 Jenkins `Overall/Read`、相应任务/构建读取权限；SCM 配置及 Replay 脚本读取还需配置读取权限（`Job/ExtendedRead` 或 `Job/Configure`，依实例而定）。触发/重建需要 `Job/Build`，更新名称描述需要构建更新权限，修改脚本需要 `Run/Replay` 及服务端沙箱/脚本审批。网关不绕过 Jenkins 权限。
- `trigger_build`、`update_build`、`rebuild_build`、`replay_build` 为四个写工具，必须在授权组显式勾选。参数黑白名单可约束任务和脚本等顶层入参，但不自动过滤查询结果；项目隔离仍需 Jenkins 账号权限。没有脚本控制台、任务配置修改或管理操作。
- `jobFullName` 使用文件夹分隔名称；例如 `团队/repo/feature%2Ftopic` 中 `%2F` 是 Jenkins 多分支任务自身的名称编码。网关逐段重新编码；不允许路径穿越。未指定 `buildNumber` 时固定本次调用开始时的最后构建，不以 `nextBuildNumber` 猜测结果。
- 构建参数支持标量及标量数组（重复表单键），布尔值编码为 `true/false`；校验 Choice 参数，不支持文件/未知插件参数。密码参数需调用者显式提供，普通任务重建拒绝隐藏、密码或无法完整恢复的原参数，不悄悄使用默认值。
- Replay 兼容 Jenkins `workflow-cps` 的 `run/rebuild` 表单以及 `jenkins-form-item`、`jenkins-form-label`、textarea 页面结构，保留 HTML 实体解码后的源码和已加载脚本名称；未替换的脚本保持原值。非 Pipeline、页面不兼容、缺权限/插件/原脚本会明确失败；仅允许重建的页面不能读取或修改脚本。不会降级为重新触发当前 Pipeline。源码超过文档/字段/输出预算时拒绝读取或提交，不执行截断源码。
- Replay 表单通常仅重定向回任务页，成功返回 `submitted=true, queue_id=null`；不会猜测队列 ID 或重发。普通触发返回经过同来源及路径验证的队列 ID。写请求超时/断连标为 `JENKINS_WRITE_UNKNOWN`，必须查询远端状态，勿自动重试。
- 日志默认扫描预算 8 MiB（`max_log_scan_bytes`，最大 32 MiB），SCM 遍历默认 200 个任务/文件夹（`max_scan_jobs`，最大 1000）。还受账号/全局行数、字段长度、输出和总期限限制；文档单次最多 2 MiB，每次调用另有累计响应上限。
- `get_build_log` 支持正负 `skip/limit`：负 skip 从末尾定位，负 limit 向前取窗口，0 使用默认 100；尾部窗口不得超过账号行数预算，未完整扫描不会返回伪造的真正尾部或精确总行数。网关签名 cursor 绑定资产、账号、任务与具体构建，需重新扫描到逻辑行位置，与插件 cursor 不兼容；密钥轮换使旧游标失效。运行中未结束的末行在下次续读时会重读，避免遗漏追加内容。
- 日志搜索默认区分大小写，支持 `useRegex/ignoreCase/maxMatches/contextLines`，正则每行限时；截断长行或预算耗尽均标记不完整。构建日志中的业务秘密仍需 Jenkins 正确掩码。
- 测试报告缺失返回空报告；JUnit 未导出 `flakyFailures` 时明确不支持。历史 SCM 仅使用构建的 Git BuildData；当前任务 SCM 不能静态恢复任意动态 checkout。SCM 搜索权限不足、动态配置或预算耗尽会标记 `partial`。状态工具不编造未导出的管理监控和云能力。
- 输出为网关 JSON 文本，不保证与插件 Java 对象逐字段相同。当前验证为隔离 HTTP 契约与本地测试；真实 Jenkins 的版本/插件组合需另行联调，构建和 Replay 只可对明确获准的测试任务执行。
