# dsh-rea — 逆向分析

REA（[github.com/morluto/rea](https://github.com/morluto/rea)，npm 包 `rea-agents`，MIT 许可）的 DeepSeek Harness 插件。

## 它做什么

- **工具**：把 REA MCP 服务器（`rea mcp`）的完整工具表注册进 Agent 工具表，公开名为 `mcp__rea__<tool>`（与 Claude Code / Codex 同形）。工具的输入 schema 原样沿用，REA 新增/下线工具时会自动重新同步。
- **延迟加载**：207 个工具的 schema 标记为 `deferLoading`，**不进请求体**，只在模型真的要用某个工具时才加载。常驻开销从 194 KB（≈4.9 万 token）降到 1.4 KB（≈341 token），工具一个不少、照样能调。
- **检索入口**：`rea_catalog` 是一个几百字节的常驻工具，按关键词在 207 个工具里搜名字/描述——因为 schema 延迟了，模型没法直接从工具表里读它们，这个工具就是它的索引。无参调用列出全部 207 个**精确工具名**（约 6.9 KB），带关键词时给出命中项的一行描述。
- **技能**：把 REA 自带的 `reverse-engineer-anything` 技能及其 `references/` 参考文档安装到 `~/.dsh/skills/reverse-engineer-anything/`，按 REA 版本号打戳，版本没变就不重拷。
- **环境侧栏**：侧栏入口显示运行时、Java/JDK、Ghidra、JADX、Apktool、WABT、Kuna/Rizin 的实际状态；面板内可填写并保存所有绝对路径，Ghidra/JADX/Apktool/WABT 还提供按需准备按钮和进度。
- **就绪检查**：`rea_doctor` 运行逆向服务自己的 `mcp doctor --json`，报告 MCP 子进程能否启动、服务端状态与可用分析引擎。只读，不打开任何目标。
- **一屏状态**：`rea_status` 用一次调用说清"有没有打开目标、绑了哪个 provider、哪些引擎装好了、因此现在能做什么"。207 个工具里有 55 个依赖"当前文档"，在 headless 引擎下没有目标就会空转——先看一眼比撞一次墙便宜。
- **结果落盘**：单次结果超过 `maxResultChars`（默认 24 000 字符）时写入 `~/.dsh/rea-artifacts/<会话>/`，模型拿到开头摘要和路径，再用 `rea_read_artifact` 分页读。`binary_session` 这类 70 KB 的结果不再挤爆一轮对话。
- **变更留痕（1.3.0 起 fail-closed，1.4.0 补齐旁路）**：不再靠硬编码名单——已知只读首词之外的**新工具默认审计**。`gdb_console`、`rizin_debug_command`、`cutter_command`、`observe_native_calls`、`observe_web_execution` 这 5 个命令逃生口在 1.4.0 纳入审计；1.5.0 起 `guard` 覆盖全部 15 个插件自有工具，路径授权改为按**值形态**判定（不再依赖键名白名单）。上游 `destructiveHint` / `openWorldHint` 作为保守下限信号，不当权威分类器（207 个里 202 个 `readOnlyHint=false`）。**157 个只读工具**允许并发调用，并由 `maxConcurrentReadTools` 限流；真实装配共 **222 工具 + 6 路由**。
- **完整 schema 渐进展开（1.4.0）**：后台独立子进程缓存全部完整输入/输出 schema 与注解（约 3 MB 内存、零上下文开销）。`rea_catalog({tool, path, includeOutput})` 按 JSON Path 逐字段展开；165 KB 的 `compare_web_captures` 默认只给约 1 KB 轮廓。
- **结构化结果与工作流（1.4.0）**：每次调用把 `evidence_id` / 置信度 / 覆盖度 / provider 写进跨会话索引，用 `rea_query_results` 复用；`rea_batch_triage` 批量初筛、`rea_diff_hint` 粗配、`rea_fuzz_harness` 生成模板、`rea_run_playbook` 用可信脚本把多次往返压成一次调用。
- **静态对抗初筛**：`rea_triage(path)` 纯本地、不执行样本：整体与分块熵、PE/ELF/Mach-O 节区与入口/导入异常、13 类壳与混淆器签名、字符串与单字节 XOR 探测、可选 YARA，输出带证据的 packed / obfuscated / unpacked 判定与下一步建议。
- **证据出口**：`rea_export_report` 把 Evidence bundle 转成 Markdown 报告与 SARIF 2.1.0，覆盖度、未解未知清单、推断边界都写进产物，可归档或接 CI。
- **产物治理**：结果默认保留 7 天并有容量上限；`sensitiveArtifacts` 让完整结果只回摘要、不落盘；`rea_purge_artifacts` 手动清理。
- **分级提示**：反编译/重建类结果强制标注「推断，非源码」，写操作结果标注「已审计」。
- **版本更新**：侧栏可检查 GitHub 新版本并一键安装；下载走多层镜像，任一失效自动换下一个，按 Release 公布的 SHA-256 校验（可用 `pinnedSha256` 钉死摘要）。侧栏会列出每个镜像的成功/失败原因与当前安全策略。

## 为什么不合并工具

207 个平铺的工具名确实又多又杂，但**合并会改变模型看到的世界**：REA 的工具是按「一个工具一个职责 + 严格输入契约」设计的，合并成一个 `rea_run(tool, input)` 式的总入口意味着模型每次都要先猜对工具名和参数结构，而它现在是从 schema 里读到的。所以选择保留 207 个工具、用延迟加载解决体积——这是宿主的原生机制（`deferLoading` 一路通到 DeepSeek 的 `defer_loading` 字段），不是插件自己的 hack。

`rea_catalog` 的输出里，每一行**已经是**可以直接调用的 `mcp__rea__*` 全名；前缀只加一次。

## 运行时怎么放

`rea-agents` 6.7.0 连同完整依赖闭包（136 个包）打成一个 `vendor/rea-runtime.tgz`（28 MB，带 SHA-256 校验）。**首次启用时**解包到 `~/.dsh/rea-runtime/`，之后 MCP 子进程用宿主自己的 node 以绝对路径直接跑，调用时不经 npm/npx、不需要网络。

之所以用「压缩包 + 首次解包」而不是把 `node_modules` 原样放进插件：

- 插件目录从 124 MB 降到 28 MB；
- 解包位置在 DSH 主目录而不是工作区 —— 工作区沙箱被观测到会把外部写入的大目录回滚掉，那会让插件某天悄悄坏掉；
- 依赖闭包完整。REA 有大量**惰性 require**（`saxes`→`xmlchars`、`pino`→`pino-std-serializers`……），按「运行时实际 import 过谁」裁过一版，第一次调用就崩；按 `package.json` 依赖闭包裁，也漏。只有全量闭包能让 207 个工具都不坏。

**解包是原子的**：校验 → 解到同级 staging 目录 → 确认 `rea-agents/scripts/rea.mjs` 在 → 删除旧目录并改名。任何一步失败都保留上一版运行时，不会出现「解包崩了、207 个工具全没」的状态。

## 实测

1.0.3 时的一次 207 工具全量回归（走解包后的运行时）：

| 分类 | 数量 | 含义 |
| --- | --- | --- |
| 跑通 | 14 | 真出了结果（Go/Rust 元数据、.NET 清单、PE 资源等） |
| 参数校验拒绝 | 144 | 工具执行了，按契约拒绝空参数 |
| 无打开目标 | 27 | 工具执行了，报告「没有目标」 |
| 参数不合契约 | 5 | 同上 |
| 缺本机引擎 | 17 | 需要 Ghidra / Hopper / IDA / JADX / Kuna / Apktool |
| **缺依赖包** | **0** | 没有任何工具因为少包而坏 |

握手耗时：冷启动约 13 s，之后约 2.4 s（1.1.0 复测）。

## Native 引擎侧栏

插件本体不会携带 Ghidra，因此仍保持约 28 MB。侧栏会自动检查当前环境：

| 引擎 | 版本 | 准备方式 |
| --- | --- | --- |
| Ghidra | 12.1.4 | 侧栏一键下载（约 543 MiB），校验后解包到 `~/.dsh/rea-engines/ghidra/` |
| JADX | 0.7.1（headless MCP jar） | 侧栏一键下载 |
| Apktool | 3.0.3 | 侧栏下载 jar 并生成启动器（Windows 为 `.bat`，其他平台为可执行 shell 脚本） |
| WABT | 1.0.42 | **仅 Windows x64 有固定版本**；其他平台按钮会说明原因并只接受手填路径 |
| Kuna/Rizin | 用户提供 | 只接受绝对路径：项目没有统一的自动安装包 |
| IDA / Hopper / JEB | 商业授权 | 只接受路径 |

Java 探测会枚举 `JAVA_HOME`、各发行版的安装目录（`C:\Program Files\Java`、Eclipse Adoptium、Microsoft、Amazon Corretto、Zulu、BellSoft，macOS 的 `/Library/Java/JavaVirtualMachines`，Linux 的 `/usr/lib/jvm`），并用 `java -XshowSettings:properties` 反查 PATH 上那个 `java` 真正属于哪个 JDK。**只有带 `javac` 的完整 JDK 才算就绪**——Ghidra 不能在 JRE 上启动。

下载全部固定版本 + SHA-256；`.part` 落盘、校验通过才改名，失败不会留下截断的归档。Ghidra 解包成功后删除归档释放 543 MB；解包失败则保留归档，重试不必重新下载。

各引擎与 Java 的许可证和发行版通知归各自项目。

## 常驻开销实测

| 配置 | 常驻 schema | token / 每请求 |
| --- | --- | --- |
| `deferCatalog: false`（全量广告） | 194 KB | 48 560 |
| `deferCatalog: true`（默认） | 1.4 KB | **341** |

延迟的 207 个工具仍然可调，`rea_catalog` 可按关键词检索（`javascript` 命中 22 个，无参列出全部 207 个名字）。

## 配置（cordis.patch.yml 的 `config`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `schemaProfile` | `compact` | 主子进程广告的 input schema 档位。`full` 会让 207 个工具的 schema 约 652 KB，不进模型上下文但会放大注册表。1.4.0 起完整定义由后台独立探测缓存，不必改这里。 |
| `outputSchemaProfile` | `off` | 主子进程不广告 output schema；后台探测子进程用 `full` 取回完整输出 schema 供 `rea_catalog({includeOutput:true})` 按需查看。 |
| `catalogProbe` | `true` | 激活后在后台起一个短生命周期子进程，缓存全部完整输入/输出 schema 与安全注解（约 3 MB 内存，零上下文开销）。失败只降级为 compact 模式，不影响激活。 |
| `imageCapture` | `true` | 把 REA 返回的 image / 二进制 resource 块写入产物目录并返回路径，不再只给占位文本。 |
| `toolCallTimeoutMs` | `900000` | 单次调用超时。REA 首次起 Ghidra/Hopper 可能几分钟。取消会话时请求会被 `notifications/cancelled` 撤回，不用等满超时。 |
| `maxBufferBytes` | `10485760` | stdio 单条消息上限（REA 自己的下限就是 10485760，传更小会被抬回下限）。 |
| `logLevel` | `info` | 子进程日志级别。 |
| `deferCatalog` | `true` | 把 207 个 REA 工具的 schema 延迟加载（不进入请求体）。置 `false` 恢复成全部常驻广告——只在确实需要模型直接看见全部 schema 时才这么干，代价是每请求多约 4.8 万 token。 |
| `enabled` | `true` | 置 `false` 时不派生子进程、不注册工具。 |
| `maxResultChars` | `24000` | 单次工具结果的字符预算（4000–200000）。超出部分落盘，返回摘要 + 路径，用 `rea_read_artifact` 分页。 |
| `allowDeviceMutations` | `false` | 是否允许 4 个会删改设备的操作。1.3.0 起破坏性操作按名字推断（`uninstall`/`remove`/`delete`/`kill`/`wipe`/`overwrite`/`push`/`install`/`stop` + 设备名词），上游新增的同类工具也会自动被拦。 |
| `allowedTargets` | `[]` | 会话级授权根目录。非空时，工具参数里**任何字符串值**（含数组与一层嵌套）只要看起来是绝对路径就必须落在这些根下，否则拒绝；键名白名单已在 1.5.0 移除。空 = 不限制。注意这是字符串级授权，不解析符号链接/junction/8.3 短名，不是 OS 隔离。 |
| `sensitiveArtifacts` | `false` | 开启后超大结果只返回摘要，**完整内容不写磁盘**（`rea_read_artifact` 无法分页，这是刻意的取舍）。 |
| `maxConcurrentReadTools` | `6` | 只读工具并发上限（1–32）。REA 的 stdout 是单条分帧通道，无界并发会撑爆响应缓冲。 |
| `resultIndexMaxBytes` | `8388608` | 跨会话 `results.jsonl` 容量上限；超出按最旧滚动，写入串行化并带 `prevHash` 哈希链。 |
| `artifactRetentionDays` | `7` | 旧会话产物保留天数（1–365），同时用于结果索引的过期清理。 |
| `artifactMaxBytes` | `268435456` | 旧会话产物总容量上限（字节），超出按最旧删除。 |
| `triageMaxBytes` | `67108864` | `rea_triage` 单次读取上限（1 MB–512 MB），超出部分截断并标注。 |
| `yaraRulesDir` | 空 | 可选，指向含 `.yar`/`.yara` 的目录；未安装 `yara` 或未配置时报告跳过，不算失败。 |
| `pinnedSha256` | 空 | 64 位十六进制摘要。设置后，Release 公布的摘要与它不符就拒绝安装（下载前），下载字节也按它校验。 |
| `maxBackups` | `2` | 自更新保留的 `.bak-*` 份数（0–10），避免每次更新累积 30 MB 备份。 |
| `updateMirrors` | `[]` | 额外追加的下载镜像前缀，排在自带镜像之后，不会替换官方直连。 |
| `trustedManifestKey` | 空 | minisign 公钥文本。设置后**只接受验签通过的 manifest 来源**（不再把 GitHub Release API 当兜底），验签失败或无 `.minisig` 时检查更新直接失败，绝不静默降级；侧栏显示实际生效的信任级别。配了公钥就必须发布 `update.json.minisig`。 |
| `playbookDir` | `~/.dsh/rea-playbooks` | 可信 playbook 脚本目录，只接受简单 `.mjs` 文件名。 |
| `playbookTimeoutMs` | `120000` | 单个 playbook 的墙钟上限（1s–600s）。 |
| `playbookMaxCalls` | `200` | 单个 playbook 允许发起的 REA 调用次数上限（1–2000）。 |
| `batchTriageLimit` | `50` | `rea_batch_triage` 单次最多处理的文件数（1–500）。 |

### 1.5.0 新增

| 项 | 作用 |
| --- | --- |
| `rea_describe_artifact` | 用文本描述已落盘的图像/二进制证据：mime、字节数、SHA-256、尺寸、来源工具、与采集时摘要是否一致；二进制本身不进上下文 |
| 路径授权 | 按值形态判定，覆盖 `output_directory` / `apk_path` / `executable_path` 等 11 个此前漏掉的真实路径参数 |
| 签名门禁 | `trustedManifestKey` 生效时签名 manifest 为唯一可信源，验签失败 fail-closed；`trustPolicy` 三态显示实际级别 |
| 结果索引 | 串行写、容量/保留期滚动、查询返回截断标记、每行 `prevHash` 哈希链 |
| 元数据一致性 | probe 与 live 子进程版本戳绑定，不一致时 `rea_catalog` 明确警告；`includeOutput` 回退 compact |
| 发布门禁 | `npm run host-matrix` 输出 `dist/host-matrix.json` 并校验文档里的工具数/分类数，数字漂移直接 FAIL |
| 并发证据 | `npm run concurrency` 对真实子进程做 30 次并发对比（无闸 vs 限流 6） |
| 报告隔离 | SARIF `message.text` 包裹 `<untrusted-evidence>`，下游 CI 渲染不再直接吃样本文本 |

### 1.4.0 新增工具

| 工具 | 作用 |
| --- | --- |
| `rea_query_results` | 查跨会话结果索引（工具、时间、Evidence ID、置信度、覆盖度、provider），避免重复分析 |
| `rea_batch_triage` | 对一个目录做非递归批量静态初筛，输出计数与报告 |
| `rea_diff_hint` | 两个样本的粗配（熵/节区/采样字符串），明确声明不是结构 diff |
| `rea_fuzz_harness` | 从崩溃描述生成 libFuzzer/AFL++ 模板，只生成文本、不编译不执行 |
| `rea_run_playbook` | 运行 `playbookDir` 里的可信 `.mjs` 脚本，把多次往返压成一次调用 |
| `rea_protocol_analyze` | tshark（TLS keylog / 流重组）与 protoc `decode_raw` 适配层，缺二进制时明确报告 |
| `rea_windows_tools` | 只读探测 cdb / TTD / wpr / logman / pdbcopy，不启动调试器 |

`rea_catalog` 现在支持 `path`（按 JSON Path 展开一个字段）、`includeOutput`、`includeAnnotations`。最大的 `compare_web_captures` 完整输入 schema 有 165 KB，默认只给约 1 KB 的轮廓，需要细节时逐字段展开。

**Playbook 是受信任代码，不是沙箱**：脚本必须是事先放进目录的文件（不接受对话里的内联代码），在子进程里跑，每次 `rea.call` 都回到父进程过同一套 guard、工具白名单、调用次数与超时限制。它能防止误操作和失控循环，不能防恶意脚本。

## 版本更新

侧栏顶部的「版本更新」会查 `api.github.com` 的最新 Release，与本地版本比较；有新版时显示版本号、来源与 Release 链接，点「下载并安装」后：

1. **元数据**先取 GitHub REST API；取不到时退回仓库里的 `update.json`（经 jsDelivr / raw 两个 CDN）。任一层可用就能知道最新版本与归档摘要。
2. **字节**按顺序尝试 GitHub 直连 → `ghproxy.net` → `gh-proxy.com` → `ghfast.top` → `hub.gitmirror.com` → `github.moeyy.xyz`。某个镜像超时、限流或返回错误页，就换下一个；同一个镜像内部还会重试一次。
3. 下载完成后**先校验 SHA-256**（取自 Release 说明里的 `sha256:` 行或 `update.json`），不匹配直接删除并换镜像。
4. 校验通过才解包、核对包内 `package.json` 的版本，然后把当前插件目录改名为 `.bak-<时间戳>`，把新目录换进去；换入失败会把旧目录改回来。
5. 安装完成后提示重启会话——新代码在下次加载时生效。

镜像只被当作传输通道，完整性由摘要决定；但摘要与归档**同源**（都来自同一个 GitHub 账号），账号被篡改时校验形同虚设。需要独立保证时设置 `pinnedSha256`：它来自本地配置，与 Release 公布的摘要不一致会在下载前直接拒绝。1.5.0 修正了签名源的回退顺序：只要配置了 `trustedManifestKey`，GitHub Release API 就**不再参与** `asset` 决策，验签失败（含 minisign 未安装）会让检查更新直接报错而不是退回未签名来源；安装前还有第二道闸，若 `asset` 来自未签名来源也会拒绝下载。侧栏「版本更新」板块显示**实际生效**的信任级别（无独立校验 / 钉死摘要 / 签名验签 / 两者）。侧栏会逐条显示每个镜像的成功或失败原因、当前钉死的摘要、保留的备份数，以及「安全策略」板块（授权范围 / 设备写操作 / 敏感产物 / 保留期）。

**发布新版本时的顺序**：`npm test` → `npm run host-matrix`（三种宿主模式真实装配 + 文档数字校验）→ `npm run concurrency`（并发压测报告）→ `npm run pack` → `npm run manifest`（签名发布时设 `DSH_REA_MINISIGN_KEY=<无口令私钥>` 并把 `update.json.minisig` 作为 Release 资产）→ 发 Release（说明里带上 `sha256:` 行）→ 提交 `update.json`。少写一步，只用镜像的用户就会看到旧的“最新版本”。`npm run triage-baseline` 可随时输出初筛的合成校准矩阵；传 `--corpus /abs/path`（下分 `packed/`、`clean/`）可得到有标签样本的识别率与误报率。

## 代理

下载与更新检查会读取 `HTTPS_PROXY` / `HTTP_PROXY`（含 `NO_PROXY`），通过 CONNECT 隧道走代理。Node 自己不认识这些变量，而很多本机代理只设置了系统代理，所以这一层是必要的；`localhost` / `127.0.0.1` 永远直连。

## 安全边界

侧栏的 POST 路由可以改动引擎路径、可以触发几百 MB 的下载，因此按「有副作用的接口」对待：

- 方法必须匹配，请求体必须是 `application/json`——跨站表单和 `text/plain` 的 fetch 都无法在不触发预检的情况下做到这一点；
- 浏览器带上 `Origin` 时必须与 `Host` 一致，`Sec-Fetch-Site` 必须是 `same-origin` 或 `none`；
- 错误返回真实的 HTTP 状态码（400/403/405/413/415/500），而不是 200 + `ok:false`；
- 路径必须是绝对路径。

最后一条不只是形式问题：`REA_APKTOOL_COMMAND` 是 REA 会实际执行的命令，跨站写它等于把一次工具调用变成执行磁盘上任意可执行文件。

子进程也不再继承宿主的完整环境变量：只放行 `PATH`、`HOME`、`TEMP`、代理和证书相关变量，加上 REA 文档中的 `REA_*` / `HOPPER_*` 引擎变量。宿主的 API key、会话 token 不会进入第三方分析进程。子进程的工作目录固定为 `~/.dsh/rea-workspace`，分析过程不会弄脏被分析的项目。

## 代码结构

```
index.js            插件入口：连接、注册、监管、路由装配
lib/paths.js        DSH 主目录下所有落点
lib/download.js     下载（超时/重试/重定向上限/原子落盘）与解包
lib/mcp-client.js   stdio JSON-RPC 客户端 + 行分帧
lib/runtime.js      运行时校验、原子解包、技能安装
lib/engines.js      Java/Ghidra/JADX/Apktool/WABT 探测与安装
lib/config.js       配置归一化、子进程环境
lib/tools.js        工具桥、rea_catalog、rea_doctor、rea_status、分级提示
lib/registry.js     工具表增量同步（失败只影响单个工具）
lib/routes.js       HTTP 路由与来源校验
lib/artifacts.js    结果落盘/分页、fail-closed 变更分类、会话范围、保留期
lib/triage.js       纯本地静态对抗初筛（熵/节区/签名/字符串/XOR/YARA）
lib/export.js       Evidence bundle → Markdown / SARIF 2.1.0
lib/analysis-tools.js  rea_triage / rea_export_report / rea_purge_artifacts
lib/schema-cache.js  完整 schema 后台探测缓存 + JSON Path 渐进展开
lib/result-index.js  跨会话结果索引 + structuredContent 快照
lib/workflow-tools.js 结果查询 / 语料初筛 / 粗配 / fuzz 模板 / playbook 工具
lib/playbook.js     可信脚本子进程执行器（IPC 代理 + 调用上限）
lib/playbook-worker.mjs  playbook 子进程入口
lib/external-adapters.js tshark/protoc 与 Windows 调试器能力探测
lib/manifest-signature.js update.json 的 minisign 签名与验签
lib/update.js       版本检查、多镜像下载、钉死摘要、目录替换
scripts/update-manifest.mjs  生成 update.json（发布用，可选签名）
scripts/host-matrix.mjs      宿主兼容性发布门禁
scripts/triage-baseline.mjs  初筛校准矩阵（合成 / 有标签语料）
```

## 测试

```bash
npm test          # node --test，152 个用例
npm run host-matrix       # 真实子进程，三种宿主模式的发布门禁 + 文档数字校验
npm run concurrency       # 真实子进程并发压测（无闸 vs 限流）
npm run triage-baseline   # 初筛合成/有标签语料校准
```

覆盖：公开名映射、行分帧、配置归一化与子进程环境、工具表增量同步、路由来源校验、结果落盘与分页边界、版本比较与镜像顺序；1.3.0 新增熵与 PE 解析、壳签名、XOR 探测、Markdown/SARIF 出口、fail-closed 分类与会话范围、保留期与敏感模式、钉死摘要端到端、分级提示；1.4.0 新增完整 schema 轮廓与路径展开、结果快照与索引查询、命令逃生口与自有工具 guard、只读并发、图像落盘、不可信数据包裹、DEX/WASM/APK 识别与反分析特征、宿主矩阵、可信 playbook 子进程、SARIF URI/执行状态修正、清单签名验签；1.5.0 新增值形态路径授权（11 个漏网路径键）、签名门禁 fail-closed 与信任级别、结果索引哈希链/容量/截断标记、live/probe 版本戳、二进制证据文本化、只读并发限流、SARIF 不可信文本包裹、文档数字门禁。

## 安装

把 `dsh-rea-<version>.tgz` 解压到稳定目录（如 `~/.dsh/plugins/dsh-rea`），通过 Plugin Manager 的 `install_bundle` 选择该目录，或直接把本包加进 profile 的 `dependencies` 与 `bundles`：

```
"dsh-rea": "link:<包目录的绝对路径>"
```

安装后重启会话即可看到 `mcp__rea__*` 工具与 `reverse-engineer-anything` 技能。

## 发布包

```bash
npm test && npm run pack   # → dist/dsh-rea-<version>.tgz（package/ 为根）
```

包内含 `index.js`、`client.js`、`lib/*.js` 与 `lib/*.mjs`、`cordis.patch.yml`、`locale/`、`icon.svg`、`README.md`、`LICENSE`，以及 `vendor/rea-runtime.tgz`（28 MB，136 个包的完整依赖闭包）与它的 SHA-256。`test/` 与 `scripts/` 不进发布包。

源码仓库：<https://github.com/xiaobaga281/dsh-rea>

## 已知边界

- REA 的 image 块与二进制 resource 块会落盘到产物目录并返回路径，供带外复核；不直接转成模型可看的图片块（宿主是否支持多模态块未做假设）。含文本的 resource 仍原样并入结果。
- 样本里的字符串、反编译文本、崩溃描述都是**不可信数据**：默认不回字符串原文，`detail`/报告里会包裹、转义、截断并注明「不得当作指令」。
- `rea_triage` 只识别 PE/ELF/Mach-O 的结构，DEX/APK/WASM 只识别容器不解析内部；加壳判定是启发式，合成校准集的识别率不代表真实壳样本，需带标签语料实测。
- `rea_protocol_analyze` 与 `rea_windows_tools` 是适配层：外部二进制缺失时明确报缺，不假装能力存在；完整 cdb 断点脚本、TTD 回放、符号执行 / 仿真脱壳 / BSim 相似度 / IDA 接入仍属后续引擎工作。
- 侧栏准备 Ghidra 需要网络和约 543 MiB 下载空间；解包后还会占用 Ghidra 本身的磁盘空间。
- 首次启用需要 `tar`（Windows 10+ 与各受支持平台自带）；Linux 上解 zip 还需要 `unzip`，缺失时错误信息会直接说明。
- WABT 只有 Windows x64 的固定构建；其他平台需要手填 `REA_WABT_BIN_DIRECTORY`。
