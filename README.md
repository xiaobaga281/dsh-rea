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
- **变更留痕（1.3.0 起 fail-closed）**：不再靠硬编码名单——已知只读首词之外的**新工具默认审计**，名字含明确写动词的也会审计（补上了原先漏掉的 `instrument_with_frida`、`execute_rizin_command`）。真实工具面上 207 个里 41 个审计、162 个只读。改设备/删除/覆盖的 4 个操作默认关闭，需要 `allowDeviceMutations`。
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
| `schemaProfile` | `compact` | REA 的 input schema 广告档位。`full` 下 207 个工具的 schema 约 3 MB（≈79 万 token），会挤爆任何上下文预算。 |
| `outputSchemaProfile` | `off` | 不广告 output schema，省下大量 token；REA 内部仍按完整契约校验返回。 |
| `toolCallTimeoutMs` | `900000` | 单次调用超时。REA 首次起 Ghidra/Hopper 可能几分钟。取消会话时请求会被 `notifications/cancelled` 撤回，不用等满超时。 |
| `maxBufferBytes` | `10485760` | stdio 单条消息上限（REA 自己的下限就是 10485760，传更小会被抬回下限）。 |
| `logLevel` | `info` | 子进程日志级别。 |
| `deferCatalog` | `true` | 把 207 个 REA 工具的 schema 延迟加载（不进入请求体）。置 `false` 恢复成全部常驻广告——只在确实需要模型直接看见全部 schema 时才这么干，代价是每请求多约 4.8 万 token。 |
| `enabled` | `true` | 置 `false` 时不派生子进程、不注册工具。 |
| `maxResultChars` | `24000` | 单次工具结果的字符预算（4000–200000）。超出部分落盘，返回摘要 + 路径，用 `rea_read_artifact` 分页。 |
| `allowDeviceMutations` | `false` | 是否允许 4 个会删改设备的操作。1.3.0 起破坏性操作按名字推断（`uninstall`/`remove`/`delete`/`kill`/`wipe`/`overwrite`/`push`/`install`/`stop` + 设备名词），上游新增的同类工具也会自动被拦。 |
| `allowedTargets` | `[]` | 会话级授权根目录。非空时，工具参数里任何绝对路径都必须落在这些根下，否则拒绝。空 = 不限制。 |
| `sensitiveArtifacts` | `false` | 开启后超大结果只返回摘要，**完整内容不写磁盘**（`rea_read_artifact` 无法分页，这是刻意的取舍）。 |
| `artifactRetentionDays` | `7` | 旧会话产物保留天数（1–365），激活时自动清理。 |
| `artifactMaxBytes` | `268435456` | 旧会话产物总容量上限（字节），超出按最旧删除。 |
| `triageMaxBytes` | `67108864` | `rea_triage` 单次读取上限（1 MB–512 MB），超出部分截断并标注。 |
| `yaraRulesDir` | 空 | 可选，指向含 `.yar`/`.yara` 的目录；未安装 `yara` 或未配置时报告跳过，不算失败。 |
| `pinnedSha256` | 空 | 64 位十六进制摘要。设置后，Release 公布的摘要与它不符就拒绝安装（下载前），下载字节也按它校验。 |
| `maxBackups` | `2` | 自更新保留的 `.bak-*` 份数（0–10），避免每次更新累积 30 MB 备份。 |
| `updateMirrors` | `[]` | 额外追加的下载镜像前缀，排在自带镜像之后，不会替换官方直连。 |

## 版本更新

侧栏顶部的「版本更新」会查 `api.github.com` 的最新 Release，与本地版本比较；有新版时显示版本号、来源与 Release 链接，点「下载并安装」后：

1. **元数据**先取 GitHub REST API；取不到时退回仓库里的 `update.json`（经 jsDelivr / raw 两个 CDN）。任一层可用就能知道最新版本与归档摘要。
2. **字节**按顺序尝试 GitHub 直连 → `ghproxy.net` → `gh-proxy.com` → `ghfast.top` → `hub.gitmirror.com` → `github.moeyy.xyz`。某个镜像超时、限流或返回错误页，就换下一个；同一个镜像内部还会重试一次。
3. 下载完成后**先校验 SHA-256**（取自 Release 说明里的 `sha256:` 行或 `update.json`），不匹配直接删除并换镜像。
4. 校验通过才解包、核对包内 `package.json` 的版本，然后把当前插件目录改名为 `.bak-<时间戳>`，把新目录换进去；换入失败会把旧目录改回来。
5. 安装完成后提示重启会话——新代码在下次加载时生效。

镜像只被当作传输通道，完整性由摘要决定；但摘要与归档**同源**（都来自同一个 GitHub 账号），账号被篡改时校验形同虚设。需要独立保证时设置 `pinnedSha256`：它来自本地配置，与 Release 公布的摘要不一致会在下载前直接拒绝。侧栏会逐条显示每个镜像的成功或失败原因、当前钉死的摘要、保留的备份数，以及「安全策略」板块（授权范围 / 设备写操作 / 敏感产物 / 保留期）。

**发布新版本时的顺序**：`npm test` → `npm run pack` → `npm run manifest`（用实际打包产物重写 `update.json` 的版本、大小与摘要）→ 发 Release（说明里带上 `sha256:` 行）→ 提交 `update.json`。少写一步，只用镜像的用户就会看到旧的“最新版本”。

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
lib/update.js       版本检查、多镜像下载、钉死摘要、目录替换
scripts/update-manifest.mjs  生成 update.json（发布用）
```

## 测试

```bash
npm test          # node --test，118 个用例
```

覆盖：公开名映射、行分帧、配置归一化与子进程环境、工具表增量同步、路由来源校验、结果落盘与分页边界、版本比较与镜像顺序；1.3.0 新增熵与 PE 解析、壳签名、XOR 探测、Markdown/SARIF 出口、fail-closed 分类与会话范围、保留期与敏感模式、钉死摘要端到端（含 7 个真实安装用例）、分级提示。

## 安装

把 `dsh-rea-1.3.0.tgz` 解压到稳定目录（如 `~/.dsh/plugins/dsh-rea`），通过 Plugin Manager 的 `install_bundle` 选择该目录，或直接把本包加进 profile 的 `dependencies` 与 `bundles`：

```
"dsh-rea": "link:<包目录的绝对路径>"
```

安装后重启会话即可看到 `mcp__rea__*` 工具与 `reverse-engineer-anything` 技能。

## 发布包

```bash
npm test && npm run pack   # → dist/dsh-rea-1.3.0.tgz（package/ 为根）
```

包内含 `index.js`、`client.js`、`lib/`、`cordis.patch.yml`、`locale/`、`icon.svg`、`README.md`、`LICENSE`，以及 `vendor/rea-runtime.tgz`（28 MB，136 个包的完整依赖闭包）与它的 SHA-256。`test/` 不进发布包。

源码仓库：<https://github.com/xiaobaga281/dsh-rea>

## 已知边界

- REA 的结果以文本/JSON 为主；图片块（例如截图）以明确占位文本返回，不静默丢弃，也不转成模型可看的图片。嵌入的 resource 块如果有文本内容会被原样并入结果。
- 侧栏准备 Ghidra 需要网络和约 543 MiB 下载空间；解包后还会占用 Ghidra 本身的磁盘空间。
- 首次启用需要 `tar`（Windows 10+ 与各受支持平台自带）；Linux 上解 zip 还需要 `unzip`，缺失时错误信息会直接说明。
- WABT 只有 Windows x64 的固定构建；其他平台需要手填 `REA_WABT_BIN_DIRECTORY`。
