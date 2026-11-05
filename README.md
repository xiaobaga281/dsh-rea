# dsh-rea — 逆向分析

REA（[github.com/morluto/rea](https://github.com/morluto/rea)，npm 包 `rea-agents`，MIT 许可）的 DeepSeek Harness 插件。

## 免责声明

**本项目仅供学习与研究使用。使用者如将其用于其他用途，须自行承担全部相关责任；作者不承担任何责任。**

- 本项目提供的是一套**逆向分析方法与工具编排**，目的是学习二进制分析、样本分析与对抗测试的原理。它不针对任何特定的第三方软件，也不提供破解许可、规避技术保护措施或绕过授权的指引。
- **使用者须自行确保使用行为合法合规**，包括但不限于遵守所在地法律法规、软件许可协议与最终用户协议、数据与隐私保护规定。未经授权分析他人软件、提取或传播他人数据、规避技术保护措施等行为，可能构成违法或侵权。
- **使用者因使用、修改、分发本项目（含衍生作品）所产生的一切后果与责任，由使用者自行承担。作者不承担任何责任**，包括但不限于直接或间接损失、数据丢失、法律责任及第三方索赔。
- 本项目按**「现状」（AS IS）**提供，不附带任何明示或暗示的担保，包括适销性、特定用途适用性与不侵权担保。
- 如果你不同意上述任何一条，请立即停止使用并删除本项目及其全部副本。

> **版本说明**：本声明自 **1.7.1** 起写入 README，并随该版本的发布包一并分发。**1.7.1 只包含这段声明与版本号变更，没有功能改动**；1.7.0 及更早版本在功能上相同，但发布包内不含这段显式声明。凡从本仓库或官方 Release 获取 1.7.1 及之后版本，即视为已阅读并知悉上述声明。

## 它做什么

- **工具**：把 REA MCP 服务器（`rea mcp`）的完整工具表注册进 Agent 工具表，公开名为 `mcp__rea__<tool>`（与 Claude Code / Codex 同形）。工具的输入 schema 原样沿用，REA 新增/下线工具时会自动重新同步。
- **延迟加载**：207 个工具的 schema 标记为 `deferLoading`，**不进请求体**，只在模型真的要用某个工具时才加载。常驻开销从 194 KB（≈4.9 万 token）降到 1.4 KB（≈341 token），工具一个不少、照样能调。
- **检索入口**：`rea_catalog` 是一个几百字节的常驻工具，按关键词在 207 个工具里搜名字/描述——因为 schema 延迟了，模型没法直接从工具表里读它们，这个工具就是它的索引。无参调用列出全部 207 个**精确工具名**（约 6.9 KB），带关键词时给出命中项的一行描述。
- **技能**：把 REA 自带的 `reverse-engineer-anything` 技能及其 `references/` 参考文档安装到 `~/.dsh/skills/reverse-engineer-anything/`，按 REA 版本号打戳，版本没变就不重拷。
- **环境侧栏**：侧栏入口显示运行时、Java/JDK、Ghidra、JADX、Apktool、WABT、Kuna/Rizin 的实际状态；面板内可填写并保存所有绝对路径，Ghidra/JADX/Apktool/WABT 还提供按需准备按钮和进度。
- **就绪检查**：`rea_doctor` 运行逆向服务自己的 `mcp doctor --json`，报告 MCP 子进程能否启动、服务端状态与可用分析引擎。只读，不打开任何目标。
- **一屏状态**：`rea_status` 用一次调用说清"有没有打开目标、绑了哪个 provider、哪些引擎装好了、因此现在能做什么"。207 个工具里有 55 个依赖"当前文档"，在 headless 引擎下没有目标就会空转——先看一眼比撞一次墙便宜。
- **结果落盘**：单次结果超过 `maxResultChars`（默认 24 000 字符）时写入 `~/.dsh/rea-artifacts/<会话>/`，模型拿到开头摘要和路径，再用 `rea_read_artifact` 分页读。`binary_session` 这类 70 KB 的结果不再挤爆一轮对话。
- **变更留痕（1.3.0 起 fail-closed，1.4.0 补齐旁路）**：不再靠硬编码名单——已知只读首词之外的**新工具默认审计**。`gdb_console`、`rizin_debug_command`、`cutter_command`、`observe_native_calls`、`observe_web_execution` 这 5 个命令逃生口在 1.4.0 纳入审计；1.5.0 起 `guard` 覆盖全部 15 个插件自有工具，路径授权改为按**值形态**判定（不再依赖键名白名单）。上游 `destructiveHint` / `openWorldHint` 作为保守下限信号，不当权威分类器（207 个里 202 个 `readOnlyHint=false`）。**157 个只读工具**允许并发调用，并由 `maxConcurrentReadTools` 限流；真实装配共 **227 工具 + 6 路由**。
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
| `networkEgressPolicy` | `warn` | 对上游标了 `openWorldHint`/`destructiveHint` 的 108 个工具的策略：`allow` 不干预、`warn` 记录审计、`deny` 直接拒绝。用于分析者侧的外联暴露控制，默认不破坏正常调用。 |
| `trustedManifestKey` | 空 | minisign 公钥文本。设置后**只接受验签通过的 manifest 来源**（不再把 GitHub Release API 当兜底），验签失败或无 `.minisig` 时检查更新直接失败，绝不静默降级；侧栏显示实际生效的信任级别。配了公钥就必须发布 `update.json.minisig`。 |
| `playbookDir` | `~/.dsh/rea-playbooks` | 可信 playbook 脚本目录，只接受简单 `.mjs` 文件名。 |
| `playbookTimeoutMs` | `120000` | 单个 playbook 的墙钟上限（1s–600s）。 |
| `playbookMaxCalls` | `200` | 单个 playbook 允许发起的 REA 调用次数上限（1–2000）。 |
| `batchTriageLimit` | `50` | `rea_batch_triage` 单次最多处理的文件数（1–500）。 |

### 1.8.4 只罚漏报的评分，看不见「满嘴胡话」

1.8.3 收尾时留了一句：下一步做 D9 之前，得先给评分加精确率，因为九维评分**只罚漏报，不罚乱报**。这一轮补上了，D9 也真的把那个缺陷照了出来。

#### 第十个维度：precision

评分逻辑从 CLI 脚本抽成 `scripts/duel/score.mjs`——纯函数，11 个单测，不再靠跑 90 秒的对抗去推断规则。

```
extra     = max(0, noise - D0基线 - 3)
precision = 1 / (1 + extra / 8)
```

- **基线来自 D0**：控制代是明文、无保护，它产生的 8 条噪声（域名、pdb 片段、UA）就是"良性闲聊"的天花板，不是手写的期望表。
- **容差 3**：控制代本身会波动，解码通道也会合理多出一两条（URL 顺带出 host、email 顺带出域名）。
- **权重 0.12，其余九维 ×0.88**：零额外噪声的代际分数一分不变，新维度不能悄悄改写历史序列。

#### 继续对抗：D9 诱饵代

D8 把信息藏起来；D9 反过来——**所有东西都可恢复，但假货比真货多**：

- 12 条明文诱饵 IoC（3 URL / 3 email / 3 IP / 3 域名），格式全部合法，一条都不在真值集里；
- 第二张哈希表，用 CRC32 算的 10 个「字典里存在、样本从不调用」的 API；
- 其余保持 D6 的可达结构（ROR13 真表、TLS 回调、24 项派发表）。

结果：召回全满（endpoint 4/4、api 9/9、behaviour 6/6），**precision 42.1%**，总分 91.9%。同样一份报告，旧的九维评分会给它 100%。

#### D9 照出的三处真实缺陷

| 缺陷 | 现象 | 改法 |
| --- | --- | --- |
| **明文诱饵被标成 "confirmed"** | `url (3 confirmed, 4 recovered)`：3 条 confirmed 全是诱饵，真正从配置解码出来的 4 条反而挂着 "verify manually"。风险判断正好颠倒 | 改为 `observed in plaintext` / `decoded`；每条明文加 `— unverified`；报告明说「明文可见不是确认，静态提取分不清活跃 C2、投放诱饵和死字符串」 |
| **高熵区的乱码被当成 email** | `J@nC.NDH`、`ID@qo.HIplXO`、`bido@ihl.xml` 每一代都被报成 email IoC | email 规则加 TLD 白名单，域名部分必须小写。真实地址一个没删（`analytics@orbit-app.example` 仍在），每代噪声 9 → 8 |
| **混合算法被说成一个算法** | `19 names matched, and ror13 fits those`——19 个名字实际横跨 ror13 与 crc32 两张表 | 多算法时改成「按算法分组，至少一组是诱饵」；`structure:` 行补 `mixed algorithms: likely separate or decoy tables, names unverified` |

#### 结果

| 代际 | endpoint | indicator | api | behav | plan | verify | prec | score |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D0–D4 | 5/5 | 6/6 | 9/9 | 6/6 | – | – | 100% | 100% |
| D5 | 4/4 | 5/5 | 9/9 | 6/6 | yes | – | 100% | 100% |
| D6 | 4/4 | 5/5 | 9/9 | 6/6 | yes | **NO** | 100% | 89.0% |
| D7 | 4/4 | 5/5 | 9/9 | 6/6 | yes | – | 100% | 100% |
| D8 | 4/4 | 5/5 | **1/9** | **4/6** | yes | – | 100% | 82.5% |
| D9 | 4/4 | 5/5 | 9/9 | 6/6 | yes | – | **42.1%** | 91.9% |

十代均值 **95.9%**，weakest D8 82.5%，precision floor 42.1%，honesty failures 0。

#### 为什么 D9 不是最弱，以及为什么这不矛盾

D9（91.9%）高于 D8（82.5%）。D8 缺的是 `api`+`behaviour`（合计 0.28 权重）——认不出 API 是根本性的；D9 缺的是判断力（0.12 权重）——把诱饵当真很危险，但它确实看见了那些字节。

加权总分把「能力」和「判断力」混成一个数，这是加权评分的固有局限。所以 `precision floor` **单列**报告，不靠总分传达：一个「满嘴胡话但全都提到」的工具，不该因为总分更高而看起来更好。

#### 遗留边界

- **D8 的盐仍不可达**：确认过工具输出里从未出现 `salt=0x...`，9 个 API 名没有任何静态方法能恢复。`api 1/9` 是能力缺口，不是评分缺陷。
- **API 诱饵没进加权分数**：D0 的导入表定义了 API 名，哈希代际没有同源基线，强行合并会引入不可比的基线。改用「报告诚实度 + 10 个回归测试」覆盖，precision 只衡量 IoC 噪声。
- **verify 仍是 `n/a`**：确认 REA 在启动 JVM 前会显式清空 `JAVA_TOOL_OPTIONS`/`_JAVA_OPTIONS`/`JDK_JAVA_OPTIONS` 并拒绝 `-Dos.*` 注入，所以不改第三方打包产物就无法塞入 `-Dapplication.tempdir`。健康账本继续按实际情况降级，而不是伪造一次成功。

### 1.8.3 引擎健康账本、评分自证，以及面板上那五个没有开关的设置

这一轮由三个问题推动：面板里的安全策略只有状态没有开关、引擎「就绪」但一跑就死、对抗评分把防守方自己封死的东西算成分析员的漏检。

#### 面板：五个设置从「只能看」变成「能改」

之前的五行安全策略读的是宿主配置行，插件没有写它的权限，于是面板只能显示「设备写操作 关闭」——**开关存在，但没接到任何东西上**。

现在插件自己拥有一份 `~/.dsh/rea-engines/policy.json`：

- 只接受五个字段，未知字段直接报错（打错一个字母却「保存成功」，比报错更危险）；
- 逐字段校验：路径必须是绝对路径、保留天数 1–365、外联策略只能是 `allow|warn|deny`；
- **原地生效**：`guardTool` 闭包读的是同一个 config 对象，所以保存后下一次工具调用就开始执行新策略，不需要重启子进程（重启会杀掉正在跑的反编译）；
- 写入走临时文件 + rename，避免半截 JSON 导致策略静默回落到「不限制」；
- 优先级：面板 > 配置行，因为面板是人刚做过的、看得见的动作。

顺带修掉三个界面缺陷：

| 现象 | 原因 | 改法 |
| --- | --- | --- |
| 打开「设备写操作」后绿灯灭了 | 用琥珀色表示「已放宽」，而琥珀色变量在该主题下没定义，圆点直接消失 | 统一语义：**绿＝开/已配置，灰＝关**；标签列固定 145px，开关与其它控件左对齐 |
| 授权目标范围是个输入框 | 最初只能手打绝对路径 | 换成文件夹选择器（`/rea/fs/list`，只返回目录名，不读文件内容），失败时可退回手填 |
| 外联策略是原生下拉框 | `<select>` 用系统控件渲染，在深色面板里像别的程序的表单 | 换成三段式分段控件，与其它控件同一套样式 |

#### 「就绪」是一个断言，得有证据

面板说 Ghidra 就绪，实际每次分析都死在：

```
java.io.IOException: Failed to create directory: ...\rea-ghidra-<id>\tmp\<user>-ghidra
```

用 REA 自带 CLI（`rea decompile <file> <addr>`）复现同样的失败——**不是本插件的集成问题**：REA 在 Windows 上用私有 DACL 建运行目录，JVM 无法在其中创建 Ghidra 需要的 `<user>-ghidra` 临时目录。

修补上游需要改三份被打包的产物（`dist/ghidra`、`dist/cli-runtime`、`dist/mcp`），升级即失效，所以没有这么做。改的是**断言本身**：

- 新增 `lib/engine-health.js`：工具层从错误信封里取出 `provider_id`，把失败压成一行原因（`jvm-scratch-denied` / `jdk` / `timeout` / `native-unsupported`）并记账；
- `providerReadiness()` 合并账本：本次会话里失败过的 provider 一律**不再声称就绪**，原因写明「上游 Windows 限制；不是 JDK 版本或安装问题」；
- 修掉一个让探针活过引擎死亡的漏洞：`inspect_address_context` 不在 `PROVIDER_OF_CONFIRM` 里，TLS/派发表步骤从来没被打上 provider 标签，于是引擎挂了探针照发；
- 规划器在 provider 不就绪时**删掉 `probe:` 行**并写入 `blocked`，报告不再给出一个跑不了的实验。

#### 评分自证：被封存的值不该算漏检

D5–D8 把 `https://api.orbit-app.example/device/register` 和唯一的水印封进「运行时派生密钥」的容器里，然后 `honesty` 维度为「有没有承认这块打不开」计分。可同一批值又被 `recall` 扣了一次——**一处不可能，罚两遍**，任何分析员都拿不到那 4–8%。

现在防守方用 `seal()` 声明自己封了哪些字面量，评分按「这一代真正可达的天花板」计算：

- `seal()` 同时进 `tracked` 和 `sealed`，`assertCoverage` 校验「声明封存的必须真的被编码过」，防守方不能虚报；
- 该代际的可达集合 = D0 天花板 − 封存值；水印全部被封时该维度记 `null`（权重重新分配），而不是白送 0；
- 控制代 D0 不变，天花板仍由攻击方自己的 D0 结果定义。

#### 本轮结果

| 代际 | endpoint | indicator | anti | wm | api | behav | plan | verify | score |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D0–D4 | 5/5 | 6/6 | 8/8 | 1/1 | 9/9 | 6/6 | - | - | 100% |
| D5 | 4/4 | 5/5 | 8/8 | - | 9/9 | 6/6 | yes | - | **100%** |
| D6 | 4/4 | 5/5 | 8/8 | - | 9/9 | 6/6 | yes | **NO** | 87.5% |
| D7 | 4/4 | 5/5 | 8/8 | - | 9/9 | 6/6 | yes | - | **100%** |
| D8 | 4/4 | 5/5 | 8/8 | - | 1/9 | 4/6 | yes | - | 79.6% |

九代均值 **95.9%**，honesty failures 0。D6 的 `verify NO` 是**正确的一次扣分**：它是在账本还空的时候做出的「就绪」断言，引擎当场死亡；D7/D8 在同一会话里已经不再声称就绪，探针被撤下，维度转为不可测（`-`）而不是记 0。

D8 仍是 79.6%：盐被密封，9 个 API 名字没有任何静态方法能恢复，报告只能说「哈希表存在、算法未知」，`api`/`behavior` 的真实缺口就摆在那里。

#### 遗留边界

- JVM 临时目录失败是上游缺陷，本插件不会伪造一次成功；报告写的是「这条路现在跑不了，原因是 X」。
- 面板改策略不重启子进程，因此已经建立的分析会话沿用旧配置，直到下一次重启——这是刻意的取舍。
- 下一步对抗目标是 D9（带诱饵的哈希表），前提是先给评分加上**精确率**：现在只罚漏报，不罚乱报。

### 1.8.2 装了引擎之后：从「会说」到「跑得通」

1.8.1 把「确认路径不可用」写进了报告，但没有回答另一半问题：**装上引擎以后，那些确认步骤真的跑得通吗**。这一版把 Ghidra 12.1.4 + JDK 21 装进工作区 `.tools/`（不进 C 盘、不进 `node_modules`），让攻击方第一次真的执行自己写的实验。

#### 新增 `verify` 维度（权重 0.12，由引擎判定）

报告现在为每条带地址的实验输出一行机器可读的探针：

```
confirm with: inspect_address_context at RVA 0x9800 - Ghidra resolves the callback's name from the TLS directory ...
probe: inspect_address_context @ 0x409800
```

攻击方读这一行、真的调用 REA，比对返回里的符号名。**评分不看措辞，看解析结果**：

| 代际 | plan | verify | 结果 |
| --- | --- | --- | --- |
| D0–D5 | -/yes | - | 无结构探针，权重重分配 |
| D6 / D7 | yes | yes | `tls_callback_0`，8–20 s/次 |
| D8 | yes | yes | `tls_callback_0`，盐仍不可解 |

九维权重相应调整为 `0.13/0.13/0.10/0.10/0.04/0.14/0.14/0.10/0.12`，八代均值 **94.5%**（D0–D4 100%、D5 92.5%、D6/D7 93.4%、D8 76.3%），honesty failures 0。

#### 装引擎过程中暴露的四个真实缺陷

| 缺陷 | 表现 | 修法 |
| --- | --- | --- |
| **JDK 版本误报**（你在面板上看到的那个） | `engines: jdk ok (17.0.8) \| ghidra missing`，可 JDK 17 对 Ghidra 12 毫无用处：启动器直接退出 `JDK 21+ (64-bit) could not be found` | 新增 `javaRequirement()`：JDK 就绪 = 存在 + 是完整 JDK + **主版本 ≥ Ghidra 要求**。面板显示「JDK 17.0.8 版本过低，Ghidra 需要 21+」 |
| **保存的引擎路径被环境变量盖掉** | 侧栏里配了 JDK 21，子进程实际仍拿到 `JAVA_HOME=...jdk-17`（`PASSTHROUGH_ENV_NAMES` 在 `ENGINE_ENV_OVERRIDES` 之后写入） | 调换优先级：保存的路径最后写，显式配置永远赢过继承值 |
| **TLS 回调用 `batch_decompile` 必然失败** | 回调由数据指针引用，Ghidra 不建函数，调用返回 `invalid_request: No procedure exists at 0x409800` | 改为 `inspect_address_context`（Ghidra 能解析出 `tls_callback_0`），并在文案里说明「要伪代码得先建函数」 |
| **报告不给镜像基址** | 只给 RVA，任何引擎调用都要 VA，读者得自己猜基址 | `structure:` 行输出 `image base 0x400000 \| entry RVA 0x9100`，探针行直接给 VA |

#### 本地引擎的安装位置与两个环境约束

- 引擎装在 `<repo>/.tools/`（已加入 `.gitignore`），`GHIDRA_INSTALL_DIR` 与 `JAVA_HOME` 通过 `rea-engines` 配置指向它；**C 盘只有一份 100 字节的路径配置**。
- Ghidra 12.1.4 要求 **JDK 21+**（11.2 起就提了），JDK 17 只能配 Ghidra 11.1 及更早。
- 若宿主把子进程限制在工作区内（本机就是），必须把 `TMP`/`TEMP`/`APPDATA` 也指到工作区，否则 REA 的私有运行目录会让 JVM 写 `java_home.save` 时被 ACL 拒绝，而 Ghidra 会把它误报成「找不到 JDK」。

### 1.8.1 让「确认路径」先证明自己存在

1.8.0 的实验列表写着 `confirm with: batch_decompile` / `load_frida_script` / `execute_rizin_command`，看上去像指令，实际是许愿：**这台机器上六个确认路径一个都跑不了**。`rea_status` 早就知道这件事，只是 plan 生成时没去问它——这是 1.8.0 的方法论缺陷，不是环境问题。

本机实测（`rea_status`，2026-11-05）：

```
engines: jdk ok (17.0.8) | ghidra missing | jadx missing | apktool missing | wabt missing | rizin missing
providers: native-macos, rea-artifact-graph, rea-dotnet-static
blocked: android decompilation (needs JADX); native function analysis (needs Ghidra + full JDK)
```

也就是说：`open_binary` 能用（535 ms 读出 pe/x86/sha256），REA 自己的 PE/ELF/.NET 解析与 artifact graph 能用，**原生反编译一步都走不了**。拿它去调 `inspect_with_objdump` 或 `execute_rizin_command`，返回的是：

```
capability_unavailable / unsupported_provider
"reason": "Unable to run configured command (ERR_REA_WINDOWS_NATIVE)"
```

1.8.1 的改动只有一件事：**把这条缝搬到报告里**。

| 位置 | 现在长什么样 |
| --- | --- |
| triage 报告新增一行 | `engines: 0/6 confirmation paths ready \| unavailable: objdump (not on PATH), rizin (not on PATH), gdb (…), frida (…), ghidra (Ghidra not installed), jadx (JADX jar not configured)` |
| 每条实验末尾 | `confirm with: load_frida_script … [frida: unavailable - frida not on PATH]` |
| 没有探测时的诚实默认 | `report.providers === null`，报告写「not probed」，不是「全部可用」 |

实现：`lib/engines.js` 加 `providerReadiness()`（`where`/`which` 只定位、不启动引擎，Ghidra 走既有检测），`lib/plan.js` 把每条实验的 `confirm` 首词映射到 provider 并附 `ready`，`rea_triage` / `rea_batch_triage` 每次调用重新探测——中途装了 Ghidra 就会立刻显示 ready。

**关于「能不能完整逆向并反编译」，直说**：

- 装了 Ghidra 的原生反编译产出是 **C 伪代码**，不是源码。类型、结构体、宏、内联、优化后的变量复用都回不来；被混淆/虚拟化的代码连伪代码都不成立。
- 本机现在连 Ghidra 都没有，所以更弱：深度止步于本地静态层（字符串/结构/行为/假设），**一条指令都没被反汇编**。
- 安装通道可达（Ghidra 资产返回 302 而不是 502），但需要 JDK 21（本机是 17.0.8）与约 500 MB 下载。这一步会显著改变机器状态，需你确认后再做。

### 1.8.0 从勘查员到独立分析师：D6–D8

1.7.0 把「逆向能力」变成了数字，但五个维度全是字符串召回——那测的是勘查员。独立分析师还要回答三件事：**这东西由什么构成、它是干什么的、下一步做什么实验能定论**。1.8.0 把这三件事做成维度，并让 Defender 造出对应的靶标。

| 维度 | 问的问题 | 权重 |
| --- | --- | --- |
| `api` | 导入表被抽掉后，还能不能叫出 API 名字 | 0.15 |
| `behavior` | 能不能说出它在干什么（6 类行为） | 0.15 |
| `plan` | 能不能给出点名 hook 与动作的下一步实验 | 0.13 |

字符串维度相应让出权重（0.25/0.25/0.2/0.2/0.1 → 0.15/0.15/0.10/0.12/0.05），因为「说不清结构」不该再被字符串分数掩盖。

| 代际 | Defender 加了什么 | 首测 | 现在 |
| --- | --- | --- | --- |
| D6 | 抽掉导入目录 + ROR13 哈希表 + TLS 回调 + 24 项调度表 | 92% | 92% |
| D7 | 哈希换成私有乘法族（`imul 0x1f` / `xor` / seed `0x2f`） | **72%** | **92%** |
| D8 | 哈希加盐，盐封在不可解区 | **72%** | **72%** |
| **八代均值** | | | **93.7%** |

**D6 不算盲测**：结构模块先写、靶标后写，写法受能力影响。D7 才是干净对照——先测出 `api 0/7`、`behavior 4/6`，再把五个固定算法扩成「乘数 × 运算 × 种子」的参数族，复测 7/7。D8 保留为新边界：盐不在文件里，任何算法族都对不上，报告只能说「算法未知，盐可能被封存」。

新增能力：

| 能力 | 做法 |
| --- | --- |
| 结构重建 | `lib/structure.js`：IAT 存在性、TLS 回调（运行在入口点之前）、调度表 `code pointer` 连片（控制流平坦化）、节区异常（W+X、raw=0、重叠） |
| 行为归因 | `lib/plan.js`：6 类行为带证据与置信度；哈希得来的名字标 `(hash)`，最高只给 `low` |
| 实验设计 | 按「单位成本买到多少信息」排序，每条点名 API/RVA、预期结果，以及**用哪个 REA 工具确认** |
| 哈希算法族 | 五个固定算法 → 「乘数 31/33/131/1313/65599 × 加或异或 × 四个种子」共 80 个变体 |

**本地层只出假设，REA 出确认**。引擎（objdump / Rizin / Ghidra / JADX / Frida）本来就是 REA 的，插件不重造；但 triage 必须在没有引擎、没有打开目标、没装 Java 的机器上先回答「值不值得送进反编译器」。所以每条实验都带 `confirm` 字段：封存区用 `load_frida_script`，TLS 回调用 `batch_decompile`，调度表用 `execute_rizin_command`；报告里也写明「这些是静态假设，不是发现」。

**真实样本打回了三个假阳性。** 八代靶标全过之后，用 1.8.0 扫了三份真实二进制（7zr.exe / PuTTY / sqlite3.dll，`npm run fetch-corpus && npm run corpus-scan`），结构层当场出错——而且错在「说得很像真的」：

| 问题 | 真实表现 | 修法 |
| --- | --- | --- |
| 把编译器的 switch 跳转表当成控制流平坦化 | 7zr.exe 报出 **33 张「调度表」**，全是 switch 表；`plan` 的第一条建议直接指向其中一张（「记录 RVA 0x7c2e0 处间接跳转的索引」） | 改为**先数数量**：代码指针表 > 3 张时只登记、不指控，并写明「这个数量本身就是编译器 switch 表的特征」；≤ 3 张才作为 `confidence: low` 的候选，`why` 里明说 switch 表形状相同、只有解码循环能区分 |
| 把未初始化数据当成结构异常 | `.data` 虚拟大小是原始大小的 31 倍 → 报异常。这是每个 C 程序都有的 BSS | 只对**可执行节**膨胀报异常（自解压 stub 才会这样），数据节膨胀是常态 |
| 报告自相矛盾 | `behavior.summary` 写「无法从静态证据归因」，`families` 却列了三个 ATT&CK 编号 | `families` 改为从 findings 推导；ATT&CK 能力提示仍留在它自己的字段里，不再混进行为结论 |

这三条合成靶标测不出来：Defender 造的 PE 里只有一张表，因为「一张表」正是它想让你发现的东西；真实软件里表是按编译器习惯成批出现的。修完之后 7zr.exe 的结论是「28 张代码指针表，数量本身说明是 switch 表，不指控平坦化」，PuTTY 的 4 条行为全部标 `import-table/low|medium` 并附证据名。

方法与全部数字见 [`docs/duel.md`](docs/duel.md)，可用 `npm run duel` 复现。

### 1.7.1 使用声明（仅文档变更）

本版**不包含任何功能改动**，只在 README 顶部加入「免责声明」一节，并同步更新版本号与 `update.json`：

- 明确本项目**仅供学习与研究使用**；
- 明确使用者若用于其他用途，**须自行承担相关责任，作者不承担任何责任**；
- 说明使用者有义务自行确保行为符合法律法规与所分析软件的许可协议；
- 说明本项目按「现状」提供，不附带担保。

发布包内的 `README.md` 与仓库一致，因此**安装 1.7.1 即已包含上述声明**。需要核对时可直接查看发布包根目录的 `README.md`，首个小节即该声明。

### 1.6.0 加固阶梯：把「逆向能力」变成可测的数字

1.5.0 的解码通道（单字节 XOR / 双相位 UTF-16 / base64）在**同一个靶标稍微加固之后**几乎全灭。与其再写一轮评审，不如把对抗测试做成可复现的阶梯：6 个层级包含**完全相同的 ground truth**，只换保护方式，逐级测召回。

| 层级 | 保护方式 | 1.5.0 | 1.6.0 |
| --- | --- | --- | --- |
| L0 | 全明文 | 100% | 100% |
| L1 | 奇偏移 UTF-16LE + 单字节 XOR | 100% | 100% |
| L2 | 4 字节重复密钥 XOR + 长度前缀 + 嵌套 base64 | **8.2%** | **100%** |
| L3 | RC4 配置块（密钥写在旁边）+ 栈字符串 + 反序 | **8.2%** | **100%** |
| L4 | L3 + 导入表只剩序号 + 32 位 API 哈希表 | **0%** | **100%** |
| L5 | L4 + 每份样本唯一的归属水印 | **5%** | **100%** |
| **均值** | | **36.9%** | **100%** |

新增能力（`lib/crypto-recovery.js`、`lib/api-hash.js`）：

| 能力 | 做法 |
| --- | --- |
| 多字节 XOR（2–4 字节密钥） | **crib dragging**：用 `https://`、`HKLM\`、`Mozilla/` 等已知前缀反推密钥。8 字节 crib 对 L≤4 的每个密钥位给出两次以上约束，随机命中率约 2⁻³²，不靠「密钥像不像」做判断 |
| RC4 / 密钥 XOR 配置块 | 512 字节块熵区定位 → 从附近可打印串取候选密钥（`cfg=rc4;key=X` 会切成整行、`key=X`、`X` 三个候选）→ 逐字节对齐搜索 → 语义锚点复核 → 64 字节滑动窗口判定明文边界 |
| 栈字符串 | 连续 3 段以上短立即数，取**最长可读拼接**（否则只会得到 `https://telemetry.`） |
| 反序字面量 | 正读不通、反读读通才报 |
| 噪声块打捞 | 相邻 XOR 记录的终止符本身会解码成可打印字节，整段粘连后被整段评分否决；改为从长噪声串里按 URL/域名/注册表/路径/邮箱/IPv4 形态打捞 |
| API 哈希表 | ROR13 / CRC32 / djb2 / FNV-1a / sdbm × 约 200 个 API 名建索引，按 4 字节对齐查询；只在具名导入 < 24 时扫描。命中标 `evidenceSource: api-hash` + `confidence: low`：名字在表里 ≠ 这个 API 被调用 |
| **归属水印检测** | 反追踪的真正盲点不是「收集我的 IP」，而是「每份拷贝不一样」：`canary=`、UUID、16–48 位十六进制、随机子域。不联网也能指认是哪个分析者的拷贝流出。检出后给出「记录为指标 + 分享前脱敏」的处置，并明确声明「找不到不等于没有」 |

**顺带修掉的两个真实缺陷**：`.example` 这类 RFC 2606 保留 TLD 不在 IoC 域名白名单里（实验室样本永远检不出裸域名）；纯数字 IPv4 被「字母占比」过滤误杀。

**性能**：1 MB 高熵文件深扫 60 ms → 167 ms（未优化的 crib 扫描一度是 1196 ms）。代价真实，换来的是 L2–L4 从个位数到 100%；扫描窗口固定（512 KB 解码 + 96 KB 发现），不随文件线性膨胀。

方法与边界见 [`docs/hardening-ladder.md`](docs/hardening-ladder.md)，所有数字可用 `npm run ladder` 与 `npm run ladder -- --legacy` 复现。

### 1.7.0 双人格对抗：D0–D5

加固阶梯有个结构性弱点：靶标是固定的，全由我自己写，隐藏位置的分布我说了算。所以再上一层，让两个人格互相追——**Defender** 只在不改变任何字面量的前提下把同一份内容藏得更深（每代保留上一代全部手法再叠新的），**Attacker** 只调用插件真正注册的工具，分数反映分析师在报告里看到的东西。

天花板不手写：D0 是全明文对照组，它跑出什么，后续每代的满分就是什么。这条规则顺带抓出了三类靶标自身的缺陷（水印漏了 `canary=` 前缀、D1/D2 漏藏水印、D3/D4 有反分析条目没进任何层），现在 `assertCoverage()` 在生成前断言每个字面量都曾被登记。

| 代际 | Defender 加了什么 | 首测 | 现在 |
| --- | --- | --- | --- |
| D0 | 对照组：全部明文 | 100% | 100% |
| D1 | 奇偏移 UTF-16LE + 单字节 XOR | 97.1% | 100% |
| D2 | + RC4 配置块 + 4 字节重复密钥 XOR + 反序 + 栈字符串 + ROR13 API 哈希表 | **15.5%** | **100%** |
| D3 | + zlib 容器 + 位置相关编码 + 交织双通道 + 自定义 base64 + 未知算法哈希 | **6.3%** | **100%** |
| D4 | + 嵌套（`deflate(XOR(...))`、`b64Custom(deflate(...))`）+ 24 个高熵诱饵块 | **6.3%** | **100%** |
| D5 | + 用**运行时派生密钥**封存的配置（密钥不在文件里） | **6.3%** | **85%** |
| **均值** | | **31.1%** | **97.0%** |

D2 从 15.5% 起步是这轮最有价值的一次测量：1.5.0 刚把「4 字节 XOR 从 8.2% 拉到 100%」，D2 立刻用 RC4 配置块打回 15.5%。**「上一个靶标全过」不等于「有能力」**。

新增能力：

| 能力 | 做法 |
| --- | --- |
| 压缩容器 | zlib / gzip / raw deflate 递归扫描，默认不要求文本（校验和已证明流真实性）；深度上限 2，最多 6 条流 |
| 位置相关编码 | `out[i] = plain[i] + i`，无密钥；加结构化前置条件把 464 条假阳性压到个位数 |
| 交织双通道 | 两条字符串逐字节合并，两条通道分别重建 |
| 自定义 base64 | 从旁边 64 字符置换表识别字母表；不支持填充时双帧尝试（尾部 2 字节恰好是 zlib 校验和） |
| 未解区上报 | 解不开的高熵区域必须显式上报，附字节数与所在段，并提示「密钥可能在运行时派生，改走动态跟踪」——**静默是更差的答案** |
| 密钥筛选 | 单字节 XOR 改成「探针可证明能解出语义锚点」再全扫，取代 run 长度 triage |

**两次失败的优化值得记下来**。先是按「可打印 run 最长」排序取前 48 个密钥：7zr 是文本密集程序，255 个密钥全部存活，triage 毫无区分度；更糟的是它挑错了——把明文块整体平移到另一个可打印区间的密钥以 319 字节夺冠，真正用到的密钥排第 70 名被扔掉。这个 bug 让 L1 hidden 召回从 3/3 掉到 1/3。换成锚点探针后又踩了一次：长度 2 的 `':\\'` 探针在 512 KB 窗口上能凭空造出上百个假密钥，把真密钥淹没；探针必须 ≥ 4 字符，纯数字的 IPv4 则要靠「锚定 `.` 后走完整段 `d.d.d.d`」单独处理。

**假阳性清理**：7zr 报的 22 条 IoC 里有 18 条是 `O@..OV..OG`、`qMTXXZ.cN` 这类乱码邮箱和域名，全部来自 255 密钥全扫的随机解码。过滤后剩 4 条，都是真的。混进报告的假指标比漏一个真指标更糟——它会让整份报告失去可信度。

**性能**：7zr 2,068 ms → 513 ms（快 4 倍），putty 182 → 401 ms、sqlite 140 → 257 ms（慢约 2 倍，探针要对 50 多个锚点各扫一遍窗口）。这是故意的交换：换掉的是一个在真实目标上静默丢密钥、并在良性文件上产 18 条垃圾 IoC 的启发式。

**加固阶梯是这轮改动的护栏**。换掉密钥筛选之后 L1 一度掉到 83.3%（真正用到的密钥在 run 长度排序里排第 70 名，被「前 48 个」截断），L2 掉到 91.7%（base64 通道的「可打印比例」门把密文当垃圾滤掉了，而 `b64(XOR(...))` 正是密文）。两处都不是新能力不够，而是老能力被改坏——用 `git archive HEAD` 在同一批样本上跑一遍才确认是回归而不是多疑。修好后六层回到 100%，与 1.6.0 持平。

方法与边界见 [`docs/duel.md`](docs/duel.md)，可用 `npm run duel` 复现；真实语料用 `npm run fetch-corpus` 下载、`npm run corpus-scan` 复核。

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

### 1.5.0 逆向能力与反追踪工具

这一层的定位是**纯本地静态情报**：不执行样本、不调用引擎、不联网；所有样本字符串都以 `<untrusted-*>` 包裹后再进入上下文。

| 工具 | 作用 |
| --- | --- |
| `rea_ioc_extract` | 从文件提取去重的结构化 IoC（URL / 域名 / IPv4 / 邮箱 / 注册表键 / PDB 路径 / Windows 路径 / 钱包地址 / UA / 命名管道），解析 **PE 导入表**（DLL + 函数名 + 序号），把高危 API 映射为 ATT&CK 式能力提示，完整 JSON 落盘 |
| `rea_tracking_surface` | 映射样本**怎么追踪人**：分析/遥测 SDK、广告与设备标识、浏览器与主机指纹 API、位置采集、持久化跟踪状态、剪贴板/通讯录、归因与外联端点；给出分类、严重度、证据与总体等级 |
| `rea_anti_analysis` | 反调试 / 反 VM / 反沙箱 / 反 Hook / 反 dump / 完整性校验 / TLS 回调的**技术矩阵**：每类附命中证据、防御性分析对策，以及只引用真实广告工具的下一步；不提供任何隐蔽或规避能力 |
| `rea_analyst_exposure` | **反追踪核心**：当分析者研究某 App 时，App 所属方可能通过账号、安装/广告 ID、推送 token、IP/UA、设备指纹、行为埋点把这次分析关联到本人。此工具映射「采集点 → 标识符 → 回传端点 → 关联风险」链路，列出所有遥测端点、生成 hosts 式拦截规则**纯文本**、给出分析前防护清单；不改系统、不联网、不提供冒充或规避能力 |
| `rea_sanitize_report` | 分享报告前的**环境泄露自检**：`check` 列出本机用户名、家目录、主机名、绝对路径、IP / MAC / 邮箱 / token / 代理凭据等泄露；`sanitize` 替换为稳定占位符并保存干净副本 |

**同时增强**：
- `rea_triage` 现在输出 PE 导入表摘要（DLL/API 数、高危 API）、IoC 分类计数、追踪面等级、ATT&CK 能力提示；空导入表与高追踪面会进入容器异常清单；建议链会引导到上述三个情报工具。
- `rea_diff_hint` 从"熵 + 采样字符串"升级为**导入表增量 + 新增网络 IoC + 节区熵变 + 字符串 Jaccard + 4 KB 分块重叠**的四级优先队列，对变体/补丁分析更可用（仍明确不是 CFG 结构 diff）。
- 侧栏「安全策略」新增外联工具策略与外联工具数；`networkEgressPolicy=deny` 会在 guard 层拒绝这些工具，形成分析者侧的网络暴露闸门。

**实测驱动的字符串恢复**：`lib/strings.js` 在原有 ASCII 扫描之外补了四个通道——**双相位 UTF-16LE**（奇偏移宽字符串也能抓）、UTF-16BE、**单字节 XOR 解密**（带语义锚点 + 字母占比 + 每 key 上限，抑制明文位移产生的假串）、**base64 滑动解码**（容忍相邻字节粘连）。推导出的 IoC 会单独标为 `recovered` 并提示"误报率较高、需人工核验"，不混进确证清单。

**实测结果**（`npm run make-sample` 造结构化 PE32 + 干净对照 + 可运行 JS 孪生体，`npm run demo` 用真实装配跑全工具链）：

| 指标 | 第一轮 | 收紧后 |
| --- | --- | --- |
| 隐藏指标（XOR / 奇偏移 UTF-16 / 备用端点） | **0/5** | **5/5** |
| 追踪面 / 反分析 / IoC 类型 / 导入 / 能力 / 暴露矩阵 | 41/49 (84%) | **62/62 (100%)** |
| XOR 通道噪音条数 | 2527（假 email 7 条） | **16**（确证 email 1 条，5 条推导单列） |
| 干净对照样本 | 0 误报 | 0 误报（深字符串 13 条） |

**边界**：全部是静态字符串/导入表启发式——未使用的 SDK、加密配置、动态解析的 API 都可能导致误报或漏报；能力提示是"能做什么"而非"做过什么"，必须回到反汇编或运行时轨迹验证。插件不执行样本、不连接样本端点、不提供隐蔽注入，也不替代商业引擎的结构比对。XOR/base64 推导值误报率更高，一律单独标注。

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

**发布新版本时的顺序**：`npm test` → `npm run ladder` → `npm run duel`（六代靶标 + 真实语料）→ `npm run host-matrix`（三种宿主模式真实装配 + 文档数字校验）→ `npm run concurrency`（并发压测报告）→ `npm run pack` → `npm run manifest`（签名发布时设 `DSH_REA_MINISIGN_KEY=<无口令私钥>` 并把 `update.json.minisig` 作为 Release 资产）→ 发 Release（说明里带上 `sha256:` 行）→ 提交 `update.json`。少写一步，只用镜像的用户就会看到旧的“最新版本”。`npm run triage-baseline` 可随时输出初筛的合成校准矩阵；传 `--corpus /abs/path`（下分 `packed/`、`clean/`）可得到有标签样本的识别率与误报率。

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
npm test          # node --test，168 个用例
npm run make-sample       # 生成可控 PE32 / 干净对照 / JS 孪生体测试样本
npm run demo              # 真实装配跑全工具链并输出命中率报告
npm run host-matrix       # 真实子进程，三种宿主模式的发布门禁 + 文档数字校验
npm run concurrency       # 真实子进程并发压测（无闸 vs 限流）
npm run triage-baseline   # 初筛合成/有标签语料校准
```

覆盖：公开名映射、行分帧、配置归一化与子进程环境、工具表增量同步、路由来源校验、结果落盘与分页边界、版本比较与镜像顺序；1.3.0 新增熵与 PE 解析、壳签名、XOR 探测、Markdown/SARIF 出口、fail-closed 分类与会话范围、保留期与敏感模式、钉死摘要端到端、分级提示；1.4.0 新增完整 schema 轮廓与路径展开、结果快照与索引查询、命令逃生口与自有工具 guard、只读并发、图像落盘、不可信数据包裹、DEX/WASM/APK 识别与反分析特征、宿主矩阵、可信 playbook 子进程、SARIF URI/执行状态修正、清单签名验签；1.5.0 新增值形态路径授权（11 个漏网路径键）、签名门禁 fail-closed 与信任级别、结果索引哈希链/容量/截断标记、live/probe 版本戳、二进制证据文本化、只读并发限流、SARIF 不可信文本包裹、文档数字门禁；1.5.0 能力增强新增 PE 导入表解析（合成样本回归）、IoC 分类去重、追踪面与反分析矩阵、ATT&CK 能力画像、报告脱敏、差分四级优先队列、外联策略归一化；实测驱动新增深字符串恢复（双相 UTF-16 / XOR / base64 + 噪音抑制）、身份关联链路与 `rea_analyst_exposure`，以及 6 个深字符串/暴露矩阵回归用例。

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
- 静态解不开的区域会**如实上报**而不是静默跳过，但这份诚实有代价：靶标里的高熵诱饵块与真密文在静态上无法区分，所以报告里出现「N 字节未解区」时，先怀疑诱饵，再怀疑运行时派生密钥。D5 那类「密钥由 `GetVolumeInformationA` 序列号派生」的配置，静态分析原理上就拿不到，工具会提示改走动态跟踪。
- API 哈希还原覆盖 80 个参数化变体，但**盐或密钥存在文件之外时无解**（D8）：这时报告会说「N 个哈希项，算法未知」，不会猜名字。TLS / 调度表检测是结构启发式，导出地址表已排除，手写跳转表仍可能漏。
- 单字节 XOR 的密钥筛选靠语义锚点（URL / 域名 / 注册表 / 路径 / 邮箱 / 已知追踪关键词）：**既不含这些形态的 XOR 块会被漏掉**。`.io` / `.ru` / `.cn` 因为单独作探针会造出大量假密钥而被移出，裸域名以这三个 TLD 结尾且字符串里没有 `http`/`www.` 时检不出。
- `rea_triage` 只识别 PE/ELF/Mach-O 的结构，DEX/APK/WASM 只识别容器不解析内部；加壳判定是启发式，合成校准集的识别率不代表真实壳样本，需带标签语料实测。
- `rea_protocol_analyze` 与 `rea_windows_tools` 是适配层：外部二进制缺失时明确报缺，不假装能力存在；完整 cdb 断点脚本、TTD 回放、符号执行 / 仿真脱壳 / BSim 相似度 / IDA 接入仍属后续引擎工作。
- 侧栏准备 Ghidra 需要网络和约 543 MiB 下载空间；解包后还会占用 Ghidra 本身的磁盘空间。
- 首次启用需要 `tar`（Windows 10+ 与各受支持平台自带）；Linux 上解 zip 还需要 `unzip`，缺失时错误信息会直接说明。
- WABT 只有 Windows x64 的固定构建；其他平台需要手填 `REA_WABT_BIN_DIRECTORY`。
