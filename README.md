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
- **延迟加载**：237 个工具的 schema 标记为 `deferLoading`，**不进请求体**，只在模型真的要用某个工具时才加载。常驻开销从 194 KB（≈4.9 万 token）降到 1.4 KB（≈341 token），工具一个不少、照样能调。
- **检索入口**：`rea_catalog` 是一个几百字节的常驻工具，按关键词在 237 个工具里搜名字/描述——因为 schema 延迟了，模型没法直接从工具表里读它们，这个工具就是它的索引。无参调用列出全部 237 个**精确工具名**（约 6.9 KB），带关键词时给出命中项的一行描述。
- **技能**：把 REA 自带的 `reverse-engineer-anything` 技能及其 `references/` 参考文档安装到 `~/.dsh/skills/reverse-engineer-anything/`，按 REA 版本号打戳，版本没变就不重拷。
- **环境侧栏**：侧栏入口显示运行时、Java/JDK、Ghidra、JADX、Apktool、WABT、Kuna/Rizin 的实际状态；面板内可填写并保存所有绝对路径，Ghidra/JADX/Apktool/WABT 还提供按需准备按钮和进度。
- **就绪检查**：`rea_doctor` 运行逆向服务自己的 `mcp doctor --json`，报告 MCP 子进程能否启动、服务端状态与可用分析引擎。只读，不打开任何目标。
- **一屏状态**：`rea_status` 用一次调用说清"有没有打开目标、绑了哪个 provider、哪些引擎装好了、因此现在能做什么"。237 个工具里有 55 个依赖"当前文档"，在 headless 引擎下没有目标就会空转——先看一眼比撞一次墙便宜。
- **结果落盘**：单次结果超过 `maxResultChars`（默认 24 000 字符）时写入 `~/.dsh/rea-artifacts/<会话>/`，模型拿到开头摘要和路径，再用 `rea_read_artifact` 分页读。`binary_session` 这类 70 KB 的结果不再挤爆一轮对话。
- **变更留痕（1.3.0 起 fail-closed，1.4.0 补齐旁路）**：不再靠硬编码名单——已知只读首词之外的**新工具默认审计**。`gdb_console`、`rizin_debug_command`、`cutter_command`、`observe_native_calls`、`observe_web_execution` 这 5 个命令逃生口在 1.4.0 纳入审计；1.5.0 起 `guard` 覆盖全部插件自有工具（注册层统一包裹，1.5.0 时 15 个、现 30 个），路径授权改为按**值形态**判定（不再依赖键名白名单）。上游 `destructiveHint` / `openWorldHint` 作为保守下限信号，不当权威分类器（237 个里 157 个只读，其余默认审计）。**157 个只读工具**允许并发调用，并由 `maxConcurrentReadTools` 限流；真实装配共 **237 工具 + 8 路由**。
- **完整 schema 渐进展开（1.4.0）**：后台独立子进程缓存全部完整输入/输出 schema 与注解（约 3 MB 内存、零上下文开销）。`rea_catalog({tool, path, includeOutput})` 按 JSON Path 逐字段展开；165 KB 的 `compare_web_captures` 默认只给约 1 KB 轮廓。
- **结构化结果与工作流（1.4.0）**：每次调用把 `evidence_id` / 置信度 / 覆盖度 / provider 写进跨会话索引，用 `rea_query_results` 复用；`rea_batch_triage` 批量初筛、`rea_diff_hint` 粗配、`rea_fuzz_harness` 生成模板、`rea_run_playbook` 用可信脚本把多次往返压成一次调用。
- **静态对抗初筛**：`rea_triage(path)` 纯本地、不执行样本：整体与分块熵、PE/ELF/Mach-O 节区与入口/导入异常、13 类壳与混淆器签名、字符串与单字节 XOR 探测、可选 YARA，输出带证据的 packed / obfuscated / unpacked 判定与下一步建议。对 .NET/CLR 程序集，`structure.managed` 额外给出**元数据清单**：CLR 头（运行时版本、入口 token、StrongName）、程序集名/版本、模块、类型与方法名清单（封顶并标注）、资源与表行数；传 `managedCil: true` 时再给出**有界 CIL 反汇编**（逐方法指令清单、调用 API / 字符串 / 字段摘要、P/Invoke 面与 EH 子句，默认 48 方法 × 400 指令封顶）——这是指令级证据，不是 CIL 反编译，不还原语义。
- **证据出口**：`rea_export_report` 把 Evidence bundle 转成 Markdown 报告与 SARIF 2.1.0，覆盖度、未解未知清单、推断边界都写进产物，可归档或接 CI。
- **产物治理**：结果默认保留 7 天并有容量上限；`sensitiveArtifacts` 让完整结果只回摘要、不落盘；`rea_purge_artifacts` 手动清理。
- **分级提示**：反编译/重建类结果强制标注「推断，非源码」，写操作结果标注「已审计」。
- **版本更新**：侧栏可检查 GitHub 新版本并一键安装；下载走多层镜像，任一失效自动换下一个，按 Release 公布的 SHA-256 校验（可用 `pinnedSha256` 钉死摘要）。侧栏会列出每个镜像的成功/失败原因与当前安全策略。
- **开发者不可见（2026-11-20）**：插件自身的运行时网络原语只有 `lib/infra/download.js` 一处，请求头固定为 `user-agent: dsh-rea` + `accept`，无版本号、无平台、无主机信息；每条出站通道的 URL/主机/请求头与用户标识结论逐项入档于「出站通道审计与本地化模式」一节，`localizedMode` 开关可把已声明的四类下载在本地拒绝。

## 为什么不合并工具

237 个平铺的工具名确实又多又杂，但**合并会改变模型看到的世界**：REA 的工具是按「一个工具一个职责 + 严格输入契约」设计的，合并成一个 `rea_run(tool, input)` 式的总入口意味着模型每次都要先猜对工具名和参数结构，而它现在是从 schema 里读到的。所以选择保留 237 个工具、用延迟加载解决体积——这是宿主的原生机制（`deferLoading` 一路通到 DeepSeek 的 `defer_loading` 字段），不是插件自己的 hack。

`rea_catalog` 的输出里，每一行**已经是**可以直接调用的 `mcp__rea__*` 全名；前缀只加一次。

## 运行时怎么放

`rea-agents` 6.7.0 连同完整依赖闭包（136 个包）打成一个 `vendor/rea-runtime.tgz`（28 MB，带 SHA-256 校验）。**首次启用时**解包到 `~/.dsh/rea-runtime/`，之后 MCP 子进程用宿主自己的 node 以绝对路径直接跑，调用时不经 npm/npx、不需要网络。

之所以用「压缩包 + 首次解包」而不是把 `node_modules` 原样放进插件：

- 插件目录从 124 MB 降到 28 MB；
- 解包位置在 DSH 主目录而不是工作区 —— 工作区沙箱被观测到会把外部写入的大目录回滚掉，那会让插件某天悄悄坏掉；
- 依赖闭包完整。REA 有大量**惰性 require**（`saxes`→`xmlchars`、`pino`→`pino-std-serializers`……），按「运行时实际 import 过谁」裁过一版，第一次调用就崩；按 `package.json` 依赖闭包裁，也漏。只有全量闭包能让 237 个工具都不坏。

**解包是原子的**：校验 → 解到同级 staging 目录 → 确认 `rea-agents/scripts/rea.mjs` 在 → 删除旧目录并改名。任何一步失败都保留上一版运行时，不会出现「解包崩了、237 个工具全没」的状态。

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

延迟的 237 个工具仍然可调，`rea_catalog` 可按关键词检索（`javascript` 命中 22 个，无参列出全部 237 个名字）。

## 还原工程：复刻对照循环

还原不是一个新反编译器，而是一圈可证伪的循环：读取目标 → 记录假设 → 编译草稿 → 与目标分层对照 → 差距进入下一轮。工具面三个：`rea_reconstruct`（状态机：start / advance / status / handoff / rewrite / dynamic-plan / dynamic-apply / trace-apply / hypothesis-record / hypothesis-check）、`rea_compare_build`（T1 结构 / T2 函数伪代码 / T3 源码字面量 / 可选 T4 行为契约 / 可选 T5 交互面；`deductFunctions=true` 时把同工具链空程序 floor 从 T2 分母扣除并双报）与 `rea_trace_behavior`（opt-in：执行双方并对照运行时轨迹）。另有 `rea_dynamic_probe`（运行时取密钥）、`rea_memory_dump`（内存镜像脱壳）与 `rea_side_effects`（注册表/管道/服务/IPv4/IPv6 连接/DNS 查询）三条 opt-in 执行工具，它们不参与循环判定。状态机有预算和四个终态：`converged`、`budget-exhausted`、`blocked`、`unreachable`；空测量判为失败，不判满分。

T4 行为契约（`behavior=true`，默认关）回答结构层答不了的问题：重建体是否说同样的话（输出字面量）、维护同样的状态（注册表 / 互斥量 / 文件路径 / 环境变量）、伸向同样的副作用家族（network / file / registry / process / crypto / memory / ui / service 与操作种类）。三个维度各自计 recall 与 precision；只声明一侧时按存在的一侧计分，两侧都空是 `null` 而不是 1.0。它是**声明面**而非执行轨迹：导入了 `connect` 不等于调用过，内联系统调用与动态解析的 API 看不见——这条限制写进每次报告，不藏在文档里。

T5 交互面（`rea_compare_build` / `rea_reconstruct advance` 的 `interaction=true`，默认关，需引擎清单）回答 GUI 目标的同类问题：重建体是否注册同样的窗口类、指向同样的窗口/对话框过程、处理同样的消息（`msg:0x1`/`msg:0x111` 等，十进制与十六进制归一化）、寻址同样的控件与定时器 ID、携带同样的 `.rsrc` 资源条目。四个维度各自计 recall 与 precision；全部证据来自反编译体、导入表与资源目录的静态读取，不创建窗口、不执行样本。Qt/WebView/Electron/自绘框架不可见，`WM_USER+n` 类算术常量不解析，switch 降界的哨兵常量两侧对称——边界在 limitations 逐条声明。`engine=false` 时显式 blocked：清单不存在不等于没有交互面。

构建引擎有两个，目标同为 x86_64-windows-gnu 的 PE：首选 WinLibs GCC 16.2.0（`npm run engine gcc`），网络到 GitHub 过慢的机器可用 `npm run engine zig` 装 zig 0.17.0（`zig cc`）。编译报告会记录实际使用的编译器，不混算。

合成靶标阶梯 R0–R5（`npm run recon`）：R0 明文对照；R1 strip + 单字节 XOR；R2 4 字节重复键 XOR 配置；R3 ROR13 API 哈希表；R4 运行时派生密钥封存的配置；R5 Win32 GUI 窗口面（窗口类 + WndProc 消息处理 + 按钮 ID + 定时器，配 `--engine --interaction` 测 T5 交互面）。每一代都由同一编译器真实编译，评分以 R0 的机械重建为天花板；R4 的封存值不在文件里，正确结果是「还原解码逻辑 + 明说秘密不可得」。设计与验收口径见 [`docs/reconstruction-plan.md`](docs/reconstruction-plan.md)。

机械基线（`npm run recon -- --baseline`）：把 Ghidra 伪代码直接翻译成 C，先在「其余函数全部为桩」的隔离编译里逐个筛选，失败者降级为桩并计数，再整文件编译收敛（持续失败会降级到可编译下限）；不经过任何模型。评分先扣除「空程序同工具链编译」与「目标全桩版本」两级运行时底噪，载荷维度只统计 **IoC 形态的指标与归属水印**（URL/域名/注册表/互斥量/canary 等），编码配置经解码通道还原出指标后同样计分；编译器词汇与构建路径不计入，避免空洞重建拿到接近满分。基线能还原控制流与导入，不还原封存数据——这是反编译器的边界，报告按此呈现。

真实语料（`npm run recon -- --corpus <dir> --baseline`）：输出函数清单、基线的翻译/桩计数、T1 与 payload 得分；triage 判为 packed/protected 的样本**拒绝**做源码基线（解包前做只会测到壳）。putty.exe 本轮复测为 `appears-unpacked`（高熵仅出现在 `.rsrc` 压缩资源），已进入基线：24/2710 函数、翻译 2/桩 22、T1 16.7%、payload 0.0%、综合 9.0%——这说明「putty 需先脱壳」是旧判定的误记，当前 triage 不再拒绝它。

**真实函数级还原**（`npm run restore -- <target> --functions FUN_a,FUN_b --draft <file.c>`）：只评审指定的函数，按函数名匹配（重建体布局不同也不影响），默认用**语义签名**（结构常量 / 运算符 / 控制流关键字 / 调用数）——该口径下 CFG 不参与计分，跨编译器可比信号即此。2 函数首测 sqlite3：2/2、**87.8%**（79.7% 的那一个会点名）；同口径复测（`--threshold 0.75`）2/2、100.0%、exit 0。2026-11-18 扩到 **9 个函数**（既有 6 体 + 从缓存伪代码手写的 FUN_180009750 / FUN_180009820 / FUN_1800099a0）：语义签名 `--threshold 0.75` → **9/9、100.0%、below threshold 0、exit 0**；同一清单同一草稿换 `--metric text --threshold 0.99` → 53.0%、below threshold 9、**exit 1**——阈值是退出码门禁，不是装饰。**7zr 首次函数级基线**：FUN_00401207 + FUN_00401519（cap-24 缓存伪代码手写，`--max-functions 24`）语义签名 `--threshold 0.75` → **2/2、97.9%、exit 0**；同清单同草稿换 `--metric text --threshold 0.99` → 56.4%、below threshold 2、**exit 1**——两个目标的正负对照口径对称。正负对照钉在 `test/restore.test.js`（相对路径串命中清单缓存、spawnSync 采集退出码）；每次门禁运行还会把结构化结果（target / metric / threshold / matched / belowThreshold / exit / 逐函数相似度）追加写入 `dist/restore-gates.jsonl`，数字核对读该文件即可。草稿一律由分析者/模型按门禁打印的反编译伪代码手写（fixture 头注释逐函数记 rva/size 出处），脚本负责取伪代码、编译、对照与收口；防抄官方源码是三层防线（按名配对的结构层 + 数字偏移/掩码计分的启发式层 + 出处注释审计），不是机制上不可能。已知边界：sqlite3 的 cap-200 清单窗口内 0 个导出符号名（`sqlite3_*` 导出在更后地址），导出面覆盖需要升级 ProbeAddress 清单机制，本轮未做。**2026-11-19 批次二（分层抽样，累计 32 个函数，落入目标区间 30–50）**：sqlite3 26 个 + 7zr 6 个（草稿 `test/fixtures/sqlite3-restored-b2.c` / `7zr-restored-b2.c`，仍全部从缓存反编译伪代码手写）；抽样判据结构化落盘（size 档 S/M/L、maxFanout、loop+写、markers、链深），**必须含硬函数**——sqlite3 窗口实测 unaff/extraout/SEH/尾调用为 0，硬函数来自 7zr 窗口：FUN_004010ac / FUN_0040116f 携带 `unaff_EBP`+`extraout_ECX/EDX`，FUN_0040125a 另含 `CONCAT31` 拼接与 "Unknown switch:"（此前回避的伪影体本轮纳入）。门禁：sqlite3 17/17、99.7%、exit 0；7zr 4/4、100.0%、exit 0；below-threshold 仅出现在按设计必败的 `--metric text --threshold 0.99` 负对照（sqlite3 17 项 22.2%–98.8%、7zr 85.1/98.8/97.7/74.9%），函数全部保留、阈值未放宽。**语义归因覆盖率（W4，2026-11-20）**：对这 32 个函数批量生成语义假设并逐条核验，**26/32 verified**（sqlite3 20/26、7zr 6/6；6 个 3–79 字节桩/取值器四通道皆无可测特征，如实计 unverified 留在分母），数字与边界见「语义假设验证」段与 `docs/reconstruction-plan.md`。

**T1 分母扣除**（`rea_compare_build` / `npm run recon -- --deduct-functions`，默认关）：T2 的分母此前把同工具链编译器注入的 CRT 函数也算成「待恢复函数」，机械基线在 R0 上被 42 个 MinGW CRT 抬到 65.7%。现在用插件托管 gcc 编译**空程序**经 Ghidra 实测出工具链 floor（43 个函数名 / 50 个 RVA / 52 个体哈希），按「（名命中 ∧ (RVA∨体哈希命中)) ∨ 体哈希命中」从严扣除，name-only 只审计不扣除，`main`/`FUN_*` 永不按名扣。结果**双报**：`t2.score`=扣除后均分（分母 after），`t2.scoreAll`=原口径均分（分母 before）——R0 机械基线 T2 65.7%→**34.6%**（分母 48→6），R1–R4 仅回落 1–2pp；真实 MSVC 语料（putty/sqlite3/7zr）窗口内 0 命中，扣除不适用、双报同数，不硬凑。`functionFilter` 门禁路径不受影响；floor 测量失败自动关闭并写明；「函数无对应计零」原则不变。

**语义假设验证**（`rea_reconstruct action=hypothesis-record` / `hypothesis-check`；restore 门禁 `--hypotheses <json>`）：把「函数语义假设 → 二进制验证」做成可证伪循环。每条假设 = 一句归因判断 + 逐字可 grep 的反编译证据 quote + 一个可检验预测（`string-literal` / `constant-at-rva` / `import-used` / `calls-target` 四通道）。`checkSemanticHypothesis` 先过**证据门**（quote 必须在所引函数的反编译体里命中，落空即 refuted），再跑预测通道，输出三态：**verified / unverified / refuted**——函数级 import 命中只到 unverified（necessary, not sufficient），same-channel 弱化语句固定写入 detail，未知通道一律 unverified，禁止冒充 verified。refuted 假设在后续每轮作为 `hypothesis-refuted` gap 回流，门禁结果写入 `dist/restore-gates.jsonl`。sqlite3 实测正负对照：DAT_18029bd28 的 double 下界（字节 `ffffffffffffdfc3`）verified；「FUN_1800096b0 弹 MessageBoxA」被体+导入表双证据 refuted（动态解析盲区如实注明）。**W4 批量实测（2026-11-20，M1 全部 32 函数）**：`dist/m1-hypotheses.mjs` 从缓存清单机械生成 45 条假设（sqlite3 36 = 34 正 + 2 负对照；7zr 9 = 7 正 + 2 负对照；evidence quote 逐字复制缓存体、先经生产核验器对门禁同参四通道预检），门禁 `--hypotheses` 4 次正向全 exit 0（sqlite3 9/9 与 17/17、7zr 2/2 与 4/4，假设结果 additive、退出码只由 T2 决定），loop 状态机 45 条逐条 `hypothesis-record`→`hypothesis-check` 落 `dist/recon-w4/reconstruct-*.json`。**已验证归因覆盖率 26/32（81.25%）**：sqlite3 20/26、7zr 6/6；6 个无假设函数（3–79 字节桩/取值器/标志检查，无串、无 DAT、无调用形状）如实计 unverified 留在分母；正假设 41/41 verified（constant-at-rva 14、calls-target 26、string-literal 1），4 条负对照全部按设计 refuted（期望结果，与意外证伪分开统计）。诚实边界：26 条 calls-target verified 均带 same-channel caveat（假设与验证同源目标自身反编译，不当成独立确认）；14 条 constant-at-rva 的预测字节按方案实测自目标文件（确认的是实测字节，不是独立指定值）；sqlite3 体引串在门禁 4000 条深度串窗口之外（全文件实测 11431 条，如 "API called with finalized prepared statement" 在文件偏移 2684912），string-literal 通道对 sqlite3 不可用属实测盲区。汇总只读脚本 `dist/m1-coverage.mjs`，数字落 `dist/m1-coverage.json`。

**动态探针**（`rea_dynamic_probe`，opt-in）：需要配置 `allowSampleExecution: true` 且每次调用 `confirm: true`；运行前需 `python -m pip install frida`（本机实测 17.26.3）。若 `python` 与 `py -3` 不是同一个解释器，插件依次探测 `python` / `py -3` / `python3`，并使用真正装了 Frida 的那个——本机就属于这种情况（Frida 在 `py -3`）。用 Frida hook 指定 RVA 的函数，在返回时读取指定参数指向的缓冲区。用于静态不可达的运行时派生密钥。**它会真的执行样本，默认样本保留自身网络访问，没有沙箱**——仅限你有权执行的样本；缓冲区内容按不可信数据处理。`sandbox=true`（另需 `sandboxSampleExecution: true`，见下）时样本改经内核强制沙箱启动、探针按 pid attach，实测容器内命中并取回缓冲区。实测在 R4 封存靶标上于 `unseal` 返回时取回了明文配置。

**自动改稿**（`draft=auto`）：从分析者草稿或上次最佳草稿出发（两者都没有则从机械基线出发），读本轮 gap 并用反编译产物做确定性修补——T2 点名的每个不匹配函数替换为其反编译对应体，T1 缺失的导入则从基线拉入绑定该导入的函数。每轮重新编译与对照，**只接受分数更高的轮次**；批次替换导致分数下降时，回退到**最近的最佳草稿**，只替换相似度最低的一个函数重试一次（回退至多一次、至多 1 次额外编译，最坏 `rounds+1` 次对照），重试仍不高则保持最佳草稿。不给 `source` 时从**上次最佳草稿**续跑（状态里记 `lastDraftPath`），不是每次从基线重来。它不编造调用路径，也不把目标字面量塞进源码骗分；需要 Ghidra 提供基线，`rounds` 1–5（默认 2）。

**交接简报**（`action=handoff`）：把最近一轮的 gap、T2 待重写函数（名字 / RVA / 相似度 / 对应反编译调用）与下一步命令写成 Markdown 落 artifacts。这是「需要理解」的接缝——机械修补到此为止，剩下的交给分析者或模型时不用再靠口头转述。

**内存镜像脱壳**（`rea_memory_dump`，opt-in）：spawn 挂起后读取主模块 `SizeOfImage` 字节，用磁盘头 + 内存节重建 image-layout PE（`PointerToRawData=VirtualAddress`、`FileAlignment=SectionAlignment`），让 triage / Ghidra 能继续读。`delayMs` 让壳先解压；为 0 时在入口点 dump，拿到的是壳本身。`waitForExec=true` 时证据是**两级、且都不等于 OEP**：第一级 `oep signal` 是 kernel32 + ntdll 双层 hook（2026-11-20 起 `VirtualProtect`/`VirtualAlloc` 之外并列钩住 `ntdll!NtAllocateVirtualMemory`/`NtProtectVirtualMemory`，按来源归因记 `layer`，kernel32 调用方与 ntdll 直调者不重复记账）看到的首个「至少一页」可执行内存标记（EXECUTE 位，只记成功返回）；第二级 `entry` 是进程级 Stalker watch（2026-11-20 起覆盖 mark 时刻存活的全部线程与之后经 `ntdll!NtCreateThreadEx` 新建的线程，上限 16、首次命中即 unfollow）观测到的「控制流首次进入被标记区域」——命中线程可以是任意被 follow 的线程（`watchThread` 即命中线程，报告带 `watchThreads[]`/`followedCount`），命中时报告命中地址、指令文本与字节（按不可信数据包裹），超时未中显式报 `entry: none before the timeout` 并注明盲区，观测器失效显式报 `entry watch unavailable`，绝不静默回退成「只有标记」还宣称成功。两级证据仍然**不是严格 OEP finder**：区内命中也可能是壳自己的代码（报告以 `inside main module: yes/no` 区分），dump 时机与判断仍留给分析者。UPX 类就地解压对观测点不可见（节区映射即 RWX，信号/entry 显式报 none），UPX 请走 `rea_unpack`；加壳样本配 hook 长时间运行可能令 agent 停止响应——root cause 已定位（2026-11-19，39 轮 A/B 矩阵）：**Frida 17.26.3 Interceptor 钩住 `kernel32!VirtualAlloc` 后，进程退出路径死锁**（空回调仍挂、延迟安装仍挂、仅挂 VirtualProtect 从不挂、永不退出的样本同钩正常、死前 hook 零触发、偶发逃逸证实为竞态；属 Frida 层问题，插件不可修仅缓解，详见 `docs/reconstruction-plan.md` §13），加壳目标用短 delay（≤8000 ms，`waitForExec` 的 `timeoutMs` 超出部分被工具层硬夹）并优先解包工具。报告里的 entry/imports 数值来自磁盘 PE 头——加壳样本它们描述的是 stub 的表，不是解压后的程序。这是非 UPX 样本的通用路径，替代“只支持 UPX 就拒绝”的死角。`sandbox=true`（另需 `sandboxSampleExecution: true`）时样本经内核强制沙箱挂起启动、dumper 按 pid attach，delay=0 时在入口点（仍挂起）读取镜像——实测容器内 dump 成功。

**副作用观测**（`rea_side_effects`，opt-in）：双方在 Frida 钩子下各跑 `durationMs`，收集注册表建键/查询/写值/删值/关句柄（`RegCreateKeyExW/A`、`RegOpenKeyExW/A`、`RegQueryValueExW/A`、`RegSetValueExW/A`、`RegDeleteValueW/A`、`RegCloseKey`——W 与 A 字符集都钩，MinGW 样本常走 A 导出，实测只钩 W 时 A 调用零事件），且**每个句柄都解析成完整键路径**：钩内 open/create 建句柄→路径映射，其余句柄（事务 open、ntdll 直开、继承句柄）回落 `NtQueryKey(KeyNameInformation)`，统一归一为 `hk*` 简写（账户 SID 属主机身份，事件只留 `hku`/`hkcr` 简写）；预定义句柄按低 32 位归一——x64 下 `HKEY_LOCAL_MACHINE` 实测以 `0xffffffff80000002` 符号扩展形式到达，旧表按全值查找永远 miss（实测暴露后已修）；`RegCloseKey` 清映射，防止句柄值复用继承旧路径；解析失败如实回落裸句柄值，绝不编造路径。三条解析路径（钩内映射 / NtQueryKey 回退 / 带路径查询）由 gcc 夹具 e2e 钉在 `test/observe.test.js`。另有命名管道创建、服务创建、IPv4/IPv6 出站连接（`connect`/`WSAConnect` 的 sockaddr 解析，IPv6 含 scope 数字）与域名解析尝试（`getaddrinfo`/`GetAddrInfoW`/`GetAddrInfoExW` 记 `dns:resolve`，dnsapi `DnsQuery_W` 记 `dns:query`），按集合算 recall 与 precision。观测的是**尝试**而不是成功；钩子打在导出函数地址上，经 GetProcAddress/IAT 动态解析的调用同样可见。**宿主保护**（`blockSampleEgress`，默认开）：非回环连接目标在 onEnter 即被写入无效 sockaddr family，连接在真实发包前失败并记 `network:connect-blocked`，`::1`/`127.0.0.1` 放行——这是用户态 best-effort，不是沙箱。拦截实测（gcc 夹具，零外网）：单次 `connect(192.0.2.1:9)`（RFC 5737 TEST-NET，不可路由）只产生 `network:connect-blocked 192.0.2.1:9`、不产生 `network:connect`（文本与磁盘事件双断言），而 `::1`/`127.0.0.1` 在拦截开启下照常观测到 `network:connect`。实测窗口边界（frida 17.26.3 / Win11 26300，根因未查）：**首条 connect 族调用之后观察器在本进程内全局静默**，报告只覆盖该次调用与其之前的钩内尝试——窗口之后未列出的事件是**未观测**，不写成「没有发生」；拦截在同一个 attach 回调内改写 sockaddr，不改变该窗口。仍不可见/拦不住：绕过 ntdll 的直接系统调用、内核驱动、raw socket 直发 DNS/53、DoH/DoT（表现为普通 443 连接，查询内容不可见）、QUIC、UDP sendto（无 connect 事件；`getaddrinfo` 对真实域名发出的明文 DNS 查询包同样照发）、ConnectEx、样本自行启动的子进程；AF_UNIX/未知地址族按非回环拦截，可能误伤本机 IPC。报告文本中的机器名/账号/主目录路径已脱敏（`[HOSTNAME]`/`[USERNAME]`/`[USERPROFILE]`），full JSON 落盘保留原始值（本机文件）。ws2_32/dnsapi 已装载则在脚本加载期直接挂，未装载时经 attachModuleObserver + 轮询延迟挂载，竞态窗口内首个调用可能漏，挂载失败与窗口结束仍未装载的 watched 导出均以 warnings 显式呈现。`sandbox=true`（另需 `sandboxSampleExecution: true`）时双方改在内核强制沙箱内运行、观测器按 pid attach——容器内实测钩子正常触发（注册表事件可见）。用于「文件轨迹干净、但程序应当触碰机器状态」的场景。

**运行时轨迹**（`rea_trace_behavior`，opt-in）：目标与重建体在各自全新的临时目录里以相同参数执行，比较退出码、stdout、stderr 与运行目录内落盘文件（相对路径 + 内容哈希）。与探针共用同一策略门：`allowSampleExecution: true` 且每次 `confirm: true`；默认**没有沙箱**，样本保留网络访问。运行前把 `TEMP` / `APPDATA` / `LOCALAPPDATA` / `HOME` 重定向到各自运行目录，因此写到临时目录或用户配置目录的文件也会被计入（相对路径 `profile/...`）；同时把身份环境变量（`COMPUTERNAME`/`USERNAME`/`USERDOMAIN`，POSIX 为 `HOSTNAME`/`USER`）替换为中性固定值（`rea-sandbox`/`analyst`/`REAGROUP`），双方同值，对照公平——这只覆盖 getenv 类读取，`GetComputerNameW`/`GetUserNameW` 等 Win32 调用仍返回真实身份。`sandbox=true`（另需 `sandboxSampleExecution: true`）时双方改经内核强制沙箱启动（无能力 AppContainer + 禁 breakaway Job），沙箱启动失败按「样本未运行」如实报告、绝不回落无沙箱执行；launcher 自身的 `sandbox-diag.txt`/`sandbox-pid.txt`（含每次运行都不同的 pid/tid/SID）从文件比对中排除，不稀释平价分。注册表、服务、命名管道、网络对端仍在盲区，这条限制写进每次报告；报告文本已脱敏，full JSON 落盘保留真实路径（本机文件）。结果用 `rea_reconstruct action=trace-apply` 记入循环：轨迹低于 90% 时不允许 `converged`，已收敛的循环会被重新打开。

**内核强制沙箱**（`sandbox=true` + `sandboxSampleExecution: true`，默认全关）：`scripts/rea-sandbox.ps1` 以「无任何 capability 的 AppContainer 令牌（本 build 上 SECURITY_CAPABILITIES 属性被拒，走 NtCreateLowBoxToken）+ KILL_ON_JOB_CLOSE 且禁 breakaway 的 Job Object（挂起创建、先入 Job 再恢复）」启动样本，强制在内核（令牌检查 + WFP + Job 限制），不依赖用户态钩子——直连 `connect(192.0.2.1:9)` 在容器内 0ms 得 `WSAEACCES(10013)`，同机无容器对照是 21s 超时；子孙进程无法 breakaway（`CREATE_BREAKAWAY_FROM_JOB` 实测被拒 err=5）。诊断走 `rea-sandbox: key=value` 契约：有 `pid=`+`child-exit=` 且 `job-enforced=true` 即样本已运行（非零退出/看门狗超时是结果不是错误），无 `pid=`、`pid=` 之前出现 `error=`、或 `job-enforced=false` 即启动失败（fail-closed，绝不回落无沙箱 spawn；2026-11-20 起 assign 失败时 launcher 在恢复主线程前终止挂起子进程，不存在「只有令牌层在起作用但样本已运行」的降级结果）。清理以 `-TimeoutMs` 看门狗的 TerminateJobObject 为主，launcher 退出前若 job 内仍有孤儿孙进程会先终止整个 job（diag 打 `action=terminate-job reason=orphan-descendants`）；node 侧对已知 child pid 做名字核对后的 `taskkill /PID /T` 兜底。**勘误（2026-11-20）**：此前记录「外部杀 launcher 时 KILL_ON_JOB_CLOSE 不可靠（实测 2026-11-19）」归因有误——launcher 曾把零初始化的 limit 结构体原样传入 `SetInformationJobObject`，`LimitFlags` 从未被赋值，被测量的机制根本没有启用；属 launcher 缺陷而非 OS 行为。修复后实测（`test/sandbox.test.js`）：taskkill 仅杀 launcher（不带 /T），job 内样本在 5s 断言窗口内被内核回收。**诚实边界**：回环（`::1`/`127.0.0.1`）默认同样被容器拦截——豁免（CheckNetIsolation LoopbackExempt）实测需管理员（err=5），非管理员宿主上回环不通是已记录的限制；UDP sendto 不被该隔离拦截（实测照发）；内核驱动、侧信道、容器内再提权、DACL 已放行对象的 IPC 不在覆盖范围；防样本不防分析工具（外部 Frida 注入属预期，实测按 pid attach 容器内钩子/内存读取/缓冲区 dump 全部可用）。

动态证据接进循环（`rea_reconstruct action=dynamic-plan` / `dynamic-apply`）：`dynamic-plan` 按「是否通过参数写内存、是否原地变换、是否在循环里、函数大小」排序解码器候选，给出 RVA、参数下标与建议 dump 长度；探针跑完后用 `dynamic-apply` 提交 dump。**证据不是判决**：它把值记成额外真值源（T3 与 payload 都认），把已耗尽的循环重开一轮并补一次迭代预算，然后要求下一份草稿仍由对照来确认——不会因为拿到一个缓冲区就宣称 `converged`。这解决了静态对照的一个结构性偏差：运行时派生密钥不在文件里，正确重建也会被当成编造。

**静默姿态与本地化模式（2026-11-20）**：以上能力的「目标侧能观测到什么」已逐格入档（[`docs/detection-surface.md`](docs/detection-surface.md)：DS-1–DS-5 行 × 六列，每格带 file:line 与证据等级 [代码]/[实测引用]/[分析，未实测]）——静态层 / Ghidra 引擎档 / `rea_unpack` 目标零执行；动态路径的注入面、环境差异、令牌与网络行为差异如实标注，[分析，未实测] 格不冒充已验证。静态优先是默认姿态：`allowSampleExecution` / `sandboxSampleExecution` 默认关（双门禁 + 每次 `confirm`），`blockSampleEgress` / `redactIdentity` 默认开，默认安装只读字节、不执行目标。边界声明：不做主动规避反逆向/反调试机制的工具（隐藏调试器、patch 反调试检查、绕过授权/DRM 属于绕过保护措施，不在本插件能力内）；「静默」= 静态优先 + 最小侵入 + 检测面如实入档，不是对目标反逆向机制的对抗；内核驱动、侧信道、容器内提权、VMProtect 类强壳仍是盲区。**本地化模式用法**：侧栏「安全策略」的 `localizedMode` 开关（或配置行，默认 false）开启后，插件自身四类下载路径（检查更新 / 下载安装 / Ghidra / 外部引擎）在走到网络层之前逐条本地拒绝，错误信息写明离线准备方式（自放 pinned 归档、填 `GHIDRA_INSTALL_DIR` 或外部工具路径）；已安装/已缓存引擎照常可用，自定义镜像同样被拒。出站请求头仅 `user-agent: dsh-rea` 与 `accept`，不含主机名/账号/用户路径；逐通道审计与残余披露面（源 IP / TLS SNI、REA 子进程、Ghidra JVM）见「出站通道审计与本地化模式」与「已知边界」。

## 配置（cordis.patch.yml 的 `config`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `schemaProfile` | `compact` | 主子进程广告的 input schema 档位。`full` 会让 237 个工具的 schema 约 652 KB，不进模型上下文但会放大注册表。1.4.0 起完整定义由后台独立探测缓存，不必改这里。 |
| `outputSchemaProfile` | `off` | 主子进程不广告 output schema；后台探测子进程用 `full` 取回完整输出 schema 供 `rea_catalog({includeOutput:true})` 按需查看。 |
| `catalogProbe` | `true` | 激活后在后台起一个短生命周期子进程，缓存全部完整输入/输出 schema 与安全注解（约 3 MB 内存，零上下文开销）。失败只降级为 compact 模式，不影响激活。 |
| `imageCapture` | `true` | 把 REA 返回的 image / 二进制 resource 块写入产物目录并返回路径，不再只给占位文本。 |
| `toolCallTimeoutMs` | `900000` | 单次调用超时。REA 首次起 Ghidra/Hopper 可能几分钟。取消会话时请求会被 `notifications/cancelled` 撤回，不用等满超时。 |
| `maxBufferBytes` | `10485760` | stdio 单条消息上限（REA 自己的下限就是 10485760，传更小会被抬回下限）。 |
| `logLevel` | `info` | 子进程日志级别。 |
| `deferCatalog` | `true` | 把 237 个 REA 工具的 schema 延迟加载（不进入请求体）。置 `false` 恢复成全部常驻广告——只在确实需要模型直接看见全部 schema 时才这么干，代价是每请求多约 4.8 万 token。 |
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
| `networkEgressPolicy` | `warn` | 对上游标了 `openWorldHint`/`destructiveHint` 的 108 个工具的策略：`allow` 不干预、`warn` 记录审计、`deny` 直接拒绝。用于分析者侧的外联暴露控制，默认不破坏正常调用。管的是**桥接工具**的外联，不是插件自身的下载——后者见 `localizedMode` 与「出站通道审计」一节。 |
| `localizedMode` | `false` | 插件自身下载闸门（可关）：开启后，`lib/infra/update.js` 的检查更新与下载安装、`lib/infra/engines.js` 的 Ghidra 与外部引擎下载——即插件已声明的四类下载路径——在走到 `lib/infra/download.js` 之前逐条本地拒绝，错误信息写明离线准备方式（自放 pinned 归档或填 `GHIDRA_INSTALL_DIR`/外部工具路径）。已安装/已缓存引擎照常可用（缓存检测在门禁之前）。面板「安全策略」可改（与既有九个策略键同机制：面板优先于配置行）；回归断言见 `test/localized-mode.test.js`。**语义分工**：`localizedMode` 管插件自身出站，`networkEgressPolicy` 管桥接工具外联，两个闸门不混用；REA 子进程与 Ghidra JVM 是独立 OS 进程，不在本门禁覆盖范围内。 |
| `blockSampleEgress` | `true` | 样本执行期的用户态外联拦截（best-effort，可关）：`rea_side_effects` 观测期间，`connect`/`WSAConnect` 的非回环目标在 onEnter 即被写入无效 sockaddr family，使连接在真实发包前失败并记 `network:connect-blocked`；`::1`/`127.0.0.1` 放行照常观测。绕过 ntdll 的直接系统调用、raw socket、ConnectEx、UDP sendto（含 `getaddrinfo` 对真实域名发出的明文 DNS 查询）仍拦不住；`rea_trace_behavior`/`rea_memory_dump`/`rea_dynamic_probe` 不经过该观测器。双方运行在同一开关下，被拦是宿主行为不是行为差异，报告会注明。 |
| `sandboxSampleExecution` | `false` | 内核强制沙箱的总开关（独立于 `allowSampleExecution`，绝不因其隐式开启）：开启后，四个执行工具（`rea_trace_behavior`/`rea_side_effects`/`rea_memory_dump`/`rea_dynamic_probe`）可传 `sandbox: true`，样本改经 `scripts/rea-sandbox.ps1` 在无能力 AppContainer + 禁 breakaway Job Object 内启动，Frida 按 pid attach。容器内 `connect(192.0.2.1:9)` 被内核 0ms 拒绝（WSAEACCES 10013）；回环默认同拦（豁免需管理员，实测 err=5）；UDP sendto 不拦。沙箱启动失败一律 fail-closed（「样本未运行」），绝不回落无沙箱执行。 |
| `redactIdentity` | `true` | 宿主身份脱敏（可关）：工具输出文本里的本机机器名→`[HOSTNAME]`、账号名→`[USERNAME]`、本机主目录前缀→`[USERPROFILE]`（会话内可逆 restore；范围校验/inside() 在还原之后用真实路径执行，分页句柄照常可用）；同时把被执行样本的环境变量身份（`COMPUTERNAME`/`USERNAME`/`USERDOMAIN`，POSIX 为 `HOSTNAME`/`USER`）替换为中性固定值，双方同值保证对照公平。样本内嵌的**他人**路径（如 PDB `C:\Users\builder\x.pdb`）是证据，原样保留。`state`/full JSON 等落盘文件保留真实路径——它们是本机文件，分页经 `rea_read_artifact` 还原句柄。 |
| `trustedManifestKey` | 空 | minisign 公钥文本。设置后**只接受验签通过的 manifest 来源**（不再把 GitHub Release API 当兜底），验签失败或无 `.minisig` 时检查更新直接失败，绝不静默降级；侧栏显示实际生效的信任级别。配了公钥就必须发布 `update.json.minisig`。 |
| `playbookDir` | `~/.dsh/rea-playbooks` | 可信 playbook 脚本目录，只接受简单 `.mjs` 文件名。 |
| `playbookTimeoutMs` | `120000` | 单个 playbook 的墙钟上限（1s–600s）。 |
| `playbookMaxCalls` | `200` | 单个 playbook 允许发起的 REA 调用次数上限（1–2000）。 |
| `batchTriageLimit` | `50` | `rea_batch_triage` 单次最多处理的文件数（1–500）。 |

### 1.8.10 一条路由把整个插件按住了

1.8.3 给 `/rea/fs/list` 同时注册了 GET 和 POST 两个 `exact` 路由，本意是「宿主只认 GET 时也不会 405」。宿主按**路径**去重：

```
webserver: duplicate exact route "/rea/fs/list"
```

插件在加载阶段就抛错，面板和工具全都不出现。1.8.3 之后的所有版本都带着这个洞，包括刚发的 v1.8.9——单测覆盖的是处理器，不是「注册表里能不能有两条同路径」。

#### 改法

一条路由，两个方法：

```js
{
  path: '/rea/fs/list',
  methods: ['GET', 'POST'],
  async handler(request, response) {
    const overGet = String(request?.method ?? 'GET').toUpperCase() === 'GET';
    const target = overGet
      ? new URL(String(request?.url ?? '/'), 'http://localhost').searchParams.get('path') ?? ''
      : String((await readRequestJson(request))?.path ?? '');
    ...
  },
}
```

三点连带调整：

- 注册时**不传 `method`**。传了的话，只认单个方法的宿主会把另一半挡掉；方法校验移到 `guardRequest`，它现在接受数组。
- `guardRequest` 对 `GET`/`HEAD` 直接放行，不再要求 `content-type: application/json`——那是给跨站 POST 用的，不适用于只读查询。
- 日志里的方法标签改成 `GET|POST`，出错时不会打成 `undefined`。

#### 回归测试

`test/fs-browse.test.js` 新增两个用例，其中第一个用的假注册表**会在同路径第二次注册时抛错**，复刻宿主行为：

- `the plugin registers each path once, which is what the host enforces`
- `the single listing route answers GET and POST, and refuses the rest`（GET 走查询串、POST 走 JSON、PUT 得 405）

顺带把整张路由表打出来核了一遍：8 条，无重复，`/rea/fs/list` 是唯一一条不声明单方法的。316 个测试通过。

### 1.8.9 一个 238 MB 的 APK

上一轮是 Windows 安装包，这一轮是 Android：`app-complete-arm64-v8a-release.apk`，238,305,217 字节。第一份报告同样错得干脆：

```
verdict: possibly-obfuscated (confidence 0.45)
anti-analysis markers: peb-flags, cpu-hypervisor, sandbox-tools
next steps: Do not trust decompiler output yet: locate the OEP / unpack before static analysis.
```

一个 APK 没有 OEP。三件事同时错了：

| 错在哪 | 为什么错 |
| --- | --- |
| 把 deflate 当加密 | APK 是 ZIP，条目本来就是压缩的，熵 8.0 是**预期的**，不是混淆 |
| 把 PE 的反分析标记套上去 | `peb-flags` / `cpu-hypervisor` 是 Windows 特征，在 ZIP 里命中纯属字符串巧合 |
| 只读了前 64 MB | ZIP 的索引在**文件末尾**，读头等于什么都没读 |

#### 三处改动

| 模块 | 做了什么 |
| --- | --- |
| `lib/static/android.js` | 用文件句柄 seek 到尾部找 EOCD，读中央目录：652 条记录、v2 签名块、dex 数量、ABI 分布、未压缩体积。不整文件读，不解压，不执行 |
| `lib/static/axml.js` | 自己解析二进制 `AndroidManifest.xml`：字符串池（UTF-8/UTF-16）、start element、类型化属性。**不需要 apktool，也不需要 JVM** |
| `lib/static/triage.js` | 档案类格式不再跑 PE 判据：反分析标记、XOR 探针、未解析高熵区全部跳过；新增 verdict `android-package` |

顺带修掉两个真实的显示缺陷：`regionnull`（高熵区没有 RVA 时拼出了 `null`），以及档案报告里重复三遍的 `not parsed`。

#### 现在的报告

```
verdict: android-package (confidence 0.9)
android: ai.deepseek.harness.mobile 0.2.1-rc.209-complete (209) | minSdk 26 targetSdk 28
         | 1 dex, 15 native libs [arm64-v8a:15] | 652 entries, 252.6 MB uncompressed | signature v2+
permissions: 25 (INTERNET, ACCESS_NETWORK_STATE, REQUEST_INSTALL_PACKAGES, VIBRATE, RECORD_AUDIO, ...)
exported components: activity ...MainActivity; service ...PhoneControlService; receiver ...ProfileInstallReceiver
manifest flags: allowBackup, cleartextTraffic

experiments:
1. Decode classes*.dex with jadx and the manifest/resources with apktool - the manifest says this is
   ai.deepseek.harness.mobile 0.2.1-rc.209-complete, then feed the 15 native libraries back into rea_triage
   why: the dex is compressed bytecode and the manifest is binary XML, so neither appears in a string pass;
        the 15 .so files are ELF and are the part this tool can already read
   confirm with: offline: jadx -d <out> <apk> and apktool d -s <apk>; no engine state is needed
```

关于这个包本身，报告里能直接读出三件事：`targetSdk 28`（远低于 Play 当前要求）、`cleartextTraffic`（release 构建仍允许明文）、`REQUEST_INSTALL_PACKAGES` + `QUERY_ALL_PACKAGES` + 一个导出的 `PhoneControlService`。这些不是我猜的，是 manifest 的字节。

#### 边界

- **dex 没有反编译**。`AndroidManifest.xml` 我能自己解，Dalvik 字节码不能——那需要 jadx（或 baksmali），而 `jadx-headless-mcp` 是 MCP 服务端，不是 CLI，没法像 Ghidra 那样直接驱动。
- **15 个 .so 没有分析**。它们是 arm64 ELF，`rea_triage` 能读，但需要先解压出来——本轮没有写解压器，也没有装 apktool。
- `apktool 3.0.3` / `jadx 0.7.1` 仍是"可安装但未验证"的引擎，上一轮文档里的判断不变。

### 1.8.8 拿一个真实的 28 MB 安装包试了一遍

前面十一代对抗全是自造样本。这一轮换真东西：`Xingchen-1.0.13-windows-amd64-compatible-setup.exe`，28,583,971 字节。第一个结论就是错的。

#### 它说「可能加壳，去找 OEP」

```
verdict: likely-packed-or-protected (confidence 0.65)
entropy: overall 7.996 | high-block ratio 0.971
packers: none matched
```

真实情况：**Inno Setup 6.7.0 安装包**。`.text` 是 Delphi 写的普通 stub，最后 27,533,347 字节是 `zlb` 压缩载荷，落在最后一个节之后，加载器根本不会映射它。

熵 7.996 量的是那 27 MB 压缩数据，不是代码；「97% 的块是高熵」同理。于是报告把「这个文件大部分是压缩字节」读成了「代码被加密了」，再给出「别信反编译，先找 OEP」——一条不存在路。

#### 五个缺陷

| 缺陷 | 现象 | 改法 |
| --- | --- | --- |
| **容器没被识别** | 没有任何 packer 签名命中，却判定"可能加壳" | 新增 `lib/infra/installer.js`：按签名识别 Inno / NSIS / InstallShield / 7z / RAR / ZIP / PyInstaller / Electron，并读出版本号 |
| **熵算错了对象** | 全文件熵把载荷算进代码 | 增加 `mapped image` 熵（最后一个节为止），判定改用镜像熵 |
| **28 MB 里 5 个巧合** | 随机 dword 撞上字典哈希，被报成「5 个从哈希解析出的导入」 | 哈希命中必须成簇：≥3 条且相邻 ≤64 字节；D6–D10 的表是连续 dword 数组，一条不少 |
| **「120 sampled」其实是前 120 条** | 采样停在大文件开头，也就是 DOS 头与 `.text` 起始 | 32 个窗口均匀覆盖全文 |
| **伪代码里混日志前缀** | `12:33:24 INFO  ProbeAddress.java>` 出现在 C 代码第一行 | 逐行剥离 Ghidra 的 log4j 装饰（整行删除会删掉代码，前缀只出现在每段第一行） |

#### 现在的报告

```
verdict: installer-with-payload (confidence 0.9)
entropy: overall 7.996 ... | mapped image 7.003 over 1050624 bytes
container: Inno Setup installer 6.7.0 - 27533347 bytes of Inno Setup "zlb" compressed blocks after file offset 0x100800
toolchain: Delphi / C++ Builder (sections .itext + .didata/.edata)
strings: 120 sampled across 32 windows (ascii)
imports: 5 DLLs / 150 APIs (150 named)

experiments:
1. Extract the 27533347 bytes of Inno Setup "zlb" compressed blocks ... (Inno Setup installer 6.7.0),
   then run rea_triage on each PE in the result
   why: the payload is compressed archive data the loader never maps, so no function-level
        work on this Delphi / C++ Builder stub can describe the application
   confirm with: offline: 7z x or innoextract - nothing in this tool surface executes the payload
```

`container` 与 `toolchain` 是两个新字段；`nextSteps` 对这类样本的第一句改成「这是容器，不是被保护的二进制」。

#### 反编译本身是通的

用 1.8.7 的第一方引擎，直接反编译入口 RVA `0xb1e60`：

```
decompile_address rva 0xb1e60
engine: ghidra-local, cached (11.4s)
function: entry @ 004b1e60
verdict: decompiled

void entry(void)
{
  LPCWSTR lpLibFileName;
  ...
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
```

首次分析 28 MB 用了 125 秒，项目缓存后 11.4 秒。Delphi 的 SEH 初始化、`LoadLibrary` 调用都在，说明引擎对真实编译器产物没有水土不服。

#### 没做到的

- **载荷没有解开**：机器上没有 `innoextract`，也没有 `7z`。Inno 6 的 `zlb` 块头不是裸 zlib（`zlb\x1a` 之后既不是 `78 9c` 也不是 raw deflate），硬解会得到一个自造的、半对的提取器——比不做更糟。报告现在直接说「先解包」，并把这一步排在实验第一位。
- 因此**里面那个应用没有被分析**。安装器 stub 的导入表、反调试标记说的都是 Inno 的运行时，不是星尘客户端本身。

### 1.8.7 引擎跑不起来，那就自己开一个

1.8.6 结尾写着第五道门堵不上：Ghidra 必须在 `-projectPath` 里建 `.gpr` / `.rep`，而那个路径在 REA 的私有运行时里，参数由 REA 传、目录由 REA 建、DACL 由 REA 装。**结论是对的，方向是错的。** 当时只想把 REA 的那条路修通，没问一句：为什么一定要走 REA？

#### 同一个 Ghidra，换个启动者

`.tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat` 一直都在。绕开 REA 直接调它，项目目录放在插件自己可写的位置，五个门一个都不存在：

| 门 | REA 的路径 | 本插件自己启动 |
| --- | --- | --- |
| tmp / cache / config | 私有运行时内，JVM 不可写 | `_JAVA_OPTIONS` 指到自己的目录 |
| ghidra.log | REA 用 `-log` 固定 | 换成不带 include 的 log4j 配置，只写 stderr |
| 项目目录 | `-projectPath` 由 REA 指定 | 自己指定 |

拦路的不是权限，是三件小事，每一件都值得记下来：

- **Ghidra 拒绝任何以点开头的路径元素**（`Path element starting with '.' is not permitted`），所以 `~/.dsh/...` 一律不能用——这是它自己的规则，不是 REA 的；
- **安装路径含非 ASCII 时 log4j 起不来**：`generic.log4j.xml` 用相对 href include 兄弟文件，`jar:file:` URL 被百分号编码后 include 失败，启动即中止；
- **`-process` 后面不能跟项目名**：它接的是可选的*程序*名，传项目名会让 Ghidra 去找一个不存在的程序然后中止。

坏消息是第一次分析 360 KB 的 `notepad.exe` 要 219 秒；好消息是项目按文件版本缓存，之后每次 10–12 秒。

#### 两个新工具

`rea_probe_address` 现在有两档：引擎可用时真的读文件并命名，否则退回节表判断；输出里的 `engine:` 行说明是哪一档。

```
probe_address 0x409800 (kind=code)
rva: 0x9800 | section: .text | executable: yes
engine: ghidra-local, cached (11.2s)
name: tls_callback_0
verdict: code - 0x9800 is executable code in .text; named tls_callback_0
```

`rea_decompile_address` 是新的，也是这个项目第一次不靠别人的进程产出伪代码：

```
decompile_address rva 0x9800
engine: ghidra-local, cached (12.2s)
function: tls_callback_0 @ 00409800
verdict: decompiled

void __fastcall tls_callback_0(int param_1) { ... }
```

TLS 回调在 Ghidra 里通常只有符号没有函数体（`batch_decompile` 会报 "no procedure exists"），所以工具在需要时先反汇编、建函数，再反编译——这正是分析员手动做的那一步。

#### 规划层：优先用自己的引擎

`providers` 里多了一个 `ghidra-local`。规划器**优先**选它，不是当兜底：

> 被包裹的 provider 的「就绪」是对一个插件看不见的沙箱的猜测，第一次调用才是验证。1.8.6 的 D6 就死在这次验证上——它按「REA 的 Ghidra 就绪」发了探针，探针当场失败。自己启动的引擎要么跑通，要么当场说明原因。

效果：D6 从 89.0% 回到 100%，D7/D8/D9 的 `verify` 全部是引擎档并解析出 `tls_callback_0`。

#### 第十一代：导入表齐全，但是假的

十代全 100% 意味着这套阶梯不再有区分度。D10 换了个方向：**把导入表填满，让它看起来什么都有**。

26 个真实的 kernel32 / user32 / advapi32 导出，样本一个都不调用，紧挨着 D6 的 ROR13 真表。工具里有这么一行：`if (named >= 24) return imports;` ——「有 24 个具名导入就不必再翻哈希表了」。D10 就从这里走过去：**api 1/9、behaviour 4/6、84.4%**。

改法是承认那句话不成立：导入目录被填满是「名字被写过」的证据，不是「名字被写全了」的证据。现在无论目录多满都扫哈希表，两套来源分开计数并标注 `overlappingSources`：

```
imports: 3 DLLs / 35 APIs (26 named, 9 from hashes - the two sources name different functions)
```

规划里也多一步：`Decide which import source the loader walks`——两套都是真实导出，只有调用它们的代码能决定。

#### 评分：编造与「读到诱饵」不是一回事

D9 的 22 条噪声里，12 条是它自己种下的诱饵，2 条是从那些诱饵 URL 派生的 host，剩下 8 条就是控制代也有的良性片段（pdb、UA）。**工具一条都没编造**，它只是把文件里的东西读了出来。

旧算法把这 22 条一起算进 precision，扣了 42.1%。现在防守方像 `seal()` 一样用 `bait:` 声明自己种了哪些值，评分分开记：

| 指标 | D9 |
| --- | --- |
| noise | 22 |
| ambiguous（防守方种的） | 12 |
| fabricated（工具自己编的） | 10（8 条基线 + 2 条派生） |
| precision | 100% |

暴露在诱饵下仍然单列显示（`bait 12 (planted by the fixture)`），只是不再记到工具账上。

#### 十一代结果

| 代际 | api | behav | plan | verify | prec | score |
| --- | --- | --- | --- | --- | --- | --- |
| D0–D4 | 9/9 | 6/6 | – | – | 100% | 100% |
| D5 | 9/9 | 6/6 | yes | – | 100% | 100% |
| D6–D9 | 9/9 | 6/6 | yes | 引擎档 | 100% | 100% |
| D10 | 9/9 | 6/6 | yes | 引擎档 | 100% | 100% |

均值 **100%**，honesty failures 0。

#### 这套阶梯到此为止

十一代全满分，说明**这批代际已经测不出更多东西**了——继续加同类的变形只会继续满分。表里那个「weakest D1」是并列时的排序产物，不是信号。

真正还值得测的是另外几条轴：真实加壳样本（UPX / Themida）、真实语言的编译器产物（Go / Rust 的运行时结构）、以及**动态**路径（Frida 那一路至今没有任何一代覆盖）。这些不是「再来一代 D11」能解决的，得先有对应的样本与判据。

#### 遗留

- Android 侧：`jadx` 0.7.1 / `apktool` 3.0.3 / `wabt` 1.0.42 都是**可下载安装的托管引擎**（pinned + sha256），但本机一个都没装，也没有 APK 样本——所以不是「不支持」，是「接口在、执行仍走 REA、从未被验证」。
- `ghidra`（被包裹的那个）在这台机器上依然跑不起来；现在它只是不重要了，不是修好了。

### 1.8.6 那个缺口堵上了，后面还有一道

1.8.5 结尾说引擎还剩一个缺口：`ghidra.log` 写不进去。这一轮先把它堵上了——**然后撞上了第五道门**。

#### 日志缺口：堵上了

Ghidra 的日志 appender 写在 `generic.log4j.xml` 里，而 `log4j.configurationFile` 系统属性优先于它。换一份**不写文件**的配置（只留 stderr），日志路径是否可写就不再是启动前提。验证后错误确实消失了。

#### 第五道门：项目目录

下一行错误是：

```
java.io.IOException: 拒绝访问。
  at java.io.File.createNewFile(File.java:1045)
  at ghidra.framework.data.DefaultProjectData.init(DefaultProjectData.java:299)
  at HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:439)
```

Ghidra 要在 `-projectPath` 里建 `.gpr` / `.rep`，而那个路径同样在 REA 的私有运行时里。**这一层没有系统属性可以覆盖**：参数是 REA 传的，路径是 REA 建的，DACL 是 REA 装的。到这儿为止，前四道门（temp / cache / config / log）都能用 `launch.properties` 挪开，第五道不能。

所以换方向——不再试着把引擎撬起来，而是让 `verify` 不需要它。

#### `verify` 的两档

新增 `lib/dynamic/probe.js` 与自有工具 `rea_probe_address`：读文件、查节表，回答两个问题。

| 断言类型 | 问的问题 | 判据 |
| --- | --- | --- |
| `code` | 这个地址是可执行代码吗 | 落在 `IMAGE_SCN_MEM_EXECUTE` 的节里 |
| `pointer` | 这个 dword 指向可执行代码吗 | 指针值落在可执行节 |

规划器在引擎不可用时不再删掉探针，而是换执行者：

```
confirm with: inspect_address_context at RVA 0x9800 ... [ghidra: unavailable - ...]
probe: probe_address @ 0x409800 (code) [local structural check]
```

报告里同时保留 `blocked` 原因，所以「谁在检查」和「为什么不是引擎」都写在明面上。

#### 结果

| 代际 | verify | 得分 |
| --- | --- | --- |
| D6 | **NO**（声称引擎、引擎当场死） | 89.0% |
| D7 / D8 | `local`（结构自证） | 100% |
| D9 | `local` | 92.8% |

十代均值 **98.0%**，weakest D6，precision floor 42.1%，honesty failures 0。

#### 这不是免费分

本地探针会失败。测试里把 `.rdata` 里的派发表地址当成 `code` 去探，得到 `verdict: not-executable`，`verify` 记 0；把 `.rdata` 里的普通 dword 当成 `pointer`，得到 `not-a-code-pointer`。只有地址真的对得上断言类型才得分。

引擎档仍然更严：`tier: engine` 的探针必须解析出符号名，返回 `available` 但没名字一律 0。

#### 诊断：五个位置

`classifyEngineFailure` 现在按位置分类：`tmp` / `cache` / `config` / `log` / `project`。前四个是「装错了」，第五个是「这台机器上跑不了」，措辞不同。

### 1.8.5 那句「盐不可达」是错的

1.8.4 把 D8 记成「盐被密封，9 个 API 名没有任何静态方法能恢复」，并把它当作诚实的能力边界写进了文档。这一轮把它推翻了：**盐一直在文件里，只是工具读到了钥匙却没有用。**

#### 三处断点，一条链

D8 的配置放在 `cfg=deflate+xor;key=2b8d41f0;` 后面。手工打开只有三步：读 header 里的 key、解 DEFLATE、用 key 异或。

工具前两步都能做，唯独第三步没做：容器解压出来的字节是高熵，而 XOR 阶段只在第 1 层跑、且只试单字节 key。于是 `salt=0x5d3a91c7` 看不见，哈希表的 9 个名字解不出，报告写「算法未知」。

#### 改动

| 位置 | 改了什么 |
| --- | --- |
| `lib/static/strings.js` | 容器阶段读取 `cfg=…xor…;key=<hex>;`，用声明的 key 解 inflate 结果后再挖一层。限制 hex 2–8 字节、只在前 4 KiB 找，避免把无关文本里的 `key=` 当成指令 |
| `lib/static/api-hash.js` | `buildHashIndex` / `recoverHashedApis` 支持 `salt`：每个名字多一条 `hash ^ salt` 索引，算法标 `+salt`；`resolveImports` 透传 |
| `lib/static/structure.js` | `structureProfile(bytes, { salt })`，输出 `hashedApis.salt` |
| `lib/static/triage.js` | 先解字符串、提取 `salt=0x…`，再解析导入与结构；隐藏字符串列表优先保留 `cfg=` / `salt=` 行，不让截断把它丢掉 |
| `lib/static/plan.js` / `lib/surface/analysis-tools.js` | 报告写 `mul31-xor-2f with salt 0x5d3a91c7`，而不是把 `+salt` 当成算法名 |

#### 结果

D8：`api 1/9 → 9/9`，`behaviour 4/6 → 6/6`，**82.5% → 100%**。

十代均值 **97.9%**（上一轮 95.9%），weakest 变成 D6 的 89.0%（唯一一次 verify 假声明），precision floor 42.1%，honesty failures 0。历史代际一分未变——D0–D5、D7 仍是 100%。

#### 引擎：四个缺口，三个能绕，一个不能

顺手把 `verify` 为什么长期 `n/a` 查到了底。Ghidra 的 JVM 在 REA 的私有运行目录里要四个位置：`tmp`、`cache`、`config`、`ghidra.log`。

- 前三个可以用 Ghidra 自己的 `application.tempdir` / `application.cachedir` / `application.settingsdir` 覆盖——逐个验证过，错误会依次推进（temp → cache → config）；
- 第四个不行：REA 用 `-log <root>/ghidra.log` 传给 analyzeHeadless，Ghidra 据此 `setApplicationLogFile`，覆盖任何 `-DlogFilename`。

REA 在启动 JVM 前还会清空 `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS`，所以不改它的打包产物就进不去。`classifyEngineFailure` 现在会说出具体是哪个目录（`tmp` / `cache` / `config` / `log`），而不是笼统的「上游 Windows 限制」。验证完已把引擎配置原样恢复。

#### 边界

- 这条链只在**样本自己声明了 key 或 salt** 时生效。没有声明的盐仍然不可达——那是真的不可达，不是没试。
- `verify` 仍是 `n/a`（原因见上），健康账本继续按实际情况降级。

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

- 新增 `lib/infra/engine-health.js`：工具层从错误信封里取出 `provider_id`，把失败压成一行原因（`jvm-scratch-denied` / `jdk` / `timeout` / `native-unsupported`）并记账；
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

实现：`lib/infra/engines.js` 加 `providerReadiness()`（`where`/`which` 只定位、不启动引擎，Ghidra 走既有检测），`lib/static/plan.js` 把每条实验的 `confirm` 首词映射到 provider 并附 `ready`，`rea_triage` / `rea_batch_triage` 每次调用重新探测——中途装了 Ghidra 就会立刻显示 ready。

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
| 结构重建 | `lib/static/structure.js`：IAT 存在性、TLS 回调（运行在入口点之前）、调度表 `code pointer` 连片（控制流平坦化）、节区异常（W+X、raw=0、重叠） |
| 行为归因 | `lib/static/plan.js`：6 类行为带证据与置信度；哈希得来的名字标 `(hash)`，最高只给 `low` |
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

新增能力（`lib/static/crypto-recovery.js`、`lib/static/api-hash.js`）：

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

**实测驱动的字符串恢复**：`lib/static/strings.js` 在原有 ASCII 扫描之外补了四个通道——**双相位 UTF-16LE**（奇偏移宽字符串也能抓）、UTF-16BE、**单字节 XOR 解密**（带语义锚点 + 字母占比 + 每 key 上限，抑制明文位移产生的假串）、**base64 滑动解码**（容忍相邻字节粘连）。推导出的 IoC 会单独标为 `recovered` 并提示"误报率较高、需人工核验"，不混进确证清单。

**实测结果**（`npm run make-sample` 造结构化 PE32 + 干净对照 + 可运行 JS 孪生体，`npm run demo` 用真实装配跑全工具链）：

| 指标 | 第一轮 | 收紧后 |
| --- | --- | --- |
| 隐藏指标（XOR / 奇偏移 UTF-16 / 备用端点） | **0/5** | **5/5** |
| 追踪面 / 反分析 / IoC 类型 / 导入 / 能力 / 暴露矩阵 | 41/49 (84%) | **62/62 (100%)** |
| XOR 通道噪音条数 | 2527（假 email 7 条） | **16**（确证 email 1 条，5 条推导单列） |
| 干净对照样本 | 0 误报 | 0 误报（深字符串 13 条） |

**边界**：全部是静态字符串/导入表启发式——未使用的 SDK、加密配置、动态解析的 API 都可能导致误报或漏报；能力提示是"能做什么"而非"做过什么"，必须回到反汇编或运行时轨迹验证。除显式 opt-in 的动态探针与运行时轨迹外，插件不执行样本、不连接样本端点、不提供隐蔽注入，也不替代商业引擎的结构比对。XOR/base64 推导值误报率更高，一律单独标注。

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

下载与更新检查会读取 `HTTPS_PROXY` / `HTTP_PROXY`（含 `NO_PROXY`），通过 CONNECT 隧道走代理。Node 自己不认识这些变量，而很多本机代理只设置了系统代理，所以这一层是必要的；`localhost` / `127.0.0.1` 永远直连。代理凭证只随 CONNECT 头发给**用户自己配置的代理**，从不发给目标站；2026-11-20 起错误消息对代理串先剥 `user:pass@` 再落文本（`lib/infra/download.js` `stripProxyUserInfo`，此前 `invalid proxy URL:` 原样回显整串、redact.js 对 userinfo 无规则，属真实泄漏点，已由 `test/localized-mode.test.js` 钉住）。

## 出站通道审计与本地化模式

本节回答「这个插件自己往哪里发包」。全仓检索结论：运行时网络原语**只有 `lib/infra/download.js` 一处**（直连 `download.js:75`、CONNECT 隧道 `:100`、隧道内层 `:115`、TLS 握手 `:135`；UA 常量 `USER_AGENT = 'dsh-rea'` 在 `:27`，无版本号、无平台、无主机信息；两个请求头构造点在 `:174` 与 `:266`，均为字面量。行号以 2026-11-20 本轮为准，后续改动以函数名定位）；`client.js` 面板的 `fetch` 目标是同源 `/rea/*` 本地路由；仓库里没有 axios / net.connect / undici / 主动定时出站（`setInterval` 均为面板本地轮询与 helper 输出扫描）。每条通道逐项入档：

| # | 通道 | 触发方式 | URL / 主机 | 请求头 | 是否含用户标识 |
| --- | --- | --- | --- | --- | --- |
| 1 | 更新元数据（`lib/infra/update.js` `fetchLatest`） | 侧栏「检查更新」按钮（POST `/rea/update/check`），无定时自动检查 | `api.github.com/repos/xiaobaga281/dsh-rea/releases/latest` → `cdn.jsdelivr.net` / `raw.githubusercontent.com` 的 `update.json`（配签名钥时另取 `.minisig`） | `user-agent: dsh-rea`、`accept: application/json, text/plain, */*`（download.js:266） | 头与 URL 均不含主机名/账号/用户路径/序列号。固有标识只剩**源 IP 与 TLS SNI**，插件无法消除，如实列为能力边界 |
| 2 | 更新字节（`installUpdate`） | 侧栏「下载并安装」（用户点击） | GitHub release asset，镜像前缀 `ghproxy.net` / `gh-proxy.com` / `ghfast.top` / `hub.gitmirror.com` / `github.moeyy.xyz`（先 GitHub 直连） | `user-agent: dsh-rea`、`accept: */*`（download.js:174） | 同上 |
| 3 | 引擎下载（`lib/infra/engines.js`） | 侧栏准备按钮或 `npm run engine <tool>`（用户显式触发） | Ghidra 12.1.4 / JADX 0.7.1 / Apktool 3.0.3 / WABT 1.0.42 / WinLibs GCC：各 GitHub release；zig 0.17.0：`registry.npmjs.org` 双包。URL 均为源内钉死的字面量 + SHA-256 校验 | 同 fetchToFile | 同上 |
| 4 | CONNECT 隧道 | 仅当用户配置了 `HTTPS_PROXY`/`HTTP_PROXY` | 发往**用户自己的代理**：`host: <目标 authority>`，仅当代理 URL 带 userinfo 时加 `proxy-authorization: Basic`；隧道内层对目标站重建 GET 用同样的 UA/accept | 凭证只到代理、不到目标站；错误文本已剥离 userinfo（见上） |
| 5 | 面板 HTTP（`client.js` `api()`） | 面板轮询/按钮 | 同源 `/rea/*`（本地 DSH 宿主路由），非第三方出站 | 浏览器自身头 | 本机通信；载荷含引擎绝对路径（见「已知边界」） |
| 6 | 开发者时通道（非插件运行时） | 开发者显式命令，不在 `localizedMode` 门禁内——它们本身就是显式触发 | `scripts/fetch-corpus.mjs` 用系统 curl（默认 UA）到 `7-zip.org` / `the.earth.li` / `sqlite.org`；`scripts/publish-release.ps1` 带 token 调 `api.github.com` | curl 默认 UA / GitHub token | 仅开发者机器、显式运行时 |
| 7 | 已声明盲区（两条，不作零出站外推） | REA 子进程（vendored 上游 `rea-agents`）与 Ghidra JVM 是**独立 OS 进程**，其自身外联不属插件通道，本插件不可断言；`scripts/ghidra/*.java` 已 grep 确认零网络命中，但 JVM 内建更新检查类功能无法由插件关掉 | — | — | 前者受 `networkEgressPolicy=deny` 的 guard 层间接约束（仅拒上游标 `openWorldHint`/`destructiveHint` 的工具），后者无约束；两者均如实入档，不是「保证不出站」 |

**`localizedMode`（默认 `false`，配置行与面板均可设）**：开启后，上表 #1–#3 即插件自身已声明的四类下载路径（更新检查、更新安装、Ghidra、外部引擎）在走到网络层之前**逐条本地拒绝**——`checkForUpdate` 的门禁放在共享 promise 缓存之前（拒绝不进缓存、不污染缓存，关闭开关后真检查照常工作），`installUpdate` 在安装体首行拒绝，`installGhidra`/`installExternalTool` 在 `downloadFile` 之前拒绝并给出离线准备指引（自放 pinned 归档、填 `GHIDRA_INSTALL_DIR` 或外部工具路径）。已安装/已缓存引擎的缓存检测在门禁之前，照常可用。`localizedMode` 与 `networkEgressPolicy` 是两个不同面的闸门，语义不混用、枚举不合并（前者管插件自身下载，后者管桥接工具外联）。第三方/自定义更新镜像（`updateMirrors`）同样被拒——留「仅 GitHub 直连」例外会让闸门出现旁路，不做例外。回归断言（离线拦截底层连接，不打真实网络）见 `test/localized-mode.test.js`：请求头仅 `{user-agent, accept}` 且 UA 字面量等于 `dsh-rea`、头值不含本机 hostname/username/homepath 金丝雀、代理凭证只出现在 CONNECT 上、localized 模式下更新/引擎四路径与分析工具（`rea_triage`/`rea_export_report`）的 socket 调用计数为 0。**边界**：该测试进程看不见 REA 子进程与 Ghidra JVM 的 socket（见 #7），结论不外推成「整个插件零出站」。

## 安全边界

侧栏的 POST 路由可以改动引擎路径、可以触发几百 MB 的下载，因此按「有副作用的接口」对待：

- 方法必须匹配，请求体必须是 `application/json`——跨站表单和 `text/plain` 的 fetch 都无法在不触发预检的情况下做到这一点；
- 浏览器带上 `Origin` 时必须与 `Host` 一致，`Sec-Fetch-Site` 必须是 `same-origin` 或 `none`；
- 错误返回真实的 HTTP 状态码（400/403/405/413/415/500），而不是 200 + `ok:false`；
- 路径必须是绝对路径。

最后一条不只是形式问题：`REA_APKTOOL_COMMAND` 是 REA 会实际执行的命令，跨站写它等于把一次工具调用变成执行磁盘上任意可执行文件。

子进程也不再继承宿主的完整环境变量：只放行 `PATH`、`HOME`、`TEMP`、代理和证书相关变量，加上 REA 文档中的 `REA_*` / `HOPPER_*` 引擎变量。宿主的 API key、会话 token 不会进入第三方分析进程。子进程的工作目录固定为 `~/.dsh/rea-workspace`，分析过程不会弄脏被分析的项目。

出站姿态（2026-11-20 审计）：插件运行时的网络原语只有 `lib/infra/download.js` 一处，请求头仅 `user-agent: dsh-rea` 与 `accept`，不含主机名、账号或用户路径；代理凭证只随 CONNECT 发给用户自己配置的代理，错误文本先剥 `user:pass@`。`localizedMode=true` 时，插件自身的四类下载路径（检查更新 / 下载安装 / Ghidra / 外部引擎）在本地逐条拒绝——用法与逐通道审计见「出站通道审计与本地化模式」。REA 子进程与 Ghidra JVM 是独立 OS 进程，其外联不在本审计范围内，属已声明盲区。

## 代码结构

<!-- code-structure:begin -->
```
- index.js: Host half of `dsh-rea`.
- client.js: Sidebar half of `dsh-rea`: the environment panel, engine preparation, update controls and the security-policy switches.
- lib/dynamic/concurrency.js: A tiny semaphore for read-only REA calls.
- lib/dynamic/dynamic.js: Opt-in dynamic probing.
- lib/dynamic/memdump.js: Rebuild a PE file from a running process's memory image.
- lib/dynamic/observe.js: Side-effect observation through API hooks.
- lib/dynamic/probe.js: Local structural probe.
- lib/dynamic/sandbox.js: Kernel-enforced sample containment: AppContainer + Job Object.
- lib/dynamic/trace.js: Runtime traces: run a binary in a throwaway directory and record what it did.
- lib/dynamic/unpack.js: Static unpacking with UPX.
- lib/infra/artifacts.js: Artifact spill, change-control policy and audit trail.
- lib/infra/config.js: Config resolution and the child's environment.
- lib/infra/download.js: HTTP downloads and archive extraction.
- lib/infra/engine-health.js: What the plugin remembers about its engines.
- lib/infra/engines.js: Engine discovery and preparation: Java, Ghidra, JADX, Apktool, WABT.
- lib/infra/installer.js: What is appended after the last section, and what built the PE in the first place.
- lib/infra/manifest-signature.js: Optional detached signature for `update.json`.
- lib/infra/paths.js: Every filesystem location `dsh-rea` owns, in one place.
- lib/infra/policy-store.js: The security policy the sidebar is allowed to change.
- lib/infra/redact.js: Reversible redaction of this host's identity from tool output text.
- lib/infra/result-index.js: Cross-session result index and structured-result snapshots.
- lib/infra/runtime.js: The vendored REA runtime: checksum, unpack, and the bundled skill.
- lib/infra/schema-cache.js: Full-schema cache and progressive disclosure for REA's deferred catalog.
- lib/infra/update.js: Self-update: check the release feed, download through redundant mirrors, and swap the plugin directory.
- lib/infra/work-root.js: Where a first-party engine may keep its working files.
- lib/restore/autodraft.js: Automatic draft repair: turn the comparison's gaps into a new draft.
- lib/restore/baseline.js: Mechanical baseline: turn a decompiled function inventory into compilable C.
- lib/restore/build.js: Compile a reconstructed source with the plugin's own gcc.
- lib/restore/compare.js: Compare a rebuilt binary with the target it was reconstructed from.
- lib/restore/ghidra-local.js: A first-party Ghidra runner.
- lib/restore/recon.js: The reconstruction loop: evidence in, drafts out, terminal state always.
- lib/static/android.js: What is actually inside an APK.
- lib/static/api-hash.js: API-hash recovery.
- lib/static/axml.js: A reader for Android's binary XML (AXML).
- lib/static/behavior.js: Behaviour contract: what a binary declares it writes, keeps and touches.
- lib/static/cil.js: Bounded CIL method-body parsing and disassembly for managed assemblies.
- lib/static/containers.js: Container recovery: find data that is compressed or packed inside the file instead of merely encoded.
- lib/static/crypto-recovery.js: Key and blob recovery for static string analysis.
- lib/static/function-matching.js: Shared function-inventory helpers: the pairing primitives used by both the restoration compare (restore layer) and the interaction extractor (static layer).
- lib/static/identity.js: Sample identity: the facts that let one binary be linked to its family.
- lib/static/intel.js: Static intelligence over a sample: imports, indicators, tracking surface, anti-analysis techniques, capability profiling, and report sanitisation.
- lib/static/interaction.js: GUI interaction surface: what a binary's window layer declares it handles.
- lib/static/managed-internals.js: Tiny shared primitives for the PE/.NET byte parsers (lib/structure.js, lib/managed.js, lib/cil.js).
- lib/static/managed.js: .NET managed-assembly manifest, parsed locally from PE bytes.
- lib/static/plan.js: From evidence to a plan.
- lib/static/strings.js: Deep string recovery for static analysis.
- lib/static/structure.js: Structural recovery for targets that hide their shape, not just their text.
- lib/static/triage.js: Static triage for an unknown binary - the "first ten minutes" of reverse engineering that REA's tool surface does not cover at all.
- lib/surface/analysis-tools.js: The plugin-owned analysis tools that REA does not provide.
- lib/surface/dynamic-tools.js: The opt-in dynamic probe tool.
- lib/surface/export.js: Human- and machine-readable exports for REA's Evidence bundles.
- lib/surface/external-adapters.js: Capability adapters for tooling REA does not expose: TLS decryption, stream reassembly, protobuf raw decoding, and Windows debugging / ETW inventory.
- lib/surface/fs-browse.js: A directory picker needs a directory listing, and a directory listing is a filesystem read on the Host.
- lib/surface/intel-tools.js: Reverse-engineering and anti-tracking tools built on the local intel core.
- lib/surface/mcp-client.js: A stdio MCP client for one REA child process.
- lib/surface/memdump-tools.js: The opt-in memory-image dump tool.
- lib/surface/observe-tools.js: The opt-in side-effect comparison tool.
- lib/surface/playbook-worker.mjs: Playbook worker.
- lib/surface/playbook.js: Trusted playbook runner.
- lib/surface/recon-tools.js: The reconstruction loop's comparison tool.
- lib/surface/registry.js: A reconciliation layer over the Host's tool registry.
- lib/surface/routes.js: The sidebar's HTTP surface.
- lib/surface/tools.js: The tool surface: one bridge per REA tool, plus the two tools this plugin owns (`rea_catalog` and `rea_doctor`).
- lib/surface/trace-tools.js: The opt-in runtime behaviour comparison tool.
- lib/surface/unpack-tools.js: The static unpack tool.
- lib/surface/workflow-tools.js: Plugin-owned workflow tools: cross-session result queries, corpus triage, local coarse diff, fuzz harness templates, and the trusted playbook runner.
- scripts/adv-gates-summary.mjs: Summarize the function-level restoration gates across all targets.
- scripts/capability-demo.mjs: End-to-end capability dry-run: build test samples, assemble the real plugin against a fake host (which still starts the real REA child), run the local analysis tools over them, and score the findings against a known e...
- scripts/concurrency-probe.mjs: Real-child concurrency evidence for the 157 read-only tools.
- scripts/corpus-scan.mjs: Real-world capability scan.
- scripts/duel/attacker.mjs: Attacker persona: use the shipped product, not the library internals.
- scripts/duel/defender.mjs: Defender persona: keep making the target harder.
- scripts/duel/score.mjs: The duel's scoring rules, kept free of filesystem and console work so the rules themselves can be tested instead of inferred from a table printed by a CLI run.
- scripts/duel/truth.mjs: Shared ground truth for the duel.
- scripts/duel.mjs: Two-persona duel.
- scripts/fetch-corpus.mjs: Real-world corpus fetcher.
- scripts/harden-ladder.mjs: Hardening ladder: measure what the analyser actually recovers as a target gets progressively better at hiding.
- scripts/host-matrix.mjs: Host compatibility gate.
- scripts/install-engine.mjs: Prepare one engine from the pinned release list, the same path the sidebar uses.
- scripts/make-sample.mjs: Build reproducible test samples for a capability dry-run.
- scripts/recon/specimen.mjs: R0–R5 specimens: real compiled targets with a source-level truth.
- scripts/recon-restore.mjs: Function-level restoration review against a real target.
- scripts/recon.mjs: Reconstruction loop report: R0–R5.
- scripts/triage-baseline.mjs: Triage calibration report.
- scripts/update-code-structure.mjs: Generate the README "代码结构" block from the modules themselves.
- scripts/update-manifest.mjs: Regenerate `update.json` - the metadata fallback the plugin uses when `api.github.com` is unreachable.
- scripts/duel/attacker.mjs: Attacker persona: use the shipped product, not the library internals.
- scripts/duel/defender.mjs: Defender persona: keep making the target harder.
- scripts/duel/score.mjs: The duel's scoring rules, kept free of filesystem and console work so the rules themselves can be tested instead of inferred from a table printed by a CLI run.
- scripts/duel/truth.mjs: Shared ground truth for the duel.
```
<!-- code-structure:end -->

## 测试

```bash
npm test          # node --test，439 个用例（完整门禁）
npm run test:smoke        # 纯 JS 快速反馈层（42 个文件，几秒出结果）
npm run make-sample       # 生成可控 PE32 / 干净对照 / JS 孪生体测试样本
npm run demo              # 真实装配跑全工具链并输出命中率报告
npm run host-matrix       # 真实子进程，三种宿主模式的发布门禁 + 文档数字校验
npm run concurrency       # 真实子进程并发压测（无闸 vs 限流）
npm run triage-baseline   # 初筛合成/有标签语料校准
```

**测试分两层**：`npm run test:smoke` 是**纯 JS 层**——42 个测试文件（显式清单写在 `package.json` 的 `test:smoke`），不编译夹具（无 gcc）、不碰 Frida/动态就绪、不起子进程、不开真实 socket（`localized-mode.test.js` 的 http/https/tls 全部是 `t.mock` 打桩），适合改完代码几秒内拿反馈；`npm test` 仍是**完整门禁**，在 smoke 之上叠加需要真实编译器/Frida/子进程的 live 测试（baseline、build-compare、dynamic、install、memdump、observe、recon、restore、sandbox、semantic-hypothesis、trace、unpack 这 12 个文件只在完整层跑）。归层判据与清单由 `test/smoke-purity.test.js` 钉住：smoke 文件出现 `node:child_process`、`node:net`、真实 `.listen(`、`compileC`/各类 readiness 依赖即红；新测试入 smoke 先过这条纯度判据，再同步 `package.json` 的显式清单与该测试内的名单。

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

- 还原对照的 T2 以**函数清单**为单位：伪代码相似度与 CFG 形状（基本块/边/分支/回环/扇出）各占一半；清单上限可配（默认 48，最多 200，`--functions` / `functions` 参数），超出会标明截断。清单与反编译结果按「文件哈希 + 上限 + 脚本版本」缓存在引擎工作目录，重复对照不再重新分析同一文件。首次分析启用多核并设 **180 秒分析上限**：超时后仍对已识别函数执行脚本，并在结果中显式标注 `analysisTimedOut`，不静默截断。清单不可用时退回入口函数并说明原因。
- 编译器不同的目标（例如 MSVC 构建）伪代码天然更低分，报告会写明这一限制。
- 还原输出在对照收敛后也只声明「与目标在 T1–T3 层一致」，不声明「这就是原源码」——等价的源码可以编译出不同的二进制。
- 运行时派生密钥的封存区静态不可达：循环能还原解码逻辑，不能还原秘密本身；终态会写 `unreachable` 并移交动态实验计划，不编造配置内容。
- 构建引擎的两种实现（WinLibs GCC / zig cc）目标同为 x86_64-windows-gnu；`rea_reconstruct` 的每轮记录都带实际编译器名，不把两种引擎的结果混算。
- 执行路径有四条：`rea_dynamic_probe`、`rea_trace_behavior`、`rea_memory_dump` 与 `rea_side_effects`。四者默认关闭，需 `allowSampleExecution: true` + 每次 `confirm: true`；样本在用户机器上真实运行，**没有沙箱**。其余所有分析路径仍然只读字节、不执行样本。宿主保护默认开、均可关：`blockSampleEgress` 只在 `rea_side_effects` 的观测器里把非回环 `connect`/`WSAConnect` 在真实发包前打断（用户态 best-effort——绕过 ntdll 的直接系统调用、raw socket、ConnectEx、UDP sendto、内核级逃逸仍拦不住，且另外三条执行路径不经该观测器）；`redactIdentity` 把工具输出里的本机机器名/账号名/主目录路径换成 `[HOSTNAME]`/`[USERNAME]`/`[USERPROFILE]` 占位符（会话内 restore 可逆，范围校验在还原后用真实路径执行），并遮蔽被执行样本的环境变量身份（只覆盖 getenv，`GetComputerNameW`/`GetUserNameW` 等 Win32 调用仍见真值）。`state`/full JSON 落盘文件保留真实路径——它们是本机文件；样本内嵌的他人身份串（如 PDB 构建机路径）是证据，不脱敏。
- **插件自身的残余披露面（如实入档，不宣称已脱敏）**：`redactIdentity` 只替换本机机器名、账号名与主目录前缀三个精确串——**非 home 前缀的绝对路径**（分析者自选的 work-root、目标文件路径）不在脱敏规则内，会原样出现在工具输出里；面板 `/rea/environment` 载荷与宿主日志含引擎安装路径/更新安装目标路径，消费者是本机浏览器与本地日志，不进模型会话；磁盘产物按设计保留原文（spill 发生在脱敏之前、动态四件套 full JSON、`writeBinary` 二进制证据）。插件自身出站的通道清单、请求头构成与用户标识结论见「出站通道审计与本地化模式」一节；REA 子进程与 Ghidra JVM 的外联属独立 OS 进程，为已声明盲区。
- `rea_memory_dump` 的 entry 观测有两条已声明的盲区，`entry: none` 一律不得读成「没有发生」：①watch 覆盖面——2026-11-20 起为**进程级** Stalker watch：mark 时刻存活的全部线程 + 之后经 `ntdll!NtCreateThreadEx` 新建的线程（onLeave 按起始地址过滤 frida 系模块、上限 16、首次命中即 unfollow），多线程壳「worker 线程标记、别的线程跳入」的场景已由多线程 gcc 夹具实测命中（`test/memdump.test.js`，修复前该场景 entry 如实报 none）；仍属盲区：mark 与新建线程 onLeave 之间的竞态窗口、硬编码 syscall 建线程、超上限后 coverage 记 `partial`（`watched thread`/`watchThreads`/`followedCount` 写进报告）；②hook 面——2026-11-20 起为 **kernel32 + ntdll 双层**：`kernel32!VirtualProtect`/`VirtualAlloc` 之外并列钩住 `ntdll!NtAllocateVirtualMemory`/`NtProtectVirtualMemory`，壳经 `GetProcAddress(GetModuleHandleW("ntdll.dll"), ...)` 直调 ntdll 导出的标记已可观测（直调 gcc 夹具实测：修复前无任何 exec-mark，修复后 `oep signal: NtProtectVirtualMemory ... layer=ntdll` 且 entry 命中；kernel32 调用方按来源归因仍记 `VirtualAlloc`/`VirtualProtect`，不重复记账）；**仍盲**：纯 shellcode 直统调用——`syscall` 指令不经过任何 ntdll 导出，两层钩子都看不见，如实声明不宣称覆盖。不对 VMProtect/虚拟化壳作任何宣称。
- `rea_memory_dump` 的观测点对 **UPX 类就地解压**永不触发（真实样本实测）：UPX 5.3.0 把节区在**映射时**就标为 RWX，stub 解压全程不发起任何 `VirtualProtect`/`VirtualAlloc` EXECUTE 标注，`oep signal` 与 `entry` 会显式报 `none`——这是观测点盲区，不是失败回退，UPX 应走 `rea_unpack`。另有实测失效模式：kernel32 hook 存在时，UPX 加壳样本运行约 8–20 s 后 Frida agent 停止响应（连 `recv('dump')` 都不回，进程仍存活）；后续二分把 root cause 收窄到 **hook `kernel32!VirtualAlloc` 本身即可让不加壳的 gcc 样本也挂起不退出**（12 s 持续存活、agent 不回 dump 请求；只挂 `VirtualProtect` 则 0.36 s 正常退出），验证员再补 where.exe / cmd.exe / where 等系统程序的同样观测——**失活不依赖样本类型，hook VirtualAlloc 是充分条件**，与 UPX 无关，VirtualAlloc hook 是 exec-mark 观测点不能移除——T3 定位实验（2026-11-19，A/B 矩阵 34 轮 + S5 确认 5 轮，gcc 夹具 sleep-exit / sleep-forever / sleep-5s-exit / alloc-tramp + where.exe，frida 17.26.3）已把 root cause 钉到 **Frida Interceptor 层**：只挂 `VirtualAlloc` 即挂（gcc 样本 3/3），只挂 `VirtualProtect` 从不挂（3/3，0.5s 内正常退出）；**空回调仍挂（3/3）**——排除插件侧回调 JS（note/send/对象分配）诱因；**延迟 300ms 安装仍挂（3/3）**——排除 loader 期安装时机。机制为**进程在 hook 存在下退出时死锁**：S5（Sleep 5s 后退出）样本 agent 心跳 1.3–4.4s 正常、退出尝试（~5.3s）后永久静默、8.3s 的 dump 请求无回执、进程存活至被 helper 击杀（进程表全程 present），且死前 hook 零触发（计数=0）——不是回调累积所致；永不退出的样本同 hook 下全程正常（sleep-forever 与 alloc-tramp 均 dump-ok，exec-mark 0.28s 命中）。偶发逃逸（where.exe 1/6、A6×S1 1/3 正常死亡）证实这是竞态而非确定性行为。属 Frida 17.26.3 层问题，插件不可修、仅缓解；零外网纪律下未向上游检索/提 issue，留待有网环境。缓解已写成参数保证：加壳样本的 `delayMs` 与 `timeoutMs` 都应 ≤8000 ms（工具参数描述内注明），并优先用解包工具；T3 后 `waitForExec=true` 的 `timeoutMs` 由工具层**硬夹到 8000 ms**并在结果文本注明（`lib/surface/memdump-tools.js` execute 内，超过部分只会延长显式失败）；`waitForExec` 对该加壳样本失败 3/3，delay 路径实测仅短 delay（≤8 s）可用。这些失败以通用超时收场，但错误输出附带 helper warnings（hook/脚本事件），能自证期间发生了什么；进程**真**死亡则显式报 `the process exited before the dump (…; entry: none)`（detached 信号 + 进程表轮询双路检测，agent 假死不冒充死亡）。
- 机械基线为了让反编译输出能编译，会放宽整型到指针的转换（`-Wno-int-conversion` 等）；它测的是控制流与导入的还原，不是类型重建。运行时底噪按「空程序同工具链编译」与「目标全桩版本」实测扣除，不手写白名单；载荷分只认指标形态（IoC/水印），普通字符串不冒充满分。
- WinLibs GCC 16.2.0 已在本机完成安装并真实编译通过（含非 ASCII 工作路径修正：GNU ld 会写坏中文路径，编译改用相对文件名）；`npm run engine gcc` 与 zig 备用路径均可用。解包/校验/就绪另有合成归档单测覆盖。
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
- .NET/managed 能力是**元数据清单 + 有界 CIL 反汇编**，不是 CIL 反编译，不还原 .NET 程序逻辑：`rea_triage` 的 `structure.managed` 给出 CLR 头、程序集名/版本、模块、类型与方法名清单（默认 64 类型 × 32 方法封顶，另有资源与全部表行数，截断有标注）；`managedCil: true` 时附加 `structure.managed.cil`——逐方法 CIL 指令清单（操作码表取自本机 .NET `System.Reflection.Emit.OpCodes`，非凭记忆转写；System.Data.dll 真实方法体实测解码零未知操作码）、token 解析（类型/方法/字段/用户字符串）、P/Invoke 面（ImplMap，mscorlib 实测解析出 kernel32/api-ms 条目）与 EH 子句（ilasm try/catch/finally 夹具实测钉死布局），默认 48 方法 × 400 指令封顶。它回答「这个方法调了什么、用了什么字符串/字段、走了哪些原生 API」，不重建表达式与控制流；混淆器改名后清单只如实列出改名结果，语义归因交上游 `inspect_managed_*` 或人工；NativeAOT / ReadyToRun 单文件发布没有可走的 `#~` 流，只会得到 CLR 头 + `metadata: null` 注记，属声明盲区。CLR 头的 StrongNameSignature 按**实测布局**（+32/+36、cb=72）读取而非 ECMA-335 正典（64 字节、+24）——差异由 ilasm 夹具与 System.Data.dll 双语料回归钉死在 `test/managed.test.js`，`snRva+snSize==metadataRva` 是判别依据。
- **注册表全路径解析是 best-effort，不是保证**：`rea_side_effects` 的句柄→路径解析在钩内 open/create 命中映射、其余回落 `NtQueryKey(KeyNameInformation)`；句柄没有查询权限、或解析调用失败时，事件如实回落为裸句柄值（`0x…`），不编造路径。x64 预定义句柄按低 32 位归一（`0xffffffff80000002`→`hklm`）；每用户配置单元归一为 `hku`/`hkcr` 简写，账户 SID 不进事件文本。`RegCloseKey` 清映射防句柄复用串路径；未被钩住的关闭路径（如 `NtClose`）不清映射，属声明盲区。
- **ETW/内核回调观测在非管理员会话不可用（2026-11-20 可行性尖刺实测，维持声明盲区）**：过滤令牌（Medium Mandatory S-1-16-8192，`BUILTIN\Administrators` 仅 deny-only，`whoami /priv` 无 profile/trace/debug 特权，`net session` rc=2）下，内核级 ETW 三栈一致拒绝——`logman` 启动 Kernel-Process / Kernel-File / Kernel-Network 与 NT Kernel Logger 均 rc=5「拒绝访问」，`StartTraceW(SystemTraceControlGuid)` rc=183（内核 Logger 全局单例被系统会话占用），PowerShell `New-EtwTraceSession` 明确要求管理员特权；普通（非内核）实时 ETW 会话同样建不起来（rc=5），「非管理员用用户态 provider」的前提不成立。内核回调（`PsSetCreateProcessNotifyRoutineEx`/`ObRegisterCallbacks`/`CmRegisterCallback`）无用户态 API，需内核驱动 + 签名，属改架构，不做。对照组：同会话 Frida 用户态钩子（`kernel32!Sleep`）正常命中——非管理员观测能力仍在既有用户态钩子层。提权后可用的正向半边未实测（过滤令牌无法非交互自助提权），如实标注；证据存档 `.workbuddy/etw-probe/`。

### 检测面与静默姿态

每条目标执行/观测路径的「目标侧能观测到什么」按 [`docs/detection-surface.md`](docs/detection-surface.md) 矩阵逐格入档（每格带 file:line 与证据等级：[代码] / [实测引用] / [分析，未实测]）：基线行三种形态（本地静态层 / Ghidra 引擎档 / `rea_unpack` 文件变换）目标零执行即目标侧零检测面；动态五行覆盖 `rea_trace_behavior`（裸 spawn 与 sandbox 两档）、`rea_dynamic_probe`、`rea_memory_dump`、`rea_side_effects`，六列为进程存在/被注入/被调试通道/环境异样/令牌特殊/行为差异；DS-5 单列宿主侧痕迹（powershell/icacls/CheckNetIsolation/Ghidra JVM/upx/python-Frida——目标侧看不见、宿主 EDR 可见）防混淆。**边界声明**：本插件不做主动规避反逆向/反调试机制的工具（隐藏调试器、patch 反调试检查、绕过授权/DRM 属于绕过保护措施，不在本插件能力内）；「静默」的实现方式 = 静态优先 + 最小侵入 + 检测面如实入档，不是对目标反逆向机制的对抗。sandbox 档对「静默」是**更显眼**而非更隐蔽（令牌/网络/桌面都是样本可感知的硬异常），它的价值是宿主防护，两个维度正交。内核驱动、侧信道、容器内提权、VMProtect 类强壳仍是盲区；矩阵中标注 [分析，未实测] 的格子（如反调试 API 通道不触发）是机制推断，不冒充已验证。
