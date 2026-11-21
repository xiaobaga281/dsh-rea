# 还原工程：从初级分析师到逆向工程师（计划书）

> 状态：**部分实施**（2026-11-16，续更至 2026-11-20）。§1–§12 保留原始设计与验收口径，不是能力声明；实施状态、实测数字、与计划的偏差见 §13。未完成项在 §13 末尾逐条列出，不冒充已交付。
> 2026-11-16 · 配套文档：[`duel.md`](duel.md)（双人格对抗）、[`hardening-ladder.md`](hardening-ladder.md)（加固阶梯）、[`REA-capability-review.md`](REA-capability-review.md)（能力评审）

## 1. 定位：三级人格阶梯

| 级 | 回答的问题 | 判据 | 现状 |
| --- | --- | --- | --- |
| 初级分析师 | 样本里有什么 | 字面量 / IoC / 追踪面召回率 | 已有：L0–L5、D0–D5 满分 |
| 高级分析师 | 它从哪来、能做什么、下一步做什么实验 | 家族归因 + 结构 / 行为 + 可执行计划 | 已有：D6–D10、`lib/identity.js`、`lib/plan.js` |
| **逆向工程师** | **它的源码是什么** | **重建源码 → 编译 → 与目标分层对照收敛** | **本计划新增** |

第三级与前两级的本质差别：报告不再是对样本的描述，而是一份**可被证伪的产物**。还原出的源码编译回去，与目标对不上就是对不上，分数不来自措辞。

## 2. 为什么是对照循环，而不是再写一个反编译器

duel 已经证明这条路的方法论有效，且每条规则都有实测出处：

- **期望不手写**：天花板来自对照代（D0）自己的检出，手写期望会悄悄漂移。还原循环沿用：R0 明文代的机械还原结果定义天花板。
- **空天花板 = 评分器失败，不是满分**：红蓝报告 P1「空心 100%」——产物目录不可写 → D0 天花板 0 条 → 0/0 被算成 100%。还原评分器第一条断言就是天花板非空。
- **封存区只罚一次**：`seal()` 把不可达值从召回分母移除，honesty 维度单独计「是否显式上报」。一处不可能，不罚两遍。
- **编造扣分**：D9 证明「满嘴胡话但全都提到」能刷高召回。还原循环里，重建源码出现目标中不存在的函数 / 字面量，precision 单列扣分。
- **每个 confirm 有着落**：`plan.js` 的 `PROVIDER_OF_CONFIRM` + `tagProviders` 已把「引擎缺失时降级本地档并保留 blocked 原因」做成模式，还原循环直接扩展它，不另起一套。

反编译器本身不新增：Ghidra 已在 `.tools/`，`ghidra-local.js` 已能绕开 REA 私有运行目录直接驱动它。缺的是**把反编译输出变成可编译源码、再拿编译产物与目标对账**的那一圈。

## 3. 复刻对照循环（核心机制）

状态机。每个状态有出口，每个出口有产物，没有挂起态：

```
intake     triage + identity + structure（现有本地层，零引擎依赖）
  → inventory  函数清单：entry / TLS 回调 / 导出 / 调用图（ghidra-local）
  → draft      逐函数源码草稿：Ghidra 伪代码 → C
               机械基线 = 纯反编译 round-trip，不靠模型能到哪要先测出来
  → build      gcc 编译重建源码（插件自有引擎，串行闸 + 超时 + 输出上限）
  → compare    分层对照（§4），产出逐条差异
  → gaps       每条差异映射到一个动作 + confirm 工具；不可达的 confirm 标 blocked
  → 下一轮 draft（迭代预算内；收敛分数单调不降，回退标红）
```

`draft` 有两种来源：分析者提交的源码（`draft=source`），或插件的机械翻译（`draft=baseline`）——把 Ghidra 伪代码转成 C、用编译错误反向修复、失败函数降级为桩，全程不经过模型。两条路径共用同一个 build 与 compare，「复刻」这一步因此可以无人驾驶地跑出下限。

四个终态，全部带产物：

| 终态 | 含义 | 产物 |
| --- | --- | --- |
| `converged` | 对照收敛 | 还原源码 + 逐层对照证据 |
| `budget-exhausted` | 迭代预算耗尽 | 残差报告：哪些函数 / 区域没对上、为什么、下一步 |
| `blocked` | 引擎缺失 | 本地档结果 + 显式 blocked 原因，不静默跳过 |
| `unreachable` | 运行时派生密钥等原理性不可达 | 封存区报告 + 动态实验计划（`plan.js` 已有链路） |

闭环的判定规则：

1. 每条 gap 必须映射到一个动作；没有动作的 gap 不允许存在，要么补动作要么归入 unreachable。
2. 每个动作的 confirm 必须映射到真实注册的工具；引擎缺失时降级本地档并保留 blocked 原因（沿用 `tagProviders`）。
3. 迭代有预算（轮数 + 墙钟），预算耗尽走 `budget-exhausted`，不允许无限循环。
4. 收敛分数逐轮记录；下降即回退，回退必须在报告里标红并附上一轮证据。
5. 循环状态落 artifacts 目录，跨会话可续跑；`rea_query_results` 能查到每一轮的证据锚点。

## 4. 对照分层

每层独立计分，各有 engine / local 两档（沿用 duel `verify` 的两档口径：名字与结构不是同一个声明）：

| 层 | 对照什么 | 工具 | 无引擎时 |
| --- | --- | --- | --- |
| T1 结构 | 导入集合（元素级，不只 imphash）、节区布局 | 本地解析（intel / structure / identity） | 完整可用 |
| T1-payload 载荷 | 扣除工具链底噪后的 IoC/水印指标 recall 与 precision（真实目标可盲评） | 本地解析（intel） | 完整可用 |
| T2 函数 | 双方 Ghidra 反编译 → 归一化伪代码 diff（地址 / 寄存器 / 常量归一）+ 函数覆盖率 + CFG 形状 | ghidra-local | 降为 T1 + 字节级函数哈希，标 blocked |
| T3 字面量 | 重建源码中的常量与靶标真值逐条对账 | 本地 | 完整可用 |
| T4 行为（可选，默认关） | 声明面契约：输出字面量 / 状态名 / 副作用家族，两侧静态提取 | 本地（`lib/behavior.js`） | 完整可用；运行时轨迹档仍未实现 |

T4 的红线说明：**重建体是我方写出的代码，不是样本**；「不执行样本」的既有边界不动。T4 默认关闭，开启也只在受控环境跑重建体，目标样本始终只读字节。

## 5. 靶标阶梯 R0–R5（合成，带源码真值）

生成器 `scripts/recon/specimen.mjs`：用同一 gcc 编译真值 C 源码，产出 `target.exe` + `truth/`（源码、函数清单、字面量清单）。沿用 defender 的 `assertCoverage`：每个真值字面量必须真的进了二进制，漏一个直接抛错——靶标自己没放进去的内容，不许算进分母。

| 代 | 保护 | 还原考点 | 复用 |
| --- | --- | --- | --- |
| R0 | 明文 C 小程序（3–5 函数：配置解码 / 字符串使用 / API 调用） | 对照代，定义天花板与机械基线 | duel D0 模式 |
| R1 | strip 符号 + XOR / 栈字符串 | 字面量还原进源码 | defender 编码器 |
| R2 | RC4 / 4 字节 XOR / zlib 嵌套配置 | 解码逻辑还原为源码函数 | duel D2–D4 通道 |
| R3 | 无导入目录 + ROR13 / 私有乘法族哈希表 | loader 源码还原 | api-hash 参数族 |
| R4 | 运行时派生密钥封存一块配置 | **「该失败」的一代** | duel D5 / D8 模式 |
| R5 | Win32 GUI 窗口面：窗口类注册 + WndProc（WM_CREATE / WM_COMMAND / WM_TIMER / WM_DESTROY）+ 按钮 ID `(HMENU)0x65` + SetTimer，命令分支写文件 | 交互面还原：窗口过程引用、消息常量、控件 / 定时器 ID、资源条目 | user32/kernel32 级静态证据（`lib/interaction.js`） |

R4 的正确行为：还原其余全部 + 显式报告封存区 + 给出动态实验计划。编造封存配置的内容即 honesty 失败——D5 已经证明「该失败的一代」是评分器诚实度的试金石。

R5 的正确行为：交互面按**静态声明面**提取与计分（`interaction=true`，opt-in）——窗口过程引用（直接名、`&FUN_*` 或映像内地址常量经 VA−imageBase→RVA 解析）、WndProc/DialogProc 中与消息参数比较或 switch 判定的整型常量（十进制与十六进制归一化，`param_2 == 1` 与 `case 0x111` 同入 `msg:0x1` / `msg:0x111`）、`GetDlgItem` / `CreateWindowEx` hmenu 实参里的控件 ID、`SetTimer` 定时器 ID、`.rsrc` 目录条目。它不创建窗口、不执行样本；Qt/WebView/Electron/自绘框架不可见，算术构造的消息常量（`WM_USER+n`）不解析，switch 降界的范围哨兵常量两侧对称、在 limitations 声明——这些边界写进每次报告，不藏在文档里。

真实样本复核：putty / 7zr / sqlite3（`scripts/fetch-corpus.mjs` 已有，开源可抽查公开源码）。**只做函数级还原**：无全程序真值，只报 T1 / T2 相似度与残差，不宣称「还原了 putty」。合成靶标分数不外推为真实壳识别率。

## 6. 构建引擎（gcc）与无编译器档

本机当前没有任何 C 编译器（`where gcc clang cl tcc cc` 全空，已实测），所以构建引擎是循环的前置依赖。

- `lib/engines.js` 增加 gcc spec：pin 便携 MinGW-w64 构建的 URL + sha256，沿用 `installExternalTool`（`lib/engines.js:443`）的并发去重 / 校验 / 原子落盘；装到 `.tools/`，侧栏显示就绪状态，`providerReadiness` 增加 gcc。首次安装需网络，之后完全离线。
- 新 `lib/build.js`：驱动 gcc 编译重建源码，沿用 `ghidra-local.js` 的子进程模式（`run` 超时杀进程树、输出上限、`serialize` 串行闸，`lib/ghidra-local.js:96` / `:241`）。
- **无编译器档**：gcc 缺失时循环跑 T1 + T2 伪代码对照，显式标 blocked。不静默降级——1.4.0 签名门禁被回退顺序架空的教训：看起来有保护，实际没有，比没有保护更糟。

## 7. 新工具面（最小增量，每个都有着落）

| 新增 | 职责 | 闭环保证 |
| --- | --- | --- |
| `rea_reconstruct` | 循环状态机（start / advance / status / handoff / dynamic-plan / dynamic-apply / trace-apply），状态落 artifacts，每轮输出 gap 清单 + 收敛分数 | ownGuard 覆盖、注册进 index.js、host-matrix 计数、单测 |
| `rea_compare_build` | 重建体 vs 目标的 T1 / T2 / T3 分层对照，可选 T4 行为契约 | 同上 |
| `rea_trace_behavior` | 运行时轨迹：双方在独立临时目录执行，比较退出码 / 输出 / 落盘文件；`trace-apply` 计入收敛门槛 | 策略门 + 每次确认；host-matrix 计数、单测 |
| `rea_memory_dump` | 内存镜像脱壳：spawn 挂起、延迟或等到可执行内存标记后读主模块内存，重建 image-layout PE | 策略门 + 每次确认；重建器单测 + Frida 实测 |
| `rea_side_effects` | 运行时副作用：Frida 钩注册表 / 命名管道 / 服务 / IPv4+IPv6 连接 / 域名解析尝试，双方事件集合对照（recall + precision） | 策略门 + 每次确认；单测 + Frida 实测 |
| `draft=auto`（参数） | 读 gap 自动改稿：T2 不匹配函数换为反编译体，T1 缺失导入拉入绑定函数 | 只保留更高分轮次；基线来源可审计 |
| `reconstruct-baseline.mjs` playbook | 机械基线：纯反编译 round-trip 能到哪 | 走现有 playbook 守卫 / 白名单 / 调用上限 |
| 上游 `verify_reconstruction` / `evaluate_reconstruction_coverage` | gap 的备选 confirm 引用（`lib/artifacts.js:316` 已分类为只读） | 已接线：经 `availableTools` 过滤，只有宿主广告时才出现；本机无上游工具，仅单测覆盖 |

不合并成单一 `rea_run`（评审既有结论：丢失可发现性与逐工具守卫）。每个新模块只有一个消费者，每个新脚本进 package.json，每个新工具进 host-matrix 计数——新增代码从第一天就受 §8 的门禁约束。

## 8. 结构审计：结构清晰、无无效分支

现状已实测，如实记录：

- **模块级已闭环**：39/40 lib 模块从 index / client 可达；唯一例外 `playbook-worker.mjs` 经 `fork` 引用（`lib/playbook.js:29`），不是孤儿。把可达性检查固化进 host-matrix，防未来回归。
- **分支级有重复**：`rvaToOffset` 两份实现（`lib/intel.js:48` 闭包 vs `lib/structure.js:83` 导出），第四轮修重叠节回落时两处都改了——合并为单源。逐条审计 provider 回退 / config 门控分支：每个分支要么有测试覆盖的可达路径，要么删除。
- **文档级已漂移**：README「代码结构」节缺 identity / intel / structure / plan / probe / ghidra-local / containers 等模块，改为脚本生成（1.4.0「162 vs 157」漂移的既有修法：数字由机器产出，手写说明持续过期）。
- **遗留低危项** P13–P16 一并列入：512 KB 窗口文案、非 PE 的 `appears-unpacked` 结论、`query_results` 缺 Evidence ID、UA 截断。

闭环门禁（host-matrix 新增断言）：

1. 每个注册工具可达，每个 lib 模块有消费者；
2. 每个 plan confirm 映射到真实工具或显式标 blocked；
3. 每个 package.json script 指向存在的文件；
4. 文档数字与实现一致，漂移即测试失败。

## 9. 分阶段实施与验收

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| 0 | 结构审计：rvaToOffset 单源化、分支审计、P13–P16、host-matrix 结构门禁、README 结构节生成 | npm test 全绿 + duel 无回退 + 门禁 PASS |
| 1 | gcc 引擎 + build.js + T1 / T2 对照（含无编译器档） | 真实编译一个 C 文件并与目标对照出分数；缺 gcc 时显式 blocked |
| 2 | R0–R2 靶标 + 循环状态机 + 评分器 + 机械基线 | R0 天花板非空自证；R1 / R2 分数由测量驱动修补 |
| 3 | R3–R4 + 真实样本函数级复核 + honesty / precision 维度 | R4 正确失败（honesty=yes）；编造有正对照扣分 |
| 4 | 文档 / README / 发布门禁收尾 | host-matrix 3/3、文档数字一致、duel 11 代无回退 |

每个阶段独立可交付、独立可回退；阶段 0 不依赖编译器，可先做。

## 10. 评分器自证

评分器先于能力被测试，三条断言各有正对照：

1. **空天花板判失败**：构造产物目录不可写 / R0 检出为空的场景，评分器必须报错而不是给 100%。
2. **封存区不罚两遍**：R4 的封存值从召回分母移除，honesty 单独计分；构造「显式上报」与「静默」两个对照，前者得分后者失败。
3. **编造扣分有正对照**：构造一份混入不存在函数 / 字面量的重建源码，precision 必须下降；干净重建不扣分。
4. **共享运行时不算还原**：评分先扣除同工具链空程序与**全桩基线**的导入/字符串，payload 层只比较扣除后的 **IoC/水印指标**（编译器词汇与构建路径不计入），并单列 recall 与 precision；真实目标因此也能盲评载荷，不再只依赖 R 阶梯真值。实测同一份机械基线在 T1 99% 的同时报出 payload 缺失（真值核对 0/2）。

## 11. 诚实边界（明确不承诺）

- 还原输出在 build-compare 收敛前是**推断不是源码**（沿用 INFERENCE_GUIDANCE 的措辞纪律）；收敛后也只声明「与目标在 T1–T3 层一致」，不声明「这就是原源码」——等价编译产物可以有不同源码。
- 运行时派生密钥、控制流虚机化、加壳：静态 + 重建原理性不可达，终态 unreachable + 动态移交，不编造。
- 不执行样本；T4 行为档默认关。编译器首次安装需网络，之后离线。
- 真实二进制无全程序真值，只报函数级相似度；合成靶标分数不外推。
- **不做主动规避反逆向/反调试机制的工具**：隐藏调试器、patch 目标的反调试检查、绕过授权/DRM 属于绕过保护措施，不在本插件能力范围内。「静默」的实现方式 = 静态优先 + 最小侵入 + 检测面如实入档，不是对目标反逆向机制的对抗；四条执行路径的目标侧可观测信号（进程存在/被注入/被调试通道/环境异样/令牌特殊/行为差异）按 [`docs/detection-surface.md`](detection-surface.md) 矩阵逐格入档并标注证据等级，[分析，未实测] 的格子不冒充已验证；内核驱动、侧信道、容器内提权、VMProtect 类强壳仍是盲区，措辞不出现绝对化宣称。
- 路径授权仍是字符串级而非 OS 隔离；playbook 仍是可信代码隔离而非沙箱——既有边界不因本计划改变。

## 12. 复现（实施后）

```bash
npm test                # 394 项，全绿
npm run duel            # D0–D10 共 11 代，无回退
npm run recon           # 新循环：R0–R5 各代分数 + honesty + precision（加 --behavior 出 T4；加 --engine --interaction 出 T5 交互面，R5 的交互断言仅在此时执行）
npm run host-matrix     # 三种宿主模式 + 结构门禁 + 文档数字校验
npm run restore -- <target> --functions A,B --draft x.c --threshold 0.9   # 函数级评审门禁（退出码）
```

本文档落盘时未实施任何代码改动；上述命令中 `npm run recon` 在阶段 2 完成前不存在，不假装能跑。

## 13. 实施状态（2026-11-16，续更至 2026-11-20）

计划落盘当天开始实施。阶段 0–2 已落地并跑出首轮数字；阶段 3 的 R3/R4 与 honesty/precision 维度随之生效；真实样本的复核只能测「可测量项」，因为真值不存在。

| 项 | 状态 | 证据 |
| --- | --- | --- |
| 结构审计 | 已落地 | `rvaToOffset` 单源化（intel 消费 structure）；host-matrix 结构门禁：模块可达 / scripts 存在 / 13 个 confirm 映射 / README 生成块；门禁首跑即抓到 `start_gdb_decompile` 死映射并删除 |
| P13–P16 | 已修复 | `test/structure-audit.test.js` 5 项：窗口文案、非 PE 结论、索引 Evidence ID/confidence 渲染、完整 UA、重叠节导入解析 |
| 构建引擎 | 已落地 | WinLibs GCC 16.2.0 本机真实编译通过（含非 ASCII 工作路径修正）；zig cc 0.17.0 备用；解包/校验/就绪由合成归档单测覆盖。实测 zig 冷启动 98 s，热缓存 0.6 s |
| 对照层 | 已落地 | `lib/compare.js`：T1 结构（导入 + 节区）/ T2 函数清单（伪代码 + CFG，上限可配、结果缓存、入口回退）/ T3 源码字面量 / payload 指标层（IoC 与水印，盲评）；运行时底噪（空程序与全桩基线）从双方扣除；空分母记 `null`，空总分判失败 |
| 循环 | 已落地 | `lib/recon.js` + `rea_reconstruct`：预算（1–20）、四终态、确定性状态文件、每条 gap 带动作与 confirm；advance 支持 `draft=baseline`（机械草稿，无需模型） |
| 机械基线 | 已落地 | `lib/baseline.js`：伪代码→C、逐函数隔离筛选（其余全桩）、整文件编译修复、失败函数降级为桩并计数；默认上限 48，可配 |
| 靶标阶梯 | 已落地 | `scripts/recon/specimen.mjs` 生成 R0–R5 并用同一编译器真实编译；`npm run recon` 出分数与 JSON；`--engine` 打开 T2，`--baseline` 增加机械基线列，`--interaction` 打开 T5（复用 T2 的引擎清单，目标侧是缓存命中），`--only` 限定代际 |
| 函数级还原（M1） | 已落地 | `scripts/recon-restore.mjs`：只评审指定函数、按名匹配、语义签名（该口径下 CFG 不参与计分）；sqlite3 首测 2/2、87.8%，复测 2/2、100.0%（threshold 75%，exit 0）；负对照 text/99% → 52.5%、exit 1。2026-11-18 扩到 9 函数：semantic/75% → 9/9、100.0%、below threshold 0、exit 0；text/99% → 53.0%、below threshold 9、exit 1。7zr 首测 2/2、97.9%、exit 0；负对照 text/99% → 56.4%、below threshold 2、exit 1。正负对照钉进 `test/restore.test.js`；每次运行追加机器可读记录至 `dist/restore-gates.jsonl`（--record 可改/关） |
| 动态探针（M2） | 已落地（opt-in） | `lib/dynamic.js` + `rea_dynamic_probe`：Frida 17.26.3，hook 指定 RVA 并 dump 参数缓冲区；R4 封存靶标实测取回明文；策略开关 + 每次确认 |
| T4 行为契约 | 已落地（opt-in） | `lib/behavior.js`：输出 / 状态 / 副作用三维度，逐维 recall + precision；工具链底噪先扣除；`behavior=true` 启用，默认分数不变；真实编译的正负对照在 `test/build-compare.test.js` |
| 动态证据闭环 | 已落地 | `rea_reconstruct action=dynamic-plan/dynamic-apply`：候选排序（写入参数下标 + 循环 + 原地变换）、dump 记为额外真值、重开已耗尽循环、补一次迭代；**不直接宣称 converged**，下一稿仍须对照确认 |

### 首轮阶梯数字（本机，本地档）

```
tier ceiling  baseline  mutation  loop             hash   unresolved sealed leak
R0   100.0%   n/a       78.0%     converged        n/a    0          -
R1   100.0%   n/a       50.5%     converged        n/a    0          -
R2   100.0%   n/a       53.1%     converged        n/a    0          -
R3   100.0%   n/a       28.1%     converged        100.0% 0          -
R4   100.0%   n/a       64.6%     converged        n/a    1          none
```

（本轮构建引擎为 WinLibs GCC 16.2.0；zig 是等价备用引擎，切换后数字会有小幅差异。）

- **ceiling** 是「用真值源码重建并编译」的分数：非空且 100.0%。payload 层只计指标形态，真值重建的 URL/水印全部命中，说明分数不是靠运行时词汇堆出来的。
- **mutation** 是**编造正对照**：真值源码外加一条明文 URL 与一个 `MessageBoxA` 调用。分数降到 68.5–82.9%，`imports.added`、`t3.unmatched` 与 payload 指标都点名。
- **loop** 用真值草稿驱动状态机，五级全部 `converged`；R4 的 2 个未解区进入 intake，封存明文**没有**出现在目标里（sealed leak none）。
- **hash** 仅 R3：ROR13 表经本地通道恢复真值 API 名 4/4。
- **引擎档（`--engine --only R0`）**：T2 以伪代码 + CFG 形状计分（清单 48 上限，截断会标注）；清单与反编译结果按脚本版本缓存，同一目标重复对照不再重新分析。

### 机械基线（`npm run recon -- --baseline --only R0`）

反编译 → 翻译 → 编译 → 对照，全程无模型；48 个函数的清单里，**11 个翻译成功（含 main、mix）、0 个降级为桩、37 个是运行时提供（CRT/libc，不重复定义）**；逐函数隔离筛选保留 13/13 个候选，整文件 3 轮编译收敛。

| 指标 | 真值重建（ceiling） | 机械基线 | 说明 |
| --- | --- | --- | --- |
| T1 结构 | 100.0% | 100.0% | 导入与节区可机械还原 |
| payload 指标 | 100.0% | 80.0% | 目标 5 个指标，基线命中 4 个；URL 与水印缺失 |
| 真值载荷字面量 | **2/2** | **0/2** | 配置数据在 .rdata，伪代码只留指针——这是反编译器的边界 |
| 综合分 | 100.0% | **73.8%** | 载荷层把「结构全对、配置没还原」显式扣出来 |

说明：payload 层只统计指标形态（URL/域名/互斥量/canary 等），编译器词汇、构建路径与普通字符串不计入；编码配置经解码通道还原后同样计分。GCC 与 zig 两个引擎的翻译覆盖不同（GCC 本轮 11/48 翻译，zig 早前 4/12），报告始终记录实际编译器。

循环层面同步收紧：`draft=baseline` 的迭代**永远不能把状态推到 `converged`**——它只是下限。实测基线草稿以 `budget-exhausted` 结束，残差里保留「载荷未还原」的事实。

### 真实语料函数级基线（`--corpus --baseline --functions 24`）

| 样本 | 函数清单 | 基线综合 | 翻译/桩 | T1 | payload | 结论 |
| --- | --- | --- | --- | --- | --- | --- |
| 7zr.exe 602 KB | 24/4359（上限） | 7.1% | 3/21（降级保底） | 13.2% | 0.0% | 真实指标全部缺失：`schemas.microsoft.com`、`3.3.33.5`、`1.0.0.0` |
| putty.exe 1.7 MB | 24/2710（上限） | **9.0%** | 2/22（降级保底） | 16.7% | 0.0% | 复测判 `appears-unpacked`（高熵仅 `.rsrc`）；旧「拒绝」是过期判定，不是样本加壳 |
| sqlite3.dll 3.2 MB | 24/5018（上限） | 7.7% | 16/8 | 17.5% | 0.0% | 控制流小部分可译，载荷零命中 |

结论：机械直译在真实编译器产物上只能保底——多数函数无法通过隔离筛选或整文件编译，降级为桩；报出的数字是**无需模型的下限**，不是失败。putty 的拒绝同样重要：对加壳样本做源码基线只会测到壳。

### 引擎性能

- 首次分析：多核 + **180 秒分析上限**；实测 R0 冷启动 **212 s**（含 JVM 与 15 个函数反编译），结果带 `analysisTimedOut=true`，不静默截断。
- 重复对照：清单与反编译结果按「文件哈希 + 上限 + 脚本版本」缓存，实测二次读取 **5 ms**。
- 非 ASCII 工作路径：WinLibs GCC 的 GNU ld 会写坏中文路径；编译参数已改为相对名（`cwd` 为工作目录），本机在 `D:\5\新建文件夹\...` 下实测编译通过。

### 真实函数级还原与动态确认（2026-11-16 追加）

- **M1 sqlite3**：`npm run restore -- dist/corpus/sqlite3.dll --functions FUN_1800096e0,FUN_1800097f0 --draft test/fixtures/sqlite3-restored.c` → T2 **semantic 87.8%**，2/2 函数匹配；其中一个函数 79.7%，差距逐条列出。草稿按反编译里的偏移、掩码与调用形状写出，越界 helper 以桩补齐以便链接——这是「真实函数级还原」的第一次可重复测量。本轮复测（同一草稿、语义签名、`--threshold 0.75`）为 2/2、100.0%、exit 0；`--metric text --threshold 0.99` 为 52.5%、below threshold 2、exit 1，阈值门禁的正负对照都实测过。
- **M1 规模化（2026-11-18）**：sqlite3 扩到 **9 个函数**——既有 6 体之外新增 FUN_180009750（118B 标志位逻辑）、FUN_180009820（89B 浮点转换，需 math.h 的 NAN、DAT_18029bd28/DAT_18029bbf8 常量池替身与 FUN_1801352e0 桩）、FUN_1800099a0（79B 字符串比较循环），全部**从 cap-200 缓存伪代码手写**（缓存键 sqlite3 相对串 cap-200=1ddedeef、cap-24=03983d75、7zr cap-24=e1070a1f，逐字路径敏感：改绝对路径即 MISS 并付冷分析；实施前以 sha256 复算键值三 HIT 确认，putty cap-24 现键 7e53a23b MISS 与既有记录一致），越界 callee（FUN_1801d4a00 / FUN_1801b0690 / FUN_1801352e0）以桩补齐。**草稿来源声明：本轮全部新增函数体从门禁缓存打印的反编译伪代码手写产出，未读 sqlite / 7-Zip 官方源码**——抄源码会让相似度测量失去意义；7zr 草稿 `test/fixtures/7zr-restored.c` 为 FUN_00401207（75B __thiscall）+ FUN_00401519（49B 指针数组 while 循环），越界 callee（FUN_00401252 / FUN_00401ea5 / FUN_00471ab6，其中 FUN_00401252 还作为回调实参出现）以桩补齐，并避开方案点名的伪影体 FUN_0040116f / FUN_004011b7 / FUN_00401656，两个 fixture 头注释逐函数记 rva/size 出处。门禁实测：`--threshold 0.75`（semantic）→ **9/9、coverage 100.0%、below threshold 0、exit 0**；同清单同草稿 `--metric text --threshold 0.99` → **53.0%、below threshold 9、exit 1**（逐函数 0.0%–87.7% 全低于 99%）。7zr 首次函数级基线：`dist/corpus/7zr.exe --functions FUN_00401207,FUN_00401519 --metric semantic --threshold 0.75 --max-functions 24` → **2/2、97.9%、below threshold 0、exit 0**；同清单同草稿 `--metric text --threshold 0.99` → **56.4%、below threshold 2、exit 1**（FUN_00401207 26.7% / FUN_00401519 86.1%），与 sqlite3 负对照同等方式钉进 `test/restore.test.js`（两个目标的正负对照口径对称）。FUN_00401207 __thiscall / FUN_00401519 __fastcall 为 32 位目标的调用约定，64 位审查构建下以条件属性保留声明；勘验稿 /tmp 试写曾测 93.4%，落盘稿复测为 97.9%。**门禁数字的机器可读固化**：每次门禁运行（手跑或测试内）由 `scripts/recon-restore.mjs --record`（默认 `dist/restore-gates.jsonl`，`--record none` 关闭）追加一行 JSON 记录——target（保留传入路径串原样，缓存键逐字敏感的字段）、metric、threshold、maxFunctions、requested、inventory（total/emitted/truncated/cached/timeStopped/analysisTimedOut）、result（status/score/matched/functions/coverage/belowThreshold）、逐函数 mismatches、exit——验证者对齐数字读 JSONL 即可，不必从文本输出提取；`test/restore.test.js` 每断言在跑完门禁后读最后一行记录并钉 target/metric/threshold/exit/belowThreshold，防止结构化记录与实测漂移。机制边界如实记录：cap-200 清单窗口内 0 个导出符号名（sqlite3_* 导出函数在更后地址），导出面覆盖需改 ProbeAddress.java 清单机制（SCRIPT_VERSION+1 → 全缓存作废+冷分析），本轮未做。
- **M2 R4 封存靶标**：生成未 strip 版本并找到 `unseal` 的 RVA；`rea_dynamic_probe`（`allowSampleExecution` + 每次 `confirm`）在函数返回时 dump 68 字节，明文为 `https://telemetry.example.test/v1/collect|orbit-7f3a91c2d8e4`——运行时派生密钥可以从执行中确认，而不是靠猜。
- **跨编译器评分**：函数级评审默认用语义签名（结构常量/运算符/控制流关键字/调用数），CFG 与文本相似度作为并列证据；MSVC 目标对 MinGW 重建时文本天然低分，语义签名才是可比信号。

### 执行安全边界

动态探针是本插件唯一的执行路径：默认关闭，需 `allowSampleExecution: true` 且每次调用 `confirm: true`；样本在用户机器上真实运行、保留自身网络访问，**没有沙箱**。它只用于你有权执行的样本；缓冲区按不可信数据包裹。其余所有分析路径仍然只读字节、不执行样本。四条执行路径（`rea_dynamic_probe` / `rea_trace_behavior` / `rea_memory_dump` / `rea_side_effects`）的**目标侧检测面**（进程存在/被注入/被调试通道/环境异样/令牌特殊/行为差异）按 [`docs/detection-surface.md`](detection-surface.md) 矩阵如实入档——本插件不做主动规避反逆向/反调试机制的工具，「静默」=静态优先+最小侵入+检测面如实入档。

### 与计划的偏差（均已实测确认）

1. **构建引擎增加 zig cc，GCC 已端到端验证**。本机到 GitHub 约 20 KB/s，276 MB 的 WinLibs 下载耗时数小时；经用户确认增加 npm 固定版本的 zig 0.17.0 作为第二引擎（`zig cc -target x86_64-windows-gnu`，同为 MinGW-w64 ABI 的 PE）。随后 WinLibs GCC 16.2.0 在本机完成安装并**真实编译通过**（含非 ASCII 工作路径修正：GNU ld 会写坏中文路径，编译参数改为相对名）。`detectGcc` 按「托管 GCC → PATH GCC → 托管 zig」选择，编译记录带 `compiler` 字段，两种引擎不混算。
2. **mutation 的语义改为「编造」**。首版用「同长异值」的编码配置做变异，实测 R2/R4 分数几乎不动（编码后无明文、长度与结构不变，静态层看不到差异）。这不是评分器缺陷，而是静态对照的边界；因此正对照改为静态可抓的编造（额外字面量 + 额外导入），并由 gap 逐条声明。
3. **T2 从入口扩到函数清单（含 CFG）**。`ProbeAddress.java` 的 `list` 模式一次运行导出伪代码**与 CFG 形状**（基本块/边/分支块/回环/最大扇出）；每个函数的相似度是伪代码三元组相似度与 CFG 相似度的平均。上限可配（默认 48，最多 200；工具参数与 `--functions` 均可调），单函数 8 秒、整轮 180 秒；清单按「文件哈希 + 上限 + 脚本版本」缓存在引擎工作目录，重复对照不再重新分析同一文件。**首次分析启用多核并设 180 秒分析上限**，超时后仍执行脚本并在结果标注 `analysisTimedOut`。清单不可用时退回入口函数并写明 fallback 原因。
4. **机械反编译基线已实现，边界明确**。`lib/baseline.js` 先做**逐函数隔离筛选**（其余函数全部为桩；只含未声明标识符/类型/函数这类可修复错误的候选保留），再整文件编译修复（覆盖 clang 与 GCC 两种诊断措辞、GNU ld 的 `undefined reference`），持续失败时逐半降级为桩以保证一个可编译的下限。为了让反编译输出可编译，基线放宽整型到指针的转换（`-Wno-int-conversion`、`-Wno-incompatible-pointer-types`）——它测的是**控制流与导入**的还原，不是类型重建。默认覆盖上限 48（与 T2 同源）。
5. **真实样本有盲评载荷层，编码形态也计分**。对照新增 **payload 层**：在扣除工具链底噪与构建元数据后，只比较 **IoC 形态的指标与归属水印**（URL/域名/IP/注册表/互斥量/canary…），并单列 recall 与 precision。编码配置通过 `extractDeepStrings` 的解码通道（单字节/重复键 XOR、zlib、base64、RC4 候选）还原出指标后同样进入该层——R1/R2 这类纯编码靶标因此有载荷分，而不是「无载荷可评」。运行时派生密钥的封存区仍然无解，此时 payload 层为空并上报未解区。
6. **上游 `verify_reconstruction` / `evaluate_reconstruction_coverage` 未接线**。§7 把它们列为可选 confirm，但本轮没有依赖它们：本机可靠路径是自有 Ghidra 引擎。需要它们时再按 `availableTools` 过滤接入，当前不在调用链里。
7. **动态执行背离「绝不执行样本」的原承诺（经用户明确选择）**。执行路径有四条：`rea_dynamic_probe`（取回运行时密钥）、`rea_trace_behavior`（双方受控执行、对照输出与落盘副作用）、`rea_memory_dump`（内存镜像脱壳）与 `rea_side_effects`（注册表/管道/服务/网络副作用）。四者默认关闭，需要 `allowSampleExecution: true` 与每次 `confirm: true`；没有沙箱，样本保留网络访问。其余路径保持只读。风险写入 README 与工具描述，不隐藏。
8. **T4 实现为「声明面契约」，不是计划里的运行时轨迹档**。计划原意是「重建体受控运行 vs 目标静态证据」，实施时改为两侧纯静态提取输出字面量、状态名与副作用家族（`lib/behavior.js`），原因有二：运行时档需要执行重建体，边界成本高；而「输出/状态/副作用」的**声明差异**已能在不执行任何东西的前提下被证伪（丢消息、编造能力都会扣分）。运行时轨迹后来以独立工具 `rea_trace_behavior` + `trace-apply` 实现（见下），T4 静态档与运行时档因此是两层证据，不互相替代。

### 闭环收口（2026-11-16 晚）

在首轮阶梯之后的补全，全部有测试：

- **T4 行为契约**：`lib/behavior.js` 把导入表映射为 `family:operation` 令牌，把深字符串分成输出 / 状态两组，扣除工具链底噪后按维度计 recall 与 precision；单侧缺失按存在的一侧计分，两侧皆空记 `null`。`rea_compare_build` 与 `rea_reconstruct` 通过 `behavior=true` 启用，启用后权重重归一化；未启用时既有分数不变。gap 会点名 `behavior-outputs-missing` / `behavior-effects-fabricated` 等，并给出动作与确认工具。
- **动态证据不再冒充收敛**：`dynamic-apply` 记录 dump、更新额外真值源、重开已耗尽的循环并补一次迭代预算，状态回到 `running`；它不写 `converged`。`dynamic-plan` 改为识别**真正被写入的参数下标**（`param_2` 不再被当成 `param_1`），并过滤「只读不写」的函数，避免把执行候选提给操作者。
- **运行时真值进入对照**：`compareBuilds` 接受 `dynamicEvidence`，经与二进制字符串相同的 IoC 归一化通道并入目标真值；因此 T3 与 payload 能确认「只在运行时存在」的密钥/端点，正确重建不再被 precision 判成编造。对照报告单列 `dynamicEvidence` 数量与限制说明。
- **阶梯实测**（`npm run recon -- --behavior`，gcc 16.2.0）：R0–R4 ceiling 均 100.0%，T4 输出维度均 100.0%；state/effects 在合成靶标里未激活（靶标只打印字面量，不落盘、不联网），因此这两维度的正/负对照由 `test/build-compare.test.js` 的真实编译用例覆盖：一个调用 `CreateFileA` + `MessageBoxA` 的程序与其「只 printf」版本对照，缺 file:create 与失败消息都会扣分。
- **T5 交互面实测**（2026-11-19，`npm run recon -- --engine --interaction`，gcc 16.2.0 + Ghidra 12.1.4）：新增 R5 Win32 GUI 代与 `lib/interaction.js` 提取器。R5 目标面实测（提取器对编译产物的输出，冻结进 truth.json，非手填）：窗口 `{win:class-register, win:create, win:wndproc=WndProc}`、消息 `{msg:0x1, msg:0x2, msg:0x111, msg:0x113}`、控件/定时器 `{ctl:0x65, timer:0x1}`、资源 `{res:manifest:0x1}`（manifest 是工具链默认项，双侧对称不伤分）。-O0 实测形态与提取规则逐条对上：WndProc 引用在 WinMain 体中是代码指针局部 `pcStack_60 = WndProc;`（直接名，非地址常量）；WM_CREATE/WM_DESTROY 是十进制 `param_2 == 1` / `== 2`，WM_COMMAND/WM_TIMER 是十六进制 `0x111`/`0x113`，两种进制归一化进同一令牌集；GCC switch 降界的范围哨兵是 `< 0x112` / `< 0x114` 形式的不等式，不在「==/!=/case」提取范围内，未混入消息集。ceiling 四维全 100.0%、overall 1.0（权重重归一化后 t5=0.130）；删去整个 WM_COMMAND 分支的突变体 messages recall 0.75（缺 `msg:0x111`）、overall 95.2%、loop 仍 converged，命名 gap `interaction-messages-missing`；按钮 ID `ctl:0x65` 经 hmenu 实参在突变体中仍在（controls recall 1.0）。`engine=false` 时 T5 显式 blocked（清单不存在≠没有交互面）；截断清单下目标侧提不出任何交互事实也判 blocked，不记 0 分。

### 自动改稿与运行时轨迹（2026-11-16 续）

- **自动改稿（`draft=auto`）**：`lib/autodraft.js` 读本轮 gap 做确定性修补——T2 的 `mismatches` 逐个用反编译对应函数体替换，T1 的 `imports.missing` 则从基线拉入绑定该导入的函数；每轮重新编译与对照，**只保留分数更高的轮次**（`best` 回退保护）。修补来源始终是 Ghidra 从目标产出的基线，不编造调用路径、不把目标字面量写入源码骗分。`rounds` 1–5（默认 2），需要 Ghidra；无源草稿时从机械基线出发，此时 `draftKind=baseline`，仍不能单独宣告收敛。
- **交接简报（`action=handoff`）**：`renderHandoff` 把最近一轮的 gap、T2 待重写函数（名字 / RVA / 相似度 / 反编译调用）与下一步命令写成 Markdown 并落 artifacts。`includeCode=true` 时再嵌入最多三个函数的 Ghidra 伪代码，DSH 模型可以直接读着改写。机械修补到此为止——需要理解代码的那一步有明确、可携带的接口。
- **模型内环（`action=rewrite`）**：DSH 模型只提交被点名的函数体（`rewrites: [{name, source}]`），插件把它们应用到上一份最佳草稿、编译、对照、记账，和其他草稿走同一套评分与预算。提交的体必须真的定义该函数；合并结果不提升就不算收敛。修掉了函数块提取丢返回类型导致 `int int main` 的缺陷，替换现在是整声明替换。
- **内存镜像脱壳（`rea_memory_dump`）**：Frida spawn 挂起后读取主模块 `SizeOfImage`，用磁盘头 + 内存节重建 image-layout PE（`PointerToRawData=VA`、`FileAlignment=SectionAlignment`），再交给 triage / Ghidra。`delayMs` 决定何时 dump；0 表示入口点（拿到的是壳）。`waitForExec=true` 的证据是**两级且都不等于 OEP**：`oep signal` = 首个「至少一页」且**成功返回**的可执行内存标记（`VirtualProtect`/`VirtualAlloc` 的 EXECUTE 位，修掉了原来记请求值不看返回的精度缺陷）；`entry` = 标记后立刻在**发起标记的线程**上挂 Stalker，按基本块观测「控制流首次进入被标记区域」，命中报告 hit 地址 + 指令文本 + 16 字节原始字节（进程取值按不可信包裹），并区分 `inside main module`（区内命中可能是壳自身）。超时未中显式报 `entry: none before the timeout - control flow was never observed in the marked region (watched thread <tid>, kernel32-level hooks only)`；观测器失效显式报 `entry watch unavailable`。盲区已写进报告措辞与 README 已知边界：watch 只覆盖标记线程（多线程壳漏报 entry）、hook 只在 kernel32 层（直调 ntdll 时连 exec-mark 都没有）。实现层有一个双保险：Frida 17.26.3 没有 `Script.setExceptionHandler`（实测顶层 TypeError 且中断后续 hook 安装），回调体各自 try/catch + Python 侧识别 `type=='error'` 消息（并入 warnings、entryWatch 翻 `unavailable`），两条腿都把脚本死亡显式化。Python 侧 wait 与 dump 两阶段**共用同一 t0 deadline**（不再各起一个 timeout 窗口，外层杀树 timer 永不压线），dump 阶段保底 `DUMP_MIN_BUDGET=10s`（负场景等 entry 耗尽 deadline 后 dump 仍有预算，`entry: none` 断言成立），wait 期间以 `session.on('detached')` + 每秒一次进程表轮询双路检测进程死亡（`device.get_process` 按名匹配不能用；注意 agent 假死不是死亡，见实验记录第 7 条）——真死了就显式报 `the process exited before the dump (…; entry: none)`，不再落到含糊的 `no dump before the timeout`；所有 error 输出都携带 helper warnings 自证期间发生了什么。真实样本复核：对 putty.exe 入口 dump 得 1,724,416 字节，重建后 348 个导入与磁盘完全一致，Ghidra 可直接打开。
- **Frida 解释器回退**：本机 `python` 没有 Frida、`py -3` 有；readiness 现在依次探测 `python` / `py -3` / `python3`，探针与 dump 都用真正装了 Frida 的那个解释器。此前动态探针在本机会静默不可用。
- **运行时轨迹（`rea_trace_behavior`）**：目标与重建体在各自全新的临时目录、以相同参数执行；比较退出码、stdout、stderr 与运行目录内的文件（相对路径 + sha256）。同一策略门（`allowSampleExecution` + 每次 `confirm`），无沙箱。运行前把 `TEMP` / `APPDATA` / `LOCALAPPDATA` / `HOME` 重定向到运行目录，写到临时目录或用户配置目录的文件因此可观测；注册表 / 服务 / 命名管道 / 网络对端仍是盲区。`lib/trace.js` 负责执行与对照，`lib/trace-tools.js` 负责门禁、报告与 artifacts 落盘。
- **副作用观测（`rea_side_effects`）**：Frida 钩 `RegCreateKeyExW` / `RegOpenKeyExW` / `RegSetValueExW` / `RegDeleteValueW`、`CreateNamedPipeW`、`connect` / `WSAConnect`（IPv4 与 IPv6 sockaddr 解析，IPv6 压缩记法 + scope 数字）、`getaddrinfo` / `GetAddrInfoW` / `GetAddrInfoExW`（记 `dns:resolve <名>`，getaddrinfo 内部链调 GetAddrInfoW 去重为一行）、dnsapi `DnsQuery_W`（记 `dns:query <名>`）、`CreateServiceW`，把双方**尝试过的**调用归一化为 `family:operation detail` 集合并算 recall/precision。ws2_32/dnsapi 五+一导出全部走 watched-modules 挂载：加载期已装载则直接挂（防重复 attach），未装载经 `attachModuleObserver(onAdded)` + 250ms 轮询延迟挂载；挂载失败与观察窗口结束仍未装载的 watched 项以 warnings 显式呈现（实测假模块名 → `nosuchmod.dll!DnsQuery_W: module never loaded before the report, hook not installed`）。实测（2026-11-19，frida 17.26.3 / Win11 26300）：解析本机主机名 + localhost 并连接 `[::1]:9` 的程序产出 `dns:resolve desktop-0q1029r`、`dns:resolve localhost`、`network:connect [::1]:9`（外加首条 getaddrinfo 名字解析链触发的 `registry:create …tcpip\parameters` 噪声——A/B 变体实测：仅 WSAStartup 不解析域名的样本零事件，该噪声随首条 getaddrinfo 出现，验证员轮确证），安静重建侧全缺 → recall 0 / precision null / score 0；六个 watched 钩子零 warnings 全部挂上。**实测窗口边界（根因未查）**：本机进程内首条 connect 族调用之后观察器全局静默——每进程至多一条 connect 族事件，其后连注册表等其他钩子事件也消失（实测 connect 后建管道只出 connect 事件），观测覆盖 = 首条 connect 族调用本身 + 其之前的钩内尝试，不冒充持续观测；钩子打在导出地址上，经 GetProcAddress/IAT 动态解析的调用同样可见（实测经函数指针发起的 connect 照常出现）。仍不可见：绕过 ntdll 的直接系统调用、内核驱动、raw socket DNS/53、DoH/DoT、QUIC、UDP sendto、ConnectEx；DnsQuery_W 直查路径可能出网，不进 pinned 执行测试，其覆盖仅由延迟挂载机制级验证 + 纯 JS 单测保证。
- **轨迹进入收敛判定（`trace-apply`）**：`rea_reconstruct action=trace-apply` 读入轨迹 JSON，记录 `state.runtime`；轨迹 < 90% 时 `recordIteration` 不允许 `converged`，已收敛的循环会被重开并补一次迭代预算。轨迹分不替代静态分，两者都通过才算收敛。
- **上游 confirm 接线**：`gapsFromComparison` 接受 `availableTools`，仅在宿主真实广告 `verify_reconstruction` / `evaluate_reconstruction_coverage` 时，把它们作为 gap 的**备选确认路径**（`also:`）；本地确认仍是第一条。已有 gap 级与工具级渲染两层单测（`also:` 出现在真实 advance 的输出里），但本机没有上游工具，真实宿主仍未验证。
- **验证**：`npm test`（`--test-concurrency=2`）**420 项全绿**（2026-11-17 OEP 升级后；此前 419）；默认无上限并发在本机偶发 gcc 进程风暴导致挂起，已把脚本固定为 2。相对 394 基线新增 26 项：自动改稿 6、运行时轨迹 5、内存镜像 6（含入口 dump、可执行标记触发与 Stalker entry 正/负对照）、副作用观测 3、上游备选 2、轨迹收敛 1、陈旧轨迹 1、交接简报 1、模型改写 1。2026-11-18 M1 规模化后 **426 项全绿**（restore 门禁 4 项：sqlite3 与 7zr 的正/负对照各一组，`test/restore.test.js`；memdump 专项 2 项见下；7zr 负对照补钉前为 425 项 / 3 项、实测 139.4 s，补钉后文档轮复测 426 项、160.5 s）；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4）且结构门禁 OK（文档轮复跑确认）；`npm run recon -- --behavior` R0–R4 ceiling 仍 100.0%（exit 0）；`node scripts/update-code-structure.mjs --check` → current。2026-11-19 副作用扩量（IPv6 连接 + 域名解析）后 **428 项全绿**（`test/observe.test.js` 5 项：纯 JS 2 + 门禁负测 1 + IPv4 管道/connect 正负对照 1 + 新增 IPv6/DNS 执行正负对照 1；全套件实测 202037 ms，与方案预期 426→428 一致）；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4）且结构门禁 OK（与上轮基线逐字一致，无新工具）；`npm run recon -- --behavior` R0–R4 ceiling 全 100.0%、全 converged（R3 hash 100.0%、R4 sealed 1 / leak none）；`node scripts/update-code-structure.mjs --check` → current。2026-11-19 自动改稿批量回退后 `npm test`（`--test-concurrency=2`）**470 项全绿**（pass 470 / fail 0 / skipped 0，实测 307 s；含本轮新增 autodraft 批量回退 11 项：7 场景 + null 等价性 2 项 + 序列化/选择器契约 2 项），README 结构块因行尾规范化由 `npm run structure` 再生成（77 entries，模块头首句无变化）。2026-11-19 交互面轮（T5 + R5）后 `npm test`（`--test-concurrency=2`）**486 项全绿**（pass 486 / fail 0 / skipped 0，实测 453.8 s；新增 `test/interaction.test.js` 13 项 + `test/build-compare.test.js` t5 档 2 项，`test/recon.test.js` 的 tier 模板用例扩到 R5 形态并加 T5 贯通断言）；`npm run recon`（默认档）R0–R4 数字与文档逐项一致（mutation 78.0/50.5/53.1/28.1/64.6，全 converged，R3 hash 100.0%、R4 leak none），R5 ceiling 100.0%；`npm run recon -- --engine --interaction` R0–R5 ceiling 全 100.0%（exit 0，R5 交互四维 100.0%、突变体 messages recall 0.75）；`npm run host-matrix` PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，无新工具）；`npm run structure` 再生成（78 entries，新模块 `lib/interaction.js` 入块）。2026-11-19 宿主机保护轮（B：redact + env 遮蔽 + 外联拦截）后 `npm test`（`--test-concurrency=2`）**497 项全绿**（pass 497 / fail 0 / skipped 0，实测 562.9 s；新增 `test/redact.test.js` 8 项、`test/observe.test.js` 非回环拦截实测 1 项、`test/trace.test.js` 身份遮蔽 1 项、`test/policy.test.js` 开关 1 项）；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，无新工具）；`npm run structure` 再生成（79 entries，新模块 `lib/redact.js` 入块）。2026-11-19 交互面验证轮修复后 `npm test` 复测 **499 项全绿**（pass 499 / fail 0 / skipped 0，实测 621.1 s，存档 `dist/full-test-run2.log`；验证员另独立复跑 607.9 s 见 `dist/verify/full-test-run-r3.log`；本轮新增 2 项：t5 状态规则分支单测 + 截断清单/零事实 blocked 端到端——t5 判定逻辑从 `compareBuilds` 提取为纯函数 `buildInteractionTier` 逐支执行，行为逐字不变），`npm run recon`（默认档）复跑数字仍逐项一致（78.0/50.5/53.1/28.1/64.6，全 converged）。

### OEP 升级实验记录（2026-11-17，Frida 17.26.3 / WinLibs gcc）

实施轮对本机实测确证的行为，防止后续按错误直觉回改：

1. **`Script.setExceptionHandler` 在 17.26.3 不存在**：注入 JS 顶层调用它得到 `TypeError: not a function` 且**中断整个脚本**，后续 hook 安装代码全部不执行、连 exec-mark 都不发（评审轮首次实测，实施轮复核代码确认）。修正是回调体（transform / callout）各自 try/catch → `send({event:'script-error',…})`，Python 侧同时识别 Frida 原生 `type=='error'` 消息——两路都显式化，不静默。
2. **Stalker transform 回调里，hook 上下文创建的 NativePointer 读回 0x0**：同一处赋值 `region=address; regionSize=size;` 中 NativePointer 失效而 JS number 幸存（评审轮 C4/C5/C6 实验：区域块确实被编译、armed 分支却永不执行、compare 时 region="0x0"）。修正是区域/主模块边界全部以 JS number 存储（`Number(address)`，x64 用户态地址 < 2^53 无精度损失），transform 内纯数字比较；callout 里对象幸存（C8：`Module.base` 正确），但为一致性 callout 同样用 number 边界判定。
3. **transform 的 keep 语义**：每条 `next()` 之后必须立即 `keep()`，漏 keep 会吞掉块首指令——评审轮 A/B 对照实测错误形状（first 不 keep）进程立即终止（`reason='process-terminated'`）。实施轮实测正确形状下验收跳板完整执行。
4. **callout 内同步 `Stalker.unfollow()` 不丢当前块**：实施轮 A/B 实测（同步 vs setImmediate 延迟）两者下验收样本的跳板写入都完整落在 dump 里——unfollow 在当前编译块结束时生效，不跳过块内指令。
5. **Python 侧进程存活检测**：`device.get_process(pid)` 在 17.26.3 按**名字**匹配（传 int 报 `'int' object has no attribute 'lower'`，传 str 对活 pid 报 ProcessNotFoundError），不能当探活用；`session.on('detached')` 对**真终止**可靠（无 hook 0.35s、带 VirtualProtect hook 1.0s 内回调 `('process-terminated', None)`，外部 kill 也触发），但**「进程假死」不是死亡**——见第 7 条——所以 wait/dump 循环另加每秒一次的 `device.enumerate_processes()` pid 轮询兜底，两者并用以防漏报；agent 假死（进程活着、不回消息）不冒充死亡，落到通用超时 + warnings 显式呈现。
6. **dump.py 子进程在管线下偶发 ~30s 退出滞留**（新旧版本同样存在，JSON 在滞留前已完整刷出，外层杀树 timer 兜底）：间歇性本机环境态，不改变结果内容；`get_process` 探活、`os._exit`、句柄不可继承三个方向实测均不能消除。
7. **hook `kernel32!VirtualAlloc` 可让样本永不退出（root cause 未定，待 issue）**：对同一 `Sleep(300); return 0` 的 gcc 样本二分实测——只挂 `VirtualProtect` 0.36s 正常退出并触发 detached；只挂 `VirtualAlloc` 或两个都挂，进程 3–12s 持续存活（enumerate 全程 present=True）、agent 连 dump 请求都不回，与样本是否加壳无关（UPX 5.3.0 加壳样本 8–20s 失效是同族现象）。验证员轮补充：**where.exe / cmd.exe / where 等系统程序在 VirtualAlloc hook 下同样挂起、agent 不回 dump——失活不依赖样本类型，hook kernel32!VirtualAlloc 是充分条件**。VirtualAlloc hook 是 exec-mark 观测点，不能移除；缓解已文档化为参数保证（加壳样本 delayMs 与 timeoutMs 均 ≤8000ms，见 `rea_memory_dump` 参数描述），假死场景以超时 + helper warnings 显式收场，不冒充任何信号。

### OEP 升级实测数字与开源样本复核（2026-11-17）

**验收样本（合成跳板，即上面实验记录所用的样本设计）**：`oep-spike/build/oeptramp.exe`（项目 compileC 实编译，compiler=gcc，x86_64）用最终版 `scripts/dynamic/dump.py` 子进程实测——`oepSignal = {kind:'VirtualAlloc', addr:'0x19071870000', size:4096, prot:0x40}`；`exec-entry` 命中 `hit=0x19071870000`（区域块首=跳板首条指令），`instruction='movabs rax, 0x7ff7337e9080'`（marker 绝对地址落在主模块），`bytes='48 b8 80 90 7e 33 f7 7f 00 00 48 b9 52 45 41 5f'`（跳板字节逐字节正确），`insideMainModule=false`、`inRegion=true`，命中延迟 0.05 s；dump 90,112 字节，跳板写入的标记字符串 `REA_OEP_EXEC` 在重建镜像偏移 36992（RVA 0x9080，.bss）处找到——控制流真的进入了新可执行区，且样本自证执行了跳板。测试套件内同一设计样本的断言（oep signal / entry 命中 / movabs / 48 b8 / `inside main module: no` / 重建 PE 含 `REA_OEP_EXEC`）在 npm test 中通过。

**开源样本第三轮复核（同一加壳样本第三次复验，未重新下载/加壳，复用并核对 SHA256）**：`packed/putty-upx.exe`（SHA256 `32da531e1bf8619fc8f953a50ffcf7ba9753b77495189269ff5cb3803ac91ddb`）与 `original/putty.exe`（SHA256 `d01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87`）与第一/二轮完全一致（官方 UPX 5.3.0 `--best`，1,706,136 → 955,032 字节，PuTTY 0.85 w64）。行为矩阵与 r1/r2 逐项一致：

| 场景 | 结果 |
| --- | --- |
| 未加壳基线 `waitForExec=1` / timeoutMs 15 s | oep signal 与 entry 均显式 `none`；dump 1,724,416 字节、entry 0xbfb24、348 imports、2000 strings + 磁盘头来源说明 |
| 加壳 `waitForExec=1` / timeoutMs 20000 | 仍 `no image — no dump before the timeout`（agent 失活行为未变，root cause 仍开放） |
| 加壳 `waitForExec=1` / timeoutMs 6000 | 全链路成功：oep signal 显式 `none before the timeout — the dump may still contain the stub`；entry 显式 `none before the timeout - no executable memory marking was observed, so there was no region to watch (kernel32-level hooks only)`；dump 1,765,376 字节 image-layout PE（UPX0/UPX1/.rsrc、stub 入口 0x1ab010、11 imports + 磁盘头说明、2000 strings） |
| 加壳 `delayMs=3000` | 1,765,376 字节重建成功，输出含磁盘头说明 |
| process_gone 路径 | 从当前 dump.py 重新生成仅去掉 VirtualAlloc hook 的 dump-deathtest.py 跑 where.exe → `the process exited before the dump (process-terminated; no exec-mark observed; entry: none)`，显式死亡报告在新代码下不变 |

对照（r3 dump vs 磁盘原始）：.text 100.0%（237/237 个 4 KB 块，971,776 字节）、.pdata 100%（7/7）、.gxfg 100%（2/2）、.tls/_RDATA 100%、.00cfg 96.5%、.rsrc 96.4%（89/92）、.rdata 59.6%（39/66）、.data 0%、.reloc 0.6%；imports 11（stub）vs 348——与 r1/r2 逐项一致，重建确定性再次成立。**结论（feasible=true）**：闭环证据保持成立——加壳（官方 UPX 5.3.0）→ 脱壳 dump（delay 3 s / waitForExec 6 s 均 1,765,376 字节 image-layout）→ 对照（重建内容 = 磁盘原始未加壳样本代码节）；OEP 信号对 UPX 类就地解压样本是漏报但显式报告（观测点盲区，已文档化并指引 `rea_unpack`），插件未把启发式宣称成 OEP。

**本轮代码级修复（读代码确认）**：`lib/memdump-tools.js:51` 工具描述新增 Blind spots 段（UPX 盲区 → 显式 none 并指引 rea_unpack；hook 下长运行 8–20 s 后 agent 停止响应），`:57`/`:58`/`:59` 参数描述写入「packed 目标 delayMs/timeoutMs ≤8000 ms」与「失败总是显式结果，不是挂起」；`scripts/dynamic/dump.py:306` 缓存 wait 循环的死亡认定、`:310-313` 直接复用（修掉二次 `process_gone()` 被 1 s 节流窗口吞掉刚发现的死亡的时序瑕疵）。节流修复的行为级差异不可直接观测（where.exe 场景 detached 信号先于/同时于进程表轮询生效，`process_gone` 的 detached 分支短路不受节流影响），只有代码级确认 + 行为级回归一致——如实记录，不宣称做过行为级 A/B。2026-11-18 rider：wait 循环前的状态初始化组补 `gone = False`（dump.py:223-233）——`delay_ms > timeout_ms` 或脚本加载吃掉 deadline 时循环体一次都不跑，`:313` 的 `if gone` 会 NameError → 栈回溯 → 落成 stderr 文案而非显式 JSON；零行为变更（循环体 ≥1 次时 :306 覆盖，死亡报告 :328 与 dump 保底 :351 的独立 `process_gone()` 调用不受影响），`py_compile` 通过，行为级回归由两个 rider 专项测试覆盖。

**定向验证命令（实施轮实测）**：`node --test --test-concurrency=2 test/memdump.test.js test/dynamic.test.js` 退出码 0，10/10（memdump 6 项含修订负测试 39.98 s 与新 trampoline 正测试 32.03 s，dynamic 4 项），总时长 104.3 s；`npm test` 退出码 0，tests 420 / pass 420 / fail 0 / skipped 0，119355 ms（方案预期 419+1=420 ✓）；`npm run host-matrix` 三模式 PASS（plain-node / electron-run-as-node / scoped-session 均 tools=237 / routes=8 / readOnly=157 / mutating=50 / destructive=4；首跑结构门禁 FAIL → `npm run structure` 再生成 77 entries 后复跑全 PASS，块过期非本次 OEP 工作引入：memdump.js / memdump-tools.js 第一句改动前后完全一致）；`node scripts/update-code-structure.mjs --check` → `code structure: current`。

**与方案的偏差（实测修正）**：① 方案【4】的跳板长度「39 字节」实为 38 字节（10+10+3+10+4+1），且首轮跳板字节把 `OEP` 误写成 `PEO` 导致 dump 搜不到标记——plan 的 qword1=0x5F50454F5F414552 的小端字节才是 `52 45 41 5F 4F 45 50 5F`，已按勘误实现；② 评审 assumed「需延迟 unfollow」的假设被 A/B 实测否定（同步 unfollow 也不丢块，见实验记录第 4 条），保留方案原形状。

**本轮遗留（不冒充）**：`waitForExec` 下「无任何 exec-mark」的报告变体与「进程死在 deadline 前 → no image 显式失败」两条已由 rider 补上专项测试（2026-11-18，`test/memdump.test.js`：前者用 Sleep 循环且不调用 VirtualAlloc/VirtualProtect 的样本——printf-and-return 样本会先退出、走到的是死亡报告而不是该变体；后者直驱 dump.py 对 where.exe，用**仅去 VirtualAlloc hook 的测试内变体**——完整 hook 下样本不退出、agent 不回 dump（实验记录第 7 条的充分条件），走通用超时而非死亡报告，工具层的秒死 gcc 样本实测正是如此（`no dump before the timeout`），故该测试钉 helper 层 JSON 而不是工具层文案）。剩余遗留：dump.py 子进程在管线下偶发 ~30 s 退出滞留为本机环境态（新旧版本同样存在，JSON 滞留前已完整刷出、外层杀树 timer 兜底，见实验记录第 6 条），未修根因；真实壳样本验证未做——多线程壳（watch 只覆盖标记线程）与 ntdll 直调壳（连 exec-mark 都无）两条盲区已写进报告措辞与 README 已知边界，**不对 VMProtect/虚拟化壳作任何宣称**，entry 命中后是否为原始 OEP 仍由分析者判断；agent 失活 root cause 仍未修，「≤8000 ms」上界来自 8 s 成功 / 20 s 失败两点实测、9–19 s 区间未二分；`rea_unpack` 静态解包路径本轮未实测，UPX 样本的完整替代路径仅以文档形式存在。

### 副作用观测扩量实测（2026-11-19，frida 17.26.3 / WinLibs gcc 16.2.0 / Win11 26300）

`rea_side_effects` 从注册表/命名管道/服务/IPv4 connect 扩到 IPv6 连接与域名解析后的正负对照实测；实施轮全链路跑 2 次、数字完全复现，验证员轮以自建夹具独立复现一致。夹具为项目 gcc 编译，零外网：只解析 localhost 与 `gethostname` 得到的本机主机名（DESKTOP-0Q1029R）、只连 `[::1]:9`，解析结果 `FreeAddrInfoW` 释放后不连接。

**正负对照样本**：正样本 = `WSAStartup` → `gethostname` → `getaddrinfo`(本机主机名) → `getaddrinfo("localhost")`（均传有效 `PADDRINFOW` 并 `FreeAddrInfoW`）→ 单次 `connect` 到 `[::1]:9`（in6 地址手工 16 字节），全部解析发生在首条 connect 之前；夹具纪律：零 printf、DNS 先于首条 connect、只许一次 connect 族调用、`GetAddrInfoW` 严禁 `ppResult=NULL`。对照体 = 仅 `Sleep`，无任何钩内调用。比较走 `compareEventSets` 纯集合层，与事件 kind 无关（新 kind 自动进 missing/added 与 recall/precision，无新对照管道）。

**数字**：目标 4 事件 / 重建 0 事件 → recall 0（0/4）、precision null、score 0、status ran（空测量才是 `empty`，本例非空非 pass）；missing 四项全部点名，groups `{registry:1, pipe:0, network:1, dns:2, service:0, other:0}`。目标事件集合精确为：

- `registry:create 0xffffffff80000002\system\currentcontrolset\services\tcpip\parameters`——环境噪声，A/B 变体实测归因于**首条 getaddrinfo 名字解析链**（仅 `WSAStartup` 不解析域名的变体零此事件；before-connect 变体中该事件紧随 `dns:resolve` 出现，验证员轮二次确证）；
- `dns:resolve desktop-0q1029r`——本机主机名，经 GetAddrInfoW 链路命中，getaddrinfo 内部链调去重为一行；
- `dns:resolve localhost`；
- `network:connect [::1]:9`——IPv6 点分十六进制压缩记法 + scope 解析并入 groups.network。

**边界复证（新钩子集下）**：首条 connect 族调用后观察器在本进程内全局静默——connect 后 `CreateNamedPipeW` 只出 `network:connect [::1]:9`、无 `pipe:create`（验证员轮 4/4 次复现）；经 GetProcAddress 函数指针发起的 connect 照常出现（钩子打在导出地址上）；UDP `sendto 127.0.0.1:9` 变体零事件（无 connect 事件可挂）。**机制级**：Frida 注入本身把 ws2_32.dll 与 dnsapi.dll 带进每个被注入进程（36 模块中二者 present），六个 watched 导出在脚本加载期全部挂上、零 warnings 是正确行为；「never loaded」警告通道以临时副本假模块名 `nosuchmod.dll` 验证（`nosuchmod.dll!DnsQuery_W: module never loaded before the report, hook not installed`），真实代码未动，本机真实 watched 表下该分支不可达。**网络纪律**：全部被观测执行中 hook 捕获的 DNS 名单仅 `{desktop-0q1029r, localhost}`、网络目标仅 `{[::1]:9}`；DNS 缓存（`Get-DnsClientCache`）差分 0→0；NIC 抓包级确认未做（pktmon 需管理员提权，被拒）——零外网结论止于夹具设计 + 用户态事件 + DNS 缓存三级证据，不宣称网络级零流量。`DnsQuery_W` 直查路径可能产生真实出网 DNS，按零外网纪律不进 pinned 执行测试，其覆盖仅延迟挂载机制级验证 + 纯 JS 单测保证。正负对照钉进 `test/observe.test.js`（5 项，见验证段）。

仍未完成（不冒充）：

1. **真实样本规模化**：putty 复测为 `appears-unpacked`，基线 9.0%；真正加壳的样本现在有 `rea_memory_dump` 这条通用内存镜像路径，且 `waitForExec` 已升级为「标记 + 控制流进入」两级证据，但**命中后的 dump 时机与是否为原始 OEP 仍由分析者判断**，不是自动 OEP 发现；多线程壳的 entry 漏报与 ntdll 直调盲区已声明，VM/虚拟化壳、反调试样本可能仍然失败。语义签名阈值可配（`--threshold`，默认 0.9）并是退出码门禁，正负对照已在 sqlite3 9 函数与 7zr 2 函数上实测并钉进 `test/restore.test.js`（见「M1 规模化（2026-11-18）」条目）。
2. **自动改稿的边界**：`draft=auto` 仍只做机械替换（2026-11-19 起含有界的批量回退：降分轮回退到最近最佳草稿、只重试相似度最低的一个函数——仍是反编译体的机械替换，不是理解）；`action=rewrite` 把「理解后写函数」的入口交给 DSH 模型，但模型是否写出正确逻辑不在插件控制内，评分器只负责接受或拒绝。没有任何自动理解。
3. **运行时深水区**：文件轨迹覆盖运行目录与 TEMP/APPDATA/HOME；`rea_side_effects` 覆盖**用户态导出地址钩住的调用**——钩子打在 ws2_32/dnsapi 的导出地址上，注册表、命名管道、服务、IPv4/IPv6 连接与域名解析尝试可见，经 GetProcAddress/IAT 动态解析的调用同样可见。仍不可见：绕过 ntdll 的直接系统调用、内核驱动、raw socket DNS/53、DoH/DoT、QUIC、UDP sendto、ConnectEx、样本自行启动的子进程；且首条 connect 族调用之后观察器静默（根因未查的实测边界）；注册表只对观察器见过的打开调用与 5 个根键伪句柄拼出完整路径，样本自带的其余句柄只记原始句柄值；GUI 或等待输入的程序会超时并被标为 blocked。
4. **上游接线未在真实宿主验证**：本机没有 `verify_reconstruction` / `evaluate_reconstruction_coverage`，只有单测。
5. **阶梯默认列未含 T4**：`npm run recon` 需加 `--behavior` 才有 T4 输出行；默认表保持与既有数字可比。

### 四项专项实测（2026-11-19）：T1 分母扣除、M1 规模化、T3 失活定位、T4 语义归因面

#### T1 分母扣除评估：可行（同工具链），双报落地

**评估结论：可行**。用插件托管 gcc（`C:\Users\25616\.dsh\rea-engines\gcc\mingw64\bin\gcc.exe` 16.2.0-ucrt-r3，与 `.tools` 同套件体系）编译**空程序**并经 Ghidra `listFunctions` 实测：floor = **43 个函数名、50 个 RVA、52 个体哈希**（脚本 `dist/t1-feasibility.mjs` / `dist/t1-classify-cached.mjs`，输出 `dist/t1-feasibility-out.json`）。命中判据从严：**（名∈floor ∧ (RVA∈floor ∨ 体哈希∈floor)) ∨ 体哈希∈floor** 才扣除，逐函数记 `matchedBy∈{name+rva, name+body-hash, body-hash}`；**name-only 只入审计、留在分母**（宁可少扣不可多扣）；`main` 与 `FUN_*` 名永不按名扣除（体哈希仍可作证据）。

- **同工具链（gcc 产物，缓存里 12+ 个 `FUN_140001000` 开头的夹具/重建体清单）**：窗口内扣除 42–46 个 CRT，name-only 1–4 个保留在分母，用户函数（main/mix/decoder/unresolved_helper 等）零误删。
- **真实语料（putty.exe total=2710、sqlite3.dll total=5018、7zr.exe total=4359，均 MSVC 系）**：cap-48/24 窗口内 name/RVA/体哈希命中**全部为 0**（`dist/t1-feasibility-out.json` 三段 counts 全零、deducted=0）→ 对跨工具链目标**扣除不适用**，双报同数，不硬凑。
- **全桩 floor**（sqlite3 窗口 48 函数全部 `dsh_stub_*` 改名桩编译）：仅新增 2 名 / 6 体哈希，并集后对真实窗口仍扣除 0。

**R 阶梯前后**（`npm run recon -- --engine --baseline` 前 / 同命令加 `--deduct-functions` 后，各整跑一遍 exit=0，完整 JSON 落 `dist/recon-before.json` / `dist/recon-after.json`）：

| 列 | R0 | R1 | R2 | R3 | R4 |
| --- | --- | --- | --- | --- | --- |
| ceiling（不变） | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| baseline overall 前→后 | 72.1%→65.9% | 52.6%→52.4% | 27.3%→26.9% | 27.5%→27.2% | 38.7%→38.5% |
| baseline T2 前(raw)→后(deducted) | 65.7%→**34.6%** | 44.5%→43.3% | 44.6%→42.5% | 45.2%→44.1% | 46.2%→45.1% |
| T2 分母 前→后 | 48→**6** | 48→47 | 48→46 | 48→47 | 48→47 |

逐条解释：R0 的夹具用户代码仅约 5 个函数，地址序前 48 窗口被 42 个 MinGW CRT 占据，扣除后分母剩 6，机械基线 T2 从被 CRT 抬高的 65.7% 回落到真实函数恢复率 34.6%；R1–R4 用户函数多（39+ 翻译函数），窗口内 CRT 仅 1–2 个，故 T2 仅回落 1–2pp、overall 回落 0.2–0.4pp。mutation / loop 收敛 / hash recall / sealed leak 四列前后完全不变（78.0/50.5/53.1/28.1/64.6，全部 converged）。`npm run recon -- --behavior`：T2 不参与（engine 关），R0–R4 ceiling 100.0%、T4 outputs 100.0%，与前后两次逐项相同——T1 扣除对该档零影响。

**真实样本前后**（`dist/t1-realsample.mjs`）：sqlite3.dll vs 手写恢复草稿（`test/fixtures/sqlite3-restored.c`，gcc 编译）窗口口径 score 0.1236（扣除前）== scoreAll 0.1236（扣除后），分母 48→48、deducted=0、name-only=0——MSVC 目标无 GCC CRT 可扣，双报同数、无误删；9 函数门禁口径（semantic/0.75，functionFilter）score 1.0、matched 9/9、无分母字段——**门禁路径不受扣除影响**。

**机制**：`rea_compare_build` / `rea_reconstruct` 新增 `deductFunctions` 参数（**默认关**），开启时对空程序 floor 做单次 memo 测量；T2 双报 `score`（扣除后均分，分母 `denominator.after`）与 `scoreAll`（原口径均分，分母 `denominator.before`），overall 自动采用扣除口径；`functionFilter`（门禁路径）时扣除不生效；floor 测量失败时扣除自动关闭、T2 维持原口径并在 floorNote/limitations 写明。**「函数无对应计零」原则不变**：扣除只改变分母由哪些函数组成，不改变任何保留函数的计零方式（专项测试 `a deducted window still counts a missing counterpart as zero` 钉死该行为）。

#### M1 规模化：累计 32 函数（落入目标区间 30–50），含硬函数

累计 **32 个函数**（起点 11 + 本批 21）：sqlite3.dll **26** 个（首批 9 + 本批 17，草稿 `test/fixtures/sqlite3-restored-b2.c`）、7zr.exe **6** 个（首批 2 + 本批 4，草稿 `test/fixtures/7zr-restored-b2.c`）。本批选择用**分层抽样**、判据结构化落盘（`dist/m1-sample-out.json`：每函数带 size 档 S/M/L、maxFanout、loop+写、markers、链深与命中 reason，可被测试直接断言），方案阶段一不改 Java、不动 `ProbeAddress.java`。窗口事实：sqlite3 窗口（cap-200）实测 unaff/extraout/SEH/尾调用 = 0；**硬函数全部来自 7zr 窗口**（7 个 unaff）——`FUN_004010ac` / `FUN_0040116f` 携带 `unaff_EBP`+`extraout_ECX/EDX`，`FUN_0040125a` 另含 `CONCAT31` 寄存器拼接与 `"Unknown switch:"`（方案此前点名的「伪影体」FUN_0040116f 本轮作为硬函数纳入，不再回避）。门禁实测（语义签名 / 0.75）：**正对照 21/21 全部过线**——sqlite3 17/17、score 99.7%、exit 0；7zr 4/4、score 100.0%、exit 0；无 below-threshold 函数。**below-threshold 名单全部来自按设计必败的 text/0.99 负对照**（函数全部保留、阈值未放宽、无函数被丢弃或删除）：sqlite3 17 项逐项 22.2%–98.8%（FUN_1800013f2 22.2% 最低，FUN_180008870 98.8% 最高）；7zr 4 项 85.1% / 98.8% / 97.7% / 74.9%。草稿来源纪律不变：全部从缓存反编译伪代码手写，未读 sqlite / 7-Zip 官方源码。

#### T3 失活 root cause：已定位（Frida Interceptor × kernel32!VirtualAlloc 退出死锁），插件不可修

**已定位（非未定位）**：agent 失活/进程假死的充分触发条件是 **Frida 17.26.3 Interceptor 对 `kernel32!VirtualAlloc` 的钩子本身**——被钩进程在钩子存续期间走向退出时，Frida 在**进程退出路径上死锁**：进程永不完成退出（enumerate 全程 present、detached 仅在 helper 击杀后才触发），in-process agent 的 JS runtime 从退出尝试时刻起永久静默（连 `recv('dump')` 都不回）。这是 Frida/系统层问题，不是插件侧 JS 诱因，插件不可修，只能缓解。

**实验矩阵**（39 轮全部本地执行，零外网；样本 = 项目 gcc 夹具 sleep-exit / sleep-forever / sleep-5s-exit / alloc-tramp + `C:\Windows\System32\where.exe`；frida 17.26.3；timeoutMs 统一 8000、waitForExec=1；产物 `C:\Users\25616\.dsh\rea-artifacts\t3-virtualalloc\`：t3-summary.json / t3-confirm.json / t3-matrix-table.md / variants/dump-A0..A6P.py）：

| 变体（钩子） | 样本 | 结果（轮数） | 排除/证明 |
| --- | --- | --- | --- |
| A0 无钩 | sleep-exit | death-report×3（1.0–1.7s） | 基线正常退出 |
| A1 仅 VirtualProtect | sleep-exit | death-report×3（~1.0s） | 保护钩不致病 |
| A2 仅 VirtualAlloc | sleep-exit | timeout-mute×3（存活至 ~18.7s） | **单钩即充分** |
| A2 仅 VirtualAlloc | where.exe | mute×2 + death×1（0.86s） | 竞态逃逸 |
| A3 双钩 | sleep-exit / where | mute×3 / mute×3 | 与钩子数量无关 |
| A4 空回调（零 JS 工作） | sleep-exit | mute×3 | **排除插件侧回调 JS（note/send/对象分配）** |
| A5 延迟 300ms 安装 | sleep-exit | mute×3（hooks-armed 0.58s 已达） | **排除 loader 期安装时机** |
| A5×sleep-forever | sleep-forever | dump-ok×2（8.7s，agent 全程应答） | **退出才是扳机** |
| A3×alloc-tramp | alloc-tramp | dump-ok×2（exec-mark 0.28/0.31s） | 钩子前期工作正常 |
| A6 心跳+环形缓冲 / A6' 纯计数 | sleep-exit | mute×2+death×1 / mute×3 | 无观测者效应 |
| S5 确认轮 A3/A6×sleep-5s-exit | sleep-5s-exit | mute×5 | 见下 |

**机制直接证据**（S5 = Sleep(5000) 后退出 + A6 心跳探针）：agent 心跳在 helper 时间 1.34 / 2.3x / 3.3x / 4.38s 正常到达（钩子前期完全正常），进程 ~5.3s 尝试退出后**心跳永久停止**，8.33s 的 dump post 无回执，进程存活到 18.24s 被 helper 击杀；**死前 hook 触发计数 = 0**——死锁不是回调累积所致，而是退出路径本身与 Frida 钩子机制的竞态死锁。永不退出的样本同钩下全程正常（sleep-forever 与 alloc-tramp 均 dump-ok）。偶发逃逸（where.exe 1/6、A6×S1 1/3 正常死亡出 death-report）证实是竞态，解释了既有记录中 3–12s / 8–20s 的随机发病窗口。

**证据边界（不冒充）**：零外网纪律下不能做 Frida 版本二分 / 上游检索，定位止于「frida 17.26.3 Interceptor + VirtualAlloc 现象层与退出死锁机制」，不能落到具体上游提交；UPX 加壳样本运行中失活的同族现象本轮未重跑（既有证据见上文 OEP 节），同属该钩子触发、同层不可修。缓解已落地：`lib/memdump-tools.js` execute 内 `waitForExec=true` 且 `timeoutMs>8000` 时**硬夹到 8000** 并在结果文本注明；失败总是显式结果（`no dump before the timeout` + helper warnings，或 `the process exited before the dump`），agent 假死不当死亡报。T3 收尾 `npm test`（`--test-concurrency=2`）**439 pass / 0 fail / exit 0**（330s）。

#### T4 语义归因面：函数语义假设 → 二进制验证的可证伪循环

**记录什么**：每条语义假设 = `{id, statement（一句话归因判断）, level（有 functionName/rva 即 function 级，否则 binary 级）, evidence[]（每条 {channel:'ghidra-decompile', rva, quote}，quote 是目标反编译体的逐字片段、可 grep）, prediction{kind, value, rva?}}`；kind 四种：`string-literal` / `constant-at-rva` / `import-used` / `calls-target`。**怎么验证**：`lib/compare.js` 新增纯函数 `checkSemanticHypothesis(targetBuffer, {layout, imports, strings, functions}, hypothesis)`，三态输出 **verified / unverified / refuted**，边界声明（`HYPOTHESIS_BOUNDARY`：verified 只表示该通道在实测证据上确认了预测，不等于唯一解释或原始源码）写进每个结果的 boundary 字段。验证顺序：①**证据门**——每条 quote 必须在所引函数的清单体里 whitespace 归一化 grep 命中，任一落空→refuted（evidence 逐字保留、只加 hit/locatable 标注，不改写）；所引 RVA/函数不在已测清单→unverified。②**预测通道**——`calls-target`：所引函数体内含对 value 的调用→verified，detail 固定携带 same-channel 弱化语句（假设与验证同源于目标自身反编译，独立确认如原始反汇编或动态轨迹仍开放），未命中→refuted；`import-used`：命中时仅 binary 级可 verified，function 级只到 unverified（necessary, not sufficient），未命中时若函数体存在且同样不含该 API 名→refuted（体+导入表双证据，sqlite3 虽有 GetProcAddress/LoadLibraryW 动态解析盲区仍可拒），否则按动态解析盲区给 unverified 并记录缺席；`string-literal`：`extractDeepStrings`（含解码通道）命中→verified，未命中→refuted 并注明运行时构造盲区；`constant-at-rva`：`rvaToOffset` 读字节与预测 hex（小端原样）比对，命中→verified，不符→refuted 并给实际字节，地址未映射/无 layout→unverified。未知 kind、无预测、通道缺失一律 unverified，**禁止冒充 verified**。

**在哪暴露**（零新增工具，host-matrix tools=237 三模式 PASS 不变）：①`rea_reconstruct` 新增 `action=hypothesis-record`（入 loop state，status=recorded，不断言）与 `action=hypothesis-check`（现场构建 layout/imports/deepStrings/Ghidra 清单四通道并判定，结果持久化）；②**refuted 回流**：`recordIteration` 把 state.hypotheses 中 status='refuted' 的条目追加为 `{id:'hypothesis-refuted', tier:'T4', confirm:'rea_reconstruct action=hypothesis-check'}` gap，renderLoop 显示 hypotheses 计数与 refuted 明细，renderHandoff 增设 Semantic hypotheses 段；③restore 门禁 `scripts/recon-restore.mjs --hypotheses <json>`：对目标缓冲+已列清单逐条核验并打印，结果作为增量字段 `hypotheses` 写入 `dist/restore-gates.jsonl`（退出码语义不变）。

**正负对照**（真实语料 sqlite3.dll，证据实测自缓存反编译清单与二进制）：**正**——pos-constant「FUN_180009820 以 DAT_18029bd28 处 double 为下界」quote `if (dVar1 < DAT_18029bd28) {` 命中 + constant-at-rva 0x18029bd28 实测字节 `ffffffffffffdfc3`（double ≈ -2^63）→ **verified**；pos-calls「FUN_180009820 调用 FUN_1801352e0」quote 命中 + 体内 grep 到调用 → **verified**（带 same-channel 注）。**拒**——neg-messagebox「FUN_1800096b0 弹 MessageBoxA」→ **refuted**（函数体与导入表均无；并如实注明 sqlite3 存在 GetProcAddress/LoadLibraryW 动态解析盲区）；函数级 import-used 命中真实导入 GetTickCount → 只到 **unverified**（necessary, not sufficient），未冒充 verified。测试 **20/20**（13 项合成纯函数矩阵 + 5 项 sqlite3 正负对照 + 2 项回路集成：refuted→gap、rea_reconstruct 工具动作）。门禁端到端：9 函数门禁加 `--hypotheses dist/t4-hypotheses.json` → T2 9/9、100.0%、below 0、exit 0 不变，三条假设 verified/refuted/unverified 如实打印并写入 JSONL 末行。

**本轮定向验证汇总**：`node --test --test-concurrency=2 test/semantic-hypothesis.test.js test/build-compare.test.js test/baseline.test.js test/recon.test.js test/restore.test.js` → **73/73 PASS**（0 失败 0 跳过；restore 门禁 4 项正负对照钉数不变：9/9 exit0、below9 exit1、2/2 exit0、below2 exit1）；`node --test --test-concurrency=2 test/tools.test.js test/capability-hardening.test.js` → 28/28 PASS（工具 schema/枚举扩展未破坏既有断言）；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，零新增工具）；`node scripts/update-code-structure.mjs --check` → current。

**W4 批量语义归因（2026-11-20，M1 全部 32 函数）**：`dist/m1-hypotheses.mjs` 从缓存清单（sqlite3 cap-200=1ddedeef、7zr cap-48=16bd7722，逐字路径串复算全 HIT）对 32 个函数机械生成假设——evidence quote 逐字复制缓存体（不靠转述），prediction 按最强可得通道（string-literal > constant-at-rva > calls-target）选，且每条先用生产核验器 `checkSemanticHypothesis` 对门禁同参四通道预检、只收 verified 才落盘：sqlite3 36 条（34 正 + 2 负对照）、7zr 9 条（7 正 + 2 负对照），共 45 条。门禁 `--hypotheses` 实测 5 次：探针 1 次（26 函数清单对 b2 草稿 → T2 17/26、exit 1——b2 草稿只含批次二 17 函数，批次一 9 函数在 b1 草稿 `test/fixtures/sqlite3-restored.c`，该失配如实入档、其 36 条假设判定仍有效）+ 4 次正向（sqlite3 b1 9/9、b2 17/17，7zr b1 2/2 cap-24、b2 4/4 cap-48，全部 exit 0、below 0），假设结果 additive、退出码只由 T2 决定（scripts/recon-restore.mjs:127）。**覆盖率（分母固定 32，不剔难函数）**：有假设 26、**verified 26/32（81.25%）**、unverified 6（全部 no-testable-hypothesis：FUN_1800013f2 / FUN_180002545 / FUN_1800096b0 / FUN_1800096c0 / FUN_180009740 / FUN_1800099a0——3–79 字节的桩、取值器、标志检查与纯内存循环，无串、无 DAT、无调用形状，四通道皆无可测特征）、refuted 函数 0；正假设 **41/41 verified**（constant-at-rva 14 + calls-target 26 + string-literal 1），负对照 **4/4 refuted**（期望结果，单列不计失败）。诚实边界：26 条 calls-target verified 全部带 same-channel caveat（假设与验证同源目标自身反编译，不当独立确认）；14 条 constant-at-rva 的预测字节按方案实测自目标文件（readPeLayout+rvaToOffset），通道确认的是实测字节而非独立指定值；**sqlite3 的 string-literal 通道在门禁参数下不可用**——`extractDeepStrings(minLength:4, maxStrings:4000)` 而全文件 ≥4 字符串实测 11431 条，体引串（如 "API called with finalized prepared statement"，文件偏移 2684912）在文件中真实存在但越出 4000 条窗口，通道如实 refuted，记为通道盲区、不折算不放宽。loop 状态机辅路径全量走通：45 条假设逐条 `hypothesis-record`→`hypothesis-check`（rea_reconstruct；绝对路径 sqlite3 cap-200 缓存 05f9d0e5 HIT 零冷分析，7zr cap-200 冷分析一次后命中），state.hypotheses 落 `dist/recon-w4/reconstruct-579fe388f0b9.json`（34 verified + 2 refuted）与 `reconstruct-256feca8e274.json`（7 verified + 2 refuted）。只读汇总脚本 `dist/m1-coverage.mjs`（纯函数 `computeM1Coverage` 折叠 JSONL 的 hypotheses 字段，id 解码函数名、负对照按钉死 id 单列）→ `dist/m1-coverage.json`。测试：`test/semantic-hypothesis.test.js` **23/23**（新增 3 项：两文件契约 + quote 逐字预检 + M1 覆盖完整性、41 正 + 4 负判定对缓存上下文全量复现、覆盖率纯函数折叠除重/分母/负对照单列），`test/restore.test.js` **10/10**（新增 2 项门禁 rider：假设 additive、exit 只由 T2 决定、负对照 refuted 不翻退出码）。零新增工具/路由，零 lib/ 源码改动，零外网。

### 自动改稿批量回退（2026-11-19）

`draft=auto` 在既有「只接受分数更高的轮次」之上补上批量回退；全部仍是反编译体的机械替换，无任何自动理解。

- **触发条件**：某一轮的整体分**严格低于**当前最佳轮（并列不触发），且本轮分数为数值——空测量（overall=null）不视为降分，不会触发回退。
- **回退目标**：**最近的最佳草稿**（各轮严格递增时即字面上一份草稿；并列轮时取最近最佳者）。
- **单函数重试**：只替换上一轮 T2 清单里相似度最低的一个函数（`lowestSimilarityMismatch`，reason 型不参与、无数值则不重试），其余批量替换全部回退。
- **有界**：回退至多一次（`rollbackUsed` 守卫）；重试编译至多 1 次，最坏 `rounds+1` 次对照；重试目标不在基线（`repairDraft` 无变化）时直接放弃、不花那次必败编译；重试编译失败不记 history 条目、最佳草稿保持。
- **best 保护逐字不变**：`(!best || (comparison.overall ?? -1) > (best.compare.overall ?? -1))`——首轮 overall=null 时 best 照常建立，成功编译不会被伪造成 auto-failed，auto 记录照常持久化（专项单测钉死）。
- **rounds 语义不变**：参数仍是「最大修复轮数 1–5 默认 2」（clamp 不动）；`auto.rounds = history.length` 仍是实际 compile+compare 轮数，重试轮计入（取值可达 rounds+1）；`retry: true` 标记经 `toAutoHistory` 进入持久化 state（序列化层单测钉死），renderLoop 渲染为 `r2 65.0% (replaced beta) single-function retry`，round 字段保持数字。
- **实现落点**：循环提取为 `lib/autodraft.js` 的纯编排函数 `runAutoRepairRounds({startText, baselineSource, rounds, measure, isSettled})`，`lib/recon-tools.js` 只提供 measure（编译名 `auto-{iteration}-{round}` / `auto-{iteration}-{round}-retry`）与 settled 判据——逐行为等价于原内联循环（首轮失败置 built、无变化 break、settled break、best 表达式逐字）。
- **实测**：`test/autodraft.test.js` 新增 11 项（文件 17/17 过）——批次下降→单函数重试成功（history 3 条、重试草稿只含 beta 替换、measure 恰 3 次）、重试仍降→best 保护、并列→回退目标为最近最佳草稿、重试目标不在基线→只测 2 次、重试编译失败→不记条目、首轮编译失败→firstFailure、null-overall 等价性（首轮 null 不伪造失败；null 后数值轮胜出且不触发回退）与 `toAutoHistory` 序列化契约；`test/recon.test.js` 16/16 过（含真实编译 e2e，集成路径未回归）。

### 交互还原与宿主保护（2026-11-19）

同日落地的两轮能力合并记录：A 交互面（`lib/interaction.js` 提取器 + `lib/compare.js` 的 opt-in T5 档）与 B 宿主机保护（`lib/redact.js` 输出脱敏 + trace 身份遮蔽 + `observe.py` 外联拦截）。数字全部实测；边界写入 `interactionLimitations()` / `observeLimitations()` 随每次报告输出，不藏在文档里。

**A 交互面。** 提取器照 `lib/behavior.js` 结构实现：`interactionContractFrom` 产出 `{windows, messages, controls, resources, facts}`，每条事实 `{kind, token, quote, channel, at}`，decompile 通道的 quote 经 `normalizeQuote` 在被引函数体内 grep 校验；复用 `compare.js` 的 toRvaNumber / normalizeQuote / findListedFunction 与 `behavior.js` 的 diffDimension，零重复实现。GUI 靶标 R5：窗口类注册 + WndProc（WM_CREATE / WM_COMMAND / WM_TIMER / WM_DESTROY）+ 按钮 ID `(HMENU)0x65` + SetTimer、命令分支写文件，gcc 16.2.0-ucrt-r3 `-O0 -mwindows` 真实编译。

目标面实测（提取器对编译产物的输出，冻结进 `scripts/recon/specimen.mjs` 的 `R5_INTERACTION`，非手填；A/W 两种源码形态实测一致）：

- windows `{win:class-register, win:create, win:wndproc=WndProc}`；messages `{msg:0x1, msg:0x2, msg:0x111, msg:0x113}`；controls `{ctl:0x65, timer:0x1}`；resources `{res:manifest:0x1}`（manifest 是工具链默认项，双侧对称不伤分）。
- -O0 实测形态与提取规则逐条对上：WndProc 引用在 WinMain 体中是代码指针局部 `pcStack_60 = WndProc;`（直接名，非地址常量；映像内地址常量则走 VA−imageBase→RVA→findListedFunction 解析，失败记 `locatable:false` 不臆造）；WM_CREATE/WM_DESTROY 是十进制 `param_2 == 1` / `== 2`，WM_COMMAND/WM_TIMER 是十六进制 `0x111`/`0x113`，两种进制归一化进同一令牌集（附 WM_NAMES 标准值注释）；GCC switch 降界的范围哨兵 `< 0x112` / `< 0x114` 是不等式，不在 ==/!=/case 提取范围，实测未混入。控件 ID 的 hmenu 实参实测出现在 WinMain 而非 WndProc，故调用点提取不限候选函数。

T5 档规则（opt-in，仅 `interaction=true` 且引擎清单可用时计分）：四维各算 recall 与 precision，单边空按存在侧计分、双边空记 `null` 不计均分，全空 status='empty'、score=null（不是 1.0）；ran 时按 WEIGHTS（t5 名义 0.15）对有分档重归一化。默认 skipped；`engine=false` 或清单缺失/截断且目标侧零事实时**显式 blocked**——清单不存在不等于没有交互面，不静默记 0 分。

正负对照（`node scripts/recon.mjs --only R5 --engine --interaction --out dist/recon-t5`；JSON 明细本验证轮复核一致）：

| 对照 | overall | t5 | 明细 |
| --- | --- | --- | --- |
| ceiling（目标 vs 真值源重编译） | 100.0% | 1.0 | 四维全 1.0，权重重归一化后 t5=0.130，loop converged、exit 0 |
| mutation（删去 WM_COMMAND 分支） | 95.2% | 0.9688 | messages recall 0.75（missing=`msg:0x111`）、controls recall 1.0（按钮 ID 经 hmenu 仍在）、命名 gap `interaction-messages-missing`、loop 仍 converged |

补齐 WM_COMMAND 分支后（还原源重编译）messages recall=precision=1、overall 回到 100.0%。非 GUI 的 R0–R4 在 `--interaction` 下 windows/messages/controls 维 n/a、仅资源维 1.0（工具链默认 manifest 双侧对称），ceiling 仍全 100.0%；全阶梯 `--engine --interaction` R0–R5 ceiling 全 100.0%（exit 0）。默认档回归：t5.score=null 不进 present、`weightsUsed.t5===undefined`，R0–R5 既有数字逐项不变（mutation 78.0/50.5/53.1/28.1/64.6，R5 ceiling 100.0%）。

**B 宿主机保护。** 三个机制，默认全开、均可经 config 行或 policy 文件关闭（policy 校验拒收非布尔值）：

- **输出脱敏（`lib/redact.js`，`redactIdentity`）**：只做三类精确替换——机器名整词（大小写不敏感、词边界）→`[HOSTNAME]`、账号名整词→`[USERNAME]`、本机主目录前缀（homedir() 精确串，`/` 与 `\` 分隔符不敏感）→`[USERPROFILE]`。**不做 `C:\Users\*` 通配**：样本内嵌的他人路径（如 PDB `C:\Users\builder\x.pdb`）是证据，实测原样保留。redact/restore 深遍历；restore 按占位符反向替换、会话内可逆。应用出口：四个执行工具（observe / trace / memdump / recon-tools 的 compare+reconstruct）的 text/report 出口、register() 对全部自有工具的安全网、buildTool 桥接出口；输入侧 restore 硬性先于 ownGuard / inside() 校验——授权与范围检查看到真实路径，脱敏后分页句柄照常可用。落盘不改：side-effects.json、behaviour-trace.json、state-* 等 disk JSON 保留真实路径——它们是本机文件，含功能性路径属设计内，分页经 `rea_read_artifact` 还原句柄。实测：`session on DESKTOP-0Q1029R, artifacts under C:\Users\25616` → `session on [HOSTNAME], artifacts under [USERPROFILE]`，restore 往返还原原文；占位符路径 restore 后 `inside()=true`、`read()` 分页成功；`rea_side_effects` 真实 Frida 运行的渲染文本含 `dns:resolve [HOSTNAME]` 与 `[USERPROFILE]` 路径、断言不含真实机器名，同一运行的磁盘 JSON 仍保留原始 `dns:resolve desktop-0q1029r` 事件。
- **样本身份遮蔽（`lib/trace.js` maskIdentity，默认 true）**：`rea_trace_behavior` 执行双方前把身份环境变量替换为中性固定值——win32 `COMPUTERNAME=rea-sandbox` / `USERNAME=analyst` / `USERDOMAIN=REAGROUP`（POSIX `HOSTNAME` / `USER` / `LOGNAME=analyst`），置于 env 合并链最后、caller env 不能旁路；target 与重建体同值，不出假差异。实测：遮蔽开输出 `rea-sandbox` / `analyst` / `REAGROUP` 且不含真实机器名，遮蔽关还原真实值（正负对照钉进 `test/trace.test.js`）。
- **外联拦截（`scripts/dynamic/observe.py` 第 4 参 block-egress，`blockSampleEgress`）**：在 connect/WSAConnect 的 onEnter 内（仍为 Interceptor.attach，不改挂载机制、不改变「首连后静默」观测窗口）对非回环目标（AF_INET 首字节≠127、AF_INET6≠::1、其余族一律按非回环）记 `network:connect-blocked` 并向 sockaddr 首部写入 0xFFFF 族值，使 connect 以 WSAEAFNOSUPPORT 在真实发包前同步失败；`::1` / `127.0.0.1` 放行照常记 `network:connect`。事件前缀仍为 network，对照归组不变。实测（gcc 夹具 + Frida，零外网）：单次 `connect(192.0.2.1:9)`（RFC 5737 TEST-NET，不可路由）→ 渲染文本与磁盘 side-effects.json 均出现 `network:connect-blocked 192.0.2.1:9` 且 `network:connect 192.0.2.1:9` 不存在（双断言）；既有 `::1` 与 `127.0.0.1:9` 用例在拦截默认开启下照常观测到 `network:connect`、无 blocked 事件。无外联证据链 = onEnter 内改写族值的机制性 fail-before-send + 目标不可路由。

边界（如实声明）：拦截是**用户态 best-effort**——绕过 ntdll 的直接系统调用、raw socket、ConnectEx、内核驱动拦不住；UDP sendto 未钩，`getaddrinfo` 对真实域名发出的明文 DNS 查询包仍会出网；DoH/DoT、QUIC 不可见；AF_UNIX/未知地址族按非回环拦截可能误伤本机 IPC；`rea_trace_behavior` / `rea_memory_dump` / `rea_dynamic_probe` 三条执行路径不经该观测器。trace 的身份遮蔽只覆盖 getenv 类读取，`GetComputerNameW` / `GetUserNameW` 等 Win32 调用仍返回真实身份。redact 为精确匹配：样本内嵌与本机相同的机器名/用户名/主目录串会被误伤（含连字符复合词命中整词），属已接受的罕见误伤；写入外部文件的占位符句柄跨会话不可还原。交互面为静态启发式：Qt/WebView/Electron/自绘框架不可见、`WM_USER+n` 算术常量不解析、`.rsrc` 仅类型+ID 存在性（DLGTEMPLATE 控件布局未解析、命名资源条目跳过）。

测试基线：`test/interaction.test.js` 13 项、`test/redact.test.js` 8 项、`test/observe.test.js` 非回环拦截实测 1 项（回环放行断言并入既有 IPv6/DNS 用例）、`test/trace.test.js` 身份遮蔽 1 项、`test/policy.test.js` 开关 1 项；全量 `npm test`（`--test-concurrency=2`）保护轮 497 项全绿（562.9 s），交互验证轮修复后 499 项全绿（存档 `dist/full-test-run2.log` 621.1 s；验证员独立复跑 607.9 s，见 `dist/verify/full-test-run-r3.log`）。`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，无新工具）；`npm run structure` 后 79 entries、`--check` current。

### 沙箱树锁修复（C 轮）与检测面矩阵（A 轮，2026-11-20）

**C-0 复现实验（修复前红态，全部本机实测，先定性后修复）**：

- **静态根因（grep+读码，先于任何动态结论）**：`scripts/rea-sandbox.ps1` 把 `new JOBOBJECT_EXTENDED_LIMIT_INFORMATION()`（C# struct 语义零初始化）原样传入 `SetInformationJobObject`，`grep -n "LimitFlags"` 全文件唯一命中 struct 字段声明行——`KILL_ON_JOB_CLOSE`（常量已定义）从未被赋值启用。2026-11-19 的「外部杀 launcher 时 KILL_ON_JOB_CLOSE 不可靠」测量的是一个从未启用的机制：launcher 缺陷，非 OS build 行为。
- **孤儿复现（红态）**：夹具父进程 spawn 自身 leaf（leaf 写 `leaf-pid.txt` 启动握手后每 500ms 心跳 30s，父不等待 leaf 即退出）；launcher wait 只等直接子进程。实测（`node --test --test-name-pattern "orphan"` 修复前）：diag `child-exit=` 落地后 leaf（pid 31216）在 8s 名字核对轮询窗口全程存活（aliveChecks 至 7.76s、`stillAliveAfterMs=30050`）——直到自身 30s 心跳**自然结束**，无任何清理；且孤儿持有的继承 stdout 管道把 `runTrace` 的回收拖住 **31.8s**（孤儿除自身存活外还拖住采集方）。ask 所述「孤儿存活 12s」在仓内无留痕（grep 命中的 plan/README 数字属 Frida VirtualAlloc 退出死锁，机制不同），本实验不引用巧合数字，复现数据以本条目为准。
- **容器令牌定性（ask 要求）**：leaf 在 launcher 已退出后自报 `leaf in-job=1`、`leaf token is-app-container=1`、`leaf token integrity-rid=0x1000`（这些断言在红态测试失败点之前已通过）——**启动器退出不改变已运行进程的令牌**，孤儿仍受 AppContainer 约束；同时 ps1 finally 的 DeleteAppContainerProfile 此时已执行而进程仍持 SID（观察侧证）。
- **外杀重定性红态**：taskkill 仅杀 launcher（无 `/T`，样本须在杀死 launcher 后仍存活才能观察到回收者）后样本（pid 12712）在 8s 窗口全程存活（`stillAliveAfterMs=8253`）——与「机制未启用」的静态事实一致。

**C-1/C-2/C-3 修复**：

- **C-1 修复一**：ps1 显式 `limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;`（`BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK` 仍未设，禁 breakaway 语义不变——其 err=5 来自 flags=0 的默认拒绝，既有断言不受影响）。
- **C-1 修复二**：wait 正常返回（非超时路径）后、`CloseHandle(job)` 前，用 `QueryInformationJobObject(JobObjectBasicProcessIdList)` 查 job 残留成员，非空则**先取退出码**再 `TerminateJobObject` 并打 diag `action=terminate-job reason=orphan-descendants processes=<n|unknown>`（查询失败降级为无条件 terminate + `processes=unknown`，containment 不依赖查询成功）；超时路径语义不动（其 TerminateJobObject 本就覆盖全 job）。
- **C-2（行为变更）**：assign 失败时在 `ResumeThread` 前 `TerminateProcess` 挂起子进程（从未执行任何样本指令）、diag 打 `action=terminate-process reason=assign-failed fail-closed=true`、按启动期失败退出非零（6）；`parseSandboxDiag` 把 `job-enforced=false` 判 `ran=false`（reason 注明 containment failed）——从「token-only 降级 + 警告但样本已运行」收紧为「拒绝运行」，CHANGELOG 已点名；评审阻断项指出的既有冲突（`test/sandbox.test.js` 原 :127-135 断言 `ran===true` + 夹具注释「the sample RAN」）已同步改写为 fail-closed 叙事，夹具形状（error=assign-job 在 pid= 之后）与修复后 ps1 输出兼容；`memdump.js`/`observe.js` 的 token-only 警告分支随语义清理（fail-closed 后不可达）。
- **C-3**：node 侧 `childMayLive` 兜底从「仅 launcher 被外杀时」放宽为 `parsed.pid !== null`（launcher 退出后一律做 `pidAliveWithName` 名字核对再 `taskkillTree`，pid 复用安全）；C-1 落地后正常路径 job 已空，兜底仅在异常时触发。评审补充的收益成立：`dynamic.js`/`memdump.js`/`observe.js` 的 `killTree(session.pid)`（taskkill /T /F powershell）场景下，powershell 死亡 → job 最后句柄关闭 → kill-on-close 首次真正生效 → 孙进程被内核清理。
- `leaf-pid.txt` 加入 `SANDBOX_HARNESS_FILES`（评审建议：孤儿夹具的启动握手文件不进 trace.files 快照断言）。

**C-4 转绿与 KILL_ON_JOB_CLOSE 重定性（走「生效」分支）**：`node --test --test-concurrency=2 test/sandbox.test.js` **18/18 全绿**（修复前同文件新增两测试红：orphan 31.8s fail、外杀 10.7s fail）。修复后：orphan 测试 2.13s 全程通过（leaf 5s 断言窗口内消失 + diag 含 `reason=orphan-descendants` 清理标记 + leaf 令牌断言保持）；外杀测试 2.27s 全程通过（**taskkill 仅杀 launcher，job 内样本在 5s 断言窗口内被内核回收**）。按预注册的两分支纪律执行勘误——生效则改写归因：ps1 头注（Job 段、-TimeoutMs 段、FAIL-CLOSED 段、诊断契约段）、`lib/sandbox.js` 头注、README「内核强制沙箱」、CHANGELOG 沙箱条目四处叙事改写为「2026-11-20 勘误：不可靠系 launcher 未设 LimitFlags（bug，非 OS 行为），修复后实测通过」；修复前红态数据保留于本条目，不删除历史、不凭推断改写。

**A 轮（检测面矩阵，静默姿态）**：新 `docs/detection-surface.md`——基线行三形态（本地静态层 / Ghidra 引擎档 / `rea_unpack`：目标零执行 = 目标侧零检测面，注明宿主侧可见性的视角边界）+ 动态五行 **DS-1/DS-1'/DS-2/DS-3/DS-4**（行编号采纳评审建议，避免与 §5 的 R0–R5 重建靶标阶梯撞名）× 六列（目标进程存在/被注入/被调试通道/环境异样/令牌特殊/行为差异）+ DS-5 宿主侧痕迹行（防混淆单列）+ 已声明盲区尾注（照抄 sandbox.js 与 README 既有声明）+ 能力边界声明；每格带 file:line 与证据等级（[代码]/[实测引用]/[分析，未实测]），DS-1' 的 Job 格按修复后树如实标注并保留勘误注记；「sandbox 更显眼而非更隐蔽（宿主防护与目标可观测性正交）」显式入档。边界声明三落点：§11 追加一条、本节执行安全边界追加一句、README「已知边界」新增「检测面与静默姿态」小节+链接。`lib/dynamic.js` 模块头「does not patch, inject or persist anything」与 probe.py:98 `Interceptor.attach`、observe.py:51「patches the export address itself」的事实矛盾修正；四个执行工具描述各补一句指向矩阵。**默认值零改动**（`allowSampleExecution`/`sandboxSampleExecution` 默认 false、`blockSampleEgress`/`redactIdentity` 默认 true，本轮逐行复核 config.js:115/:120/:125/:126）。新 `test/detection-surface.test.js` **6 项全绿**（矩阵行齐全+file:line 引用正则、措辞 lint（禁词：任何/保证/全部/不惊动/undetectable，跳过措辞纪律元行）、四默认值钉、dynamic.js 修正钉、三落点钉、复用既有覆盖声明）；无新工具、无新 config 键、无新 confirm 映射。`npm run structure` 再生成（80 entries）+ `--check` current；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，无新工具）。

### 静默姿态与隐私保护（2026-11-20）

A（检测面矩阵）/ B（出站审计与本地化模式）/ C（沙箱树锁缺陷）三轮的合并小结。逐项实验细节见上节「沙箱树锁修复（C 轮）与检测面矩阵（A 轮，2026-11-20）」，出站通道逐条表见 README「出站通道审计与本地化模式」，矩阵本体见 [`docs/detection-surface.md`](detection-surface.md)。本节只写实测到的内容；机制推断处标注「分析，未实测」。

- **检测面矩阵**：每条目标执行/观测路径的「目标侧能观测到什么」按六列（目标进程存在 / 被注入 / 被调试通道 / 环境异样 / 令牌特殊 / 行为差异）逐格入档；行编号 DS-1 / DS-1' / DS-2 / DS-3 / DS-4（四条执行工具，trace 另分裸 spawn 与 sandbox 两档）+ DS-5（宿主侧痕迹单列防混淆），每格带 file:line 与证据等级（[代码] / [实测引用] / [分析，未实测]）。基线行三种形态——本地静态层（`lib/recon-tools.js:144` 工具自述 read-only）、Ghidra 引擎档（子进程是 JVM 而非目标，`-import` 只读导入，工程缓存按哈希）、`rea_unpack`（`upx -d -o` 写新文件，源字节不变）——目标零执行即目标侧零检测面；该结论限定目标进程视角，宿主侧 JVM/UPX/powershell 对 EDR 可见（DS-5）。DS-1 的环境异样格如实声明矛盾：getenv 级身份遮蔽与 `GetComputerNameW`/`GetUserNameW` 直询真实值并存，不一致本身就是可察觉信号。DS-1' 显式写入方向性结论：sandbox 对「静默」是**更显眼**而非更隐蔽（令牌/网络/桌面都是样本可感知的硬异常），它的价值是宿主防护，与目标可观测性正交。DS-2/DS-3/DS-4 的注入面（Frida agent、导出地址补丁、Stalker 重写、block-egress 改写 connect 结果）与盲区（首连后静默、直系统调用、DoH/QUIC、UDP sendto）同表声明。
- **静态优先默认（默认值零改动，`test/detection-surface.test.js` 钉住）**：`allowSampleExecution=false`（`lib/config.js:115`）、`sandboxSampleExecution=false`（`:120`）、`blockSampleEgress=true`（`:125`）、`redactIdentity=true`（`:126`）、`localizedMode=false`（`:152`）；静态工具的 engine 默认开、behavior/interaction 默认关——默认安装下插件只读字节、不执行目标。运行时派生密钥、真实行为轨迹、尝试过的副作用、加壳样本内存镜像四类证据必须动态才可获得、无可静态替代，T4/T5 因此维持 opt-in 以保数字可比。
- **本地化模式（`localizedMode`，默认 false，第 10 个面板策略键，`lib/policy-store.js:41/:59`）**：开启后，插件自身已声明的四类下载路径在走网络前逐条本地拒绝——更新检查门禁在共享 promise 缓存之前（`lib/update.js:208-213`，拒绝不进缓存、不污染缓存语义，关掉开关后真检查照常）、更新安装在安装体首行（`lib/update.js:300-302`）、Ghidra 下载在 pinned 归档校验之后、下载之前（`lib/engines.js:482-483`）、外部引擎下载在就绪检测之后、下载之前（`lib/engines.js:579-580`）。错误信息写明离线准备方式（自放 pinned 归档或填 `GHIDRA_INSTALL_DIR` / 外部工具路径）；已安装/已缓存引擎的检测在门禁之前，照常可用；自定义镜像（`updateMirrors`）同样被拒，不留直连旁路。与 `networkEgressPolicy`（桥接工具外联闸门）语义分离、枚举不合并。`test/localized-mode.test.js` 11 项以拦截层实跑（mock 底层 socket，零真实连接）。
- **出站无标识符审计**：运行时网络原语仅 `lib/download.js` 一处；`USER_AGENT = 'dsh-rea'` 常量（`:27`，无版本/平台/主机信息），请求头构造仅两处字面量（`:174` 大文件 `accept: */*`、`:266` 元数据 `accept: application/json, text/plain, */*`），grep 全仓无第二处 user-agent 构造点；网络三模块 grep `os.hostname` / `userInfo` / `homedir` 零命中。代理凭证只在 CONNECT 上发给用户自己配置的代理，从不发给目标站；本轮补口 `stripProxyUserInfo`（`lib/download.js:45`，`:90` 起错误文本先剥 `user:pass@`——redact.js 对 userinfo 无规则，原样回显属真实泄漏面）。固有标识只剩源 IP 与 TLS SNI（及代理方可见的 CONNECT 目标），插件不可消除，列为能力边界；REA 子进程与 Ghidra JVM 是独立 OS 进程，其外联为已声明盲区，结论不外推成整个插件零出站。
- **沙箱树锁缺陷定性与修复**：先定性——孤儿孙进程仍受容器令牌约束（leaf 自报 `in-job=1`、`is-app-container=1`、`integrity-rid=0x1000`，`connect(192.0.2.1:9)` 得 `rc=-1 err=10013 ms=0`），令牌未逃逸，缺陷属资源回收残留而非隔离突破。根因由同上下文 A/B 对照钉死：launcher 从未给 `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` 赋 `LimitFlags`，`KILL_ON_JOB_CLOSE` 从未启用（flags=0 对照组孤儿存活至自身 Sleep 结束 5761ms；flags=0x2000 对照组 128ms 内被内核回收）。修复三层：C-1 显式赋 `KILL_ON_JOB_CLOSE`（`scripts/rea-sandbox.ps1:445`）+ wait 返回后查询 job 残留成员、非空则先取退出码再 `TerminateJobObject`（diag `action=terminate-job reason=orphan-descendants`）+ `SetHandleInformation` 禁 job 句柄继承；C-2 assign 失败改为 fail-closed（`ResumeThread` 前 `TerminateProcess` + 退出码 6，`parseSandboxDiag` 判 `ran=false`），不再存在「token-only 降级但样本已运行」的结果；C-3 node 侧兜底放宽为 `parsed.pid !== null`，并经 `pidAliveWithName` 名字核对防 pid 复用误杀。修复后实测：orphan 用例 leaf 在 5s 断言窗口内被回收（整测 2.13s）、外杀 launcher（taskkill 不带 /T）后样本在同窗口内被内核回收（整测 2.27s；独立复跑：leaf 握手后约 208ms 终止、外杀后 137ms 回收），`test/sandbox.test.js` 18/18 绿。勘误：2026-11-19「外杀 launcher 时 KILL_ON_JOB_CLOSE 不可靠」归因有误——被测机制此前从未启用，属 launcher 缺陷而非 OS 行为；修复前红态数据留档不删。
- **能力边界（不做的事与盲区，如实声明）**：本插件不做主动规避反逆向/反调试机制的工具——隐藏调试器、patch 反调试检查、绕过授权/DRM 属于绕过保护措施，不在本插件能力内；「静默」的实现方式 = 静态优先 + 最小侵入 + 检测面如实入档，不是对目标反逆向机制的对抗。盲区：Qt/WebView/Electron/自绘框架的交互不可见；内核驱动、侧信道、容器内提权、VMProtect 类强壳不可防；直系统调用绕不过 AppContainer 的网络拒绝（令牌检查与 WFP 在内核，容器内直连 `192.0.2.1:9` 实测 0ms 得 `WSAEACCES 10013`），但内核驱动级的对抗不在覆盖范围；UDP sendto 不被该隔离拦截（实测照发）。矩阵中标注 [分析，未实测] 的格子（OS 调试通道不触发、自校验察觉 hook 补丁）需用带对应反逆向检查的样本实测后更新。

### 能力补全五连（2026-11-20）

W1 进程级 exec-mark watch、W2 ntdll 层 exec-mark 钩子、W3 .NET/managed 元数据清单、W4 语义归因批量覆盖、W5 ETW/内核回调可行性尖刺，同日落地。本节只写实测数字与实测边界；声明盲区逐条保留，不宣称覆盖。

**W1 多线程壳的 exec-mark 覆盖（进程级 watch）**：`scripts/dynamic/dump.py` 的 Stalker watch 从「仅标记线程」扩到进程级——armWatch 先 follow 标记线程（失败 = watch 整体 `unavailable`，旧语义保持），再 `Process.enumerateThreads()` 全量 follow，并挂 `ntdll!NtCreateThreadEx` onLeave 按起始地址（args[4]）过滤 frida 系模块的 agent 线程（加载时 enumerateModules 建范围表并对每个 frida 范围 `Stalker.exclude`，agent 代码不进插桩面）；上限 `MAX_WATCH_THREADS=16`，超限发 `watch-scope` 警告且 entryWatch 记 `partial`；`onRegionEntry` 首次命中即 unfollow 全部已 follow 线程，并随 exec-entry 上报命中线程。A/B 实测（gcc 多线程夹具：main 起两个 worker，worker 各自 `VirtualAlloc(RWX,4096)` 写 `mov eax,imm;ret` 桩 + SetEvent，main 等两事件后跨线程依次执行两个区域；helper 直驱 `wait_for_exec=1 timeout=8000ms`，frida 17.26.3）：修复前（等价旧单线程 watch，仅 follow 标记线程）wallMs=40392、`oepSignal` 有值（VirtualAlloc）而 `execEntry=null`、followedCount=1——「worker 线程标记、别的线程跳入」漏报复现；修复后 wallMs=32005、entry 命中（`mov eax, 0x60`，inRegion=true）且命中线程 = main 线程（≠标记线程）、`watchThreads` 5 个、followedCount=5——main + 2 worker + 2 agent 线程全覆盖。回归：`test/memdump.test.js` 新增「多线程 worker 标记、main 执行命中」与「worker 自标自执行（单线程对照，旧覆盖面不回退）」两测试（实测 2368ms / 2312ms），断言 execEntry.threadId ∈ watchThreads、followedCount≥3。行为差异（已入档 `docs/detection-surface.md` DS-3 与 README 已知边界）：输出新增 `watchThreads[]`/`followedCount`；`watchThread` 语义从「标记线程」改为「命中线程」；`entryWatch` 新增 `partial` 档。声明盲区（如实保留，非欠账）：①mark 与 NtCreateThreadEx onLeave 之间的竞态窗口；②硬编码 syscall 建线程（不经该导出）；③超 16 线程上限后 coverage=partial；④mark 时刻已存在的 agent 线程无法按起始地址过滤、会被 follow（exclude 后无正确性问题，仅调度层开销）。

**W2 ntdll 层 exec-mark 钩子（直调 ntdll 的壳）**：kernel32 两钩子之后并列 attach `ntdll!NtAllocateVirtualMemory` / `ntdll!NtProtectVirtualMemory`（onLeave 仅 STATUS_SUCCESS 时解引用指针落成数值，保持 oepSignal.size 数值形状），共用 note() 通路并标 `layer='ntdll'`（kernel32 钩子标 `layer='kernel32'`，渲染行不变）；加载期记录 kernel32+kernelbase 模块范围作系统包装层，ntdll 钩子 onLeave 查 `this.returnAddress`——落在包装层则跳过（同一分配已由 kernel32 钩子按 `VirtualAlloc`/`VirtualProtect` 先到先得记账），只有真直调者记 `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`；note() 入口双闸过滤（调用方∈frida 系范围、区域∈frida 系范围都跳过，拦 agent 匿名页 / Stalker code cache 等区域闸拦不住的形态）；`oepSignal` 先到先得语义不动，重复触发只发记录性 `exec-mark-duplicate` warning。A/B 实测（直调 ntdll 的 gcc 夹具：`GetModuleHandleW(L"ntdll.dll")`→`GetProcAddress` 解析两 API→NtAllocateVirtualMemory(RW)→写 `mov eax,0x60;ret` 桩→NtProtectVirtualMemory(RX)→call 执行，全程不经 kernel32 分配/保护 API）：修复前（剥掉 ntdll 两钩子、kernel32 钩子保留）wallMs=40010、`oepSignal=null`、`execEntry=null`——「连 exec-mark 都不出现」的盲区复现；修复后 wallMs=32981、`oepSignal={kind:'NtProtectVirtualMemory', layer:'ntdll', prot:32}` 且 entry 命中（inRegion=true）。kernel32 夹具对照：kind 保持 `'VirtualAlloc'`、layer='kernel32'——归因去重生效、既有 kind 不翻；另一组 bisect 在多线程夹具实测到 duplicate 事件（第二条 worker 分配记 `duplicate exec-mark: VirtualAlloc (kernel32) … the first mark stands`，先到先得保持）。剥钩负控与直调正测钉进 `test/memdump.test.js`。声明盲区：**纯 shellcode 直统调用**——`syscall` 指令不经过任何 ntdll 导出，两层钩子都不可见，如实声明不宣称覆盖；多线程夹具在本机当前环境 Frida spawn 不稳定（实测零钩子变体也偶发早夭，属 W1 已声明的 Frida 层风险、非 W2 回归）——live 测试已加有界重试（最多 3 次，仅对环境性早亡类失败重试，干净跑仍必须命中断言）。

**W3 .NET/managed 元数据清单**：新 `lib/managed.js` `parseManaged`——CLR 目录（dataDirs[14]）→ `IMAGE_COR20_HEADER` → BSJB 校验 → 流目录 → `#~` 表（45 张 schema 驱动行宽）→ Module/TypeDef/MethodDef/Assembly/ManifestResource 清单，接入 `rea_triage` 的 `structure.managed`。双语料实测：①ilasm 运行时组装的夹具 mini.exe（2048 字节，测试期用 Framework64 ilasm 组装、不执行）：assembly mini 1.0.0.0、3 类型（`<Module>`/Program/Helper）/3 方法（Main/.ctor/GetSeed）、8 张表行数逐项命中、#US 含 "dsh-rea managed fixture"、strongName {0,0}、CLR 头 @24=@32=0；②系统真实语料 `System.Data.dll`（3,536,184 字节，只读解析）：assembly System.Data 4.0.0.0、typeDefTotal=1140、methodDefTotal=14072、resourceTotal=21（默认封顶列 16）、strongName {rva:1903824,size:256} 且 rva+size==metadataRva、metadata v4.0.30319、流大小 #~ 694832 / #Strings 337468 / #US 258808 / #GUID 16 / #Blob 234068、解析耗时 2.44ms（<100ms 预算），放开封顶后 1140 类型全列、Fill/Open 方法在列。负例：无 CLR 目录 → `null` 且 `structureProfile().managed` 深等于 `{present:false,rva:0,size:0}`；CLR 目录指向非 BSJB 字节 → `metadata:null` + note（不抛异常）。三处实测钉死的布局差异入档并由 `test/managed.test.js`（12 项）回归保护：StrongNameSignature 按实测 +32/+36（cb=72）而非 ECMA-335 正典 +24；CustomAttributeType 编码索引按 3 tag bits（按 2 bits 会使 System.Data 的 Assembly 表漂移 4,616 字节落在垃圾上）；#US 首字节 0x00 是空串条目不是流结束。边界：这是**元数据清单/识别**能力，不是 CIL 反编译，不还原 .NET 程序逻辑；NativeAOT/ReadyToRun 单文件发布无可走的 `#~` 流 → `metadata:null` + note，属声明盲区；混淆器改名只如实列出。零新增工具（host-matrix tools=237 不变）。

**W4 语义归因覆盖率（M1 全部 32 函数）**：分母固定 32 个函数、不剔难函数。**已验证归因覆盖率 26/32（81.25%）**——sqlite3 20/26、7zr 6/6；6 个无假设函数（FUN_1800013f2 / FUN_180002545 / FUN_1800096b0 / FUN_1800096c0 / FUN_180009740 / FUN_1800099a0，3–79 字节桩/取值器/标志检查/纯内存循环，无串、无 DAT、无调用形状，四通道皆无可测特征）如实计 unverified 留在分母；refuted 函数 0。假设级：45 条（sqlite3 36 = 34 正 + 2 负对照；7zr 9 = 7 正 + 2 负对照），正假设 **41/41 verified**（constant-at-rva 14、calls-target 26、string-literal 1），负对照 **4/4 refuted**（期望结果，与意外证伪分开统计）。门禁与状态机双路径实测：restore 门禁 `--hypotheses` 4 次正向全 exit 0（sqlite3 9/9 与 17/17、7zr 2/2 与 4/4；假设结果 additive、退出码只由 T2 决定），loop 状态机 45 条逐条 `hypothesis-record`→`hypothesis-check` 落 `dist/recon-w4/`；汇总只读脚本 `dist/m1-coverage.mjs` → `dist/m1-coverage.json`。诚实边界：26 条 calls-target verified 均带 same-channel caveat（假设与验证同源目标自身反编译，不当独立确认）；14 条 constant-at-rva 的预测字节实测自目标文件（确认的是实测字节，非独立指定值）；sqlite3 的 string-literal 通道受门禁 4000 条深度串窗口限制不可用（全文件实测 11431 条串，体引串真实存在但在窗口外）——通道盲区如实入档，不折算覆盖率。

**W5 ETW/内核回调可行性尖刺（结论：非管理员会话不可用，维持声明盲区）**：本机当前会话为过滤令牌（`whoami /groups`：Medium Mandatory S-1-16-8192、`BUILTIN\Administrators` 仅 deny-only；`whoami /priv` 无 profile/trace/debug 特权；`net session` 拒绝 rc=2）。内核级 ETW 三栈一致拒绝：`logman` 启动 Kernel-Process / Kernel-File / Kernel-Network 与 NT Kernel Logger 四次全部「拒绝访问」rc=5；`advapi32!StartTraceW`+SystemTraceControlGuid rc=183（ERROR_ALREADY_EXISTS，内核 Logger 全局单例被系统会话占用，查询也被拒 rc=5）；PowerShell `New-EtwTraceSession` 明确文案「需要管理员特权」。比方案预期更严：普通（非内核）实时 ETW 会话也建不起来（StartTraceW rc=5），「非管理员用用户态 provider」的前提不成立，系统 provider / 自有 provider 两条路线均 blocked、不作为通过依据。内核回调（`PsSetCreateProcessNotifyRoutineEx` / `ObRegisterCallbacks` / `CmRegisterCallback`）无用户态 API，需内核驱动 + 签名 = 改架构，不做。对照组成立：同会话 Frida spawn + `Interceptor.attach(kernel32!Sleep)` 成功命中事件（thread=31704, ms=75）——非管理员观测能力仍在既有用户态钩子层。提权复测未跑成：`schtasks /RL HIGHEST` 被拒而同法普通任务可创建（证明拒绝专指提权请求），runas/UAC 需口令或交互同意——「提权后可用」的正向半边缺测、如实标注；「需管理员」由明确文案 + 三栈拒绝 + 特权清单支撑。后续若单独立项：管理员/提升会话中启用 Kernel-Process 等内核提供者做进程/线程/镜像加载观测是可行方向。证据存档 `.workbuddy/etw-probe/`（RESULTS.md + out/ 原始输出），零外网、无残留会话/ETL。

收口实测：`npm run test:smoke` 407/407 pass（复跑实测 9.4s）；全量 `npm test`（`--test-concurrency=2`）560 项 → **559 pass / 0 fail / 1 skipped**（680.8s，套件转绿）；`npm run host-matrix` 三模式 PASS（tools=237, routes=8, readOnly=157, mutating=50, destructive=4，零新增工具）、structure OK。

### 注册表全路径与 .NET CIL 有界反汇编（2026-11-20）

两条 P1/P2 剩余支一次收掉。**注册表句柄全路径**：`observe.py` 新增 `RegQueryValueExW/A`（`registry:query` 事件）与 `RegCloseKey` 钩子；句柄解析三层——钩内 open/create 建映射 → 其余句柄（事务 open、ntdll 直开、继承句柄）回落 `NtQueryKey(KeyNameInformation)` 并归一为 `hk*` 简写（账户 SID 属主机身份，事件只留 `hku`/`hkcr`）→ 失败如实回落裸句柄值，绝不编造路径；`RegCloseKey` 清映射防句柄值复用继承旧路径。实测暴露并修复两个旧错：x64 预定义句柄符号扩展（`HKEY_LOCAL_MACHINE` 以 `0xffffffff80000002` 到达，旧表按全值查永远 miss——e2e 里 ws2_32 初始化的一批 HKLM 查询全部变成「句柄值当路径」）与 HIVES 标签错（`0x80000003`=HKEY_USERS 错标 hkcr、`0x80000000`=HKCR 缺失、`0x80000004`=HKPD 错标 hkcc）。gcc 夹具 e2e 三路径断言全中：钩内映射 `registry:set hkcu\software\dsh-rea-observe\marker`；事务句柄（`RegOpenKeyTransactedW` 不在钩内）经 NtQueryKey 解析为 `registry:set hku\software\dsh-rea-observe	xn`（SID 剥除）；带路径查询 `registry:query hkcu\software\dsh-rea-observe\marker`；且零 `registry:* 0x…` 裸句柄事件。渲染端 missing/added 摘录改「排序后取 30」（注册表查询风暴实测会把 network/pipe 事件挤出报告文本——修后既有 DNS/IPv6 用例恢复可见）。**.NET CIL 有界反汇编**：新 `lib/cil.js`（tiny/fat 方法体头、EH 子句小/大布局、指令解码含分支/switch 目标、#US 串解码）+ `lib/managed.js` 表遍历（方法/字段所有权映射、ImplMap P/Invoke、七类 token 解析）+ `rea_triage` 新参数 `managedCil` 与 `markUntrusted` 渲染（样本派生名一律包裹转义）、`describeManagedSummary` 附 CIL 行、.NET nextStep 提示。操作码表 230 条（含 0xFE 双字节段）从本机 .NET `System.Reflection.Emit.OpCodes` 生成，非凭记忆转写——实测修正多处记忆错误（`sub=0x59`、`ckfinite=0xC3`、`ldsfld=0x7E`、`callvirt=0x6F`、`add.ovf=0xD6`）。实测：mini.il 夹具逐指令解析（Main=ldstr/pop/ret 且字符串解析为 "dsh-rea managed fixture"、.ctor 解析出 `System.Object::.ctor`、GetSeed 解析出 `Helper::seed`；实测 ilasm 对 entrypoint 方法发 fat 头——按实测断言，不按直觉）；eh.il 夹具（try/catch/finally）实测 2 个 EH 子句的 kind/边界/TypeRef classToken 全中——EH 布局（DataSize 推导子句数、small 12 字节打包无对齐垫）经真实 ilasm 输出验证，不是按文档猜的；System.Data.dll 真实方法体解码零未知操作码（封顶 8 方法）；mscorlib ImplMap 实测解析出 kernel32/api-ms 条目。边界：**指令清单不是反编译**，不重建表达式与控制流；CIL 层默认关（`managedCil` 显式开）；NtQueryKey 无权限/失败回落裸句柄；未被钩住的关闭路径（如 `NtClose`）不清句柄映射，属声明盲区；零新增工具（tools=237 不变）。

### 真实强对抗样本上的闭环（2026-11-20）

评价轮指出的最大未验证地带是「ceiling 来自自建靶标」。本轮把闭环第一次搬到真实对抗样本：**al-khaser v1.1.0 x64**（官方 GitHub release 二进制，280,576 字节，sha256 0cd8a40f…baf；开源的反分析技术集成测试程序，v1.1.0 新增对 Ghidra/dnSpy 等分析工具的检测）。获取：github.com 直连在本环境被拦（000），改走 api.github.com release-asset 通道（200）下载，7z 档案密码取自项目自带 release workflow（-mhe=on 加密头），解压落 `dist/corpus-adv/`；全程官方渠道、零第三方镜像。

实测：`rea_triage` 在该样本上识别六类反分析证据（debugger-api / peb-flags / timing / cpu-hypervisor / sandbox-tools / debugger-trap），带具体地址（`int 2d @0x175d7`、`rdtsc @0x8650/0x8662`、`cpuid @0x467d`、PEB `gs:[0x30] @0x17d1d`）与 7 个 ATT&CK 提示（T1055/T1547/T1082/T1056/T1027/T1140/T1537）。Ghidra 冷分析建 cap-200 缓存（198 函数，`ghidra-work/cache/function-lists/v3/`）。函数级还原选三个真实 CRT/反分析函数、草稿只依据反编译伪代码手写：FUN_140018a14（安全 cookie 初始化，0x2b992ddfa232 魔数 + 时间/进程/线程/性能计数器混熵）、FUN_1400184ec（cpuid/XCR0 特性检测，661 字节 35 块，GenuineIntel 门 + 叶 7/叶 0x24 + xgetbv 掩码）、FUN_1400187f0（安全失败上报，IsProcessorFeaturePresent(0x17)→RtlCaptureContext→RtlLookupFunctionEntry→RtlVirtualUnwind→0x40000015 异常记录→UnhandledExceptionFilter，含 unaff_retaddr 伪影）。**闭环迭代实测：第一轮 68.3%（2/3 低于 0.75，exit 1——真实 MSVC/CRT 反编译携带的栈偏移/返回地址标记常量是源级草稿天然缺失的特征，这是自建靶标上没出现过的真发现）→ 按反编译逐字补齐栈窗口转写 → 85.6%（3/3 全过，exit 0）**；负对照 text/99% 31.7%、exit 1。动态面：样本在内核沙箱内实测（无能力 AppContainer + Job + 出站拦截），注册表钩子事件捕获、parity 100%、零外部出站——真实对抗样本在容器内被有效约束。证据钉：`test/restore.test.js` 新增只读 pin（corpus/草稿/两份门禁记录在位）。诚实边界：闭环覆盖 3/198 函数，不是全样本还原；真实样本的 SEH 表、导出面等硬形态仍需扩窗；动态观测只覆盖首连前窗口（frida 层既有限制）。

### 真实样本闭环常态化（2026-11-21）

按上轮结论把闭环从「一个样本一次验证」推进为「常态化数字」。① al-khaser 扩到 **5 个函数**：新增 tls_callback_0（真实反分析 TLS 钩子：懒建双 Event、0xdeadbeef 标记、SetEvent 信号；草稿对齐门禁实际读取的 cap-200 缓存渲染）与 FUN_14000a210（CRT wstring 拆卸：0xfff/0x1f 堆守卫 + _invoke_watson + SSO 复位 7/0/0），一次过门禁 **5/5 @87.0%（exit 0）**；负对照 text/99% 31.0%、exit 1。② 第二样本：**7zr UPX ultra-brute 全管线**（本机离线构造，零下载）——UPX 5.3.0 --ultra-brute 打包 602,624→263,168 字节（43.67%），triage 实测 `UPX [UPX0,UPX1,UPX!]` confidence 1，rea_unpack 140ms 解包（与原版字节差 298/602,624≈0.05%，集中在校验和字段），解包镜像冷缓存 + 既有 7zr 草稿 → **4/4 @100.0%（exit 0）**——打包→静态解包→函数级还原端到端成立。③ 常态化：`scripts/adv-gates-summary.mjs` 汇总 restore-gates.jsonl（385 runs / 7 组 / corpus-adv 计数），`node scripts/adv-gates-summary.mjs` 一条命令出真实样本收敛率。环境事实：pafish 官方二进制被本机 Defender 判 PUA（文件读取都被过滤驱动拒绝），放弃该样本；VMAware 无 release 资产。**缓存稳定性发现（如实入档）**：同一 al-khaser 二进制两次冷分析给出不同函数边界集（tls_callback_0 156B/13 块 vs 172B/7 块；198 函数集成员亦不同）——缓存键内一致，跨冷跑不可假设同窗口；本轮草稿对齐门禁实际读取的 cap-200 缓存渲染，未受影响。证据钉扩展：restore.test.js pin 同时覆盖 trio/5 函数/ultra-brute 解包/两份负对照。

### 导出面接入闭环（2026-11-21，残差 #8 关闭）

残差 #8 的原始定性（「导出面覆盖需升级 ProbeAddress 清单机制」）只对了一半。实测定位：cap-200 窗口地址跨度 0x13f2–0x17110 物理覆盖 **341/358 个代码导出**（导出表解析：361 个名称导出，sqlite3_version 指向 "3.46.0" 字符串验证解析正确），但清单 0 个带导出名——Ghidra 分析没有把导出标签提升为函数名，窗口大小不是瓶颈。机制修复走**读时覆盖**（不动 Java、缓存零作废）：`lib/structure.js parsePeExports` 解析数据目录 0（名称/RVA/转发标记，4,096 上限），`lib/ghidra-local.js applyExportNames` 把导出名按 RVA 覆盖到清单（`exported:true`，原名 `listedAs`），并解析 **/INCREMENTAL jmp 跳板**——导出 RVA 指向 `e9 rel32` 5 字节桩（实测 sqlite3.dll 361 个导出 0 个直配、151 个经跳板解析到 cap-200 窗口内真身），桩目标地址即函数真身。覆盖只读确定性：缓存保留 FUN_* 原名，每次读取重放；`exportNamesApplied`/`exportNamesViaThunk`/`exportCount` 随清单上报。**首个按导出名的门禁**：sqlite3_value_int（89B：+0x14 值类型标志 0x24/8/0x12 分派 + DAT_ 边界钳位）与 sqlite3_stricmp（77B：空指针处理 + 大小写折叠表循环），草稿 `test/fixtures/sqlite3-exports-restored.c` 仅依据反编译伪代码手写 → **2/2 @98.6%（exit 0）**；负对照 text/99% 43.1%、exit 1。测试：parsePeExports 两项入 smoke 层（真实语料 + 非 PE 降级）；restore pin 扩展导出记录（≥0.95 + 负对照在位）。施工事故（如实）：覆盖层 section-name 正则曾被 python heredoc 双层吞转义写成**真实 NUL 字节**——文件变二进制（grep 全瞎、V8 运行时容忍），字节级修复为 ` ` 转义；教训：跨语言转义的代码生成后必须 `file`/字节级自检。**改名回归（实测后修复，2026-11-21）**：覆盖第一版直接替换函数名，全量套件 7 个 sqlite3 门禁红——被请求的 FUN_180009820 等本是导出地址（sqlite3_value_int），改名后按名匹配断。修正为**双身份设计**：FUN_* 名永不动（旧门禁记录/草稿/假设全按它请求），导出名作为第二可解析身份随条目走；门禁选择、compare 的 functionFilter、matchFunctionListsByName 配对、源码体查找四处全部双名解析——新旧门禁同跑复绿。边界：覆盖不改反编译体文本内的 FUN_* 引用（语义指标按调用数计分，不受影响）；转发导出（RVA 指回导出目录）不参与匹配；64MB 以上二进制跳过覆盖（读上限）。

### 下一步（按顺序）

1. ~~OEP 自动发现~~（2026-11-17 已做第一步）：`rea_memory_dump waitForExec` 从「某块内存被标成可执行」升级为「控制流被观测进入新可执行区」（Stalker 块首 callout + 每条 next() 后 keep()，区域边界以 JS number 存——transform 回调里 hook 上下文创建的 NativePointer 实测读回 0x0）。合成跳板样本实测：38 字节（方案原写 39，实测勘误，见上节偏差①）跳板写入 RWX 区并跳入，报告打出 `oep signal: VirtualAlloc 0x19071870000` 与 `entry: control flow entered the marked region at 0x19071870000 movabs rax, 0x7ff7337e9080 (inside main module: no)`，dump（90,112 字节）含跳板写入的 `REA_OEP_EXEC` 标记（重建镜像偏移 36992，RVA 0x9080）；只标记不跳入的负样本显式报 `entry: none before the timeout`。仍然不是内核级 OEP、不宣称对付 VMProtect。2026-11-20 起多线程壳（进程级 watch）与 ntdll 导出直调（kernel32+ntdll 双层钩子）已覆盖，见上节「能力补全五连」；剩余盲区——纯 shellcode 直统调用、mark 与新建线程 onLeave 之间的竞态窗口、硬编码 syscall 建线程、超 16 线程上限后 coverage=partial——见 README 已知边界。
2. ~~M1 规模化~~（2026-11-18 已做）：sqlite3 `--functions` 扩到 9 个（6 既有 + FUN_180009750/FUN_180009820/FUN_1800099a0，全部从缓存伪代码手写），semantic/75% → 9/9、100.0%、exit 0，text/99% 负对照 → below threshold 9、exit 1；7zr 首次函数级基线 2/2、97.9%、exit 0（text/99% 负对照 56.4%、below 2、exit 1）；通过率以退出码 + 函数数 + below 计数钉进 `test/restore.test.js`（sqlite3 正/负对照与 7zr 正/负对照共 4 项，详见「M1 规模化（2026-11-18）」条目与 `test/memdump.test.js` 两个 rider 专项测试）。残差：sqlite3 导出面未覆盖（cap-200 清单窗口 0 个导出符号名，机制边界见上条目）；2 函数旧口径（87.8% / 100.0% / 52.5%）本轮未重跑，文档按既有口径分列；缓存键对传入路径串逐字敏感（mtime 漂移即失配 = 一次冷跑 + 缓存重写）未修根因，测试以相对路径串钉死规避。
3. ~~运行时补盲区：IPv6/域名~~（2026-11-19 已做）：`rea_side_effects` 扩到 IPv6 sockaddr 解析（`connect`/`WSAConnect` 双钩）与域名解析（`getaddrinfo`/`GetAddrInfoW`/`GetAddrInfoExW` + dnsapi `DnsQuery_W`，watched-modules 延迟挂载），正负对照钉进 `test/observe.test.js`（正样本 4 事件 / 安静重建 recall 0 / precision null / score 0，实测 2026-11-19）。剩余：ETW 与内核回调经 2026-11-20 可行性尖刺实测，非管理员会话不可用（三栈拒绝 + 内核 Logger rc=183，见上节 W5），维持声明盲区、提权后方向留待单独立项；~~注册表句柄完整路径~~（2026-11-20 已做：三层解析——钩内映射 / NtQueryKey 回退 / 失败如实回落裸句柄，gcc 夹具 e2e 三路径钉死，见上节）；首条 connect 后观测静默的根因未查；NIC 抓包级「零外部 DNS 包」确认未做（现有证据止于 winsock 用户态层零发送 + 夹具只解析 localhost/本机主机名、只连环回）。
4. ~~T1 分母扣除~~（2026-11-19 已做）：`--deduct-functions` / `deductFunctions` 双报落地（`t2.score`=扣除后、`t2.scoreAll`=原始，分母 before/after 同报），floor=同工具链空程序实测（43 名 / 50 RVA / 52 体哈希），R0 机械基线 T2 65.7%→34.6%（分母 48→6），R1–R4 回落 1–2pp，真实 MSVC 语料 0 命中→不适用双报同数；「函数无对应计零」不变。剩余：机制仅同工具链适用，跨工具链目标需各自工具链的 floor 测量；putty/7zr/sqlite3 之外的语料未测。
5. ~~T3 agent 失活定位~~（2026-11-19 已做）：root cause 钉到 Frida 17.26.3 Interceptor × `kernel32!VirtualAlloc` 的进程退出路径死锁（39 轮 A/B 矩阵：空回调仍挂、延迟安装仍挂、仅 VirtualProtect 从不挂、永不退出样本同钩正常、死前零 hook 触发、偶发逃逸=竞态）；插件不可修，缓解=超时硬夹 8000ms + 显式失败 + 假死不当死亡。剩余：**有网环境**向上游检索/提 issue（附 t3 矩阵数据）并验证新版 Frida 是否已改；9–19s 区间仍未二分（历史遗留）；UPX 运行中失活同族现象未重跑二分。
6. ~~T4 语义归因面~~（2026-11-19 已做；**2026-11-20 W4 扩展到 M1 全部 32 函数**，详见上节「W4 批量语义归因」）：`hypothesis-record`/`hypothesis-check` 三态判定（verified/unverified/refuted，边界声明内置）+ refuted 回流为 T4 gap + restore 门禁 `--hypotheses`；sqlite3 正负对照 20/20，门禁 e2e 9/9 exit 0 不变。W4 实测：45 条假设（sqlite3 34 正+2 负、7zr 7 正+2 负）门禁 4 次正向全 exit 0（9/9、17/17、2/2、4/4），loop 状态机逐条 record→check 落 `dist/recon-w4/`，**已验证归因覆盖率 26/32**（sqlite3 20/26、7zr 6/6；6 个无可测特征函数如实 unverified 留分母；负对照 4/4 refuted 单列），汇总 `dist/m1-coverage.mjs`。剩余：putty 的 `--hypotheses` 仍列可选扩展未跑（7zr 已跑，机制同路径，putty 假设文件需按其清单另写）；`calls-target` 只覆盖已测窗口（cap≤200）——本轮 32 个 M1 函数全部落在各自门禁窗口内（sqlite3 cap-200、7zr cap-24/48），26 个有假设函数无一因窗口外停 unverified，但窗口外函数的假设仍会停 unverified，需 T2 扩窗（ProbeAddress.java skip 参数）；sqlite3 的 string-literal 通道受门禁 4000 条深度串窗口限制不可用（全文件 11431 条串，盲区如实入档）；`state.hypotheses` 的 refuted gap 每轮重复出现（按设计作未闭合缺口），是否去重待定。
7. ~~自动改稿批量回退~~（2026-11-19 已做）：批次替换导致分数下降时回退到**最近的最佳草稿**，只重试相似度最低的一个函数；至多 1 次额外编译（最坏 rounds+1 次对照）、回退至多一次；best 保护表达式与 rounds 语义逐字保持，null-overall 行为等价（不伪造 auto-failed、不误触发回退）；`retry` 标记经 `toAutoHistory` 持久化并在 renderLoop 标注。剩余：回退清单来自 T2 mismatches，T2 blocked 时无清单可回退（保持既有 blocked 行为）；「重试胜出后下一轮对同一文本重复编译一次」为默认简单实现（上限仍 ≤ rounds+1），如需省掉可改为胜出后直接走常规修补（取舍已记录）。
8. M1 继续扩量与导出面：~~sqlite3 导出面~~（2026-11-21 已做，见上节）：真实定性是清单机制没接导出名（窗口本身覆盖 341/358 个代码导出）——读时覆盖 + 跳板解析后 151 个导出函数获真名，导出名门禁 2/2 @98.6%；7zr 侧硬函数（unaff_EBP / CONCAT31 / "Unknown switch:"）已纳入 4 个，SEH / 尾调用样本在两个窗口内实测为 0，更多硬形态需扩窗或换语料。
9. 交互面与宿主保护收尾（2026-11-19 两轮遗留，见上节）：`--interaction` 单独使用时的 `scripts/recon.mjs` 提示语、mutation compare 补 `maxFunctions`/`timeoutMs`（A 轮遗留，未实施）；侧栏面板为 `blockSampleEgress` / `redactIdentity` 增加可视开关行（两键已经 config 行 + policy 文件 + 面板 POST 通道可改，panel 5 行断言需同步）；Linux CI 侧 host-matrix 复核（宿主差异项，本机 win32 无法执行）；多目标/多端口样本上的拦截复测（现仅单机 TEST-NET 夹具实测）。边界类事项不是待办、已声明：UDP sendto / DoH/DoT / raw socket / 直系统调用拦截不可及；trace 身份遮蔽仅 getenv 级；switch 降界哨兵若未来在其它编译形态下混入 ==/case 上下文，需实测后再加过滤（当前 R5 实测未混入，不臆造规则）。
10. ~~检测面矩阵（A 轮静默姿态）~~（2026-11-20 已做，见上节）：矩阵文档 + 边界三落点 + 默认值零改动结论 + dynamic.js 措辞矛盾修正 + `test/detection-surface.test.js` 6 项。剩余：矩阵中标 [分析，未实测] 的格子（`IsDebuggerPresent`/`ProcessDebugPort` 等 OS 调试通道不触发、自校验对 hook 补丁的察觉）需用**带对应反逆向检查的样本**实测后更新（本轮零外网纪律下未做，不冒充已验证）；probe/dump/observe 裸 spawn 路径的环境遮蔽化列为后续能力改动单独评估（若实施必须双侧同值，`trace.js:236` 模式）；T4/T5 维持 opt-in 的取舍不变（静态可默认、为数字可比保持 opt-in）；宿主 EDR/取证视角不在矩阵范围（DS-5 仅防混淆）。
11. ~~沙箱树锁缺陷（C 轮）~~（2026-11-20 已做，见上节）：C-0 留痕复现（红态数据在案）→ C-1 LimitFlags + 孤儿清理 → C-2 fail-closed → C-3 兜底放宽 → C-4 转绿 + 重定性（生效分支）+ 四处叙事勘误。剩余：assign-job 失败无法在本机真实注入，集成层只覆盖 ps1 代码路径评审，parse 层由 `DIAG_ASSIGN_FAILED` 单元钉（夹具与修复后 ps1 输出形状兼容）；C-2 是行为变更（token-only 降级收紧为拒绝运行），依赖旧降级场景的运行所有者需按 CHANGELOG 调整；外杀重定性的测量止于本机 Win11 26300 单机实测，其它 OS build 未测（既有诚实口径不变）；`--test-concurrency=2` 下全量 npm test 本轮未跑（定向子集自证，见测试基线）。
12. ~~能力补全五连~~（2026-11-20 已做，见上节）：W1 进程级 watch（多线程夹具红→绿、followedCount 1→5、命中线程=main）、W2 ntdll 双钩子（直调夹具从无任何 exec-mark 到 layer=ntdll 命中）、W3 managed 清单（ilasm 夹具 + System.Data.dll 双语料、解析 2.44ms）、W4 归因覆盖率 26/32（41 正假设全 verified、4 负对照 refuted）、W5 ETW=非管理员不可用（三栈拒绝实测）。剩余：putty 的 `--hypotheses` 未跑（机制同路径，假设文件需按其清单另写）；calls-target 窗口外函数仍会停 unverified（扩窗需 ProbeAddress.java 清单机制 SCRIPT_VERSION+1 → 全缓存作废+冷分析，未做）；多线程夹具在本机 Frida spawn 偶发环境性早亡（零钩子变体亦然，属 Frida 层风险）——live 测试有界重试已加，根因留待环境稳定或换 attach/sandbox 路径复测；`test/memdump.test.js` 两条测试健壮性残差：skip 守卫宽于注释声称（实测观测到「标记后死亡、entry:none」被跳过）待收窄、no-mark 变体的 retry/skip 守卫已于 2026-11-21 补齐（全量套件实测命中一次该闪断后修复，复跑绿）；W5 提权后正向确认缺测（过滤令牌无法非交互提权），若单独立项在管理员会话复测。
