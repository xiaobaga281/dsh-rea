# REA / dsh-rea 逆向能力评审（1.2.0 修订版）

> 评审对象：`dsh-rea` **1.2.0** 所桥接的 REA 6.7.0 工具面（207 个 MCP 工具）+ 插件自有的 4 个工具
> 评审日期：2026-11-03
> 证据基础：完整 `tools/list` 快照（207 条 schema，83.7 KB）、`reverse-engineer-anything` 技能及其 references、真实会话握手与 `binary_session` 返回、以及 1.2.0 插件侧实现与 71 个测试。
> 与上一版的差别：本版重采了全部量化数据，**修正了一处误判**，并把 1.2.0 新增的插件层能力（结果落盘、变更闸门、状态工具、自更新）纳入评估——它们改变了"哪些短板还能补"的判断，也带来了新的风险面。
> 局限：未对真实样本做全量工具回归；"缺失"结论来自 schema 语义 + 关键词穷举（已逐条核对上下文，排除 `candidate`→`ida`、`network`→`etw` 这类误命中），不代表引擎内部绝无该能力。

---

## 一、结论

它仍然不是"207 个工具的拼盘"，而是一套**以证据为核心的分析工作台**：每个结论要求 observation、limitation 与 Evidence ID，未解问题必须落成带严重度与"所需权威等级"的 residual unknown，交付物可校验、可导入导出。这在同类工具里少见，也是最被低估的价值。

**1.2.0 之后，插件层从"桥接"升级为"治理层"**：结果体积、参数可见性、状态自检、变更闸门、版本自更新这五件事不再由模型自行应对。这修掉了评审里最容易量化的三类失败（上下文挤爆、空转、误改目标），但**没有触及任何一个分析能力短板**——加壳判定、TLS 解密、脚本编排、Windows 调试仍然是空白。

**一句话**：分析能力没变，可用性与安全性提升了一个台阶；剩下最划算的投入，全部在"REA 不做、插件能做"的空隙里。

---

## 二、1.2.0 已落地什么（附实测与残留问题）

| 项 | 做法 | 实测 | 残留问题 |
| --- | --- | --- | --- |
| 结果体积治理 | 超 `maxResultChars`（默认 24 000，可配 4k–200k）的结果写入 `~/.dsh/rea-artifacts/<session>/`，返回摘要 + 路径；`rea_read_artifact` 分页读（限制在产物目录内，拒绝越界） | `binary_session` 原 73 KB 不再进上下文 | 只对文本结果生效；结构化结果（`structuredContent`）走的是序列化路径；产物目录无清理策略，敏感样本内容会长期驻留磁盘 |
| 变更审计 + 闸门 | 30 个写目标/设备/调试会话的工具写入 `audit.jsonl`；其中 4 个破坏性操作（`uninstall/install_adb_package`、`push_adb_file`、`stop_adb_app`）默认拒绝，需 `allowDeviceMutations` | 默认拒绝可用，审计落盘 | **按名字硬编码**：REA 升级后新增的写操作不会自动进闸门，这是"静默失效"型风险，需要改成按 schema/描述或前缀规则 + 未知工具默认审计 |
| schema 按需可见 | `rea_catalog({tool:"..."})` 返回该工具完整 input schema | 13 参数的 `capture_process_scenario` 实测 6 852 字符 | 只给 input，不给 output schema；仍靠模型主动查询，不是失败时自动提示 |
| `rea_status` | 一次调用给出目标 / provider / 引擎 / 受阻能力 | 装配验证输出完整四段 | 解析依赖 `binary_session` 的返回形状，上游改结构就会退化成"unavailable" |
| 多镜像自更新 | 元数据 2 层（GitHub API → 仓库 `update.json` 经两个 CDN）；字节 6 层（GitHub 直连 + 5 个公共镜像，逐镜像重试）；SHA-256 校验通过才解包；`.bak` 备份 + 失败回滚 | 以 `current=1.1.0` 实测返回 1.2.0、来源 `api.github.com`、摘要一致；4 个端到端用例（替换成功 / 校验失败不动原目录 / 版本不符拒绝 / 无摘要拒绝） | 见第七节"供应链"——这是 1.2.0 引入的**最大新风险** |

**顺带修掉的一个真 bug**：Git for Windows 的 GNU tar 会把 `C:\...` 的盘符当成远程主机（`Cannot connect to C: resolve failed`）。凡 PATH 里 Git 的 tar 优先于 `system32\tar.exe` 的机器，运行时解包、Ghidra、WABT、自更新四处都会失败。现已统一传正斜杠 + 失败后 `--force-local` 重试。

---

## 三、能力矩阵

成熟度：**A** 可直接投产 ｜ **B** 可用但有明确边界 ｜ **C** 仅占位或需外部补齐 ｜ **D** 缺失

| 维度 | 覆盖 | 成熟度 | 关键抓手 | 主要缺口 |
| --- | --- | --- | --- | --- |
| 二进制格式解析 | ~30 | **A-** | `inspect_macho`、`inspect_pe_resources`、`inspect_go_binary`、`inspect_wasm_artifact`、`extract_firmware` | 无 dyld_shared_cache 解析；无文件系统镜像挂载/遍历 |
| 证据治理 | ~20 | **A** | `export_evidence_bundle`、`verify_reconstruction`、`record_unknown`、`evaluate_reconstruction_coverage` | 仅 JSON 出口，缺 Markdown / SARIF / STIX |
| 静态分析（native） | ~60 | **B+** | `analyze_function`、`procedure_pseudo_code`、`trace_native_values`、`set_comment`（带读回校验） | 单函数粒度；无全程序图、无 PDB/DWARF 导入、无 FLIRT 式库识别、无二进制 diff |
| 静态分析（managed / JS / Android） | ~45 | **B** | `inspect_managed_members`、`analyze_javascript_application`、`inspect_android_method` | .NET 只到成员哈希与 IL 元组，无 C# 反编译；Android 类级仅到 smali |
| 动态调试 | ~25 | **B-** | `start_gdb_session`（MI3）、`observe_native_calls`（LLDB）、`start_frida_session`、`execute_rizin_command` | **Windows 空白**；无内核/驱动视角；无快照回放；无进程 dump 离线分析 |
| 协议解析 | 7 | **C+** | `inspect_packet_fields`、`inspect_packet_capture`、`decode_signal_recording` | 不能解密 TLS、不能重组流、不能定义协议；无 protobuf/gRPC/ASN.1/CBOR |
| 自动化 / 编排 | 3 | **C** | `batch_decompile`、`capture_process_scenario`、`load_frida_script` | 无脚本沙箱、无语料批处理、无跨会话结果库、无 CI 入口 |
| 对抗 / 反检测 | 0 | **D** | — | 无加壳判定、无熵分析、无 YARA、无反调试对抗、无内存脱壳 |
| 插件层治理（1.2.0 新增） | 4 | **B** | `rea_catalog`、`rea_status`、`rea_read_artifact`、`rea_doctor` | 闸门靠硬编码名单；无敏感产物保留策略 |

**规模事实（重采）**：207 个工具、61 个前缀组、schema 合计 83.7 KB；**55 个（27%）没有任何必填参数**，其中 10 个明确绑定"当前光标/当前文档"——headless 下不先 `open_binary` 就会报"无目标"，这是空转失败的主要来源；30 个工具会写状态；单工具参数最多 13 个。

**引擎耦合（description 命中，已排除误命中）**：Ghidra 24、ADB 29、Hopper 22、Frida 9、Rizin 6、GDB 5、TShark 5、JEB 4、Cutter 2、LLDB 1、**IDA Pro 0**。

> **对上一版的修正**：旧版写"IDA 9"，是 `candidate`、`valid a` 之类子串的误命中。逐条核对后，工具面里**没有任何 IDA 支撑的工具**。因此"Ghidra 和 IDA 都不能注入脚本"这句话也要改：不是"不能注入"，而是**根本没接**。目前唯一的用户代码入口是 `load_frida_script`，命令逃生口是 `execute_rizin_command` / `cutter_command` / `gdb_console`。这也意味着"接 IDA"不是改造项，而是从零新增项。

---

## 四、分维度评审

### 4.1 静态分析

**做得好的**

- **函数档案化**：`analyze_function` 一次给出身份、签名、调用关系、字符串引用、伪代码与局限，比"逐个取字段"更接近分析员的思维单位。
- **可写回且带读回校验**：`set_address_name` / `annotate_native_function` / `set_comment` 让"模型命名 → 落库 → 回归"成为闭环，而不是一次性输出。这是 LLM 辅助逆向里最实用的一环。
- **分页视图**：`inspect_analysis_view` 把大结果按 kind 分页。

**欠缺的**

- **没有全程序视角**：入口全是"一个函数/一个地址"，没有整体调用图导出、类型系统导出，也没有跨函数类型传播。核心逻辑分散在十几个函数时，靠单点查询拼图效率低。
- **符号信息不进**：无 PDB/DWARF 导入，无 FLIRT/Lumina 库识别。静态链接 OpenSSL/libcurl 时只能靠字符串与调用形态猜。
- **没有二进制 diff**：`compare_functions` 比的是**两批 Evidence 记录**，不是两个二进制的结构相似度。补丁比对（1-day 定位）缺图同构/模糊哈希那一层。
- **数据流只到"有界静态依赖图"**（`trace_native_values`），无跨过程指针分析，污点传播只能人工接力。

**边界**：它不替你做"理解"，只整理可验证的局部事实。对混淆过的代码，反编译结果本身不可信，而它没有"反编译可信度"标注。1.2.0 的 `RESULT_GUIDANCE` 仍是两句通用提示，未按工具类型区分——对 `procedure_pseudo_code` 应强制标注"这是推断，不是源码"。

### 4.2 动态调试

**做得好的**

- **多调试器并存且有生命周期管理**：GDB 走 MI3 解析（不是抓 stdout），Rizin 用 `-N` 抑制用户配置保证可复现，Cutter bridge 带 `expected_generation` 并发保护——都是踩过坑才有的设计。
- **LLDB 用法克制**：`observe_native_calls` 只在"自有进程 + 指定断点"下录制调用，不开放任意表达式求值。
- **1.2.0 起破坏性操作有闸门**：`uninstall_adb_package` 等默认拒绝。

**欠缺的**

- **Windows 完全没有**：无 WinDbg/cdb、无 TTD 录制回放、无 ETW。而本机就是 Windows——对 Windows 样本只剩 Frida 一条命，且 Frida 在受保护进程里容易被摘。
- **没有内核/系统视角**：无 eBPF/ftrace（Linux）与 ETW（Windows）的系统调用级观测，只有 `read_adb_logcat` 这类设备日志。
- **没有快照与回放**：调试线性、不可重放；`capture_process_scenario` 能"记录一次"，但缺"回到第 N 条指令"。
- **没有内存取证链路**：不能 dump 进程再离线分析（`inspect_recorded_crash` 只吃 core，且限定 Linux ELF64）。
- **移动端只到"能用"**：ADB 侧 29 个工具齐全，但需设备已连、Frida server 已起；无 AVD 编排；iOS 侧缺 dyld cache / class-dump 配套。

### 4.3 协议与二进制解析

**做得好的**

- **二进制格式深度**：Mach-O 到 slice/load command/权限/签名/entitlements；PE 到资源树与 .NET 的 ModuleRef/ImplMap/非 IL 方法；Go/Rust 取构建元数据与依赖清单；WASM 做类型级接口比较；EVM 静态解析 selector。这是它最扎实的部分。
- **字段级抓包**：先 `inspect_packet_fields` 发现协议/字段，再 `inspect_packet_capture` 按选择取值，"先探再取"避免整包入上下文。

**欠缺的**

- **不能解密**：无 TLS keylog 注入，HTTPS 目标只能看握手。这是恶意样本分析最大的单点阻碍。
- **不能重组流**：只能取"第 N 帧的某字段"，没有"这条 TCP 流的应用层消息序列"，也没有 HTTP/2、WebSocket 边界。
- **不能定义协议**：无自定义 dissector，无从样本反推字段边界的工具。
- **序列化缺一整块**：protobuf（无描述符提取、无 `--decode_raw` 封装）、gRPC、ASN.1、CBOR、MessagePack、Java 序列化都没有。
- **固件只到"切出来"**：Unblob 能解包，但无文件系统挂载/遍历、无基址恢复、无 RTOS 识别。

### 4.4 自动化与脚本

**现状**：`batch_decompile` 是唯一的"批量"原语；`execute_rizin_command` / `cutter_command` / `gdb_console` 是三个命令逃生口；`load_frida_script` 是唯一用户代码入口。Ghidra 无脚本注入，IDA 未接入（见上文修正）。

**这意味着**：一个"反编译 300 个函数 → 按调用特征筛出解密例程 → 批量改名"的任务，只能由模型发起约 300 次调用，每轮带上下文成本，且不可复现、不可回归。**这是当前工作流最大的效率瓶颈**，1.2.0 的结果落盘只缓解了单条结果的体积，没有减少调用次数。

**另外缺**：无语料模式（一次处理一个目录/一批样本）、无结果持久化（证据只活在会话里）、无 CI 入口。

### 4.5 对抗与反检测

**结论：仍为零。** 1.2.0 未触及此维度。关键词穷举确认：`entropy`、`packer`、`obfuscat`、`yara`、`unpack`、`anti-debug` 在 207 条描述里均无命中（`packed` 仅出现在 `search_strings` 的"Ghidra 可能漏掉 packed 字面量"里）。

缺的是逆向工程最前面的十分钟：加壳了吗（熵、节区名、导入表规模、入口点异常）？什么壳（VMProtect/Themida/.NET Reactor/ConfuserEx 指纹）？有无反调试/反虚拟机（PEB、时序、CPUID、进程名）？字符串是否加密（编码识别、XOR 爆破）？

没有这些，后面的 Ghidra 分析会在"一堆无法解释的跳转"里空转。**这仍是投入产出比最高的一块空白**，因为它不依赖任何重型引擎。

---

## 五、短板归因：哪些是 REA 的，哪些是本插件的

| 短板 | 归属 | 插件能否补 |
| --- | --- | --- |
| 无 Windows 调试器 | REA 工具面 | 能（插件自带 cdb/TTD 桥，作为独立工具注册） |
| 无脚本编排 | REA | 能（playbook 子进程沙箱，把多次 MCP 调用压成一次） |
| 无加壳/混淆/YARA | REA | 能（纯本地静态检查，不需要引擎） |
| 无 TLS 解密/流重组 | REA | 能（自带 tshark 封装：`-o tls.keylog_file` / `-z follow`） |
| 无 protobuf/ASN.1 | REA | 能（`protoc --decode_raw` / `asn1tools` 包装） |
| 无语料/跨会话结果 | REA | 能（SQLite 索引 + 批量编排） |
| 未接 IDA | REA | 能但成本高（需新增 idalib/python 桥，属"新引擎"） |
| 单函数粒度、无全程序图 | REA 引擎 | **不能**（要改 Ghidra 侧插件） |
| 无符号执行/仿真脱壳 | REA 引擎 | 部分（外接 angr/Qiling，是新增引擎而非补能力） |
| 无二进制相似度 | REA 引擎 | 部分（BSim/Diaphora 需另装） |

**结论**：插件层能补的是"**编排、预处理、交付、安全**"四类，覆盖 10 条短板中的 7 条，且都不需要动 REA。1.2.0 已经证明了这条路走得通（四类里的"安全"已完成一半）。

---

## 六、前沿思路与潜在改进点

1. **Decompiler-in-the-loop 的语义标注**。已有"命名 + 读回"，缺"命名提案—证据—批量应用—回归"闭环。让模型基于 `analyze_function` 的结构特征产出**带置信度的命名提案**，由 playbook 批量写回并记录 diff。
2. **假设驱动的分析**。`record_unknown` 提供了骨架，但"谁来产生假设"仍靠人。可从证据缺口自动生成候选假设（例如"存在未被引用的高熵数据段 → 疑似加密配置"），把未知列表变成待办队列。
3. **差分优先**。与其从零读一个样本，不如"同族两版本做函数级差分 → 只看变化点"。JS 侧有 `compare_application_versions`，native 侧缺结构相似度；可先用"函数规模/调用签名/字符串集"粗配再交人确认。
4. **协议状态机学习**。当前只能取字段；前沿是从多条流反推消息边界与状态迁移。对 IoT 与 C2 分析价值很高。
5. **抗对抗前置**。把"是否加壳/是否反调试"作为第一等公民，决定后续走静态还是动态、走 Ghidra 还是先脱壳。
6. **证据的机器可读交付**。Evidence bundle 已是 JSON，缺 SARIF（给 CI）、STIX（给威胁情报）、Markdown（给人）三种出口。
7. **证据库而非证据会话**。把 Evidence/unknown 落 SQLite，使分析可跨会话复用、可做回归基线——这也是"模型辅助逆向"能否工程化的分水岭。

---

## 七、风险边界

**原来就有的五条**

1. **授权边界**。工具面含 Frida 注入、GDB 任意命令、ADB 装卸载、进程 PTY 执行——完整的代码执行面。应记录"授权目标范围"，并在越界路径/设备上拒绝。1.2.0 只对 4 个操作做了硬闸门，范围授权仍未实现。
2. **变更型操作**。30 个工具会写目标。**闸门目前是硬编码名单**，REA 升级新增的写操作不会自动纳入——这是"静默失效"型风险，与本次评审在 1.1.0 里抓到的那类问题同构。建议改为：未知写操作默认审计 + 按描述/`isReadOnly` 推断。
3. **供应链**。28 MB、136 个包的闭包没有 SBOM，也没有 npm provenance；Ghidra 从网络下载（虽校验 SHA-256）。上游被投毒则原样执行。
4. **数据外泄**。反编译结果、字符串、配置、密钥都进模型上下文。对企业样本等于把分析对象上传，需要"敏感产物不出本机"的策略（本地模型 / 脱敏 / 只回摘要）。**1.2.0 的产物落盘让这个问题从"传输中"延伸到"静态存储"**：`~/.dsh/rea-artifacts/` 会长期保留完整反编译结果，目前无保留期、无清理、无加密。
5. **目标可检测性**。Frida、GDB、Rizin 都会被反调试识别。**不要承诺隐蔽性**；应提供"当前是否会被检测"的提示与"改用快照/离线分析"的建议。
6. **模型幻觉**。反编译代码上的推断极易被写成事实。REA 的 Evidence 模型是对的解药，但插件侧仍是两句通用提示，未按工具类型分级。

**1.2.0 新增的两条**

7. **自更新的信任链**。下载走 5 个**第三方镜像**，完整性只由"Release 说明里公布的 SHA-256"保证——镜像只当传输通道，这点设计正确；但**摘要与归档同源**（都来自同一个 GitHub 仓库/账号），账号或 Release 被篡改时校验形同虚设。缓解：摘要应随发布清单签名（或至少在 `update.json` 之外提供独立通道），并允许运维在配置里**钉死**期望摘要；无公布摘要时当前实现直接拒绝，这条要保持。
8. **目录替换的破坏半径**。更新会把整个插件目录改名 `.bak-<时间戳>` 再换入新目录，失败自动回滚。风险点有两个：一是**备份目录会累积**（每次更新留一份 26 MB+ 的完整副本，含 28 MB 运行时归档），目前只保留最近一份但无大小上限；二是**替换发生在宿主加载期间**，已加载的模块不会重新读取，必须重启会话——UI 已提示，但没有强制，用户可能以为已生效。

---

## 八、可落地方案

排序原则：**先降成本与风险（P0）→ 再把人工流程自动化（P1）→ 最后引入新引擎（P2）**。P0 全部在插件层，不改 REA。

### P0 · 下一迭代（1–2 周）

| # | 改进 | 具体做法 | 预期效果 | 验收 |
| --- | --- | --- | --- | --- |
| 1 | **静态对抗初筛（插件自实现）** | 熵/节区异常/导入表规模/入口点异常 → 加壳初判；字符串 + 编码识别 + XOR 爆破；YARA 规则目录扫描。纯本地，零引擎依赖 | 补上 REA 完全缺失的"前十分钟"；triage 从分钟级到秒级 | 20 个已知壳样本识别率 ≥70%，误报 ≤10% |
| 2 | **证据出口** | Evidence bundle → Markdown 报告 / SARIF，附覆盖度与未解未知清单 | 交付物可读可审计，能接 CI | 一条命令产出可直接归档的报告 |
| 3 | **闸门去硬编码** | 改为按 schema/`isReadOnly`/前缀推断 + 未知写操作默认审计；配置里支持"会话级授权目标范围" | 消除"上游升级后闸门静默失效" | 注入一个伪造的新写操作工具，验证被审计且被拦 |
| 4 | **产物目录治理** | 保留期（默认 7 天）+ 容量上限 + `rea_purge_artifacts`；敏感标记样本可选只回摘要不落盘 | 解决"敏感反编译结果长期驻留磁盘" | 到期自动清理，越界读取仍被拒 |
| 5 | **自更新加固** | 配置支持 `pinnedSha256`；备份保留份数上限；镜像失败原因可观测（面板显示每个镜像的结果） | 更新链路可审计、可钉死、可诊断 | 钉死摘要后，摘要不符的发布被拒绝且给出明确提示 |
| 6 | **按工具类型分级提示** | `procedure_pseudo_code` 等推断类结果强制标注"反编译推断，非源码"；写操作结果标注"已审计" | 降低幻觉被当作事实的概率 | 抽样 10 个推断类工具，输出均带标注 |

### P1 · 3–6 周（结构性改进）

| # | 改进 | 具体做法 | 预期效果 |
| --- | --- | --- | --- |
| 7 | **Playbook 沙箱（最高价值）** | 子进程 + 权限最小化隔离；暴露 `rea.call(tool,args)` / `artifact` / `log`；`rea_run_playbook(name, input)` 一次执行整段脚本，产物写 artifact 目录 | 把"300 次模型往返"压成"1 次调用 + 1 段脚本"；批量反编译/改名/导出成为确定性、可回归的流水线 |
| 8 | **语料模式 + 结果库** | `rea_batch_triage(dir)`；样本/函数/证据/未知写入 `~/.dsh/rea-artifacts/rea.db`（SQLite），跨会话可查 | 500 样本可跑；分析结果可复用、可回归 |
| 9 | **原生版本差分编排** | 组合 `analyze_function` + `compare_functions`，按函数规模/调用签名/字符串集粗配，输出"疑似补丁点"候选 | 1-day 定位从数小时人工到候选列表 |
| 10 | **协议补强** | 自带 tshark 封装：`-o tls.keylog_file`、`-z follow,tcp/http2`、`http.file_data` 导出；`protoc --decode_raw` / `asn1tools` 包装 | 补上 TLS 解密与流重组，覆盖 HTTPS/gRPC 主流目标 |
| 11 | **Windows 动态补齐** | 接 `cdb -c` 脚本化断点与 `ttd` 录制回放，作为插件自有工具注册 | Windows 从"只能用 Frida"到"断点 + 回放" |

### P2 · 2–3 月（引入新引擎，能力跃迁）

| # | 改进 | 说明 | 预期 |
| --- | --- | --- | --- |
| 12 | 符号执行 / 仿真脱壳 | 外接 angr（路径约束）与 Qiling/Speakeasy（OEP 定位、API 追踪） | 能处理 VM 保护与自解压样本 |
| 13 | 二进制相似度 | Ghidra BSim / Diaphora 导出函数指纹，跨样本聚类 | 家族归类、1-day 批量匹配 |
| 14 | 反对抗 | 反调试/反虚拟机检测（PEB、时序、CPUID）+ ScyllaHide 类隐藏配置生成 | 受保护样本可调试 |
| 15 | IDA 接入 | idalib / IDAPython 桥（当前工具面 0 覆盖，属从零新增） | 补齐商业反编译器生态与脚本能力 |
| 16 | Fuzz harness 生成 | 从 `inspect_recorded_crash` 反向生成 AFL++/libFuzzer 模板，崩溃去重 | 从"读懂"走到"打穿" |

### 不建议做（明确排除）

- **不要把 207 个工具合并成 `rea_run(tool, input)`**：会摧毁 schema 可见性，模型必须猜参数。当前 `deferLoading` + `rea_catalog` 是更好的解。
- **不要在插件里内置"隐蔽注入"能力**：既是法律风险，也会让工具被 AV/EDR 标记，反而降低可用性。
- **不要用 `node:vm` 当安全边界**：它不是沙箱。playbook 必须被声明为"可信代码"，用子进程 + 权限最小化隔离。
- **不要让镜像承担完整性**：镜像只做传输，摘要必须来自独立可验证的来源，且允许运维钉死。

---

## 九、一句话总结

**它是一个"把证据管好"的静态分析工作台；制品解析接近商业水准，动态偏 Linux/macOS 且 Windows 为空白，自动化与对抗是明显洼地。** 1.2.0 把插件从"桥接"提升为"治理层"，修掉了上下文、空转、误操作这三类可量化的失败，但没有增加一个分析能力。

下一步最划算的投入仍然是三件事：**加壳与协议的前置处理（P0-1/2，零引擎依赖）、脚本化编排（P1-7，把 300 次往返压成 1 次）、证据库与出口（P1-8 / P0-2，让分析可复用、可交付）**——三件都在插件层，不动 REA 就能拿到大部分收益；同时必须补上 1.2.0 自更新带来的供应链与产物驻留风险。

---

## 附录 · 1.3.0 落地状态（2026-11-03）

本节记录第八节 P0 六项的实际落地情况，避免文档与代码脱节。全部改动都在插件层，未改 REA。

| P0 项 | 状态 | 实现 |
| --- | --- | --- |
| 1 静态对抗初筛 | ✅ | `lib/triage.js` + `rea_triage`：纯本地、不执行样本。整体/分块熵、PE/ELF/Mach-O 节区与入口/导入异常、13 类壳与混淆器签名、字符串（ASCII/UTF-16LE）、单字节 XOR 探测、可选 YARA（未安装则跳过）。输出带证据的 verdict / confidence / reasons / nextSteps / limitations。 |
| 2 证据出口 | ✅ | `lib/export.js` + `rea_export_report`：Evidence bundle → Markdown + SARIF 2.1.0，含覆盖度、未解未知、推断边界；可从内联对象、本地 JSON 或直接调 `export_evidence_bundle` 获取。 |
| 3 闸门去硬编码 | ✅ | `classifyTool` 改为「已知只读首词 + 明确写动词 + 全新首词 fail-closed + 描述声明」四路判定；`allowedTargets` 提供会话级路径白名单。真实工具面校验：207 个中 4 个破坏性、41 个审计（补上了原先漏掉的 `instrument_with_frida`、`execute_rizin_command`）、162 个只读，无误拦。 |
| 4 产物治理 | ✅ | 默认 7 天保留期 + 256 MB 容量上限，激活时自动清理；`rea_purge_artifacts` 手动清理且只删本插件的会话目录；`sensitiveArtifacts` 让完整结果只回摘要、不落盘。 |
| 5 自更新加固 | ✅ | `pinnedSha256`（与 Release 摘要不符在下载前拒绝，字节也按它校验）、`maxBackups` 默认 2、`mirrorAttempts` 逐镜像结果在侧栏可见、「安全策略」板块展示当前策略。 |
| 6 分级提示 | ✅ | `guidanceFor`：反编译/重建类强制标注「推断，非源码」，写操作标注「已审计」，其余保持两句通用提示。 |

**顺带修掉的一个真实缺陷**：`installUpdate` / `checkForUpdate` 的共享 promise 在「首个 await 之前就失败」的路径上永远不清空（内层 `finally` 先于外层赋值执行），导致后续所有安装直接返回第一次失败的结果。已改为在返回的 promise 链上清空，并补了端到端用例覆盖。

**未做（P1/P2）**：playbook 沙箱、语料模式与 SQLite 结果库、原生版本差分、tshark TLS 解密与流重组、cdb/TTD Windows 调试桥、angr/Qiling 仿真脱壳、BSim 相似度、反调试对抗、fuzz harness、IDA 接入。这些要么需要新增引擎，要么需要新的子进程隔离边界，不属于本轮「降成本与风险」的范围。

**仍未消除的风险**：单函数粒度与全程序图属 REA 引擎层，插件改不动；自更新的摘要与归档仍同源（`pinnedSha256` 只是把信任锚移到本地配置，不是签名）；反编译产物进入模型上下文的数据外泄问题，只能靠 `sensitiveArtifacts` + 本地模型策略缓解。
