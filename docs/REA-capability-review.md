# REA / dsh-rea 逆向能力评审（1.3.1 版）

> 评审对象：`dsh-rea` **1.3.1** 所桥接的 REA 6.7.0 工具面（207 个 MCP 工具）+ 插件自有 7 个工具
> 评审日期：2026-11-04
> 证据基础：本次重新连接真实 MCP 子进程，导出两份完整 `tools/list` 快照——① `schemaProfile=full` 输入（207 条，801 KB）；② `schemaProfile=compact` + `outputSchemaProfile=full`（207 条，2.58 MB）。逐条核对描述上下文排除误命中；并通读 1.3.1 的 `index.js`、`lib/`（triage / export / artifacts / tools / config / update / mcp-client）、119 个测试与两份已发布 Release。
> 与 1.2.0 修订版的差别：本版不再重复"缺什么引擎"的清单，而是把**实测发现的元数据断层、闸门绕过、结果扁平化**放在首位——它们不是"没有能力"，而是"能力已经在上游存在、却被插件丢掉了"，修复成本远低于新增引擎。
> 局限：未用真实样本做全量工具回归；"缺失"结论来自 schema 语义 + 关键词穷举（已逐条核对上下文），不代表引擎内部绝无该能力。

---

## 一、结论

它仍然不是"207 个工具的拼盘"，而是**以证据为核心的分析工作台**：每个结论要求 observation、limitation 与 Evidence ID，未解问题必须落成带严重度与所需权威等级的 residual unknown，交付物可校验、可导入导出。1.3.0 补上了"分析质量与风险边界"这层（本地初筛、Markdown/SARIF 出口、fail-closed 闸门、产物治理、自更新加固、分级提示），1.3.1 修掉了 Electron 宿主下整个插件静默不激活的致命缺陷。

**但本次重采数据推翻了 1.2.0 评审里一个乐观判断**："schema 按需可见"并没有真正解决。上游每个工具都提供完整输入 schema、完整输出 schema 与四类安全注解，插件默认把输出 schema 关闭、把输入 schema 设为 compact，并在同步时只保留 `name/description/inputSchema`。结果是：

- **复杂工具的参数实际上不可见**：207/207 个工具的 full 与 compact 输入 schema 都不同，147 个工具的完整定义超过 compact 的 1.5 倍，最大的 `compare_web_captures` 达 165 KB；而 `rea_catalog({tool})` 在 8 000 字符处截断——等于把 95% 的嵌套结构扔掉。
- **结果被拍平成字符串**：REA 的 `structuredContent` 带 `evidence_id`、`confidence`、`coverage`、`provider` 等字段，插件统一 `JSON.stringify` 成文本、再统一包装成 `{text:string}` 输出。上游 2.35 MB 输出 schema 全被丢弃。
- **图像结果被丢弃**：`textOf()` 把 `image` 与无文本的 `resource` 块换成一行占位提示，18 个涉及截图/UI/视觉的工具因此只能拿文字替身。

**一句话**：1.3.1 的短板已从"REA 没做"转为"**上游给了、桥接层没接住，以及几处治理边界不一致**"。这是好消息——补这些不需要新引擎，也不需要动 REA。

---

## 二、版本沿革与 1.3.1 现状

| 版本 | 定位 | 关键变化 |
| --- | --- | --- |
| 1.1.0 | 重构与稳健性 | 单文件 1166 行拆成 `lib/`；增量工具同步、取消传播、原子解包、环境白名单、路由校验、49 测试 |
| 1.2.0 | 治理层 | 结果落盘、`rea_catalog({tool})` 按需输入 schema、`rea_status`、变更闸门、六镜像自更新 |
| 1.3.0 | 分析质量与风险边界 | `rea_triage` / `rea_export_report` / `rea_purge_artifacts`；`allowedTargets`、`sensitiveArtifacts`、保留期、`pinnedSha256`、`maxBackups`；fail-closed 分类；分级提示 |
| 1.3.1 | 桌面端激活修复 | `childEnvironment()` 显式设置 `ELECTRON_RUN_AS_NODE=1`；补回归测试；119/119 通过 |

**1.3.0 的 P0 六项确实全部落地**（详见旧版附录，本文不重复），但落地质量有三处需要注意：

1. `rea_triage` 的 `nextSteps` 建议"用动态快照 / 离线 dump 的解压后镜像再跑一次初筛"，**而工具面里没有任何进程 dump / 内存 dump 工具**（本次穷举 0 命中）。建议链是断的。
2. `rea_export_report` 的 SARIF 把 `invocations[0].executionSuccessful` 硬编码为 `true`，`artifactLocation.uri` 直接写本机绝对路径（SARIF 要求 URI 形式，且会泄漏本机目录结构）；不校验 bundle 的哈希/签名。
3. v1.3.1 Release 说明写"设置 `ELECTRON_RUN_AS_NODE` 与 `ELECTRON_NO_ATTACH_CONSOLE`"，**代码里只有前者**（全仓库检索无后者）。发布说明与实现存在漂移，属于信任链上的小裂缝。

---

## 三、能力矩阵（1.3.1）

成熟度：**A** 可直接投产 ｜ **B** 可用但有明确边界 ｜ **C** 仅占位或需外部补齐 ｜ **D** 缺失

| 维度 | 覆盖 | 成熟度 | 关键抓手 | 主要缺口 |
| --- | --- | --- | --- | --- |
| 二进制格式解析 | ~30 | **A-** | `inspect_macho`、`inspect_binary_layout`（ELF 全量 RELR/符号表）、`inspect_pe_resources`、`inspect_go_binary` / `inspect_rust_binary`、`inspect_wasm_artifact` / `inspect_evm_interface`、`extract_firmware` | 无 dyld_shared_cache、无文件系统镜像挂载/遍历、无基址恢复 |
| 证据治理 | ~20 | **A** | `export_evidence_bundle`、`verify_reconstruction`、`record_unknown`、`evaluate_reconstruction_coverage`；插件新增 Markdown + SARIF | 仅会话内；无跨会话结果库；SARIF 元数据失真（见上） |
| 静态分析（native） | ~60 | **B+** | `analyze_function`、`procedure_pseudo_code`、`batch_decompile`（可一次传地址数组并发反编译）、`trace_native_values`、可写回且读回校验的注释/命名 | 单函数粒度；无全程序图、无 PDB/DWARF/FLIRT 导入、无结构相似度 diff |
| 静态分析（managed / JS / Android） | ~45 | **B** | `inspect_managed_members`、`analyze_javascript_application`、`inspect_android_method`、Flutter/Dart AOT 快照 | .NET 只到成员哈希与 IL 元组；Android 类级仅到 smali |
| 动态调试 | ~25 | **B-** | GDB MI3、LLDB 调用录制、Frida 会话生命周期、Rizin/Cutter、`inspect_recorded_crash`（Linux ELF64 core） | **Windows 全空白**（WinDbg/cdb/TTD/ETW 描述命中 0）；无内核/系统视角（eBPF/ftrace 0）；无快照回放；无进程 dump（0） |
| 协议解析 | 7 | **C+** | `inspect_packet_fields` → `inspect_packet_capture` 的"先探再取"字段级抓包、sigrok 信号解码 | TLS keylog/解密 0；流重组仅 1 处提及；自定义 dissector 0；protobuf/gRPC/ASN.1/CBOR/MessagePack 全 0 |
| 自动化 / 编排 | 3 | **C** | `batch_decompile`（真实并发批量）、`load_frida_script`、三个命令逃生口 | Ghidra 无脚本注入、IDA 0；插件无 playbook、无语料模式、无 CI 入口；**207 个桥接工具全部 `isConcurrencySafe:false`** |
| 对抗 / 反检测 | 插件 1 + REA 0 | **C**（1.2.0 为 D） | `rea_triage`：熵、PE/ELF/Mach-O 节区、13 类壳签名、单字节 XOR、可选 YARA | YARA 默认未配置；无反调试/反 VM 静态特征、无多字节加密配置识别、无脱壳/内存 dump；**反检测隐蔽性不应承诺** |
| 插件层治理 | 7 | **B** | 结果落盘 + 保留期、闸门、状态、目录清理、分级提示、多镜像自更新 | 见第五节：guard 只覆盖桥接工具；上游注解/输出 schema 未利用 |

**规模事实（本次重采）**：207 个工具、61 个前缀组；描述合计 92 KB；输入 schema compact 84 KB / full **652 KB**；输出 schema full **2.25 MB**（均值 11 KB，最大 138 KB）；注解合计 18 KB。**55 个（27%）无必填参数**，13 个连属性都没有，其中 10 个绑定"当前光标/当前文档"——headless 下不先 `open_binary` 就会空转；单工具最多 13 参数；属性合计 570 个。

**引擎耦合（仅描述层命中，已排除子串误命中）**：Ghidra 24、Hopper 22、Frida 9、Rizin 6、GDB 5、TShark 5、ADB 6（按名称前缀的 ADB 类工具实际 29 个）、JEB 2、LLDB 1、Cutter 2、sigrok 2、**IDA Pro 0**。旧版"IDA 9"是 `candidate` 之类子串误命中，本版再次确认工具面无任何 IDA 支撑。

---

## 四、本次重采的新发现（按严重度排序）

### 4.1 元数据断层：上游给了，桥接层丢了

`tools/list` 在 `outputSchemaProfile=full` 下，207/207 个工具都带完整 `outputSchema` 与四类 `annotations`：

| 注解 | 分布 | 插件当前用法 |
| --- | --- | --- |
| `readOnlyHint` | true **5** / false **202** | 未使用 |
| `destructiveHint` | true **31** | 未使用 |
| `idempotentHint` | false **40** | 未使用 |
| `openWorldHint` | true **100** | 未使用 |

**注意不要把 `readOnlyHint` 当权威分类器**：REA 对 202/207 保守地给了 `false`（连 `list_names`、`read_bytes` 都是 false），直接采用会把只读工具全判成写操作。插件自研的四路 fail-closed 分类器（实测 45 个变更类 = 4 破坏性 + 41 审计，162 个只读）精度明显更高。正确用法是**把注解当保守下限信号**：`destructiveHint=true` 与 `openWorldHint=true` 用来触发"额外审计/外部副作用提示"，而最终分类仍以插件规则为准。

### 4.2 闸门的实际漏洞：5 个命令逃生口被判为只读

交叉比对发现，上游标 `destructiveHint=true` 但插件判为**只读**的恰好 5 个，且都是任意命令/实时执行面：

`gdb_console`、`rizin_debug_command`、`cutter_command`、`observe_native_calls`、`observe_web_execution`

它们不进 `audit.jsonl`、不受 `destructive` 闸门约束。`execute_rizin_command` 与 `instrument_with_frida` 已被 1.3.0 补抓，这 5 个是同类漏网。

### 4.3 授权范围可绕过：guard 只挂在桥接工具上

`index.js` 的 `guardTool()` 只作为 `buildTool()` 的参数传给 207 个 REA 工具；7 个插件自有工具直接 `ctx.tools.register(...)`，**完全不走 guard**。后果：

- 配置了 `allowedTargets` 的会话，仍可用 `rea_triage({path:'C:/任意/文件'})` 或 `rea_export_report({path:...})` 读取授权根之外的任意绝对路径文件；
- `rea_purge_artifacts` 删除文件不写审计；
- `rea_read_artifact` 的路径限制只靠自身实现，与会话策略不统一。

这是 1.3.0 新增边界时产生的不一致，属于"策略看似生效、实际有旁路"。

### 4.4 结果扁平化 + 视觉能力丢失

`buildTool()` 把所有结果归一成 `{text:string}`，`textOf()` 对 `image` 块写入 `[image result not forwarded]`、对二进制 `resource` 写入占位串。18 个涉及截图/UI/视觉的工具（`capture_adb_screen`、`capture_web_screenshot`、`compare_web_screenshots`、`observe_native_ui`、`capture_electron_scenario`、`inspect_electron_page` 等）因此无法把画面交给多模态模型，也不能保存原始图供复核。同时 `structuredContent` 的置信度、覆盖度、Evidence ID 被当作普通文本，无法做置信度分级或结构化检索。

### 4.5 参数可见性没有真正解决

- `schemaProfile=compact`（默认）会把嵌套对象压成不透明的 `object`：例如 `compare_functions` 的 `left/right`、`inspect_analysis_view` 的 `source/view` 只剩一个 `type: object`，而 full 版本里含 `evidence_id` 正则、枚举、必填嵌套字段。
- 207/207 个工具的两种 schema 都不同，147 个工具完整定义超过 compact 的 1.5 倍。
- `rea_catalog({tool})` 在 8 000 字符截断：最大的 `compare_web_captures` 完整输入 schema 165 KB，等于只给到 5%。

**成本对照**：完整输入 schema 652 KB + 输出 schema 2.25 MB + 注解 18 KB ≈ 2.9 MB，全部可以只驻留宿主内存（不进模型上下文）；按需返回单个工具平均 11 KB。这是一个"零上下文成本、纯内存"的改进。

### 4.6 并发被无条件串行化

207 个桥接工具一律 `isConcurrencySafe: () => false`。REA 自己的 `batch_decompile` 是并发的，但插件层的批量编排/语料模式一旦实现，仍会被宿主排队。162 个只读工具完全可以放开。

### 4.7 1.3.1 暴露的新风险类别：宿主环境耦合的静默失效

1.1.0 引入环境白名单 → 桌面端子进程以 GUI 模式启动并立即退出 → `apply()` 提前返回 → 路由与 207 工具全部缺席。这个缺陷**从 1.1.0 一直潜伏到 1.3.0 发布后用户重启桌面端才暴露**，因为期间所有验证都在纯 Node 假宿主上做。它说明：插件层的任何环境/路径假设都可能在特定宿主下静默失效，而当前发布门禁里没有宿主矩阵。

---

## 五、分维度评审

### 5.1 静态分析

**优势**：`analyze_function` 以函数为分析单位一次给出身份、签名、调用关系、字符串引用、伪代码与局限；命名/注释可写回且读回校验，是 LLM 辅助逆向里最实用的一环；`batch_decompile` 支持一次传入地址数组并发反编译（旧评审低估了它）；`inspect_binary_layout` 对 ELF 的符号/RELR/原始名字节覆盖很深；制品解析（Mach-O 权限与 entitlements、PE 资源与 .NET 混合体、Go/Rust 构建元数据、WASM 接口比较、EVM selector）接近商业水准。

**欠缺**：无全程序视角（无整体调用图导出、无类型系统导出、无跨函数类型传播）；无 PDB/DWARF/FLIRT/Lumina；`compare_functions` 比的是两批 Evidence 记录，不是两个二进制的结构相似度，1-day 定位仍缺图同构/模糊哈希；`trace_native_values` 只到有界静态依赖图，无跨过程指针/污点分析。

**1.3.0 新增的 triage 边界（读源码确认）**：只解析 PE/ELF/Mach-O 三种容器的极少数字段，DEX/APK、WASM、.NET 单文件、固件一律 `format:'unknown'`，此时只剩熵/壳签名/XOR 三个信号，安装程序与压缩资源容易误报；13 类壳签名找明文字符串，新版 VMProtect/Themida 常无明文；XOR 只探测前 64 KB 的单字节英文 marker，多字节/RC4/AES 配置、栈字符串、控制流平坦化、不透明谓词均未覆盖；无反调试/反 VM 静态特征（PEB、CPUID、时序、进程名）、无签名/证书与编译时间戳异常、无 overlay 检查；只读 64 MB 且截断不重新采样；加权启发式没有校准数据集。**它是合格的前十分钟分流器，不是检测器，不能当免检结论。**

**边界**：反编译结果本身不可信，插件已按工具类型强制标注"推断，非源码"——这条做对了；但样本字符串进上下文带来的间接提示注入风险（见第七节）尚未处理。

### 5.2 动态调试

**优势**：多调试器并存且有生命周期管理（GDB 走 MI3 解析、Rizin `-N` 抑制用户配置、Cutter 带 `expected_generation` 并发保护）；LLDB 用法克制；破坏性设备操作有闸门；`inspect_recorded_crash` 能离线读 Linux core 的全部 PRSTATUS/SIGINFO 字段。

**欠缺**：Windows 完全空白（本机就是 Windows，对 Windows 样本只剩 Frida 一条命，且受保护进程里容易被摘）；无内核/系统视角（ETW、eBPF/ftrace）；无快照回放（`time-travel/replay` 描述命中 1 处且是 Web 抓包快照，不是指令级回放）；**无进程/内存 dump**（0 命中）——这既让 triage 的建议链断掉，也让"脱壳后重跑初筛"无法执行；移动端需设备已连、Frida server 已起，无 AVD 编排。

### 5.3 协议与二进制解析

**优势**：二进制格式深度是全套工具最扎实的部分；字段级抓包"先探再取"避免整包入上下文；sigrok 信号解码是少见的硬件侧补充。

**欠缺**：不能解密（TLS keylog 0）、不能重组流（仅 `inspect_packet_capture` 一处提及 follow）、不能定义协议（dissector 0）；protobuf/gRPC/ASN.1/CBOR/MessagePack/Java 序列化整块缺失；固件只到"切出来"，无文件系统挂载/遍历、无基址恢复、无 RTOS 识别。**这是二进制解析 A- 与协议解析 C+ 的巨大落差**，也是 C2/IoT 分析里最常卡住的地方。

### 5.4 自动化与脚本

**现状**：`batch_decompile` 是唯一的批量原语；`execute_rizin_command` / `cutter_command` / `gdb_console` 是三个命令逃生口；`load_frida_script` 是唯一用户代码入口；Ghidra 无脚本注入、IDA 未接。插件侧无 playbook、无语料模式、无结果库、无 CI 入口，且 207 个工具全被串行化。

**影响**：一个"反编译 300 个函数 → 按调用特征筛出解密例程 → 批量改名 → 导出证据"的任务，仍需要模型发起大量往返、不可复现、不可回归；1.2.0 的结果落盘只缓解单条体积，1.3.0 的 SARIF 出口只解决交付，都没减少编排成本。**这仍是工作流最大的效率瓶颈。**

### 5.5 对抗与反检测

从 1.2.0 的 **D** 升到 **C**：`rea_triage` 是纯本地、不执行样本的初筛，输出带证据的判定与置信度，方向正确且零引擎依赖。

**仍然缺**：YARA 需外部二进制 + 用户自备规则目录（默认 `not-configured`）；无反调试/反 VM 静态特征；无多字节加密配置提取；无脱壳与内存 dump；无控制流混淆识别；无"当前调试手段是否会被检测"的提示。**明确边界**：本插件不提供、也不应承诺隐蔽注入能力；"反检测"维度应理解为"识别样本的保护手段并选择合适路径"，不是"让调试器不被发现"。

---

## 六、短板归因

| 短板 | 归属 | 插件能否补 | 本轮建议 |
| --- | --- | --- | --- |
| 元数据断层（schema/注解/结构化结果） | **插件桥接层** | 能，纯内存 | **P0-1** |
| 闸门漏 5 个命令口 / guard 只覆盖桥接工具 | **插件桥接层** | 能 | **P0-2** |
| 图像与二进制资源被丢弃 | **插件桥接层** | 能（落盘 + 条件转发） | **P0-3** |
| 间接提示注入面 | **插件桥接层** | 能 | **P0-4** |
| 宿主兼容性门禁 | **插件发布流程** | 能 | **P0-5** |
| triage 校准与建议链 | **插件自有能力** | 能 | **P0-6** |
| 无脚本编排 / 语料 / 结果库 | REA + 插件 | 能（playbook + SQLite） | P1 |
| 无 TLS 解密 / 流重组 / 序列化解析 | REA | 能（自带 tshark/protoc 封装） | P1 |
| Windows 调试 / 系统级观测 | REA | 能但需新增引擎桥 | P1/P2 |
| 单函数粒度、无全程序图 / 符号 | REA 引擎 | **不能**（要改 Ghidra 侧） | 排除 |
| 仿真脱壳 / 符号执行 / 二进制相似度 | REA 引擎 | 部分（新增引擎） | P2 |
| IDA 接入 | REA | 能但成本高 | P2 |

**结论**：最划算的六项全部在插件桥接层，不动 REA、不进模型上下文、不改协议，且每项都有可量化的验收。

---

## 七、前沿思路与风险边界

**前沿思路（与本项目相关的部分）**

1. **结构化证据图谱**：把 `structuredContent` 的 `evidence_id / confidence / coverage / provider` 与输出 schema 一起沉淀成可查询结果库，让"假设 → 取证 → 验证 → 回归"形成闭环，而不是每次会话从零开始。这是 agentic 逆向能否工程化的分水岭。
2. **渐进式 schema 披露（progressive disclosure）**：不在上下文里塞 2.9 MB schema，而是缓存完整定义、按 JSON Path 按需展开。对 165 KB 的复杂工具尤其关键。
3. **置信度校准的语义命名**：`analyze_function` + 批量命名 + 读回校验 + 置信度提案，把 LLM4Decompile 类能力落到可验证的写回闭环，而非让模型直接改结论。
4. **差分优先 / 1-day**：先用函数规模、调用签名、字符串集粗配，再交人确认；BSim/Diaphora 属后一步。
5. **协议状态机推断**：从多条流反推消息边界与状态迁移，比逐帧取字段高一个层次；对 C2/IoT 价值高。
6. **仿真与符号执行选路**：Qiling/Speakeasy 定位 OEP、angr 做路径约束，处理 VM 保护与自解压样本。
7. **多模态取证**：截图/UI 树进视觉模型，与 `observe_native_ui` 的文字事实交叉验证——前提是桥接层不再丢弃图像块。
8. **可信发布**：Sigstore/minisign 对 `update.json` 签名，把信任锚从"同一账号里的摘要"移到独立可验证的密钥。

**风险边界**

1. **授权与目标范围**：工具面含任意命令执行、Frida 注入、ADB 装卸载，`allowedTargets` 目前有旁路（4.3）。必须"所有工具、包括插件自有工具"统一走策略。
2. **代码执行面未完全审计**：5 个命令逃生口在闸门之外（4.2）；`destructiveHint=true` 的 31 个里还有 `export_evidence_bundle`、`close_binary` 等被上游保守标记，不能简单照抄，但可作为"需额外审计"的信号集合。
3. **间接提示注入（新增，此前两版未提）**：二进制里的字符串、反编译文本、网页 DOM 都是攻击者可控内容，会直接进入模型上下文；`rea_triage` 默认输出 20 条字符串样本、`rea_export_report` 把 observation 原文写进报告。`"ignore previous instructions"` 这类载荷可劫持分析流程。缓解：把样本内容当不可信数据，默认只回计数/长度/哈希，完整内容放 artifact 并加隔离标记；报告渲染时转义而非原样拼接。
4. **推断可信度**：反编译与重建是推断。分级提示已落地，但 `invocations.executionSuccessful: true` 硬编码与绝对路径 URI 会让机器可读交付物失真，等于把不确定性洗掉。
5. **数据外泄与静态驻留**：反编译结果、字符串、密钥进模型上下文；产物落盘有 7 天保留期与 256 MB 上限、`sensitiveArtifacts` 可只回摘要，但**进入模型上下文的那部分仍未脱敏**（企业样本等于上传分析对象）。
6. **供应链**：六镜像只当传输通道（设计正确），SHA-256 来自 Release 说明或 `update.json`，`pinnedSha256` 把信任锚移到本地配置；但**摘要与归档仍同源**（同一账号/仓库），账号被篡改时校验形同虚设。28 MB 运行时闭包仍无 SBOM/provenance。发布说明与实现漂移（2.3）也是同一类问题。
7. **目标可检测性**：Frida/GDB/Rizin 都会被反调试识别，**不要承诺隐蔽性**；应提供"是否易被检测"提示与"改用离线/快照路径"建议。
8. **宿主环境耦合（新增）**：1.3.1 的教训——环境白名单、路径假设、平台相关解包都可能在特定宿主下静默失效，且假宿主测试发现不了。发布门禁需要宿主矩阵。
9. **模型幻觉**：Evidence 模型是对的解药，但结构化元数据被拍平后，模型无法自动区分"置信度 0.4 的推断"与"已验证事实"，只能靠提示词。

---

## 八、可落地方案

排序原则：**先把上游已有的东西接住、把边界补齐（P0）→ 再自动化工作流（P1）→ 最后引入新引擎（P2）**。P0 全部在插件桥接层，不改 REA、不增加上下文预算。

### P0 · 下一迭代（1–2 周）

| # | 改进 | 具体做法 | 预期效果 | 验收 |
| --- | --- | --- | --- | --- |
| 1 | **元数据与结构化结果管线** | 激活时以 `schemaProfile=full` + `outputSchemaProfile=full` 拉一次 `tools/list`，缓存完整输入/输出 schema 与 `annotations`（约 2.9 MB，仅内存）；对外仍注册 compact 轮廓。`rea_catalog` 增加 `path` 参数按 JSON Path 渐进展开、`includeOutput` 返回输出 schema 与安全注解；`buildTool` 从 `structuredContent` 抽出 `evidence_id/confidence/coverage/provider` 写 sidecar JSON | 复杂工具参数从"猜"变"可查"；结果可验证、可检索、可按置信度分级；单次按需约 11 KB，**上下文零增长** | 对 `compare_functions`、`compare_web_captures` 能查到嵌套必填字段与 evidence_id 正则；抽查结果 sidecar 含置信度字段 |
| 2 | **闸门统一化** | 把 5 个命令逃生口加入审计/变更分类；`guardTool` 应用到全部 7 个插件自有工具（`rea_triage` / `rea_export_report` 的路径参数走 `allowedTargets`，`rea_purge_artifacts` 写审计）；用 `destructiveHint` / `openWorldHint` 作保守下限信号而非唯一依据 | 消除授权旁路；任意命令执行面可审计；上游新增工具的外部副作用有提示 | 注入 5 个工具名验证被审计；`allowedTargets` 下用 `rea_triage` 读越界路径被拒；162 个只读工具无误拦 |
| 3 | **图像/二进制结果落地** | `textOf()` 遇到 `image` / `resource.blob` 时写入 artifact 目录（`.png` / `.bin` + 哈希），返回路径、尺寸、mimeType 与摘要；宿主支持时额外转发 image block | 18 个视觉相关工具从"不可用"变"可用"，截图/UI 分析可参与且原始证据可复核 | 对 `capture_web_screenshot` 类调用产生落盘文件与可回访路径，不进上下文的图片不丢 |
| 4 | **不可信数据隔离** | 样本字符串/反编译文本标为 untrusted：`rea_triage` 默认只回字符串计数、编码分布与前 N 条长度，完整内容放 artifact；`rea_export_report` 渲染时转义控制序列与类指令文本，报告头部写明"以下为不可信样本内容" | 降低样本内嵌提示词劫持分析流程的风险 | 构造含 `"ignore previous instructions"` 的样本，验证不进入可直接执行的提示位置 |
| 5 | **宿主兼容性发布门禁** | 发布前跑矩阵：纯 Node / Electron `ELECTRON_RUN_AS_NODE` × Windows / Linux，各执行一次真实 `apply` + 握手 + `/rea/environment`；任一失败即阻断发布 | 杜绝 1.3.1 那类"代码没问题但宿主静默失效" | 门禁脚本纳入 `npm test` 或发布脚本，四种组合全绿 |
| 6 | **triage 校准与建议链闭合** | 建 20–50 个已知壳/未壳/安装程序样本的判定基线，输出可公布的识别率与误报率；补 DEX/APK/WASM 容器识别、overlay 与证书/时间戳异常；`nextSteps` 只推荐工具面里真实存在的动作，并把"dump 后重跑"换成可执行的 `open_binary` / `binary_session` / `inspect_analysis_view` 路径 | 初筛结论从"启发式声明"变"有校准指标"，建议可执行 | 基线报告落库；误报率可量化；`nextSteps` 里每个工具名都能在 207 清单里查到 |

### P1 · 3–6 周（结构性改进）

| # | 改进 | 具体做法 | 预期效果 |
| --- | --- | --- | --- |
| 7 | **只读工具并发 + Playbook 沙箱** | 先用 P0-2 的分类结果把 162 个只读工具设为 `isConcurrencySafe:true`；再用子进程（非 `node:vm`）跑可信脚本，暴露 `rea.call` / `artifact` / `log`，`rea_run_playbook` 一次执行整段 | 批量反编译/改名/导出从"几百次往返"压成"1 次调用 + 1 段脚本"，确定性、可回归；并发放开后吞吐显著提升 |
| 8 | **证据/结果库 + 语料模式** | 把 sidecar 元数据、Evidence、unknown、样本哈希写入 `~/.dsh/rea-artifacts/rea.db`（SQLite）；`rea_batch_triage(dir)` 一次处理目录；跨会话检索与回归基线 | 500 样本可跑；分析可复用、可比对、可审计 |
| 9 | **协议补强** | 自带 tshark 封装（`-o tls.keylog_file`、`-z follow,tcp/http2`、`http.file_data`）；`protoc --decode_raw` / `asn1tools` 包装；自定义 dissector 描述文件 | 补上 TLS 解密、流重组与主流序列化，覆盖 HTTPS/gRPC/IoT 目标 |
| 10 | **原生差分优先编排** | 组合 `batch_decompile` + `compare_functions`，按函数规模/调用签名/字符串集粗配，输出"疑似补丁点"候选 | 1-day 定位从数小时人工缩短到候选列表 |
| 11 | **Windows 动态与系统观测** | 接 `cdb -c` 脚本化断点、TTD 录制回放；ETW/eBPF 系统调用级观测，作为插件自有工具注册 | Windows 从"只能 Frida"到"断点 + 回放 + 系统视角"；注意只在授权目标上启用 |
| 12 | **SARIF 修正** | `executionSuccessful` 取真实状态；`artifactLocation.uri` 转 `file:///` 或相对 URI；target 附 SHA-256；导出清单签名 | 交付物不再失真，可安全接 CI |

### P2 · 2–3 月（能力跃迁）

| # | 改进 | 说明 | 预期 |
| --- | --- | --- | --- |
| 13 | 仿真脱壳 / 符号执行 | Qiling/Speakeasy 定位 OEP + API 追踪，angr 做路径约束选路 | 能处理 VM 保护与自解压样本，补上 triage 之后断掉的那一段 |
| 14 | 二进制相似度 | Ghidra BSim / Diaphora 导出函数指纹，跨样本聚类 | 家族归类、1-day 批量匹配 |
| 15 | 反调试/反 VM 静态特征 | PEB、CPUID、时序、进程名、虚拟机 artifact 指纹 → 生成"调试风险提示"与离线路径建议 | 受保护样本选择合适路径，不承诺隐蔽性 |
| 16 | IDA 接入 | idalib / IDAPython 桥（当前 0 覆盖，属从零新增） | 补齐商业反编译器生态与脚本能力 |
| 17 | 多模态取证 | 落盘的截图接视觉模型，与 UI 树文字事实交叉验证 | UI 混淆、图表型反混淆可参与分析 |
| 18 | Fuzz harness + 签名发布 | 从 `inspect_recorded_crash` 生成 AFL++/libFuzzer 模板；`update.json` 用 minisign/Sigstore 签名 | 从"读懂"走到"打穿"；信任锚独立于仓库账号 |

### 明确不做

- **不要把 207 个工具合并成 `rea_run(tool, input)`**：会摧毁 schema 可见性。`deferLoading` + 渐进式 `rea_catalog` 才是正解。
- **不要用 `readOnlyHint` 直接替换分类器**：202/207 都是 false，会造成 202 个误拦；只作保守下限信号。
- **不要内置"隐蔽注入"能力**：法律风险 + 被 AV/EDR 标记，反而降低可用性。
- **不要用 `node:vm` 当安全边界**：playbook 必须声明为可信代码并用子进程隔离。
- **不要让镜像承担完整性**：镜像只做传输；摘要需独立通道，且允许运维钉死。
- **不要在未校准前把 `rea_triage` 结论当免检依据**：它是分流器，不是检测器。

---

## 九、一句话总结

**1.3.1 是一个"证据治理扎实、制品解析接近商业水准、动态偏 Linux/macOS 且 Windows 空白、协议与自动化仍是洼地"的分析工作台；1.3.0 把对抗初筛从零补到可用，1.3.1 让桌面端真正能加载。**

本轮最重要的判断变化是：**最高优先级不再是"新增分析引擎"，而是"把上游已经提供的 2.9 MB 元数据与结构化结果接住，并补上三处治理旁路"**。这六件事全在插件桥接层，不动 REA、不增加上下文、每项都可量化验收；做完之后，P1 的 playbook 与证据库才有可靠的结构化基础，P2 的新引擎才有可复用的结果管线。

---

## 附录 · 与前两版评审的差异

| 项 | 1.2.0 修订版 | 1.3.1 版（本版） |
| --- | --- | --- |
| 对抗维度 | D（完全缺失） | C（triage 可用，但 YARA 默认未配置、无反调试/脱壳） |
| schema 可见性 | 判定为"已解决（`rea_catalog({tool})`）" | **修正**：compact 把嵌套压平、8 000 字符截断，复杂工具仍不可见；full 单工具最大 165 KB |
| 闸门 | 指出"硬编码名单会静默失效" | 1.3.0 已改 fail-closed；本版实测发现 5 个命令口漏判 + 7 个自有工具绕过 guard |
| 输出 schema | 指出"只给 input，不给 output" | 实测上游 207/207 都有（2.25 MB），插件默认关闭且同步时丢弃 |
| 注解 | 未评估 | 实测 readOnlyHint 5/202、destructiveHint 31、openWorldHint 100；给出正确用法与陷阱 |
| 结果形态 | 只讨论体积 | 指出结构化字段与图像块被拍平/丢弃，18 个视觉工具受影响 |
| 风险边界 | 6 + 2 条 | 新增：间接提示注入、宿主环境耦合静默失效、授权范围旁路、发布说明与实现漂移 |
| 方案重心 | P0 六项"降成本与风险" | 1.3.0 已全部落地；新 P0 六项聚焦"接住元数据 + 补边界 + 校准初筛" |

---

## 附录 · 1.4.0 落地状态（2026-11-04）

本次评审后按方案实施，版本 `1.4.0`（本地提交，**未发布**，`update.json` 仍指向 1.3.1）。完整测试 144/144；宿主矩阵三种模式（纯 Node / Electron / 授权范围）各装配出 221 工具 + 6 路由，全 PASS。

| 方案项 | 状态 | 实现与实测 |
| --- | --- | --- |
| P0-1 元数据与结构化结果管线 | ✅ | `lib/schema-cache.js` 后台探测子进程缓存 207 个完整定义（实测 3 084 KB 内存），`rea_catalog({tool,path,includeOutput})` 按 JSON Path 展开；`compare_web_captures` 完整输入 165 694 字节 → 轮廓 1 076 字符。`lib/result-index.js` 把 `structuredContent` 的 Evidence ID / 置信度 / 覆盖度 / provider 写入 `results.jsonl`，`rea_query_results` 跨会话查询 |
| P0-2 闸门统一化 | ✅ | 5 个命令逃生口显式归类为变更；`guardTool` 现在也覆盖 7 个插件自有工具（产物目录内路径豁免）；`destructiveHint` 触发轻量审计、`openWorldHint` 用于标注，不覆盖 fail-closed 分类；162 个只读工具 `isConcurrencySafe=true` |
| P0-3 图像/二进制落盘 | ✅ | `flattenContent()` 收集 image / resource.blob，`artifacts.writeBinary()` 存盘并返回路径、字节数、mimeType；宿主矩阵验证 scoped 模式下 `rea_triage` 越界路径被拒 |
| P0-4 不可信数据隔离 | ✅ | `markUntrusted()` 转义控制字符与 `<>`、截断、包裹标签；`rea_triage` 默认不回字符串原文；Markdown/SARIF 报告声明不可信内容 |
| P0-5 宿主兼容性门禁 | ✅ | `npm run host-matrix`：纯 Node / `ELECTRON_RUN_AS_NODE` / 授权范围三模式真实装配，断言子进程环境、工具数、路由数、catalog 可用性、路径授权；输出 Linux 未覆盖提示 |
| P0-6 triage 校准与建议链 | ✅ | 新增 DEX/WASM/APK(ZIP) 识别、PE overlay / 时间戳 / Authenticode 证书表、6 类反调试反 VM 标记；`nextSteps` 只引用真实广告的工具名，明确"工具面没有进程 dump"；`npm run triage-baseline` 输出合成矩阵并支持 `--corpus` 带标签语料（**合成集识别率 1.0 不代表真实壳样本**） |
| P1-7 playbook 沙箱 | ✅ | `lib/playbook.js` + worker：子进程 + IPC 代理 `rea.call`，工具白名单、`playbookMaxCalls`、`playbookTimeoutMs`、结果传输上限；只接受目录内 `.mjs` 文件名。明确声明"可信代码，不是防恶意脚本的沙箱" |
| P1-8 结果库 + 语料模式 | ✅（JSONL 而非 SQLite） | 为避开 Node 版本相关的 `node:sqlite` 实验 API 与原生依赖，改用 append-only JSONL + 尾部有界扫描；`rea_batch_triage` 非递归批量初筛并写索引 |
| P1-9 协议补强 | ⚠️ 适配层 | `rea_protocol_analyze` 封装 tshark（keylog / follow / 字段）与 `protoc --decode_raw`；缺二进制时精确报告缺失并指向 REA 自带字段级工具，不假装成功。完整 dissector / protobuf 描述符提取仍未做 |
| P1-10 差分优先 | ✅（粗配层） | `rea_diff_hint` 本地比较熵、节区、采样字符串，输出优先级列表并声明不是结构 diff；函数级匹配仍需 BSim/Diaphora |
| P1-11 Windows 动态 | ⚠️ 能力探测 | `rea_windows_tools` 用 `where` 只读探测 cdb/TTD/wpr/logman/pdbcopy，不启动调试器、不执行任意命令。完整 cdb 脚本化与 TTD 回放仍需新引擎桥 |
| P1-12 SARIF 修正 | ✅ | 移除硬编码 `executionSuccessful:true`（改为调用方显式传入），`artifactLocation.uri` 转 `file:///` URI 并百分号编码，附 target 哈希字段与不可信内容标记 |
| P2-15 反调试静态特征 | ✅ | 并入 triage 的 `antiAnalysis`（debugger-api / PEB / timing / CPUID-hypervisor / sandbox-tools / 反 VM 注册表） |
| P2-18 签名发布清单 + fuzz 模板 | ✅（部分） | `DSH_REA_MINISIGN_KEY` 生成 `update.json.minisig`，`trustedManifestKey` 让所有 manifest 来源必须验签；`rea_fuzz_harness` 生成 libFuzzer/AFL++ 模板（只生成文本，不编译不执行） |
| P2-13/14/16 仿真脱壳 / BSim / IDA | ❌ 不落地 | 需要新增 Python 引擎、Ghidra 插件或商业 IDA 授权与脚本桥，属"新引擎"而非插件层改动；本次不假装实现 |
| P2-17 多模态取证 | ⚠️ 基础已备 | 图像已落盘可带外复核；未把 image block 转发给宿主（宿主是否支持多模态块未做假设） |

**仍未消除的风险**：单函数粒度与全程序图属 REA 引擎层；`pinnedSha256` / minisign 都是可选信任锚，默认安装链路仍摘要与归档同源；反编译文本进入模型上下文的数据外泄问题只能靠 `sensitiveArtifacts` + 本地模型策略缓解；合成校准集不能当作真实检测率对外公布。
