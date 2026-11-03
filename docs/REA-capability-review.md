# REA / dsh-rea 逆向能力评审

> 评审对象：`dsh-rea` 1.1.0 所桥接的 REA 6.7.0 工具面（207 个工具）
> 评审日期：2026-11-03
> 证据基础：完整 `tools/list` 快照（207 条 schema，219 KB）、`reverse-engineer-anything` 技能及其 6 份 references、一次真实会话的握手与 `binary_session` 返回、以及本插件侧实现。
> 局限：未对真实样本执行全量工具回归；"缺失"结论来自 schema 语义与关键词穷举（已人工核对上下文，排除 `network`→`etw` 这类误命中），不代表引擎内部绝无该能力。

---

## 一、结论

这不是"207 个工具的拼盘"，而是一套**以证据为核心的分析工作台**：每个结论都要求 observation、limitation 和 Evidence ID，未解决的问题必须落成带严重度与"所需权威等级"的 residual unknown，交付物可校验、可导入导出。这一点在同类工具里很少见，也是它最被低估的价值。

但它的能力分布很不均匀：

**强在三处**

1. **制品解析的广度**。PE/.NET、Mach-O（含 code signature、dyld 解析链）、ELF、Go/Rust 元数据、WASM、EVM 字节码、Dart AOT、plist、Assets.car、SQLite、固件（binwalk/unblob）、APK/IPA/HAP——这一类"不执行就能说清结构"的能力，覆盖度超过多数商业套件。
2. **证据治理**。`record_unknown` / `update_unknown` / `verify_unknown_resolution` / `build_reconstruction_obligation_ledger` / `evaluate_reconstruction_coverage` 构成了一条"假设—证据—覆盖度—结论"的闭环，且带乐观并发（`expected_revision`）。
3. **静态与运行时的对照**。`correlate_static_and_runtime`、`reconcile_javascript_runtime`、`find_changed_behavior`、11 个 `compare_*`，把"我看到的"和"它跑的"显式分开再对齐，这是很多逆向报告出错的根源。

**弱在三处**

1. **Windows 动态分析是空的**。没有 WinDbg、没有 x64dbg、没有 TTD/ETW 回溯。GDB(MI3)/Rizin/LLDB/Frida 覆盖 Linux/macOS/移动端，Windows 只剩 Frida 一条命。对以 Windows 样本为主的工作流，这是硬缺口。
2. **没有脚本层**。除 `execute_rizin_command`、`cutter_command`、`gdb_console`、`load_frida_script` 外，Ghidra 和 IDA 都**不能注入脚本**。这意味着"批量反编译 200 个函数并按自定义规则筛选"只能由模型一轮一轮调用完成，成本高、不可复现。
3. **对抗面几乎为零**。没有加壳/混淆检测、没有熵与节区异常、没有 YARA、没有反调试处理、没有内存脱壳。遇到真实恶意样本，第一步就会卡住。

---

## 二、能力矩阵

成熟度：**A** 可直接投产 ｜ **B** 可用但有明确边界 ｜ **C** 仅占位或需外部补齐 ｜ **D** 缺失

| 维度 | 覆盖 | 成熟度 | 关键抓手 | 主要缺口 |
| --- | --- | --- | --- | --- |
| 静态分析（native） | ~60 个工具 | B+ | `analyze_function`、`procedure_pseudo_code`、`trace_native_values`、`inspect_native_instruction`、`set_comment` | 单函数级；无全程序反编译、无符号导入（PDB/DWARF）、无结构体恢复、无 FLIRT/Lumina 式库识别 |
| 静态分析（managed / JS / Android） | ~45 个工具 | B | `inspect_managed_members`、`analyze_javascript_application`、`inspect_android_method` | .NET 只到成员哈希与 IL 元组，无 C# 反编译；Android 方法级可用，类级仅到 smali |
| 动态调试 | ~25 个工具 | B- | `start_gdb_session`、`observe_native_calls`(LLDB)、`start_frida_session`、`instrument_with_frida` | Windows 空白；无内核/驱动级；无快照回放；无内存取证式 dump |
| 协议解析 | 7 个工具 | C+ | `inspect_packet_capture`、`inspect_packet_fields`、`decode_signal_recording` | 只能按字段取值：无 TLS 解密、无流重组、无自定义协议定义、无 protobuf/ASN.1/gRPC |
| 二进制格式 | ~30 个工具 | A- | `inspect_macho`、`inspect_pe_resources`、`inspect_go_binary`、`inspect_wasm_artifact`、`extract_firmware` | 无 dyld_shared_cache 解析（iOS 大规模分析受限）、无文件系统镜像挂载 |
| 自动化 / 编排 | 3 个工具 | C | `batch_decompile`、`execute_rizin_command`、`capture_process_scenario` | 无脚本沙箱、无语料批处理、无跨会话结果库、无 CI 入口 |
| 对抗 / 反检测 | 0 | D | — | 无加壳判定、无熵分析、无 YARA、无反调试对抗、无内存脱壳 |
| 证据治理 | ~20 个工具 | A | `export_evidence_bundle`、`verify_reconstruction`、`record_unknown` | 仅 JSON；缺 SARIF/Markdown 等交付格式 |

**规模事实**：207 个工具、61 个前缀组；其中 55 个（27%）**没有任何必填参数**，依赖"当前文档/当前光标"这类环境状态——headless 引擎下若不先 `open_binary`，这批工具会直接报"无目标"。这是"空转失败"的主要来源。

**引擎耦合**（description 命中数）：Hopper 22、Ghidra 24、ADB 13、IDA 9、Frida 9、Rizin 6、GDB 5、TShark 5、Cutter 2、JEB 2。也就是说近一半的 native 能力在只有 Ghidra 时形态会变，部分工具（`current_*`、`goto_address`、`set_bookmark`）本质是 Hopper GUI 的延伸，headless 下不可用。

---

## 三、分维度评审

### 3.1 静态分析

**做得好的**

- **函数档案化**：`analyze_function` 一次性给出身份、签名、调用关系、字符串引用、伪代码与局限，比"逐个取字段"更接近分析员的思维单位。
- **可写回**：`set_address_name` / `annotate_native_function` / `set_comment` 都带**读回校验**，这让"模型命名 + 落库"成为可闭环的工作流，而不是一次性输出。这是 LLM 辅助逆向里最实用的一环。
- **分页与视图**：`inspect_analysis_view` 把大结果（伪代码、JS 图、抓包）拆成可按 kind 分页的视图，避免一次性塞爆上下文。

**欠缺的**

- **没有全程序视角**。所有入口都是"一个函数/一个地址"，没有"导出整个调用图/整个类型系统"，也没有跨函数的类型传播。真实样本的核心逻辑常分散在十几个函数里，靠单点查询拼图效率低。
- **符号信息不进**。没有 PDB/DWARF 导入，也没有 FLIRT/Lumina 这类静态库函数识别——遇到静态链接的 OpenSSL/libcurl，只能靠字符串和调用形态猜。
- **没有二进制 diff**。`compare_functions` 比较的是**两批 Evidence 记录**，不是两个二进制的结构相似度。做补丁比对（1-day 定位）时，缺的是图同构/模糊哈希那一层。
- **数据流只到"有界静态依赖图"**（`trace_native_values`），没有跨过程指针分析，污点传播只能人工接力。

**边界**：它不会替你做"理解"，只把可验证的局部事实整理好。对混淆过的代码，反编译结果本身不可信，而它没有内置的"反编译可信度"标注。

### 3.2 动态调试

**做得好的**

- **多调试器并存且有生命周期管理**：GDB 用 MI3 解析（不是抓 stdout），Rizin 用 `-N` 抑制用户配置保证可复现，Cutter 走 bridge 会话并带 `expected_generation` 做并发保护——这些都是踩过坑才会有的设计。
- **LLDB 的用法克制**：`observe_native_calls` 只在"自有进程 + 指定断点"下录制调用，不开放任意表达式求值。
- **危险面被显式标注**：`push_adb_file`、`install_adb_package`、`capture_process_scenario` 在描述里直接写"device-mutating"，这在安全评审时很重要。

**欠缺的**

- **Windows 完全没有**。没有 WinDbg/cdb、没有 TTD 录制回放、没有 ETW。Windows 上只能靠 Frida 注入，而 Frida 在受保护进程里很容易被摘。
- **没有内核/驱动视角**。无 eBPF/ftrace（Linux）与 ETW（Windows）的系统调用级观测，只有 `read_adb_logcat` 这种设备日志。
- **没有快照与回放**。调试是线性的、不可重放的；对比 `capture_process_scenario` 的"记录一次"能力，缺的是"回到第 N 条指令"。
- **没有内存取证链路**。不能对进程做完整 dump 再离线分析（`inspect_recorded_crash` 只吃 core，且限定 Linux ELF64）。
- **移动端只到"能用"**：ADB 工具齐全（设备/包/进程/日志/截图/推拉/装卸载），但需要设备已连、Frida server 已起；没有 AVD 编排、没有 iOS 真机链路（`list_frida_devices` 理论上能连，但没有 dyld cache / class-dump 这类 iOS 静态配套）。

### 3.3 协议与二进制解析

**做得好的**

- **二进制格式的深度**：Mach-O 能到 slice/load command/权限/签名/entitlements；PE 能到资源树与 .NET 的 ModuleRef/ImplMap/非 IL 方法；Go/Rust 能取构建元数据与依赖清单；WASM 能做类型级接口比较；EVM 能静态解析 selector。这一层的完整度是它最扎实的部分。
- **字段级抓包**：`inspect_packet_fields` 先发现协议/字段，`inspect_packet_capture` 再按选择取值，是"先探再取"的正确顺序，避免把整包塞进上下文。

**欠缺的**

- **不能解密**。没有 TLS keylog 注入，HTTPS 目标只能看握手。这是当前恶意样本分析最大的单点阻碍。
- **不能重组流**。只能取"第 N 帧的某字段"，没有"这条 TCP 流的应用层消息序列"，也没有 HTTP/2、WebSocket 的消息边界。
- **不能定义协议**。没有自定义 dissector，也没有从样本反推字段边界的工具（Netzob 那类）。
- **序列化格式缺一大块**：protobuf（无描述符提取、无 `--decode_raw` 封装）、gRPC、ASN.1、CBOR、MessagePack、Java 序列化都没有。
- **固件只到"切出来"**：Unblob 能解包，但没有文件系统挂载/遍历，也没有基址恢复与 RTOS 识别。

### 3.4 自动化与脚本

**现状**：`batch_decompile` 是唯一的"批量"原语；`execute_rizin_command` / `cutter_command` / `gdb_console` 是三个"任意命令"逃生口；`load_frida_script` 是唯一的"用户代码"入口。Ghidra 与 IDA **没有任何脚本注入能力**。

**这意味着**：一个"反编译全部 300 个函数 → 按调用特征筛出解密例程 → 批量改名"的任务，只能由模型发起约 300 次工具调用，每轮都带上下文成本，且不可复现、不可回归。这是当前工作流最大的效率瓶颈。

**另外缺**：没有语料模式（一次处理一个目录/一批样本）、没有结果持久化（证据只活在会话里）、没有 CI 入口（CLI 只在 REA 上游有 `analyze-javascript-application`，插件没暴露）。

### 3.5 对抗与反检测

**结论：基本为零。** 关键词穷举确认：`entropy`、`packer`、`obfuscat`、`yara`、`unpack`、`anti-debug`、`detect It` 在 207 条描述里均无命中（`packed` 仅出现在 `search_strings` 的"Ghidra 可能漏掉 packed 字面量"里）。

缺的是逆向工程最前面的十分钟：

- 这个样本加壳了吗？（熵、节区名、导入表规模、入口点异常）
- 是哪种壳/保护？（VMProtect/Themida/.NET Reactor/ConfuserEx 指纹）
- 有没有反调试/反虚拟机？（PEB、时序、CPUID、注册表、进程名）
- 字符串是否被加密？（编码识别、XOR 爆破）

没有这些，后面的 Ghidra 分析会在"一堆无法解释的跳转"里空转。**这是投入产出比最高的一块空白**，因为它不依赖任何重型引擎。

---

## 四、短板归因：哪些是 REA 的，哪些是本插件的

这是决定"能不能改"的关键。

| 短板 | 归属 | 插件能否补 |
| --- | --- | --- |
| 无 Windows 调试器 | REA 工具面 | 能（插件自带 cdb/TTD 桥，作为独立工具注册） |
| 无 Ghidra/IDA 脚本注入 | REA | 能（插件提供 **playbook 沙箱**，把多次 MCP 调用编排成一次） |
| 无加壳/混淆/YARA | REA | 能（纯本地静态检查，不需要引擎） |
| 无 TLS 解密/流重组 | REA | 能（插件自带 tshark 封装，`-o tls.keylog_file` / `-z follow`） |
| 无 protobuf/ASN.1 | REA | 能（`protoc --decode_raw` / `asn1tools` 包装） |
| 无语料/跨会话结果 | REA | 能（SQLite 索引 + 批量编排） |
| 单函数粒度、无全程序图 | REA 引擎 | **不能**（要改 Ghidra 侧插件） |
| 无符号执行/仿真脱壳 | REA 引擎 | 部分（外接 angr/Qiling，是"新增引擎"而非"补能力"） |
| 无二进制相似度 | REA 引擎 | 部分（BSim/Diaphora 需另装） |

**结论**：插件层能补的是"**编排、预处理、交付、安全**"这四类，覆盖上面 8 条短板中的 6 条，且都不需要动 REA。这决定了下面的路线图。

---

## 五、前沿思路与潜在改进点

1. **Decompiler-in-the-loop 的语义标注**。已有 `set_address_name` + 读回，但缺"命名建议—证据—批量应用—回归"的闭环。前沿做法是让模型基于 `analyze_function` 的结构特征（调用形态、常量、字符串邻接）产出**带置信度的命名提案**，再由 playbook 批量写回并记录 diff。
2. **假设驱动的分析**。`record_unknown` 已经提供了骨架，但"谁来产生假设"仍靠人。可以从证据缺口自动生成候选假设（例如"存在未被引用的高熵数据段 → 疑似加密配置"），把未知列表变成待办队列。
3. **差分优先**。与其从零读一个样本，不如"同族两版本做函数级差分 → 只看变化点"。REA 有 JS 版本的 `compare_application_versions`，native 侧缺结构相似度；插件可以先用"函数规模/调用签名/字符串集"做粗配，再交给人确认。
4. **协议状态机学习**。当前只能取字段；前沿是从多条流样本反推消息边界与状态迁移（Netzob/Protobuf 反推）。这块对 IoT/恶意样本 C2 分析价值很高。
5. **抗对抗前置**。把"是否加壳/是否反调试"作为分析的第一等公民，决定后续走静态还是动态、走 Ghidra 还是先脱壳。
6. **证据的机器可读交付**。Evidence bundle 已是 JSON，但缺 SARIF（给 CI）、STIX（给威胁情报）、Markdown（给人）三种出口。

---

## 六、风险边界

**必须写清楚的六条**

1. **授权边界**。工具面包含 Frida 注入、GDB 任意命令、ADB 装卸载、进程 PTY 执行——这是完整的代码执行面。插件应在每次会话记录"授权目标范围"，并在越界路径（非授权目录/设备）上拒绝。
2. **变更型操作**。30 个工具会写目标（`set_*`、`push_adb_file`、`install_adb_package`、`uninstall_adb_package`、`stop_adb_app`、`capture_*`）。当前只靠描述里的 "device-mutating" 提示，没有强制闸门。**这是最容易出事的地方**：模型一次误判就可能卸载掉分析设备上的包。
3. **供应链**。28 MB、136 个包的闭包没有 SBOM，也没有 npm provenance；Ghidra 从网络下载（虽校验 SHA-256）。一旦上游包被投毒，插件会原样执行。
4. **数据外泄**。反编译结果、字符串、配置、密钥都会进入模型上下文。对企业样本，这等于把分析对象上传。需要"敏感产物不出本机"的策略（本地模型 / 脱敏 / 只回摘要）。
5. **目标可检测性**。Frida、GDB、Rizin 都会被反调试识别。**不要承诺隐蔽性**；反过来，应该提供"当前是否会被检测"的提示，以及"改用快照/离线分析"的建议。
6. **模型幻觉**。反编译代码上的推断极易被写成事实。REA 的 Evidence 模型是对的解药，但插件侧目前只在结果末尾追加两句通用提示（`RESULT_GUIDANCE`），没有按工具类型区分——对 `procedure_pseudo_code` 应该强制标注"这是反编译推断"。

---

## 七、可落地方案

排序原则：**先降成本与风险（P0）→ 再把人工流程自动化（P1）→ 最后引入新引擎（P2）**。P0 全部可在插件层完成，不改 REA。

### P0 · 1–2 周（低风险、立刻见效）

| # | 改进 | 具体做法 | 预期效果 | 验收 |
| --- | --- | --- | --- | --- |
| 1 | **结果体积治理** | 在 `buildTool.execute` 后加 `maxResultChars`（默认 24k）；超限写 `~/.dsh/rea-artifacts/<session>/`，返回摘要 + 路径；新增 `rea_open_artifact(path, offset, limit)` 分页读取 | 单次调用上下文峰值降 60–80%；`binary_session`（实测 73 KB）不再挤爆一轮对话 | 同一分析任务 token 总消耗对比基线下降 ≥50% |
| 2 | **变更型工具闸门** | 30 个写操作工具默认需要 `REA_ALLOW_MUTATION=1`；插件记录审计行（时间/工具/参数/目标）；`uninstall_adb_package` 等破坏性操作二次确认 | 误删/误改概率归零；满足审计要求 | 未设开关时写操作全部被拒，且有可读提示 |
| 3 | **`rea_catalog` 增加 schema 模式** | `rea_catalog({tool:"capture_process_scenario"})` 返回该工具完整 input schema（最大 7.3 KB，按需） | 修复"延迟加载后模型看不见参数结构"导致的首次调用失败；14 参数工具不再瞎猜 | 复杂工具首次调用成功率提升（抽样 20 个多参工具） |
| 4 | **`rea_status` 一屏就绪** | 合并 `binary_session` + `list_documents` + 引擎可用性，输出"当前目标 / 引擎 / 可做/不可做的任务" | 55 个无参工具不再因"无打开目标"空转；README 实测的 27 次空转可消除 | 空转失败率下降 ≥70% |
| 5 | **静态对抗初筛（插件自实现）** | 熵/节区异常/导入表规模/入口点异常 → 加壳初判；字符串 + 编码识别 + XOR 爆破；YARA 规则目录扫描 | 补上 REA 完全缺失的"前十分钟"；恶意样本 triage 从分钟级到秒级 | 对 20 个已知壳样本的识别率 ≥70%，误报 ≤10% |
| 6 | **证据出口** | Evidence bundle → Markdown 报告 / SARIF，附覆盖度与未解未知清单 | 交付物可读可审计；能接 CI | 一条命令产出可直接归档的报告 |

### P1 · 3–6 周（结构性改进）

| # | 改进 | 具体做法 | 预期效果 |
| --- | --- | --- | --- |
| 7 | **Playbook 沙箱（最高价值）** | 用 `node:vm` + 子进程隔离；暴露 `rea.call(tool,args)` / `artifact` / `log`；`rea_run_playbook(name, input)` 一次执行整段脚本；产物写 artifact 目录 | 把"300 次模型往返"压成"1 次调用 + 1 段脚本"；批量反编译/批量改名/批量导出成为确定性流水线 |
| 8 | **语料模式 + 结果库** | `rea_batch_triage(dir)`；样本/函数/证据/未知写入 `~/.dsh/rea-artifacts/rea.db`（SQLite）；跨会话可查 | 500 样本可跑；分析结果可复用、可回归 |
| 9 | **原生版本差分编排** | 组合 `analyze_function` + `compare_functions`，按函数规模/调用签名/字符串集做粗配，输出"疑似补丁点"候选 | 1-day 定位从数小时人工到候选列表 |
| 10 | **协议补强** | 插件自带 tshark 封装：`-o tls.keylog_file`、`-z follow,tcp/http2`、导出 `http.file_data`；`protoc --decode_raw` / `asn1tools` 包装 | 补上 TLS 解密与流重组，覆盖 HTTPS/gRPC 主流目标 |
| 11 | **Windows 动态补齐** | 接 `cdb -c` 脚本化断点与 `ttd` 录制回放（作为插件自有工具注册） | Windows 从"只能用 Frida"到"断点 + 回放" |

### P2 · 2–3 月（引入新引擎，能力跃迁）

| # | 改进 | 说明 | 预期 |
| --- | --- | --- | --- |
| 12 | 符号执行 / 仿真脱壳 | 外接 angr（路径约束）与 Qiling/Speakeasy（OEP 定位、API 追踪） | 能处理 VM 保护与自解压样本 |
| 13 | 二进制相似度 | Ghidra BSim / Diaphora 导出函数指纹，跨样本聚类 | 家族归类、1-day 批量匹配 |
| 14 | 反对抗 | 反调试/反虚拟机检测（PEB、时序、CPUID）+ ScyllaHide 类隐藏配置生成 | 受保护样本可调试 |
| 15 | Fuzz harness 生成 | 从 `inspect_recorded_crash` 反向生成 AFL++/libFuzzer 模板，崩溃去重 | 从"读懂"走到"打穿" |

### 不建议做（明确排除）

- **不要把 207 个工具合并成 `rea_run(tool, input)`**：会摧毁 schema 可见性，模型必须猜参数。当前 `deferLoading` + `rea_catalog` 是更好的解。
- **不要在插件里内置"隐蔽注入"能力**：既是法律风险，也会让工具被 AV/EDR 标记，反而降低可用性。
- **不要用 `node:vm` 当安全边界**：它不是沙箱。playbook 必须被声明为"可信代码"，用子进程 + 权限最小化隔离，而不是靠 vm。

---

## 八、一句话总结

**它是一个"把证据管好"的静态分析工作台，静态与制品解析接近商业水准，动态偏 Linux/macOS，自动化与对抗是明显洼地。** 最划算的投入不是加更多分析引擎，而是补三件事：**结果体积与参数可见性（P0）、脚本化编排（P1）、加壳与协议的前置处理（P0/P1）**——这三件都在插件层，不动 REA 就能拿到大部分收益。
