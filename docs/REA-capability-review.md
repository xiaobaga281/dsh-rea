# dsh-rea 1.4.0 逆向能力评审（第三版 · 2026-11-04）

> **方法**：重新连接真实 REA MCP 子进程，导出 `compact + full-output`（2,576,421 B）与 `full-input`（652 KB）两份 `tools/list` 快照，逐条核对 207 个工具的名称、描述、输入 schema、输出 schema 与 annotations；并实际运行 1.4.0 的装配、分类、schema 缓存、更新检查与宿主矩阵。本文所有数字都来自本机实测，不沿用上一版结论。
>
> **身份与立场**：以资深逆向研究专家视角评审。评价对象是「插件 + 上游 REA 运行时」构成的完整工作台；凡插件层能修的算插件问题，需上游或商业授权才能补的明确标为能力天花板。

---

## 一、结论

1.4.0 把 1.3.1 评审指出的**桥接层元数据断层**基本补齐了：完整 schema 进宿主内存、按 JSON Path 渐进展开、结构化结果锚点入索引、闸门覆盖自有工具、只读工具放开并发、宿主矩阵进门禁。**连续三轮「评审 → 改进 → 再评审」之后，纯插件层可做的结构性改进已接近天花板**；本轮最有价值的发现不再是"REA 缺哪个引擎"，而是三个此前没被抓到、**可复现、可修复且都在插件层**的治理缺陷：

1. **`allowedTargets` 的路径授权只认 14 个硬编码键名**，而真实 schema 里至少 11 个承载绝对路径的参数不在名单内 —— 配了授权范围的会话仍可读写范围外路径（**P0，安全边界失效**）。
2. **`trustedManifestKey` 被元数据源的回退顺序架空**：配置签名公钥后，实测 `updateStatus().source` 仍是 `api.github.com`，签名源从未被咨询 —— 用户以为有独立信任根，实际没有（**P0，供应链**）。
3. **`results.jsonl` 无保留期/容量治理**，且 157 个并发工具同时追加写；查询只扫末尾 20,000 行 —— 长期运行后历史证据静默"查不到但还在占盘"（**P1，证据链**）。

总体评级：**静态分析 B+ / 动态调试 B- / 二进制解析 A- / 协议解析 C+ / 自动化 C+ / 对抗与反检测 C+**。1.4.0 提升的是"把上游能力接住"和"把工作流串起来"，**没有增加任何一个逆向引擎**；五个维度的能力上限仍由 REA 上游决定。

---

## 二、实测基线（1.4.0，2026-11-04）

| 指标 | 实测值 |
|---|---|
| 上游工具面 | 207 工具 / 61 组 / 570 个顶层参数 / 55 个无必填参数 / 单工具最多 13 参数 |
| schema 体积 | compact+全量输出 2,576,421 B；full 输入 652 KB；最大单工具 `compare_web_captures` 165,694 B |
| 1.4.0 装配 | 221 工具（207 延迟 + 14 自有）/ 6 路由；host-matrix 三种宿主模式 3/3 PASS |
| 测试 | `npm test` 144/144 |
| 分类分布 | **157 只读并发 / 50 变更（4 破坏性 + 5 命令逃生口 + 41 审计）/ 108 带 external 提示** |
| schema 缓存 | 207 条完整定义，真实探测约 3,084 KB 宿主内存；165 KB schema → 1,076 字符轮廓、`left.evidence_id` 展开 351 字符 |
| 本机外部二进制 | `tshark` / `protoc` / `cdb` / `windbg` / `etw` **全部缺失** |

---

## 三、能力矩阵（1.4.0）

| 维度 | 成熟度 | 1.4.0 实际变化 | 仍然欠缺 |
|---|---|---|---|
| 静态分析 | **B+**（制品解析 A-） | triage 补 DEX/WASM/APK、PE overlay/时间戳/证书表、6 类反分析标记；`rea_catalog` 让复杂工具参数真正可见 | 无全程序图/类型重建/结构 diff；triage 仍是启发式分流器，无真实语料校准；IDA 覆盖 0 |
| 动态调试 | **B-** | 5 个命令逃生口纳入审计；只读工具不再无条件排队 | Windows 全空白（cdb/TTD/ETW 命中 0）、无内核视角、无进程 dump、无回放；并发放开缺服务端压测证据 |
| 协议与二进制解析 | 二进制 **A-** / 协议 **C+** | 新增 `rea_protocol_*` 适配层，缺工具时精确降级 | TLS keylog 0、dissector 0、protobuf/gRPC/ASN.1/CBOR 0、流重组仅 1 处；本机 5 个外部二进制全缺 → 适配层能力实测为 0 |
| 自动化脚本 | **C+**（原 C） | `rea_run_playbook` 子进程 + IPC 代理（白名单/调用上限/超时）、`rea_batch_triage`、`rea_diff_hint`、`rea_query_results` | 无 Ghidra 脚本注入、无 CI、无 playbook 语料；**playbook 是隔离不是沙箱**；157 个工具并发无闸 |
| 对抗与反检测 | **C+**（原 C） | 样本字符串/报告文本转义并标为不可信；SARIF 去掉硬编码成功状态；`pinnedSha256` + 可选 minisign | YARA 默认未配置、无反调试/反 VM 动态对抗、无脱壳；**签名门禁实测失效**；不承诺隐蔽性 |

---

## 四、本轮新发现（按严重度）

### 4.1 【P0】`allowedTargets` 可被 11+ 个真实路径参数绕过

`pathOutsideScope()` 用 `PATH_KEYS` 硬编码了 14 个键名（`path` / `file` / `target` / `output` / `directory` / `url` …），只检查这些键里的绝对字符串路径（已用 `resolve()` 挡住 `..` 遍历，这一点是对的）。但真实 207 工具的输入 schema 里共出现 **39 个路径类参数名，其中 37 个不在白名单**。剔除 `max_file_bytes`、`direction`、`source_kind` 这类误命中后，仍至少 11 个是真实文件路径：

| 参数 | 出现的工具（示例） | 后果 |
|---|---|---|
| `output_directory` | `extract_firmware`、`recover_javascript_sources`、`pull_adb_package` | 可向授权根外写文件 |
| `local_path` / `apk_path` / `device_path` | `push_adb_file`、`install_adb_package`、`pull_adb_file` | 设备/本地读写越界 |
| `input_path` / `source_paths` / `executable_path` / `application_path` | `analyze_javascript_application`、`capture_electron_scenario` | 读越界文件、拉起越界程序 |
| `working_directory` / `capture_path` / `additional_paths` | `observe_native_calls`、`inspect_web_network_capture` | 工作目录/输出越界 |

自有工具的 `ownGuard` 更窄（正则只匹配完整键名 `path|file|directory|dir|target|output|input`），同样漏掉复合键。**这不是理论风险**：配置 `allowedTargets` 的会话调用 `extract_firmware({output_directory:'C:/Windows/Temp'})` 会通过检查。

> 修复方向：放弃键名白名单，改为**值形态判定** —— 遍历 args 的所有字符串值，凡匹配 `^[A-Za-z]:[\\/]` / `^\\\\` / `^/` 就按 `resolve()` 后与授权根比对；非字符串（数字、布尔）天然排除，证据 ID 等含 `/` 但不以根开头的值也不受影响。对 `url` 单独做 scheme 白名单。验收：把上表 11 个键各注入一个越界绝对路径，全部被拒；正常调用无误拦。

### 4.2 【P0】签名门禁被回退顺序架空（实测）

`fetchLatest()` 的元数据源顺序是 `[api.github.com Release, raw manifest, jsDelivr manifest]`；`trustedManifestKey` 的验签**只挂在后两个 manifest 源上**，而循环在第一个源成功时就 `return`。实测：

```
checkForUpdate({ current:'1.3.1', trustedManifestKey:'minisign public key RWT…' })
  → latest 1.4.0, source api.github.com, updateStatus().source api.github.com
```

即：**只要 GitHub API 可达，签名永远不会被验证**；用户配置了独立信任根却得到"已保护"的错觉。更糟的是 `verifyManifestText()` 在 minisign 缺失时抛错，manifest 源失败后仍会回退到未签名的 Release 源，形成"验签失败 → 静默降级"。Release 源携带的 `asset.sha256` 来自 Release 说明本身，与归档同源，账号被篡改时不能提供独立保证；目前唯一真正独立的信任根只有本地 `pinnedSha256`。

> 修复方向：设置 `trustedManifestKey` 时把签名 manifest 源提为**唯一可信源**（Release API 只用于展示版本提示，不参与 `asset` 决策）；验签失败必须 fail-closed 并明确报错，不得回退；把 `pinnedSha256` / 签名 / 无保护三态统一成 `trustPolicy`，侧栏显示**实际生效**的级别。验收：配置公钥且 GitHub API 可用时 `source` 必须为签名源；删掉 `.minisig` 后检查更新必须失败而非成功。

### 4.3 【P1】结果索引无治理、并发写、查询静默截断

`results.jsonl` 位于跨会话 base 目录，`artifacts.purge()` 只清理 session 子目录，**完全不碰它**；`record()` 用 `appendFile` 且 157 个工具现在可并发调用，多个异步写之间没有串行化；`query()` 只取末尾 `MAX_SCAN_LINES = 20_000` 行且不返回截断标记。结果是：长期使用后文件无限增长、早期证据查不到却没有任何提示、审计与结果写可能交错。

> 修复方向：纳入 `artifactRetentionDays` / `artifactMaxBytes`（按行滚动或分片）；用 Promise 队列串行化追加；`query()` 返回 `truncated:true` 与扫描行数；每行加 `prevHash` 形成可校验的哈希链。验收：写入 25,000 行后查询返回截断标记、文件大小受 cap 约束、并发 50 次写入后每行都是合法 JSON。

### 4.4 【P1】双源元数据一致性与 `includeOutput` 回退

完整 schema 来自**第二个短生命周期子进程**，实际工具参数来自 live 子进程；两者没有版本戳绑定，上游升级或 profile 语义变化时可能不一致。`createSchemaCache.describe()` 取 `source = full ?? compact`，而 `includeOutput` 分支只读 `source.outputSchema ?? full?.outputSchema` —— 实测当 full 快照不含 `outputSchema`、compact 含 207 个时，`includeOutput=true` 会误报 "not available"。默认配置下 full 探测带输出 schema 所以不触发，但这是一条静默降级路径。

> 修复方向：probe 时记录 `initialize` 返回的 `serverInfo.version` / `protocolVersion`，与 live 比对并在 `rea_doctor` 显示；不一致时以 live compact 为准并标注；`includeOutput` 回退到 `full.outputSchema ?? compact.outputSchema`。

### 4.5 【P1】二进制/图像产物只归档、不可读

1.4.0 把 image 与 resource.blob 落盘了（比 1.3.1 的占位符进步），但 `rea_read_artifact()` 用 `readFile(path,'utf8')`，没有任何工具能读取 `.png` / `.bin` 的内容或元信息。描述层关键词命中的 18 个"视觉相关"工具里（含 `list_segments` 等误命中），真正产出截图的约 5 个（`capture_web_screenshot`、`capture_adb_screen`、`compare_web_screenshots`、`observe_native_ui`、`capture_process_scenario`），其结果对模型仍是**不可见、不可分析**的。

> 修复方向：`writeBinary()` 同步写 `.meta.json`（mime、字节数、sha256、来源工具、时间）；新增 `rea_describe_artifact` 返回尺寸/哈希/EXIF/PNG 文本块等文本化索引；若宿主支持 image content block，提供 opt-in 转发（默认关闭，避免上下文爆炸）。验收：截图调用后能用工具读到尺寸与摘要而非乱码。

### 4.6 【P2】不可信内容在报告侧只标记、未包裹

`markUntrusted()` 已用于对话侧样本字符串；但 `export.js` 的 SARIF 只在 `properties` 里放了 `'dsh-rea/untrusted-content': true`，`results[].message.text` 仍是未包裹/未转义的自由文本。下游 CI 若把它渲染成 HTML，样本里的指令文本仍有注入面。

> 修复方向：`message.text` 过 `markUntrusted('evidence', …)`；Markdown 表格继续用 `escapeCell`；SARIF `invocations` 状态从真实执行结果推导而非固定缺省。

### 4.7 【P2】说明与实现的数字漂移（第三次出现）

README、本报告旧版、v1.4.0 Release 说明都写"**162 个只读工具放开并发**"，实测 1.4.0 是 **157**（因为 5 个命令逃生口被正确纳入 mutating）。1.3.1 也曾出现 Release 说明写了 `ELECTRON_NO_ATTACH_CONSOLE` 而代码没有的漂移。**手写说明会持续过期**。

> 修复方向：`host-matrix` 输出机器可读 JSON（工具数、路由数、分类分布、schema 体积），Release 说明由脚本从该 JSON 生成；CI 断言这些数字，变化时测试失败而不是文档静默过期。

### 4.8 【边界，非缺陷】必须诚实标注的四件事

- 本机 `tshark` / `protoc` / `cdb` / `windbg` / `etw` **全部缺失**，所以 P1 的协议与 Windows 适配层目前是"精确报缺"而非"能力增强"；换台机器装好工具才有价值。
- 157 个只读工具放开并发**没有 REA 服务端并发压测证据**。好消息是分类器保守：真实工具面里 0 个 `open/start/attach/select` 类会话状态动词被判为只读，串扰风险可控；但 stdout 单通道 + `maxBufferBytes` 下大量并发响应仍可能撑爆缓冲。
- `triage-baseline` 的 tp3/fp0/tn4/fn0 是**合成样本自证**，不代表真实壳识别率；无真实带标签语料。
- `allowedTargets` 是**字符串级授权、不是 OS 隔离**：`resolve()` 不解析符号链接 / junction / 8.3 短名，能读到的路径不等于真实受限。文档不应把它描述成沙箱。

---

## 五、分维度详评

### 5.1 静态分析

**优势**：函数档案化与命名读回校验是同类工具里少见的严谨设计；`batch_decompile` 提供真实并发批量；对 ELF/PE/Mach-O/Go/Rust/WASM/Dart AOT/Flutter 的制品解析深度足够（Ghidra 相关 24 个、Hopper 22 个工具）。1.4.0 让 `rea_catalog({tool,path})` 真正解决"13 参数工具怎么看清"的问题，并用结果索引把 evidence_id 留了下来。

**欠缺**：没有全程序级调用图/类型重建/二进制结构 diff（BSim、Diaphora、bindiff 命中 0），符号服务器/PDB/FLIRT/Lumina 命中 0；`rea_triage` 的熵 + 节区 + 13 类壳签名是启发式分流器，未校准；IDA Pro / idalib / IDAPython 覆盖 **0**（JEB 仅 2 个工具）。反编译器输出始终标注为推断，这点做得对。

### 5.2 动态调试

**优势**：GDB MI3、LLDB 录制、Frida 完整生命周期（9 个工具）、Linux core 离线分析（不启动目标）。1.4.0 把 5 个可执行任意命令的逃生口纳入审计，并把只读调用从全局串行中解放出来。

**欠缺**：Windows 动态调试全空白（cdb/TTD/ETW 命中 0）、eBPF/ftrace 0、内核/驱动视角仅 1 处 ADB 描述、**进程 dump / minidump 命中 0**（而 triage 的建议链过去正是指向它，1.4.0 已改为只引用真实工具，但能力缺口仍在）、时间旅行/回放仅 1 处 Web 抓包描述。并发放开后缺少服务端回归证据。

### 5.3 协议与二进制解析

**二进制 A-**：字段级抓包"先探再取"、sigrok 信号解码、SQLite/WAL 快照、PE 资源、原生加载镜像与不可变快照比对 —— 证据链设计成熟。

**协议 C+**：TShark 相关 5 个工具，但 **TLS keylog / 解密 0、自定义 dissector 0、protobuf/gRPC/ASN.1/CBOR 0、流重组仅 1 处描述**。1.4.0 的适配层能在 tshark/protoc 存在时封装 keylog 与 `decode_raw`，本机二者皆缺 → 实测能力 0，只输出"缺工具"的诚实降级。这是能力天花板，不是插件 bug。

### 5.4 自动化与脚本

**优势**：1.4.0 是这一维度提升最大的版本 —— `rea_run_playbook` 把长链往返压成一次脚本调用，IPC 代理每次 `rea.call` 都过 `guardTool` + 白名单 + 调用上限 + 超时；`rea_batch_triage` / `rea_diff_hint` / `rea_query_results` / `rea_fuzz_harness` 补齐了语料与结果复用；`npm run host-matrix` 三种宿主模式真实装配进了发布门禁。

**欠缺**：无 Ghidra/JEB 脚本注入、无 CI 集成、无 playbook 语料库与版本管理；子进程**可读全盘文件，不是安全沙箱**（文档已明说）；157 个工具无并发上限闸；`node:vm` 明确不用是对的。

### 5.5 对抗与反检测

**优势**：`rea_triage` 纯本地解析、不执行样本；1.4.0 补 DEX/WASM/APK 容器与 6 类反调试/反 VM 静态标记；样本字符串与报告文本转义、截断、标为不可信（缓解间接提示注入）；`allowedTargets` / `pinnedSha256` / `maxBackups` / 分级提示构成策略层。

**欠缺**：YARA 规则目录默认未配置、无动态反调试对抗、无脱壳/仿真执行（angr/Qiling/Unicorn 命中 0）；不承诺隐蔽性，这对研究工具是正确的定位。**但本轮两个 P0 都在这个维度**：路径授权可被绕过、签名信任根实际未生效 —— 策略层看起来完整，实际覆盖有洞。

---

## 六、风险边界（明确不承诺）

1. `allowedTargets` 不是沙箱：字符串前缀 + `resolve()`，不解析符号链接/junction/8.3 短名，且当前漏掉 11 个路径参数。
2. Playbook 与 5 个命令逃生口可执行任意代码；隔离针对事故与失控脚本，不防恶意脚本。
3. 签名未启用（或被回退架空）时，摘要与归档同源，账号被篡改即失效；多镜像只是传输通道，不承担完整性。
4. 结果索引是 JSONL 元数据，不是防篡改证据库；`rea_query_results` 的置信度/覆盖度来自上游自述，未经独立验证。
5. 反编译/重建输出是**推断，非源码**；triage 结论是启发式分流，不是壳鉴定结论；合成基线数字不可外推。
6. 不执行样本（triage）、不承诺隐蔽性、不做内核/驱动级攻击面；Windows 动态与内核视角当前为 0。

---

## 七、前沿思路（值得跟踪，但先别急着做）

- **可验证证据链**：把 evidence_id → 产物哈希 → 结论做成带 attestation 的链（SLSA/TUF 思路），比"报告里写一句话"强得多；本轮 P1 的哈希链是最小起点。
- **LLM 幻觉抑制**：强制每个结论绑定到 evidence_id，无证据即标 `inferred`；1.4.0 的结果索引已具备基础设施，缺的是导出侧强校验。
- **函数语义相似度**：BSim / SAFE / jTrans 类嵌入匹配，解决无符号二进制的跨版本函数对应，比字符串粗配高一个量级。
- **混合执行辅助脱壳**：Qiling/angr 的 concolic 执行定位 OEP，配合动态 dump，闭合 triage 的建议链。
- **多模态取证文本化**：截图 → UI 树 / OCR / 控件属性，而不是把 base64 图像直接塞进上下文。
- **供应链多密钥**：单一 PAT + 同源摘要 → 独立签名密钥 + 时间戳 + 密钥轮换，正是 4.2 的方向。

---

## 八、可落地方案

### P0 · 1 周内（全在插件层，不动上游，不增加上下文）

| # | 方向 | 具体改动 | 预期效果 / 量化验收 |
|---|---|---|---|
| 1 | **路径授权改为值形态判定** | `pathOutsideScope()` 遍历所有字符串值匹配绝对路径形态；`ownGuard` 同步；`url` 单独 scheme 白名单；保留 `resolve()` | 39 个路径类参数全覆盖；上表 11 个越界注入全部被拒，正常调用零误拦 |
| 2 | **签名门禁 fail-closed** | 配 `trustedManifestKey` 时签名 manifest 为唯一可信源；验签失败不回退；统一 `trustPolicy` 三态并在侧栏显示实际生效级别 | 配公钥且 API 可达时 `source` = 签名源；删 `.minisig` 后检查更新**失败**而非成功 |
| 3 | **结果索引治理** | 纳入保留期/容量、串行化追加、`truncated` 标记、`prevHash` 哈希链 | 25,000 行后查询返回截断标记且体积受 cap；并发 50 写无损坏行 |
| 4 | **说明-实现一致性门禁** | host-matrix 输出机器可读指标，Release 说明脚本生成，CI 断言工具数/分类分布 | 消除"162 vs 157"类漂移；数字变化导致测试失败 |
| 5 | **元数据单源化** | probe/live 版本戳绑定；`includeOutput` 回退 compact；`rea_doctor` 显示一致性 | full 无 outputSchema 时仍能返回；版本不一致时明确降级 |

### P1 · 3–6 周（把"能跑"变成"可信"）

| 方向 | 具体改动 | 预期效果 |
|---|---|---|
| 并发压测与限流 | 真实子进程 20–50 并发混合场景；加 `maxConcurrentReadTools`（默认 4–8）信号闸 | 给出 REA 会话串扰/缓冲上限的实测结论，避免 stdout 单通道被撑爆 |
| 真实语料基线 | ≥30 个带标签样本（UPX/ASPack/Themida/VMProtect/无壳），输出混淆矩阵与误报率 | triage 从"合成自证"变成有统计意义的识别率 |
| 报告侧不可信隔离 | SARIF `message.text` 过 `markUntrusted`；`invocations` 从真实结果推导 | 下游 CI 渲染不再有注入面 |
| 二进制产物文本化 | `.meta.json` + `rea_describe_artifact`，opt-in image block | 18 个视觉命中工具里真正产图的约 5 个变得可分析 |
| 统一信任根 | `pinnedSha256` + minisign + 无保护三态合并，侧栏显示实际状态 | 用户不再误以为"配了就安全" |

### P2 · 2–3 月（需上游 REA / 新引擎 / 商业授权，插件层做不到）

- 协议：tshark TLS keylog + TCP 流重组 + 自定义 dissector、protoc `decode_raw` 落地（先解决二进制分发）。
- Windows 动态：cdb / TTD / ETW / PDB 符号服务器 / 进程 dump（补齐 triage 建议链的能力终点）。
- 静态跃迁：进程 dump 后重跑 triage、BSim/Diaphora 结构相似度、符号导入、IDA（商业授权）。
- 仿真：Qiling/angr 混合执行定位 OEP 与自动脱壳。
- 供应链：多密钥 + 时间戳 + 密钥轮换，脱离单一 PAT。

### 明确不做

- 把 `readOnlyHint` 当权威分类器（202/207 为 false，会大面积误拦）。
- 把 207 个工具合并成单一 `rea_run`（丢失可发现性与逐工具守卫）。
- 内置隐蔽注入 / 反检测对抗能力（研究工具定位，合规边界）。
- 用 `node:vm` 当 playbook 沙箱（不是安全边界）。
- 让镜像承担完整性（镜像只是通道）；把 JSONL 说成数据库。

---

## 九、一句话总结

**1.4.0 已经把"接住上游"这件事做到了桥接层的上限；下一轮真正该做的是把三处看似完整、实测有洞的治理边界补严（路径授权覆盖、签名信任根生效、结果索引治理），并用并发压测与真实语料把"能跑"变成"可信" —— 之后再往上，全都是上游引擎与商业授权的账。**

---

## 附录 · 与前两版的差异与复现

| 版本 | 当时的 P0 | 本版结论 |
|---|---|---|
| 1.2.0 评审 | 结果落盘、多镜像自更新、延迟注册 | 已落地，不再是瓶颈 |
| 1.3.1 评审 | 元数据断层、闸门旁路、图像丢弃、并发串行、宿主门禁、triage 校准 | 1.4.0 全部落地；本版复核确认有效（207 完整 schema 进缓存、5 个逃生口已审计、host-matrix 3/3） |
| **1.4.0 评审（本版）** | **签名门禁失效、路径键覆盖、结果索引治理、说明漂移** | 三项可复现缺陷 + 能力天花板明确 |

复现命令（本机）：

```bash
npm test                    # 144/144
npm run host-matrix         # 3/3 PASS，221 tools / 6 routes
npm run triage-baseline     # 合成矩阵，仅作回归
node <schema-probe>         # 导出 full / compact 两份 tools/list 快照
```

分类分布复核脚本会打印 `readOnlyConcurrent: 157 / mutating: 50 / destructiveBlocked: 4 / externalHint: 108`，以及 `checkForUpdate({trustedManifestKey})` 的 `source` —— 这两个数字是本版两个 P0 的直接证据。

---

## 附录 · 1.5.0 落地状态（2026-11-04 晚）

按本版 P0/P1 改进，**测试 152/152**、**host-matrix 3/3（222 工具 + 6 路由）**、**并发压测 30/30**。

| 方案项 | 状态 | 实现 |
|---|---|---|
| P0-1 路径授权值形态判定 | ✅ | `scopeCandidates()` 遍历所有字符串值（数组 + 一层嵌套）匹配绝对路径形态；`pathOutsideScope()` 与 `ownGuard` 共用；URL scheme 白名单；11 个漏网路径键回归用例；host-matrix 新增 `output_directory` 越界断言 |
| P0-2 签名门禁 fail-closed | ✅ | 配 `trustedManifestKey` 时只跑验签 manifest 源，Release API 不参与；失败直接抛错不回退；`installUpdate` 第二道闸拒绝未签名来源；`resolveTrustPolicy()` 四态（`none`/`pin`/`signature`/`pin+signature`），侧栏显示实际级别。实测配 key → `phase=error`、`source=null`、明确拒绝；不配 → `1.4.0 / api.github.com / none` |
| P0-3 结果索引治理 | ✅ | Promise 队列串行写、`prevHash`/`hash` 链、每 100 写自动按保留期/容量滚动、`queryDetailed()` 返回 `truncated`/`scanned`/`totalLines`、`rea_query_results` 显示截断提示 |
| P0-4 说明一致性门禁 | ✅ | host-matrix 输出 `dist/host-matrix.json`（工具数/路由数/分类分布），并断言 README 里的 `157 个只读工具` 与 `222 工具`；实测第一次运行就抓到 162/221 漂移，修正后 3/3 PASS |
| P0-5 元数据单源化 | ✅ | `ReaMcpClient` 保存 `initialize` 的 `serverInfo.version`；`prime/primeFull` 绑定版本戳，`versionConsistent=false` 时 `rea_catalog` 输出警告；`includeOutput` 回退 `full → compact → source` |
| P1 并发限流与压测 | ✅ | `lib/concurrency.js` semaphore（默认 6，可配 1–32）挂到所有只读桥接工具；`npm run concurrency` 真实子进程 30 次并发对比：无闸 30/30、39 ms；限流 30/30、26 ms——这组轻量只读工具能承受突发，限流不损失吞吐 |
| P1 真实语料基线 | ⚠️ 部分 | `triage-baseline --corpus` 已支持带标签语料并输出混淆矩阵/识别率/误报率；**本机没有真实壳样本**，所以仍只有合成矩阵，不宣称识别率 |
| P1 报告隔离 | ✅ | SARIF `results[].message.text` 过 `markUntrusted('evidence')`，包裹 + 转义 + 截断 |
| P1 二进制文本化 | ✅ | `writeBinary()` 写 `.meta.json`（mime/字节/摘要/来源工具/PNG·GIF·WebP 尺寸）；新增 `rea_describe_artifact` 返回文本描述与"是否与采集时摘要一致"；二进制本身仍不进上下文（opt-in 多模态转发未做） |
| P1 统一信任根 | ✅ | `trustPolicy` 四态 + 侧栏实际级别 + 安装前第二道闸，签名/pin/无保护不再混淆 |
| P2 上游能力 | ❌ 未做 | tshark keylog / cdb·TTD·ETW / 进程 dump / BSim / Qiling·angr / IDA 均需新引擎或商业授权，插件层无法实现，不假装落地 |

**仍存边界**：路径授权是字符串级（`resolve()` 不解析 junction/8.3 短名）；playbook 仍是可信代码隔离而非沙箱；`results.jsonl` 是带哈希链的元数据而非防篡改证据库；并发压测只覆盖 6 个轻量只读工具，大结果/长事务工具未验证；签名发布需要运维持有 minisign 私钥并发布 `.minisig`，否则配了 `trustedManifestKey` 会**正确地**让检查更新失败。

---

## 附录 · 1.5.0 第二轮改进：逆向能力与反追踪（2026-11-04 晚）

用户明确要求这一轮的重点是**逆向分析能力**与**反追踪**，而不是继续做工程治理。因此在同一未发布的 1.5.0 里补了一层纯本地静态情报，不依赖任何上游引擎，也不改动 REA 子进程。

### 反追踪的三层含义（本轮一并落地）

| 层 | 问题 | 落地 |
|---|---|---|
| 样本侧 | 这个文件**怎么追踪人** | `rea_tracking_surface`：10 个追踪族（遥测 SDK / 广告与设备标识 / 浏览器与主机指纹 / 位置 / 持久化状态 / 剪贴板通讯录 / 归因 / 外联端点…），输出分类、严重度、证据、评分与等级 |
| 分析者侧 | 分析报告**会不会暴露我** | `rea_sanitize_report`：检测并替换本机用户名、家目录、主机名、绝对 Windows/Unix 路径、IP、MAC、邮箱、Bearer / PAT / API key、代理凭据；`networkEgressPolicy` 把 108 个 `openWorldHint` 工具纳入 allow/warn/deny 策略，侧栏显示实际生效状态 |
| 对抗侧 | 样本**怎么妨碍分析** | `rea_anti_analysis`：10 类技术（调试器 API、硬件断点、时序、CPUID/管理程序、VM 工件、沙箱启发式、Hook/插桩检测、反 dump、自完整性、TLS 回调），每类带证据、防御性对策、以及**只引用真实广告工具**的下一步；明确不提供规避或隐蔽能力 |

### 逆向能力的实质增量

- **PE 导入表解析**（此前完全没有）：`parsePEImports()` 从数据目录解析 `IMAGE_IMPORT_DESCRIPTOR` 链，处理 32/64 位 thunk、按序号导入、RVA→文件偏移；这是"熵 + 节区"之外的第一类语义信息，用合成 PE32 做回归。
- **结构化 IoC**：`rea_ioc_extract` 提取 11 类指标并去重、带偏移，完整 JSON 落盘；`rea_triage` 现在直接给出 IoC 分类计数。
- **ATT&CK 式能力画像**：11 条规则把导入 API 映射到 T1055/T1059/T1547/T1071/T1082/T1113/T1056/T1573/T1486/T1027/T1140，加上追踪面 T1537；每条带证据与置信度，明确标注"能做什么 ≠ 做过什么"。
- **差分升级**：`rea_diff_hint` 从熵+采样字符串变成四级优先队列——新增高危导入 > 新增网络 IoC > 节区熵变 > 字符串 Jaccard 与 4 KB 分块重叠。
- **初筛闭环**：`rea_triage` 报告新增导入摘要、高危 API、追踪等级、能力提示，并把建议链指向三个情报工具；空导入表与高追踪面进入容器异常清单。

### 预期效果与验收

静态阶段从"猜这个文件是不是加壳"扩展到"它有哪些能力、能追踪什么、会怎么阻碍分析、报告能不能安全分享"；全部纯本地、零网络、零样本执行、零新增上下文常驻。`npm test` 162/162（新增 10 个情报用例）、host-matrix 3/3（**226 工具 + 6 路由**）、真实装配完整 schema 3084 KB 且版本戳匹配。

### 明确未做

不提供隐蔽注入、反检测规避、绕过授权或任何攻击能力；不执行样本；不连接样本端点；不新增反汇编/反编译/仿真引擎。结构比对（BSim/Diaphora）、真实进程 dump、TLS keylog 解密、Windows 动态调试、IDA 接入仍是上游/商业授权的能力天花板。追踪面与反分析矩阵是**字符串与导入表启发式**，未使用的 SDK、加密配置、动态解析都会造成误报/漏报，结论必须回到反汇编或运行时轨迹验证。

---

## 附录 · 实测驱动改进与「反追踪」定义修正（2026-11-04 晚，第三轮）

用户提出两个要求：① 写一个测试程序，用插件实际逆向它，看效果，不行就继续加强；② 澄清「反追踪」指的是**分析者用插件分析某个 App 时，App 所属方通过埋点、设备指纹、账号关联把分析者本人识别出来**。上一版把它理解成"报告脱敏 + 样本追踪面识别"，方向偏了：报告脱敏只处理分析结束后的文档，而真正的风险发生在**分析过程中采集的标识符被回传给应用所属方**。

### 反追踪的最终落点

`rea_analyst_exposure` 把风险建模成「采集点 → 标识符 → 回传端点 → 关联风险」链路，覆盖 7 条链路：账号/登录态（critical）、设备与广告标识、推送/崩溃实例 ID、网络出口 IP 与 UA、浏览器/主机/区域指纹、行为埋点与会话回放、位置与本地数据。每条给出样本里的静态证据、把分析者关联出去的具体机制、以及对应的防御性缓解建议。工具还输出：
- 全部遥测端点（含 XOR/UTF-16/base64 恢复出来的隐藏端点），并标注哪些是推导值、误报率更高；
- hosts 式拦截规则的**纯文本**（只打印，绝不修改系统）；
- 分析前 preflight 清单（隔离可回滚环境、绝不用真实账号/手机号/推送 ID、独立网络出口、时区语言屏幕一致性、样本不要放在含用户名路径、抓包核对未列出的端点、分享前脱敏）。

明确边界：这是分析者的隐私/OPSEC 防护建议，不是冒充他人、绕过授权或规避检测；不改系统状态、不联网、不执行样本。

### 实测方法

本机没有任何 C 编译器，所以用 `npm run make-sample` 生成可复现的**结构化 PE32**（真实 `IMAGE_IMPORT_DESCRIPTOR` 链、3 个 DLL / 17 个导入 API、ASCII + 奇/偶偏移 UTF-16 + 单字节 XOR + 高熵 .text 节）、一个同骨架的**干净对照样本**（误报控制），以及一个可运行的 **JS 孪生体**。`npm run demo` 用假宿主真实装配插件（仍启动真实 REA 子进程），调用全部本地分析工具，按 62 项期望清单打分。

### 第一轮：84%（41/49），明确不合格

| 项 | 结果 |
|---|---|
| 工具层端到端 | 全通 |
| 干净对照样本 | 0 误报 |
| **隐藏指标** | **0/5** — XOR 加密的 C2/SDK/反分析字符串、奇偏移 UTF-16 备用端点、base64 配置全部漏检 |
| 追踪面 / 反分析 | 7/9、6/7（漏项同样来自加密字符串） |

根因：字符串层只有「ASCII + 偶偏移 UTF-16」两个通道，`triage` 的 XOR 探测只报告候选 key、不把解出的文本送进 IoC / 追踪面 / 反分析矩阵。

### 改进

1. 新增 `lib/strings.js`：双相位 UTF-16LE、UTF-16BE、**单字节 XOR 解密**（语义锚点 + 字母占比 + 每 key 上限）、**base64 滑动解码**（容忍前后粘连字节、四种帧偏移）。每条推导结果标记 `derived` 与恢复方式。
2. `rea_ioc_extract` 把推导指标单列为「需人工核验」，不混进确证清单；`summarizeIocs()` 分别给出 `confirmedByType` 与 `derived`。
3. 追踪面新增 7 个**身份关联**族（账号/OAuth、推送 token、崩溃实例 ID、网络身份、行为埋点/会话回放、区域时区、安装 ID），`capabilityProfile` 增加 GetProcAddress 动态解析 API 提示。
4. 新增 `rea_analyst_exposure`（本节开头）。
5. `rea_triage` 输出字符串通道分布、隐藏字符串计数与样例、深度反分析技术列表。

### 噪音治理（第二轮发现的问题）

第一轮改进后命中率虽然 100%，但 XOR 通道产出 **2527 条**字符串，IoC 里的 email 从真实 1 条涨到 7 条——命中率是假的，误报被掩盖了。检查噪音样本发现根因：相邻 XOR key 会把**明文**位移成看似可读的乱码（如 `KERNEL32.dll` → `JDSODM23/emm`）。收紧为「强语义锚点 + 字母占比 ≥ 0.55 + 每 key 上限 12」后，XOR 条数 2527 → 142 → **16**，确证 email 回到 1 条，隐藏指标仍 5/5；干净样本深字符串 559 → **13** 且零误报。

### 最终结果

| 指标 | 第一轮 | 最终 |
|---|---|---|
| 总命中 | 41/49 (84%) | **62/62 (100%)** |
| 隐藏指标 | 0/5 | **5/5** |
| 追踪 / 反分析 / IoC / 导入 / 能力 / 暴露矩阵 | 部分 | **全项通过** |
| 确证 IoC | 含假指标 | **11 条确证 + 5 条推导单列** |
| 干净对照 | 0 误报 | 0 误报 |
| 测试 | 162/162 | **168/168** |

**仍未解决**：真实编译产物（.NET 元数据、Go/Rust 字符串表、控制流平坦化）、加密配置需要多字节/RC4/AES 解密，delay-load 与 bound import 未解析，静态证据无法证明某个标识真的被回传。这些需要新引擎或动态轨迹，属于能力天花板，不假装已实现。
