# 交接提示词：继续完善 dsh-rea（DSH 逆向复刻插件）

> 用法：把下面「交接提示词」整段发给另一个编码 Agent。它自带项目坐标、现状、门禁、剩余任务与验收口径，不需要再补上下文。
> 生成时间：2026-11-16；对应工作树：`D:\5\新建文件夹\plugins\dsh-rea`（1.9.0，未提交改动较多）。

---

## 交接提示词（复制此段）

你是接手 `dsh-rea` 的编码 Agent。这是 DSH（DeepSeek Harness）的逆向工程插件，目标不是"再写一个反编译器"，而是让 DSH 模型通过它完成**分析 → 复刻 → 对照 → 修正**的可证伪闭环，最终达到并稳定超过资深逆向工程师的作业水平。你的任务是继续完善这个项目，不是重写它。

### 0. 项目坐标（先确认，不要猜）

- 根目录：`D:\5\新建文件夹\plugins\dsh-rea`（Windows，Git Bash；路径含中文，构建参数已用相对名规避 GNU ld 写坏中文路径的问题）。
- 版本：`package.json` 1.9.0；工作树有大量未提交改动。**不要** `git reset --hard`、`git checkout --`、`git clean`，也不要删 `.workbuddy`、`dist`、`.tools`。
- 当前门禁事实（你接手时应先复现，若数字不同先查清原因）：
  - `npm test` → **419 项全绿**（脚本已固定 `--test-concurrency=2`；默认无上限并发在本机会因 gcc 进程风暴偶发挂起）。
  - `npm run host-matrix` → 三模式 PASS，结构门禁 OK，`tools=237 routes=8 readOnly=157 mutating=50 destructive=4`。
  - `npm run recon -- --behavior` → R0–R4 ceiling 100.0%，loop 全部 converged；`--baseline` 另有机械下限列。
- 关键文档：`docs/reconstruction-plan.md`（§13 是实施状态、偏差、剩余任务，**先读**）、`README.md` 的「还原工程」节、`docs/duel.md`、`docs/hardening-ladder.md`。
- 关键代码：
  - `lib/recon.js`（循环状态、收敛/终态、gap、handoff、渲染）
  - `lib/recon-tools.js`（`rea_reconstruct` / `rea_compare_build` 工具面与动作）
  - `lib/compare.js`（T1/T2/T3/payload 分层、函数匹配、相似度）
  - `lib/behavior.js`（T4 声明面：输出/状态/副作用）
  - `lib/build.js` / `lib/baseline.js` / `lib/autodraft.js`（编译、机械基线、自动/模型改稿）
  - `lib/dynamic.js` / `lib/dynamic-tools.js`（Frida 探针）
  - `lib/trace.js` / `lib/trace-tools.js`（运行时轨迹）
  - `lib/memdump.js` / `lib/memdump-tools.js`（内存镜像脱壳）
  - `lib/observe.js` / `lib/observe-tools.js`（注册表/管道/服务/网络副作用）
  - `scripts/dynamic/*.py`（Frida helper：probe/dump/observe）

### 1. 先读什么、先跑什么（按顺序，别跳）

1. `git status --short`：确认改动范围，不要回滚。
2. `docs/reconstruction-plan.md` §13：已完成项、实测数字、与计划的偏差、未完成项。
3. `README.md` 的「还原工程：复刻对照循环」整节：工具面、T1–T4、动态证据、内存脱壳、副作用观测。
4. `npm test` 与 `npm run host-matrix`：复现基线。失败先修基线，不要在其上叠新功能。
5. 只跑相关测试时：`node --test test/recon.test.js test/build-compare.test.js` 等；Frida 相关测试需要 `py -3` 里有 `frida`（本机 17.26.3），`python` 里没有——`dynamicReadiness` 已按 `python` → `py -3` → `python3` 顺序探测。

### 2. 已经完成的能力（不要重做，改动要保回归）

- **分层对照**：T1 结构（导入元素级 + 节区）、T2 函数（伪代码/语义/CFG，按 RVA 或按名，阈值可配）、T3 源码字面量、payload 指标（IoC/水印，扣工具链底噪）、T4 行为契约（opt-in，输出/状态/副作用家族，逐维 recall+precision）。
- **循环状态机**：`rea_reconstruct` 的 start / advance / status / handoff / rewrite / dynamic-plan / dynamic-apply / trace-apply；预算 1–20；四终态 `converged`、`budget-exhausted`、`blocked`、`unreachable`；空测量判失败；每轮 gap 带动作与 confirm；状态落 artifacts 可续跑。
- **机械复刻**：`draft=baseline`（Ghidra 直译下限，永不宣告收敛）；`draft=auto`（读 gap 用反编译体替换不匹配函数，只保留更高分轮次，可从 `lastDraftPath` 续跑）。
- **模型内环**：`action=handoff`（gap + T2 函数 RVA/相似度，`includeCode=true` 嵌最多 3 个 Ghidra 伪代码）；`action=rewrite`（模型只提交 `{name, source}`，插件合并、编译、对照、记账）。整声明替换，修过 `int int main` 缺陷。
- **动态证据**：`dynamic-plan` 排序解码器候选（真实写入参数下标 + 循环 + 原地变换）→ `rea_dynamic_probe`（opt-in）→ `dynamic-apply`（记录证据、重开循环、补一次预算，不直接 converged）；动态值作为额外真值进入 T3/payload。
- **运行时轨迹**：`rea_trace_behavior` 双方在独立临时目录执行，比较退出码/stdout/stderr/落盘文件；TEMP/APPDATA/HOME 重定向；`trace-apply` 记录 `state.runtime`，<90% 禁止 converged，构建变化自动 stale。
- **内存镜像脱壳**：`rea_memory_dump` spawn 挂起/延迟/`waitForExec`（≥1 页可执行内存标记 **且** Stalker 观测到控制流首次进入被标记区域，报告 hit 地址+指令，未中显式 `entry: none`，观测器失效显式 `unavailable`）→ 磁盘头 + 内存节重建 image-layout PE；putty 实测 1,724,416 字节、348 imports 与磁盘一致；合成跳板样本实测 entry 命中且 dump 含 `REA_OEP_EXEC` 标记。
- **副作用观测**：`rea_side_effects` 钩注册表建键/写值/删值、命名管道、服务、IPv4 connect，事件集合 recall/precision；实测管道 + 127.0.0.1:9 被目标命中、安静重建缺失。
- **结构门禁**：host-matrix 校验模块可达、scripts 存在、13 个 confirm 映射、README 结构块；README 工具计数必须与实际一致。

### 3. 剩余任务（按优先级，一次只做一个）

**P0 — 真正的 OEP 自动发现（第一步已完成 2026-11-17）**
已完成：`rea_memory_dump waitForExec` 升级为两级证据——`oep signal`（kernel32 层首个 ≥1 页且成功返回的可执行内存标记）+ `entry`（发起标记线程上的 Stalker 观测「控制流首次进入被标记区域」，报告 hit 地址/指令/字节，未中显式 `entry: none before the timeout`，观测器失效显式 `unavailable`）。合成跳板样本（分配 RWX → 写 38 字节跳板 → 跳入 → 睡眠）实测 entry 命中且 dump 含 `REA_OEP_EXEC`；只标记不跳入的负样本显式报 none。已知盲区写进 README：watch 只覆盖标记线程、hook 只在 kernel32 层（ntdll 直调连 exec-mark 都没有）。
剩余：真实壳样本规模化验证（多线程壳、ntdll 直调壳）；仍不是内核级 OEP，别宣称能对付 VMProtect；entry 命中后是否为原始 OEP 仍由分析者判断。

**P0 — 上游宿主验证（如果有真实宿主）**
现状：`gapsFromComparison(result, { availableTools })` 会在宿主广告 `verify_reconstruction` / `evaluate_reconstruction_coverage` 时给出 `also:` 备选路径；只有 gap 级与工具级单测，没有真实宿主。
目标：在有上游 REA 服务、且确实广告这两个工具的机器上跑一次完整 `advance`，确认 `also:` 出现、调用可用；把结果写进 §13。
验收：真实宿主截图/日志（工具名 + 输出），失败则记录具体错误，不修改本地评分逻辑。
如果没有这样的宿主：保持现状，不要伪造验证。

**P1 — 运行时观察扩展**
现状：`rea_side_effects` 只覆盖用户态 API 的注册表/管道/服务/IPv4；直接系统调用、动态解析 API、内核驱动、IPv6/域名不可见。
目标（选一个做透）：a) 增加 IPv6 与域名解析观测；b) 增加 ETW 或内核回调路径；c) 记录注册表句柄的完整路径（当前只映射本次 run 内 open/create 的句柄）。
验收：新维度有正负对照测试（目标有、重建无 → 扣分），报告 limitations 同步更新，不把未观测写成「没有发生」。

**P1 — 真实样本规模化与 T2 分母**
现状：putty 复测 `appears-unpacked`，基线 9.0%（24/2710 函数、2 译 22 桩）；T2 在真实样本上把大量 CRT/运行库函数计入分母，重建体天然对不上，分数偏低。
目标：评估「用工具链空程序/全桩基线的函数名集合从 T2 分母扣除」是否可行；若可行，给出打分前后对比、对 R0–R4 的影响、文档与门禁更新；若不可行，把原因写进 §13。
验收：`npm run recon -- --engine` 的 R 阶梯不回归；真实样本分数变化有解释；不改变「函数无对应计零」的原则。

**P2 — 自动改稿的批量回退**
现状：`draft=auto` 一轮替换全部 mismatches，靠 best 保护；批量替换可能伤到好草稿，但下一轮仍从受伤草稿继续。
目标：批次导致分数下降时，回退到上一份草稿并只替换相似度最低的一个函数重试（有界，最多 1 次额外编译）。
验收：单测覆盖「批次下降 → 单函数重试」；不增加无界编译；`rounds` 语义不变。

**P2 — 发布收尾**
版本号、CHANGELOG、README 数字、`docs/reconstruction-plan.md` 的「下一步」、`dist/host-matrix.json` 一致；`npm run structure` 后 `host-matrix` 必须 PASS。

### 4. 工程约束（违反会直接失败）

- **测试**：`npm test` 必须全绿；新增功能必须带测试。测试会真实编译 C（gcc 16.2.0，托管在 `.tools`）、真实执行 Frida（在 `py -3`），不要在网络/CPU 受限环境跑全量；至少跑相关文件。
- **工具计数**：新增工具会让 `tools=237` 变化。README 有多处「237 个工具 / 237 工具 + 8 路由」，必须同步；`npm run host-matrix` 会校验，不过就是文档漂移。同款提醒：README「出站通道审计与本地化模式」一节的通道清单是**逐项入档**的审计结论，新增出站调用（新的 URL/主机/请求头）必须同步该表与 `test/localized-mode.test.js` 的头断言；`localizedMode` 本身不新增工具（2026-11-20 落地时 `tools=237` 不变）。
- **结构块**：README 的代码结构节由 `npm run structure` 生成，手改会被 host-matrix 判 stale。新增 `lib/*.js` 后必须重跑。
- **模块可达**：每个 `lib` 模块必须有消费者（index/client/scripts/其他 lib），否则结构门禁失败。
- **plan confirm 映射**：新增 gap 的 `confirm` 必须是真实注册的工具，或显式 `blocked`；host-matrix 校验 13 个映射。
- **路径与守卫**：自有工具统一走 `ownGuard`；新增工具必须能通过 `allowedTargets` 作用域测试（参考 host-matrix 对 `rea_compare_build` / `rea_reconstruct` 的检查）。
- **执行门禁**：任何执行样本的路径必须 `allowSampleExecution: true` + 每次 `confirm: true`；工具描述必须写「会真的执行、无沙箱」。没有授权时只读字节。
- **非 ASCII 路径**：编译参数用相对名（cwd 为工作目录），不要改回绝对路径；否则 GNU ld 会写坏中文路径。
- **并发**：`package.json` 的 `test` 脚本保持 `--test-concurrency=2`；不要改回默认无上限。

### 5. 诚实边界（这个项目的生命线）

1. 空测量是失败，不是 100%；blocked 的层不许算满分，也不许静默丢弃。
2. 不编造：不把目标不存在的导入/字面量/行为写进源码来让某层通过；precision 会扣，且会毁掉复刻可信度。
3. 不宣称字节一致：等价源码经不同编译器必然不同；「一致」只指 T1–T4/payload/运行时分层一致。
4. 拿到动态 dump 不等于收敛：必须再写稿、再对照。
5. 真实样本没有源码真值：只报函数级相似度与残差，不说「还原了 putty/7zr」。
6. 未观测不等于不存在：注册表/网络盲区必须写在报告里。
7. 不执行未授权样本、不连接样本端点、不外传样本。

### 6. 工作方式

1. 一次只领一个任务；先复现基线（测试 + host-matrix），再改代码。
2. 改前先读相关模块与测试，找出现有模式（子进程超时杀进程树、输出上限、串行闸、`markUntrusted` 包裹样本数据）。
3. 小步修改；每步跑相关测试；不要顺手重构无关模块。
4. 新增能力必须同时更新：实现 + 测试 + 工具描述 + README/`docs/reconstruction-plan.md` + 计数/结构门禁。
5. 交付时给出：改了什么文件、为什么、测试结果、门禁结果、仍未解决的残差。
6. 不确定就先读代码/文档/跑测量，不要猜；需要用户决策时给出选项与代价。

### 7. 禁止事项

- 禁止 `git reset --hard` / `git checkout --` / `git clean -fd` / 删除 `.workbuddy`、`dist`、`.tools`。
- 禁止把测试改成跳过以“变绿”；skip 只能用于环境缺失（无 gcc/Frida）且要说明。
- 禁止在没有真实宿主时声称上游接线已验证。
- 禁止为了分数把目标字面量塞进源码、或把 blocked 层从权重里悄悄去掉。
- 禁止新增一个没有消费者、没有测试、没有 host-matrix 计数的工具。
- 禁止把「启发式」写成「自动 OEP」；把「声明面」写成「运行时行为」。

### 8. 交付格式（每次回复）

1. 任务与结论（一句话）。
2. 改动文件清单（路径 + 作用）。
3. 验证：`npm test` / 相关测试 / `host-matrix` / `recon` 的实际数字。
4. 未完成与风险（明确写，不藏）。
5. 下一个建议任务（一个，具体到文件/函数）。

先跑基线，再从 P0 里选一个。没有测量结果的“改进”不算改进。

---

## 使用说明

- 这段提示词假设接手者能读写本机文件、运行 npm/node/python；如果对方是纯对话 Agent，把「工程约束」和「交付格式」保留，删掉需要执行的部分。
- 如果只想让接手者做某一项，把「剩余任务」里其他项删掉，只留目标项与验收，避免它扩大范围。
- 每次交接前建议先跑一遍 `npm test` 与 `npm run host-matrix`，把实际数字填进第 0 节，避免它按过期数字判断。
