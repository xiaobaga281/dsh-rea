# 检测面矩阵（静默姿态：目标侧能观测到什么）

> 状态：2026-11-20 初版（C 轮沙箱修复合入后的树）。本文档回答一个问题：**对每条目标执行/观测路径，目标一侧（或其反逆向机制）原则上能察觉到什么**。它不是能力宣传，而是能力边界入档：每格标注证据等级，未实测的机制推断如实标注，不冒充已验证。
>
> 视角边界：「目标侧检测面」指目标进程（或目标内的反逆向检查）能感知的信号。宿主侧的进程/文件访问（JVM、UPX、python/Frida、powershell）对 EDR 与宿主审计可见，那是另一张表——见 DS-5，不属于本矩阵各列。
>
> 措辞纪律：本文档不使用绝对化宣称（「任何」「保证」「全部」「不惊动任何」「undetectable」）。每条结论限定在已声明的机制与已实测的范围内；`test/detection-surface.test.js` 的措辞 lint 钉住这一点。

证据等级：

- **[代码]**：本会话读到的代码事实，`file:line` 可复核。
- **[实测引用]**：plan/README/test 已记录的本机实测（含 `test/sandbox.test.js` 2026-11-20 的沙箱矩阵），本文档引用其记录，不重复测量。
- **[分析，未实测]**：机制推断，本轮没有用带对应反逆向检查的样本验证过。

## 静态优先与门禁（默认值现状）

四条执行路径（DS-1/DS-2/DS-3/DS-4 的工具入口）默认全关：`allowSampleExecution` 默认 false [代码 lib/infra/config.js:115] 且每次调用还需 `confirm: true` [代码 lib/surface/trace-tools.js:80-82 等]；沙箱层再叠一道独立门禁 `sandboxSampleExecution` 默认 false [代码 lib/infra/config.js:120]，不因前者隐式开启 [代码 lib/surface/trace-tools.js:107-110]。宿主保护默认开、可关：`blockSampleEgress` 默认 true [代码 lib/infra/config.js:125]、`redactIdentity`/身份遮蔽默认 true [代码 lib/infra/config.js:126]。

因此**默认安装下，本插件不执行目标**：triage / intel / structure / strings / behavior 声明面 / interaction / hypothesis-check / compare / reconstruct 只在进程内读字节 [代码 lib/surface/recon-tools.js:144（工具自述 "Read-only: both binaries are read, never executed"）]。

## 基线行：目标零执行 = 目标侧零检测面

矩阵第一行，三种形态。目标进程不存在，目标内的反逆向检查（反调试、反注入、自校验）无从谈起——五列均为「不可观测（目标未运行）」：

1. **本地静态层**（triage / intel / structure / strings / behavior 声明面 / interaction / hypothesis-check 本地通道 / compare / reconstruct）：插件进程内读字节。[代码 lib/surface/recon-tools.js:144]
2. **Ghidra 引擎档**（`rea_compare_build` / `rea_reconstruct` 的 T2，engine 默认开 [代码 lib/surface/recon-tools.js:220/:743]）：子进程是 JVM 而非目标 [代码 lib/restore/ghidra-local.js:107-144（run 拉起的是 headless 分析器）]；目标文件仅被 `-import` 读入 Ghidra 自有 project [代码 lib/restore/ghidra-local.js:226/:234]，project 缓存按目标内容 SHA-256 + 脚本版本 + 页大小/证据上限/预算建 [代码 lib/restore/ghidra-local.js:218-224]，不修改目标文件 → 目标侧零。
3. **rea_unpack**（upx -d，[代码 lib/dynamic/unpack.js:86]）：`-o output` 写新文件，源文件字节不变 → 目标零执行、样本自校验基线不受影响 → 目标侧零。

边界注记：「零检测面」限定**目标进程视角**。宿主侧 JVM/UPX/python 进程与文件访问对 EDR 等第三方可见（DS-5），不属本矩阵各列。

## 动态路径行（六列）

六列：**目标进程存在 / 被注入 / 被调试通道 / 环境异样 / 令牌特殊 / 行为差异（自校验能否察觉）**。

### 总览

| 行 | 进程存在 | 被注入 | 被调试通道 | 环境异样 | 令牌特殊 | 行为差异 |
| --- | --- | --- | --- | --- | --- | --- |
| DS-1 `rea_trace_behavior`（裸 spawn） | 是 | 否 | 不触发（[分析，未实测]） | 是（env 遮蔽 + profile 重定向 + Win32 直询矛盾） | 否（宿主普通令牌） | pid 改写只影响我方读到的文本 |
| DS-1' 同上 `sandbox=true` | 是 | 否 | 不触发（[分析，未实测]） | 是（同 DS-1 + 可选专用 desktop） | **是**（AppContainer） | **是**（内核网络拒绝） |
| DS-2 `rea_dynamic_probe` | 是 | **是**（Frida agent） | 不触发（[分析，未实测]） | 裸 spawn 路径无遮蔽 | 否 | hook 补丁字节可被自校验察觉 |
| DS-3 `rea_memory_dump` | 是 | **是**（Frida agent） | 不触发（[分析，未实测]） | 裸 spawn 路径无遮蔽 | 否 | hook + Stalker 可被自校验/时序察觉；已实测退出死锁 |
| DS-4 `rea_side_effects` | 是 | **是**（Frida agent） | 不触发（[分析，未实测]） | 裸 spawn 路径无遮蔽 | 否 | 导出地址补丁可被自校验察觉；block-egress 改变 connect 结果 |

### DS-1 rea_trace_behavior（默认裸 spawn，sandbox=false）

门禁：`allowSampleExecution` [代码 lib/infra/config.js:115] + 每次 `confirm: true` [代码 lib/surface/trace-tools.js:80-82]。

- **目标进程存在 = 是**：node spawn 真实启动目标；stdin 关闭、stdout/stderr 管道、windowsHide [代码 lib/dynamic/trace.js:236-238]。
- **被注入 = 否**：无 agent 进入目标 [分析]。
- **被调试通道 = 不附加调试器**：`IsDebuggerPresent` / `ProcessDebugPort` / `ProcessDebugObjectHandle` 从 OS 视角不被触发 [分析，未实测——本轮没有用带反调试检查的样本验证]。
- **环境异样 = 是，且部分可被样本察觉**：
  - getenv 级身份遮蔽：`COMPUTERNAME=rea-sandbox` / `USERNAME=analyst` / `USERDOMAIN=REAGROUP`（win32）[代码 lib/dynamic/trace.js:107-119]，置于 env 合并链末位、caller env 不能旁路 [代码 lib/dynamic/trace.js:233-236]；
  - TEMP/APPDATA/HOME 重定向进运行目录 [代码 lib/dynamic/trace.js:209-227]；
  - **可察觉矛盾（如实声明）**：遮蔽只覆盖 getenv 类读取，`GetComputerNameW`/`GetUserNameW` 等 Win32 直询仍返回真实值——getenv 与 Win32 不一致本身就是异常信号 [代码 lib/dynamic/trace.js:104-105 与 :386-387]；
  - 全新临时工作目录（每次运行 `mkdtemp` 级新目录）[代码 lib/surface/trace-tools.js:112-115]。
- **令牌特殊 = 否**：宿主普通令牌 [分析]。
- **行为差异**：输出里的目标 pid 被改写为 `[PID]` [代码 lib/dynamic/trace.js:289-292]——只影响我方读到的文本，目标自身行为不变；除上述环境值外无附加行为差异 [分析]。

### DS-1' rea_trace_behavior（sandbox=true，经 scripts/runtime/rea-sandbox.ps1）

门禁：在 DS-1 之上另需 `sandboxSampleExecution` [代码 lib/infra/config.js:120；门禁 lib/surface/trace-tools.js:107-110]。

- **目标进程存在 = 是**：挂起创建、先入 Job 再恢复 [代码 scripts/runtime/rea-sandbox.ps1:493（CREATE_SUSPENDED）与 :528/:539（AssignProcessToJobObject 先于 ResumeThread）]。
- **被注入 = 否**：无 Frida agent [分析]。
- **被调试通道 = 不触发**：同 DS-1 [分析，未实测]。
- **环境异样 = 是**：launcher 侧同 DS-1 的 env 遮蔽 [代码 scripts/runtime/rea-sandbox.ps1:257-263] + profile 重定向 [代码 scripts/runtime/rea-sandbox.ps1:254-256]；`-Desktop` 时另加专用 desktop [代码 scripts/runtime/rea-sandbox.ps1:414]，`GetThreadDesktop` 类检查可察觉差异 [分析，未实测]。
- **令牌特殊 = 是**：无能力 AppContainer——`NtCreateLowBoxToken` 显式建令牌 [代码 scripts/runtime/rea-sandbox.ps1:481]；实测子进程报 `TokenIsAppContainer=1`、完整性级别 0x1000 (Low) [实测引用 test/sandbox.test.js「a sample runs to completion」断言 `token is-app-container=1` / `integrity-rid=0x1000`]。宿主普通令牌看不到这一切换，`IsProcessInJob` 成员在 job 内成立 [实测引用 test/sandbox.test.js job 树测试]。
- **Job（2026-11-20 修复后状态）**：`KILL_ON_JOB_CLOSE` 现已实际赋值生效 [代码 scripts/runtime/rea-sandbox.ps1:445]；launcher 退出前若 job 内仍有孤儿孙进程先终止整个 job 并打 diag 标记 [代码 scripts/runtime/rea-sandbox.ps1:563-568]；**外杀 launcher（taskkill 仅杀 launcher、不带 /T）实测 job 内样本在 5s 断言窗口内被内核回收** [实测引用 test/sandbox.test.js「killing the launcher externally」2026-11-20，整测 2.3s]。禁 breakaway 成立：`CREATE_BREAKAWAY_FROM_JOB` 实测被拒 err=5 [实测引用 test/sandbox.test.js job 树测试]。勘误注记：2026-11-19 的「外杀 launcher 时 KILL_ON_JOB_CLOSE 不可靠」记录归因有误——`LimitFlags` 此前从未赋值，被测量的机制根本没有启用（launcher 缺陷而非 OS 行为）；修复前复现实测孤儿 leaf 在 launcher 退出后存活至自身心跳结束、修复后 5s 内回收 [实测引用 test/sandbox.test.js orphan 测试红→绿记录，plan §13 条目 11]。
- **行为差异 = 是（内核级）**：非回环 connect 得 `WSAEACCES 10013`（0ms）[实测引用 test/sandbox.test.js kernel deny 测试]；回环默认亦拒（CheckNetIsolation 豁免需管理员，实测 err=5）[实测引用 同测试]；UDP sendto 不被拦（已声明盲区）。**方向性结论（显式入档）**：sandbox 对「静默」是**更显眼**而非更隐蔽——令牌、网络、桌面都是硬异常；它的价值是宿主防护（containment），与目标侧可观测性是两个正交维度，不得混写。

### DS-2 rea_dynamic_probe

链路：lib/surface/dynamic-tools.js → lib/dynamic/dynamic.js → scripts/dynamic/probe.py。门禁同 DS-1（[代码 lib/surface/dynamic-tools.js:43-48]）。

- **目标进程存在 = 是**。
- **被注入 = 是**：spawn 模式（默认）由 Frida `device.spawn` 挂起创建并注入 agent [代码 scripts/dynamic/probe.py:137-142]。Frida 注入本身会把 ws2_32.dll 与 dnsapi.dll 带进每个被注入进程 [实测引用 docs/reconstruction-plan.md §13 副作用观测扩量节（36 模块中二者 present）]——反注入扫描（模块枚举 / 模块计数差）可察觉 [分析]。
- **被调试通道 = 不触发**：Frida 不走 Windows 调试 API，`IsDebuggerPresent`/`ProcessDebugPort` 从 OS 视角不触发 [分析，未实测]。
- **环境异样 = 裸 spawn 路径无遮蔽**：`lib/dynamic/dynamic.js` 的 spawn 仅传 windowsHide/stdio，无 IDENTITY_MASK 处理、无 profile 重定向 [代码 lib/dynamic/dynamic.js:117-126]——与 DS-1 不一致，列为后续能力改动单独评估（若实施必须双侧同值 [代码 lib/dynamic/trace.js:233-236 注释即此模式]，否则对照不公平）。本轮未改动。
- **令牌特殊 = 否**（非沙箱）[分析]；`sandbox=true` 时同 DS-1' + 按 pid attach [代码 lib/dynamic/dynamic.js:103-115]。
- **行为差异**：hook 目标 RVA 的 `Interceptor.attach` 补丁函数前几条指令 [代码 scripts/dynamic/probe.py:98]——带 .text/导出自校验的样本可察觉补丁 [分析]。

### DS-3 rea_memory_dump

链路：lib/surface/memdump-tools.js → lib/dynamic/memdump.js → scripts/dynamic/dump.py。门禁同 DS-1（[代码 lib/surface/memdump-tools.js:72-77]）。

- **目标进程存在 = 是**；**被注入 = 是**：同 DS-2 注入面 [代码 lib/dynamic/memdump.js:183-186 → dump.py]。
- **被调试通道 = 不触发**：同 DS-2 [分析，未实测]。
- **环境异样 = 裸 spawn 路径无遮蔽**：[代码 lib/dynamic/memdump.js:183-186]（同 DS-2 的后续项处置）。
- **令牌特殊 = 否**；`sandbox=true` 时 launchSandboxed 挂起创建 + 按 pid attach [代码 lib/dynamic/memdump.js:169-180]。
- **行为差异 = 是，多重**：
  - 额外 hook **两层**：`kernel32!VirtualProtect`/`VirtualAlloc` 与 `ntdll!NtAllocateVirtualMemory`/`NtProtectVirtualMemory`（W2，2026-11-20 起——直调 ntdll 导出的壳的 EXECUTE 标记由此可见；returnAddress 来源归因使 kernel32/kernelbase 调用方仍由 kernel32 层记账（kind 保持 `VirtualAlloc`/`VirtualProtect`），真直调者才记 `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`（layer=ntdll），重复触发只发记录性 `exec-mark-duplicate`）[代码 scripts/dynamic/dump.py:411-460（双层钩子）、:189-211（包装层归因）、:378-409（note 双闸过滤 + 先到先得）]——自校验 / 内联 hook 扫描可察觉 [分析]；
  - `waitForExec=true` 时 Stalker **进程级**重写被跟踪线程执行的代码（块首跳板）：mark 时刻存活的所有线程，加之后经 `ntdll!NtCreateThreadEx` 新建的线程（onLeave 按起始地址过滤 frida 系模块、上限 16、首次命中即逐个 unfollow 退出）[代码 scripts/dynamic/dump.py:334-350（armWatch）、:185-222（followThread/followAllThreads/unfollowAll）、:244-268（NtCreateThreadEx 钩子）、lib/dynamic/memdump.js:15]——插桩代码范围与时序扰动随线程数上升，可被自校验/时序检查察觉 [分析]；frida 系模块范围在首次 follow 之前已 `Stalker.exclude`，agent 自身代码不进插桩面、其匿名页分配（trampoline slab / code cache）由调用方范围表归因排除 [代码 scripts/dynamic/dump.py:162-182]；**声明盲区（W1，如实入档）**：mark 与新建线程 onLeave 之间的竞态窗口、硬编码 syscall 建线程（不经该导出）、超上限后 coverage 记 `partial` [代码 scripts/dynamic/dump.py:223-238、:363]；
  - **已实测同族失效**：`kernel32!VirtualAlloc` hook 存在时样本退出路径死锁、进程不退出（Frida 17.26.3 层、插件不可修，39 轮 A/B 定位）[实测引用 README.md 已知边界与 docs/reconstruction-plan.md §13 T3 定位节]——对目标侧表现为「进程该退不退」。注意区分：该现象与沙箱孤儿孙进程（C 轮修复对象）机制不同，数字巧合勿混。

### DS-4 rea_side_effects

链路：lib/surface/observe-tools.js → lib/dynamic/observe.js → scripts/dynamic/observe.py。门禁同 DS-1（[代码 lib/surface/observe-tools.js:66-70]）。

- **目标进程存在 = 是**；**被注入 = 是**：同 DS-2 注入面 [代码 scripts/dynamic/observe.py:457-458 device.spawn；observe.py:449 attach 模式]。
- **被调试通道 = 不触发**：同 DS-2 [分析，未实测]。
- **环境异样 = 裸 spawn 路径无遮蔽**：python helper 以普通 spawn 启动、无 env 处理 [代码 lib/dynamic/observe.js:65-69]（同 DS-2 的后续项处置）。
- **令牌特殊 = 否**；`sandbox=true` 时同 DS-1'（容器内实测钩子正常触发 [实测引用 CHANGELOG 沙箱接入轮]）。
- **行为差异 = 是**：
  - hook 集全打在**导出地址**：注册表 W/A 8 个导出 + `CreateNamedPipeW` + `CreateServiceW` [代码 scripts/dynamic/observe.py:400-411]、`connect`/`WSAConnect`/`getaddrinfo` 族/`DnsQuery_W` [代码 scripts/dynamic/observe.py:287-294]；模块头自述「`Interceptor.attach` patches the export address itself」[代码 scripts/dynamic/observe.py:51]——经 `GetProcAddress`/IAT 的调用同样可见（实测函数指针 connect 照常出现 [实测引用 plan §13]），带导出自校验的样本可察觉补丁 [代码+分析]；
  - **block-egress（默认开）**：`blockEgress` 默认 true [代码 lib/dynamic/observe.js:54]，`blockSampleEgress` 默认 true [代码 lib/infra/config.js:125]；onEnter 把非回环 sockaddr 族值改写为 0xFFFF，connect 以 `WSAEAFNOSUPPORT` 在真实发包前同步失败 [代码 scripts/dynamic/observe.py:260-268]——样本看到 connect 失败且错误码异常；沙箱路径则是内核 `WSAEACCES` [实测引用]。宿主防护同时是样本可感知的行为改变，双写入档；双方同开关运行，故不构成 A/B 行为差异（报告注明）[代码 lib/dynamic/observe.js:211]。
- **盲区（非检测面但同表声明）**：首条 connect 族调用后观察器进程内全局静默 [实测引用 scripts/dynamic/observe.py:46-53]；直系统调用（绕过 ntdll）、raw socket、DoH/DoT、QUIC、UDP sendto、ConnectEx、样本自行启动的子进程不可见 [代码 lib/dynamic/observe.js:209]。

### DS-5 宿主侧痕迹行（防混淆单列）

目标进程视角之外。**目标侧反逆向机制看不见这些**（目标未运行，或进程内无此类痕迹），但宿主 EDR / 审计可见：

- sandbox 启动链：powershell.exe 进程、icacls（workdir 完整性级别）[代码 scripts/runtime/rea-sandbox.ps1 SetLowIntegrity 经 icacls.exe /setintegritylevel]、CheckNetIsolation LoopbackExempt 尝试 [代码 scripts/runtime/rea-sandbox.ps1:331]、CreateAppContainerProfile [代码 scripts/runtime/rea-sandbox.ps1:364/:368] / DeleteAppContainerProfile [代码 scripts/runtime/rea-sandbox.ps1:367/:580]、专用 desktop 创建 [代码 scripts/runtime/rea-sandbox.ps1:414]。
- 引擎与工具链：Ghidra JVM（`-import` 读入自有 project）、upx、python/Frida 进程 [代码 lib/restore/ghidra-local.js:107-144、lib/dynamic/unpack.js:86、lib/dynamic/dynamic.js:117-126]。
- 四条执行路径的 Frida 注入对宿主可见（python 进程 + 目标进程内 agent 线程）[分析]。

## 已声明盲区（固定尾注，照抄既有声明，不新造）

- lib/dynamic/sandbox.js 头注 Not covered 原文：内核驱动、侧信道、容器内提权、通过 DACL 已对容器放行的对象进行的 IPC [代码 lib/dynamic/sandbox.js:42-45]；UDP sendto 不被本 build 的 AppContainer 网络隔离拦截（实测），TCP/经 connect 的 DNS 被拦 [实测引用 lib/dynamic/sandbox.js 头注 + test/sandbox.test.js]。
- VMProtect 类强壳/虚拟化壳：不在宣称范围内。多线程壳的「标记线程≠执行线程」entry 漏报已由进程级 Stalker watch 覆盖（W1，2026-11-20：mark 时刻存活的各线程 + 之后新建线程，上限 16）[代码 scripts/dynamic/dump.py:360-376]；壳直调 `ntdll!NtProtectVirtualMemory`/`NtAllocateVirtualMemory` 的 exec-mark 盲区已由 ntdll 导出层钩子覆盖（W2，2026-11-20，直调夹具实测红→绿）[代码 scripts/dynamic/dump.py:427-460]；**仍属盲区（如实声明）**：纯 shellcode 直统调用（`syscall` 指令不经过 ntdll 导出）对两层钩子都不可见；mark 与新建线程 onLeave 之间的竞态窗口；硬编码 syscall 建线程；超上限后 coverage=partial。
- trace 身份遮蔽仅 getenv 级，`GetComputerNameW`/`GetUserNameW` 等 Win32 直询仍返回真实身份 [代码 lib/dynamic/trace.js:386-387]。
- 观察器首条 connect 族调用后进程内全局静默 [实测引用 scripts/dynamic/observe.py:46-53]。
- IPC DACL 例外、回环豁免需管理员、container 内提权不覆盖 [代码 lib/dynamic/sandbox.js 盲区清单]。

## 能力边界与已声明盲区

**本插件不做主动规避反逆向/反调试机制的工具**：隐藏调试器、patch 目标的反调试检查、绕过授权/DRM 属于绕过保护措施，不在本插件能力范围内。「静默」在本插件里的实现方式 = **静态优先 + 最小侵入 + 检测面如实入档**，不是对目标反逆向机制的对抗——本文档就是把检测面摊开给分析者看，而不是把检测面藏起来。

仍属盲区、本文档不宣称覆盖：内核驱动与内核级观测、侧信道、容器内提权、VMProtect 类强壳/虚拟化壳。上文所有「不触发」格均为机制分析（[分析，未实测]），如需对带反调试检查的样本出结论，须用此类样本实测后更新本表。

数字与措辞由 `test/detection-surface.test.js` 钉住（矩阵行存在性、file:line 引用、绝对化措辞 lint、四个策略开关默认值）；工具计数（tools=237）由 `npm run host-matrix` 的 README claims 门禁钉住。
