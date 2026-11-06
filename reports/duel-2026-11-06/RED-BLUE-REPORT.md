# dsh-rea 1.8.10 双人格对抗测试报告

> 测试时间：2026-11-06 · 主机：Windows（DESKTOP-0Q1029R）· Node 24.15 · REA 6.7.0 · Ghidra 12.1.4 / JDK 21
> 被测对象：`D:\5\新建文件夹\plugins\dsh-rea`（插件 1.8.10，22 个注册工具）
> 方法：红军（攻击方）只负责造样本、选通道、埋诱饵；蓝军（防守方）只拿到一个文件路径，用插件真实注册的工具作答；裁判用独立 ground truth 逐条对账。

---

## 0. 结论摘要

**蓝军强在"把打包进去的字面量挖出来"，弱在"标准编码的覆盖面"和"IOC 分类学的完整度"。**

> **2026-11-06 更新：第一轮 P1–P6、P8–P12 修复并回归（325/325）；第二轮补上 P7，并新增内嵌 PE、指令级反分析、空格 hex、base32、JWT/SSH（331/331）；第三轮修复分析器 DoS（8 MB 的 MZ 文件从 848,720 ms 降到 3,129 ms）、XOR(UTF-16LE)、hex 容器下钻、ws/tcp/UNC/host:port、.NET 识别（336/336）。详见 §12–§14。**

- 插件自带靶场（D0–D10）在产物目录可写时 **满分 100%**，11 代全部 4/4–5/5 endpoint、9/9 API、6/6 行为、honesty 全部通过，`verify` 由 Ghidra 命名到 `tls_callback_0`；**316/316 单元测试通过**。
- 但同一套靶场在受限 shell 里跑出了 **"空心 100%"**：产物目录不可写 → `rea_ioc_extract` 整体失败 → D0 天花板是 0 条 → `0/0` 被算成 100%，评分器没有任何断言。**这是本次最严重的缺陷（P1）**：CI 里会得到绿色假象。
- 独立红军样本打穿了 4 条通道与 6 类 IOC：**hex 编码、JSON `\u` 转义、DWORD 形式的 IPv4、gzip 容器**全部漏检（gzip 还被误报为"运行时派生密钥的加密区"）；**Telegram bot token、mutex、IPv6、defanged 域名、bech32 BTC、AWS 密钥**不在分类学里。
- 反分析矩阵在**干净的微软签名二进制 `whoami.exe` 上误报 TLS 回调**（证据只有字符串 "TLS"），而同一次 `rea_triage` 的结构行写着"TLS callbacks 0"——两个工具互相矛盾，报告没有交叉校验。
- **Ghidra 并发不安全**：两次并行场景（probe+decompile、probe+probe，均冷启动）各有一个调用因项目锁失败；代码里五个分析工具都声明 `isConcurrencySafe: () => true`。

独立评分（红军口径，S1 复合样本）：

| 维度 | 结果 |
| --- | --- |
| 隐藏通道召回 | 5/11 命中（明文叠加、zlib、b64(zlib)、单字节 XOR、UTF-16BE），2 条拆分只拿到碎片，4 条未命中（hex、`\u`、DWORD、gzip）；水印单列命中 |
| 诱饵抗性 | 失败：良性诱饵 `microsoft.com` 被写进 behaviour 的"reports to a remote endpoint" |
| 反分析准确率 | 3 族真命中（timing/vm/hook）/ 1 族误报（TLS） |
| 水印识别 | 命中（`orbit-7f3a91c2d8e4`） |
| 引擎能力 | 通过（Ghidra 冷启动 57.8s，缓存 8.5s，符号 `entry` 正确） |
| 边界安全 | 通过（空文件/1 字节/截断/目录/不存在/穿越路径/只读/Unicode/空格 全部安全拒绝或降级） |

---

## 1. 双人格设定与测试环境

| 角色 | 职责 | 约束 |
| --- | --- | --- |
| 红军（攻击方） | 生成样本：真实签名 PE + 叠加区载荷；逐通道对照实验；IOC 分类学清单；畸形/恶意输入 | 只用文件字节，不读插件源码来决定"藏哪里" |
| 蓝军（防守方） | 只拿路径，调用 `rea_triage / ioc_extract / tracking_surface / anti_analysis / analyst_exposure / diff_hint / batch_triage / probe_address / decompile_address / export_report / sanitize_report ...` | 不看红军脚本，结论全部来自工具输出 |
| 裁判 | 独立 ground truth + 手工逐条比对；对蓝军的"找不到"和"找错了"分别计分 | 不只信插件自评 |

环境备注：本机 DSH 沙箱最初连工作区写权限都拿不到（`SetNamedSecurityInfoW Win32 5`），用 ACL 诊断脚本修好 `WRITE_OWNER` 后命令行可读、但**仍不可写工作区**；需要写用户目录 `~/.dsh` 的两组测试（单元测试、靶场）因而用一次完全权限运行。插件工具本身由宿主进程执行，产物写入 `~/.dsh/rea-artifacts` 正常。

---

## 2. 第 0 轮：基线（插件自证）

```
rea_doctor : healthy, 207/207 tools, 6/6 prompts, catalog digest 一致
rea_status : jdk ok / ghidra ok / jadx apktool wabt rizin missing
node --test: tests 316  pass 316  fail 0  (5.99s)
npm run duel: 11 代全部 100%，honesty failures: none
```

内置靶场（产物目录可写时）关键行：

```
ceiling from D0: 5 endpoints, 6 indicators, 15 tracking families, 8 anti markers, 1 watermarks
D0  5/5 6/6 15/15 8/8 1/1   api 9/9  behav 6/6  precision 100.0%  100.0%
D6  4/4 5/5 15/15 8/8 0/0   api 9/9  behav 6/6  plan yes  verify tls_callback_0  100.0%
D10 4/4 5/5 15/15 8/8 0/0   api 9/9  behav 6/6  plan yes  verify tls_callback_0  100.0%
mean 100.0%  weakest D1  honesty failures: none
```

**这一轮蓝军全胜。** 但同一命令在受限 shell 下（`dist/` 不可写、`~/.dsh` 不可写）输出了下面这份"全绿"：

```
ceiling from D0: 0 endpoints, 0 indicators, 0 tracking families, 8 anti markers, 1 watermarks
D1..D10  endpoints 0/0  indicators 0/0  tracking 0/0 ... score 100.0%
honesty failures: D5, D6, D7, D8, D9, D10
```

`duel.json` 里 D0 行 `ok:false`，错误是 `EPERM: mkdir 'C:\Users\25616\.dsh\rea-artifacts\...'`——IOC 工具整体失败，天花板变空，而评分器照样给 100%。**这是"测试通过但什么都没测到"的典型**，也是我把它列为 P1 的原因。

---

## 3. 第 1 轮：通道矩阵（红军逐通道对照）

同一份 JSON 配置（C2、备用 IP、Telegram token、BTC、邮箱、注册表、PDB、mutex、水印）用 13 种方式埋进**真实签名的 `whoami.exe` 叠加区**，每种一个文件，蓝军只看文件：

| 通道 | 文件 | 蓝军结果 | 判定 |
| --- | --- | --- | --- |
| 明文 JSON 叠加 | P0 | URL/IP/邮箱/域名/注册表/BTC/PDB 全中 | ✅ |
| zlib 流 | P1 | 8 条解码全中（`[zlib>ascii]`） | ✅ |
| base64(zlib(JSON)) | P2 | 全中，另有 1 条 delta 垃圾 `B:\')f,J%R` | ✅（含 1 FP） |
| 单字节 XOR 0x5A | P3 | 全中（`[xor-0x5a>salvage]`） | ✅ |
| UTF-16BE | P5 | URL/域名命中（有一条截断重复 `...pol`） | ✅ |
| reversed | P9 | 未单独跑（与 zlib/XOR 同梯） | — |
| **hex 编码 URL** | P4 | **0 条** | ❌ |
| **JSON `\uXXXX` 转义** | P7 | **0 条** | ❌ |
| **DWORD 形式 IPv4**（0xCB00714D=203.0.113.77） | P6 | 只报 `5.1.0.0`，真 IP 丢失；拆分域名报成两段 | ❌ |
| **gzip 流** | P10 | **0 条**，并输出"unresolved encrypted region(s): 1 (353 bytes at 0x18000)…key is probably derived at run time" | ❌ + 误判 |
| NUL 拆分 URL | P8 | 报成 `https://cdn-sync.example` + 独立域名 `corp.net`，未拼回 | ⚠️ 部分 |
| 两段式拆分 URL | P12 | 报成 `https://cdn-sync` + `example-corp.net`，未拼回 | ⚠️ 部分 |

**结论：解码阶梯对"它自己设计过的容器"很强，对"业界标准但没排进队"的编码几乎为零。** hex 与 gzip 是恶意软件配置里最常见的两种外层；`\u` 转义在 JS/Electron 系载荷里同样常见。gzip 那条更糟：不是沉默，而是**给了错误解释**（"加密区、密钥运行时派生"），分析师会照着去挂调试器。

---

## 4. 第 2 轮：复合样本 S1（真实签名 PE + 叠加区混合载荷）

`S1-composite.exe` = `whoami.exe` + 654 字节叠加区，同时包含：

- 明文诱饵 `https://www.microsoft.com/en-us/security`
- hex 编码 C2、`\u` 转义 C2、UTF-16LE C2
- DWORD IP、Telegram token、mutex、水印 `orbit-7f3a91c2d8e4`
- 追踪标记（FirebaseAnalytics/AppsFlyer/getLastKnownLocation/AdvertisingIdClient）
- 反分析标记（VMware/VBox/SbieDll/frida）

蓝军输出对账：

| ground truth | 蓝军 | 判定 |
| --- | --- | --- |
| UTF-16LE C2 `backup.example-corp.net/sync` | `ioc_extract` 命中 | ✅ |
| hex C2 `api.example-corp.net/v1/collect` | 未出现 | ❌ |
| `\u` C2 `ops.example-corp.net/ping` | 未出现 | ❌ |
| DWORD IP 203.0.113.77 | 未出现 | ❌ |
| Telegram token / mutex | 未出现（无此类型） | ❌ |
| 水印 `orbit-7f3a91c2d8e4` | `exposure` 命中 `canary-param` | ✅ |
| 追踪面 | `medium (15)`，telemetry/identity/fingerprint/location 四类 | ✅ |
| 反分析 | 4 族：timing / vm / hook / **debugger(TLS)** | ✅ + 1 FP |
| **诱饵 URL** | 被写进 `behaviour: reports to a remote endpoint (https://www.microsoft.com/...)` | ❌ 归因错误 |

两点值得单说：

1. **诱饵归因**。红军的意图就是"让报告把 microsoft.com 写成 C2"。蓝军确实照做了：behaviour 行把唯一的明文 URL 当成"reports to"的证据，而三条真 C2（hex/`\u`/dword）一条都没进报告。对分析师来说，这比"没找到"更危险——它给了一个**错误但看起来可信**的结论。建议：behaviour 引用网络证据时列出全部候选并标注"1 of N，未验证"，或干脆只写类型不写 URL。
2. **TLS 误报**。`anti_analysis` 对**未修改的 `whoami.exe`** 也报 `[debugger] TLS callback / early execution`，证据 `TLS | .tls`；同一次 triage 的结构行是 `TLS callbacks 0`。`lib/intel.js:252` 的 markers 里就是裸 `'TLS'`、`'.tls'`。攻击方只要在任意位置写 "TLS" 三个字母，就能给报告注入一条不存在的高级反分析技术。

---

## 5. 第 3 轮：IOC 分类学（T1 清单）

一行一个候选，共 20 类。蓝军 19 条命中，但类型覆盖是：

| 命中 | 未命中 |
| --- | --- |
| url、domain、ipv4、email、registry、winpath、pdb、ethereum、useragent（截断成 `Mozilla/5.0`） | **telegram bot token**（只作为 URL 的一部分）、**mutex**、**IPv6 ×2**、**defanged `hxxp://evil[.]example[.]com`**、**bech32 BTC `bc1q...`**、**AWS access key** |

`lib/intel.js:108-115` 的类型表只有 email/domain/registry/winpath/ipv4/url/bitcoin(legacy)/pdb/ethereum/useragent。Telegram token 与 mutex 是**主机侧与 C2 侧都最常用的两类 IOC**，缺席的代价是报告里少了可 pivot 的线索。

---

## 6. 第 4 轮：引擎（Ghidra）与并发

- `decompile_address 0x1cb0`（S1，冷启动）：**57.8s**，输出 `entry()` 调两个初始化函数，符号 `function: entry @ 140001cb0`。
- 同一地址第二次：**8.5s / 20.1s（cached）**，缓存有效。
- `probe_address 0x1cb0`：`name: entry`，`verdict: code ... named entry`，字节串正确。
- **并发碰撞（两次并行场景均复现）**：第一次是 `probe_address` 与 `decompile_address` 同时冷启动，probe 失败；第二次同时对 `S2-恶意样本😀.exe` 与 `S3-space name.exe` 发两个冷启动 `probe_address`，一个成功命名 `entry`，另一个返回：
  `engine: ghidra-local failed: at ghidra.app.util.headless.AnalyzeHeadless.launch(...)`
  代码位置：`lib/analysis-tools.js` 五个工具的 `isConcurrencySafe: () => true`（211/303/356/418/453 行），而 `lib/ghidra-local.js:112` 的注释自己写着"the next attempt collides with the project lock"。
  影响：agent 并行发工具调用是常态，此时结果会**随机退化**到本地结构层（probe 还能给出 `verdict: code`，但拿不到符号名；decompile 直接失败）。

---

## 7. 第 5 轮：边界与恶意输入

| 输入 | 结果 |
| --- | --- |
| 0 字节 / 1 字节 / 纯文本伪装 `.exe` / 截断 100 字节 | 不崩溃，`format: unknown`，`verdict: appears-unpacked (0)` |
| 目录路径 | `path must name a regular file`（清晰拒绝） |
| 不存在的路径 | `ENOENT`（清晰拒绝） |
| 穿越路径 `C:\Windows\System32\..\..\Windows\System32\whoami.exe` | 归一化后正常读取（符合预期） |
| Unicode 文件名 / 含空格路径 / 只读文件 | 正常处理 |
| 16 MB 纯随机 | `possibly-obfuscated (0.45)`，高熵判定正确；但反分析误报 `peb-flags, cpu-hypervisor, sandbox-tools`，且实验文案写"dump **524288 字节**区域"——那是 512 KB 的采样窗口（`lib/strings.js:34`），不是文件里 16 MB 的高熵区，数字具有误导性 |
| 16 MB 全零 | 正常（entropy 0） |
| PE 内容但扩展名 `.txt` | 正常按 PE 解析（不依赖扩展名，正确） |
| `C:\Windows\System32` 批量 20 个真实二进制 | 19 unpacked / 1 possibly-obfuscated（`AutoCatHost.exe` entropy 7.5），无崩溃 |

批量与其它流程工具：

- `batch_triage` 名称过滤正常（`P0`→1、`S1`→2、`zzz`→0），报告落盘为 md。
- `export_report` 用 bundle 路径导出 **SARIF 2.1.0 + Markdown 均通过校验**（2 results / 5 rules / level 正确；Markdown 的"推断边界/不可信数据"声明完整）。
- `sanitize_report`：hostname/username/home/ipv4/email/路径/代理 都能识别并替换，GitHub token 也能；但 **AWS access key、secret key、Slack webhook 全部漏检**，对只含这三样的文本直接回"No … secret patterns found"。（评审更正：check 模式头部"9 kinds / 12 occurrences"与列出的 9 条、12 次是一致 的，此前误判为计数 bug；真正的问题只有凭据规则缺失。）
- `protocol_analyze`：无 tshark 时明确说明并给出替代路径（诚实降级）。
- `fuzz_harness`：生成 libFuzzer 模板并落盘（不编译）。
- `describe_artifact` / `read_artifact`：可读、可分页（11036 字符 → 600/页）。
- `query_results`：10 条命中，但只给时间戳与工具名，没有描述里承诺的 Evidence ID/confidence。
- `purge_artifacts`：0 删除、保留 3.9 MB、当前会话不动（安全）。
- `run_playbook`：能列出目录并给出安装格式；**执行路径在本机无法验证**——playbook 目录在 `~/.dsh`，沙箱不可写，而 worker 用 `fork`（受限 shell 直接 EPERM）。

---

## 8. 缺陷清单（按优先级）

| ID | 严重度 | 症状 | 证据 | 建议修法 |
| --- | --- | --- | --- | --- |
| P1 | 高 | 靶场在产物目录不可写时输出 **空心 100%**，评分器不校验 D0 是否真的跑出结果 | `duel.json` D0 `ok:false`、ceiling 全 0、11 代仍 100% | `score.mjs:164` 断言：D0 `ok` 为假或 ceiling 为空 → 直接失败；`attack()` 的 `errors` 非空即 throw |
| P2 | 高 | 产物落盘失败会**拖垮整个 `rea_ioc_extract`**，而不是降级为"不落盘、只返回报告" | `EPERM mkdir ~/.dsh/rea-artifacts/...`，工具返回错误、0 指标 | `lib/artifacts.js` 持久化失败时返回内存结果并附 warning；把 artifact root 做成可配置（env 或 policy） |
| P3 | 高 | Ghidra 并发调用互相踩项目锁，结果随机失败/退化 | 两个冷启动 `probe_address` 并行，一个 `AnalyzeHeadless.launch` 失败 | `isConcurrencySafe` 改 `false`，或在 `ghidra-local.js` 里加进程内互斥队列（按项目名串行） |
| P4 | 高 | 缺 **hex** 解码通道 | P4 全 0；`strings.js` 通道表无 hex | 在 ASCII 扫描后加"偶数长度 hex run → 解码 → 递归扫描"，设最小长度与可打印率门槛 |
| P5 | 高 | 缺 **gzip** 容器（仅 zlib），且被误报为"运行时派生密钥的加密区" | P10：`unresolved encrypted region 353 bytes`，0 指标 | 识别 `1f 8b 08` 魔数走 `gunzipSync`；未能解压时文案改为"未识别的高熵容器"，不要断言"密钥运行时派生" |
| P6 | 中 | 缺 **JSON `\uXXXX` 转义**解码 | P7 全 0 | 在 base64/文本通道后加"含 `\u` 的 JSON 片段 → unescape → 递归" |
| P7 | 中 | 缺 **DWORD/BE 整数形式 IPv4** | P6：0xCB00714D 未还原 | 在结构扫描中读 4 字节，按 `<I`/`>I` 判为点分 IPv4，并要求端口/上下文佐证 |
| P8 | 中 | IOC 类型缺 Telegram token、mutex、IPv6、defanged、bech32、AWS key | T1：全部未命中 | 扩 `lib/intel.js` 类型表；defanged 先做 `[.]`→`.`、`hxxp`→`http` 归一化再匹配 |
| P9 | 中 | 反分析 TLS 族裸匹配 `TLS`/`.tls`，与结构层"TLS callbacks 0"矛盾 | 干净 `whoami.exe` 也报 `[debugger] TLS callback` | 调用 PE 解析结果：无 TLS 目录则不得报该族；或降级为 `evidence-only` 且标注"字符串命中，结构未证实" |
| P10 | 中 | behaviour 把**诱饵 URL**当作"reports to"的唯一证据 | S1：`reports to a remote endpoint (https://www.microsoft.com/...)` | 列全部网络候选并标 `1 of N (unverified)`，不把单个明文 URL 写进行为断言 |
| P11 | 中 | `sanitize_report` 漏 AWS/Slack 凭据 | 只含 AKIA/secret/Slack 的文本回"no findings" | 加 AWS `AKIA[0-9A-Z]{16}`、`aws_secret_access_key=`、Slack/Discord webhook 规则 |
| P12 | 低 | `export_report` 省略 bundle/path 时报上游 `path` 校验错误，与文档"omit both"不符 | 调用报 `export_evidence_bundle: path expected string` | 调上游前生成临时 bundle 路径，或先 `get_evidence_bundle` 再导出 |
| P13 | 低 | 16 MB 随机文件的实验文案把 512 KB 采样窗口写成"待 dump 的区域" | `dump the 524288-byte region` | 文案用"首个高熵窗口（512 KB，共 32 个）" |
| P14 | 低 | 非 PE 输入也给 `appears-unpacked` 结论 | 0 字节文件 `verdict: appears-unpacked (0)` | 增加 `unknown/non-PE` 结论，避免"无毒"暗示 |
| P15 | 低 | `query_results` 不返回 Evidence ID/confidence | 10 条只有时间与工具名 | 把索引里的 id/confidence 一并渲染 |
| P16 | 低 | useragent 截断为 `Mozilla/5.0`，丢失 `orbit/3.0` 特征 | T1 | 按整行/整段取值，上限内保留完整 UA |

---

## 9. 蓝军做对了什么（不应被缺陷清单掩盖）

1. **叠加区（overlay）确实被扫描**——`@98305` 这类偏移说明它读到了最后一个节之后的数据，这是很多商业工具都会漏的地方。
2. **UTF-16BE 通道**是加分项，不在常见工具的能力表里。
3. **水印识别**工作正常：独立埋的 canary 被 `exposure` 精确取出，并给出"截图/逐字引用即被归因"的正确解释。
4. **诚实报告**在多数情况下成立：无法解开的区域会显式列出，空文件/畸形文件不编造结论，缺引擎时明确说"缺什么、装什么"。
5. **边界安全**做得好：目录/不存在/穿越/只读/Unicode 全部安全处理，没有崩溃、没有越界写。
6. **导出链路**（SARIF/Markdown）质量高于预期，推断边界与不可信数据声明齐全，可直接进 CI。
7. **性能**可接受：1.5 MB 的 certutil 正常完成；Ghidra 冷启动 57.8s、缓存 8.5s。

---

## 10. 复现方式

```powershell
# 1) 基线（需要写 ~/.dsh，故用完全权限）
node --experimental-test-isolation=none --test
node scripts/duel.mjs --out "$env:TEMP\rea-duel-1810b" --label 1.8.10

# 2) 通道矩阵与复合样本
python reports\duel-2026-11-06\tools\probe_channels.py
python reports\duel-2026-11-06\tools\gen_specimens.py

# 3) 蓝军逐文件作答（任一 MCP 工具调用皆可）
#    rea_ioc_extract / rea_triage / rea_anti_analysis / rea_tracking_surface / rea_analyst_exposure
```

产物与证据：

- 红军样本：`%TEMP%\rea-spec\`（S1/S1b、P0–P12、E0–E7、T1）
- 插件产物：`C:\Users\25616\.dsh\rea-artifacts\2026-11-06T11-08-44-419Z-11544\`
  - `001…019-*.json`（各次 IoC 全量结果）、`016-evidence-report.md`、`017-evidence-report.sarif`
  - `011/020/021-batch-triage.md`（批量报告）
- 靶场结果：`%TEMP%\rea-duel-1810b\duel.json`

---

## 11. 建议的修复顺序

1. **P1 + P2**（评分器断言 + 产物落盘降级）——先让"测试失败时真的失败"。
2. **P3**（Ghidra 串行化）——并发是 agent 的默认用法，偶发失败最难排查。
3. **P4 + P5**（hex、gzip）——投入产出比最高，两条通道能覆盖大量真实 loader。
4. **P8 + P9 + P10**（IOC 类型、TLS 交叉校验、诱饵归因）——直接决定报告可信度。
5. **P6 + P7 + P11**（`\u`、DWORD IP、凭据正则）——锦上添花但成本低。

按此顺序修完，再用同一套红军样本回归，预期 S1 的通道召回可从 5/11 提到 10/11 以上。

---

## 12. 修复记录与回归（2026-11-06）

### 12.1 已修复

| ID | 修复 | 文件 |
| --- | --- | --- |
| P1 | `scoreAll()` 在 D0 `ok === false`、或整条天花板为空时直接抛错；靶场打印工具失败的代际，不再把"没测到"算成 100% | `scripts/duel/score.mjs`、`scripts/duel.mjs` |
| P2 | 产物落盘失败不再拖垮工具：`ioc_extract` / `sanitize_report` 捕获写错误，返回完整结果并注明"未保存"；报告摘要同时改写为"未知高熵区（可能是运行时密钥 / 未识别容器 / 诱饵）"，不再断言是加密 | `lib/intel-tools.js` |
| P3 | `probe_address` / `decompile_address` 的 `isConcurrencySafe` 改为 `false`，并在 `ghidra-local.js` 里加了进程内串行队列（不依赖宿主是否遵守该标志），Ghidra 项目锁不再被并行调用踩坏 | `lib/analysis-tools.js`、`lib/ghidra-local.js` |
| P4 | 新增 **hex** 通道：偶数长度 hex run → 解码 → 递归扫描（单段上限 4 KiB） | `lib/strings.js` |
| P5 | gzip 走 `gunzipSync`（此前误用 `inflateSync`，所有 gzip 流 100% 失败）；`unresolvedRegions` 不再把 gzip 当"加密" | `lib/containers.js` |
| P6 | 新增 **JSON `\uXXXX`** 通道：≥4 个转义 → 解码 → 递归 | `lib/strings.js` |
| P8 | IOC 类型新增 **Telegram bot token、mutex、IPv6（含压缩形式且排除时钟）、bech32 BTC、AWS key**；新增 **defang 还原**（`[.]`/`(.)`/`hxxp`） | `lib/intel.js` |
| P9 | TLS 族改为**结构校验**：解析 TLS 目录并数回调，目录缺失或回调为 0 时不报该族（`whoami.exe` 误报消失） | `lib/containers.js`、`lib/intel.js`、`lib/intel-tools.js` |
| P10 | behaviour 不再把第一个 URL 当作"the endpoint"：单个才具名，多个写"N candidate endpoints, unverified" | `lib/plan.js` |
| P11 | sanitize 新增 AWS access key / secret key / Slack webhook 规则 | `lib/intel.js` |
| P12 | `export_report` 省略 bundle/path 时，先写入会话产物目录再读回，符合文档中"omit both"的用法 | `lib/analysis-tools.js` |

### 12.2 回归结果

```
node --experimental-test-isolation=none --test
  tests 325  pass 325  fail 0        # 316 旧 + 9 新增（test/red-team-regressions.test.js）

node scripts/duel.mjs --only D0,D5            # 沙箱内、产物不可写
  D0   5/5 6/6 15/15 7/7 1/1  api 9/9  behav 6/6   precision 100.0%
  D5   4/4 5/5 15/15 7/7 0/0  api 9/9  behav 6/6   honesty: yes
  honesty failures: none
```

同一套红军样本的**修复前后**对照（直接调用模块，非 MCP）：

| 红军目标 | 修复前 | 修复后 |
| --- | --- | --- |
| P4 hex 编码 URL | 0 条 | ✅ 命中（`channels.hex=2`） |
| P7 JSON `\u` 转义 | 0 条 | ✅ 命中（`channels["json-escape"]=3`） |
| P10 gzip | 0 条 + "加密区"误判 | ✅ 打开（`channels.gzip=9`） |
| S1 hex / `\u` C2 | 0 / 0 | ✅ / ✅ |
| Telegram token、mutex | 未分类 | ✅ / ✅ |
| T1 IPv6 / AWS / defanged | 0 / 0 / 0 | ✅ / ✅ / ✅ |
| 干净 `whoami.exe` 的 TLS 误报 | 报 `[debugger] TLS callback` | ✅ 不报（目录存在但 callbacks=0） |
| 诱饵 URL 被写成 C2 | `(https://www.microsoft.com/...)` | ✅ `(4 candidate endpoints, unverified)` |
| 沙箱内跑靶场 | 天花板 0 条、11 代 100% | ✅ 天花板 5 endpoints / 15 tracking，分数有意义 |
| 产物目录不可写 | 整个 `ioc_extract` 失败 | ✅ 返回完整报告 + "not saved" 提示 |
| 两个冷启动 Ghidra 分析并行 | 一个失败（项目锁） | ✅ 两个都成功，`name=entry`，合计 91.8s（队列串行） |

### 12.3 暂缓项（不是遗漏，是需要另外设计）

- **P7 DWORD 形式 IPv4**：4 字节窗口在任意二进制里都是海量候选，没有上下文时直接扫会制造大量假阳性，违背这个插件的精度取向。合理做法是"只在已知字段名（`ip`/`c2`/`host`/`server`）后的 4 字节尝试"，并标 `inferred`；需要单独一轮样本验证误报率，故本轮不做。
- **P13 512 KB 窗口文案 / P14 非 PE 的 `appears-unpacked` 结论 / P15 `query_results` 缺 Evidence ID / P16 UA 截断**：都是低危可读性问题，不影响结论，留待下一轮。

### 12.4 生效方式

插件宿主在启动时加载 `index.js`，模块已被缓存；**重启 DSH 会话（或禁用/启用一次本插件）后**，MCP 工具才会用上新代码。聚类外的 `node --test` / `node scripts/duel.mjs` 已经是新代码。

---

## 13. 第二轮红蓝对抗（同日，重启后）

重启后先复核上一轮：`rea_anti_analysis(whoami.exe)` 只剩 `timing` 一族，TLS 误报确认消失——MCP 路径已经是新代码。

### 13.1 红军新靶标

| 靶标 | 攻击面 | 期望蓝军看见 |
| --- | --- | --- |
| R1a | 合法 PE 后追加一个**完整 PE**（`where.exe`，65 KB） | "这里还有一个 PE"，以及偏移/位数/大小 |
| R1b | 合法 PE 后追加 **ZIP**（含 config） | 识别为自解压容器并给提取步骤 |
| R2 | 编码动物园：**带空格 hex**、**base32**、**JWT**、**onion v3**、**SSH 私钥头**、拆半 URL、**带标签的 DWORD IP**（`0xCB00714D` 与十进制 `3405803837`） | 逐项分类 |
| R3 | 在 `.text` 代码洞写入**指令级反调试**：`mov rax, gs:[0x30]`、`mov eax, fs:[0x30]`、`int 2d`、`rdtsc`、`rdtscp`、`cpuid`、`xgetbv` | 按族给出 RVA 证据 |

### 13.2 首测结果（修复前）

| 目标 | 结果 |
| --- | --- |
| R1b ZIP | ✅ `installer-with-payload (0.9)`，容器行 + 提取实验，质量很高 |
| R1a 内嵌 PE | ⚠️ 只说 "large PE overlay (65538 bytes)"，**没说那是一个 PE**，也没有偏移/位数/大小 |
| R2 空格 hex / base32 | ❌ 0（hex 通道只认连续串；base32 根本没有通道） |
| R2 JWT / SSH 私钥 | ❌ 类型不存在 |
| R2 DWORD IP | ❌ 0；带标签的 `0x...` 与十进制都漏 |
| R3 指令级反调试 | ❌ 只报 import 带来的 `timing`；PEB / `int 2d` / `rdtsc` / `cpuid` 全部不可见 |

### 13.3 本轮修复

| 能力 | 实现 |
| --- | --- |
| **内嵌 PE 识别** | `structure.js` 新增 `findEmbeddedPes()`：找 MZ → 跟 `e_lfanew` → 校验 PE 签名/可选头 magic/节表，输出 `offset/bits/sections/size`（上限 8 个）；`structureProfile` 暴露 `embeddedPes`；triage 增加 anomaly 行（"embedded PE at file offset 0x…"），plan 增加 priority-1 的"切出来单独 triage"实验 |
| **指令级反分析** | `structure.js` 新增 `scanCodeSignals()`：只扫可执行节，匹配 PEB 访问（x64/x86）、`rdtsc/rdtscp`、`cpuid`、`xgetbv`、`int 2d`，带节名与 RVA；triage 的 anti 分类与 `rea_anti_analysis` 都合并这些证据（新增 `peb-flags`、`debugger-trap` 两族） |
| **带空格 hex** | hex 通道同时接受 `68 74 74 70 ...` 形式（去掉分隔符后解码，前缀/后缀仍用语义锚点把关） |
| **base32** | 新增 RFC 4648 解码通道（`[A-Z2-7]{24,}`，解出文本或锚点才保留） |
| **JWT / SSH 私钥** | 新增 IOC 类型（`eyJ...x3` 三段式；`-----BEGIN … PRIVATE KEY-----`） |
| **DWORD IPv4** | 只在**带字段标签**（`ip/addr/host/c2/server/gate/beacon/callback`）时把 `0xXXXXXXXX` 或 8–10 位十进制转成点分 IP；拒绝 0.x、127/8、组播段；**无标签的 32 位常量一律不转**，避免把 build id 当 C2 |

### 13.4 回归结果（修复后）

```
node --test             tests 331  pass 331  fail 0     # 316 → 331（新增 6 个第二轮回归）
node scripts/duel.mjs   D0–D10 全部 100%，honesty failures: none
```

同一批靶标的模块级验证：

```
embedded PE count=1  0x18001  64-bit  7sec  ~65536B
triage anomaly:      embedded PE at file offset 0x18001 (64-bit, 7 sections, ~65536 bytes) — carve it out and triage it as its own sample
plan step:           Carve 65536 bytes at file offset 0x18001 and run rea_triage on the result as its own sample
spaced hex URL       PASS      base32 URL PASS      JWT PASS      SSH key PASS
dword IPv4           PASS      (203.0.113.77 / 203.0.113.61，两个带标签字面量各自还原)
code signals         8 条：PEB×2 / int 2d / rdtsc / rdtscp / cpuid / xgetbv
anti categories      peb-flags, timing, debugger-trap, cpu-hypervisor
precision guard      无标签 32 位常量 → 0 条 ipv4
```

### 13.5 仍然没做

- **拆半 URL 拼回**：`https://split.example` + `-corp.net/x` 目前仍报两段。拼接需要"相邻 + 边界字符 + 合法 URL"三重约束，且真实样本里更多是分节存放而非相邻；留待有真实语料时再做，避免为合成靶标过拟合。
- P13–P16（512 KB 窗口文案、非 PE 的 `appears-unpacked`、`query_results` 缺 Evidence ID、UA 截断）继续留待下一轮。

---

## 14. 第三轮红蓝对抗（同日，第三批）

### 14.1 红军新靶标

| 靶标 | 攻击面 | 期望蓝军看见 |
| --- | --- | --- |
| R3a | **UTF-16LE 文本整体单字节 XOR**（Windows loader 的经典配置存法） | 宽字符 URL |
| R3b | `base64(deflate(xor5a(json)))` | 穿过三层 |
| R3c | `hex(gzip(xor4(json)))`，4 字节密钥 | 穿过三层 |
| R3d | 非 HTTP 协议：`ws://`、`tcp://`、`ftp://`、`\\\\server\\share`、`ip:port`、`.shop` 域名 | 逐项分类 |
| R3e | **8 MB 的 `MZ` 重复**（压缩后 8 KB 的"分析器 DoS"） | 快速失败，而不是卡死 |
| R3f | **zlib 炸弹**：64 MB 零压缩成 65 KB | 有界解压 |
| R3g | `csc.exe` 编译的 **.NET 托管程序集** | 标注 managed，而不是当成原生 PE |

### 14.2 首测结果（修复前）

| 目标 | 结果 |
| --- | --- |
| R3a XOR(UTF-16LE) | ❌ 只看到 `ascii`，URL 丢失 |
| R3b b64(deflate(xor5a)) | ✅ 已能穿过（`base64=12`） |
| R3c hex(gzip(xor4)) | ❌ hex 通道解出二进制后被"非文本"判定丢弃，从不下钻；通道列表里连 `hex` 都没有 |
| R3d 协议 | ⚠️ 只认 `https://`；`ws/tcp/ftp/UNC/ip:port` 全漏（`.shop` 因 URL 规则命中） |
| R3e MZ flood | 💥 **`extractDeepStrings` 跑了 848,720 ms（14 分 8 秒）**，8 MB 文件即可拖死分析 |
| R3f zlib 炸弹 | 未测到（被 R3e 挡住） |
| R3g .NET | ❌ 只写 `format: pe32`，没有 managed 提示，分析师会用原生反编译器 |

**这是三轮里最严重的一次发现**：一个 8 KB 的文件（8 MB 的 `MZ` 重复）能让静态分析卡死 14 分钟。CPU profile 显示 **94.7% 的时间在一条正则**——salvage 阶段的 email 规则 `[A-Za-z0-9._%+-]+@…` 在 `9.9.9…` 这类解码流上逐字符回溯，复杂度 O(n²)；域名的 `(?:[a-z0-9-]+\.)+` 是第二个同类问题。

### 14.3 修复

| 能力 | 实现 |
| --- | --- |
| **分析器 DoS（P0）** | ① email 正则全部加界：本地部分 `{1,64}`、域名 `{1,255}`、TLD `{2,24}`（`strings.js` salvage、`intel.js` IOC、sanitize 三处）；② 域名正则改 `(?:[a-z0-9-]{1,63}\.){1,8}`；③ `absorb()` 增加 `degenerate()` 守卫：解码结果前 256 字节里不同字节 ≤6 个就拒绝继续下钻（`1313…` 这类重复数据不再触发 200 次全量分析） |
| **XOR(UTF-16LE)** | 新增 `xor-0xKK>utf16le` 通道：识别"可打印, k, 可打印, k"的宽字符串形状，按 key 解出并校验语义锚点 |
| **hex 里的容器** | hex 解码后若是 gzip/zlib 头，直接交给 `absorb`，不再因为没有可打印文本而丢弃——`hex(gzip(xor4))` 因此可穿 |
| **协议覆盖** | URL 规则扩到 `https?/ftps?/wss?/tcp/udp/smb`；新增 `hostport`（带端口校验 1–65535）与 `unc`（`\\\\host\\share`）类型 |
| **.NET 识别** | `structure.js` 读 data directory 14（CLR），`structureProfile.managed`；triage 输出 anomaly 与 next step：用 `inspect_managed_artifact / inspect_managed_members`，不要用原生反编译器 |

### 14.4 回归结果

```
node --test             tests 336  pass 336  fail 0     # 331 → 336（新增 5 个第三轮回归）
node scripts/duel.mjs   D0–D10 全部 100%，honesty failures: none
```

同一批靶标的模块级复验：

```
XOR(UTF-16LE) URL        PASS   channels 出现 xor=38
base64(deflate(xor5a))   PASS
hex(gzip(xor4))          PASS   channels 出现 hex=3
ws://  tcp://  host:port  .shop  ftp://  UNC   PASS ×6
managed                  CLR header present → anomaly + next step 均出现
R3e 8 MB MZ flood        3,129 ms（修复前 848,720 ms）
R3f 64 MB zlib bomb        432 ms
```

### 14.5 仍然存在的限制

- **压缩层内的 4 字节 XOR 依赖 crib 锚点**。同样 `hex(gzip(xor4))` 的链路：78 字节、含单个 `https://` 锚点的配置能还原；140 字节、含两个不同 URL 的配置，crib 对不齐就还原不出——这是已知的 keyed-XOR 设计边界，不是本轮引入的。真实配置通常更长、锚点更多，但报告里不应把它说成"必解"。
- R3e 仍有 3.1 s 的固定成本（8 MB 全量字符串 + 多通道扫描），属于可接受范围；若要进一步压，可以把 `maxStrings`/扫描窗口按文件大小自适应。
- P13–P16 仍未做。

