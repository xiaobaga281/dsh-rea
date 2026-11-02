# dsh-rea — 逆向分析

REA（[github.com/morluto/rea](https://github.com/morluto/rea)，npm 包 `rea-agents`，MIT 许可）的 DeepSeek Harness 插件。

## 它做什么

- **工具**：把 REA MCP 服务器（`rea mcp`）的完整工具表注册进 Agent 工具表，公开名为 `mcp__rea__<tool>`（与 Claude Code / Codex 同形）。工具的输入 schema 原样沿用，REA 新增/下线工具时会自动重新同步。
- **延迟加载**：207 个工具的 schema 标记为 `deferLoading`，**不进请求体**，只在模型真的要用某个工具时才加载。常驻开销从 194 KB（≈4.9 万 token）降到 1.4 KB（≈341 token），工具一个不少、照样能调。
- **检索入口**：`rea_catalog` 是一个几百字节的常驻工具，按关键词在 207 个工具里搜名字/描述——因为 schema 延迟了，模型没法直接从工具表里读它们，这个工具就是它的索引。
- **技能**：把 REA 自带的 `reverse-engineer-anything` 技能及其 `references/` 参考文档安装到 `~/.dsh/skills/reverse-engineer-anything/`。
- **环境侧栏**：侧栏入口显示运行时、Java/JDK、Ghidra、JADX、Apktool、WABT、Kuna/Rizin 的实际状态；面板内可填写并保存所有绝对路径，Ghidra/JADX/Apktool/WABT 还提供按需准备按钮和进度。
- **就绪检查**：`rea_doctor` 运行逆向服务自己的 `mcp doctor --json`，报告 MCP 子进程能否启动、服务端状态与可用分析引擎。只读，不打开任何目标。

## 为什么不合并工具

207 个平铺的工具名确实又多又杂，但**合并会改变模型看到的世界**：REA 的工具是按「一个工具一个职责 + 严格输入契约」设计的，合并成一个 `rea_run(tool, input)` 式的总入口意味着模型每次都要先猜对工具名和参数结构，而它现在是从 schema 里读到的。所以选择保留 207 个工具、用延迟加载解决体积——这是宿主的原生机制（`deferLoading` 一路通到 DeepSeek 的 `defer_loading` 字段），不是插件自己的 hack。

## 运行时怎么放

`rea-agents` 6.7.0 连同完整依赖闭包（136 个包）打成一个 `vendor/rea-runtime.tgz`（28 MB，带 SHA-256 校验）。**首次启用时**解包到 `~/.dsh/rea-runtime/`，之后 MCP 子进程用宿主自己的 node 以绝对路径直接跑，调用时不经 npm/npx、不需要网络。

之所以用「压缩包 + 首次解包」而不是把 `node_modules` 原样放进插件：

- 插件目录从 124 MB 降到 28 MB；
- 解包位置在 DSH 主目录而不是工作区 —— 工作区沙箱被观测到会把外部写入的大目录回滚掉，那会让插件某天悄悄坏掉；
- 依赖闭包完整。REA 有大量**惰性 require**（`saxes`→`xmlchars`、`pino`→`pino-std-serializers`……），按「运行时实际 import 过谁」裁过一版，第一次调用就崩；按 `package.json` 依赖闭包裁，也漏。只有全量闭包能让 207 个工具都不坏。

## 实测（207 个工具全量回归，走解包后的运行时）

| 分类 | 数量 | 含义 |
| --- | --- | --- |
| 跑通 | 14 | 真出了结果（Go/Rust 元数据、.NET 清单、PE 资源等） |
| 参数校验拒绝 | 144 | 工具执行了，按契约拒绝空参数 |
| 无打开目标 | 27 | 工具执行了，报告「没有目标」 |
| 参数不合契约 | 5 | 同上 |
| 缺本机引擎 | 17 | 需要 Ghidra / Hopper / IDA / JADX / Kuna / Apktool |
| **缺依赖包** | **0** | 没有任何工具因为少包而坏 |

首次启用约 16 s（含解包 5 s + 握手 2 s），之后启用约 2 s。

## Native 引擎侧栏

插件本体不会携带 Ghidra，因此仍保持约 28 MB。侧栏会自动检查当前环境：

- Ghidra：服务验证的 12.1.4；
- Java：Ghidra 需要安装声明范围内的 64 位完整 JDK；当前机器已有 Java 17，但没有 Ghidra；
- JADX：需要用户提供 `REA_JADX_MCP_JAR` 和 JDK 17+；
- Apktool：需要用户提供 `REA_APKTOOL_COMMAND`；
- WABT：需要用户提供 `REA_WABT_BIN_DIRECTORY`；
- Kuna/Rizin：需要用户提供 `REA_KUNA_COMMAND`。

点击“准备 Ghidra”后，插件从官方发布地址下载 Ghidra 12.1.4（约 543 MB），校验 SHA-256 后解包到 `~/.dsh/rea-engines/ghidra/`，并自动把发现的路径注入 REA 子进程。准备完成后会重启 REA MCP 连接，随后 Go/ELF/PE 等 native 目标才能走函数级分析和伪代码流程。

Ghidra 下载地址、版本和校验值固定在插件代码中；失败时会保留错误信息，不覆盖已有配置。JADX、Apktool、WABT 的准备按钮同样会校验固定版本的 SHA-256；Kuna/Rizin 和商业 IDA/Hopper/JEB 仍需要用户提供合法安装与绝对路径。各引擎与 Java 的许可证和发行版通知归各自项目。

## 常驻开销实测

| 配置 | 常驻 schema | token / 每请求 |
| --- | --- | --- |
| `deferCatalog: false`（全量广告） | 194 KB | 48 560 |
| `deferCatalog: true`（默认） | 1.4 KB | **341** |

延迟的 207 个工具仍然可调（实测 `binary_session` 返回 73 KB），`rea_catalog` 可按关键词检索（`javascript` 命中 23 个，无参列出全部 207 个）。

## 配置（cordis.patch.yml 的 `config`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `schemaProfile` | `compact` | REA 的 input schema 广告档位。`full` 下 207 个工具的 schema 约 3 MB（≈79 万 token），会挤爆任何上下文预算。 |
| `outputSchemaProfile` | `off` | 不广告 output schema，省下大量 token；REA 内部仍按完整契约校验返回。 |
| `toolCallTimeoutMs` | `900000` | 单次调用超时。REA 首次起 Ghidra/Hopper 可能几分钟。 |
| `maxBufferBytes` | `10485760` | stdio 单条消息上限（REA 自己的下限就是 10485760，传更小会被抬回下限）。 |
| `logLevel` | `info` | 子进程日志级别。 |
| `deferCatalog` | `true` | 把 207 个 REA 工具的 schema 延迟加载（不进入请求体）。置 `false` 恢复成全部常驻广告——只在确实需要模型直接看见全部 schema 时才这么干，代价是每请求多约 4.8 万 token。 |
| `enabled` | `true` | 置 `false` 时不派生子进程、不注册工具。 |

## 分析能力

取决于目标与本机已有软件：静态 JavaScript/Electron、.NET、Go/Rust 元数据、SQLite、ZIP/APK/IPA 清单等**无需额外引擎**；原生二进制函数级反编译需要 Ghidra、Hopper、IDA 或 Kuna。Ghidra 可从侧栏按需准备；JADX、Apktool、WABT 可从侧栏按需准备；Kuna/Rizin、商业工具仍由用户提供路径。所有路径都可以直接在侧栏表单填写和保存，插件会持久化到 `~/.dsh/rea-engines/config.json` 并注入后续子进程。

## 安装

把 `dsh-rea-1.0.3.tgz` 解压到稳定目录（如 `~/.dsh/plugins/dsh-rea`），通过 Plugin Manager 的 `install_bundle` 选择该目录，或直接把本包加进 profile 的 `dependencies` 与 `bundles`：

```
"dsh-rea": "link:<包目录的绝对路径>"
```

安装后重启会话即可看到 `mcp__rea__*` 工具与 `reverse-engineer-anything` 技能。

## 发布包

```bash
npm pack      # → dsh-rea-1.0.3.tgz（package/ 为根）
```

包内含 `index.js`、`client.js`、`cordis.patch.yml`、`locale/`、`icon.svg`、`README.md`、`LICENSE`，以及 `vendor/rea-runtime.tgz`（28 MB，136 个包的完整依赖闭包）与它的 SHA-256。

源码仓库：<https://github.com/xiaobaga281/dsh-rea>

## 已知边界

- REA 的结果以文本/JSON 为主；图片块（例如截图）以明确占位文本返回，不静默丢弃，也不转成模型可看的图片。
- 侧栏准备 Ghidra 需要网络和约 543 MB 下载空间；解包后还会占用 Ghidra 本身的磁盘空间。
- 首次启用需要 `tar`（Windows 10+ 与各受支持平台自带）。
