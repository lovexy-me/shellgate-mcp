# ShellGate MCP

让 AI 客户端（任何支持远程 MCP 的客户端）通过 **Streamable HTTP + Bearer Token** 安全地远程管理设备：执行命令、后台任务、读写文件。服务端不带模型、不需要 API key；令牌只在本地生成，仓库与 Release 不含任何令牌。

按使用场景分成三个版本，**各自独立的功能、默认配置、文档和发布标签**，共用同一套核心代码（鉴权、确认码、输出脱敏、审计），不是同一程序复制三份。

| 版本 | 场景 | 平台 | 特有功能 | 配置样例 | 发布标签 |
|---|---|---|---|---|---|
| [OpenWrt 版](editions/openwrt/README.md) | 路由器、软路由 | aarch64 / armv7 / x86_64 musl 静态 | uci、opkg、防火墙等危险命令确认；procd 服务；体积最小（无 HTTPS 下载、无桌面工具） | [`env.example`](editions/openwrt/files/env.example) | `openwrt-v*` |
| [PE 维护版](editions/pe/README.md) | U 盘 PE 救援、装机、修复 | Windows x64 / x86（WinPE、已装系统），附救援 Linux 静态版 | Ventoy 管理、桌面截图与键鼠、装机修复脚本、自建 PE、局域网 / 隧道模式 | [`shellgate.env.example`](editions/pe/shellgate.env.example) | `pe-v*` |
| [WSL2 / Linux 版](editions/wsl/README.md) | 日常主机、WSL2 | Python 3.10+，systemd 用户服务 | Docker 工具、ripgrep 搜索、与 Windows 互通 | [`env.example`](editions/wsl/deploy/env.example) | `wsl-v*` |

## 目录

```
core/               Rust 核心（OpenWrt 版与 PE 版共用），按 cargo feature 组合功能
editions/openwrt/   OpenWrt 版：安装脚本、procd 服务、配置样例、文档
editions/pe/        PE 维护版：自建 PE（pe-build/）、第三方 PE 自启模板（pe-autostart/）、配置样例、文档
editions/wsl/       WSL2/Linux 版：Python 包、systemd 单元、安装脚本、文档
tests/              共用的 MCP 一致性测试（Python 版与 Rust 二进制都跑同一套）
```

## Rust 核心的编译开关

| feature | 含义 |
|---|---|
| `edition-openwrt` | 路由器版：只含通用工具 |
| `edition-pe` | = `ventoy` + `download` + `desktop` |
| `edition-linux` | = `ventoy` + `download`（U 盘上救援 Linux 用） |
| 默认（不加参数） | 全部功能，用于测试 |

```sh
cd core
cargo zigbuild --release --no-default-features --features edition-openwrt --target aarch64-unknown-linux-musl
cargo zigbuild --release --no-default-features --features edition-pe --target x86_64-pc-windows-gnu
```

`system_info` 与 MCP `initialize` 的返回里带 `edition` 字段，可确认跑的是哪个版本。

## 发布

每个版本单独打标签、单独发布：`openwrt-v0.3.0`、`pe-v0.3.0`（版本号取 `core/Cargo.toml`），`wsl-v0.2.5`（取 `editions/wsl/pyproject.toml` 与 `__init__.py`）。标签与版本号不一致时发布会失败。

## 许可

MIT
