# ShellGate for OpenWrt (Rust)

与主项目相同的 MCP 接口和鉴权，用 Rust 重写成**单个静态二进制**（aarch64 约 1.4 MB，空闲内存约 1–2 MB），适合 360 T7 这类小闪存路由器。不依赖 Python、bash 或 systemd。

## 与 Python 版的区别

| | Python 版（WSL2/Linux） | Rust 版（OpenWrt） |
|---|---|---|
| 运行环境 | Python 3.10+、systemd | 任意 Linux，静态 musl |
| Shell | `bash -lc` | `/bin/sh -c`（busybox ash） |
| Docker 工具 | 有 | 无（需要时用 run_command） |
| 搜索 | ripgrep | 内置正则搜索 |
| 默认写入目录 | `$HOME,/tmp` | `/tmp,/root,/etc/config` |
| 审计日志 | `~/.local/state/shellgate` | `/var/log/shellgate`（内存，重启清空，保护闪存） |
| 额外危险命令 | | `sysupgrade`、`firstboot`、`jffs2reset`、`mtd write/erase`、`fw_setenv`、重启 network/firewall/dropbear/cloudflared 等 |

v0.2.0 起与 Python 版行为一致：默认输出脱敏（`SHELLGATE_REDACT`、`SHELLGATE_REDACT_DOMAINS`）、`run_command` 支持 `stdin`、新增 `run_script`（解释器 `sh` / `ash`，装了的话也可用 `bash` / `python3`），说明见[主 README](../README.md#输出脱敏--output-redactionv020)。

MCP 传输：Streamable HTTP，无状态，JSON 响应（`POST /mcp`）。`/health` 免鉴权。

## 支持的 CPU

| 发布文件 | 适用 |
|---|---|
| `shellgate-aarch64-unknown-linux-musl` | MT7981（360 T7、小米 AX3000T 等）、MT7986、大多数 ARM64 路由器 |
| `shellgate-armv7-unknown-linux-musleabihf` | IPQ40xx 等 Cortex-A7/A9 |
| `shellgate-x86_64-unknown-linux-musl` | x86 软路由 |

MIPS 路由器（MT7621 等）暂不提供。

## 安装（需要已刷 OpenWrt / ImmortalWrt）

SSH 登录路由器后：

```sh
cd /tmp
wget https://raw.githubusercontent.com/lovexy-me/shellgate-mcp/main/openwrt/files/install.sh
sh install.sh
```

脚本会自动识别 CPU、从 GitHub Releases 下载对应二进制到 `/usr/bin/shellgate`，安装 procd 服务 `/etc/init.d/shellgate`，生成随机令牌写入 `/etc/shellgate/env`（600），加入 `/etc/sysupgrade.conf` 让升级固件后保留，最后做健康检查并**只显示一次令牌**。

如果路由器访问不了 GitHub：在电脑上下载对应二进制，`scp -O` 到 `/tmp/shellgate`，然后 `sh install.sh /tmp/shellgate`。

常用命令：

```sh
/etc/init.d/shellgate restart
logread -e shellgate
vi /etc/shellgate/env && /etc/init.d/shellgate restart
sh uninstall.sh            # 加 --purge 删除配置
```

## 远程访问的两种方式

**A. cloudflared 跑在路由器上**：`SHELLGATE_HOST=127.0.0.1`，Tunnel 指向 `http://127.0.0.1:8790`。cloudflared 本身有几十 MB，128 MB 闪存的设备要先确认空间。

**B. 复用局域网里已有的 cloudflared（推荐小闪存设备）**：在 `/etc/shellgate/env` 设 `SHELLGATE_HOST=<路由器 LAN IP>`，在已有 Tunnel 里加一个主机名指向 `http://<路由器 LAN IP>:8790`。确保防火墙没有把 8790 暴露到 WAN（OpenWrt 默认 WAN 入站拒绝）。

客户端配置：URL `https://<主机名>/mcp`，请求头 `Authorization: Bearer <令牌>`。

## 自己编译

```sh
pip install ziglang cargo-zigbuild
rustup target add aarch64-unknown-linux-musl
cd openwrt
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

打 `v*` 标签时 GitHub Actions 会自动编译三个架构并发布到 Releases。

测试：`cargo test`，以及用 Python 端到端测试跑 Rust 二进制：
`SHELLGATE_BIN=openwrt/target/release/shellgate pytest -q tests/test_e2e.py`
