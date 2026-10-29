# ShellGate MCP

让 AI 客户端（Hark、Claude、Cursor 等任何支持远程 MCP 的客户端）通过 **Streamable HTTP + Bearer Token** 远程控制你的 Linux / WSL2：执行命令、跑后台任务、读写文件、管理 Docker。

服务端**不带任何模型**，也不需要 API key。决策由 MCP 客户端负责，ShellGate 只负责安全地执行。

> 路由器（OpenWrt / ImmortalWrt）请看 [`openwrt/`](openwrt/README.md)：Rust 单文件版本，约 1.4 MB。

## 特点

| | |
|---|---|
| 传输 | MCP Streamable HTTP（无状态模式，断线重连不丢会话） |
| 鉴权 | `Authorization: Bearer <token>`，常量时间比较；`/health` 免鉴权 |
| 网络 | 默认只监听 `127.0.0.1:8790`，通过 Cloudflare Tunnel 发布，不用开端口 |
| 危险命令 | `rm -rf`、`mkfs`、`dd of=`、`reboot`、`wsl --shutdown`、`docker prune/rm`、`systemctl stop`、`git push -f`、`curl \| sh` 等会先返回**一次性确认码**（绑定命令+目录，5 分钟过期，用过即失效） |
| 两种模式 | `full`：任何命令（危险的要确认码）；`allowlist`：只允许白名单程序，禁止 `$()` 和反引号 |
| 文件保护 | 配置/令牌、审计日志、`~/.ssh`、`~/.cloudflared`、`/etc/shadow`、sudoers 永远禁止通过文件工具访问；写入只能落在允许目录；覆盖前自动备份 `.bak-时间戳` |
| 输出脱敏 | 默认开启：公网 IP、全局 IPv6、MAC、WireGuard 密钥、JWT/长令牌、UUID、`password=` 等密文、指定域名在返回前替换成占位符；审计日志也只存脱敏后的内容 |
| 审计 | 每次调用写入 JSONL（时间、来源 IP（读取 CF-Connecting-IP）、工具、参数、结果、耗时），自动轮转 |
| 资源限制 | 超时会杀掉整个进程组、输出截断（保留首尾）、并发与后台任务数量上限 |

## 工具

| 工具 | 作用 |
|---|---|
| `run_command` | 执行命令并等待结果（默认 60 秒，最长 600 秒）；可选 `stdin` |
| `run_script` | 执行多行脚本（`sh` / `bash` / `python3` / `ash`），可带 `args`、`stdin`；每一行都过危险命令检查 |
| `start_job` / `job_output` / `job_input` / `list_jobs` / `cancel_job` | 后台长任务：拉镜像、编译、升级；可以向 stdin 输入内容 |
| `read_file` / `write_file` / `edit_file` | 带行号读取、写入/追加、精确替换（自动备份） |
| `list_dir` / `search_files` | 列目录、正则搜索（有 ripgrep 时自动使用） |
| `system_info` | 系统、内核、WSL 检测、负载、内存、磁盘 |
| `docker_ps` / `docker_logs` / `docker_stats` / `docker_restart` | 常用 Docker 操作，参数不经过 shell |
| `audit_tail` | 查看最近的审计记录 |

在 WSL 里可以通过 `run_command` 调用 `powershell.exe` / `cmd.exe` 操作 Windows。

## 安装（WSL2 / Ubuntu）

```bash
# 1. 建议先开启 systemd（只需一次）：在 /etc/wsl.conf 加入
#    [boot]
#    systemd=true
#    然后在 Windows 里执行 wsl --shutdown 再重新打开 WSL

# 2. 安装
sudo apt install -y python3-venv ripgrep
git clone https://github.com/lovexy-me/shellgate-mcp.git
cd shellgate-mcp
./scripts/install.sh
sudo loginctl enable-linger $USER   # 不开终端也保持运行
```

安装脚本会：创建虚拟环境 `~/.local/share/shellgate/venv`，生成随机令牌写入 `~/.config/shellgate/env`（权限 600），安装并启动 systemd 用户服务，最后做健康检查并**只显示一次令牌**。

常用命令：

```bash
systemctl --user status shellgate
journalctl --user -u shellgate -f
nano ~/.config/shellgate/env && systemctl --user restart shellgate
```

升级：`git pull && ./scripts/install.sh`（保留现有配置和令牌）。
卸载：`./scripts/uninstall.sh`（加 `--purge` 同时删除配置和审计日志）。

## 通过 Cloudflare Tunnel 发布

在 `~/.cloudflared/config.yml` 的兜底规则之前加入：

```yaml
ingress:
  - hostname: shell.example.com
    service: http://127.0.0.1:8790
  - service: http_status:404
```

```bash
cloudflared tunnel route dns <隧道名> shell.example.com
sudo systemctl restart cloudflared   # 或按你原来的方式重启
curl https://shell.example.com/health
```

**不要**在 `/mcp` 前面加需要交互登录的 Cloudflare Access 页面，MCP 客户端完成不了；Bearer 令牌就是门禁。

## 接入客户端

- URL：`https://shell.example.com/mcp`
- 传输：Streamable HTTP
- 请求头：`Authorization: Bearer <你的令牌>`

Claude Code 示例：

```bash
claude mcp add --transport http shellgate https://shell.example.com/mcp \
  --header "Authorization: Bearer <token>"
```

## 输出脱敏 / Output redaction（v0.2.0）

**中文**：默认开启（`SHELLGATE_REDACT=1`），只能在服务端环境变量里关闭，工具调用参数里没有开关。所有返回给客户端的文本（命令输出、后台任务输出、`read_file`、搜索结果、`audit_tail`、`system_info`、Docker 输出、错误信息）都会脱敏；**输入不改动**，命令照原样执行。

| 内容 | 替换为 | 说明 |
|---|---|---|
| 公网 IPv4 | `<ip>` | 逐个地址判断；保留 10/8、127/8、172.16/12、192.168/16、100.64/10、169.254/16、0.0.0.0/8、组播、广播和子网掩码；CIDR 后缀保留（`<ip>/24`）；只写前几段的公网网段也会遮：`198.51.100.`、`198.51.100.x`、`198.51.*.*`、`198.51.100/24` 和规则名里的 `Allow_198_51_100_Net` |
| 全局 IPv6（2000::/3） | `<ipv6>` | 保留 `::1`、`fe80::/10`、`fc00::/7`（ULA） |
| MAC | `<mac>` | 全 0 与广播地址保留 |
| WireGuard 密钥 / PEM 私钥 | `<key>` | 43 个 base64 字符 + `=` |
| JWT、≥60 字符的 base64 令牌 | `<token>` | 路径和纯十六进制摘要不算 |
| UUID | `<uuid>` | |
| `password=`、`token:`、`api_key`、`private_key`、`preshared_key`、`Authorization: Bearer …`、UCI `option key '…'` 等 | 值改为 `<x>` | 名字保留 |
| `SHELLGATE_REDACT_DOMAINS` 里的域名及其子域 | `<domain>` | 逗号分隔，按后缀匹配 |

有替换时，结果里会多一个字段 `"redacted": "[redacted: ip=3 mac=1]"`。占位符不是真实值，不要把它写回配置文件。

**English**: Redaction is on by default (`SHELLGATE_REDACT=1`) and can only be turned off in the server environment, never per call. It applies to every string a tool returns (including errors and `audit_tail`); tool inputs are executed unmodified, and the audit log stores redacted arguments/results only (the raw client IP stays in the on-device log for forensics, but is masked in `audit_tail` output). Public IPv4 → `<ip>` (decided per address; private/CGNAT/link-local/loopback kept; CIDR suffix kept; partial public prefixes such as `198.51.100.`, `198.51.100.x`, `198.51.*.*`, `198.51.100/24` and identifier forms like `Allow_198_51_100_Net` are masked too), global IPv6 → `<ipv6>`, MAC → `<mac>`, WireGuard/PEM keys → `<key>`, JWT and long base64 → `<token>`, UUID → `<uuid>`, secret `key=value` / `key: value` → `<x>`, domains under `SHELLGATE_REDACT_DOMAINS` → `<domain>`. A `"redacted"` field summarises the counts when anything was replaced.

### `run_script` 与 `stdin`

- `run_command` 新增可选参数 `stdin`：例如 `command="ssh host bash -s"`，脚本正文放在 `stdin`，不再需要多层引号转义。
- 新工具 `run_script(script, interpreter="sh", args=[], stdin, timeout, cwd, confirm_code)`：脚本写入 `mkdtemp` 创建的 0700 私有目录，执行后（包括超时、出错）总会删除。每次调用目录独立，可以并发。
- 危险命令检查会扫描**脚本的每一行**、命令里调用的本地脚本文件（`sh x.sh`、`./run.sh`、`. ./env`），以及喂给 shell/python 的 `stdin`；确认码绑定脚本内容、参数、stdin 和目录，内容一变就要重新确认。

`run_command` gains an optional `stdin`; the new `run_script` tool runs a script body from a private temp file that is always removed. The confirmation policy now scans every line of scripts, local script files a command executes, and stdin fed to an interpreter; confirm codes are bound to the exact script/args/stdin/cwd.

## 配置

见 [`deploy/env.example`](deploy/env.example)。常用项：

| 变量 | 默认 | 说明 |
|---|---|---|
| `SHELLGATE_MODE` | `full` | `full` 或 `allowlist` |
| `SHELLGATE_ALLOWED_COMMANDS` | 空 | allowlist 模式下允许的程序名 |
| `SHELLGATE_ALLOWED_DIRS` | `$HOME,/tmp` | 文件写入范围（allowlist 模式下读取也受限） |
| `SHELLGATE_PROTECTED_PATHS` | 空 | 额外禁止访问的路径 |
| `SHELLGATE_DANGER_PATTERNS` | 空 | 额外需要确认的正则 |
| `SHELLGATE_PORT` | `8790` | 监听端口 |
| `SHELLGATE_REDACT` | `1` | 输出脱敏；`0` 关闭（不建议） |
| `SHELLGATE_REDACT_DOMAINS` | 空 | 需要脱敏的域名后缀，逗号分隔（`example.org` 也匹配 `a.example.org`） |

## 安全须知

- `full` 模式等于把你这个用户的 shell 交给持有令牌的人。令牌泄露时立刻改 `SHELLGATE_TOKEN` 并重启服务。
- 危险命令检测是**护栏，不是沙箱**：刻意混淆的命令可能绕过。需要更严格时用 `allowlist` 模式。
- `run_command` 不受文件路径保护约束（文件工具才受约束）。
- 以普通用户运行，不要用 root。需要 sudo 的操作请自行配置精确的 sudoers 规则（NOPASSWD 只放行你需要的命令）。

## 开发

```bash
pip install -e ".[dev]"
pytest -q        # 单元测试 + 启动真实服务、用官方 MCP 客户端跑的端到端测试
```

MIT License
