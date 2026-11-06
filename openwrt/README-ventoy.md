# ShellGate 随身 Ventoy 救援盘版（v0.3.0）

同一个 Rust 单文件程序，现在可以在 **Linux（x86_64 musl 静态）** 和 **Windows（x86_64 .exe）** 上运行，并能直接管理插着的 Ventoy U 盘（增删镜像、改 `ventoy.json`）。

> 仓库里**不含任何令牌、隧道 token 或密码**。令牌只在刷 U 盘时由你在自己电脑上生成，写进 U 盘上的配置文件。

## U 盘上的文件

```
Ventoy 数据分区（卷标 Ventoy）
├── shellgate/
│   ├── shellgate.env        ← 配置（含令牌，只有这里有）
│   ├── shellgate.exe        ← Windows 版，双击运行
│   ├── shellgate-linux      ← Linux 版（救援 ISO 里也会内置一份）
│   ├── cloudflared.exe      ← 可选，隧道模式才需要
│   └── logs/                ← Windows 下的审计日志（自动创建）
├── iso/ …                   ← 各种镜像
└── ventoy/ventoy.json       ← Ventoy 配置
```

程序按这个顺序找配置：`--env-file 路径` → 环境变量 `SHELLGATE_ENV_FILE` → **程序同目录的 `shellgate.env`** → `/etc/shellgate/env`（Windows：`C:\ProgramData\shellgate\shellgate.env`）→ **`<Ventoy 分区>/shellgate/shellgate.env`**。

## 生成配置（刷盘时在你自己电脑上做一次）

```sh
shellgate --init-config /media/你/Ventoy/shellgate/shellgate.env     # Linux
shellgate.exe --init-config E:\shellgate\shellgate.env               # Windows
```

会生成一个随机令牌、写入配置（Linux 下权限 600）并**只显示一次**，已存在的文件不会被覆盖。也可以手写，**最少只要一行**：

```ini
token=这里换成至少32位的随机串
```

（`shellgate --gen-token` 可以只打印一个新令牌。没填、太短、或还是 `change-me` 这类模板值时程序拒绝启动。）

## 三种网络模式（一行切换）

| `net=` | 监听 | 适合 | 需要填 |
|---|---|---|---|
| 不写 / `local`（默认） | `127.0.0.1:8790` | 本机或你自己另起隧道/SSH | `token` |
| `lan` | `0.0.0.0:8790` | **和你在同一个局域网** | `token` + `net=lan` |
| `tunnel` | `127.0.0.1:8790` + 自动启动 cloudflared | 在外面、对方网络 | `token` + `tunnel_token`（写了 tunnel_token 时 `net` 可省略） |

所有模式都**强制** `Authorization: Bearer <令牌>`，`/health` 之外的请求没令牌一律 401。

### 局域网模式

```ini
token=…
net=lan
```

启动后终端会打印 `http://<本机局域网IP>:8790/mcp`。默认同时用 mDNS 广播 **`ventoy-rescue.local`**，客户端也可以填 `http://ventoy-rescue.local:8790/mcp`。
- 改名：`mdns_name=别的名字`；关闭：`mdns=0`。
- Windows 第一次运行会弹防火墙提示，选“专用网络”允许即可。
- mDNS 在 Linux 上已测试；Windows 用的是同一段代码，但**还没在真机验证**，Windows 自带的 mDNS 服务也占 5353 端口，万一 `.local` 解析不到，直接用打印出来的 IP。
- 局域网模式是明文 HTTP，只在你信任的网络里用；离开时关掉程序。

### 隧道模式（不开任何端口，只走出站）

```ini
token=…
tunnel_token=在 Cloudflare 后台为这个 U 盘单独建的隧道的 token
```

1. 在 Cloudflare Zero Trust 里新建一条**专用隧道**，公共主机名指向 `http://localhost:8790`。
2. 把 `cloudflared`（Windows 下 `cloudflared.exe`）放在 shellgate 同目录或 PATH 里，或用 `cloudflared=完整路径` 指定。
3. ShellGate 会启动并守护 `cloudflared tunnel --no-autoupdate run`，崩了自动重启。隧道 token 通过环境变量 `TUNNEL_TOKEN` 传给它，**不出现在命令行/进程列表里**；cloudflared 日志写在受保护的 `logs/cloudflared.log`。
4. 客户端填 `https://<你的主机名>/mcp`。

**U 盘丢了**：在 Cloudflare 后台删掉这条隧道，并换掉其他地方用的令牌即可作废。

## 在别人电脑上怎么用

- **Windows**：打开 U 盘 `shellgate\shellgate.exe`（双击即可，窗口里能看到日志；关窗口或 Ctrl+C 即停止，cloudflared 一起退出）。
- **Linux 救援系统**：运行 `shellgate`；Ventoy 分区已挂载时自动找到配置。没挂载时先 `mount /dev/disk/by-label/Ventoy /mnt/ventoy`，或在已启动的服务里调用 `ventoy_info` 加 `mount=true`（挂到 `/mnt/ventoy`）。也可以用 `ventoy_root=/某路径` 或环境变量 `VENTOY_ROOT` 指定。
- 在别人电脑上运行前，请先征得机主同意。

## 在各种 PE 里自动启动

模板都在 `openwrt/pe-autostart/`，**都不含令牌**：令牌只在 U 盘的 `shellgate/shellgate.env` 里。按你要用的 PE 选一种或几种（互不冲突，重复启动时第二个会因端口占用直接退出）：

| PE | 放什么 | 原理 |
|---|---|---|
| 官方 WinPE / Windows 安装盘（原版 ISO） | `ventoy/shellgate-inject.7z`（用 `pe-autostart/make-inject.sh shellgate.exe` 打包）+ `ventoy.json` 里 `"injection": [{"parent": "/ISO", "archive": "/ventoy/shellgate-inject.7z"}]` | Ventoy 注入插件把 `VentoyAutoRun.bat` 和 `X:\shellgate\shellgate.exe` 放进内存盘，在 winpeshl 之前执行 |
| FirPE | `FirPE/Hooks/onBootFinished.cmd` + `shellgate/pe-start.cmd` | FirPE 生命周期钩子，所有服务启动完后执行（钩子文件按 GBK 读，模板只用 ASCII） |
| HotPE | `HotPE/HotPE.INI` + `shellgate/pe-start.cmd` | HotPE 启动时加载任意盘 `\HotPE\HotPE.INI`（PECMD 脚本） |
| 微PE（WePE） | `WEPE/WEPE.INI` + `shellgate/pe-start.cmd` | 微PE 启动时 `PECMD LOAD \WEPE\WEPE.INI` |
| 其他 PE / 手动 | `shellgate/pe-start.cmd` | 双击或在命令行运行；它在所有盘符里找 `\shellgate\shellgate.exe` + `shellgate.env` |

`pe-start.cmd` 与钩子模板都要求 U 盘上有 `shellgate/shellgate.exe` 和 `shellgate/shellgate.env`。

**WinPE 里程序会自动做的事（v0.3.x）**

- 识别 WinPE（注册表 `MiniNT`），`system_info` 返回 `winpe`、`powershell`、`os_version`。
- `net=lan|tunnel` 时：没有 IPv4 地址就执行 `wpeutil InitializeNetwork` 并等最多 90 秒；`lan` 模式再执行 `wpeutil DisableFirewall`（PE 防火墙默认挡入站）。结果写到 `<state_dir>/pe-network.log` 和控制台。不想要就写 `pe_network=0`。
- 允许写入的目录自动加上 `X:\`（内存盘，重启即丢）和 `%TEMP%`；`X:\Windows\System32\config` 仍受保护。
- 以 SYSTEM 身份运行时，工作目录不再落在受保护的 `systemprofile`，改用 `X:\Users\Public` 或临时目录。
- `run_script` 没指定解释器而 PowerShell 不可用（多数 PE 没装）时自动改用 cmd，并在结果里给 `note`；明确指定 `powershell` 但不可用则直接报错说明。
- cmd 脚本按系统 OEM 代码页（中文系统是 GBK）写入，中文 `echo` 正常；有代码页表示不了的字符（如 emoji）时，脚本自动先 `chcp 65001` 再按 UTF-8 写入。
- 输出逐行判断编码：UTF-8 行按 UTF-8，其余按 OEM 代码页，混合输出（如 GBK 的 `ipconfig` + UTF-8 程序）不再乱码。
- mDNS 等拿到局域网地址后才开始应答，5353 端口暂时打不开会自动重试，地址变化会重新广播。

## 新增工具

| 工具 | 作用 |
|---|---|
| `ventoy_info` | 找到 Ventoy 数据分区：路径、文件系统、容量/剩余、Ventoy 版本（VTOYEFI 分区可读时）、`ventoy/ventoy.json` 是否存在；Linux 下 `mount=true` 可自动挂载 |
| `ventoy_list` | 列出 `.iso .wim .img .vhd .vhdx .efi .vtoy`，含大小、修改时间；同时列出没下完的临时文件 |
| `ventoy_add` | 从 http(s) 下载镜像到分区（后台任务，返回 `task_id`），可选 `sha256` 校验；校验失败、中断、取消都会删掉临时文件；不覆盖已有文件；FAT32 分区拒绝 >4 GiB；空间不够提前拒绝；支持 `HTTPS_PROXY` |
| `ventoy_add_status` | 下载进度（百分比、速度）；`cancel=true` 取消 |
| `ventoy_remove` | 删除镜像，**必须走一次性确认码** |
| `ventoy_config_get` / `ventoy_config_set` | 读写 `ventoy/ventoy.json`；写之前校验必须是合法 JSON 对象，旧文件自动备份为 `ventoy.json.bak-时间戳` |

这些工具参数都不经过 shell，路径只能落在 Ventoy 分区里（拒绝 `..`、绝对路径、盘符）。

## Windows 上的差异

- `run_command`：`cmd /D /S /C "<命令>"`；配置 `shell=powershell` 则改用 PowerShell。
- `run_script`：解释器 `powershell`（默认）、`pwsh`、`cmd`、`python`。
- 超时/取消：`taskkill /T /F /PID` 杀整个进程树。
- 新增需要确认码的危险命令：`format X:`、`diskpart`（含脚本里单独一行 `clean`）、`del /s`、`rd /s`、`Remove-Item -Recurse`、`bcdedit /set|/delete…`、`bcdboot`、`Format-Volume`、`Clear-Disk`、`Initialize-Disk`、`Remove-Partition`、`shutdown`、`Stop-Computer`、`Restart-Computer`、`reg delete/import/load`、`cipher /w`、`vssadmin delete`、`manage-bde -off`、停止/删除服务、杀 cloudflared/shellgate/系统关键进程、禁用网卡、`\\.\PhysicalDrive` 原始磁盘访问等（Linux 上同样生效）。
- 受保护路径新增：`%SystemRoot%\System32\config`（SAM、SYSTEM、SECURITY、SOFTWARE 注册表文件）、`NTDS`、`NTUSER.DAT`；另外任何路径里的 `Windows/System32/config`（包括 Linux 下挂载的 Windows 盘）都禁止用文件工具读写。
- 输出脱敏规则不变。

## 配置项一览（都可省略，除了 token）

```ini
token=                # 必填，≥32 位
net=local|lan|tunnel
tunnel_token=         # 隧道模式
cloudflared=          # cloudflared 路径（默认同目录或 PATH）
mdns=1|0              # lan 模式默认 1
mdns_name=ventoy-rescue
ventoy_root=          # 找不到卷标 Ventoy 时手动指定
port=8790
host=                 # 一般不用填：lan → 0.0.0.0，其他 → 127.0.0.1
state_dir=            # 审计日志目录（Linux 默认 /var/log/shellgate，Windows 默认配置旁的 logs\）
pe_network=1|0        # WinPE + lan/tunnel：自动 wpeutil InitializeNetwork；lan 再关 PE 防火墙（默认 1）
```

短名字（`token`）和完整名字（`SHELLGATE_TOKEN`）等价，原有的 `SHELLGATE_*` 配置项全部照旧可用。

## 编译

```sh
pip install ziglang cargo-zigbuild
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
cd openwrt
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target x86_64-pc-windows-gnu
```

测试：`cargo test`；端到端：
`SHELLGATE_BIN=openwrt/target/release/shellgate pytest -q tests/test_e2e.py tests/test_ventoy_e2e.py`

## 已知限制

- Windows 版需要 **Windows 10 / Server 2016 及以上**（含 Win10 PE）；Win7/8.1 不支持。
- Windows 版已在 Win11 真机，以及 FirPE、HotPE、官方 Windows 安装环境 PE（QEMU 虚拟机）里测试；微PE 只做了启动方式验证；mDNS 在 Windows 上未验证。
- **FirPE、HotPE 用自己的 PECMD 外壳，不执行 Ventoy 的 `VentoyAutoRun.bat`**：注入包对它们无效，要用上表的钩子 / INI。
- **官方 WinPE 只有执行过 `wpeinit` 才有网络和即插即用**。Ventoy 注入的 `VentoyAutoRun.bat` 在 wpeinit 之前运行，所以 lan/tunnel 模式下程序会自己 `wpeutil InitializeNetwork`；`local` 模式不动网络。Windows 安装程序界面出来后它自己也会初始化网络。
- 多数 PE 没有 PowerShell、`where`、`whoami`；脚本请用 cmd 写。
- PE 跑在内存里：`X:\` 上写的东西重启就没了，要留的写到 U 盘或硬盘。
- 局域网模式在 PE 里会关掉 PE 的防火墙（只影响这次 PE 会话，不影响硬盘上的系统）。
- Linux 下按卷标找分区依赖 `/dev/disk/by-label`（udev）；极简系统没有 udev 时请用 `ventoy_root=` 指定。
- Ventoy 版本号只能在 VTOYEFI 分区可读（已挂载/有盘符）时读到，否则返回 `null`。
- ShellGate 被强杀（kill -9 / 任务管理器结束）时，cloudflared 子进程可能残留，需要手动结束。
- 路由器（OpenWrt）发布包用 `--no-default-features` 编译，不含 `ventoy_add` 的下载功能，以保持体积。
