# ShellGate PE —— 自建 Ventoy 救援 PE（只放构建脚本）

在**你自己的 Windows** 上一条命令生成一个中文 WinPE 救援镜像：开机自动联网、自动拉起 ShellGate（MCP），
带 PowerShell / WMI / BitLocker / 中文字体、常用救援工具、装机与引导修复脚本。产物是 ISO（BIOS+UEFI 双启动）
和 WIM，直接丢进 Ventoy 盘即可。

## 许可证说明（为什么仓库里没有 ISO）

- 微软 ADK/WinPE 许可不允许公开分发预制的 WinPE 镜像。所以本仓库与 Release **只有脚本**；镜像只能在你自己的机器上
  （或 CI 内部）生成，生成的镜像供你自己用，不要公开上传。
- 公开仓库的 Actions artifact 任何登录用户都能下载，所以 CI 默认**只构建、只校验、不上传镜像**；只有手动触发并给出
  age 公钥时，ISO 才会被加密后上传，保留 1 天，私钥只在维护者自己的机器上。
- 第三方工具一律在构建时从官方地址下载并校验 sha256（`tools.json`），不进仓库。不允许再分发的免费软件
  （CPU-Z、Everything 等）默认不装，加 `-Full` 才装，且那样的镜像更不能分享。
- 不从 FirPE / HotPE 等任何别人的 PE 里提取文件。

## 一条命令构建

管理员 PowerShell，在仓库根目录：

```powershell
powershell -ExecutionPolicy Bypass -File openwrt\pe-build\Build-ShellGatePE.ps1 -Arch amd64 -Out D:\sgpe -ShellGate dist\shellgate-x86_64-windows.exe
```

- 第一次会自动静默安装 ADK（只装“部署工具”）+ WinPE 加载项，约 3 GB，之后加 `-SkipAdkInstall`。
- 输出：`D:\sgpe\ShellGatePE-amd64.iso`、`ShellGatePE-amd64.wim`、`build-report-amd64.json`（装了哪些组件/工具）。
- 校验：`openwrt\pe-build\Test-ShellGatePE.ps1 -Out D:\sgpe -Arch amd64`（只读挂载检查组件、PowerShell、ShellGate、工具）。

常用参数：

| 参数 | 作用 |
|---|---|
| `-Arch x86` | 32 位 PE。新 ADK 已无 x86 WinPE，脚本自动改用 ADK 2004（最后一版带 x86）。**CPU 需支持 PAE、NX、SSE2**（奔腾 4 Prescott 以后）。 |
| `-Base winre` | 改用本机 `C:\Recovery\WindowsRE\Winre.wim` 作底座，**获得 Wi-Fi**（WinPE 官方没有无线栈）。 |
| `-Drivers D:\drv` | 额外驱动目录（递归找 .inf）。Intel RST/VMD、厂商网卡驱动放这里。 |
| `-Extras D:\tools` | 你自己的工具目录，原样复制进 `X:\Program Files\ShellGatePE\`。 |
| `-Full` | 也装不可再分发的免费工具（仅自用）。 |
| `-ScratchMB 512` | WinPE scratch 空间（默认 512 MB）。 |

## 放进 Ventoy

```
Ventoy盘\
  ShellGatePE-amd64.iso          ← 构建产物
  shellgate\
    shellgate.env                 ← 只需一行 token=（用 shellgate --gen-token 生成）；可加 net=lan / tunnel_token=
    pe.ini                        ← 可选：resolution=max 或 1920x1080
    drivers\                      ← 可选：开机自动 drvload 这里所有 .inf（外置驱动）
    plugins\                      ← 可选：*.7z 自动解到 X:\Plugins\<名字>\ 并执行其中 autorun.cmd；*.cmd 直接执行
    logs\                         ← 自动生成：pe-<日期>.log、ShellGate 审计日志
```

镜像里**没有任何令牌**：没有 `shellgate.env` 时 ShellGate 不启动，菜单照常可用。Legacy BIOS 与 UEFI 两种 Ventoy
模式都能启动（ISO 用 oscdimg 生成的 El Torito 双引导）。

## 启动流程（startnet.cmd → shellgate-pe.cmd → menu）

1. `wpeinit`（PnP、网络栈）；`chcp 936` 中文代码页。
2. 找 Ventoy 盘（第一个有 `\shellgate\shellgate.env` 的盘），日志写到 `\shellgate\logs\`。
3. 自动加载外置驱动、插件；按 `pe.ini` 调分辨率（默认取 ≤1920 宽的最大模式）。
4. 拉起 ShellGate：联网按 `net=` 与 `pe_network`（lan/tunnel 时无 IPv4 自动 `wpeutil InitializeNetwork`，lan 再关防火墙）。
5. 菜单：有 WinPE-HTA 时弹图形菜单（`menu.hta`），同时保留 cmd 菜单（总是可用）。

## 组件（全部 + zh-cn 语言包）

WMI、NetFX、Scripting、PowerShell、StorageWMI、DismCmdlets、SecureBootCmdlets、EnhancedStorage、SecureStartup
（BitLocker / manage-bde）、FMAPI、PlatformId、HTA、MDAC、Dot3Svc（802.1X 有线）、PPPoE、RNDIS（手机 USB 共享网络）、
WDS-Tools、SRT、Setup、LegacySetup、WinReCfg、Rejuv、GamingPeripherals、FontSupport-ZH-CN。ADK 里没有的会在报告里
列为 missing，不会中断构建。

## 工具

| 工具 | 用途 | 许可证 | 进镜像方式 |
|---|---|---|---|
| ShellGate | MCP 远程（自启） | MIT（本仓库） | 构建时复制 |
| cloudflared | 隧道模式 | Apache-2.0 | 构建时下载 + sha256 |
| 7-Zip（7za + 7zFM） | 压缩、解 ISO | LGPL-2.1 | 构建时下载 + sha256 |
| wimlib-imagex | WIM/ESD/SWM 释放与捕获 | GPL-3/LGPL-3 | 构建时下载 + sha256 |
| TestDisk / PhotoRec / QPhotoRec | 分区表恢复、文件恢复 | GPL-2+ | 构建时下载 + sha256 |
| Explorer++ | 文件管理器 | GPL-3 | 构建时下载 + sha256 |
| Notepad++ portable | 编辑器 | GPL-3 | 构建时下载 + sha256 |
| aria2c | 断点续传下载 | GPL-2+ | 构建时下载 + sha256 |
| dufs | 一条命令 HTTP 文件共享（手机取数据） | MIT/Apache-2 | 构建时下载 + sha256（仅 x64） |
| smartctl | 硬盘 SMART | GPL-2+ | 构建时下载（SourceForge 无固定哈希，需 `-AllowUnpinned`） |
| bootsect.exe | NTLDR/BOOTMGR 引导扇区 | ADK 自带 | 从本机 ADK 复制 |
| virtio-win | VM 用的存储/网卡驱动 | GPL-2/BSD | 构建时下载 + sha256 |
| CPU-Z、Everything | 硬件信息、文件搜索 | 免费不可再分发 | 仅 `-Full` |
| DiskGenius、Intel RST/VMD、NTPWEdit | 分区/恢复、NVMe 驱动、改密码 | 免费不可再分发且无稳定直链 | 手动放 `-Extras` / `-Drivers` / 盘上 plugins |

## 装机与修复脚本（PE 内 `X:\Program Files\ShellGatePE\bin`）

- `win-install.cmd apply <源> <目标:> [--index N] [--drivers DIR] [--unattend FILE]`：
  Vista~11 用 `dism /Apply-Image`（失败退回 wimlib-imagex），支持 WIM/ESD/SWM、已解包的 ISO 目录；
  XP/2003 识别源里的 `I386`/`AMD64`，拷贝安装源、放置 `ntldr`(=setupldr.bin)+`ntdetect.com`、`$WIN_NT$.~BT\winnt.sif`。
- `win-disk.cmd layout|boot|fixboot`：分区（GPT/MBR）、`bcdboot`（Vista+）或 `bootsect /nt52`+`boot.ini`（XP）。
  破坏性操作单独成文件，ShellGate 的安全策略会扫到 diskpart/bcdboot/bootsect 并要确认码。
- `win-offline.cmd users|reg|password`：离线 hive（XP~11 通用）；改密码交给放进 plugins 的 NTPWEdit/chntpw。

GHO：Ghost 是专有软件且不可再分发，不内置；有 ghost64.exe 的放进 plugins 可用，否则先转 WIM。

## 参考 FirPE / HotPE 后的功能对照

见 [COMPARISON.md](COMPARISON.md)（只读列出了两者 ISO 的目录与菜单，没有提取或运行其中任何程序）。
