# FirPE 2.1.0 / HotPE 2.8 功能对照

方法：用 7-Zip 只读列出两个 ISO 及其中 WIM 的目录、菜单（`MENU.LST`/`TOOLS.LST`/`HotPE.INI`/`Pecmd.ini`）。
没有运行、也没有提取任何程序进本仓库或自建镜像。

## 它们有什么（按类）

| 类别 | FirPE 2.1.0 | HotPE 2.8 |
|---|---|---|
| 分区与磁盘 | DiskGenius、分区助手 PartAssist、BOOTICE、Defraggler；DOS 版 DG.IMG、MHDD | DiskGenius、PartAssist（HPM 模块）、BOOTICE |
| 备份还原 / 装机 | CGI、Dism++、EasyRC、WinNTSetup 5.x（含 MinWin、WimBoot） | Dism++、WinNTSetup 5.4、WIT、Ghost64（MoreTools） |
| 引导修复 | NTBOOTautofix、BOOTICE | NT6Bootfix、NTBootAutofix、Fixboot |
| 密码重置 | WindowsLoginUnlocker | NTPWEdit |
| 数据恢复 | Recuva、WinHex | Recuva、WinHex |
| 硬件检测 | AIDA64、CPU-Z、CrystalDiskInfo、DisplayX、键盘测试、MemTest、蓝屏分析 | AIDA64、CPU-Z、HDTune、DisplayX、键鼠测试、BlueScreenView、内存测试 |
| 网络 | PENetwork、AutoWIFI、网卡驱动包 NETWORK.7Z（按需解压） | 网卡驱动包 Network.7z + DrvIndex（按需解压） |
| 远程 | 远程协助、Mstsc、Dufs 文件共享、访问共享 | RDTools |
| 文件管理 | Explorer（精简）、Everything、FastCopy、SpaceSniffer、7-Zip | Explorer、Everything、WizTree、FastCopy、7-Zip |
| 浏览器 / 下载 | 360Chrome、迅雷 | Browser（C86）、迅雷、aria2（壁纸用） |
| 外壳 / 体验 | WinXShell + StartAllBack 开始菜单、搜狗五笔、Edgeless 插件系统（ept 包管理）、主题/壁纸 | WinXShell + StartAllBack、搜狗输入法、HPM 模块（U 盘 `HotProgMods\*.HPM` 自动加载）、Edgeless 插件、在线壁纸、AutoDPI |
| 驱动 | 外置驱动包 + orderdrv | 外置驱动包 Network.7z/SRS.7z，DrvIndex 按硬件只解需要的 |
| 多分辨率 | DisplaySwitch.wcs | AutoDPI.WCS |
| 启动 | grub4dos 菜单：Win11PE / Win2003PE（老机）/ DiskGenius DOS / MaxDos / grubfm | 直接 bootmgr |

## ShellGate PE 的对应方案

| 类别 | ShellGate PE 内置（开源可再分发） | 构建时下载并校验 sha256（免费不可再分发，仅 `-Full` 自用） | 缺口 / 说明 |
|---|---|---|---|
| 分区与磁盘 | diskpart、`win-disk.cmd layout`（GPT/MBR 一键分区）、PowerShell Storage cmdlets（Get-Disk/Initialize-Disk/New-Partition）、TestDisk | — | **DiskGenius、分区助手无合规替代**（无损调整分区大小、坏道扫描）。GParted 是 Linux 程序，可另放 GParted Live ISO 到同一 Ventoy 盘。DiskGenius 可手动放 `-Extras`。 |
| 备份还原 / 装机 | dism（Apply/Capture）、wimlib-imagex（WIM/ESD/SWM）、`win-install.cmd`（WinNTSetup 思路：Vista~11 释放 + bcdboot；XP 拷 I386 + ntldr + winnt.sif）、unattend.xml / winnt.sif | — | **Ghost/GHO 无合规替代**（Ghost 专有）；CGI/Dism++/EasyRC 是免费闭源、不可再分发，不内置；GHO 先在别处转 WIM。 |
| 引导修复 | bcdboot、bcdedit、bootsect（ADK）、`win-disk.cmd fixboot nt52/nt60` | — | 图形化 NTBOOTautofix 不内置，命令行等价。 |
| 密码重置 | 离线 hive 挂载（`win-offline.cmd`，reg load） | — | **清空/解锁密码需 NTPWEdit 或 chntpw**：NTPWEdit 免费不可再分发且官网直链失效；chntpw 是 GPL 但无官方 Windows 版。放到盘上 `plugins\` 自动加载。 |
| 数据恢复 | PhotoRec / QPhotoRec（GUI）、TestDisk | — | Recuva/WinHex 免费或付费闭源，不内置。 |
| 硬件检测 | smartctl、wmic、PowerShell `Get-PhysicalDisk`/`Get-CimInstance`、`systeminfo` | CPU-Z（`-Full`） | AIDA64、HDTune 付费；CrystalDiskInfo 是 MIT 但 SourceForge 无稳定直链/哈希，暂以 smartctl 代替。 |
| 网络 | WinPE 网络栈 + Dot3Svc（802.1X）、PPPoE、RNDIS（手机 USB 共享）、自动 `wpeutil InitializeNetwork`、virtio NetKVM | — | **Wi-Fi：WinPE 官方没有无线栈**，用 `-Base winre`（取本机 WinRE）+ 厂商驱动；仍不支持 WPA 企业网的图形配置，用 `netsh wlan` 命令。 |
| 远程 | **ShellGate（MCP，自启）+ cloudflared 隧道**、dufs 文件共享、截图键鼠工具（desktop=on） | — | 远程协助/Mstsc 是 Windows 组件，WinPE 里没有；用 ShellGate 的截图 + 键鼠代替。 |
| 文件管理 | Explorer++、7-Zip 7zFM、Notepad++ | Everything（`-Full`） | FastCopy 是免费闭源，用 `robocopy` 代替。 |
| 浏览器 | — | — | **缺口**：现代浏览器在 WinPE 里缺依赖（无 WebView2、无 Media Foundation），且 Chromium 系体积大；文件下载用 aria2c / PowerShell `Invoke-WebRequest`。 |
| 外壳 / 开始菜单 | cmd 文本菜单（总可用）+ HTA 图形菜单 | — | WinXShell、StartAllBack 闭源不可再分发；HTA 菜单是开源的最小替代，没有任务栏。 |
| 外置插件目录 | Ventoy 盘 `\shellgate\plugins\`：`*.7z` 自动解压并执行 `autorun.cmd`，`*.cmd` 直接执行（参考 HotPE HPM / Edgeless 的“放进去就加载”） | — | 不兼容 HPM/Edgeless 包格式（它们依赖 PECMD）。 |
| 驱动自动加载 | 构建时注入（virtio、`-Drivers`）；开机 `drvload` 盘上 `\shellgate\drivers\**\*.inf` | — | 不做 DrvIndex 那种按硬件 ID 只解压所需的索引包；Intel RST/VMD 需手动下载（Intel 对脚本下载返回 403）。 |
| 多分辨率 | `shellgate --display max|1920x1080|list`（ChangeDisplaySettings），开机按 `pe.ini` 设置 | — | 只能在显卡驱动提供的模式里选；基本显示驱动通常最高 1920x1080 或更低。 |
| 老机器 | x86 版（ADK 2004）；IDE/AHCI 由 WinPE 自带驱动 | — | **Win2003 PE（FirPE 的老机型选项）不提供**：它基于 Windows Server 2003 文件，不能合规再造；不支持 PAE/NX/SSE2 的 CPU 无法启动 Win10 系 PE。 |
