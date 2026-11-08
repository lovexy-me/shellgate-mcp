@echo off
rem ============================================================================
rem win-disk.cmd -- 破坏性磁盘操作（分区、写引导、引导修复）。XP ~ Win11。
rem 单独成文件，是为了让 ShellGate 的安全策略扫到 diskpart/bcdboot/bootsect 并要确认码。
rem
rem   win-disk.cmd layout  <disk> <uefi|bios> [espMB] [--apply]
rem        GPT(UEFI): ESP(FAT32,S:) + MSR + Windows(NTFS,W:)
rem        MBR(BIOS): 单个活动 NTFS 分区(W:)，XP/7/10 通用
rem        不加 --apply 只打印 diskpart 脚本（预演）；盘符默认 W:，可先 set WINLTR=V 改
rem   win-disk.cmd boot    <windows:> <system:> [bios|uefi] [nt52|nt60]
rem        Vista+ : bcdboot <windows:>\Windows /s <system:> /f BIOS|UEFI /l zh-cn
rem        XP     : bootsect /nt52 <system:> /force /mbr + 写 boot.ini
rem   win-disk.cmd fixboot <system:> [nt52|nt60]
rem        nt52: NTLDR 引导扇区+MBR；nt60: BOOTMGR 引导扇区+MBR，并对找到的每个 Windows 跑 bcdboot
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
set "PEDIR=X:\Program Files\ShellGatePE"
set "BOOTSECT=%PEDIR%\bin\bootsect.exe"
if not exist "%BOOTSECT%" if exist X:\Windows\System32\bootsect.exe set "BOOTSECT=X:\Windows\System32\bootsect.exe"
if /i "%~1"=="" goto :help
if /i "%~1"=="help" goto :help
if /i "%~1"=="layout" goto :layout
if /i "%~1"=="boot" goto :boot
if /i "%~1"=="fixboot" goto :fixboot
echo 未知子命令 %1
:help
findstr /b "rem " "%~f0" | findstr /v "===="
exit /b 0

rem ---------------------------------------------------------------- layout
:layout
set "DISK=%~2" & set "FW=%~3" & set "ESP=%~4" & set "GO=%~5"
if "%DISK%"=="" echo 用法: win-disk layout ^<disk号^> ^<uefi^|bios^> [espMB] [--apply] & exit /b 2
if "%FW%"=="" set "FW=uefi"
if "%ESP%"=="" set "ESP=300"
if /i "%ESP%"=="--apply" (set "ESP=300" & set "GO=--apply")
if not defined WINLTR set "WINLTR=W"
set "S=X:\dp-layout.txt"
> "%S%" echo select disk %DISK%
if /i "%FW%"=="uefi" (
  >> "%S%" echo clean
  >> "%S%" echo convert gpt
  >> "%S%" echo create partition efi size=%ESP%
  >> "%S%" echo format quick fs=fat32 label="ESP"
  >> "%S%" echo assign letter=S
  >> "%S%" echo create partition msr size=16
  >> "%S%" echo create partition primary
  >> "%S%" echo format quick fs=ntfs label="Windows"
  >> "%S%" echo assign letter=%WINLTR%
) else (
  >> "%S%" echo clean
  >> "%S%" echo convert mbr
  >> "%S%" echo create partition primary
  >> "%S%" echo format quick fs=ntfs label="Windows"
  >> "%S%" echo assign letter=%WINLTR%
  >> "%S%" echo active
)
echo --- diskpart 脚本 ---
type "%S%"
if /i not "%GO%"=="--apply" (echo [预演] 未执行。加 --apply 才真正分区。& exit /b 0)
diskpart /s "%S%"
exit /b %errorlevel%

rem ---------------------------------------------------------------- boot
:boot
set "WT=%~2" & set "ST=%~3" & set "FW=%~4" & set "NT=%~5"
if "%ST%"=="" echo 用法: win-disk boot ^<Windows盘:^> ^<系统分区:^> [bios^|uefi] [nt52^|nt60] & exit /b 2
if "%FW%"=="" set "FW=bios"
if /i "%NT%"=="nt52" goto bootxp
if exist "%WT%\Windows\System32\ntoskrnl.exe" goto bootnt6
if exist "%WT%\WINDOWS\system32\ntoskrnl.exe" if not exist "%WT%\Windows\Boot" goto bootxp
:bootnt6
set "F=BIOS"
if /i "%FW%"=="uefi" set "F=UEFI"
echo bcdboot %WT%\Windows /s %ST% /f %F% /l zh-cn
bcdboot %WT%\Windows /s %ST% /f %F% /l zh-cn
exit /b %errorlevel%
:bootxp
echo [XP] bootsect /nt52 %ST% /force /mbr
if not exist "%BOOTSECT%" (
  echo [!] 本 PE 没有 bootsect.exe（ADK 的 WinPE-Setup/LegacySetup 组件里有，或从安装源 boot\bootsect.exe 取）。
  echo     替代：用 Ventoy 的 grub 直接链式引导 ntldr，或在目标机用 XP 安装盘修复控制台 fixboot/fixmbr。
) else (
  "%BOOTSECT%" /nt52 %ST% /force /mbr
)
> "%ST%\boot.ini" echo [boot loader]
>> "%ST%\boot.ini" echo timeout=5
>> "%ST%\boot.ini" echo default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
>> "%ST%\boot.ini" echo [operating systems]
>> "%ST%\boot.ini" echo multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Windows" /fastdetect
attrib +s +h +r "%ST%\boot.ini" 2>nul
echo 已写 %ST%\boot.ini（如系统不在第 1 分区，请手工改 partition(n)）
exit /b 0

:fixboot
set "S=%~2" & set "M=%~3"
if "%S%"=="" echo 用法: win-disk fixboot ^<系统分区:^> [nt52^|nt60] & exit /b 2
if /i "%M%"=="nt52" (
  if exist "%BOOTSECT%" ("%BOOTSECT%" /nt52 %S% /force /mbr) else echo 没有 bootsect.exe，见 win-disk boot 的说明
) else (
  if exist "%BOOTSECT%" ("%BOOTSECT%" /nt60 %S% /force /mbr)
  for %%d in (C D E F G H I J K L M N O P) do if exist "%%d:\Windows\System32\ntoskrnl.exe" (
    echo bcdboot %%d:\Windows /s %S% /l zh-cn
    bcdboot %%d:\Windows /s %S% /l zh-cn
  )
)
exit /b %errorlevel%

