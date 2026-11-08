@echo off
rem ============================================================================
rem win-install.cmd -- 在 ShellGate PE 里安装 Windows XP ~ Windows 11 (x86/x64)
rem
rem   （分区和写引导是破坏性操作，放在 win-disk.cmd：layout / boot / fixboot）
rem   win-install.cmd apply   <source> <target:> [--drivers DIR] [--unattend FILE] [--index N]
rem        Vista+ : wim/esd/swm 用 dism 释放（dism 不行时退回 wimlib-imagex），iso 自动挂载取 install.wim
rem                 gho 需要 ghost（不可再分发，不内置）
rem        XP/2003: 源目录里的 I386/AMD64 整体拷到 C:\，写 winnt.sif，准备 $WIN_NT$.~BT 引导
rem   win-install.cmd drivers <target:> <driverDir>      Vista+ dism /Add-Driver /Recurse
rem   win-install.cmd check   <target:>                  装完自检
rem
rem 本文件只做释放/驱动/自检，不含分区与写引导，ShellGate 下可直接运行。
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
set "PEDIR=X:\Program Files\ShellGatePE"
set "WIMLIB=%PEDIR%\wimlib\wimlib-imagex.exe"
if /i "%~1"=="" goto :help
if /i "%~1"=="help" goto :help
if /i "%~1"=="layout" (echo 分区请直接运行 win-disk.cmd layout ...（破坏性操作单独成文件，ShellGate 会要确认码）& exit /b 2)
if /i "%~1"=="apply" goto :apply
if /i "%~1"=="boot" (echo 写引导请直接运行 win-disk.cmd boot ...& exit /b 2)
if /i "%~1"=="drivers" goto :drivers
if /i "%~1"=="check" goto :check
echo 未知子命令 %1 & goto :help

:help
for /f "usebackq tokens=* delims=" %%L in ("%~f0") do (set "L=%%L" & if "!L:~0,4!"=="rem " if not "!L:~4,4!"=="====" echo(!L:~4!)
exit /b 0

rem ---------------------------------------------------------------- apply
:apply
set "SRC=%~2" & set "TGT=%~3"
if "%TGT%"=="" echo 用法: win-install apply ^<源^> ^<目标盘:^> [--index N] [--drivers DIR] [--unattend FILE] & exit /b 2
set "IDX=1" & set "DRV=" & set "UNA="
:apa
shift & shift & shift
:apl
if "%~1"=="" goto apd
if /i "%~1"=="--index" (set "IDX=%~2" & shift)
if /i "%~1"=="--drivers" (set "DRV=%~2" & shift)
if /i "%~1"=="--unattend" (set "UNA=%~2" & shift)
shift & goto apl
:apd
if not exist "%TGT%\" echo 目标盘 %TGT% 不存在 & exit /b 2

rem ---- XP/2003: 源目录含 I386 或 AMD64
if exist "%SRC%\I386\" goto xp
if exist "%SRC%\AMD64\" goto xp
if exist "%SRC%\i386\" goto xp

rem ---- ISO: 挂载后找 sources\install.*
for %%F in ("%SRC%") do if /i "%%~xF"==".iso" (
  echo [i] ISO 需先挂载：PE 下用 "imdisk" 或把 ISO 解包到目录后再传目录。
  echo     ShellGate 里通常直接传 Ventoy 盘上已解包的目录，或用 7za x 解到临时盘。
  exit /b 2
)
set "WIM=%SRC%"
if exist "%SRC%\sources\install.wim" set "WIM=%SRC%\sources\install.wim"
if exist "%SRC%\sources\install.esd" set "WIM=%SRC%\sources\install.esd"
if not exist "%WIM%" echo 找不到镜像 %WIM% & exit /b 2
for %%F in ("%WIM%") do if /i "%%~xF"==".gho" (
  echo [x] GHO 需要 Norton Ghost（专有、不可再分发，不内置）。
  echo     可行替代：把 GHO 在别处还原后用 wimlib-imagex capture 成 WIM，再用本脚本释放。
  exit /b 3
)
echo [1/3] 释放 %WIM% (index %IDX%) -^> %TGT%
dism /Apply-Image /ImageFile:"%WIM%" /Index:%IDX% /ApplyDir:%TGT%\
if errorlevel 1 (
  echo [!] dism 失败，改用 wimlib-imagex
  if not exist "%WIMLIB%" echo 没有 wimlib-imagex & exit /b 1
  "%WIMLIB%" apply "%WIM%" %IDX% %TGT%\ || exit /b 1
)
if defined DRV (
  echo [2/3] 注入驱动 %DRV%
  dism /Image:%TGT%\ /Add-Driver /Driver:"%DRV%" /Recurse /ForceUnsigned
)
if defined UNA (
  echo [3/3] 无人值守 %UNA% -^> %TGT%\Windows\Panther\unattend.xml
  if not exist "%TGT%\Windows\Panther" mkdir "%TGT%\Windows\Panther"
  copy /y "%UNA%" "%TGT%\Windows\Panther\unattend.xml" >nul
)
echo 完成。下一步: win-disk boot %TGT% ^<系统分区:^> ^<bios^|uefi^>
exit /b 0

:xp
echo [XP/2003 模式] 源 %SRC%
set "ARCHDIR=I386"
if exist "%SRC%\AMD64\" set "ARCHDIR=AMD64"
echo [1/4] 拷贝 %ARCHDIR% -^> %TGT%\%ARCHDIR%
xcopy "%SRC%\%ARCHDIR%" "%TGT%\%ARCHDIR%\" /E /I /H /Y /Q || exit /b 1
if exist "%SRC%\I386\" if /i not "%ARCHDIR%"=="I386" xcopy "%SRC%\I386" "%TGT%\I386\" /E /I /H /Y /Q
echo [2/4] 准备 $WIN_NT$.~BT 文本安装引导
if not exist "%TGT%\$WIN_NT$.~BT" mkdir "%TGT%\$WIN_NT$.~BT"
for %%f in (ntdetect.com setupldr.bin) do if exist "%TGT%\%ARCHDIR%\%%f" copy /y "%TGT%\%ARCHDIR%\%%f" "%TGT%\" >nul
if exist "%TGT%\setupldr.bin" ren "%TGT%\setupldr.bin" ntldr
if defined UNA (
  echo [3/4] winnt.sif -^> %TGT%\$WIN_NT$.~BT\winnt.sif
  copy /y "%UNA%" "%TGT%\$WIN_NT$.~BT\winnt.sif" >nul
) else (
  echo [3/4] 无 --unattend，跳过 winnt.sif（将走交互式文本安装）
)
echo [4/4] 注意: XP 不支持 dism /Add-Driver。SATA/AHCI 驱动只能走以下两条路之一：
echo        a) BIOS 里把 SATA 模式改成 IDE/Compatible 再装（最省事）；
echo        b) 用 nLite 等把 F6 驱动集成进安装源的 I386（本脚本不代做，属源改造）。
echo 下一步: win-disk boot %TGT% %TGT% bios nt52
exit /b 0

rem ---------------------------------------------------------------- drivers / check
:drivers
if "%~3"=="" echo 用法: win-install drivers ^<目标盘:^> ^<驱动目录^> & exit /b 2
dism /Image:%~2\ /Add-Driver /Driver:"%~3" /Recurse /ForceUnsigned
exit /b %errorlevel%

:check
set "T=%~2"
if "%T%"=="" echo 用法: win-install check ^<目标盘:^> & exit /b 2
echo --- %T% ---
if exist "%T%\Windows\System32\ntoskrnl.exe" (echo [ok] Vista+ 系统文件在位) else if exist "%T%\WINDOWS\system32\ntoskrnl.exe" (echo [ok] XP 系统文件在位) else echo [x] 没有 ntoskrnl.exe
if exist "%T%\Windows\Panther\unattend.xml" echo [ok] unattend.xml
if exist "%T%\$WIN_NT$.~BT\winnt.sif" echo [ok] winnt.sif
if exist "%T%\ntldr" echo [ok] ntldr
dir /b "%T%\Windows\System32\config" 2>nul | find /i "SYSTEM" >nul && echo [ok] 注册表 hive
exit /b 0
