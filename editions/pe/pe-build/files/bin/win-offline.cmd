@echo off
rem ============================================================================
rem win-offline.cmd -- 离线系统维护：改密码 / 启用账户 / 离线注册表 / 引导修复
rem 对 XP ~ Win11 都适用（SAM/SYSTEM/SOFTWARE 的 hive 格式一直兼容）。
rem
rem   win-offline.cmd users    <windows:>              列出本地账户（读 SAM）
rem   win-offline.cmd password <windows:> <user>       清空该账户密码
rem   win-offline.cmd enable   <windows:> <user>       启用被停用的账户
rem   win-offline.cmd reg      <windows:> <hive> <命令...>   在离线 hive 上跑 reg 命令
rem                                hive = system|software|sam|default|ntuser:<用户名>
rem   （引导修复在 win-disk.cmd fixboot）
rem   win-offline.cmd bcdlist  <system:>               看 BCD
rem
rem 清空密码/解锁账户要改 SAM 里的二进制 F/V 值：交给 NTPWEdit（免费、不可再分发）或
rem chntpw（GPL）。两者都不内置；放进 Ventoy 盘 \shellgate\plugins\ 后自动可用。
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
if /i "%~1"=="" goto :help
if /i "%~1"=="help" goto :help
set "W=%~2"
if /i "%~1"=="users" goto users
if /i "%~1"=="password" goto password
if /i "%~1"=="enable" goto enable
if /i "%~1"=="reg" goto regcmd
if /i "%~1"=="fixboot" (echo 引导修复请运行 win-disk.cmd fixboot ...& exit /b 2)
if /i "%~1"=="bcdlist" goto bcdlist
echo 未知子命令 %1 & goto :help
:help
for /f "usebackq tokens=* delims=" %%L in ("%~f0") do (set "L=%%L" & if "!L:~0,4!"=="rem " if not "!L:~4,4!"=="====" if not "!L:~4,4!"=="----" echo(!L:~4!)
exit /b 0

:hive
rem %1 = windows drive, %2 = hive name -> sets HPATH
set "HROOT=%~1\Windows\System32\config"
if not exist "%HROOT%" set "HROOT=%~1\WINDOWS\system32\config"
if not exist "%HROOT%" (echo 找不到 %~1 上的注册表目录 & exit /b 2)
exit /b 0

:users
call :hive "%W%" || exit /b 2
reg load HKLM\SG_SAM "%HROOT%\SAM" >nul || (echo 无法加载 SAM & exit /b 1)
echo --- 本地账户 ---
for /f "tokens=*" %%k in ('reg query "HKLM\SG_SAM\SAM\Domains\Account\Users\Names" 2^>nul') do if /i not "%%~nxk"=="Names" echo %%~nxk
reg unload HKLM\SG_SAM >nul
exit /b 0

:password
set "U=%~3"
if "%U%"=="" echo 用法: win-offline password ^<windows:^> ^<用户名^> & exit /b 2
if exist "X:\Program Files\ShellGatePE\ntpwedit\NTPWEdit.exe" (
  echo 用 NTPWEdit 打开 SAM（图形界面，选中用户 -> Change password -> 留空 -> Save changes）
  start "" "X:\Program Files\ShellGatePE\ntpwedit\NTPWEdit.exe"
  exit /b 0
)
echo [x] 本 PE 没有 NTPWEdit（免费但不可再分发，不内置）。
echo     自助：把 NTPWEdit 放到 Ventoy 盘 \shellgate\plugins\ 下（解压为 ntpwedit 目录），
echo     下次开机自动加载；或用 chntpw（GPL）的 Windows 版放同一位置。
echo     纯内置的替代：win-offline reg "%W%" software "add ..." 关闭登录要求不可靠，不建议。
exit /b 3

:enable
set "U=%~3"
if "%U%"=="" echo 用法: win-offline enable ^<windows:^> ^<用户名^> & exit /b 2
echo 启用账户同样需要改 SAM 的 F 值，见 password 的说明（NTPWEdit 的 "Unlock" 按钮）。
exit /b 3

:regcmd
set "H=%~3"
if "%H%"=="" echo 用法: win-offline reg ^<windows:^> ^<system^|software^|sam^|default^|ntuser:用户^> ^<reg 命令...^> & exit /b 2
call :hive "%W%" || exit /b 2
set "F=%HROOT%\%H%"
if /i "!H:~0,7!"=="ntuser:" (
  for /f "tokens=2 delims=:" %%u in ("%H%") do set "F=%W%\Users\%%u\NTUSER.DAT"
  if not exist "!F!" for /f "tokens=2 delims=:" %%u in ("%H%") do set "F=%W%\Documents and Settings\%%u\NTUSER.DAT"
)
if not exist "%F%" (echo 找不到 hive %F% & exit /b 2)
reg load HKLM\SG_OFF "%F%" >nul || (echo 无法加载 %F% & exit /b 1)
echo 已挂载为 HKLM\SG_OFF。执行: reg %4 %5 %6 %7 %8 %9
reg %4 %5 %6 %7 %8 %9
set "RC=%errorlevel%"
reg unload HKLM\SG_OFF >nul
exit /b %RC%

:bcdlist
bcdedit /store "%~2\EFI\Microsoft\Boot\BCD" /enum all 2>nul || bcdedit /store "%~2\boot\BCD" /enum all
exit /b 0
