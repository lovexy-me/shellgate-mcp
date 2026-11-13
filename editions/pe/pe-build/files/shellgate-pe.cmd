@echo off
rem ShellGate PE boot sequence (runs once from startnet.cmd):
rem   1. find the Ventoy stick: the drive with \shellgate\shellgate.env that is the Ventoy stick (ventoy\ventoy.json or label Ventoy), else the first drive with it
rem   2. logs to <stick>\shellgate\logs\pe-<date>.log
rem   3. load drivers from <stick>\shellgate\drivers  (any *.inf, recursive)   -- like FirPE/HotPE's external driver dir
rem   4. load plugins from <stick>\shellgate\plugins  (*.cmd run, *.7z unpacked to X:\Plugins\<name> + its autorun.cmd)
rem   5. screen resolution from <stick>\shellgate\pe.ini (resolution=max|1920x1080), default max <=1920 wide
rem   6. start ShellGate with that env file; network bring-up follows pe_network/net in the env file
rem The token never lives in the image: no stick config -> ShellGate is not started.
setlocal EnableExtensions EnableDelayedExpansion
set "SG=X:\Program Files\ShellGate\shellgate.exe"
set "PEDIR=X:\Program Files\ShellGatePE"
set "STICK="
rem prefer the Ventoy stick we booted from (\ventoy\ventoy.json, then volume label Ventoy);
rem the first drive letter with a config is only the fallback
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" if exist "%%d:\ventoy\ventoy.json" set "STICK=%%d:"
)
if not defined STICK for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" (
    vol %%d: 2>nul | findstr /i /e /c:"Ventoy" >nul && set "STICK=%%d:"
  )
)
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" set "STICK=%%d:"
)
if not defined STICK (
  echo [ShellGate PE] 没找到 \shellgate\shellgate.env（Ventoy 盘根目录）。ShellGate 未启动；菜单仍可用。
  set "LOG=X:\shellgate-pe.log"
) else (
  if not exist "!STICK!\shellgate\logs" mkdir "!STICK!\shellgate\logs" 2>nul
  for /f "tokens=1-3 delims=/-. " %%a in ("%date%") do set "D=%%a%%b%%c"
  set "LOG=!STICK!\shellgate\logs\pe-!D!.log"
)
echo ==== ShellGate PE boot %date% %time% stick=!STICK! >> "!LOG!" 2>nul
if not exist "!LOG!" set "LOG=X:\shellgate-pe.log"

rem ---- PowerShell: WinPE leaves the execution policy at Restricted, which blocks every script module
rem      (the Resolve-DnsName shim in Modules\DnsShim included). RemoteSigned: local scripts run,
rem      downloaded ones still need a signature.
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d RemoteSigned /f >nul 2>&1
if exist "X:\Windows\SysWOW64" reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d RemoteSigned /f >nul 2>&1

rem ---- PATH: tools
set "PATH=%PATH%;%PEDIR%\bin;%PEDIR%\7zip;%PEDIR%\7zip-full;%PEDIR%\7zip-x86;%PEDIR%\wimlib;%PEDIR%\testdisk;%PEDIR%\aria2;%PEDIR%\dufs;%PEDIR%\cloudflared;%PEDIR%\notepadpp;%PEDIR%\explorerpp;%PEDIR%\smartmontools"
setx PATH "%PATH%" /m >nul 2>&1

if defined STICK (
  rem ---- drivers
  if exist "!STICK!\shellgate\drivers" (
    for /r "!STICK!\shellgate\drivers" %%i in (*.inf) do (
      drvload "%%i" >> "!LOG!" 2>&1 && echo [drv] %%~nxi >> "!LOG!"
    )
  )
  rem ---- plugins
  if exist "!STICK!\shellgate\plugins" (
    for %%p in ("!STICK!\shellgate\plugins\*.7z") do (
      echo [plugin] %%~np >> "!LOG!"
      7za x -y -o"X:\Plugins\%%~np" "%%p" >nul 2>&1 || 7z x -y -o"X:\Plugins\%%~np" "%%p" >nul 2>&1
      if exist "X:\Plugins\%%~np\autorun.cmd" call "X:\Plugins\%%~np\autorun.cmd" >> "!LOG!" 2>&1
    )
    for %%p in ("!STICK!\shellgate\plugins\*.cmd") do (
      echo [plugin] %%~nxp >> "!LOG!"
      call "%%p" >> "!LOG!" 2>&1
    )
  )
)

rem ---- resolution
set "RES=max"
if defined STICK if exist "!STICK!\shellgate\pe.ini" (
  for /f "usebackq tokens=1,* delims==" %%a in ("!STICK!\shellgate\pe.ini") do if /i "%%a"=="resolution" set "RES=%%b"
)
"%SG%" --display !RES! >> "!LOG!" 2>&1

rem ---- ShellGate (cmd stays the main path; PowerShell is a bonus inside this PE)
if defined STICK (
  echo [shellgate] start, config !STICK!\shellgate\shellgate.env >> "!LOG!"
  start "ShellGate" /min cmd /c ""%SG%" --env-file "!STICK!\shellgate\shellgate.env" >> "!LOG!" 2>&1"
)
endlocal & set "PATH=%PATH%;X:\Program Files\ShellGatePE\bin;X:\Program Files\ShellGatePE\cloudflared;X:\Program Files\ShellGatePE\aria2;X:\Program Files\ShellGatePE\dufs;X:\Program Files\ShellGatePE\smartmontools;X:\Program Files\ShellGatePE\7zip;X:\Program Files\ShellGatePE\wimlib;X:\Program Files\ShellGatePE\testdisk;X:\Program Files\ShellGatePE\explorerpp;X:\Program Files\ShellGatePE\notepadpp"
exit /b 0
