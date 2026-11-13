@echo off
rem Start ShellGate from a Ventoy stick inside any WinPE (FirPE hook, HotPE/WePE startup, or double-click).
rem Looks for <drive>:\shellgate\shellgate.exe + shellgate.env; the Ventoy stick (\ventoy\ventoy.json or
rem volume label Ventoy) wins over other drives. The token stays in shellgate.env.
setlocal EnableExtensions
set "STICK="
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" if exist "%%d:\shellgate\shellgate.exe" if exist "%%d:\ventoy\ventoy.json" set "STICK=%%d:"
)
if not defined STICK for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" if exist "%%d:\shellgate\shellgate.exe" (
    vol %%d: 2>nul | findstr /i /e /c:"Ventoy" >nul && set "STICK=%%d:"
  )
)
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined STICK if exist "%%d:\shellgate\shellgate.env" if exist "%%d:\shellgate\shellgate.exe" set "STICK=%%d:"
)
if not defined STICK (
  echo [shellgate] no \shellgate\shellgate.exe + shellgate.env found on any drive
  goto :eof
)
start "ShellGate" /min "%STICK%\shellgate\shellgate.exe" --env-file "%STICK%\shellgate\shellgate.env"
echo [shellgate] started from %STICK% (config %STICK%\shellgate\shellgate.env)
