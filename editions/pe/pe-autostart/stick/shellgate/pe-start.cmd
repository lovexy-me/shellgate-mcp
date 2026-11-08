@echo off
rem Start ShellGate from a Ventoy stick inside any WinPE (FirPE hook, HotPE/WePE startup, or double-click).
rem Looks for <drive>:\shellgate\shellgate.exe + shellgate.env on every drive; the token stays in shellgate.env.
setlocal
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if exist "%%d:\shellgate\shellgate.env" if exist "%%d:\shellgate\shellgate.exe" (
    start "ShellGate" /min "%%d:\shellgate\shellgate.exe" --env-file "%%d:\shellgate\shellgate.env"
    echo [shellgate] started from %%d:
    goto :eof
  )
)
echo [shellgate] no \shellgate\shellgate.exe + shellgate.env found on any drive
