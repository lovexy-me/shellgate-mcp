@echo off
rem FirPE lifecycle hook (<stick>\FirPE\Hooks\onBootFinished.cmd, runs after all services started).
rem FirPE reads hook files as GBK: keep this file ASCII. Starts ShellGate via <stick>\shellgate\pe-start.cmd.
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if exist "%%d:\shellgate\pe-start.cmd" (
    call "%%d:\shellgate\pe-start.cmd"
    goto :eof
  )
)
