@echo off
rem ShellGate autostart for a Ventoy stick (Ventoy injection plugin, VentoyAutoRun.bat).
rem Ventoy runs this before winpeshl/PECMD with %%1 = ISO path on the stick, %%2 = ISO drive letter.
rem No token here: the config is read from <stick>\shellgate\shellgate.env.
set "SG_EXE=X:\shellgate\shellgate.exe"
set "SG_CFG=%~d1\shellgate\shellgate.env"
echo [shellgate] iso=%1 cfg=%SG_CFG%
if not exist "%SG_CFG%" (echo [shellgate] no config found & goto :eof)
start "ShellGate" /min "%SG_EXE%" --env-file "%SG_CFG%"
