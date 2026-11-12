@echo off
rem Hot-fix plugin for ShellGate PE images built before 2026-11-12: status button (no tasklist in WinPE)
rem and the local / lan / tunnel mode switch. Copy this .cmd and the sg-menu-fix folder to <stick>\shellgate\plugins\.
set "PEDIR=X:\Program Files\ShellGatePE"
if exist "%PEDIR%\bin\sg.ps1" (echo [plugin] sg-menu-fix: PE already has sg.ps1, skipped& exit /b 0)
copy /y "%~dp0sg-menu-fix\sg.ps1" "%PEDIR%\bin\" >nul
copy /y "%~dp0sg-menu-fix\sg.cmd" "%PEDIR%\bin\" >nul
copy /y "%~dp0sg-menu-fix\menu.hta" "%PEDIR%\menu.hta" >nul
copy /y "%~dp0sg-menu-fix\menu.cmd" "X:\Windows\System32\menu.cmd" >nul
echo [plugin] sg-menu-fix applied
