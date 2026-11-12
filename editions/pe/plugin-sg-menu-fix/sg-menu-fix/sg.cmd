@echo off
rem ShellGate PE control: sg status | sg mode local|lan|tunnel | sg restart
powershell -NoLogo -ExecutionPolicy Bypass -File "%~dp0sg.ps1" %*
