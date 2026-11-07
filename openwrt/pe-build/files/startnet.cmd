@echo off
rem ShellGate PE startup. wpeinit brings up PnP + network stack; everything else is in shellgate-pe.cmd.
chcp 936 >nul
title ShellGate PE
wpeinit
call X:\Windows\System32\shellgate-pe.cmd
call X:\Windows\System32\menu.cmd
