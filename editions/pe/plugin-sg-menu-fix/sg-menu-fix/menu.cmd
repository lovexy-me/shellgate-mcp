@echo off
rem ShellGate PE text menu (always available; the HTA menu is optional because mshta needs WinPE-HTA).
chcp 936 >nul
set "PEDIR=X:\Program Files\ShellGatePE"
if exist "%PEDIR%\menu.hta" if exist X:\Windows\System32\mshta.exe start "" mshta.exe "%PEDIR%\menu.hta"
:menu
echo.
echo  ===================== ShellGate PE =====================
echo   1 文件管理 (Explorer++)          2 编辑器 (Notepad++)
echo   3 磁盘列表 (diskpart list)       4 分区恢复 (TestDisk)
echo   5 文件恢复 (QPhotoRec)           6 装系统 / 引导修复 (win-install)
echo   7 离线改密码 / 注册表 (win-offline)  8 硬件信息 (smartctl, systeminfo)
echo   9 网络: 初始化 / 关防火墙 / ipconfig
echo   S ShellGate 状态                 M ShellGate 模式 (本机/局域网/隧道)
echo   P PowerShell
echo   C 命令行                         R 重启    Q 关机
echo  =========================================================
set "c="
set /p c=选择: 
if /i "%c%"=="1" start "" "%PEDIR%\explorerpp\Explorer++.exe"
if /i "%c%"=="2" start "" "%PEDIR%\notepadpp\notepad++.exe"
if /i "%c%"=="3" (echo list disk> X:\dl.txt & echo list volume>> X:\dl.txt & diskpart /s X:\dl.txt & del X:\dl.txt)
if /i "%c%"=="4" start "" "%PEDIR%\testdisk\testdisk_win.exe"
if /i "%c%"=="5" start "" "%PEDIR%\testdisk\qphotorec_win.exe"
if /i "%c%"=="6" start "win-install" cmd /k "%PEDIR%\bin\win-install.cmd" help
if /i "%c%"=="7" start "win-offline" cmd /k "%PEDIR%\bin\win-offline.cmd" help
if /i "%c%"=="8" (if exist "%PEDIR%\smartmontools\smartctl.exe" ("%PEDIR%\smartmontools\smartctl.exe" --scan) & wmic cpu get name & wmic memorychip get capacity & wmic diskdrive get model,size,interfacetype)
if /i "%c%"=="9" (wpeutil InitializeNetwork & wpeutil DisableFirewall & ipconfig)
if /i "%c%"=="S" call "%PEDIR%\bin\sg.cmd" status
if /i "%c%"=="M" goto setmode
if /i "%c%"=="P" start "PowerShell" powershell -NoLogo
if /i "%c%"=="C" start "cmd" cmd /k
if /i "%c%"=="R" wpeutil reboot
if /i "%c%"=="Q" wpeutil shutdown
goto menu
:setmode
set "mm="
set /p mm=模式 local=本机 lan=局域网 tunnel=隧道: 
call "%PEDIR%\bin\sg.cmd" mode %mm%
goto menu
