<#
.SYNOPSIS
  Offline check of a built ShellGate PE: mounts the WIM read-only and verifies components,
  PowerShell, ShellGate, tools, startup scripts and the ISO size. Writes verify-<arch>.txt.
#>
param(
    [string]$Out = "$PSScriptRoot\..\..\build\pe",
    [ValidateSet('amd64', 'x86')][string]$Arch = 'amd64',
    [int]$MaxIsoMB = 1500
)
$ErrorActionPreference = 'Stop'
$wim = Join-Path $Out "ShellGatePE-$Arch.wim"
$iso = Join-Path $Out "ShellGatePE-$Arch.iso"
$mnt = Join-Path $Out "verify-mount-$Arch"
$log = Join-Path $Out "verify-$Arch.txt"
$fail = 0
$lines = New-Object System.Collections.Generic.List[string]
function Check($ok, $what) {
    $s = if ($ok) { 'PASS' } else { 'FAIL'; $script:fail++ }
    $lines.Add("$s  $what"); Write-Host "$s  $what" -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}

Check (Test-Path $wim) "WIM exists: $wim"
if (Test-Path $iso) {
    $mb = [math]::Round((Get-Item $iso).Length / 1MB, 1)
    Check ($mb -gt 200 -and $mb -lt $MaxIsoMB) "ISO size $mb MB (200..$MaxIsoMB)"
} else { Check $false "ISO exists: $iso" }

New-Item -ItemType Directory -Force -Path $mnt | Out-Null
& dism.exe /Mount-Image /ImageFile:$wim /Index:1 /MountDir:$mnt /ReadOnly | Out-Null
if ($LASTEXITCODE -ne 0) { Check $false "mount read-only"; $lines | Set-Content $log -Encoding UTF8; exit 1 }
try {
    $pk = (& dism.exe /Image:$mnt /Get-Packages /Format:Table) -join "`n"
    foreach ($c in 'WinPE-WMI', 'WinPE-NetFX', 'WinPE-Scripting', 'WinPE-PowerShell', 'WinPE-StorageWMI', 'WinPE-DismCmdlets',
                   'WinPE-SecureBootCmdlets', 'WinPE-SecureStartup', 'WinPE-EnhancedStorage', 'WinPE-HTA', 'WinPE-Dot3Svc',
                   'WinPE-FMAPI', 'WinPE-PlatformId', 'WinPE-PPPoE', 'WinPE-RNDIS', 'WinPE-MDAC', 'WinPE-FontSupport-ZH-CN') {
        Check ($pk -match [regex]::Escape($c) + '-Package') "component $c"
    }
    Check ($pk -match 'WinPE-PowerShell-Package~.*~zh-CN') "PowerShell zh-cn language pack"
    $ps = Join-Path $mnt 'Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    Check (Test-Path $ps) "PowerShell present offline: Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    Check (Test-Path (Join-Path $mnt 'Windows\System32\manage-bde.exe')) "BitLocker manage-bde.exe"
    Check (Test-Path (Join-Path $mnt 'Windows\System32\wbem\WMIC.exe')) "WMI wmic.exe"
    Check (Test-Path (Join-Path $mnt 'Windows\System32\mshta.exe')) "HTA mshta.exe"
    $sg = Join-Path $mnt 'Program Files\ShellGate\shellgate.exe'
    Check (Test-Path $sg) "ShellGate at X:\Program Files\ShellGate\shellgate.exe"
    Check (-not (Get-ChildItem $mnt -Recurse -Filter shellgate.env -EA SilentlyContinue)) "no shellgate.env (token) inside the image"
    foreach ($f in 'startnet.cmd', 'shellgate-pe.cmd', 'menu.cmd') { Check (Test-Path (Join-Path $mnt "Windows\System32\$f")) "startup script $f" }
    $pe = Join-Path $mnt 'Program Files\ShellGatePE'
    $tools = @{ '7-Zip' = '7zip\7za.exe'; 'wimlib-imagex' = 'wimlib\wimlib-imagex.exe'; 'TestDisk' = 'testdisk\testdisk_win.exe';
                'PhotoRec' = 'testdisk\photorec_win.exe'; 'Explorer++' = 'explorerpp\Explorer++.exe'; 'Notepad++' = 'notepadpp\notepad++.exe';
                'aria2c' = 'aria2\aria2c.exe'; 'cloudflared' = 'cloudflared\cloudflared.exe'; 'win-install' = 'bin\win-install.cmd';
                'win-offline' = 'bin\win-offline.cmd'; 'menu.hta' = 'menu.hta'; 'bootsect' = 'bin\bootsect.exe' }
    foreach ($k in $tools.Keys | Sort-Object) { Check (Test-Path (Join-Path $pe $tools[$k])) "tool $k ($($tools[$k]))" }
    # win-install's ISO fallback needs the full 7-Zip (7za has no ISO/UDF handler): 7z.exe and 7z.dll side by side
    $sz = if ($Arch -eq 'x86') { '7zip-x86' } else { '7zip-full' }
    foreach ($f in '7z.exe', '7z.dll') { Check (Test-Path (Join-Path $pe "$sz\$f")) "full 7-Zip $sz\$f (ISO/UDF for win-install)" }
    $intl = (& dism.exe /Image:$mnt /Get-Intl) -join "`n"
    Check ($intl -match 'zh-CN') "UI language zh-CN"
    $sc = (& dism.exe /Image:$mnt /Get-ScratchSpace) -join "`n"
    Check ($sc -match '512') "scratch space 512 MB"
    $lines.Add(""); $lines.Add("dism /Get-Intl:"); $lines.Add($intl)
} finally {
    & dism.exe /Unmount-Image /MountDir:$mnt /Discard | Out-Null
}
$lines.Add(""); $lines.Add("failures: $fail")
$lines | Set-Content $log -Encoding UTF8
Write-Host "failures: $fail"
exit $(if ($fail) { 1 } else { 0 })
