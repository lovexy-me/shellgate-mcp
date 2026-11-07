<#
.SYNOPSIS
  Build "ShellGate PE": a Chinese-language Windows PE rescue image with ShellGate (MCP) auto-starting,
  for a Ventoy stick. Runs on your own Windows machine or in CI; it never ships a prebuilt image.

.DESCRIPTION
  Microsoft's ADK/WinPE licence does not allow handing out a prebuilt WinPE image, so this repository
  contains the build script only. The ADK, the WinPE add-on and every third-party tool are downloaded
  from their official addresses at build time and verified against sha256 (pe-build/tools.json).
  Nothing is extracted from someone else's PE ISO.

.PARAMETER Arch
  amd64 (default) or x86. x86 needs an ADK whose WinPE add-on still ships x86: use
  -AdkVersion 2004 (ADK 10.0.19041 / "Windows 10 2004", the last one with x86 WinPE).
  A 2004-based x86 PE requires a CPU with PAE, NX and SSE2 (Pentium 4 Prescott and later).

.PARAMETER Base
  winpe (default) - copype from the ADK WinPE add-on.
  winre           - take WinRE from this machine (C:\Recovery\...\Winre.wim or a mounted install.wim).
                    WinRE already contains the Wi-Fi stack, which WinPE does not have at all.

.PARAMETER Full
  Add the optional, non-redistributable tools (CPU-Z, Everything, ...). The resulting image is for
  your own use; do not publish it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Build-ShellGatePE.ps1 -Arch amd64 -Out D:\pe
  powershell -ExecutionPolicy Bypass -File .\Build-ShellGatePE.ps1 -Base winre -Arch amd64 -Out D:\pe
#>
[CmdletBinding()]
param(
    [ValidateSet('amd64', 'x86')][string]$Arch = 'amd64',
    [ValidateSet('winpe', 'winre')][string]$Base = 'winpe',
    [string]$Out = "$PSScriptRoot\..\..\build\pe",
    [string]$ShellGate,                       # shellgate.exe for this arch; default: looked up next to the script
    [string]$Drivers,                         # extra .inf tree to inject (Intel RST/VMD, NIC, ...)
    [string]$Extras,                          # extra tools tree copied into Program Files verbatim
    [ValidateSet('latest', '2004')][string]$AdkVersion = 'latest',
    [switch]$Full,
    [switch]$SkipAdkInstall,                  # ADK already installed
    [switch]$AllowUnpinned,                   # accept tools whose sha256 is null in tools.json
    [switch]$NoIso,
    [int]$ScratchMB = 512
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 1   # tools.json entries have optional keys
$script:Started = Get-Date

function Say($m, $c = 'Cyan') { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) -ForegroundColor $c }
function Die($m) { Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Need-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Die "run this in an elevated PowerShell (DISM needs administrator)"
    }
}

# ---------------------------------------------------------------- download helpers

function Get-File($Url, $Dest, $Sha256) {
    if ((Test-Path $Dest) -and $Sha256 -and $Sha256 -ne 'microsoft-signed') {
        if ((Get-FileHash $Dest -Algorithm SHA256).Hash -eq $Sha256.ToUpper()) { Say "cached  $(Split-Path $Dest -Leaf)" Gray; return }
    }
    Say "下载    $Url"
    $tmp = "$Dest.part"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -MaximumRedirection 10 `
            -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    } catch { Remove-Item $tmp -EA SilentlyContinue; throw "download failed: $Url -> $_" }
    $h = (Get-FileHash $tmp -Algorithm SHA256).Hash
    if ($Sha256 -eq 'microsoft-signed') {
        # ADK bootstrappers change with every servicing release: verify the Authenticode signature instead
        $sig = Get-AuthenticodeSignature $tmp
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Remove-Item $tmp -Force; throw "$Url is not validly signed by Microsoft ($($sig.Status) $($sig.SignerCertificate.Subject))"
        }
        Say "  Microsoft 签名有效，sha256 $h" Gray
    } elseif ($Sha256) {
        if ($h -ne $Sha256.ToUpper()) { Remove-Item $tmp -Force; throw "sha256 mismatch for $Url`n  expected $Sha256`n  got      $h" }
    } else {
        Say "  未固定 sha256: $h" Yellow
        if (-not $AllowUnpinned) { Remove-Item $tmp -Force; throw "$Url has no pinned sha256; re-run with -AllowUnpinned or pin it in tools.json" }
    }
    Move-Item $tmp $Dest -Force
}

function Expand-Any($Archive, $Dest) {
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    $ext = [IO.Path]::GetExtension($Archive).ToLower()
    if ($ext -eq '.zip') { Expand-Archive -Path $Archive -DestinationPath $Dest -Force; return }
    if ($ext -eq '.iso') {
        $img = Mount-DiskImage -ImagePath (Resolve-Path $Archive) -PassThru
        try {
            $l = ($img | Get-Volume).DriveLetter
            Copy-Item "${l}:\*" $Dest -Recurse -Force
        } finally { Dismount-DiskImage -ImagePath (Resolve-Path $Archive) | Out-Null }
        return
    }
    $7z = Get-SevenZip
    & $7z x -y -o"$Dest" $Archive | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z failed on $Archive" }
}

# 7zr.exe (7z format only) bootstraps the full 7-Zip from its official installer, which then
# unpacks zip/7z/NSIS installers. Both are pinned in sha256.
function Get-SevenZip {
    if ($script:SevenZip -and (Test-Path $script:SevenZip)) { return $script:SevenZip }
    $r = Join-Path $Work '7zr.exe'
    Get-File 'https://github.com/ip7z/7zip/releases/download/26.05/7zr.exe' $r '9BF582B894DFA665F852D7E9112B02290A1C303C2D95A21FCDC41FFCB03143B7'
    $inst = Join-Path $Dl '7z2605-x64.exe'
    Get-File 'https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.exe' $inst 'FD99E86F57D8F429EF5ED045BF98315AF962E2309B0F1BA87A147A44C71647D0'
    $full = Join-Path $Work '7z-host'
    & $r x -y -o"$full" $inst | Out-Null
    $script:SevenZip = if (Test-Path "$full\7z.exe") { "$full\7z.exe" } else { $r }
    return $script:SevenZip
}

# ---------------------------------------------------------------- ADK

$AdkLinks = @{
    latest = @{ adk = 'https://go.microsoft.com/fwlink/?linkid=2289980'; pe = 'https://go.microsoft.com/fwlink/?linkid=2289981'; name = 'ADK 10.1.26100 (2026-09)' }
    '2004' = @{ adk = 'https://go.microsoft.com/fwlink/?linkid=2120254'; pe = 'https://go.microsoft.com/fwlink/?linkid=2120253'; name = 'ADK 10.1.19041 (Windows 10 2004, last with x86 WinPE)' }
}

function Install-Adk {
    $l = $AdkLinks[$AdkVersion]
    Say "安装 $($l.name)（静默）"
    $a = Join-Path $Work 'adksetup.exe'; $b = Join-Path $Work 'adkwinpesetup.exe'
    Get-File $l.adk $a 'microsoft-signed'
    Get-File $l.pe  $b 'microsoft-signed'
    # Deployment tools give copype/dism/oscdimg; the add-on gives the WinPE source
    & $a /quiet /norestart /features OptionId.DeploymentTools | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "adksetup exit $LASTEXITCODE" }
    & $b /quiet /norestart /features OptionId.WindowsPreinstallationEnvironment | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "adkwinpesetup exit $LASTEXITCODE" }
}

function Find-AdkPaths {
    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit",
               "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit") | Where-Object { Test-Path $_ }
    foreach ($r in $roots) {
        $copype = Join-Path $r 'Windows Preinstallation Environment\copype.cmd'
        if (Test-Path $copype) {
            # host tools are amd64 whatever PE architecture is being built
            $oscdimg = Join-Path $r 'Deployment Tools\amd64\Oscdimg\oscdimg.exe'
            $dism = Join-Path $r 'Deployment Tools\amd64\DISM\dism.exe'
            if (-not (Test-Path $dism)) { $dism = "$env:SystemRoot\System32\dism.exe" }
            return @{ Root = $r; Copype = $copype; Oscdimg = $oscdimg; Dism = $dism
                      SetEnv = Join-Path $r 'Deployment Tools\DandISetEnv.bat'
                      PeRoot = Join-Path $r "Windows Preinstallation Environment\$Arch" }
        }
    }
    return $null
}

# ---------------------------------------------------------------- optional components

# Every WinPE optional component that exists in the add-on, in the order DISM wants
# (a package's dependencies first). Each one is paired with its zh-cn language pack.
$Components = @(
    'WinPE-WMI', 'WinPE-NetFX', 'WinPE-Scripting', 'WinPE-PowerShell', 'WinPE-StorageWMI',
    'WinPE-DismCmdlets', 'WinPE-SecureBootCmdlets', 'WinPE-EnhancedStorage', 'WinPE-SecureStartup',
    'WinPE-FMAPI', 'WinPE-PlatformId', 'WinPE-HTA', 'WinPE-MDAC', 'WinPE-Dot3Svc',
    'WinPE-PPPoE', 'WinPE-RNDIS', 'WinPE-WDS-Tools', 'WinPE-SRT', 'WinPE-Setup',
    'WinPE-FontSupport-ZH-CN', 'WinPE-LegacySetup', 'WinPE-WinReCfg', 'WinPE-Rejuv', 'WinPE-GamingPeripherals'
)
# Components with no language pack of their own
$NoLangPack = @('WinPE-FontSupport-ZH-CN', 'WinPE-PlatformId', 'WinPE-FMAPI', 'WinPE-GamingPeripherals')

function Add-Components($Mount, $OcRoot) {
    $added = @(); $missing = @()
    # the zh-cn base language pack first, or the component language packs have nothing to attach to
    $lp = Join-Path $OcRoot 'zh-cn\lp.cab'
    if (Test-Path $lp) {
        Say "  语言包 zh-cn lp.cab"
        & $Dism /Image:$Mount /Add-Package /PackagePath:"$lp" /Quiet | Out-Null
        if ($LASTEXITCODE -eq 0) { $added += 'zh-cn lp.cab' } else { $missing += "zh-cn lp.cab(dism $LASTEXITCODE)" }
    } else { $missing += 'zh-cn lp.cab' }
    foreach ($c in $Components) {
        $cab = Join-Path $OcRoot "$c.cab"
        if (-not (Test-Path $cab)) { $missing += $c; continue }
        Say "  组件 $c"
        & $Dism /Image:$Mount /Add-Package /PackagePath:"$cab" /Quiet | Out-Null
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) { $missing += "$c(dism $LASTEXITCODE)"; continue }
        $added += $c
        if ($NoLangPack -contains $c) { continue }
        $lp = Join-Path $OcRoot "zh-cn\${c}_zh-cn.cab"
        if (Test-Path $lp) {
            & $Dism /Image:$Mount /Add-Package /PackagePath:"$lp" /Quiet | Out-Null
        }
    }
    return @{ Added = $added; Missing = $missing }
}

# ---------------------------------------------------------------- tools

function Install-Tools($Mount) {
    $manifest = Get-Content (Join-Path $PSScriptRoot 'tools.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $dst = Join-Path $Mount 'Program Files\ShellGatePE'
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    $report = @()
    foreach ($t in $manifest.tools) {
        if ($t.arch -notcontains $Arch) { continue }
        if (-not $t.redistributable -and -not $Full) { $report += [pscustomobject]@{ id = $t.id; state = 'skipped (not redistributable; use -Full)' }; continue }
        $url = if ($t.url -is [string]) { $t.url } elseif ($t.url) { $t.url.$Arch } else { $null }
        $sha = if ($t.sha256 -is [string]) { $t.sha256 } elseif ($t.sha256) { $t.sha256.$Arch } else { $null }
        if (-not $url) { $report += [pscustomobject]@{ id = $t.id; state = 'no download URL (see note in tools.json)' }; continue }
        $file = Join-Path $Dl ("{0}-{1}{2}" -f $t.id, $Arch, [IO.Path]::GetExtension(($url -split '\?')[0]))
        try { Get-File $url $file $sha } catch {
            if ($t.optional) { $report += [pscustomobject]@{ id = $t.id; state = "download failed (optional): $_" }; continue }
            throw
        }
        $to = Join-Path $dst $t.id
        try {
            switch ($t.extract) {
                'raw' { New-Item -ItemType Directory -Force -Path $to | Out-Null; Copy-Item $file (Join-Path $to $t.files.'*'[0]) -Force }
                'driver-iso' {
                    $x = Join-Path $Work "virtio-$Arch"
                    Expand-Any $file $x
                    $w = if ($Arch -eq 'x86') { 'w10\x86' } else { 'w10\amd64' }
                    foreach ($d in $t.files.'*') {
                        $p = Join-Path $x "$d\$w"
                        if (Test-Path $p) { Copy-Item $p (Join-Path $DrvStage $d) -Recurse -Force }
                    }
                }
                default {
                    $x = Join-Path $Work "x-$($t.id)-$Arch"
                    Remove-Item $x -Recurse -Force -EA SilentlyContinue
                    Expand-Any $file $x
                    New-Item -ItemType Directory -Force -Path $to | Out-Null
                    $pats = if ($t.files.PSObject.Properties.Name -contains $Arch) { $t.files.$Arch } else { $t.files.'*' }
                    foreach ($pat in $pats) {
                        $src = Get-ChildItem (Join-Path $x $pat) -Recurse -EA SilentlyContinue
                        if (-not $src) { Say "  缺文件 $($t.id): $pat" Yellow; continue }
                        foreach ($s in $src) {
                            if ($s.PSIsContainer) { Copy-Item $s.FullName $to -Recurse -Force } else { Copy-Item $s.FullName $to -Force }
                        }
                    }
                }
            }
            $report += [pscustomobject]@{ id = $t.id; state = 'ok'; license = $t.license; redistributable = $t.redistributable }
        } catch {
            if ($t.optional) { $report += [pscustomobject]@{ id = $t.id; state = "extract failed (optional): $_" } } else { throw }
        }
    }
    if ($Extras -and (Test-Path $Extras)) {
        Copy-Item "$Extras\*" $dst -Recurse -Force
        $report += [pscustomobject]@{ id = '(extras)'; state = "copied from $Extras" }
    }
    return $report
}

# ---------------------------------------------------------------- main

Need-Admin
$Work = Join-Path $Out 'work'
$Dl = Join-Path $Out 'download'
$DrvStage = Join-Path $Work 'drivers'
$Mount = Join-Path $Work 'mount'
$Media = Join-Path $Out "media-$Arch"
New-Item -ItemType Directory -Force -Path $Work, $Dl, $DrvStage | Out-Null

if ($Arch -eq 'x86' -and $AdkVersion -eq 'latest') {
    Say "x86: 新版 ADK 已不含 x86 WinPE，自动改用 -AdkVersion 2004（CPU 需支持 PAE/NX/SSE2）" Yellow
    $AdkVersion = '2004'
}

if (-not $SkipAdkInstall -and -not (Find-AdkPaths)) { Install-Adk }
$adk = Find-AdkPaths
if (-not $adk) { Die "ADK not found after install; install it manually or pass -SkipAdkInstall with it present" }
Say "ADK: $($adk.Root)"
$Dism = $adk.Dism

# --- base image
if (Test-Path $Mount) { & $Dism /Unmount-Image /MountDir:$Mount /Discard 2>&1 | Out-Null; Remove-Item $Mount -Recurse -Force -EA SilentlyContinue }
Remove-Item $Media -Recurse -Force -EA SilentlyContinue
Say "copype $Arch -> $Media"
# copype needs the ADK environment (WinPERoot, OSCDImgRoot) from DandISetEnv.bat
& cmd.exe /c "call `"$($adk.SetEnv)`" >nul && call `"$($adk.Copype)`" $Arch `"$Media`"" | Out-Null
if (-not (Test-Path "$Media\media\sources\boot.wim")) { Die "copype did not produce boot.wim" }

if ($Base -eq 'winre') {
    $re = Get-ChildItem 'C:\Recovery\WindowsRE\Winre.wim' -Force -EA SilentlyContinue
    if (-not $re) {
        $re = Get-ChildItem 'C:\Windows\System32\Recovery\Winre.wim' -Force -EA SilentlyContinue
    }
    if (-not $re) { Die "-Base winre: no Winre.wim found (C:\Recovery\WindowsRE or C:\Windows\System32\Recovery). Mount your install.wim and copy Windows\System32\Recovery\Winre.wim out first." }
    Say "底座改为本机 WinRE: $($re.FullName)（含 Wi-Fi 栈）"
    Copy-Item $re.FullName "$Media\media\sources\boot.wim" -Force
    attrib -r "$Media\media\sources\boot.wim"
}

New-Item -ItemType Directory -Force -Path $Mount | Out-Null
Say "挂载 boot.wim"
& $Dism /Mount-Image /ImageFile:"$Media\media\sources\boot.wim" /Index:1 /MountDir:$Mount | Out-Null
if ($LASTEXITCODE -ne 0) { Die "dism /Mount-Image failed" }

try {
    # --- optional components
    $oc = Join-Path $adk.PeRoot 'WinPE_OCs'
    Say "加组件（全部可用的 + zh-cn 语言包）"
    $comp = Add-Components $Mount $oc

    # --- locale: Chinese UI, zh-CN input, CST, UTF-8-friendly console
    Say "中文化"
    & $Dism /Image:$Mount /Set-AllIntl:zh-cn | Out-Null
    & $Dism /Image:$Mount /Set-TimeZone:"China Standard Time" | Out-Null

    # --- tools
    Say "工具"
    $tools = Install-Tools $Mount

    # --- ShellGate
    if (-not $ShellGate) {
        $cand = @("$PSScriptRoot\..\..\dist\shellgate-$(if($Arch -eq 'x86'){'i686'}else{'x86_64'})-windows.exe",
                  "$PSScriptRoot\shellgate.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
        $ShellGate = $cand
    }
    if (-not $ShellGate -or -not (Test-Path $ShellGate)) { Die "shellgate.exe for $Arch not found; pass -ShellGate <path>" }
    $sgDir = Join-Path $Mount 'Program Files\ShellGate'
    New-Item -ItemType Directory -Force -Path $sgDir | Out-Null
    Copy-Item $ShellGate (Join-Path $sgDir 'shellgate.exe') -Force
    Say "ShellGate: $ShellGate -> X:\Program Files\ShellGate\shellgate.exe（镜像内没有任何令牌）"

    # --- drivers
    $drvDirs = @($DrvStage) + @($Drivers | Where-Object { $_ -and (Test-Path $_) })
    foreach ($d in $drvDirs) {
        if (-not (Get-ChildItem $d -Recurse -Filter *.inf -EA SilentlyContinue)) { continue }
        Say "注入驱动 $d"
        & $Dism /Image:$Mount /Add-Driver /Driver:"$d" /Recurse /ForceUnsigned | Out-Null
        if ($LASTEXITCODE -ne 0) { Say "  部分驱动未装入 (dism $LASTEXITCODE)" Yellow }
    }

    # --- scratch space, startup scripts
    & $Dism /Image:$Mount /Set-ScratchSpace:$ScratchMB | Out-Null
    Say "scratch space = ${ScratchMB}MB"
    foreach ($f in 'startnet.cmd', 'shellgate-pe.cmd', 'menu.cmd') {
        Copy-Item (Join-Path $PSScriptRoot "files\$f") (Join-Path $Mount "Windows\System32\$f") -Force
    }
    $pe = Join-Path $Mount 'Program Files\ShellGatePE'
    Copy-Item (Join-Path $PSScriptRoot 'files\menu.hta') (Join-Path $pe 'menu.hta') -Force
    Copy-Item (Join-Path $PSScriptRoot 'files\bin') $pe -Recurse -Force
    # bootsect.exe (NTLDR/BOOTMGR boot sectors for XP-style and legacy repairs) ships with the ADK
    $bs = Get-ChildItem "$($adk.Root)\Deployment Tools\$Arch" -Recurse -Filter bootsect.exe -EA SilentlyContinue | Select-Object -First 1
    if ($bs) { Copy-Item $bs.FullName (Join-Path $pe 'bin\bootsect.exe') -Force; Say "bootsect.exe <- $($bs.FullName)" }

    $info = [pscustomobject]@{
        built    = (Get-Date).ToString('s')
        arch     = $Arch
        base     = $Base
        adk      = $AdkVersion
        components_added = $comp.Added
        components_missing = $comp.Missing
        tools    = $tools
    }
    $info | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Mount 'shellgate-pe.json') -Encoding UTF8
    $info | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out "build-report-$Arch.json") -Encoding UTF8
} finally {
    Say "卸载并提交 boot.wim"
    & $Dism /Unmount-Image /MountDir:$Mount /Commit | Out-Null
    if ($LASTEXITCODE -ne 0) { Say "unmount /Commit failed ($LASTEXITCODE); trying /Discard" Yellow; & $Dism /Unmount-Image /MountDir:$Mount /Discard | Out-Null }
}

$wim = Join-Path $Out "ShellGatePE-$Arch.wim"
Copy-Item "$Media\media\sources\boot.wim" $wim -Force
Say "WIM: $wim ($([math]::Round((Get-Item $wim).Length/1MB,1)) MB)"

if (-not $NoIso) {
    if (-not $adk.Oscdimg) { Die "oscdimg.exe not found in the ADK Deployment Tools" }
    $iso = Join-Path $Out "ShellGatePE-$Arch.iso"
    $etfs = "$Media\fwfiles\etfsboot.com"; $efisys = "$Media\fwfiles\efisys.bin"
    # BIOS + UEFI dual boot
    & $adk.Oscdimg -m -o -u2 -udfver102 -bootdata:"2#p0,e,b$etfs#pEF,e,b$efisys" "$Media\media" $iso | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "oscdimg exit $LASTEXITCODE" }
    Say "ISO: $iso ($([math]::Round((Get-Item $iso).Length/1MB,1)) MB)"
    (Get-FileHash $iso -Algorithm SHA256).Hash | Set-Content "$iso.sha256"
}
(Get-FileHash $wim -Algorithm SHA256).Hash | Set-Content "$wim.sha256"

Say ("完成，用时 {0:n1} 分钟。把 ISO 复制到 Ventoy 盘，并在盘根建 \shellgate\shellgate.env（只需一行 token=）。" -f ((Get-Date) - $script:Started).TotalMinutes) Green
