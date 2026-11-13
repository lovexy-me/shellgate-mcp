# ShellGate PE control: status / mode / restart. Works without tasklist/taskkill/findstr (absent in WinPE 26100).
#   sg.ps1 status            process, health, network mode, addresses, tunnel connections
#   sg.ps1 mode local|lan|tunnel   rewrite net= in <stick>\shellgate\shellgate.env and restart ShellGate
#   sg.ps1 restart
# The access token and tunnel token are never printed.
param([string]$Cmd = 'status', [string]$Arg = '')
$ErrorActionPreference = 'SilentlyContinue'
$script:rc = 0
$SG = 'X:\Program Files\ShellGate\shellgate.exe'

# The config on the Ventoy stick we booted from wins (a drive with \ventoy\ventoy.json or the volume
# label Ventoy); only when no drive looks like a Ventoy stick is the first drive letter with a config used.
$script:EnvHow = ''
function Find-Env {
    if ($env:SG_ENV_FILE -and (Test-Path -LiteralPath $env:SG_ENV_FILE)) { $script:EnvHow = 'SG_ENV_FILE'; return $env:SG_ENV_FILE }
    $c = @(foreach ($d in 'CDEFGHIJKLMNOPQRSTUVWYZ'.ToCharArray()) { if (Test-Path -LiteralPath "${d}:\shellgate\shellgate.env") { $d } })
    foreach ($d in $c) { if (Test-Path -LiteralPath "${d}:\ventoy\ventoy.json") { $script:EnvHow = 'Ventoy 启动盘（ventoy\ventoy.json）'; return "${d}:\shellgate\shellgate.env" } }
    foreach ($d in $c) {
        $l = try { ([System.IO.DriveInfo]"${d}:\").VolumeLabel } catch { '' }
        if ($l -eq 'Ventoy') { $script:EnvHow = 'Ventoy 启动盘（卷标 Ventoy）'; return "${d}:\shellgate\shellgate.env" }
    }
    if ($c.Count) { $script:EnvHow = '按盘符找到的第一个（没认出 Ventoy 盘）'; return "$($c[0]):\shellgate\shellgate.env" }
    return $null
}
function Norm([string]$k) { $k = $k.Trim().ToLower(); if ($k.StartsWith('shellgate_')) { $k = $k.Substring(10) }; $k }
function Read-Cfg([string]$path) {
    $h = @{}
    foreach ($l in (Get-Content -LiteralPath $path)) {
        $t = $l.Trim(); if (-not $t -or $t.StartsWith('#') -or $t -notmatch '=') { continue }
        $i = $t.IndexOf('='); $h[(Norm $t.Substring(0, $i))] = $t.Substring($i + 1).Trim().Trim('"')
    }
    $h
}
function Net-Mode($c) {
    $n = "$($c['net'])".ToLower()
    if (-not $n -and @('local','lan','tunnel') -contains "$($c['mode'])".ToLower()) { $n = "$($c['mode'])".ToLower() }
    switch ($n) { '' { if ($c['tunnel_token']) { 'tunnel' } else { 'local' } } 'localhost' { 'local' } 'loopback' { 'local' } 'cloudflare' { 'tunnel' } 'cf' { 'tunnel' } default { $n } }
}
function IPv4s {
    $r = @()
    $o = (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')
    foreach ($a in $o) { foreach ($ip in $a.IPAddress) { if ($ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -notmatch '^(127\.|169\.254\.)') { $r += $ip } } }
    $r
}
$ModeName = @{ local = '本机 (只允许本机 127.0.0.1)'; lan = '局域网 (同网段设备可连)'; tunnel = '隧道 (经 Cloudflare 远程)' }

function Show-Status {
    $envf = Find-Env
    Write-Host '========== ShellGate 状态 =========='
    $p = Get-Process shellgate
    if ($p) { Write-Host ("进程: 运行中  PID {0}" -f (($p | ForEach-Object Id) -join ',')) -ForegroundColor Green }
    else { Write-Host '进程: 未运行' -ForegroundColor Red }
    if (-not $envf) { Write-Host '配置: 没找到 U 盘 \shellgate\shellgate.env（令牌不在镜像里，没有配置就不会启动）' -ForegroundColor Yellow; return }
    $c = Read-Cfg $envf; $m = Net-Mode $c
    $port = if ($c['port']) { $c['port'] } else { '8790' }
    Write-Host "配置: $envf  [$script:EnvHow]"
    Write-Host "模式: $m  $($ModeName[$m])"
    try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$port/health"; Write-Host "健康检查: HTTP $($r.StatusCode)  $($r.Content)" -ForegroundColor Green }
    catch { Write-Host "健康检查: 127.0.0.1:$port 无响应" -ForegroundColor Red }
    $ips = @(IPv4s)
    Write-Host ("本机 IPv4: {0}" -f $(if ($ips) { $ips -join ', ' } else { '无（未联网）' }))
    switch ($m) {
        'local'  { Write-Host "连接地址: http://127.0.0.1:$port/mcp （仅本机）" }
        'lan'    { foreach ($ip in $ips) { Write-Host "连接地址: http://${ip}:$port/mcp" }
                   $n = if ($c['mdns_name']) { $c['mdns_name'] } else { 'ventoy-rescue' }; Write-Host "          http://$($n -replace '\.local$','').local:$port/mcp （mDNS）"
                   foreach ($ip in $ips) { Write-Host "网页管理: http://${ip}:$port/admin （局域网里的手机或电脑用浏览器打开，用访问令牌登录）" -ForegroundColor Cyan } }
        'tunnel' {
            $cf = Get-Process cloudflared
            Write-Host ("cloudflared: {0}" -f $(if ($cf) { "运行中 PID $($cf.Id -join ',')" } else { '未运行' }))
            $sd = if ($c['state_dir']) { $c['state_dir'] } else { Join-Path (Split-Path $envf) 'logs' }
            $lf = Join-Path $sd 'cloudflared.log'
            if (Test-Path -LiteralPath $lf) {
                $lines = @(Get-Content -LiteralPath $lf -Tail 400)
                $from = 0; for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Starting tunnel|Starting metrics server') { $from = $i } }
                $n = 0; $err = $null
                for ($i = $from; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match 'Registered tunnel connection') { $n++ }
                    if ($lines[$i] -match 'Unregistered tunnel connection|Connection terminated') { $n-- }
                    if ($lines[$i] -match ' ERR |not valid|failed to|error') { $err = $lines[$i] }
                }
                if ($n -lt 0) { $n = 0 }
                Write-Host "隧道连接: $n" -ForegroundColor $(if ($n -gt 0) { 'Green' } else { 'Yellow' })
                if ($err) { if ($err -match 'token is not valid|Unauthorized') { $err = '隧道令牌无效，请用「模式: 隧道」重新填写（先删掉 shellgate.env 里的 tunnel_token= 行）' }
                    Write-Host ("最近错误: " + ($err -replace 'https?://\S+', '<url>')) -ForegroundColor Yellow }
            } else { Write-Host '隧道连接: 还没有 cloudflared.log' -ForegroundColor Yellow }
            if (-not $c['tunnel_token']) { Write-Host '缺少 tunnel_token：用「模式→隧道」按钮填写' -ForegroundColor Red }
        }
    }
}

function Restart-SG {
    $envf = Find-Env
    if (-not $envf) { Write-Host '没找到 U 盘 \shellgate\shellgate.env，无法启动' -ForegroundColor Red; return }
    if (-not (Test-Path -LiteralPath $SG)) { Write-Host "找不到 $SG" -ForegroundColor Red; return }
    Get-Process shellgate, cloudflared | Stop-Process -Force
    # Menu windows inherit a shorter PATH than the boot script; ShellGate looks for cloudflared on PATH.
    $pd = 'X:\Program Files\ShellGatePE'
    foreach ($t in 'cloudflared','bin','7zip','wimlib','aria2','dufs') { $d = Join-Path $pd $t; if ((Test-Path $d) -and ($env:PATH -notlike "*$d*")) { $env:PATH = "$env:PATH;$d" } }
    Start-Sleep 1
    $logd = Join-Path (Split-Path $envf) 'logs'; New-Item -ItemType Directory -Force $logd | Out-Null
    $log = Join-Path $logd ('pe-' + (Get-Date -Format yyyyMMdd) + '.log')
    Add-Content -LiteralPath $log "[shellgate] restart $(Get-Date -Format s) via sg.ps1"
    Start-Process cmd.exe -WindowStyle Minimized -ArgumentList "/c `"`"$SG`" --env-file `"$envf`" >> `"$log`" 2>&1`""
    Write-Host '已重启，等待上线...'
    $c = Read-Cfg $envf; $port = if ($c['port']) { $c['port'] } else { '8790' }; $up = $false
    for ($i = 0; $i -lt 20 -and -not $up; $i++) { Start-Sleep 1
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:$port/health" | Out-Null; $up = $true } catch {} }
    if (-not $up) { Write-Host "20 秒内没上线，看日志: $log" -ForegroundColor Red }
}

function Set-Mode([string]$m) {
    $m = $m.ToLower()
    if (@('local','lan','tunnel') -notcontains $m) { Write-Host '用法: sg.ps1 mode local|lan|tunnel'; return }
    $envf = Find-Env
    if (-not $envf) { Write-Host '没找到 U 盘 \shellgate\shellgate.env' -ForegroundColor Red; return }
    $c = Read-Cfg $envf
    $newTok = $null
    if ($m -eq 'tunnel' -and -not $c['tunnel_token']) {
        Write-Host '隧道模式需要 Cloudflare 隧道令牌（Zero Trust → Tunnels → 安装命令里 --token 后面那串）。'
        if ($env:SG_TUNNEL_TOKEN) { $newTok = $env:SG_TUNNEL_TOKEN.Trim() }
        elseif ([Console]::IsInputRedirected) {
            Write-Host '没有可输入的控制台：请在菜单里操作，或设置环境变量 SG_TUNNEL_TOKEN 后再运行。未修改' -ForegroundColor Red; $script:rc = 2; return
        } else {
            Write-Host -NoNewline '粘贴隧道令牌（不回显，回车结束，5 分钟内无输入自动取消）: '
            $sb = New-Object Text.StringBuilder; $deadline = (Get-Date).AddMinutes(5)
            while ($true) {
                if ((Get-Date) -gt $deadline) { Write-Host ''; Write-Host '超时未输入，未修改' -ForegroundColor Red; $script:rc = 2; return }
                if (-not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 100; continue }
                $k = [Console]::ReadKey($true)
                if ($k.Key -eq 'Enter') { break }
                if ($k.Key -eq 'Backspace') { if ($sb.Length) { [void]$sb.Remove($sb.Length - 1, 1) }; continue }
                if ($k.KeyChar -ge ' ') { [void]$sb.Append($k.KeyChar); $deadline = (Get-Date).AddMinutes(5) }
            }
            Write-Host ''; $newTok = $sb.ToString().Trim()
        }
        if (-not $newTok -or $newTok.Length -lt 20) { Write-Host '令牌为空或太短，未修改' -ForegroundColor Red; $script:rc = 2; return }
    }
    Copy-Item -LiteralPath $envf "$envf.bak" -Force
    $out = New-Object System.Collections.Generic.List[string]; $done = $false
    foreach ($l in (Get-Content -LiteralPath $envf)) {
        $t = $l.Trim()
        if ($t -and -not $t.StartsWith('#') -and $t -match '=') {
            $k = Norm $t.Substring(0, $t.IndexOf('='))
            $v = $t.Substring($t.IndexOf('=') + 1).Trim().ToLower()
            if ($k -eq 'net') { if (-not $done) { $out.Add("net=$m"); $done = $true }; continue }
            if ($k -eq 'mode' -and @('local','lan','tunnel','localhost','loopback','cloudflare','cf') -contains $v) { continue }
        }
        $out.Add($l)
    }
    if (-not $done) { $out.Add("net=$m") }
    if ($newTok) { $out.Add("tunnel_token=$newTok") }
    [IO.File]::WriteAllLines($envf, $out, (New-Object Text.UTF8Encoding $false))
    Write-Host "已切换为: $m  $($ModeName[$m])（原配置备份为 shellgate.env.bak）" -ForegroundColor Green
    if ($m -ne 'local') { wpeutil InitializeNetwork | Out-Null }
    Restart-SG
    Show-Status
}

switch ($Cmd.ToLower()) {
    'status'  { Show-Status }
    'mode'    { Set-Mode $Arg }
    'restart' { Restart-SG; Show-Status }
    default   { Write-Host '用法: sg.ps1 status | mode local|lan|tunnel | restart' }
}
exit $script:rc
