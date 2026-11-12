ShellGate 便携版 / portable
==========================

解压即用，不用安装。
Unzip and run, nothing to install.

1. 运行 shellgate（Windows 双击 shellgate.exe）。
   第一次启动会在同一目录生成 shellgate.env（含一个新的访问令牌），并在浏览器打开管理页。
   First start writes shellgate.env (with a fresh access token) next to the program and opens
   the admin page in your browser.

2. 管理页 http://127.0.0.1:8791 （只有本机能打开）：
   - 「给 AI / MCP 客户端」：一键复制连接配置（URL + 令牌）。
   - 「Cloudflare 隧道」：填你自己的 Cloudflare API 令牌和一个域名，自动建好隧道，
     任何地方的 AI 都能通过 https://你的域名/mcp 连上这台电脑。
     令牌权限：账户 / Cloudflare Tunnel / 编辑 + 区域 / DNS / 编辑。
   Admin page: copy the MCP client config; set up a Cloudflare tunnel from your own API token
   (Account: Cloudflare Tunnel Edit + Zone: DNS Edit) so agents can reach this PC from anywhere.

3. 以后再打开管理页：运行 shellgate --open ，或看窗口里打印的 admin page 地址。
   Reopen the admin page later with `shellgate --open` (or the URL printed in the console).

文件 / files
- shellgate(.exe)   服务本体 / the server
- cloudflared(.exe) Cloudflare 官方隧道程序 / Cloudflare's tunnel client
- shellgate.env     配置（含令牌，勿外传）/ config incl. the token, keep private
- logs/             审计日志、隧道日志 / audit and tunnel logs

安全 / safety
- 默认只监听本机；隧道模式下外网访问必须带令牌。危险命令要确认码。
- 不想用了：关掉窗口即可；删除整个文件夹即卸载。
