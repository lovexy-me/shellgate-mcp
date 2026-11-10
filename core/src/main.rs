//! ShellGate MCP server for OpenWrt / embedded Linux / Windows (Ventoy rescue stick).
//!
//! Implements the MCP Streamable HTTP transport in stateless JSON-response mode:
//! every POST /mcp carries one JSON-RPC message (or a batch) and gets a JSON reply.

#[cfg(feature = "admin")]
mod admin;
mod audit;
#[cfg(feature = "admin")]
mod cf;
mod config;
mod desktop;
#[cfg(all(windows, feature = "desktop"))]
mod desktop_win;
mod events;
mod exec;
#[cfg(feature = "net-tools")]
mod lan;
mod net;
mod platform;
mod policy;
mod redact;
mod tools;
mod ventoy;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};

use tools::App;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Portable and Android builds create their own config on first start (with a fresh token).
pub const SELF_CONFIG: bool = cfg!(any(feature = "edition-portable", feature = "edition-android", target_os = "android"));

static RESTART: tokio::sync::Notify = tokio::sync::Notify::const_new();
static RESTART_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ask the server to stop and start again with a freshly read config (admin page, Cloudflare wizard).
#[allow(dead_code)]
pub fn request_restart() {
    RESTART_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
    // let the HTTP reply go out first
    tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(400)).await; RESTART.notify_waiters(); RESTART.notify_one(); });
}

/// Replace this process with a fresh copy of itself (same arguments), so the config is re-read
/// from scratch. Unix keeps the PID (exec), which a supervising Android service relies on.
fn reexec() -> ! {
    let exe = std::env::current_exe().expect("current_exe");
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // drop the SHELLGATE_* values that came from the config file, so edits take effect
        let mut c = std::process::Command::new(&exe);
        c.args(&args);
        for (k, _) in std::env::vars() {
            if k.starts_with("SHELLGATE_") && !PRESERVE_ENV.with(|p| p.borrow().contains(&k)) {
                c.env_remove(&k);
            }
        }
        let e = c.exec();
        eprintln!("restart failed: {e}");
        std::process::exit(75)
    }
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new(&exe);
        c.args(&args);
        for (k, _) in std::env::vars() {
            if k.starts_with("SHELLGATE_") && !PRESERVE_ENV.with(|p| p.borrow().contains(&k)) {
                c.env_remove(&k);
            }
        }
        match c.spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => { eprintln!("restart failed: {e}"); std::process::exit(75) }
        }
    }
}

thread_local! {
    /// SHELLGATE_* variables that were set in the real environment before the config was read.
    static PRESERVE_ENV: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
const PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
#[cfg(unix)]
const SHELL_NOTE: &str = "- Commands run as the service user via /bin/sh -c; cwd and env do not persist between calls.\n\
- On OpenWrt prefer uci, logread, ubus, /etc/init.d/<service> for configuration and services.\n\
- Multi-line scripts: use run_script (sh, bash, python3, ash), or run_command with stdin (e.g. `ssh host sh -s`).\n";
#[cfg(windows)]
const SHELL_NOTE: &str = "- This host is Windows. run_command uses cmd /C (PowerShell if SHELLGATE_SHELL=powershell); cwd and env do not persist.\n\
- Multi-line scripts: use run_script with interpreter powershell (default), pwsh, cmd or python.\n\
- Paths are Windows paths (C:\\...); file tools need absolute paths.\n";

const INSTRUCTIONS_COMMON: &str = "- Long tasks (package installs, downloads): use start_job, then poll job_output.\n\
- Ventoy stick: ventoy_info / ventoy_list / ventoy_add (+ ventoy_add_status) / ventoy_remove / ventoy_config_get / ventoy_config_set.\n\
- Output is redacted on the server (public IPs, MACs, keys, tokens, secrets); placeholders like\n  \
<ip> or <x> are not the real values, so never write them back into config files.\n\
- If a tool answers status=confirmation_required, show the user the command and reasons,\n  \
and only call again with confirm_code after the user explicitly agrees.\n\
- Prefer read_file/edit_file over sed/cat for files under the allowed directories.";

fn instructions() -> String {
    format!("ShellGate runs commands and edits files on the user's own machine (router, PC, or a rescue stick session).\n{SHELL_NOTE}{INSTRUCTIONS_COMMON}")
}

struct Ctx {
    app: Arc<App>,
    expected: Vec<u8>,
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

async fn health() -> Response {
    json_response(StatusCode::OK, &json!({"status": "ok", "service": "shellgate", "version": VERSION, "impl": "rust"}))
}

fn authorized(ctx: &Ctx, headers: &HeaderMap) -> bool {
    let supplied = headers.get(header::AUTHORIZATION).map(HeaderValue::as_bytes).unwrap_or(b"");
    policy::ct_eq(supplied, &ctx.expected)
}

fn unauthorized() -> Response {
    let mut r = json_response(StatusCode::UNAUTHORIZED, &json!({"error": "unauthorized"}));
    r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"shellgate\""));
    r
}

fn rpc_error(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

async fn handle_message(ctx: &Ctx, ip: &str, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    // notifications and client responses get no reply
    let Some(id) = id else { return None };
    if method.is_empty() {
        return None;
    }
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = if PROTOCOLS.contains(&asked) { asked } else { PROTOCOLS[0] };
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "shellgate", "version": VERSION, "edition": tools::EDITION},
                "instructions": instructions(),
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": ctx.app.tool_list()}),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "missing tool name"));
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (mut value, is_error) = ctx.app.call(ip, name, &args).await;
            // a screenshot travels as MCP image content, not inside the JSON text
            let image = value.as_object_mut().and_then(|m| m.remove("_image"));
            let mut content = vec![json!({"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default()})];
            if let Some(img) = image {
                content.push(json!({"type": "image", "data": img["data"], "mimeType": img["mimeType"]}));
            }
            json!({"content": content, "structuredContent": value, "isError": is_error})
        }
        "resources/list" => json!({"resources": []}),
        "prompts/list" => json!({"prompts": []}),
        _ => return Some(rpc_error(id, -32601, &format!("method not found: {method}"))),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

async fn mcp_post(State(ctx): State<Arc<Ctx>>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    let ip = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return json_response(StatusCode::BAD_REQUEST, &rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
    };
    let reply = match &parsed {
        Value::Array(batch) => {
            let mut out = vec![];
            for m in batch {
                if let Some(r) = handle_message(&ctx, &ip, m).await {
                    out.push(r);
                }
            }
            if out.is_empty() { None } else { Some(Value::Array(out)) }
        }
        m => handle_message(&ctx, &ip, m).await,
    };
    match reply {
        Some(v) => json_response(StatusCode::OK, &v),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn mcp_other(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers) {
        return unauthorized();
    }
    // stateless server: no server-initiated SSE stream and no sessions to delete
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

fn usage() -> ! {
    println!("shellgate {VERSION}\n\
usage: shellgate [--env-file PATH] [--version] [--gen-token] [--init-config PATH] [--display WxH|max|list]\n\
  --env-file PATH     config file (also SHELLGATE_ENV_FILE)\n\
  --gen-token         print a new random 48-character token and exit\n\
  --init-config PATH  write a new config with a fresh random token (refuses to overwrite) and exit\n\
  --display SPEC      Windows: set the screen resolution (1920x1080, max, list) and exit\n\
config search order: --env-file, SHELLGATE_ENV_FILE, {} next to the executable, {}, <Ventoy partition>/{}/{}",
             config::STICK_ENV_NAME, config::DEFAULT_ENV_FILE, config::STICK_DIR, config::STICK_ENV_NAME);
    std::process::exit(0)
}

fn new_token() -> String {
    policy::random_hex(24)
}

fn init_config(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if p.exists() {
        return Err(format!("{path} already exists; not overwritten"));
    }
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let token = new_token();
    use std::io::Write;
    let mut f = platform::private_opts().write(true).create_new(true).open(p).map_err(|e| format!("{path}: {e}"))?;
    f.write_all(config::template(&token).as_bytes()).map_err(|e| e.to_string())?;
    println!("wrote {path}\ntoken (shown once; put it in your MCP client as `Authorization: Bearer <token>`):\n{token}");
    Ok(())
}

fn main() {
    let mut env_file: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--env-file" | "--config" => env_file = args.next(),
            "--version" | "-V" => { println!("{VERSION}"); return; }
            "--open" => {}
            "--gen-token" => { println!("{}", new_token()); return; }
            // WinPE helper: set the screen resolution (WIDTHxHEIGHT | max | list) and exit
            "--display" => {
                let spec = args.next().unwrap_or_else(|| "list".into());
                #[cfg(all(windows, feature = "desktop"))]
                match desktop_win::set_display(&spec) {
                    Ok(m) => { println!("{m}"); return; }
                    Err(e) => { eprintln!("{e}"); std::process::exit(1) }
                }
                #[cfg(not(all(windows, feature = "desktop")))]
                { eprintln!("--display {spec}: Windows desktop build only"); std::process::exit(1) }
            }
            "--init-config" => {
                let Some(p) = args.next() else { usage() };
                if let Err(e) = init_config(&p) { eprintln!("{e}"); std::process::exit(2) }
                return;
            }
            _ => usage(),
        }
    }
    PRESERVE_ENV.with(|p| *p.borrow_mut() = std::env::vars().map(|(k, _)| k).filter(|k| k.starts_with("SHELLGATE_")).collect());
    let mut open_admin = false;
    if SELF_CONFIG {
        let path = config::self_config_path(env_file.clone());
        match config::ensure_config(&path) {
            Ok(true) => { eprintln!("first start: created {} with a new access token", path.display()); open_admin = true; }
            Ok(false) => {}
            Err(e) => { eprintln!("{e}"); platform::pause_if_double_clicked(); std::process::exit(2) }
        }
        env_file = Some(path.to_string_lossy().to_string());
    }
    if std::env::args().any(|a| a == "--open") {
        open_admin = true;
    }
    let settings = match config::load(env_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            platform::pause_if_double_clicked();
            std::process::exit(2)
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    rt.block_on(serve(settings, open_admin));
    drop(rt);
    if RESTART_FLAG.load(std::sync::atomic::Ordering::SeqCst) {
        reexec();
    }
}

/// Open the admin page in the default browser (portable build, first start or --open).
#[allow(unused_variables)]
fn open_browser(url: &str) {
    #[cfg(windows)]
    { let _ = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn(); }
    #[cfg(all(unix, not(target_os = "android")))]
    { let _ = std::process::Command::new("xdg-open").arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn(); }
}

#[allow(unused_variables)]
async fn serve(settings: config::Settings, open_admin: bool) {
    events::mark_started();
    let addr: SocketAddr = match format!("{}:{}", settings.host, settings.port).parse() {
        Ok(a) => a,
        Err(e) => { eprintln!("bad listen address: {e}"); platform::pause_if_double_clicked(); std::process::exit(2) }
    };
    let net = settings.net;
    if !addr.ip().is_loopback() && net != config::NetMode::Lan {
        eprintln!("WARNING: listening on {addr}; prefer 127.0.0.1 behind a tunnel, or set net=lan on purpose.");
    }
    let expected = format!("Bearer {}", settings.token).into_bytes();
    let audit = audit::Audit::new(&settings.audit_log, settings.audit_max_bytes);
    let sem = Semaphore::new(settings.max_concurrent.max(1));
    let mode = if settings.mode_allowlist { "allowlist" } else { "full" };
    let redactor = redact::Redactor::new(settings.redact, &settings.redact_domains);
    let redact_state = if settings.redact { "on" } else { "OFF" };
    let audit_path = settings.audit_log.clone();
    let env_file = settings.env_file.clone();
    let net_settings = settings.clone();
    let policy = match policy::Policy::new(settings) {
        Ok(p) => p,
        Err(e) => { eprintln!("{e}"); platform::pause_if_double_clicked(); std::process::exit(2) }
    };
    let app = Arc::new(App { policy, audit, jobs: Mutex::new(Default::default()), sem, redactor,
                             downloads: std::sync::Mutex::new(Default::default()), shot: std::sync::Mutex::new(None) });
    let ctx = Arc::new(Ctx { app, expected });

    let router = Router::new()
        .route("/health", get(health))
        .route("/mcp", axum::routing::post(mcp_post).get(mcp_other).delete(mcp_other))
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024))
        .with_state(ctx);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => { eprintln!("cannot listen on {addr}: {e}"); platform::pause_if_double_clicked(); std::process::exit(1) }
    };
    eprintln!("ShellGate {VERSION} (rust) on http://{addr}/mcp (net={}, mode={mode}, redact={redact_state}, config={env_file}, audit={audit_path})",
              net.as_str());
    if platform::is_winpe() {
        eprintln!("running in Windows PE (pe_network={})", if net_settings.pe_network { "on" } else { "off" });
        tokio::spawn(net::winpe_network(net_settings.clone()));
    }
    match net {
        config::NetMode::Lan => {
            let port = net_settings.port;
            match net::primary_ipv4() {
                Some(ip) => eprintln!("lan mode: connect from the same LAN to http://{ip}:{port}/mcp (Bearer token required)"),
                None => eprintln!("lan mode: no LAN address detected yet; listening on {addr}"),
            }
            if net_settings.mdns {
                net::spawn_mdns(net_settings.mdns_name.clone());
                eprintln!("lan mode: also http://{}.local:{port}/mcp via mDNS", net_settings.mdns_name);
            }
        }
        config::NetMode::Tunnel => {
            if net_settings.tunnel_token.is_empty() {
                eprintln!("tunnel mode: no tunnel_token set; run cloudflared yourself, pointing at http://127.0.0.1:{}", net_settings.port);
            } else {
                tokio::spawn(net::supervise_cloudflared(net_settings.clone()));
            }
        }
        config::NetMode::Local => {}
    }
    #[cfg(feature = "admin")]
    if net_settings.admin_port != 0 {
        let key = admin::ensure_key(&net_settings);
        let url = format!("http://127.0.0.1:{}/#k={key}", net_settings.admin_port);
        eprintln!("admin page: {url}");
        tokio::spawn(admin::serve(net_settings.clone()));
        if open_admin && !cfg!(target_os = "android") && std::env::var_os("SHELLGATE_NO_BROWSER").is_none() {
            open_browser(&url);
        }
    }
    let shutdown = async {
        tokio::select! {
            _ = platform::shutdown_signal() => {}
            _ = RESTART.notified() => { events::ev("restarting with the new config"); }
        }
    };
    if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
        eprintln!("server error: {e}");
    }
}
