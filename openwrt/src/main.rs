//! ShellGate MCP server for OpenWrt / embedded Linux.
//!
//! Implements the MCP Streamable HTTP transport in stateless JSON-response mode:
//! every POST /mcp carries one JSON-RPC message (or a batch) and gets a JSON reply.

mod audit;
mod config;
mod exec;
mod policy;
mod tools;

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
const PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const INSTRUCTIONS: &str = "ShellGate runs commands and edits files on the user's own router / Linux host.\n\
- Commands run as the service user via /bin/sh -c; cwd and env do not persist between calls.\n\
- On OpenWrt prefer uci, logread, ubus, /etc/init.d/<service> for configuration and services.\n\
- Long tasks (opkg install, downloads): use start_job, then poll job_output.\n\
- If a tool answers status=confirmation_required, show the user the command and reasons,\n  \
and only call again with confirm_code after the user explicitly agrees.\n\
- Prefer read_file/edit_file over sed/cat for files under the allowed directories.";

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
                "serverInfo": {"name": "shellgate", "version": VERSION},
                "instructions": INSTRUCTIONS,
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools::definitions()}),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "missing tool name"));
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (value, is_error) = ctx.app.call(ip, name, &args).await;
            json!({
                "content": [{"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default()}],
                "structuredContent": value,
                "isError": is_error,
            })
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
    println!("shellgate {VERSION}\nusage: shellgate [--env-file PATH] [--version]\ndefault env file: {}", config::DEFAULT_ENV_FILE);
    std::process::exit(0)
}

fn main() {
    let mut env_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--env-file" => env_file = args.next(),
            "--version" | "-V" => { println!("{VERSION}"); return; }
            _ => usage(),
        }
    }
    let settings = match config::load(env_file) {
        Ok(s) => s,
        Err(e) => { eprintln!("{e}"); std::process::exit(2) }
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    rt.block_on(serve(settings));
}

async fn serve(settings: config::Settings) {
    let addr: SocketAddr = match format!("{}:{}", settings.host, settings.port).parse() {
        Ok(a) => a,
        Err(e) => { eprintln!("bad listen address: {e}"); std::process::exit(2) }
    };
    if !addr.ip().is_loopback() {
        eprintln!("WARNING: listening on {addr}; prefer 127.0.0.1 behind a tunnel.");
    }
    let expected = format!("Bearer {}", settings.token).into_bytes();
    let audit = audit::Audit::new(&settings.audit_log, settings.audit_max_bytes);
    let sem = Semaphore::new(settings.max_concurrent.max(1));
    let mode = if settings.mode_allowlist { "allowlist" } else { "full" };
    let audit_path = settings.audit_log.clone();
    let env_file = settings.env_file.clone();
    let policy = match policy::Policy::new(settings) {
        Ok(p) => p,
        Err(e) => { eprintln!("{e}"); std::process::exit(2) }
    };
    let app = Arc::new(App { policy, audit, jobs: Mutex::new(Default::default()), sem });
    let ctx = Arc::new(Ctx { app, expected });

    let router = Router::new()
        .route("/health", get(health))
        .route("/mcp", axum::routing::post(mcp_post).get(mcp_other).delete(mcp_other))
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024))
        .with_state(ctx);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => { eprintln!("cannot listen on {addr}: {e}"); std::process::exit(1) }
    };
    eprintln!("ShellGate {VERSION} (rust) on http://{addr}/mcp (mode={mode}, config={env_file}, audit={audit_path})");
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    };
    if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
        eprintln!("server error: {e}");
    }
}
