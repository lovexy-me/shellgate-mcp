//! Local admin page: status, connection details for MCP clients, and the Cloudflare wizard.
//!
//! Listens on 127.0.0.1:<admin_port> only. Every API call needs the admin key, a random value
//! written to `<state_dir>/admin.key` (private file) at start and handed to the page by the
//! launcher (portable: opened in the browser as `/#k=<key>`; Android: loaded by the app's WebView).
//! The ShellGate Bearer token is also accepted, so a user who has the token can always get in.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use crate::config::Settings;
use crate::events;
use crate::policy;

const PAGE: &str = include_str!("admin.html");

struct AdminCtx {
    s: Settings,
    key: String,
}

pub fn key_path(s: &Settings) -> PathBuf {
    Path::new(&s.state_dir).join("admin.key")
}

/// Create (or reuse) the admin key file and return the key.
pub fn ensure_key(s: &Settings) -> String {
    let p = key_path(s);
    if let Ok(k) = std::fs::read_to_string(&p) {
        let k = k.trim().to_string();
        if k.len() >= 32 {
            return k;
        }
    }
    let _ = crate::platform::create_private_dir(Path::new(&s.state_dir));
    let k = policy::random_hex(20);
    use std::io::Write;
    let _ = std::fs::remove_file(&p);
    if let Ok(mut f) = crate::platform::private_opts().write(true).create_new(true).open(&p) {
        let _ = f.write_all(k.as_bytes());
    }
    k
}

fn authorized(ctx: &AdminCtx, h: &HeaderMap) -> bool {
    let k = h.get("x-admin-key").map(|v| v.as_bytes()).unwrap_or(b"");
    if !k.is_empty() && policy::ct_eq(k, ctx.key.as_bytes()) {
        return true;
    }
    let b = h.get(header::AUTHORIZATION).map(|v| v.as_bytes()).unwrap_or(b"");
    policy::ct_eq(b, format!("Bearer {}", ctx.s.token).as_bytes())
}

/// Failed login: answer slowly so a LAN guesser gets about one try per second per connection.
async fn unauth() -> Response {
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    j(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}))
}

fn j(status: StatusCode, v: Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], v.to_string()).into_response()
}

/// Connection details. `with_token` only for the authenticated admin page, never for the MCP tool.
pub fn connection_info(s: &Settings, with_token: bool) -> Value {
    let lan_ip = crate::net::primary_ipv4().map(|ip| ip.to_string());
    let (conns, last_err, _) = crate::net::tunnel_log_state(&s.state_dir);
    let mcp_public = if s.public_url.is_empty() { None } else { Some(format!("{}/mcp", s.public_url)) };
    let lan_url = lan_ip.as_ref().map(|ip| format!("http://{ip}:{}/mcp", s.port));
    let mut v = json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "edition": crate::tools::EDITION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "net": s.net.as_str(),
        "listen": format!("{}:{}", s.host, s.port),
        "local_url": format!("http://127.0.0.1:{}/mcp", s.port),
        "lan_ip": lan_ip,
        "lan_url": if s.net == crate::config::NetMode::Lan { lan_url } else { None },
        "public_url": mcp_public,
        "tunnel": {
            "configured": !s.tunnel_token.is_empty(),
            "running": events::TUNNEL_RUNNING.load(Ordering::Relaxed),
            "connections": conns,
            "restarts": events::TUNNEL_RESTARTS.load(Ordering::Relaxed),
            "last_error": last_err.map(|e| e.chars().take(300).collect::<String>()),
        },
        "uptime_s": events::uptime(),
        "config": s.env_file,
        "redact": s.redact,
        "desktop": s.desktop,
    });
    if with_token {
        v["token"] = json!(s.token);
        let url = v["public_url"].as_str().map(str::to_string)
            .or_else(|| v["lan_url"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("http://127.0.0.1:{}/mcp", s.port));
        v["client_config"] = json!({"mcpServers": {"shellgate": {
            "type": "http", "url": url,
            "headers": {"Authorization": format!("Bearer {}", s.token)}
        }}});
    }
    v
}

async fn page() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store"),
      (header::HeaderName::from_static("x-frame-options"), "DENY"),
      (header::HeaderName::from_static("content-security-policy"), "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")],
     PAGE).into_response()
}

async fn status(State(ctx): State<Arc<AdminCtx>>, h: HeaderMap) -> Response {
    if !authorized(&ctx, &h) {
        return unauth().await;
    }
    let reveal = h.get("x-reveal").is_some();
    let mut v = connection_info(&ctx.s, reveal);
    // the page is local, but people copy its log into chats and issues: redact it like tool output
    let red = crate::redact::for_settings(&ctx.s, true);
    let mut c = crate::redact::Counts::default();
    let ev: Vec<Value> = events::recent(60).into_iter().map(|(t, m)| json!({"t": t, "m": red.text(&m, &mut c)})).collect();
    v["events"] = json!(ev);
    let (_, _, tail) = crate::net::tunnel_log_state(&ctx.s.state_dir);
    v["tunnel_log"] = json!(tail.iter().map(|l| red.text(&crate::redact::mask_ingress_hosts(l), &mut c)).collect::<Vec<_>>());
    j(StatusCode::OK, v)
}

#[cfg(not(feature = "admin"))]
async fn cf(State(ctx): State<Arc<AdminCtx>>, h: HeaderMap, _body: Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return unauth().await;
    }
    j(StatusCode::OK, json!({"status": "error", "error": "this build has no Cloudflare wizard: create the tunnel in the Cloudflare dashboard and paste its token here"}))
}

#[cfg(feature = "admin")]
async fn cf(State(ctx): State<Arc<AdminCtx>>, h: HeaderMap, body: Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return unauth().await;
    }
    let a: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    match crate::cf::tool(&ctx.s, &a).await {
        Ok(v) => {
            events::ev(format!("admin: cloudflare {} ok", a.get("action").and_then(Value::as_str).unwrap_or("?")));
            j(StatusCode::OK, v)
        }
        Err(e) => j(StatusCode::OK, json!({"status": "error", "error": e})),
    }
}

async fn settings_post(State(ctx): State<Arc<AdminCtx>>, h: HeaderMap, body: Bytes) -> Response {
    if !authorized(&ctx, &h) {
        return unauth().await;
    }
    let a: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let path = PathBuf::from(&ctx.s.env_file);
    let mut changes: Vec<(&str, Option<String>)> = vec![];
    if let Some(n) = a.get("net").and_then(Value::as_str) {
        if !["local", "lan", "tunnel"].contains(&n) {
            return j(StatusCode::OK, json!({"status": "error", "error": "net must be local, lan or tunnel"}));
        }
        changes.push(("net", Some(n.to_string())));
    }
    if let Some(t) = a.get("tunnel_token").and_then(Value::as_str) {
        let t = t.trim();
        changes.push(("tunnel_token", if t.is_empty() { None } else { Some(t.to_string()) }));
    }
    if let Some(u) = a.get("public_url").and_then(Value::as_str) {
        let u = u.trim().trim_end_matches('/');
        if !u.is_empty() && !u.starts_with("https://") {
            return j(StatusCode::OK, json!({"status": "error", "error": "public_url must start with https://"}));
        }
        changes.push(("public_url", if u.is_empty() { None } else { Some(u.to_string()) }));
    }
    let mut new_tok = None;
    if a.get("new_token").and_then(Value::as_bool) == Some(true) {
        let t = policy::random_hex(24);
        new_tok = Some(t.clone());
        changes.push(("token", Some(t)));
    }
    if changes.is_empty() {
        return j(StatusCode::OK, json!({"status": "error", "error": "nothing to change"}));
    }
    match crate::config::set_keys(&path, &changes) {
        Ok(()) => {
            events::ev(format!("admin: settings changed ({})", changes.iter().map(|c| c.0).collect::<Vec<_>>().join(", ")));
            let mut v = json!({"status": "ok", "restart_required": true});
            // the caller is already authenticated; a LAN page needs the new token to stay logged in
            if let Some(t) = new_tok { v["token"] = json!(t); }
            j(StatusCode::OK, v)
        }
        Err(e) => j(StatusCode::OK, json!({"status": "error", "error": e})),
    }
}

async fn restart(State(ctx): State<Arc<AdminCtx>>, h: HeaderMap) -> Response {
    if !authorized(&ctx, &h) {
        return unauth().await;
    }
    events::ev("admin: restart requested");
    crate::request_restart();
    j(StatusCode::OK, json!({"status": "ok", "restarting": true}))
}

fn routes(s: Settings, key: String) -> Router {
    let ctx = Arc::new(AdminCtx { s, key });
    Router::new()
        .route("/", get(page))
        .route("/api/status", get(status))
        .route("/api/cloudflare", post(cf))
        .route("/api/settings", post(settings_post))
        .route("/api/restart", post(restart))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(ctx)
}

/// The same page and API under `/admin` on the main port, for other devices on the LAN (net=lan only).
/// Login is the ShellGate access token (Bearer); the local admin key is accepted too.
pub fn lan_router(s: &Settings) -> Router {
    let key = ensure_key(s);
    routes(s.clone(), key)
}

pub async fn serve(s: Settings) {
    if s.admin_port == 0 {
        return;
    }
    let key = ensure_key(&s);
    // SHELLGATE_ADMIN_HOST: 127.0.0.1 by default; a router may set its LAN address (the admin key is still required)
    let host = std::env::var("SHELLGATE_ADMIN_HOST").ok().filter(|h| !h.trim().is_empty()).unwrap_or_else(|| "127.0.0.1".into());
    let addr = format!("{}:{}", host.trim(), s.admin_port);
    let router = routes(s, key);
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            events::ev(format!("admin page on http://{addr}/ (key in admin.key)"));
            let _ = axum::serve(l, router).await;
        }
        Err(e) => events::ev(format!("admin page: cannot listen on {addr}: {e}")),
    }
}
