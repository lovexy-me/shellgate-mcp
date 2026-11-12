//! Helper agents: a second ShellGate process the main one hands work to over loopback.
//!
//! * session agent (Windows): when ShellGate runs as a service (session 0, no desktop), the
//!   desktop_* tools are run by a copy of itself started in the logged-on user's session.
//! * elevated agent (Windows): a ShellGate running as a normal user asks once for elevation
//!   (one UAC prompt on the user's screen); run_command elevated=true then runs through it for the
//!   rest of the process lifetime.
//!
//! The agent listens on 127.0.0.1 at a random port, accepts only requests carrying the random
//! secret it was started with, writes its port to a file the parent reads, and exits when the
//! parent process is gone. Policy checks and redaction stay in the parent: the agent only executes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::config::Settings;

pub const SECRET_HEADER: &str = "x-agent-secret";

#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    pub port: u16,
    pub secret: String,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn port_file(state_dir: &str, kind: &str) -> PathBuf {
    Path::new(state_dir).join(format!("agent-{kind}.port"))
}

/// What an agent does with one request. `desktop` is supplied by the caller (Windows build).
pub type DesktopFn = Arc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;

pub async fn handle(settings: &Settings, sem: &Semaphore, desktop: Option<&DesktopFn>, req: &Value) -> Result<Value, String> {
    match req["op"].as_str().unwrap_or("") {
        "ping" => Ok(json!({"status": "ok", "pid": std::process::id(), "elevated": crate::platform::is_elevated()})),
        "run" => {
            let cmd = req["command"].as_str().ok_or("command missing")?;
            let cwd = req["cwd"].as_str().unwrap_or(".");
            let t = req["timeout"].as_u64().unwrap_or(settings.default_timeout).min(settings.max_timeout).max(1);
            crate::exec::run_once(settings, sem, cmd, cwd, t, req["stdin"].as_str()).await
        }
        "desktop" => {
            let f = desktop.ok_or("this agent has no desktop")?.clone();
            let name = req["name"].as_str().unwrap_or("").to_string();
            let args = req["args"].clone();
            tokio::task::spawn_blocking(move || f(&name, &args)).await.map_err(|e| e.to_string())?
        }
        other => Err(format!("unknown agent op {other}")),
    }
}

/// Minimal HTTP/1.1 request reader: returns (headers lowercased, body).
async fn read_request(s: &mut tokio::net::TcpStream) -> Result<(Vec<(String, String)>, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = s.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Err("header too large".into());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let headers: Vec<(String, String)> = head.lines().skip(1)
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect();
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if len > 8 * 1024 * 1024 {
        return Err("body too large".into());
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok((headers, body))
}

async fn respond(s: &mut tokio::net::TcpStream, code: u16, v: &Value) {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let head = format!("HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(&body).await;
    let _ = s.shutdown().await;
}

/// Serve requests until `alive` says the parent is gone. Writes the port to `port_file` first.
pub async fn serve(settings: Settings, secret: String, port_file: PathBuf, desktop: Option<DesktopFn>,
                   alive: impl Fn() -> bool + Send + 'static) -> Result<(), String> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let tmp = port_file.with_extension("tmp");
    std::fs::write(&tmp, format!("{port} {}\n", std::process::id())).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &port_file).map_err(|e| e.to_string())?;
    let settings = Arc::new(settings);
    let sem = Arc::new(Semaphore::new(settings.max_concurrent.max(1)));
    let secret = Arc::new(secret);
    let watchdog = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if !alive() {
                break;
            }
        }
    });
    tokio::pin!(watchdog);
    loop {
        tokio::select! {
            _ = &mut watchdog => break,
            acc = l.accept() => {
                let Ok((mut s, peer)) = acc else { continue };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let (settings, sem, secret, desktop) = (settings.clone(), sem.clone(), secret.clone(), desktop.clone());
                tokio::spawn(async move {
                    let Ok((h, body)) = read_request(&mut s).await else { return };
                    let ok = h.iter().any(|(k, v)| k == SECRET_HEADER && crate::policy::ct_eq(v.as_bytes(), secret.as_bytes()));
                    if !ok {
                        respond(&mut s, 401, &json!({"error": "unauthorized"})).await;
                        return;
                    }
                    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let out = match handle(&settings, &sem, desktop.as_ref(), &req).await {
                        Ok(v) => json!({"ok": v}),
                        Err(e) => json!({"err": e}),
                    };
                    respond(&mut s, 200, &out).await;
                });
            }
        }
    }
    let _ = std::fs::remove_file(&port_file);
    Ok(())
}

/// Send one request to an agent.
pub async fn call(ep: &Endpoint, req: &Value, timeout: Duration) -> Result<Value, String> {
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ep.port)).await.map_err(|e| format!("agent: {e}"))?;
        let body = serde_json::to_vec(req).unwrap_or_default();
        let head = format!("POST /call HTTP/1.1\r\nHost: 127.0.0.1\r\n{SECRET_HEADER}: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", ep.secret, body.len());
        s.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
        s.write_all(&body).await.map_err(|e| e.to_string())?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.map_err(|e| e.to_string())?;
        let i = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("agent: bad response")?;
        let status = String::from_utf8_lossy(&resp[..i]);
        if !status.starts_with("HTTP/1.1 200") {
            return Err(format!("agent: {}", status.lines().next().unwrap_or("")));
        }
        let v: Value = serde_json::from_slice(&resp[i + 4..]).map_err(|e| format!("agent: {e}"))?;
        match (v.get("ok"), v.get("err")) {
            (Some(ok), _) => Ok(ok.clone()),
            (_, Some(e)) => Err(e.as_str().unwrap_or("agent error").to_string()),
            _ => Err("agent: empty answer".into()),
        }
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| "agent: timed out".to_string())?
}

/// Wait for an agent's port file (written after it binds) and check it answers.
pub async fn wait_ready(port_file: &Path, secret: &str, wait: Duration) -> Result<Endpoint, String> {
    let end = tokio::time::Instant::now() + wait;
    loop {
        if let Some(port) = std::fs::read_to_string(port_file).ok().and_then(|t| t.split_whitespace().next()?.parse::<u16>().ok()) {
            let ep = Endpoint { port, secret: secret.to_string() };
            if call(&ep, &json!({"op": "ping"}), Duration::from_secs(3)).await.is_ok() {
                return Ok(ep);
            }
        }
        if tokio::time::Instant::now() >= end {
            return Err("the helper did not start (for elevation: was the UAC prompt declined or left unanswered?)".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Is the process with this pid still running?
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        crate::agent_win::pid_alive(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serve_and_call() {
        let dir = std::env::temp_dir().join(format!("sgagent-{}", crate::policy::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let pf = dir.join("agent-test.port");
        let mut s = Settings::for_tests();
        s.state_dir = dir.display().to_string();
        s.max_output_bytes = 10_000;
        s.max_timeout = 10;
        s.default_timeout = 10;
        let secret = crate::policy::random_hex(16);
        let desk: DesktopFn = Arc::new(|name: &str, _a: &Value| Ok(json!({"did": name})));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let h = tokio::spawn(serve(s, secret.clone(), pf.clone(), Some(desk), move || !stop2.load(std::sync::atomic::Ordering::SeqCst)));
        let ep = wait_ready(&pf, &secret, Duration::from_secs(5)).await.unwrap();
        let r = call(&ep, &json!({"op": "run", "command": "echo agent-ok", "cwd": dir.display().to_string()}), Duration::from_secs(10)).await.unwrap();
        assert!(r["stdout"].as_str().unwrap().contains("agent-ok"));
        let d = call(&ep, &json!({"op": "desktop", "name": "desktop_windows", "args": {}}), Duration::from_secs(5)).await.unwrap();
        assert_eq!(d["did"], "desktop_windows");
        let bad = Endpoint { port: ep.port, secret: "wrong".into() };
        assert!(call(&bad, &json!({"op": "ping"}), Duration::from_secs(5)).await.unwrap_err().contains("401"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(6), h).await.unwrap().unwrap().unwrap();
        assert!(!pf.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
