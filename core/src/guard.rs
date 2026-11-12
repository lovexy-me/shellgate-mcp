//! Guarded changes: snapshot config files, run a command, and restore the files (then run a
//! reload command) unless the change is confirmed within a deadline. Made for OpenWrt uci /
//! firewall / network edits over the very link the change might break, but works for any files.
//!
//! State lives in <state_dir>/guard/<id>/ (meta.json + file copies), so a pending rollback also
//! survives a ShellGate restart or a reboot: `recover` re-arms or runs it at startup.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub const OPENWRT_FILES: &[&str] = &["/etc/config/network", "/etc/config/firewall", "/etc/config/wireless", "/etc/config/dhcp"];
pub const OPENWRT_RELOAD: &str = "/etc/init.d/network reload; /etc/init.d/firewall reload; (wifi reload || true) 2>/dev/null; /etc/init.d/dnsmasq reload";
pub const MAX_FILES: usize = 20;
pub const MAX_FILE_BYTES: u64 = 5_000_000;
pub const MIN_TIMEOUT: u64 = 15;
pub const MAX_TIMEOUT: u64 = 900;
pub const DEFAULT_TIMEOUT: u64 = 120;
/// Danger reasons a guarded change may skip the confirm code for: the rollback undoes them.
pub const COVERED_REASONS: &[&str] = &["service that may cut remote access", "network interface down"];

static LOCK: Mutex<()> = Mutex::new(());

pub fn is_openwrt() -> bool {
    Path::new("/etc/openwrt_release").exists()
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn root(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("guard")
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

pub fn read_meta(dir: &Path) -> Result<Value, String> {
    let t = fs::read_to_string(meta_path(dir)).map_err(|e| format!("{}: {e}", dir.display()))?;
    serde_json::from_str(&t).map_err(|e| e.to_string())
}

fn write_meta(dir: &Path, v: &Value) -> Result<(), String> {
    let tmp = dir.join("meta.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, meta_path(dir)).map_err(|e| e.to_string())
}

/// Copy the files into a new guard directory. Returns (id, dir, meta).
pub fn snapshot(state_dir: &str, files: &[String], command: &str, reload: &str, timeout: u64) -> Result<(String, PathBuf, Value), String> {
    if files.is_empty() {
        return Err("files: list the config files the command changes (they are restored on rollback)".into());
    }
    if files.len() > MAX_FILES {
        return Err(format!("at most {MAX_FILES} files"));
    }
    let id = format!("g{}-{}", now(), crate::policy::random_hex(2));
    let dir = root(state_dir).join(&id);
    fs::create_dir_all(root(state_dir)).map_err(|e| e.to_string())?;
    crate::platform::create_private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut list = vec![];
    for (i, f) in files.iter().enumerate() {
        let p = Path::new(f);
        if p.is_dir() {
            let _ = fs::remove_dir_all(&dir);
            return Err(format!("{f} is a directory; list files"));
        }
        let existed = p.is_file();
        let backup = format!("f{i}");
        if existed {
            let len = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            if len > MAX_FILE_BYTES {
                let _ = fs::remove_dir_all(&dir);
                return Err(format!("{f} is larger than 5 MB"));
            }
            if let Err(e) = fs::copy(p, dir.join(&backup)) {
                let _ = fs::remove_dir_all(&dir);
                return Err(format!("{f}: {e}"));
            }
        }
        list.push(json!({"path": f, "existed": existed, "backup": backup}));
    }
    let meta = json!({"id": id, "command": command, "reload": reload, "files": list,
                      "created": now(), "deadline": now() + timeout, "status": "pending"});
    write_meta(&dir, &meta)?;
    Ok((id, dir, meta))
}

/// Which files differ from their snapshot now.
pub fn changed_files(dir: &Path, meta: &Value) -> Vec<String> {
    let mut out = vec![];
    for f in meta["files"].as_array().into_iter().flatten() {
        let path = f["path"].as_str().unwrap_or("");
        let now = fs::read(path).ok();
        let then = if f["existed"].as_bool().unwrap_or(false) { fs::read(dir.join(f["backup"].as_str().unwrap_or(""))).ok() } else { None };
        if now != then {
            out.push(path.to_string());
        }
    }
    out
}

/// Put every file back as it was (removing files that did not exist). Returns restored paths.
pub fn restore_files(dir: &Path, meta: &Value) -> Result<Vec<String>, String> {
    let mut restored = vec![];
    let mut errors = vec![];
    for f in meta["files"].as_array().into_iter().flatten() {
        let path = f["path"].as_str().unwrap_or("");
        if f["existed"].as_bool().unwrap_or(false) {
            let src = dir.join(f["backup"].as_str().unwrap_or(""));
            let want = fs::read(&src).map_err(|e| format!("{}: {e}", src.display()))?;
            if fs::read(path).ok().as_deref() == Some(&want[..]) {
                continue;
            }
            let tmp = format!("{path}.sgguard");
            match fs::write(&tmp, &want).and_then(|_| {
                let _ = crate::platform::copy_mode(path, Path::new(&tmp));
                fs::rename(&tmp, path)
            }) {
                Ok(()) => restored.push(path.to_string()),
                Err(e) => { let _ = fs::remove_file(&tmp); errors.push(format!("{path}: {e}")) }
            }
        } else if Path::new(path).exists() {
            match fs::remove_file(path) {
                Ok(()) => restored.push(path.to_string()),
                Err(e) => errors.push(format!("{path}: {e}")),
            }
        }
    }
    if errors.is_empty() { Ok(restored) } else { Err(errors.join("; ")) }
}

/// Mark kept / rolled_back etc. only while still pending; returns the meta as it was.
pub fn transition(dir: &Path, to: &str) -> Result<Value, String> {
    let _g = LOCK.lock().unwrap();
    let mut m = read_meta(dir)?;
    if m["status"] != "pending" {
        return Err(format!("guard {} is already {}", m["id"].as_str().unwrap_or(""), m["status"].as_str().unwrap_or("")));
    }
    let before = m.clone();
    m["status"] = json!(to);
    m["closed"] = json!(now());
    write_meta(dir, &m)?;
    Ok(before)
}

fn record(dir: &Path, key: &str, v: Value) {
    let _g = LOCK.lock().unwrap();
    if let Ok(mut m) = read_meta(dir) {
        m[key] = v;
        let _ = write_meta(dir, &m);
    }
}

/// Roll back now if still pending: restore the files, then run the reload command.
pub async fn rollback(dir: PathBuf, shell: String, why: &str) -> Result<Value, String> {
    let meta = transition(&dir, "rolling_back")?;
    let restored = restore_files(&dir, &meta);
    let reload = meta["reload"].as_str().unwrap_or("").to_string();
    let mut reload_out = Value::Null;
    if !reload.is_empty() {
        let mut c = crate::platform::shell_command(&shell, &reload);
        c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        reload_out = match tokio::time::timeout(Duration::from_secs(90), c.output()).await {
            Ok(Ok(o)) => json!({"exit_code": o.status.code(),
                                "stderr": String::from_utf8_lossy(&o.stderr).chars().take(2000).collect::<String>()}),
            Ok(Err(e)) => json!({"error": e.to_string()}),
            Err(_) => json!({"error": "reload timed out after 90 s"}),
        };
    }
    let (status, files) = match &restored {
        Ok(r) => ("rolled_back", json!(r)),
        Err(e) => ("rollback_failed", json!({"error": e})),
    };
    let result = json!({"why": why, "restored": files, "reload": reload_out, "at": now()});
    {
        let _g = LOCK.lock().unwrap();
        let mut m = read_meta(&dir)?;
        m["status"] = json!(status);
        m["rollback"] = result.clone();
        write_meta(&dir, &m)?;
    }
    Ok(json!({"status": status, "id": meta["id"], "rollback": result}))
}

/// Arm the timer for one guard.
pub fn arm(dir: PathBuf, shell: String, deadline: u64) {
    tokio::spawn(async move {
        let wait = deadline.saturating_sub(now());
        tokio::time::sleep(Duration::from_secs(wait)).await;
        if read_meta(&dir).map(|m| m["status"] == "pending").unwrap_or(false) {
            if let Err(e) = rollback(dir.clone(), shell, "deadline passed without guarded_confirm").await {
                record(&dir, "rollback_error", json!(e));
            }
        }
    });
}

/// At startup: re-arm pending guards (rolling back at once those whose deadline passed, e.g.
/// after a reboot the change caused), and drop closed guards older than 7 days.
pub fn recover(state_dir: &str, shell: &str) -> usize {
    let mut n = 0;
    let Ok(rd) = fs::read_dir(root(state_dir)) else { return 0 };
    for e in rd.flatten() {
        let dir = e.path();
        let Ok(m) = read_meta(&dir) else { continue };
        match m["status"].as_str() {
            Some("pending") => {
                arm(dir, shell.to_string(), m["deadline"].as_u64().unwrap_or(0));
                n += 1;
            }
            Some("rolling_back") => {
                // interrupted mid-rollback: finish it
                record(&dir, "status", json!("pending"));
                arm(dir, shell.to_string(), 0);
                n += 1;
            }
            _ => {
                if m["created"].as_u64().unwrap_or(0) + 7 * 86400 < now() {
                    let _ = fs::remove_dir_all(&dir);
                }
            }
        }
    }
    n
}

pub fn find(state_dir: &str, id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("bad guard id".into());
    }
    let dir = root(state_dir).join(id);
    if !meta_path(&dir).is_file() {
        return Err(format!("no guard {id}"));
    }
    Ok(dir)
}

pub fn list(state_dir: &str) -> Vec<Value> {
    let mut v: Vec<Value> = fs::read_dir(root(state_dir)).into_iter().flatten().flatten()
        .filter_map(|e| read_meta(&e.path()).ok())
        .map(|m| json!({"id": m["id"], "status": m["status"], "command": m["command"], "deadline": m["deadline"],
                        "seconds_left": if m["status"] == "pending" { json!(m["deadline"].as_u64().unwrap_or(0).saturating_sub(now())) } else { Value::Null }}))
        .collect();
    v.sort_by(|a, b| b["id"].as_str().cmp(&a["id"].as_str()));
    v.truncate(20);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sgguard-{name}-{}", crate::policy::random_hex(4)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn rollback_restores_and_removes() {
        let d = tmp("rb");
        let state = d.join("state");
        let a = d.join("a.conf");
        let b = d.join("b.conf");
        fs::write(&a, "option x 1\n").unwrap();
        let files = vec![a.display().to_string(), b.display().to_string()];
        let marker = d.join("reloaded");
        let reload = format!("touch {}", marker.display());
        let (_id, dir, meta) = snapshot(state.to_str().unwrap(), &files, "edit", &reload, 30).unwrap();
        fs::write(&a, "option x 2\n").unwrap();
        fs::write(&b, "new\n").unwrap();
        assert_eq!(changed_files(&dir, &meta).len(), 2);
        let r = rollback(dir.clone(), "sh".into(), "test").await.unwrap();
        assert_eq!(r["status"], "rolled_back");
        assert_eq!(fs::read_to_string(&a).unwrap(), "option x 1\n");
        assert!(!b.exists());
        assert!(marker.exists());
        assert!(rollback(dir.clone(), "sh".into(), "again").await.is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn kept_is_not_rolled_back() {
        let d = tmp("keep");
        let state = d.join("state");
        let a = d.join("a.conf");
        fs::write(&a, "1").unwrap();
        let (_id, dir, _) = snapshot(state.to_str().unwrap(), &[a.display().to_string()], "edit", "", 30).unwrap();
        fs::write(&a, "2").unwrap();
        transition(&dir, "kept").unwrap();
        assert!(rollback(dir.clone(), "sh".into(), "late").await.is_err());
        assert_eq!(fs::read_to_string(&a).unwrap(), "2");
        let _ = fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn timer_and_recover() {
        let d = tmp("timer");
        let state = d.join("state");
        let a = d.join("a.conf");
        fs::write(&a, "1").unwrap();
        let (_id, dir, _) = snapshot(state.to_str().unwrap(), &[a.display().to_string()], "edit", "", 0).unwrap();
        fs::write(&a, "2").unwrap();
        // deadline already passed (e.g. after a reboot): recover rolls back right away
        assert_eq!(recover(state.to_str().unwrap(), "sh"), 1);
        for _ in 0..50 {
            if read_meta(&dir).unwrap()["status"] == "rolled_back" { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(read_meta(&dir).unwrap()["status"], "rolled_back");
        assert_eq!(fs::read_to_string(&a).unwrap(), "1");
        let _ = fs::remove_dir_all(&d);
    }
}
