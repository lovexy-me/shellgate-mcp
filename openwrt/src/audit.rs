//! Append-only JSON Lines audit log with one-step size rotation (keeps flash/tmpfs small).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

pub struct Audit {
    path: PathBuf,
    max_bytes: u64,
    lock: Mutex<()>,
}

const MAX_FIELD: usize = 2000;

fn trim(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() > MAX_FIELD => {
            let mut end = MAX_FIELD;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            Value::String(format!("{}...[{} chars]", &s[..end], s.len()))
        }
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), trim(v))).collect()),
        other => other.clone(),
    }
}

/// UTC timestamp, RFC 3339, without pulling in a date crate.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

impl Audit {
    pub fn new(path: &str, max_bytes: u64) -> Self {
        let path = PathBuf::from(path);
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        Self { path, max_bytes, lock: Mutex::new(()) }
    }

    pub fn write(&self, ip: &str, tool: &str, args: &Value, result: &str, duration_ms: u64, extra: Map<String, Value>) {
        let mut entry = json!({
            "ts": now_rfc3339(), "ip": ip, "tool": tool, "args": trim(args),
            "result": result, "duration_ms": duration_ms,
        });
        if let Value::Object(m) = &mut entry {
            for (k, v) in extra {
                m.insert(k, trim(&v));
            }
        }
        let _g = self.lock.lock().unwrap();
        if fs::metadata(&self.path).map(|m| m.len() >= self.max_bytes).unwrap_or(false) {
            let _ = fs::rename(&self.path, self.path.with_extension("jsonl.1"));
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).mode(0o600).open(&self.path) {
            let _ = writeln!(f, "{entry}");
        }
    }

    pub fn tail(&self, n: usize) -> Vec<Value> {
        let Ok(text) = fs::read_to_string(&self.path) else { return vec![] };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        lines[lines.len().saturating_sub(n)..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}
