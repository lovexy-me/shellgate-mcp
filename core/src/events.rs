//! A small in-memory ring of recent service events (start, tunnel up/down, config changes),
//! shown on the local admin page. Every event is also written to stderr as before.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX: usize = 200;

static RING: Mutex<VecDeque<(u64, String)>> = Mutex::new(VecDeque::new());
pub static STARTED_UNIX: AtomicU64 = AtomicU64::new(0);
/// cloudflared child is currently running (tunnel mode).
pub static TUNNEL_RUNNING: AtomicBool = AtomicBool::new(false);
pub static TUNNEL_RESTARTS: AtomicU32 = AtomicU32::new(0);
pub static TUNNEL_PID: AtomicU32 = AtomicU32::new(0);

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Record an event and print it to stderr.
pub fn ev(msg: impl Into<String>) {
    let msg = msg.into();
    eprintln!("{msg}");
    if let Ok(mut r) = RING.lock() {
        if r.len() >= MAX {
            r.pop_front();
        }
        r.push_back((now(), msg));
    }
}

pub fn recent(n: usize) -> Vec<(u64, String)> {
    let r = RING.lock().map(|r| r.iter().cloned().collect::<Vec<_>>()).unwrap_or_default();
    let skip = r.len().saturating_sub(n);
    r.into_iter().skip(skip).collect()
}

pub fn mark_started() {
    STARTED_UNIX.store(now(), Ordering::Relaxed);
}

pub fn uptime() -> u64 {
    now().saturating_sub(STARTED_UNIX.load(Ordering::Relaxed))
}
