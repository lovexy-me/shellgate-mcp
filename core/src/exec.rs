//! Command execution: one-shot commands and background jobs.

use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Semaphore;

use crate::config::Settings;
use crate::platform;
use crate::policy::random_hex;

/// Keeps the first and last `limit/2` bytes of a stream.
struct HeadTail {
    limit: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: usize,
}

impl HeadTail {
    fn new(limit: usize) -> Self {
        Self { limit, head: Vec::new(), tail: VecDeque::new(), total: 0 }
    }
    fn push(&mut self, data: &[u8]) {
        self.total += data.len();
        let half = self.limit / 2;
        for &b in data {
            if self.head.len() < half {
                self.head.push(b);
            } else {
                self.tail.push_back(b);
                if self.tail.len() > half {
                    self.tail.pop_front();
                }
            }
        }
    }
    fn finish(self) -> (String, bool) {
        let truncated = self.total > self.head.len() + self.tail.len();
        let mut out = self.head;
        if truncated {
            out.extend_from_slice(platform::TRUNC_MARKER);
        }
        out.extend(self.tail);
        (platform::decode_output(&out), truncated)
    }
}

/// Reads a pipe into a shared buffer, so whatever arrived is still there if we stop waiting.
async fn collect<R: AsyncRead + Unpin>(mut r: R, ht: Arc<Mutex<HeadTail>>) {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => ht.lock().unwrap().push(&buf[..n]),
        }
    }
}

fn command(s: &Settings, cmd: &str, cwd: &str) -> Command {
    let mut c = platform::shell_command(&s.shell, cmd);
    c.current_dir(cwd);
    c
}

pub async fn run_once(s: &Settings, sem: &Semaphore, cmd: &str, cwd: &str, timeout: u64, stdin: Option<&str>) -> Result<Value, String> {
    run_cmd(s, sem, command(s, cmd, cwd), timeout, stdin).await
}

#[cfg_attr(windows, allow(dead_code))]
/// Run a program (no shell) in its own process group; stdin text (if any) is written then closed.
pub async fn run_argv(s: &Settings, sem: &Semaphore, prog: &str, args: &[String], cwd: &str, timeout: u64,
                      stdin: Option<&str>) -> Result<Value, String> {
    let mut c = platform::new_command(prog);
    c.args(args).current_dir(cwd);
    run_cmd(s, sem, c, timeout, stdin).await
}

/// Run a prepared command (its process tree is killed on timeout).
pub async fn run_cmd(s: &Settings, sem: &Semaphore, mut cmd: Command, timeout: u64,
                     stdin: Option<&str>) -> Result<Value, String> {
    let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
    let start = Instant::now();
    let mut child = cmd
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let pid = child.id();
    platform::track(&child, false);
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => {
            let data = data.as_bytes().to_vec();
            Some(tokio::spawn(async move {
                let _ = pipe.write_all(&data).await;
                let _ = pipe.shutdown().await;
            }))
        }
        _ => None,
    };
    let out_buf = Arc::new(Mutex::new(HeadTail::new(s.max_output_bytes)));
    let err_buf = Arc::new(Mutex::new(HeadTail::new(s.max_output_bytes)));
    let out = tokio::spawn(collect(child.stdout.take().unwrap(), out_buf.clone()));
    let err = tokio::spawn(collect(child.stderr.take().unwrap(), err_buf.clone()));
    let mut timed_out = false;
    let status = match tokio::time::timeout(Duration::from_secs(timeout), child.wait()).await {
        Ok(st) => st.ok(),
        Err(_) => {
            timed_out = true;
            platform::terminate(&mut child).await;
            child.wait().await.ok()
        }
    };
    platform::untrack(pid);
    if let Some(w) = writer {
        w.abort();
    }
    // a program the command started (e.g. `start notepad`, a GUI app, a daemon) inherits the pipes
    // and keeps them open after the command itself exits; keep what arrived and stop waiting
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let (a, b) = tokio::join!(tokio::time::timeout_at(deadline, out), tokio::time::timeout_at(deadline, err));
    let held_open = a.is_err() || b.is_err();
    let take = |b: &Arc<Mutex<HeadTail>>| {
        std::mem::replace(&mut *b.lock().unwrap(), HeadTail::new(0)).finish()
    };
    let (stdout, t1) = take(&out_buf);
    let (stderr, t2) = take(&err_buf);
    let mut v = json!({
        "exit_code": status.and_then(|s| s.code()),
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "truncated": t1 || t2,
        "duration_ms": start.elapsed().as_millis() as u64,
    });
    if held_open && !timed_out {
        v["note"] = json!("the command exited but a program it started is still running and holding its output open; output after exit is not captured (use start_job to follow a long-running program)");
    }
    Ok(v)
}

pub struct Job {
    pub id: String,
    pub command: String,
    pub cwd: String,
    pub started: u64,
    pub started_at: Instant,
    child: Child,
    pid: Option<u32>,
    stdin: Option<ChildStdin>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
    exit: Option<Option<i32>>,
    finished_at: Option<Instant>,
}

impl Drop for Job {
    fn drop(&mut self) {
        platform::untrack(self.pid);
    }
}

impl Job {
    fn poll(&mut self) {
        if self.exit.is_none() {
            if let Ok(Some(st)) = self.child.try_wait() {
                self.exit = Some(st.code());
                self.finished_at = Some(Instant::now());
            }
        }
    }
    pub fn running(&mut self) -> bool {
        self.poll();
        self.exit.is_none()
    }
    pub fn summary(&mut self) -> Value {
        self.poll();
        let end = self.finished_at.unwrap_or_else(Instant::now);
        json!({
            "job_id": self.id,
            "command": self.command,
            "cwd": self.cwd,
            "status": if self.exit.is_none() { "running" } else { "exited" },
            "exit_code": self.exit.flatten(),
            "started_unix": self.started,
            "runtime_s": ((end - self.started_at).as_millis() as f64 / 100.0).round() / 10.0,
            "output_lines": self.lines.lock().unwrap().len(),
        })
    }
}

#[derive(Default)]
pub struct Jobs {
    pub map: HashMap<String, Job>,
}

fn pump<R: AsyncRead + Unpin + Send + 'static>(r: R, lines: Arc<Mutex<VecDeque<String>>>) {
    tokio::spawn(async move {
        // read raw lines: next_line() errors on non-UTF-8 (OEM code page) output and would stop the pump
        let mut reader = BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            }
            let line = platform::decode_output(&buf);
            let mut l = lines.lock().unwrap();
            l.push_back(line);
            if l.len() > 2000 {
                l.pop_front();
            }
        }
    });
}

impl Jobs {
    pub fn start(&mut self, s: &Settings, cmd: &str, cwd: &str) -> Result<&mut Job, String> {
        // forget finished jobs when at capacity, oldest first
        while self.map.len() >= s.max_jobs {
            let oldest = self.map.iter_mut().filter_map(|(k, j)| (!j.running()).then(|| (k.clone(), j.started_at)))
                .min_by_key(|(_, t)| *t).map(|(k, _)| k);
            match oldest {
                Some(k) => { self.map.remove(&k); }
                None => return Err(format!("too many running jobs ({}); cancel one first", self.map.len())),
            }
        }
        let mut child = command(s, cmd, cwd)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|e| format!("spawn failed: {e}"))?;
        let pid = child.id();
        platform::track(&child, false);
        let lines = Arc::new(Mutex::new(VecDeque::new()));
        pump(child.stdout.take().unwrap(), lines.clone());
        pump(child.stderr.take().unwrap(), lines.clone());
        let id = random_hex(4);
        let job = Job {
            id: id.clone(), command: cmd.into(), cwd: cwd.into(),
            started: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            started_at: Instant::now(), stdin: child.stdin.take(), child, pid, lines,
            exit: None, finished_at: None,
        };
        self.map.insert(id.clone(), job);
        Ok(self.map.get_mut(&id).unwrap())
    }

    pub fn get(&mut self, id: &str) -> Result<&mut Job, String> {
        self.map.get_mut(id).ok_or_else(|| format!("unknown job_id: {id}"))
    }
}

pub async fn write_stdin(job: &mut Job, data: &str, newline: bool) -> Result<(), String> {
    if !job.running() {
        return Err("job is not running".into());
    }
    let stdin = job.stdin.as_mut().ok_or("stdin closed")?;
    let mut buf = data.as_bytes().to_vec();
    if newline {
        buf.push(b'\n');
    }
    stdin.write_all(&buf).await.map_err(|e| e.to_string())?;
    stdin.flush().await.map_err(|e| e.to_string())
}

pub async fn cancel(job: &mut Job) {
    if job.running() {
        platform::terminate(&mut job.child).await;
        job.poll();
    }
}

#[cfg(all(test, unix))]
mod env_tests {
    use super::*;

    /// run_command must not hand ShellGate's token (or the tunnel token) to the commands it runs.
    #[tokio::test]
    async fn run_command_env_has_no_tokens() {
        let secret = "sg-envtest-0123456789abcdef-secret";
        std::env::set_var("SHELLGATE_TOKEN", secret);
        std::env::set_var("TUNNEL_TOKEN", "tunnel-envtest-0123456789abcdef");
        std::env::set_var("SG_ENVTEST_COPY", format!("Bearer {secret}"));
        std::env::set_var("SG_ENVTEST_KEEP", "kept-value");
        let mut s = Settings::for_tests();
        s.shell = "sh".into();
        s.max_output_bytes = 1_000_000;
        s.max_timeout = 60;
        let sem = Semaphore::new(1);
        let v = run_once(&s, &sem, "env; set", "/", 20, None).await.unwrap();
        let out = v.to_string();
        std::env::remove_var("SHELLGATE_TOKEN");
        std::env::remove_var("TUNNEL_TOKEN");
        std::env::remove_var("SG_ENVTEST_COPY");
        std::env::remove_var("SG_ENVTEST_KEEP");
        assert!(out.contains("kept-value"), "env output missing: {out}");
        assert!(!out.contains("SHELLGATE_TOKEN"), "SHELLGATE_TOKEN leaked to the child");
        assert!(!out.contains(secret), "token value leaked to the child");
        assert!(!out.contains("TUNNEL_TOKEN"), "TUNNEL_TOKEN leaked to the child");
    }
}
