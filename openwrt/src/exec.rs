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
            out.extend_from_slice(b"\n...[output truncated]...\n");
        }
        out.extend(self.tail);
        (String::from_utf8_lossy(&out).into_owned(), truncated)
    }
}

async fn collect<R: AsyncRead + Unpin>(mut r: R, limit: usize) -> HeadTail {
    let mut ht = HeadTail::new(limit);
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => ht.push(&buf[..n]),
        }
    }
    ht
}

fn kill_group(pid: Option<u32>, sig: i32) {
    if let Some(pid) = pid {
        unsafe { libc::kill(-(pid as i32), sig) };
    }
}

async fn terminate(child: &mut Child) {
    let pid = child.id();
    kill_group(pid, libc::SIGTERM);
    if tokio::time::timeout(Duration::from_secs(3), child.wait()).await.is_err() {
        kill_group(pid, libc::SIGKILL);
        let _ = child.wait().await;
    }
}

fn command(s: &Settings, cmd: &str, cwd: &str) -> Command {
    let mut c = Command::new(&s.shell);
    c.arg("-c").arg(cmd).current_dir(cwd).process_group(0).kill_on_drop(true);
    c
}

pub async fn run_once(s: &Settings, sem: &Semaphore, cmd: &str, cwd: &str, timeout: u64) -> Result<Value, String> {
    let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
    let start = Instant::now();
    let mut child = command(s, cmd, cwd)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let out = tokio::spawn(collect(child.stdout.take().unwrap(), s.max_output_bytes));
    let err = tokio::spawn(collect(child.stderr.take().unwrap(), s.max_output_bytes));
    let mut timed_out = false;
    let status = match tokio::time::timeout(Duration::from_secs(timeout), child.wait()).await {
        Ok(st) => st.ok(),
        Err(_) => {
            timed_out = true;
            terminate(&mut child).await;
            child.wait().await.ok()
        }
    };
    let (stdout, t1) = out.await.map_err(|e| e.to_string())?.finish();
    let (stderr, t2) = err.await.map_err(|e| e.to_string())?.finish();
    Ok(json!({
        "exit_code": status.and_then(|s| s.code()),
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "truncated": t1 || t2,
        "duration_ms": start.elapsed().as_millis() as u64,
    }))
}

pub struct Job {
    pub id: String,
    pub command: String,
    pub cwd: String,
    pub started: u64,
    pub started_at: Instant,
    child: Child,
    stdin: Option<ChildStdin>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
    exit: Option<Option<i32>>,
    finished_at: Option<Instant>,
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
        let mut reader = BufReader::new(r).lines();
        while let Ok(Some(line)) = reader.next_line().await {
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
        let lines = Arc::new(Mutex::new(VecDeque::new()));
        pump(child.stdout.take().unwrap(), lines.clone());
        pump(child.stderr.take().unwrap(), lines.clone());
        let id = random_hex(4);
        let job = Job {
            id: id.clone(), command: cmd.into(), cwd: cwd.into(),
            started: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            started_at: Instant::now(), stdin: child.stdin.take(), child, lines,
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
        terminate(&mut job.child).await;
        job.poll();
    }
}
