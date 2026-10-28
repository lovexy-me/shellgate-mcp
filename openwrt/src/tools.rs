//! MCP tool definitions and implementations.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, Semaphore};

use crate::audit::Audit;
use crate::exec::{self, Jobs};
use crate::policy::{feeds_interpreter, random_hex, referenced_scripts, within, Policy};
use crate::redact::{Counts, Redactor};

pub struct App {
    pub policy: Policy,
    pub audit: Audit,
    pub jobs: Mutex<Jobs>,
    pub sem: Semaphore,
    pub redactor: Redactor,
}

const SCRIPT_INTERPRETERS: &[&str] = &["sh", "bash", "python3", "ash"];
const MAX_STDIN: usize = 4_000_000;

/// Removes a private temp directory when dropped, whatever happened in between.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir();
        for _ in 0..10 {
            let p = base.join(format!("shellgate-{}", random_hex(8)));
            match fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("cannot create temp dir: {e}")),
            }
        }
        Err("cannot create a unique temp dir".into())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    path.split(':').filter(|d| !d.is_empty()).map(|d| format!("{d}/{name}"))
        .find(|p| fs::metadata(p).map(|m| m.is_file() && m.mode() & 0o111 != 0).unwrap_or(false))
}

fn digest(t: &str) -> String {
    format!("{:016x}", Policy::fingerprint(&[t]))
}

/// Write via a unique temp file in the same directory, then rename over the target.
fn atomic_write(p: &str, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = Path::new(p);
    let dir = path.parent().ok_or("bad path")?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mode = fs::metadata(p).map(|m| m.mode() & 0o7777).unwrap_or(0o644);
    for _ in 0..10 {
        let tmp = dir.join(format!(".{name}.{}.sgtmp", random_hex(4)));
        let mut f = match fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        };
        let res = f.write_all(content).and_then(|_| f.sync_all())
            .and_then(|_| fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)))
            .and_then(|_| fs::rename(&tmp, p));
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        return Ok(());
    }
    Err("cannot create a unique temp file".into())
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required})
}

pub fn definitions() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    let confirm = s("One-time code from a previous confirmation_required answer, only after the user agreed");
    json!([
        {"name": "run_command", "description": "Run a shell command (/bin/sh -c) and wait for it. Returns exit_code, stdout, stderr. timeout in seconds (default 60, max 600); for longer work use start_job. stdin (optional) is written to the command's standard input, e.g. command=\"ssh host sh -s\" with the script body in stdin.",
         "inputSchema": obj(json!({"command": s("Shell command"), "cwd": s("Working directory (default: home)"), "timeout": i("Seconds"), "stdin": s("Text written to the command's stdin"), "confirm_code": confirm.clone()}), &["command"])},
        {"name": "run_script", "description": "Run a multi-line script with sh, bash, python3 or ash and wait for it. The script is written to a private temp file (removed afterwards) and run as `<interpreter> <file> <args...>`. Every line is checked by the same safety policy as run_command. Returns exit_code, stdout, stderr.",
         "inputSchema": obj(json!({"script": s("Script body"), "interpreter": {"type": "string", "enum": SCRIPT_INTERPRETERS, "default": "sh", "description": "sh, bash, python3 or ash"},
                                   "args": {"type": "array", "items": {"type": "string"}, "description": "Arguments passed to the script"},
                                   "stdin": s("Text written to the script's stdin"), "timeout": i("Seconds"), "cwd": s("Working directory (default: home)"), "confirm_code": confirm.clone()}), &["script"])},
        {"name": "start_job", "description": "Start a long-running command in the background. Returns job_id; poll with job_output.",
         "inputSchema": obj(json!({"command": s("Shell command"), "cwd": s("Working directory"), "confirm_code": confirm}), &["command"])},
        {"name": "job_output", "description": "A background job's status and the last `tail` lines of output (max 2000).",
         "inputSchema": obj(json!({"job_id": s("Job id"), "tail": i("Lines, default 100")}), &["job_id"])},
        {"name": "job_input", "description": "Write text to a running job's stdin (e.g. answer a prompt).",
         "inputSchema": obj(json!({"job_id": s("Job id"), "data": s("Text to send"), "newline": b("Append newline, default true")}), &["job_id", "data"])},
        {"name": "list_jobs", "description": "List background jobs.", "inputSchema": obj(json!({}), &[])},
        {"name": "cancel_job", "description": "Stop a background job (SIGTERM, then SIGKILL).",
         "inputSchema": obj(json!({"job_id": s("Job id")}), &["job_id"])},
        {"name": "read_file", "description": "Read a text file with line numbers. offset is 1-based; limit max 5000 lines.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "offset": i("First line, default 1"), "limit": i("Lines, default 500")}), &["path"])},
        {"name": "write_file", "description": "Create, overwrite or append to a file in an allowed directory. Overwrites keep a .bak copy.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "content": s("File content"), "append": b("Append instead of overwrite")}), &["path", "content"])},
        {"name": "edit_file", "description": "Replace exact text in a file. old_string must be unique unless replace_all. Keeps a .bak copy.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "old_string": s("Exact text to find"), "new_string": s("Replacement"), "replace_all": b("Replace every match")}), &["path", "old_string", "new_string"])},
        {"name": "list_dir", "description": "List a directory: name, type, size, modified time.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "show_hidden": b("Include dotfiles")}), &["path"])},
        {"name": "search_files", "description": "Search file contents for a regex under a directory. Returns file:line:text matches.",
         "inputSchema": obj(json!({"pattern": s("Regex"), "path": s("Directory or file"), "glob": s("Filename filter such as *.conf"), "max_results": i("Default 200")}), &["pattern", "path"])},
        {"name": "system_info", "description": "Host overview: OS/OpenWrt release, board, kernel, uptime, load, memory, storage.", "inputSchema": obj(json!({}), &[])},
        {"name": "audit_tail", "description": "Show the last n audit log entries (what was run through ShellGate).",
         "inputSchema": obj(json!({"n": i("Entries, default 20")}), &[])},
    ])
}

fn arg_str<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}
fn req_str<'a>(a: &'a Value, k: &str) -> Result<&'a str, String> {
    arg_str(a, k).ok_or_else(|| format!("missing argument: {k}"))
}
fn arg_i64(a: &Value, k: &str, d: i64) -> i64 {
    a.get(k).and_then(Value::as_i64).unwrap_or(d)
}
fn arg_bool(a: &Value, k: &str, d: bool) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(d)
}

fn home() -> String {
    std::env::var("HOME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "/root".into())
}

fn ok(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        m.entry("status").or_insert(json!("ok"));
    }
    v
}

impl App {
    /// Run a tool, audit it, and return (result json, is_error).
    /// Inputs run unmodified; only what is returned (and logged) is redacted.
    pub async fn call(self: &Arc<Self>, ip: &str, name: &str, args: &Value) -> (Value, bool) {
        let start = Instant::now();
        let res = self.dispatch(name, args).await;
        let ms = start.elapsed().as_millis() as u64;
        let mut logged_args = args.clone();
        self.redactor.value(&mut logged_args, &mut Counts::default());
        let mut counts = Counts::default();
        match res {
            Ok(mut v) => {
                self.redactor.value(&mut v, &mut counts);
                let status = v.get("status").and_then(Value::as_str).unwrap_or("ok").to_string();
                let mut extra = Map::new();
                if let Some(code) = v.get("exit_code") {
                    extra.insert("exit_code".into(), code.clone());
                }
                if !counts.is_empty() {
                    if let Value::Object(m) = &mut v {
                        m.insert("redacted".into(), json!(counts.footer()));
                    }
                    extra.insert("redacted".into(), json!(counts.footer()));
                }
                self.audit.write(ip, name, &logged_args, &status, ms, extra);
                (v, false)
            }
            Err(e) => {
                let e = self.redactor.text(&e, &mut counts);
                let mut extra = Map::new();
                extra.insert("error".into(), json!(e));
                self.audit.write(ip, name, &logged_args, "error", ms, extra);
                let mut out = json!({"status": "error", "error": e});
                if !counts.is_empty() {
                    out["redacted"] = json!(counts.footer());
                }
                (out, true)
            }
        }
    }

    fn resolve_cwd(&self, cwd: Option<&str>) -> Result<String, String> {
        let c = cwd.filter(|c| !c.is_empty()).map(|c| c.replacen('~', &home(), 1)).unwrap_or_else(home);
        let p = Path::new(&c);
        if !p.is_dir() {
            return Err(format!("cwd does not exist: {c}"));
        }
        Ok(p.canonicalize().map_err(|e| e.to_string())?.to_string_lossy().into())
    }

    /// Refusal/confirmation answer, or None when the command may run. Scans the command, every
    /// line of an inline script, local script files the command runs, and stdin when it feeds a
    /// shell/python interpreter.
    #[allow(clippy::too_many_arguments)]
    fn gate(&self, kind: &str, cmd: &str, cwd: &str, code: Option<&str>, stdin: Option<&str>,
            script: Option<&str>, extra: &[String]) -> Option<Value> {
        let mut v = self.policy.allowlist_violations(cmd);
        if let Some(sc) = script.filter(|_| self.policy.settings.mode_allowlist) {
            for x in self.policy.allowlist_violations(sc) {
                if !v.contains(&x) {
                    v.push(x);
                }
            }
        }
        if !v.is_empty() {
            return Some(json!({"status": "denied", "reasons": v}));
        }
        let mut reasons = self.policy.text_danger_reasons(cmd);
        let mut fp: Vec<String> = vec![kind.into(), cmd.into(), cwd.into()];
        fp.extend(extra.iter().cloned());
        if let Some(sc) = script {
            reasons.extend(self.policy.text_danger_reasons(sc).into_iter().map(|w| format!("{w} (in script)")));
            fp.push(digest(sc));
        }
        let code_text = format!("{cmd}\n{}", script.unwrap_or(""));
        if let Some(inp) = stdin.filter(|t| !t.is_empty()) {
            if feeds_interpreter(&code_text) {
                reasons.extend(self.policy.text_danger_reasons(inp).into_iter().map(|w| format!("{w} (in stdin)")));
            }
        }
        fp.push(digest(stdin.unwrap_or("")));
        let mut files = referenced_scripts(cmd, cwd, 1_000_000);
        if let (Some(sc), "script") = (script, kind) {
            files.extend(referenced_scripts(sc, cwd, 1_000_000));
        }
        for (path, body) in files {
            reasons.extend(self.policy.text_danger_reasons(&body).into_iter().map(|w| format!("{w} (in {path})")));
            fp.push(path);
            fp.push(digest(&body));
        }
        if reasons.is_empty() {
            return None;
        }
        let mut uniq: Vec<String> = vec![];
        for r in reasons {
            if !uniq.contains(&r) {
                uniq.push(r);
            }
        }
        let fp = Policy::fingerprint(&fp);
        if self.policy.redeem(code, fp) {
            return None;
        }
        Some(json!({
            "status": "confirmation_required", "reasons": uniq, "command": cmd, "cwd": cwd,
            "confirm_code": self.policy.issue(fp), "expires_in_s": self.policy.settings.confirm_ttl,
            "next": "Ask the user. Only if they explicitly agree, call again with exactly the same arguments plus this confirm_code.",
        }))
    }

    fn backup(&self, p: &str) -> Option<String> {
        use std::os::unix::fs::OpenOptionsExt;
        if !self.policy.settings.backup_on_write || !Path::new(p).is_file() {
            return None;
        }
        let ts = crate::audit::now_rfc3339().replace([':', '-'], "");
        let base = format!("{p}.bak-{ts}");
        for i in 0..6 {
            let bak = if i == 0 { base.clone() } else { format!("{base}-{}", random_hex(2)) };
            if fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&bak).is_ok() {
                return fs::copy(p, &bak).ok().map(|_| bak);
            }
        }
        None
    }

    async fn dispatch(self: &Arc<Self>, name: &str, a: &Value) -> Result<Value, String> {
        let s = &self.policy.settings;
        match name {
            "run_command" => {
                let cmd = req_str(a, "command")?;
                let cwd = self.resolve_cwd(arg_str(a, "cwd"))?;
                let stdin = arg_str(a, "stdin");
                if stdin.is_some_and(|t| t.len() > MAX_STDIN) {
                    return Err("stdin larger than 4 MB".into());
                }
                if let Some(b) = self.gate("run", cmd, &cwd, arg_str(a, "confirm_code"), stdin, None, &[]) {
                    return Ok(b);
                }
                let t = (arg_i64(a, "timeout", s.default_timeout as i64).max(1) as u64).min(s.max_timeout);
                exec::run_once(s, &self.sem, cmd, &cwd, t, stdin).await.map(ok)
            }
            "run_script" => {
                let script = req_str(a, "script")?;
                let interp = arg_str(a, "interpreter").filter(|i| !i.is_empty()).unwrap_or("sh");
                if !SCRIPT_INTERPRETERS.contains(&interp) {
                    return Err(format!("interpreter must be one of: {}", SCRIPT_INTERPRETERS.join(", ")));
                }
                if script.len() > MAX_STDIN {
                    return Err("script larger than 4 MB".into());
                }
                let stdin = arg_str(a, "stdin");
                if stdin.is_some_and(|t| t.len() > MAX_STDIN) {
                    return Err("stdin larger than 4 MB".into());
                }
                let args: Vec<String> = match a.get("args") {
                    None | Some(Value::Null) => vec![],
                    Some(Value::Array(v)) => v.iter().map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    }).collect(),
                    Some(_) => return Err("args must be a list of strings".into()),
                };
                let exe = which(interp).ok_or_else(|| format!("interpreter not found on this host: {interp}"))?;
                let cwd = self.resolve_cwd(arg_str(a, "cwd"))?;
                let shown = format!("{interp} <script> {}", args.join(" ")).trim_end().to_string();
                let extra = [interp.to_string(), serde_json::to_string(&args).unwrap_or_default()];
                if let Some(mut b) = self.gate("script", &shown, &cwd, arg_str(a, "confirm_code"), stdin, Some(script), &extra) {
                    if b["status"] == "confirmation_required" {
                        b["interpreter"] = json!(interp);
                    }
                    return Ok(b);
                }
                let t = (arg_i64(a, "timeout", s.default_timeout as i64).max(1) as u64).min(s.max_timeout);
                let dir = TempDir::new()?; // 0700, unique per call, removed on drop
                let file = dir.0.join(if interp == "python3" { "script.py" } else { "script.sh" });
                {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file)
                        .map_err(|e| format!("cannot write script: {e}"))?;
                    f.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
                }
                let mut argv = vec![file.to_string_lossy().to_string()];
                argv.extend(args);
                let res = exec::run_argv(s, &self.sem, &exe, &argv, &cwd, t, stdin).await;
                drop(dir);
                let mut v = res?;
                v["interpreter"] = json!(interp);
                Ok(ok(v))
            }
            "start_job" => {
                let cmd = req_str(a, "command")?;
                let cwd = self.resolve_cwd(arg_str(a, "cwd"))?;
                if let Some(b) = self.gate("job", cmd, &cwd, arg_str(a, "confirm_code"), None, None, &[]) {
                    return Ok(b);
                }
                let mut jobs = self.jobs.lock().await;
                Ok(ok(jobs.start(s, cmd, &cwd)?.summary()))
            }
            "job_output" => {
                let mut jobs = self.jobs.lock().await;
                let job = jobs.get(req_str(a, "job_id")?)?;
                // give the output pumps a moment to drain after exit
                if !job.running() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let tail = arg_i64(a, "tail", 100).clamp(1, 2000) as usize;
                let output = {
                    let l = job.lines.lock().unwrap();
                    l.iter().skip(l.len().saturating_sub(tail)).cloned().collect::<Vec<_>>().join("\n")
                };
                let mut v = job.summary();
                v["output"] = json!(output);
                Ok(ok(v))
            }
            "job_input" => {
                let mut jobs = self.jobs.lock().await;
                let job = jobs.get(req_str(a, "job_id")?)?;
                exec::write_stdin(job, req_str(a, "data")?, arg_bool(a, "newline", true)).await?;
                Ok(json!({"status": "ok"}))
            }
            "list_jobs" => {
                let mut jobs = self.jobs.lock().await;
                let list: Vec<Value> = jobs.map.values_mut().map(|j| j.summary()).collect();
                Ok(json!({"status": "ok", "jobs": list}))
            }
            "cancel_job" => {
                let mut jobs = self.jobs.lock().await;
                let job = jobs.get(req_str(a, "job_id")?)?;
                exec::cancel(job).await;
                Ok(ok(job.summary()))
            }
            "read_file" => {
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                let bytes = fs::read(&p).map_err(|e| format!("{p}: {e}"))?;
                let text = String::from_utf8_lossy(&bytes);
                let lines: Vec<&str> = text.split_inclusive('\n').collect();
                let start = (arg_i64(a, "offset", 1).max(1) - 1) as usize;
                let limit = arg_i64(a, "limit", 500).clamp(1, 5000) as usize;
                let mut body = String::new();
                for (n, l) in lines.iter().enumerate().skip(start).take(limit) {
                    let l: String = l.chars().take(4000).collect();
                    body.push_str(&format!("{:>6}\t{}", n + 1, l));
                }
                Ok(json!({"status": "ok", "path": p, "total_lines": lines.len(),
                          "truncated": start + limit < lines.len(), "content": body}))
            }
            "write_file" => {
                let p = self.policy.check_path(req_str(a, "path")?, true)?;
                let content = req_str(a, "content")?;
                if content.len() > 4_000_000 {
                    return Err("content larger than 4 MB".into());
                }
                if let Some(dir) = Path::new(&p).parent() {
                    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                }
                let append = arg_bool(a, "append", false);
                let bak = if append { None } else { self.backup(&p) };
                if append {
                    use std::io::Write;
                    let mut f = fs::OpenOptions::new().create(true).append(true).open(&p).map_err(|e| e.to_string())?;
                    f.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
                } else {
                    atomic_write(&p, content.as_bytes())?;
                }
                Ok(json!({"status": "ok", "path": p, "bytes": content.len(), "backup": bak}))
            }
            "edit_file" => {
                let p = self.policy.check_path(req_str(a, "path")?, true)?;
                let (old, new) = (req_str(a, "old_string")?, req_str(a, "new_string")?);
                if old.is_empty() {
                    return Err("old_string must not be empty".into());
                }
                let text = fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?;
                let count = text.matches(old).count();
                let all = arg_bool(a, "replace_all", false);
                if count == 0 {
                    return Err("old_string not found".into());
                }
                if count > 1 && !all {
                    return Err(format!("old_string matches {count} times; add context or set replace_all"));
                }
                let bak = self.backup(&p);
                let out = if all { text.replace(old, new) } else { text.replacen(old, new, 1) };
                atomic_write(&p, out.as_bytes())?;
                Ok(json!({"status": "ok", "path": p, "replacements": if all { count } else { 1 }, "backup": bak}))
            }
            "list_dir" => {
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                let hidden = arg_bool(a, "show_hidden", false);
                let mut entries: Vec<Value> = vec![];
                let mut rd: Vec<_> = fs::read_dir(&p).map_err(|e| format!("{p}: {e}"))?.flatten().collect();
                rd.sort_by_key(|e| e.file_name());
                for e in rd.into_iter().take(1000) {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !hidden && name.starts_with('.') {
                        continue;
                    }
                    let Ok(m) = fs::symlink_metadata(e.path()) else { continue };
                    let kind = if m.file_type().is_symlink() { "link" } else if m.is_dir() { "dir" } else { "file" };
                    entries.push(json!({"name": name, "type": kind, "size": m.len(), "modified_unix": m.mtime()}));
                }
                Ok(json!({"status": "ok", "path": p, "entries": entries}))
            }
            "search_files" => {
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                let rx = regex::Regex::new(req_str(a, "pattern")?).map_err(|e| format!("bad regex: {e}"))?;
                let glob = arg_str(a, "glob").map(str::to_string);
                let max = arg_i64(a, "max_results", 200).clamp(1, 2000) as usize;
                let protected = s.protected_paths.clone();
                let allow_roots = if s.mode_allowlist { s.allowed_dirs.clone() } else { vec![] };
                let res = tokio::task::spawn_blocking(move || search(&p, &rx, glob.as_deref(), max, &protected, &allow_roots))
                    .await.map_err(|e| e.to_string())?;
                Ok(json!({"status": "ok", "matches": res.0, "truncated": res.1}))
            }
            "system_info" => Ok(system_info()),
            "audit_tail" => {
                let n = arg_i64(a, "n", 20).clamp(1, 200) as usize;
                Ok(json!({"status": "ok", "entries": self.audit.tail(n)}))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }
}

fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pat.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn search(root: &str, rx: &regex::Regex, glob: Option<&str>, max: usize, protected: &[String], roots: &[String]) -> (Vec<String>, bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut out = vec![];
    let mut stack = vec![(root.to_string(), 0usize)];
    let skip_dirs = ["/proc", "/sys", "/dev"];
    while let Some((path, depth)) = stack.pop() {
        if out.len() > max || Instant::now() > deadline {
            break;
        }
        if protected.iter().any(|p| within(&path, p)) || skip_dirs.iter().any(|d| within(&path, d) && !within(root, d)) {
            continue;
        }
        if !roots.is_empty() && !roots.iter().any(|r| within(&path, r)) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if meta.is_dir() {
            if depth > 20 {
                continue;
            }
            if let Ok(rd) = fs::read_dir(&path) {
                for e in rd.flatten() {
                    stack.push((e.path().to_string_lossy().to_string(), depth + 1));
                }
            }
            continue;
        }
        if !meta.is_file() || meta.len() > 5_000_000 {
            continue;
        }
        if let Some(g) = glob {
            let name = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !glob_match(g, &name) {
                continue;
            }
        }
        let Ok(mut f) = fs::File::open(&path) else { continue };
        let mut buf = vec![];
        if f.read_to_end(&mut buf).is_err() || buf.iter().take(1024).any(|&b| b == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        for (n, line) in text.lines().enumerate() {
            if rx.is_match(line) {
                let l: String = line.chars().take(300).collect();
                out.push(format!("{path}:{}:{l}", n + 1));
                if out.len() > max {
                    break;
                }
            }
        }
    }
    let truncated = out.len() > max;
    out.truncate(max);
    (out, truncated)
}

fn read_trim(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn kv(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix(&format!("{key}=")).map(|v| v.trim_matches(['"', '\'']).to_string()))
}

fn statvfs(path: &str) -> Option<Value> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let f = st.f_frsize as f64;
    Some(json!({"total_mb": (st.f_blocks as f64 * f / 1048576.0).round(), "free_mb": (st.f_bavail as f64 * f / 1048576.0).round()}))
}

fn system_info() -> Value {
    let kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    let os = read_trim("/etc/openwrt_release").and_then(|t| kv(&t, "DISTRIB_DESCRIPTION"))
        .or_else(|| read_trim("/etc/os-release").and_then(|t| kv(&t, "PRETTY_NAME")))
        .unwrap_or_default();
    let mut mem = Map::new();
    if let Some(t) = read_trim("/proc/meminfo") {
        for (k, name) in [("MemTotal", "total"), ("MemAvailable", "available"), ("SwapFree", "swap_free")] {
            if let Some(v) = t.lines().find(|l| l.starts_with(&format!("{k}:"))).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok()) {
                mem.insert(name.into(), json!(v / 1024));
            }
        }
    }
    let uptime = read_trim("/proc/uptime").and_then(|u| u.split_whitespace().next().and_then(|v| v.parse::<f64>().ok())).unwrap_or(0.0);
    let load: Vec<f64> = read_trim("/proc/loadavg").map(|l| l.split_whitespace().take(3).filter_map(|v| v.parse().ok()).collect()).unwrap_or_default();
    let mut storage = Map::new();
    for m in ["/", "/overlay", "/tmp"] {
        if Path::new(m).exists() {
            if let Some(v) = statvfs(m) {
                storage.insert(m.into(), v);
            }
        }
    }
    json!({
        "status": "ok",
        "hostname": read_trim("/proc/sys/kernel/hostname").unwrap_or_default(),
        "os": os,
        "board": read_trim("/tmp/sysinfo/model").unwrap_or_default(),
        "kernel": kernel,
        "arch": std::env::consts::ARCH,
        "wsl": kernel.to_lowercase().contains("microsoft"),
        "uptime_h": (uptime / 360.0).round() / 10.0,
        "load": load,
        "mem_mb": mem,
        "storage": storage,
        "time_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn glob() {
        assert!(super::glob_match("*.conf", "a.conf"));
        assert!(super::glob_match("net*", "network"));
        assert!(!super::glob_match("*.conf", "a.txt"));
        assert!(super::glob_match("a?c", "abc"));
    }
}
