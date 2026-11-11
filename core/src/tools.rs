//! MCP tool definitions and implementations.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, Semaphore};

use crate::xfer;
use crate::guard;
use crate::audit::Audit;
use crate::exec::{self, Jobs};
use crate::platform;
use crate::policy::{feeds_interpreter, random_hex, referenced_scripts, within, Policy};
use crate::ventoy;
use crate::redact::{Counts, Redactor};

pub struct App {
    pub policy: Policy,
    pub audit: Audit,
    pub jobs: Mutex<Jobs>,
    pub sem: Semaphore,
    pub redactor: Redactor,
    pub downloads: std::sync::Mutex<HashMap<String, Arc<ventoy::Download>>>,
    /// last desktop_screenshot: coordinate mapping and content hash
    #[cfg_attr(not(all(windows, feature = "desktop")), allow(dead_code))]
    pub shot: std::sync::Mutex<Option<(crate::desktop::Mapping, u64)>>,
    /// helper agents by kind ("session", "elevated"), see agent.rs
    pub agents: Mutex<HashMap<String, crate::agent::Endpoint>>,
}

#[cfg(unix)]
const SCRIPT_INTERPRETERS: &[&str] = &["sh", "bash", "python3", "ash"];
#[cfg(windows)]
const SCRIPT_INTERPRETERS: &[&str] = &["powershell", "pwsh", "cmd", "python"];
#[cfg(unix)]
const DEFAULT_INTERPRETER: &str = "sh";
#[cfg(windows)]
const DEFAULT_INTERPRETER: &str = "powershell";
const MAX_DOWNLOADS: usize = 2;

/// Which edition this binary was built as (cargo feature edition-*); shown in system_info and initialize.
pub const EDITION: &str = if cfg!(feature = "edition-openwrt") {
    "openwrt"
} else if cfg!(feature = "edition-pe") {
    "pe"
} else if cfg!(feature = "edition-linux") {
    "linux"
} else if cfg!(feature = "edition-android") {
    "android"
} else if cfg!(feature = "edition-portable") {
    "portable"
} else {
    "full"
};
const MAX_STDIN: usize = 4_000_000;

/// Removes a private temp directory when dropped, whatever happened in between.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Result<Self, String> {
        let base = std::env::temp_dir();
        for _ in 0..10 {
            let p = base.join(format!("shellgate-{}", random_hex(8)));
            match platform::create_private_dir(&p) {
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
    platform::which(name)
}

fn digest(t: &str) -> String {
    format!("{:016x}", Policy::fingerprint(&[t]))
}

/// Write via a unique temp file in the same directory, then rename over the target.
fn atomic_write(p: &str, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let path = Path::new(p);
    let dir = path.parent().ok_or("bad path")?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    for _ in 0..10 {
        let tmp = dir.join(format!(".{name}.{}.sgtmp", random_hex(4)));
        let mut f = match platform::private_opts().write(true).create_new(true).open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        };
        let res = f.write_all(content).and_then(|_| f.sync_all())
            .and_then(|_| { drop(f); platform::copy_mode(p, &tmp) })
            .and_then(|_| fs::rename(&tmp, p));
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        return Ok(());
    }
    Err("cannot create a unique temp file".into())
}

fn script_file_name(interp: &str) -> &'static str {
    match interp {
        "python3" | "python" => "script.py",
        "powershell" | "pwsh" => "script.ps1",
        "cmd" => "script.cmd",
        _ => "script.sh",
    }
}

/// Pick the interpreter for run_script. `requested` is the caller's choice (None/empty = default).
/// Returns (interpreter, note for the result). With no explicit choice and no working PowerShell
/// (most WinPE builds) the default falls back to cmd; an explicit `powershell` that cannot run is an
/// error that says so, instead of a confusing "not found" or a hang.
fn pick_interpreter(requested: Option<&str>, ps_usable: impl Fn() -> bool) -> Result<(&'static str, Option<String>), String> {
    let explicit = requested.filter(|i| !i.trim().is_empty());
    let want = explicit.unwrap_or(DEFAULT_INTERPRETER);
    let Some(interp) = SCRIPT_INTERPRETERS.iter().copied().find(|i| *i == want) else {
        return Err(format!("interpreter must be one of: {}", SCRIPT_INTERPRETERS.join(", ")));
    };
    if interp != "powershell" || ps_usable() {
        return Ok((interp, None));
    }
    if explicit.is_some() {
        return Err("PowerShell is not available on this host (WinPE images often ship without it, or it cannot \
start); use interpreter=cmd, or python if installed".into());
    }
    Ok(("cmd", Some("PowerShell is not available on this host (e.g. WinPE); the script ran with cmd instead. \
Write cmd syntax, or pass interpreter explicitly.".into())))
}

/// cmd reads a .cmd file in the console (OEM) code page. Encode it there when every character
/// fits; otherwise switch the console to UTF-8 first (`chcp 65001`) and write UTF-8.
#[cfg_attr(unix, allow(dead_code))]
fn cmd_script_bytes(script: &str, oem: impl Fn(&str) -> Option<Vec<u8>>) -> Vec<u8> {
    let crlf = script.replace("\r\n", "\n").replace('\n', "\r\n");
    match oem(&crlf) {
        Some(b) => b,
        None => {
            let mut v = b"@chcp 65001 >nul\r\n".to_vec();
            v.extend_from_slice(crlf.as_bytes());
            v
        }
    }
}

#[cfg(windows)]
fn oem_encoder(s: &str) -> Option<Vec<u8>> {
    platform::encode_oem(s)
}

#[cfg(unix)]
fn oem_encoder(s: &str) -> Option<Vec<u8>> {
    Some(s.as_bytes().to_vec())
}

/// Script bytes as the interpreter wants them: cmd needs CRLF line ends and the OEM code page,
/// Windows PowerShell 5.1 needs a UTF-8 BOM to read non-ASCII text correctly.
fn script_bytes(interp: &str, script: &str) -> Vec<u8> {
    match interp {
        "cmd" => cmd_script_bytes(script, oem_encoder),
        "powershell" | "pwsh" => {
            let mut v = vec![0xEF, 0xBB, 0xBF];
            v.extend_from_slice(script.as_bytes());
            v
        }
        _ => script.as_bytes().to_vec(),
    }
}

/// The command that runs a script file with its arguments, no shell in between where possible.
fn script_command(interp: &str, exe: &str, file: &str, args: &[String], cwd: &str) -> tokio::process::Command {
    let mut c = platform::new_command(exe);
    c.current_dir(cwd);
    match interp {
        "powershell" | "pwsh" => {
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file]).args(args);
        }
        #[cfg(windows)]
        "cmd" => {
            // cmd /S /C ""<file>" "arg" ..." : outer quotes stripped, the rest taken literally
            let mut line = format!("\"{file}\"");
            for a in args {
                line.push_str(&format!(" \"{}\"", a.replace('"', "")));
            }
            c.raw_arg(format!("/D /S /C \"{line}\""));
        }
        _ => {
            c.arg(file).args(args);
        }
    }
    c
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required})
}

pub fn definitions() -> Value {
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    let confirm = s("One-time code from a previous confirmation_required answer, only after the user agreed");
    #[allow(unused_mut)]
    let mut v = json!([
        {"name": "run_command", "description": "Run a shell command (Linux: /bin/sh -c; Windows: cmd /C, or PowerShell when SHELLGATE_SHELL=powershell) and wait for it. Returns exit_code, stdout, stderr. timeout in seconds (default 60, max 600); for longer work use start_job. stdin (optional) is written to the command's standard input, e.g. command=\"ssh host sh -s\" with the script body in stdin.",
         "inputSchema": obj(json!({"command": s("Shell command"), "cwd": s("Working directory (default: home)"), "timeout": i("Seconds"), "stdin": s("Text written to the command's stdin"), "confirm_code": confirm.clone(), "sudo": b("Linux: run as root with sudo -n (no shell); only commands listed in SHELLGATE_SUDO_ALLOW, and sudoers must allow them without a password"), "elevated": b("Windows, when ShellGate is not already elevated: run as administrator through a helper started once with a UAC prompt on the user's screen (the user must accept it); later calls reuse it")}), &["command"])},
        {"name": "run_script", "description": "Run a multi-line script and wait for it (Linux: sh, bash, python3, ash; Windows: powershell, pwsh, cmd, python; with no interpreter given and no working PowerShell, as in most WinPE, cmd is used and the result carries a note). The script is written to a private temp file (removed afterwards) and run as `<interpreter> <file> <args...>`. Every line is checked by the same safety policy as run_command. Returns exit_code, stdout, stderr.",
         "inputSchema": obj(json!({"script": s("Script body"), "interpreter": {"type": "string", "enum": SCRIPT_INTERPRETERS, "default": DEFAULT_INTERPRETER, "description": SCRIPT_INTERPRETERS.join(", ")},
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
        {"name": "file_hash", "description": "SHA-256 and size of a file (to verify a transfer or a download).",
         "inputSchema": obj(json!({"path": s("Absolute path")}), &["path"])},
        {"name": "read_binary", "description": "Read a binary file in chunks as base64 (length default 256 KB, max 1 MB). Loop with offset += length until eof; the last chunk carries the whole file's sha256. Text files are refused (use read_file, which redacts secrets): only binary content leaves unredacted.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "offset": i("Byte offset, default 0"), "length": i("Bytes, default 262144, max 1048576")}), &["path"])},
        {"name": "write_binary", "description": "Upload a file in base64 chunks (each up to 1 MB decoded). Chunks go to <path>.sgpart: offset 0 starts it over, every other offset must equal the bytes already written (the answer gives next_offset, so an interrupted upload can resume). Pass the whole file's sha256 with the last chunk: it is verified, then the file replaces <path> (old one kept as .bak). On mismatch the partial file is deleted.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "data": s("Base64 chunk"), "offset": i("Byte offset of this chunk, default 0"), "sha256": s("Whole file's SHA-256, with the last chunk")}), &["path", "data"])},
        {"name": "guarded_change", "description": "Make a risky config change with automatic rollback: copies the listed files, runs the command, and unless guarded_confirm keeps it within timeout seconds, puts the files back and runs the reload command. Use it for uci / firewall / network / wireless edits made over the link they could break: after the change, check you can still reach the host, then confirm. On OpenWrt files default to /etc/config/{network,firewall,wireless,dhcp} and reload to reloading network, firewall, wifi and dnsmasq. The pending rollback survives a ShellGate restart or a reboot. Commands that only risk cutting remote access need no confirm code here (the rollback covers them); other dangerous commands still do.",
         "inputSchema": obj(json!({"command": s("Shell command that makes the change, e.g. uci set ... && uci commit firewall && /etc/init.d/firewall reload"),
                                   "files": {"type": "array", "items": {"type": "string"}, "description": "Files to snapshot and restore (absolute paths)"},
                                   "reload": s("Command run after restoring the files"), "timeout": i("Seconds before the automatic rollback (15-900, default 120)"),
                                   "cwd": s("Working directory"), "confirm_code": s("One-time code from a previous confirmation_required answer, only after the user agreed")}), &["command"])},
        {"name": "guarded_confirm", "description": "Keep or undo a guarded_change: action=keep makes it permanent, action=rollback undoes it now, action=status (default) shows it and which files changed; with no id, lists recent guarded changes.",
         "inputSchema": obj(json!({"id": s("Id returned by guarded_change"), "action": s("keep | rollback | status")}), &[])},
        {"name": "edit_file", "description": "Replace exact text in a file. old_string must be unique unless replace_all. Keeps a .bak copy.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "old_string": s("Exact text to find"), "new_string": s("Replacement"), "replace_all": b("Replace every match")}), &["path", "old_string", "new_string"])},
        {"name": "list_dir", "description": "List a directory: name, type, size, modified time.",
         "inputSchema": obj(json!({"path": s("Absolute path"), "show_hidden": b("Include dotfiles")}), &["path"])},
        {"name": "search_files", "description": "Search file contents for a regex under a directory. Returns file:line:text matches.",
         "inputSchema": obj(json!({"pattern": s("Regex"), "path": s("Directory or file"), "glob": s("Filename filter such as *.conf"), "max_results": i("Default 200")}), &["pattern", "path"])},
        {"name": "system_info", "description": "Host overview: OS/OpenWrt release, board, kernel, uptime, load, memory, storage.", "inputSchema": obj(json!({}), &[])},
        {"name": "audit_tail", "description": "Show the last n audit log entries (what was run through ShellGate).",
         "inputSchema": obj(json!({"n": i("Entries, default 20")}), &[])},
        {"name": "ventoy_info", "description": "Find the Ventoy data partition (volume labelled Ventoy, or ventoy_root in the config): path, filesystem, capacity, free space, Ventoy version if readable, whether ventoy/ventoy.json exists. Linux: mount=true mounts an unmounted Ventoy partition at /mnt/ventoy.",
         "inputSchema": obj(json!({"mount": b("Linux only: mount the Ventoy partition at /mnt/ventoy if it is not mounted")}), &[])},
        {"name": "ventoy_list", "description": "List boot images on the Ventoy partition (.iso .wim .img .vhd .vhdx .efi .vtoy) with size and modified time; paths are relative to the partition.",
         "inputSchema": obj(json!({}), &[])},
        {"name": "ventoy_add", "description": "Download an image from an http(s) URL onto the Ventoy partition as a background task (returns task_id; poll with ventoy_add_status). Optional sha256 is verified; on mismatch or any failure the partial file is deleted. Never overwrites an existing file.",
         "inputSchema": obj(json!({"url": s("http(s) URL of the image"), "filename": s("File name to save as (default: last URL segment); must end in an image extension"),
                                   "subdir": s("Folder inside the Ventoy partition, e.g. iso/linux (created if missing)"), "sha256": s("Expected SHA-256 (64 hex chars)")}), &["url"])},
        {"name": "ventoy_add_status", "description": "Progress of ventoy_add downloads (all, or one task_id). cancel=true stops a running download and deletes its partial file.",
         "inputSchema": obj(json!({"task_id": s("Task id (omit for all)"), "cancel": b("Cancel this download")}), &[])},
        {"name": "ventoy_remove", "description": "Delete an image from the Ventoy partition. Always answers confirmation_required first; call again with the confirm_code only after the user agrees.",
         "inputSchema": obj(json!({"path": s("Image path relative to the Ventoy partition, as shown by ventoy_list"), "confirm_code": s("One-time code from the confirmation_required answer, only after the user agreed")}), &["path"])},
        {"name": "ventoy_config_get", "description": "Read ventoy/ventoy.json from the Ventoy partition (raw text plus parsed JSON and validity).",
         "inputSchema": obj(json!({}), &[])},
        {"name": "ventoy_config_set", "description": "Replace ventoy/ventoy.json. The content must be a valid JSON object (checked before writing); the old file is kept as ventoy.json.bak-<timestamp>. On FAT32 the result may carry warnings about paths Ventoy will not match (upper-case 8.3 folder names such as /ISO are seen in lower case). Write placeholders like <ip> back only if they are really meant literally: output is redacted.",
         "inputSchema": obj(json!({"content": s("Complete new ventoy.json text")}), &["content"])},
    ]);
    #[cfg(all(unix, not(target_os = "android")))]
    if let Value::Array(a) = &mut v {
        a.extend(crate::sysops::definitions());
    }
    #[cfg(feature = "net-tools")]
    if let Value::Array(a) = &mut v {
        a.extend([
        json!({"name": "lan_scan", "description": "Find hosts on the local network by a TCP connect sweep (no root needed). targets: CIDR like 192.168.1.0/24, a range 192.168.1.10-40, or one address; defaults to the /24 around each local address. ports defaults to a common set (ssh, http(s), smb, rdp, adb 5555, vnc, rtsp...). Returns each responding host with its open ports and their likely service. Useful from a phone or WinPE to locate a TV (adb 5555) or PC (smb/rdp) on the far LAN.",
         "inputSchema": obj(json!({"targets": s("CIDR, range or address; comma-separate several (optional)"), "ports": s("comma-separated ports (optional)"), "timeout_ms": i("per-connection timeout, default 600"), "concurrency": i("parallel connections, default 256")}), &[])}),
        json!({"name": "http_request", "description": "Make an HTTP(S) request from this host and return status, headers and body (text, or base64 for binary). For talking to a device's web API/UI on the far LAN (router, camera, TV). insecure=true skips TLS verification for self-signed certs. Body is capped (default 256 KB).",
         "inputSchema": obj(json!({"url": s("http:// or https:// URL"), "method": s("GET (default), POST, PUT, ..."), "headers": json!({"type": "object", "description": "request headers (optional)", "additionalProperties": {"type": "string"}}), "body": s("request body (optional)"), "insecure": b("skip TLS certificate verification (self-signed devices)"), "timeout_s": i("default 30, max 120"), "max_bytes": i("max body bytes, default 262144")}), &["url"])}),
        ]);
    }
    #[cfg(feature = "admin-lite")]
    if let Value::Array(a) = &mut v {
        a.push(json!({"name": "connection_info", "description": "This server's own connection details for an MCP client: the public tunnel URL (if set), the LAN address, the edition, tunnel status and uptime. Does not include the token.", "inputSchema": obj(json!({}), &[])}));
    }
    #[cfg(feature = "admin")]
    if let Value::Array(a) = &mut v {
        a.extend([
        json!({"name": "cloudflare_setup", "description": "Set up (or tear down) a Cloudflare named tunnel for this host from the user's own Cloudflare API token, and switch this server to tunnel mode. Steps: verify the token, pick the account and the zone for the hostname, create a tunnel, add a DNS CNAME and the ingress route to http://127.0.0.1:<port>, write tunnel_token and public_url into the config, and start cloudflared. The API token is used only for this call and is not stored unless save_token=true. action: plan (check token, list zones/accounts), create (do it), remove (delete the tunnel and DNS record).",
         "inputSchema": obj(json!({"action": s("plan | create | remove"), "api_token": s("Cloudflare API token (Zone:DNS edit + Account:Cloudflare Tunnel edit). Not stored unless save_token=true"), "hostname": s("public hostname, e.g. pc.example.com (must be a zone in this account)"), "account_id": s("Cloudflare account id (optional if the token has one account)"), "tunnel_name": s("tunnel name (default: the hostname's first label)"), "save_token": b("also save the API token in the config for later changes (default false)")}), &["action"])}),
        ]);
    }
    v
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
    platform::home()
}

fn ok(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        m.entry("status").or_insert(json!("ok"));
    }
    v
}

impl App {
    /// tools/list: the base tools, plus the desktop tools on Windows when desktop=on.
    pub fn tool_list(&self) -> Value {
        let mut v = definitions();
        if !cfg!(feature = "ventoy") {
            if let Value::Array(a) = &mut v {
                a.retain(|t| !t["name"].as_str().unwrap_or("").starts_with("ventoy_"));
            }
        }
        if cfg!(all(windows, feature = "desktop")) && self.policy.settings.desktop {
            if let Value::Array(a) = &mut v {
                a.extend(crate::desktop::definitions());
            }
        }
        if cfg!(target_os = "android") {
            if let Value::Array(a) = &mut v {
                a.extend(crate::android::definitions());
            }
        }
        if cfg!(all(unix, not(target_os = "android"))) && self.policy.settings.desktop {
            if let Value::Array(a) = &mut v {
                a.extend(crate::desktop::definitions().into_iter()
                    .filter(|t| ["desktop_screenshot", "desktop_input", "desktop_windows"].contains(&t["name"].as_str().unwrap_or("")))
                    .map(|mut t| {
                        let d = t["description"].as_str().unwrap_or("").to_string();
                        t["description"] = json!(format!("Linux (X11/Wayland via grim, import or scrot / xdotool or ydotool / wmctrl; coordinates are physical pixels, no scaling, no Set-of-Marks): {d}"));
                        t
                    }));
            }
        }
        v
    }

    /// Confirmation answer for a desktop action with risk reasons, or None when it may go ahead.
    #[cfg_attr(not(all(windows, feature = "desktop")), allow(dead_code))]
    fn confirm_gate(&self, kind: &str, args: &Value, reasons: Vec<String>) -> Option<Value> {
        if reasons.is_empty() {
            return None;
        }
        let mut a = args.clone();
        if let Value::Object(m) = &mut a {
            m.remove("confirm_code");
        }
        let fp = Policy::fingerprint(&[kind.to_string(), a.to_string()]);
        if self.policy.redeem(arg_str(args, "confirm_code"), fp) {
            return None;
        }
        Some(json!({
            "status": "confirmation_required", "reasons": reasons, "tool": kind,
            "confirm_code": self.policy.issue(fp), "expires_in_s": self.policy.settings.confirm_ttl,
            "next": "Ask the user. Only if they explicitly agree, call again with exactly the same arguments plus this confirm_code.",
        }))
    }

    #[cfg(not(any(all(windows, feature = "desktop"), all(unix, not(target_os = "android")))))]
    async fn desktop(self: &Arc<Self>, _name: &str, _a: &Value) -> Result<Value, String> {
        Err("desktop tools exist only in the Windows and Linux desktop builds".into())
    }

    #[cfg(all(unix, not(target_os = "android")))]
    async fn desktop(self: &Arc<Self>, name: &str, a: &Value) -> Result<Value, String> {
        let me = self.clone();
        let name = name.to_string();
        let a = a.clone();
        tokio::task::spawn_blocking(move || me.desktop_linux(&name, &a)).await.map_err(|e| e.to_string())?
    }

    #[cfg(all(unix, not(target_os = "android")))]
    fn desktop_linux(&self, name: &str, a: &Value) -> Result<Value, String> {
        use crate::desktop as d;
        use crate::desktop_linux as l;
        match name {
            "desktop_screenshot" => {
                let region = a.get("region").and_then(Value::as_array).and_then(|r| {
                    let v: Vec<i64> = r.iter().filter_map(Value::as_i64).collect();
                    (v.len() == 4 && v[2] > 0 && v[3] > 0).then(|| (v[0], v[1], v[2], v[3]))
                });
                let (png, tool) = l::screenshot(region)?;
                let (w, h) = l::png_size(&png).unwrap_or((0, 0));
                let hash = Policy::fingerprint(&[xfer::sha256_hex(&png)]);
                let (ox, oy) = region.map(|r| (r.0 as i32, r.1 as i32)).unwrap_or((0, 0));
                let map = d::Mapping { ox, oy, scale: 1.0 };
                let prev = self.shot.lock().unwrap().replace((map, hash));
                if arg_bool(a, "only_if_changed", true) && prev.is_some_and(|(m, h)| m == map && h == hash) {
                    return Ok(json!({"changed": false, "width": w, "height": h, "origin": [ox, oy], "tool": tool}));
                }
                Ok(json!({"changed": true, "width": w, "height": h, "origin": [ox, oy], "tool": tool,
                          "note": "coordinates are physical screen pixels (Linux screenshots are not scaled)",
                          "_image": {"data": d::b64(&png), "mimeType": "image/png"}}))
            }
            "desktop_input" => {
                let actions = d::parse_actions(a.get("actions").unwrap_or(&Value::Null))?;
                let reasons = d::batch_reasons(&actions, false, &|t| self.policy.text_danger_reasons(t));
                if let Some(c) = self.confirm_gate(name, a, reasons) {
                    return Ok(c);
                }
                let map = if arg_str(a, "coords") == Some("physical") { None } else { self.shot.lock().unwrap().map(|x| x.0) }
                    .unwrap_or(d::Mapping { ox: 0, oy: 0, scale: 1.0 });
                let n = l::input(&actions, &map)?;
                Ok(json!({"status": "ok", "done": n}))
            }
            "desktop_windows" => {
                let action = arg_str(a, "action").unwrap_or("list");
                if action == "list" {
                    return Ok(json!({"status": "ok", "windows": l::windows()?}));
                }
                let (id, title) = l::find_window(arg_str(a, "window"))?;
                if action == "close" {
                    if let Some(c) = self.confirm_gate(name, a, vec![format!("close window \"{title}\" (unsaved work may be lost)")]) {
                        return Ok(c);
                    }
                }
                l::window_action(action, &id)
            }
            _ => Err(format!("{name} is not available on Linux (no UI Automation): use desktop_screenshot and desktop_input with coordinates")),
        }
    }

    #[cfg(all(windows, feature = "desktop"))]
    async fn desktop(self: &Arc<Self>, name: &str, a: &Value) -> Result<Value, String> {
        if crate::agent_win::in_service_session() {
            // a service has no desktop: hand the call to a copy of ShellGate in the user's session
            let ep = self.agent("session").await?;
            return crate::agent::call(&ep, &json!({"op": "desktop", "name": name, "args": a}), Duration::from_secs(120)).await;
        }
        let me = self.clone();
        let name = name.to_string();
        let a = a.clone();
        tokio::task::spawn_blocking(move || me.desktop_blocking(&name, &a)).await.map_err(|e| e.to_string())?
    }

    /// Desktop call run in this process (what a session agent does for the service).
    pub fn desktop_local(&self, name: &str, a: &Value) -> Result<Value, String> {
        #[cfg(all(windows, feature = "desktop"))]
        { self.desktop_blocking(name, a) }
        #[cfg(all(unix, not(target_os = "android")))]
        { self.desktop_linux(name, a) }
        #[cfg(not(any(all(windows, feature = "desktop"), all(unix, not(target_os = "android")))))]
        { let _ = (name, a); Err("no desktop in this build".into()) }
    }

    /// Endpoint of a running helper agent of this kind, starting it if needed.
    #[cfg_attr(not(windows), allow(unused_variables))]
    async fn agent(&self, kind: &str) -> Result<crate::agent::Endpoint, String> {
        let mut agents = self.agents.lock().await;
        if let Some(ep) = agents.get(kind) {
            if crate::agent::call(ep, &json!({"op": "ping"}), Duration::from_secs(3)).await.is_ok() {
                return Ok(ep.clone());
            }
            agents.remove(kind);
        }
        #[cfg(not(windows))]
        { return Err(format!("{kind} helper agents are a Windows feature")); }
        #[cfg(windows)]
        {
            let s = &self.policy.settings;
            let secret = random_hex(16);
            let pf = crate::agent::port_file(&s.state_dir, kind);
            let _ = fs::remove_file(&pf);
            let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
            let args = vec!["--env-file".into(), s.env_file.clone(), "--agent".into(), kind.to_string(), secret.clone(),
                            pf.display().to_string(), std::process::id().to_string()];
            let wait = match kind {
                "session" => { crate::agent_win::spawn_in_user_session(&exe, &args)?; 20 }
                "elevated" => { crate::agent_win::spawn_elevated(&exe, &args)?; 120 }
                other => return Err(format!("unknown agent kind {other}")),
            };
            let ep = crate::agent::wait_ready(&pf, &secret, Duration::from_secs(wait)).await?;
            agents.insert(kind.to_string(), ep.clone());
            Ok(ep)
        }
    }

    #[cfg(all(windows, feature = "desktop"))]
    fn desktop_blocking(&self, name: &str, a: &Value) -> Result<Value, String> {
        use crate::desktop as d;
        use crate::desktop_win as w;
        w::dpi_aware();
        match name {
            "desktop_windows" => {
                let action = arg_str(a, "action").unwrap_or("list");
                if action == "list" {
                    return Ok(w::windows_json());
                }
                let h = w::find_window(arg_str(a, "window"))?;
                if action == "close" {
                    let t = w::window_title(h);
                    if let Some(c) = self.confirm_gate(name, a, vec![format!("close window \"{t}\" (unsaved work may be lost)")]) {
                        return Ok(c);
                    }
                }
                w::window_action(action, h)
            }
            "desktop_tree" => {
                let all = arg_bool(a, "all", false);
                let h = if all { None } else { Some(w::find_window(arg_str(a, "window"))?) };
                let depth = arg_i64(a, "depth", 12).clamp(1, 40) as usize;
                let max = arg_i64(a, "max_nodes", 300).clamp(10, 2000) as usize;
                let (uia, note, lines) = w::tree(h, all, depth, max)?;
                let mut v = json!({"uia": uia, "count": lines.len(), "tree": lines.join("\n"),
                                   "hint": "refs are valid until the next desktop_tree; rects are physical pixels"});
                if !note.is_empty() {
                    v["note"] = json!(note);
                }
                if lines.len() <= 1 && !uia {
                    v["fallback"] = json!("no usable control tree: use desktop_screenshot and desktop_input with coordinates");
                }
                Ok(v)
            }
            "desktop_element" => {
                let r = arg_i64(a, "ref", 0).max(0) as usize;
                let action = req_str(a, "action")?.to_string();
                let text = arg_str(a, "text").map(String::from);
                let (ctype, cname, rect) = w::ref_info(r)?;
                let mut reasons = vec![];
                if matches!(action.as_str(), "click" | "double_click") && d::risky_control(&cname) {
                    reasons.push(format!("click on \"{cname}\" ({ctype})"));
                }
                if let Some(t) = &text {
                    reasons.extend(self.policy.text_danger_reasons(t).into_iter().map(|x| format!("{x} (typed)")));
                }
                if let Some(c) = self.confirm_gate(name, a, reasons) {
                    return Ok(c);
                }
                let (cx, cy) = (rect.0 + rect.2 / 2, rect.1 + rect.3 / 2);
                let via = if matches!(action.as_str(), "double_click" | "right_click") {
                    None
                } else {
                    w::element_action(r, action.clone(), text.clone())?
                };
                let res = match via {
                    Some(v) => v,
                    None => match action.as_str() {
                        "click" | "double_click" | "right_click" => {
                            if rect.2 <= 0 || rect.3 <= 0 {
                                return Err(format!("ref {r} has no on-screen rectangle to click"));
                            }
                            let (b, n) = match action.as_str() { "double_click" => (0, 2), "right_click" => (1, 1), _ => (0, 1) };
                            w::click_at(cx, cy, b, n)?;
                            json!({"via": "mouse", "at": [cx, cy]})
                        }
                        "set_value" => {
                            if rect.2 > 0 && rect.3 > 0 {
                                w::click_at(cx, cy, 0, 1)?;
                            }
                            w::press_combo(&[0x11, b'A' as u16])?;
                            w::type_text(text.as_deref().unwrap_or(""))?;
                            json!({"via": "keyboard"})
                        }
                        other => return Err(format!("{other} is not supported by this control")),
                    },
                };
                Ok(json!({"ref": r, "control": format!("{ctype} \"{cname}\""), "action": action, "result": res}))
            }
            "desktop_screenshot" => {
                let (vx, vy, vw, vh) = w::virtual_screen();
                let (x, y, cw, ch) = if let Some(rg) = a.get("region").and_then(Value::as_array) {
                    let n: Vec<i32> = rg.iter().filter_map(Value::as_i64).map(|v| v as i32).collect();
                    if n.len() != 4 {
                        return Err("region must be [x, y, width, height]".into());
                    }
                    (n[0], n[1], n[2], n[3])
                } else if arg_str(a, "window").is_some() {
                    w::window_rect(w::find_window(arg_str(a, "window"))?)
                } else {
                    (vx, vy, vw, vh)
                };
                // clip to the virtual screen
                let (x0, y0) = (x.max(vx), y.max(vy));
                let (x1, y1) = ((x + cw).min(vx + vw), (y + ch).min(vy + vh));
                if x1 <= x0 || y1 <= y0 {
                    return Err("capture area is off screen".into());
                }
                let mut frame = w::capture(x0, y0, x1 - x0, y1 - y0)?;
                let max_w = arg_i64(a, "max_width", 1280).max(0) as usize;
                let (nw, nh, scale) = d::fit(frame.w, frame.h, max_w);
                let map = d::Mapping { ox: x0, oy: y0, scale };
                let hash = d::frame_hash(&frame);
                let prev = *self.shot.lock().unwrap();
                *self.shot.lock().unwrap() = Some((map, hash));
                if arg_bool(a, "only_if_changed", true) && prev.is_some_and(|(m, h)| h == hash && m == map) {
                    return Ok(json!({"changed": false, "width": nw, "height": nh, "scale": scale, "origin": [x0, y0],
                                     "note": "screen unchanged since the last screenshot; no image sent"}));
                }
                frame = d::downscale(&frame, nw, nh);
                let mut marks = 0;
                if arg_bool(a, "marks", false) {
                    for (n, r) in w::last_rects() {
                        let (sx, sy) = map.to_shot(r.0, r.1);
                        let (ex, ey) = map.to_shot(r.0 + r.2, r.1 + r.3);
                        if ex > 0 && ey > 0 && sx < nw as i32 && sy < nh as i32 {
                            d::draw_mark(&mut frame, sx as i64, sy as i64, (ex - sx) as i64, (ey - sy) as i64, n);
                            marks += 1;
                        }
                    }
                }
                let jpeg = arg_str(a, "format") == Some("jpeg");
                let (bytes, mime) = if jpeg {
                    (d::encode_jpeg(&frame, arg_i64(a, "quality", 70).clamp(20, 95) as u8)?, "image/jpeg")
                } else {
                    (d::encode_png(&frame), "image/png")
                };
                let mut v = json!({"changed": true, "width": nw, "height": nh, "scale": scale, "origin": [x0, y0],
                                   "physical": [x1 - x0, y1 - y0], "bytes": bytes.len(), "format": mime,
                                   "coords": "desktop_input x/y = pixels of this image; physical = origin + x*scale"});
                if arg_bool(a, "marks", false) {
                    v["marks"] = json!(marks);
                    if marks == 0 {
                        v["marks_note"] = json!("no control rectangles: call desktop_tree first (marks use its refs)");
                    }
                }
                v["_image"] = json!({"data": d::b64(&bytes), "mimeType": mime});
                Ok(v)
            }
            "desktop_input" => {
                let actions = d::parse_actions(a.get("actions").unwrap_or(&Value::Null))?;
                let danger = |t: &str| self.policy.text_danger_reasons(t);
                let reasons = d::batch_reasons(&actions, w::foreground_is_console(), &danger);
                if let Some(c) = self.confirm_gate(name, a, reasons) {
                    return Ok(c);
                }
                let physical = arg_str(a, "coords") == Some("physical");
                let map = self.shot.lock().unwrap().map(|(m, _)| m);
                if !physical && map.is_none() && actions.iter().any(|x| matches!(x, d::Action::Move { .. } | d::Action::Drag { .. }
                        | d::Action::Click { x: Some(_), .. } | d::Action::Scroll { x: Some(_), .. })) {
                    return Err("no screenshot yet: take desktop_screenshot first, or pass coords=physical".into());
                }
                let m = map.unwrap_or(d::Mapping { ox: 0, oy: 0, scale: 1.0 });
                let f = move |x: f64, y: f64| if physical { (x.round() as i32, y.round() as i32) } else { m.to_physical(x, y) };
                let done = w::run_actions(&actions, &f)?;
                Ok(json!({"done": done, "count": done.len()}))
            }
            other => Err(format!("unknown desktop tool {other}")),
        }
    }

    /// Run a tool, audit it, and return (result json, is_error).
    /// Inputs run unmodified; only what is returned (and logged) is redacted.
    pub async fn call(self: &Arc<Self>, ip: &str, name: &str, args: &Value) -> (Value, bool) {
        let start = Instant::now();
        let mut res = self.dispatch(name, args).await;
        // screenshots bypass the text redactor (base64 is not text) and are re-attached afterwards
        let image = match &mut res { Ok(Value::Object(m)) => m.remove("_image"), _ => None };
        // read_binary: binary bytes bypass the text redactor (text files are refused there)
        let raw = match &mut res { Ok(Value::Object(m)) if name == "read_binary" => m.remove("data"), _ => None };
        let ms = start.elapsed().as_millis() as u64;
        let mut logged_args = args.clone();
        if let Some(Value::String(d)) = logged_args.get("data").filter(|_| name == "write_binary") {
            logged_args["data"] = json!(format!("<{} base64 chars>", d.len()));
        }
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
                if let Some(d) = raw {
                    if let Value::Object(m) = &mut v {
                        m.insert("data".into(), d);
                    }
                }
                if let Some(img) = image {
                    extra.insert("image_bytes".into(), json!(img["data"].as_str().map(|d| d.len() * 3 / 4).unwrap_or(0)));
                    if let Value::Object(m) = &mut v {
                        m.insert("_image".into(), img);
                    }
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
        Ok(crate::platform::clean_display(&p.canonicalize().map_err(|e| e.to_string())?))
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

    async fn android(&self, name: &str, a: &Value) -> Result<Value, String> {
        let sd = self.policy.settings.state_dir.clone();
        if name == "android_screen" {
            if arg_str(a, "action") == Some("screenshot") {
                let r = crate::android::call(&sd, json!({"op": "screenshot", "max_width": arg_i64(a, "max_width", 1080)}), Duration::from_secs(20)).await?;
                let png = r["png"].as_str().unwrap_or("").to_string();
                return Ok(json!({"status": "ok", "width": r["width"], "height": r["height"], "screen_width": r["screen_width"],
                                 "screen_height": r["screen_height"], "note": "tap/swipe take screen pixels: scale by screen_width/width",
                                 "_image": {"data": png, "mimeType": "image/png"}}));
            }
            let r = crate::android::call(&sd, json!({"op": "tree", "max_nodes": arg_i64(a, "max_nodes", 300)}), Duration::from_secs(20)).await?;
            crate::android::remember_tree(r["tree"].as_str().unwrap_or(""));
            return Ok(json!({"status": "ok", "package": r["package"], "count": r["count"], "truncated": r["truncated"], "tree": r["tree"]}));
        }
        let (req, reasons) = crate::android::plan(a, &|t| self.policy.text_danger_reasons(t))?;
        if let Some(c) = self.confirm_gate(name, a, reasons) {
            return Ok(c);
        }
        let r = crate::android::call(&sd, req, Duration::from_secs(15)).await?;
        Ok(json!({"status": "ok", "result": r}))
    }

    async fn guarded_change(&self, a: &Value) -> Result<Value, String> {
        let s = &self.policy.settings;
        let cmd = req_str(a, "command")?;
        let cwd = self.resolve_cwd(arg_str(a, "cwd"))?;
        let v = self.policy.allowlist_violations(cmd);
        if !v.is_empty() {
            return Ok(json!({"status": "denied", "reasons": v}));
        }
        let openwrt = guard::is_openwrt();
        let files: Vec<String> = match a.get("files").and_then(Value::as_array) {
            Some(l) if !l.is_empty() => l.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            _ if openwrt => guard::OPENWRT_FILES.iter().map(|x| x.to_string()).collect(),
            _ => vec![],
        };
        let mut checked = vec![];
        for f in &files {
            checked.push(self.policy.check_path(f, true)?);
        }
        let reload = match arg_str(a, "reload") {
            Some(r) => r.to_string(),
            None if openwrt && a.get("files").and_then(Value::as_array).is_none_or(|l| l.is_empty()) => guard::OPENWRT_RELOAD.to_string(),
            None => String::new(),
        };
        let mut reasons: Vec<String> = self.policy.text_danger_reasons(cmd).into_iter()
            .filter(|r| !guard::COVERED_REASONS.contains(&r.as_str())).collect();
        reasons.extend(self.policy.text_danger_reasons(&reload).into_iter()
            .filter(|r| !guard::COVERED_REASONS.contains(&r.as_str())).map(|r| format!("{r} (in reload)")));
        if let Some(c) = self.confirm_gate("guarded_change", a, reasons) {
            return Ok(c);
        }
        let timeout = (arg_i64(a, "timeout", guard::DEFAULT_TIMEOUT as i64).max(0) as u64).clamp(guard::MIN_TIMEOUT, guard::MAX_TIMEOUT);
        let (id, dir, meta) = guard::snapshot(&s.state_dir, &checked, cmd, &reload, timeout)?;
        // arm before running: if the command cuts us off (or restarts ShellGate) the rollback still happens
        guard::arm(dir.clone(), s.shell.clone(), meta["deadline"].as_u64().unwrap_or(0));
        let run_t = s.default_timeout.min(timeout.saturating_sub(5).max(5));
        let out = exec::run_once(s, &self.sem, cmd, &cwd, run_t, None).await?;
        let changed = guard::changed_files(&dir, &meta);
        Ok(json!({"status": "ok", "id": id, "result": out, "changed_files": changed, "rollback_in_s": timeout,
                  "next": format!("Check the host is still reachable and works as intended, then call guarded_confirm id={id} action=keep. Without it, the files are restored and the reload runs in {timeout} s.")}))
    }

    fn backup(&self, p: &str) -> Option<String> {
        if !self.policy.settings.backup_on_write || !Path::new(p).is_file() {
            return None;
        }
        let ts = crate::audit::now_rfc3339().replace([':', '-'], "");
        let base = format!("{p}.bak-{ts}");
        for i in 0..6 {
            let bak = if i == 0 { base.clone() } else { format!("{base}-{}", random_hex(2)) };
            if platform::private_opts().write(true).create_new(true).open(&bak).is_ok() {
                return fs::copy(p, &bak).ok().map(|_| bak);
            }
        }
        None
    }

    fn ventoy_root(&self) -> Result<ventoy::Root, String> {
        ventoy::find_root(&self.policy.settings.ventoy_root)
    }

    async fn ventoy_info(&self, mount: bool) -> Result<Value, String> {
        #[cfg(windows)]
        let _ = mount; // drives are mounted by Windows itself
        match self.ventoy_root() {
            Ok(r) => Ok(ventoy::info(&r)),
            #[cfg(unix)]
            Err(e) if mount => {
                let Some((dev, rest)) = ventoy::mount_args() else { return Err(e) };
                let target = rest[0].clone();
                fs::create_dir_all(&target).map_err(|e| format!("cannot create {target}: {e}"))?;
                let s = &self.policy.settings;
                let r = exec::run_argv(s, &self.sem, "mount", &[dev.clone(), target.clone()], "/", 60, None).await?;
                if r["exit_code"] != json!(0) {
                    return Err(format!("mount {dev} {target} failed: {}", r["stderr"].as_str().unwrap_or("").trim()));
                }
                let mut v = ventoy::info(&self.ventoy_root()?);
                v["mounted_now"] = json!(target);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    fn ventoy_add(&self, a: &Value) -> Result<Value, String> {
        let root = self.ventoy_root()?;
        let url = req_str(a, "url")?.trim();
        let low = url.to_lowercase();
        if !(low.starts_with("https://") || low.starts_with("http://")) {
            return Err("url must start with http:// or https://".into());
        }
        let sha = arg_str(a, "sha256").map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty());
        if let Some(x) = &sha {
            if !ventoy::valid_sha256(x) {
                return Err("sha256 must be 64 hex characters".into());
            }
        }
        let name = ventoy::download_name(url, arg_str(a, "filename"))?;
        let sub = ventoy::safe_rel(arg_str(a, "subdir").unwrap_or(""))?;
        let dir = Path::new(&root.path).join(&sub);
        let dest = dir.join(&name);
        let dest_s = platform::clean_display(&dest);
        self.policy.check_protected(&dest_s)?;
        if dest.exists() {
            return Err(format!("{} already exists; remove it first with ventoy_remove", sub.join(&name).display()));
        }
        let mut map = self.downloads.lock().unwrap();
        if map.values().any(|d| d.running() && d.dest == dest) {
            return Err("this file is already being downloaded".into());
        }
        let running = map.values().filter(|d| d.running()).count();
        if running >= MAX_DOWNLOADS {
            return Err(format!("{running} downloads already running; wait or cancel one"));
        }
        // forget old finished tasks
        if map.len() > 20 {
            let mut done: Vec<(String, u64)> = map.iter().filter(|(_, d)| !d.running()).map(|(k, d)| (k.clone(), d.started_unix)).collect();
            done.sort_by_key(|x| x.1);
            for (k, _) in done.into_iter().take(map.len() - 20) {
                map.remove(&k);
            }
        }
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let id = random_hex(4);
        let d = ventoy::new_download(id.clone(), url.to_string(), dest);
        map.insert(id, d.clone());
        drop(map);
        let free = platform::disk_space(&root.path).map(|x| x.1).unwrap_or(0);
        let fs_type = root.fs_type.clone();
        let shown = d.clone();
        tokio::task::spawn_blocking(move || ventoy::run_download(&d, sha, &fs_type, free));
        let mut v = shown.summary(&root.path);
        v["next"] = json!("Poll ventoy_add_status with this task_id until status is done or failed.");
        Ok(ok(v))
    }

    #[cfg(not(all(unix, not(target_os = "android"))))]
    async fn sysops(&self, name: &str, _a: &Value) -> Result<Value, String> {
        Err(format!("{name} is for Linux and OpenWrt hosts"))
    }

    #[cfg(all(unix, not(target_os = "android")))]
    async fn sysops(&self, name: &str, a: &Value) -> Result<Value, String> {
        use crate::sysops as so;
        let s = &self.policy.settings;
        let root = so::root_prefix(&s.sudo_allow);
        let run = |body: &'static str, args: Vec<String>, t: u64, rootp: &'static str| {
            let mut argv = vec!["-c".to_string(), so::script(body), "sg".to_string()];
            argv.extend(args);
            async move {
                let mut c = platform::new_command("sh");
                c.args(&argv).env("SG_ROOT", rootp.trim_end()).current_dir("/");
                exec::run_cmd(s, &self.sem, c, t, None).await
            }
        };
        let finish = |mut r: Value| {
            let out = r["stdout"].as_str().unwrap_or("").to_string();
            let rep = so::parse_report(&out);
            if let Value::Object(m) = &mut r {
                m.remove("stdout");
                m.insert("report".into(), rep);
            }
            r
        };
        let state = std::path::Path::new(&s.state_dir);
        match name {
            "sys_maintain" => {
                let act = req_str(a, "action")?;
                if !["status", "check_updates", "upgrade", "clean", "services", "logs"].contains(&act) {
                    return Err(format!("unknown action {act}"));
                }
                let pk = arg_str(a, "packages").unwrap_or("").trim().to_string();
                if pk.chars().any(|c| !(c.is_ascii_alphanumeric() || " .+-_:@=".contains(c))) {
                    return Err("packages: names only (letters, digits, . + - _ : @ =)".into());
                }
                let needs_root = matches!(act, "check_updates" | "upgrade" | "clean" | "logs");
                let rp = if needs_root { root? } else { root.unwrap_or("") };
                if act == "upgrade" {
                    let what = if pk.is_empty() { "upgrade all packages".to_string() } else { format!("upgrade {pk}") };
                    if let Some(c) = self.confirm_gate(name, a, vec![what]) {
                        return Ok(c);
                    }
                }
                let t = (arg_i64(a, "timeout", if act == "upgrade" { 600 } else { 180 }).max(1) as u64).min(s.max_timeout.max(600));
                let mut args = vec![act.to_string()];
                args.extend(pk.split_whitespace().map(String::from));
                Ok(ok(finish(run(so::MAINTAIN, args, t, rp).await?)))
            }
            "config_backup" => {
                let rp = root?;
                let out = match arg_str(a, "path").filter(|p| !p.is_empty()) {
                    Some(p) => self.policy.check_path(p, true)?,
                    None => state.join("backups").join(format!("config-{}.tar.gz", guard::now())).display().to_string(),
                };
                let r = finish(run(so::BACKUP, vec![out.clone()], 300, rp).await?);
                let mut r = ok(r);
                if std::path::Path::new(&out).is_file() {
                    r["sha256"] = json!(xfer::sha256_file(&out)?);
                }
                Ok(r)
            }
            "firmware_check" | "firmware_flash" => {
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                if !std::path::Path::new(&p).is_file() {
                    return Err(format!("{p}: not a file"));
                }
                let got = xfer::sha256_file(&p)?;
                let want = arg_str(a, "sha256").unwrap_or("").trim().to_lowercase();
                let sha_ok = want.is_empty() || want == got;
                if name == "firmware_check" {
                    let mut r = ok(finish(run(so::FW_CHECK, vec![p.clone()], 120, "").await?));
                    r["sha256"] = json!(got);
                    r["sha256_match"] = if want.is_empty() { Value::Null } else { json!(sha_ok) };
                    return Ok(r);
                }
                if want.is_empty() || !sha_ok {
                    return Err(format!("sha256 mismatch: image is {got}"));
                }
                let keep = arg_bool(a, "keep_config", true);
                let what = format!("flash {p} with sysupgrade{} (device reboots)", if keep { "" } else { " -n, wiping all settings" });
                if let Some(c) = self.confirm_gate(name, a, vec![what]) {
                    return Ok(c);
                }
                let chk = finish(run(so::FW_CHECK, vec![p.clone()], 120, "").await?);
                if chk["report"]["sysupgrade_test_rc"] != "0" {
                    return Ok(json!({"status": "error", "error": "sysupgrade -T rejected the image", "check": chk["report"]}));
                }
                let bk = state.join("backups").join(format!("pre-flash-{}.tar.gz", guard::now())).display().to_string();
                let b = finish(run(so::BACKUP, vec![bk.clone()], 300, "").await?);
                if b["exit_code"] != 0 {
                    return Ok(json!({"status": "error", "error": "config backup failed; not flashing", "backup": b}));
                }
                let mut fargs = vec![p.clone(), if keep { "1" } else { "0" }.into()];
                if let Ok(exe) = std::env::current_exe() {
                    fargs.push(exe.display().to_string());
                }
                if let Some(dir) = std::path::Path::new(&s.env_file).parent().filter(|d| d.starts_with("/etc")) {
                    fargs.push(dir.display().to_string());
                } else if !s.env_file.is_empty() {
                    fargs.push(s.env_file.clone());
                }
                let r = finish(run(so::FW_FLASH, fargs, 60, "").await?);
                Ok(json!({"status": if r["report"]["started"] == "yes" { "ok" } else { "error" }, "flash": r["report"], "lines": r["report"]["lines"], "backup": bk,
                          "note": "sysupgrade starts in 3 s; the device reboots and ShellGate is unreachable for a few minutes"}))
            }
            "os_reinstall" => {
                let rp = root?;
                let distro = req_str(a, "distro")?.trim().to_lowercase();
                if !so::DISTROS.contains(&distro.as_str()) {
                    return Err(format!("distro must be one of {}", so::DISTROS.join(", ")));
                }
                let safe = |x: &str| x.chars().all(|c| !c.is_control());
                let mut args = vec![distro.clone()];
                if let Some(r) = arg_str(a, "release").filter(|r| !r.trim().is_empty()) {
                    if !r.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
                        return Err("release: letters, digits, dots only".into());
                    }
                    args.push(r.trim().into());
                }
                let key = arg_str(a, "ssh_key").filter(|k| !k.trim().is_empty());
                let pw = arg_str(a, "password").filter(|k| !k.is_empty());
                if key.is_none() && pw.is_none() {
                    return Err("give ssh_key (preferred) or password for the new system's root login".into());
                }
                if let Some(k) = key { if !safe(k) { return Err("ssh_key has control characters".into()); } args.push("--ssh-key".into()); args.push(k.trim().into()); }
                if let Some(p) = pw { if !safe(p) { return Err("password has control characters".into()); } args.push("--password".into()); args.push(p.into()); }
                if let Some(e) = arg_str(a, "extra").filter(|e| !e.trim().is_empty()) {
                    if !safe(e) || e.contains(['`', '$', ';', '|', '&', '<', '>']) {
                        return Err("extra: plain options only".into());
                    }
                    args.extend(e.split_whitespace().map(String::from));
                }
                let reboot = arg_bool(a, "reboot", false);
                let url = arg_str(a, "script_url").filter(|u| !u.is_empty()).unwrap_or(so::REINSTALL_URL).to_string();
                if !url.starts_with("https://") {
                    return Err("script_url must be https".into());
                }
                let what = format!("reinstall this machine as {}{}: the system disk is wiped", args[..if args.len() > 1 && !args[1].starts_with("--") { 2 } else { 1 }].join(" "),
                                   if reboot { ", rebooting right away" } else { " (prepared; reboot to start)" });
                if let Some(c) = self.confirm_gate(name, a, vec![what]) {
                    return Ok(c);
                }
                let dir = state.join("reinstall").display().to_string();
                let mut sargs = vec![url, dir];
                sargs.extend(args);
                let r = finish(run(so::REINSTALL, sargs, 600, rp).await?);
                let ok_run = r["report"]["reinstall_rc"] == "0";
                let mut out = json!({"status": if ok_run { "ok" } else { "error" }, "report": r["report"]});
                if ok_run && reboot {
                    let mut c = platform::new_command("sh");
                    c.args(["-c", &format!("( sleep 3; {}reboot ) </dev/null >/dev/null 2>&1 &", rp)]);
                    let _ = exec::run_cmd(s, &self.sem, c, 10, None).await;
                    out["note"] = json!("rebooting into the installer in 3 s; reach the new system over SSH when it finishes");
                } else if ok_run {
                    out["note"] = json!("installer prepared; reboot to start it (run_command reboot)");
                }
                Ok(out)
            }
            _ => Err(format!("unknown tool {name}")),
        }
    }

    async fn dispatch(self: &Arc<Self>, name: &str, a: &Value) -> Result<Value, String> {
        let s = &self.policy.settings;
        if name.starts_with("ventoy_") && !cfg!(feature = "ventoy") {
            return Err(format!("{name}: this {EDITION} edition is built without the ventoy tools"));
        }
        if name.starts_with("desktop_") && crate::desktop::TOOL_NAMES.contains(&name) {
            if !s.desktop {
                return Err("desktop tools are off; set desktop=on in shellgate.env to enable them".into());
            }
            return self.desktop(name, a).await;
        }
        if matches!(name, "sys_maintain" | "config_backup" | "firmware_check" | "firmware_flash" | "os_reinstall") {
            return self.sysops(name, a).await;
        }
        if crate::android::TOOL_NAMES.contains(&name) {
            if !cfg!(target_os = "android") {
                return Err(format!("{name} is only in the Android app"));
            }
            return self.android(name, a).await;
        }
        match name {
            "run_command" => {
                let cmd = req_str(a, "command")?;
                let cwd = self.resolve_cwd(arg_str(a, "cwd"))?;
                let stdin = arg_str(a, "stdin");
                if stdin.is_some_and(|t| t.len() > MAX_STDIN) {
                    return Err("stdin larger than 4 MB".into());
                }
                let elevated = arg_bool(a, "elevated", false);
                if elevated && !platform::is_elevated() {
                    if !cfg!(windows) {
                        return Err("elevated=true is for Windows; on Linux use sudo=true with SHELLGATE_SUDO_ALLOW".into());
                    }
                    if let Some(b) = self.gate("elevated", cmd, &cwd, arg_str(a, "confirm_code"), stdin, None, &[]) {
                        return Ok(b);
                    }
                    let t = (arg_i64(a, "timeout", s.default_timeout as i64).max(1) as u64).min(s.max_timeout);
                    let ep = self.agent("elevated").await?;
                    let mut r = crate::agent::call(&ep, &json!({"op": "run", "command": cmd, "cwd": cwd, "timeout": t, "stdin": stdin}),
                                                   Duration::from_secs(t + 15)).await?;
                    r["elevated"] = json!(true);
                    return Ok(ok(r));
                }
                let sudo = arg_bool(a, "sudo", false);
                if sudo && cfg!(windows) {
                    return Err("sudo=true is for Linux; on Windows run ShellGate elevated instead".into());
                }
                let argv = if sudo { Some(crate::policy::sudo_argv(cmd, &s.sudo_allow)?) } else { None };
                if let Some(b) = self.gate(if sudo { "sudo" } else { "run" }, cmd, &cwd, arg_str(a, "confirm_code"), stdin, None, &[]) {
                    return Ok(b);
                }
                let t = (arg_i64(a, "timeout", s.default_timeout as i64).max(1) as u64).min(s.max_timeout);
                if let Some(argv) = argv {
                    let mut args = vec!["-n".to_string(), "--".to_string()];
                    args.extend(argv.iter().cloned());
                    let mut r = exec::run_argv(s, &self.sem, "sudo", &args, &cwd, t, stdin).await?;
                    if r["exit_code"] == 1 && r["stderr"].as_str().unwrap_or("").to_lowercase().contains("password") {
                        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
                        let prog = platform::which(&argv[0]).unwrap_or_else(|| argv[0].clone());
                        r["hint"] = json!(format!("sudo wants a password: add a sudoers rule such as '{user} ALL=(root) NOPASSWD: {prog} *' via visudo"));
                    }
                    r["sudo"] = json!(true);
                    return Ok(ok(r));
                }
                exec::run_once(s, &self.sem, cmd, &cwd, t, stdin).await.map(ok)
            }
            "run_script" => {
                let script = req_str(a, "script")?;
                let (interp, note) = pick_interpreter(arg_str(a, "interpreter"), platform::powershell_usable)?;
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
                        if let Some(n) = &note {
                            b["note"] = json!(n);
                        }
                    }
                    return Ok(b);
                }
                let t = (arg_i64(a, "timeout", s.default_timeout as i64).max(1) as u64).min(s.max_timeout);
                let dir = TempDir::new()?; // 0700, unique per call, removed on drop
                let file = dir.0.join(script_file_name(interp));
                {
                    use std::io::Write;
                    let mut f = platform::private_opts().write(true).create_new(true).open(&file)
                        .map_err(|e| format!("cannot write script: {e}"))?;
                    f.write_all(&script_bytes(interp, script)).map_err(|e| e.to_string())?;
                }
                let cmd = script_command(interp, &exe, &file.to_string_lossy(), &args, &cwd);
                let res = exec::run_cmd(s, &self.sem, cmd, t, stdin).await;
                drop(dir);
                let mut v = res?;
                v["interpreter"] = json!(interp);
                if let Some(n) = note {
                    v["note"] = json!(n);
                }
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
            "guarded_change" => self.guarded_change(a).await,
            "guarded_confirm" => {
                let sd = s.state_dir.clone();
                let Some(id) = arg_str(a, "id").filter(|x| !x.is_empty()) else {
                    return Ok(json!({"status": "ok", "guards": guard::list(&sd)}));
                };
                let dir = guard::find(&sd, id)?;
                match arg_str(a, "action").unwrap_or("status") {
                    "keep" => {
                        guard::transition(&dir, "kept")?;
                        Ok(json!({"status": "ok", "id": id, "kept": true}))
                    }
                    "rollback" => guard::rollback(dir, s.shell.clone(), "rolled back by guarded_confirm").await,
                    "status" => {
                        let m = guard::read_meta(&dir)?;
                        let changed = guard::changed_files(&dir, &m);
                        let left = if m["status"] == "pending" { json!(m["deadline"].as_u64().unwrap_or(0).saturating_sub(guard::now())) } else { Value::Null };
                        Ok(json!({"status": "ok", "id": id, "state": m["status"], "command": m["command"], "seconds_left": left,
                                  "changed_files": changed, "rollback": m.get("rollback").cloned().unwrap_or(Value::Null)}))
                    }
                    other => Err(format!("action must be keep, rollback or status, not {other}")),
                }
            }
            "file_hash" => {
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                let size = fs::metadata(&p).map_err(|e| format!("{p}: {e}"))?.len();
                Ok(json!({"status": "ok", "path": p, "size": size, "sha256": xfer::sha256_file(&p)?}))
            }
            "read_binary" => {
                use std::io::{Read, Seek, SeekFrom};
                let p = self.policy.check_path(req_str(a, "path")?, false)?;
                if !Path::new(&p).is_file() {
                    return Err(format!("{p}: not a file"));
                }
                if xfer::looks_text(&p)? {
                    return Err("this is a text file: use read_file (its output is redacted)".into());
                }
                let size = fs::metadata(&p).map_err(|e| e.to_string())?.len();
                let offset = arg_i64(a, "offset", 0).max(0) as u64;
                let length = (arg_i64(a, "length", xfer::CHUNK_DEFAULT as i64).max(1) as u64).min(xfer::CHUNK_MAX);
                let mut f = fs::File::open(&p).map_err(|e| e.to_string())?;
                f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
                let mut chunk = Vec::with_capacity(length as usize);
                f.take(length).read_to_end(&mut chunk).map_err(|e| e.to_string())?;
                let eof = offset + chunk.len() as u64 >= size;
                let mut v = json!({"status": "ok", "path": p, "size": size, "offset": offset, "length": chunk.len(), "eof": eof,
                                   "chunk_sha256": xfer::sha256_hex(&chunk), "data": xfer::b64_encode(&chunk)});
                if eof {
                    v["sha256"] = json!(xfer::sha256_file(&p)?);
                }
                Ok(v)
            }
            "write_binary" => {
                use std::io::Write;
                let p = self.policy.check_path(req_str(a, "path")?, true)?;
                let part = format!("{p}.sgpart");
                let chunk = xfer::b64_decode(req_str(a, "data")?)?;
                if chunk.len() as u64 > xfer::CHUNK_MAX {
                    return Err("chunk larger than 1 MB".into());
                }
                let want = arg_str(a, "sha256").map(|x| x.trim().to_lowercase()).unwrap_or_default();
                if !want.is_empty() && !(want.len() == 64 && want.bytes().all(|b| b.is_ascii_hexdigit())) {
                    return Err("sha256 must be 64 hex characters".into());
                }
                if let Some(dir) = Path::new(&p).parent() {
                    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                }
                let have = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
                let offset = arg_i64(a, "offset", 0).max(0) as u64;
                let mut f = if offset == 0 {
                    fs::File::create(&part)
                } else if offset == have {
                    fs::OpenOptions::new().append(true).open(&part)
                } else {
                    return Ok(json!({"status": "error", "error": format!("offset {offset} does not match the {have} bytes already written"),
                                     "next_offset": have}));
                }.map_err(|e| format!("{part}: {e}"))?;
                f.write_all(&chunk).map_err(|e| e.to_string())?;
                drop(f);
                let written = offset + chunk.len() as u64;
                if want.is_empty() {
                    return Ok(json!({"status": "ok", "path": p, "partial": part, "next_offset": written}));
                }
                let got = xfer::sha256_file(&part)?;
                if got != want {
                    let _ = fs::remove_file(&part);
                    return Ok(json!({"status": "error", "error": "sha256 mismatch, partial file deleted",
                                     "expected": want, "actual": got, "size": written}));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(&p).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o644);
                    let _ = fs::set_permissions(&part, fs::Permissions::from_mode(mode));
                }
                let bak = self.backup(&p);
                #[cfg(windows)]
                let _ = fs::remove_file(&p);
                fs::rename(&part, &p).map_err(|e| format!("{p}: {e}"))?;
                Ok(json!({"status": "ok", "path": p, "size": written, "sha256": got, "verified": true, "backup": bak}))
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
                    entries.push(json!({"name": name, "type": kind, "size": m.len(), "modified_unix": m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)}));
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
            "system_info" => Ok({ let mut v = system_info(); v["edition"] = json!(EDITION); v }),
            #[cfg(feature = "net-tools")]
            "lan_scan" => {
                let specs: Vec<String> = match arg_str(a, "targets").filter(|t| !t.trim().is_empty()) {
                    Some(t) => t.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
                    None => crate::lan::default_targets(),
                };
                if specs.is_empty() {
                    return Err("no LAN address found; pass targets, e.g. 192.168.1.0/24".into());
                }
                let mut targets = vec![];
                for sp in &specs {
                    targets.extend(crate::lan::parse_targets(sp)?);
                }
                targets.sort();
                targets.dedup();
                targets.truncate(2048);
                let ports: Vec<u16> = match arg_str(a, "ports").filter(|p| !p.trim().is_empty()) {
                    Some(p) => p.split(',').map(|x| x.trim().parse::<u16>().map_err(|_| format!("bad port: {x}"))).collect::<Result<_, _>>()?,
                    None => crate::lan::DEFAULT_PORTS.to_vec(),
                };
                if ports.is_empty() || ports.len() > 64 {
                    return Err("ports: 1 to 64 ports".into());
                }
                let timeout = arg_i64(a, "timeout_ms", 600).clamp(50, 5000) as u64;
                let conc = arg_i64(a, "concurrency", 256).clamp(8, 512) as usize;
                let mut v = crate::lan::scan(targets, ports, timeout, conc).await;
                v["targets"] = json!(specs);
                Ok(v)
            }
            #[cfg(feature = "net-tools")]
            "http_request" => {
                let url = req_str(a, "url")?.to_string();
                let method = arg_str(a, "method").unwrap_or("GET").to_string();
                let headers: Vec<(String, String)> = a.get("headers").and_then(Value::as_object)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect())
                    .unwrap_or_default();
                let body = arg_str(a, "body").map(str::to_string);
                let insecure = arg_bool(a, "insecure", false);
                let timeout = arg_i64(a, "timeout_s", 30).clamp(1, 120) as u64;
                let max = arg_i64(a, "max_bytes", 262_144).clamp(1024, 4_000_000) as usize;
                tokio::task::spawn_blocking(move || crate::lan::http_request(&method, &url, &headers, body.as_deref(), timeout, insecure, max))
                    .await.map_err(|e| e.to_string())?
            }
            #[cfg(feature = "admin-lite")]
            "connection_info" => Ok(crate::admin::connection_info(s, false)),
            #[cfg(feature = "admin")]
            "cloudflare_setup" => crate::cf::tool(s, a).await,
            "audit_tail" => {
                let n = arg_i64(a, "n", 20).clamp(1, 200) as usize;
                Ok(json!({"status": "ok", "entries": self.audit.tail(n)}))
            }
            "ventoy_info" => self.ventoy_info(arg_bool(a, "mount", false)).await,
            "ventoy_list" => {
                let root = self.ventoy_root()?;
                let pol = &self.policy;
                Ok(ventoy::list(&root, &|p| pol.check_protected(p).is_err()))
            }
            "ventoy_add" => self.ventoy_add(a),
            "ventoy_add_status" => {
                let root = self.ventoy_root().map(|r| r.path).unwrap_or_default();
                let map = self.downloads.lock().unwrap();
                if let Some(id) = arg_str(a, "task_id").filter(|i| !i.is_empty()) {
                    let d = map.get(id).ok_or_else(|| format!("unknown task_id: {id}"))?;
                    if arg_bool(a, "cancel", false) && d.running() {
                        d.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let mut v = d.summary(&root);
                    if arg_bool(a, "cancel", false) {
                        v["cancel_requested"] = json!(true);
                    }
                    return Ok(ok(v));
                }
                let mut list: Vec<Value> = map.values().map(|d| d.summary(&root)).collect();
                list.sort_by_key(|v| v["started_unix"].as_u64().unwrap_or(0));
                Ok(json!({"status": "ok", "tasks": list}))
            }
            "ventoy_remove" => {
                let root = self.ventoy_root()?;
                let rel = req_str(a, "path")?;
                let p = ventoy::image_path(&root, rel)?;
                let ps = platform::clean_display(&p);
                self.policy.check_protected(&ps)?;
                let m = fs::metadata(&p).map_err(|e| e.to_string())?;
                let mt = m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                let fp = Policy::fingerprint(&["ventoy_remove".to_string(), ps.clone(), m.len().to_string(), mt.to_string()]);
                if !self.policy.redeem(arg_str(a, "confirm_code"), fp) {
                    return Ok(json!({
                        "status": "confirmation_required", "reasons": ["delete a boot image from the Ventoy stick"],
                        "path": rel, "size_bytes": m.len(),
                        "confirm_code": self.policy.issue(fp), "expires_in_s": self.policy.settings.confirm_ttl,
                        "next": "Ask the user. Only if they explicitly agree, call again with the same path plus this confirm_code.",
                    }));
                }
                fs::remove_file(&p).map_err(|e| format!("delete failed: {e}"))?;
                Ok(json!({"status": "ok", "deleted": rel, "size_bytes": m.len()}))
            }
            "ventoy_config_get" => {
                let root = self.ventoy_root()?;
                self.policy.check_protected(&platform::clean_display(&ventoy::config_path(&root)))?;
                ventoy::config_get(&root)
            }
            "ventoy_config_set" => {
                let root = self.ventoy_root()?;
                let content = req_str(a, "content")?;
                if content.len() > 1_000_000 {
                    return Err("ventoy.json larger than 1 MB".into());
                }
                self.policy.check_protected(&platform::clean_display(&ventoy::config_path(&root)))?;
                ventoy::config_set(&root, content)
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

#[cfg_attr(windows, allow(dead_code))]
fn read_trim(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

#[cfg_attr(windows, allow(dead_code))]
fn kv(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix(&format!("{key}=")).map(|v| v.trim_matches(['"', '\'']).to_string()))
}

fn space(path: &str) -> Option<Value> {
    let (total, free) = platform::disk_space(path)?;
    Some(json!({"total_mb": (total as f64 / 1048576.0).round(), "free_mb": (free as f64 / 1048576.0).round()}))
}

#[cfg(unix)]
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
            if let Some(v) = space(m) {
                storage.insert(m.into(), v);
            }
        }
    }
    json!({
        "status": "ok",
        "hostname": read_trim("/proc/sys/kernel/hostname").unwrap_or_default(),
        "os": os,
        "board": read_trim("/tmp/sysinfo/model").or_else(|| read_trim("/sys/class/dmi/id/product_name")).unwrap_or_default(),
        "kernel": kernel,
        "arch": std::env::consts::ARCH,
        "wsl": kernel.to_lowercase().contains("microsoft"),
        "winpe": false,
        "uptime_h": (uptime / 360.0).round() / 10.0,
        "load": load,
        "mem_mb": mem,
        "storage": storage,
        "time_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    })
}

#[cfg(windows)]
fn system_info() -> Value {
    let (total, avail, up, host) = platform::win_sysinfo();
    let mut storage = Map::new();
    for v in platform::volumes() {
        if let Some(mut s) = space(&v.root) {
            s["label"] = json!(v.label);
            s["fs"] = json!(v.fs_type);
            storage.insert(v.root.clone(), s);
        }
    }
    json!({
        "status": "ok",
        "hostname": host,
        "os": "Windows",
        "os_version": platform::windows_version(),
        "winpe": platform::is_winpe(),
        "powershell": platform::powershell_usable(),
        "arch": std::env::consts::ARCH,
        "wsl": false,
        "uptime_h": ((up as f64) / 360.0).round() / 10.0,
        "mem_mb": {"total": total, "available": avail},
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

    #[cfg(unix)]
    #[test]
    fn interpreter_default_and_unknown() {
        assert_eq!(super::pick_interpreter(None, || false).unwrap(), ("sh", None));
        assert_eq!(super::pick_interpreter(Some(""), || false).unwrap().0, "sh");
        assert_eq!(super::pick_interpreter(Some("bash"), || false).unwrap().0, "bash");
        assert!(super::pick_interpreter(Some("perl"), || true).unwrap_err().contains("must be one of"));
    }

    #[cfg(windows)]
    #[test]
    fn interpreter_powershell_fallback() {
        let (i, n) = super::pick_interpreter(None, || false).unwrap();
        assert_eq!(i, "cmd");
        assert!(n.unwrap().contains("ran with cmd"));
        assert_eq!(super::pick_interpreter(None, || true).unwrap(), ("powershell", None));
        assert!(super::pick_interpreter(Some("powershell"), || false).unwrap_err().contains("not available"));
        assert_eq!(super::pick_interpreter(Some("cmd"), || false).unwrap(), ("cmd", None));
    }

    #[test]
    fn cmd_script_encoding() {
        // fake OEM code page that only has ASCII and the GBK bytes for "中"
        let oem = |s: &str| -> Option<Vec<u8>> {
            let mut v = vec![];
            for c in s.chars() {
                match c {
                    '中' => v.extend_from_slice(&[0xD6, 0xD0]),
                    c if c.is_ascii() => v.push(c as u8),
                    _ => return None,
                }
            }
            Some(v)
        };
        assert_eq!(super::cmd_script_bytes("@echo off\necho 中", oem), b"@echo off\r\necho \xD6\xD0".to_vec());
        // a character outside the code page: chcp 65001 first, then UTF-8
        let out = super::cmd_script_bytes("echo 中✓\r\n", oem);
        assert!(out.starts_with(b"@chcp 65001 >nul\r\n"));
        assert!(out.ends_with("echo 中✓\r\n".as_bytes()));
        assert!(!String::from_utf8(out).unwrap().contains("\r\r"));
    }
}
