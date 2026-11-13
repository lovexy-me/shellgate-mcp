//! Configuration from environment variables, optionally loaded from an env file.
//!
//! The env file holds `KEY=VALUE` lines. Besides the full `SHELLGATE_*` names, short lowercase
//! names are accepted (`token=...` means `SHELLGATE_TOKEN=...`, `net=lan` means `SHELLGATE_NET=lan`),
//! so a rescue-stick config can be a single `token=` line.
//!
//! No secret ever has a built-in default: the token (and the optional Cloudflare tunnel token)
//! only come from the env file / environment that the user writes on their own machine.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::platform::{self, SEP};
use crate::policy::resolve;

#[cfg(unix)]
pub const DEFAULT_ENV_FILE: &str = "/etc/shellgate/env";
#[cfg(windows)]
pub const DEFAULT_ENV_FILE: &str = "C:\\ProgramData\\shellgate\\shellgate.env";

/// File name looked for next to the executable and in `<Ventoy>/shellgate/`.
pub const STICK_ENV_NAME: &str = "shellgate.env";
pub const STICK_DIR: &str = "shellgate";

/// How the HTTP listener is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetMode {
    /// 127.0.0.1 only (default); something else (SSH, an external tunnel) publishes it.
    Local,
    /// 0.0.0.0 so other machines on the same LAN can connect directly; Bearer token enforced.
    Lan,
    /// 127.0.0.1 plus a supervised `cloudflared tunnel run` using SHELLGATE_TUNNEL_TOKEN.
    Tunnel,
}

impl NetMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetMode::Local => "local",
            NetMode::Lan => "lan",
            NetMode::Tunnel => "tunnel",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub token: String,
    pub host: String,
    pub port: u16,
    pub mode_allowlist: bool,
    pub allowed_commands: Vec<String>,
    pub allowed_dirs: Vec<String>,
    pub protected_paths: Vec<String>,
    pub extra_danger_patterns: Vec<String>,
    pub audit_log: String,
    pub audit_max_bytes: u64,
    pub default_timeout: u64,
    pub max_timeout: u64,
    pub max_output_bytes: usize,
    pub max_concurrent: usize,
    pub max_jobs: usize,
    pub confirm_ttl: u64,
    pub shell: String,
    pub backup_on_write: bool,
    pub env_file: String,
    pub redact: bool,
    pub redact_domains: Vec<String>,
    /// personal-data rules (email, CN mobile, IMEI, serial, SSID); SHELLGATE_REDACT_PII=0 turns them off
    pub redact_pii: bool,
    /// commands run_command may run as root (sudo=true), ";"-separated prefixes; empty = off
    pub sudo_allow: Vec<String>,
    // ---- rescue stick (v0.3.0)
    pub net: NetMode,
    pub tunnel_token: String,
    pub cloudflared: String,
    pub mdns: bool,
    pub mdns_name: String,
    pub ventoy_root: String,
    pub state_dir: String,
    /// WinPE only, net=lan|tunnel: start networking (wpeutil InitializeNetwork) when there is no IPv4
    /// address, and in lan mode turn the WinPE firewall off (wpeutil DisableFirewall). Default on.
    pub pe_network: bool,
    /// Windows desktop tools (screenshot, UI Automation, mouse/keyboard). Off unless desktop=on.
    pub desktop: bool,
    /// Local admin page (status, connection info, Cloudflare setup) on 127.0.0.1:<admin_port>; 0 = off.
    pub admin_port: u16,
    /// Public https base URL of this server (set by the Cloudflare wizard), e.g. https://pc.example.com
    pub public_url: String,
}

impl Settings {
    /// Settings for unit tests (no env access).
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Settings {
            token: "x".repeat(40), host: "127.0.0.1".into(), port: 1, mode_allowlist: false,
            allowed_commands: vec![], allowed_dirs: vec![], protected_paths: vec![],
            extra_danger_patterns: vec![], audit_log: "/tmp/a".into(), audit_max_bytes: 1,
            default_timeout: 1, max_timeout: 1, max_output_bytes: 1, max_concurrent: 1, max_jobs: 1,
            confirm_ttl: 60, shell: platform::default_shell(), backup_on_write: true, env_file: String::new(),
            redact: true, redact_domains: vec![], redact_pii: true, sudo_allow: vec![], net: NetMode::Local, tunnel_token: String::new(),
            cloudflared: String::new(), mdns: false, mdns_name: "ventoy-rescue".into(), ventoy_root: String::new(),
            state_dir: String::new(), pe_network: true, desktop: false, admin_port: 0, public_url: String::new(),
        }
    }
}

/// Map a short lowercase key (`token`) to its full name (`SHELLGATE_TOKEN`).
fn full_key(k: &str) -> String {
    if k == "VENTOY_ROOT" || k.starts_with("SHELLGATE_") {
        return k.to_string();
    }
    if k.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return format!("SHELLGATE_{}", k.to_uppercase());
    }
    k.to_string()
}

/// Values read from the config file. They live only in this process's memory: they are never
/// written into the process environment, so commands, jobs and helpers started by ShellGate cannot
/// read the access token or the tunnel token from their inherited environment.
static FILE_VALUES: std::sync::RwLock<Option<HashMap<String, String>>> = std::sync::RwLock::new(None);

fn parse_env_text(text: &str) -> HashMap<String, String> {
    let text = text.trim_start_matches('\u{feff}'); // Notepad may save a UTF-8 BOM
    let mut m = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = full_key(k.trim());
            let v = v.trim().trim_matches('"').trim_matches('\'');
            m.entry(k).or_insert_with(|| v.to_string()); // first occurrence wins, as before
        }
    }
    m
}

fn load_env_file(path: &Path) {
    let m = fs::read_to_string(path).map(|t| parse_env_text(&t)).unwrap_or_default();
    *FILE_VALUES.write().unwrap_or_else(|e| e.into_inner()) = Some(m);
}

/// A config value: the real environment wins (as before), then the config file. Empty = unset.
pub fn var(key: &str) -> Option<String> {
    if let Some(v) = env::var(key).ok().filter(|v| !v.is_empty()) {
        return Some(v);
    }
    FILE_VALUES.read().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(key).cloned()).filter(|v| !v.is_empty())
}

fn get(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|| default.to_string())
}

fn split(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn num<T: std::str::FromStr>(key: &str, default: T) -> T {
    var(key).and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn expand(p: &str) -> String {
    let p = if let Some(rest) = p.strip_prefix('~') { format!("{}{}", platform::home(), rest) } else { p.to_string() };
    #[cfg(windows)]
    let p = expand_win_vars(&p);
    resolve(&p).unwrap_or(p)
}

/// Expand `%VAR%` references (Windows convention) in a configured path.
#[cfg(windows)]
fn expand_win_vars(p: &str) -> String {
    let mut out = String::new();
    let mut rest = p;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                out.push_str(&env::var(name).unwrap_or_else(|_| format!("%{name}%")));
                rest = &after[j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Where to read the config from, first match wins:
/// `--env-file` > `SHELLGATE_ENV_FILE` > `shellgate.env` next to the executable >
/// the platform default if it exists > `<Ventoy partition>/shellgate/shellgate.env` > platform default.
pub fn locate_env_file(cli: Option<String>) -> PathBuf {
    if let Some(p) = cli.filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(p) = env::var("SHELLGATE_ENV_FILE").ok().filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(d) = platform::exe_dir() {
        let p = d.join(STICK_ENV_NAME);
        if p.is_file() {
            return p;
        }
    }
    if Path::new(DEFAULT_ENV_FILE).is_file() {
        return PathBuf::from(DEFAULT_ENV_FILE);
    }
    if let Ok(root) = crate::ventoy::find_root(&env::var("VENTOY_ROOT").unwrap_or_default()) {
        let p = Path::new(&root.path).join(STICK_DIR).join(STICK_ENV_NAME);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(DEFAULT_ENV_FILE)
}

/// Obvious template values must never be accepted as a real token.
fn looks_like_placeholder(t: &str) -> bool {
    let l = t.to_lowercase();
    ["change", "replace", "your", "token-here", "填写", "请", "<", ">", "xxxx", "example"].iter().any(|p| l.contains(p))
}

/// Portable / Android builds: when no config exists yet, create one with a fresh token
/// (next to the executable for the portable build, or at the path given with --env-file).
pub fn ensure_config(path: &Path) -> Result<bool, String> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    use std::io::Write;
    let token = crate::policy::random_hex(24);
    let mut f = platform::private_opts().write(true).create_new(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(template(&token).as_bytes()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Where a self-configuring build keeps its config when nothing was found.
pub fn self_config_path(cli: Option<String>) -> PathBuf {
    let found = locate_env_file(cli.clone());
    if found.is_file() || cli.is_some() || env::var_os("SHELLGATE_ENV_FILE").is_some() {
        return found;
    }
    platform::exe_dir().map(|d| d.join(STICK_ENV_NAME)).unwrap_or(found)
}

/// Set (Some) or remove (None) keys in the env file, keeping every other line and comment.
/// Keys are written in their short form (`tunnel_token=`). The file is rewritten atomically.
pub fn set_keys(path: &Path, changes: &[(&str, Option<String>)]) -> Result<(), String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let text = text.trim_start_matches('\u{feff}');
    let mut done = vec![false; changes.len()];
    let mut out: Vec<String> = vec![];
    for raw in text.lines() {
        let line = raw.trim();
        let key = if line.starts_with('#') || line.starts_with(';') { None } else { line.split_once('=').map(|(k, _)| full_key(k.trim())) };
        // a commented template line `#key=` is replaced in place by the first set of that key
        let commented = line.strip_prefix('#').and_then(|l| l.split_once('=')).map(|(k, _)| k.trim().to_string())
            .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '_')).map(|k| full_key(&k));
        let mut replaced = false;
        for (i, (k, v)) in changes.iter().enumerate() {
            let fk = full_key(k);
            if key.as_deref() == Some(fk.as_str()) {
                if !done[i] {
                    if let Some(v) = v { out.push(format!("{k}={v}")); }
                    done[i] = true;
                }
                replaced = true; // drop duplicates and removed keys
                break;
            }
            if commented.as_deref() == Some(fk.as_str()) && !done[i] && v.is_some() && !text_has_key(text, &fk) {
                out.push(raw.to_string());
                out.push(format!("{k}={}", v.as_ref().unwrap()));
                done[i] = true;
                replaced = true;
                break;
            }
        }
        if !replaced {
            out.push(raw.to_string());
        }
    }
    for (i, (k, v)) in changes.iter().enumerate() {
        if !done[i] {
            if let Some(v) = v { out.push(format!("{k}={v}")); }
        }
    }
    for (k, v) in changes {
        if let Some(v) = v {
            if v.contains('\n') || v.contains('\r') {
                return Err(format!("{k}: value must be one line"));
            }
        }
    }
    let tmp = path.with_extension("env.tmp");
    {
        use std::io::Write;
        let _ = fs::remove_file(&tmp);
        let mut f = platform::private_opts().write(true).create_new(true).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all((out.join("\n") + "\n").as_bytes()).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

fn text_has_key(text: &str, fk: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.split_once('=').map(|(k, _)| full_key(k.trim()) == fk).unwrap_or(false)
    })
}

pub fn load(env_file: Option<String>) -> Result<Settings, String> {
    let path = locate_env_file(env_file);
    load_env_file(&path);

    let token = get("SHELLGATE_TOKEN", "");
    if token.len() < 32 || looks_like_placeholder(&token) {
        return Err(format!(
            "SHELLGATE_TOKEN is missing, shorter than 32 characters, or still a template value (config: {}).\n\
             Generate one with `shellgate --gen-token`, or create a config with `shellgate --init-config <path>`.",
            path.display()
        ));
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("SHELLGATE_TOKEN must not contain spaces or control characters".into());
    }
    // command policy mode; `mode=lan|tunnel|local` is accepted as a friendly alias for net=
    let mut mode = get("SHELLGATE_MODE", "full").to_lowercase();
    let mut net_raw = get("SHELLGATE_NET", "").to_lowercase();
    if ["lan", "tunnel", "local"].contains(&mode.as_str()) {
        if net_raw.is_empty() {
            net_raw = mode.clone();
        }
        mode = "full".into();
    }
    if mode != "full" && mode != "allowlist" {
        return Err("SHELLGATE_MODE must be 'full' or 'allowlist'".into());
    }
    let tunnel_token = get("SHELLGATE_TUNNEL_TOKEN", "");
    let net = match net_raw.as_str() {
        "" => if tunnel_token.is_empty() { NetMode::Local } else { NetMode::Tunnel },
        "local" | "localhost" | "loopback" => NetMode::Local,
        "lan" => NetMode::Lan,
        "tunnel" | "cloudflare" | "cf" => NetMode::Tunnel,
        other => return Err(format!("SHELLGATE_NET must be local, lan or tunnel (got {other})")),
    };
    if net == NetMode::Tunnel && !tunnel_token.is_empty() && looks_like_placeholder(&tunnel_token) {
        return Err("SHELLGATE_TUNNEL_TOKEN is still a template value".into());
    }
    let default_host = if net == NetMode::Lan { "0.0.0.0" } else { "127.0.0.1" };

    let h = platform::home();
    let cfg_dir = path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    #[cfg(unix)]
    let default_state = if crate::SELF_CONFIG && !cfg_dir.is_empty() { format!("{cfg_dir}/logs") } else { "/var/log/shellgate".to_string() };
    #[cfg(windows)]
    let default_state = if cfg_dir.is_empty() { format!("{}\\shellgate", env::temp_dir().display()) } else { format!("{cfg_dir}\\logs") };
    let state_dir = get("SHELLGATE_STATE_DIR", &default_state);
    let audit_log = get("SHELLGATE_AUDIT_LOG", &format!("{state_dir}{SEP}audit.jsonl"));
    let audit_dir = Path::new(&audit_log).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let ventoy_root = get("SHELLGATE_VENTOY_ROOT", &get("VENTOY_ROOT", ""));

    // The config directory holds the token(s). When the config sits directly in a filesystem
    // root (e.g. the root of the Ventoy partition) protect only the file, not the whole drive.
    let cfg_is_root = Path::new(&cfg_dir).parent().is_none()
        || (!ventoy_root.is_empty() && resolve(&cfg_dir) == resolve(&ventoy_root));
    let cfg_protect = if cfg_is_root { path.to_string_lossy().to_string() } else { cfg_dir };

    let mut protected: Vec<String> = vec![
        cfg_protect,
        audit_dir,
        format!("{h}{SEP}.ssh"),
        format!("{h}{SEP}.cloudflared"),
    ];
    #[cfg(unix)]
    protected.extend(["/etc/shadow", "/etc/gshadow", "/etc/dropbear", "/etc/sudoers", "/etc/sudoers.d"].map(String::from));
    #[cfg(windows)]
    {
        let sysroot = get("SystemRoot", "C:\\Windows");
        protected.push(format!("{sysroot}\\System32\\config")); // SAM, SYSTEM, SECURITY, SOFTWARE hives
        protected.push(format!("{sysroot}\\NTDS"));
        protected.push(format!("{h}\\NTUSER.DAT"));
    }
    protected.extend(split(&get("SHELLGATE_PROTECTED_PATHS", "")));

    #[cfg(unix)]
    let default_dirs = if cfg!(target_os = "android") { format!("{h},/storage/emulated/0") } else { format!("/tmp,{h},/etc/config") };
    #[cfg(windows)]
    let default_dirs = {
        let mut d = vec![env::temp_dir().display().to_string(), h.clone()];
        d.extend(winpe_extra_dirs(platform::is_winpe(), platform::temp_dirs()));
        dedup_dirs(d).join(",")
    };
    Ok(Settings {
        token,
        host: get("SHELLGATE_HOST", default_host),
        port: num("SHELLGATE_PORT", 8790),
        mode_allowlist: mode == "allowlist",
        allowed_commands: split(&get("SHELLGATE_ALLOWED_COMMANDS", "")),
        allowed_dirs: split(&get("SHELLGATE_ALLOWED_DIRS", &default_dirs)).iter().map(|d| expand(d)).collect(),
        protected_paths: protected.iter().filter(|p| !p.is_empty()).map(|p| expand(p)).collect(),
        extra_danger_patterns: split(&get("SHELLGATE_DANGER_PATTERNS", "")),
        audit_log: expand(&audit_log),
        audit_max_bytes: num("SHELLGATE_AUDIT_MAX_BYTES", 2_000_000),
        default_timeout: num("SHELLGATE_DEFAULT_TIMEOUT", 60),
        max_timeout: num("SHELLGATE_MAX_TIMEOUT", 600),
        max_output_bytes: num("SHELLGATE_MAX_OUTPUT_BYTES", 100_000),
        max_concurrent: num("SHELLGATE_MAX_CONCURRENT", 2),
        max_jobs: num("SHELLGATE_MAX_JOBS", 4),
        confirm_ttl: num("SHELLGATE_CONFIRM_TTL", 300),
        shell: get("SHELLGATE_SHELL", &platform::default_shell()),
        backup_on_write: truthy(&get("SHELLGATE_BACKUP_ON_WRITE", "true")),
        env_file: path.to_string_lossy().to_string(),
        redact: !matches!(get("SHELLGATE_REDACT", "1").trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        redact_domains: split(&get("SHELLGATE_REDACT_DOMAINS", "")),
        redact_pii: !matches!(get("SHELLGATE_REDACT_PII", "1").trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        sudo_allow: get("SHELLGATE_SUDO_ALLOW", "").split(';').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect(),
        net,
        tunnel_token,
        cloudflared: get("SHELLGATE_CLOUDFLARED", ""),
        mdns: truthy(&get("SHELLGATE_MDNS", if net == NetMode::Lan { "1" } else { "0" })),
        mdns_name: get("SHELLGATE_MDNS_NAME", if cfg!(feature = "edition-pe") || cfg!(feature = "edition-linux") { "ventoy-rescue" } else { "shellgate" }).trim_end_matches(".local").to_string(),
        ventoy_root,
        state_dir: expand(&state_dir),
        pe_network: truthy(&get("SHELLGATE_PE_NETWORK", "1")),
        desktop: truthy(&get("SHELLGATE_DESKTOP", "0")),
        admin_port: num("SHELLGATE_ADMIN_PORT", if cfg!(feature = "admin-lite") { 8791 } else { 0 }),
        public_url: get("SHELLGATE_PUBLIC_URL", "").trim_end_matches('/').to_string(),
    })
}

/// Extra default allowed directories inside WinPE: the RAM drive X:\ (everything there is
/// throw-away) and the temp directories (%TEMP%/%TMP%), which WinPE points at X:\Windows\TEMP.
#[cfg_attr(unix, allow(dead_code))]
fn winpe_extra_dirs(is_pe: bool, temps: Vec<String>) -> Vec<String> {
    if !is_pe {
        return vec![];
    }
    let mut v = vec!["X:\\".to_string()];
    v.extend(temps);
    v
}

/// Drop empty and repeated entries (case-insensitive, trailing separators ignored), keep order.
#[cfg_attr(unix, allow(dead_code))]
fn dedup_dirs(dirs: Vec<String>) -> Vec<String> {
    let key = |d: &str| {
        let t = d.replace('/', "\\").to_lowercase();
        let t = t.trim_end_matches('\\').to_string();
        t
    };
    let mut out: Vec<String> = vec![];
    for d in dirs {
        if !d.trim().is_empty() && !out.iter().any(|o| key(o) == key(&d)) {
            out.push(d);
        }
    }
    out
}

/// Text of a fresh config file: only the token is filled in; everything else is commented out.
pub fn template(token: &str) -> String {
    format!(
"# ShellGate rescue-stick config. Keep this file private: it holds the access token.
# Only `token` is required. Lines starting with # are ignored.
token={token}

# Network mode: local (default, 127.0.0.1 only) | lan (0.0.0.0, same LAN, Bearer token enforced) | tunnel
#net=lan

# Cloudflare tunnel token (only for net=tunnel; cloudflared(.exe) next to shellgate or on PATH)
#tunnel_token=

# mDNS name announced in lan mode (http://ventoy-rescue.local:8790/mcp); set mdns=0 to disable
#mdns_name=ventoy-rescue

# Ventoy data partition, if it is not found by its label \"Ventoy\"
#ventoy_root=/mnt/ventoy

#port=8790
#state_dir=

# WinPE, net=lan|tunnel: bring the network up (wpeutil InitializeNetwork) and, for lan, turn the
# WinPE firewall off (wpeutil DisableFirewall). Set pe_network=0 to leave both alone.
#pe_network=1

# Windows only: desktop tools (screenshots, UI Automation control tree, mouse and keyboard).
# Off by default; every action is written to the audit log; risky key combos need a confirm code.
#desktop=on

# Local admin page (status, connection info, Cloudflare setup) on http://127.0.0.1:8791 ; 0 = off
#admin_port=8791
")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_values_stay_out_of_the_environment() {
        let m = parse_env_text("\u{feff}token=abc\n# c\nnet = lan\nSHELLGATE_PORT='9'\ntoken=second\n");
        assert_eq!(m.get("SHELLGATE_TOKEN").map(String::as_str), Some("abc"));
        assert_eq!(m.get("SHELLGATE_NET").map(String::as_str), Some("lan"));
        assert_eq!(m.get("SHELLGATE_PORT").map(String::as_str), Some("9"));
        let dir = std::env::temp_dir().join(format!("sg-cfg-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let f = dir.join("shellgate.env");
        fs::write(&f, "SHELLGATE_ZZ_ENVTEST_SECRET=zz-secret-value\n").unwrap();
        load_env_file(&f);
        assert_eq!(var("SHELLGATE_ZZ_ENVTEST_SECRET").as_deref(), Some("zz-secret-value"));
        assert!(env::var_os("SHELLGATE_ZZ_ENVTEST_SECRET").is_none(), "config value leaked into the process environment");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_keys() {
        assert_eq!(full_key("token"), "SHELLGATE_TOKEN");
        assert_eq!(full_key("net"), "SHELLGATE_NET");
        assert_eq!(full_key("SHELLGATE_PORT"), "SHELLGATE_PORT");
        assert_eq!(full_key("VENTOY_ROOT"), "VENTOY_ROOT");
    }

    #[test]
    fn placeholders_rejected() {
        assert!(looks_like_placeholder("CHANGE_ME_CHANGE_ME_CHANGE_ME_CHANGE_ME"));
        assert!(looks_like_placeholder("<your token>"));
        assert!(!looks_like_placeholder(&"t".repeat(48)));
        assert!(!looks_like_placeholder("3f9a0c1d2b4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f506"));
    }

    #[test]
    fn template_has_no_secret_but_the_given_token() {
        let t = template("TESTTOKEN");
        assert!(t.contains("token=TESTTOKEN"));
        assert!(t.contains("#tunnel_token=\n"));
    }

    #[test]
    fn winpe_dirs() {
        assert!(winpe_extra_dirs(false, vec!["X:\\Windows\\TEMP".into()]).is_empty());
        assert_eq!(winpe_extra_dirs(true, vec!["X:\\Windows\\TEMP".into()]), vec!["X:\\", "X:\\Windows\\TEMP"]);
        let d = dedup_dirs(vec!["X:\\Windows\\TEMP".into(), "x:\\windows\\temp\\".into(), "".into(), "X:\\".into()]);
        assert_eq!(d, vec!["X:\\Windows\\TEMP", "X:\\"]);
    }
}
