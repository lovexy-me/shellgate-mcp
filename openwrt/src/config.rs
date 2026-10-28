//! Configuration from environment variables, optionally loaded from an env file.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::resolve;

pub const DEFAULT_ENV_FILE: &str = "/etc/shellgate/env";

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
}

fn load_env_file(path: &Path) {
    let Ok(text) = fs::read_to_string(path) else { return };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if env::var_os(k).is_none() {
                env::set_var(k, v);
            }
        }
    }
}

fn get(key: &str, default: &str) -> String {
    env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn split(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn num<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn home() -> String {
    env::var("HOME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "/root".into())
}

fn expand(p: &str) -> String {
    let p = if let Some(rest) = p.strip_prefix("~") { format!("{}{}", home(), rest) } else { p.to_string() };
    resolve(&p).unwrap_or(p)
}

pub fn load(env_file: Option<String>) -> Result<Settings, String> {
    let path = PathBuf::from(
        env_file.or_else(|| env::var("SHELLGATE_ENV_FILE").ok().filter(|v| !v.is_empty()))
            .unwrap_or_else(|| DEFAULT_ENV_FILE.into()),
    );
    load_env_file(&path);

    let token = get("SHELLGATE_TOKEN", "");
    if token.len() < 32 {
        return Err("SHELLGATE_TOKEN is missing or shorter than 32 characters. \
                    Generate one with: head -c 30 /dev/urandom | base64"
            .into());
    }
    let mode = get("SHELLGATE_MODE", "full").to_lowercase();
    if mode != "full" && mode != "allowlist" {
        return Err("SHELLGATE_MODE must be 'full' or 'allowlist'".into());
    }
    let h = home();
    let state_dir = get("SHELLGATE_STATE_DIR", "/var/log/shellgate");
    let audit_log = get("SHELLGATE_AUDIT_LOG", &format!("{state_dir}/audit.jsonl"));
    let cfg_dir = path.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let audit_dir = Path::new(&audit_log).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();

    let mut protected: Vec<String> = vec![
        cfg_dir,
        audit_dir,
        format!("{h}/.ssh"),
        format!("{h}/.cloudflared"),
        "/etc/shadow".into(),
        "/etc/dropbear".into(),
        "/etc/sudoers".into(),
        "/etc/sudoers.d".into(),
    ];
    protected.extend(split(&get("SHELLGATE_PROTECTED_PATHS", "")));

    let default_dirs = format!("/tmp,{h},/etc/config");
    Ok(Settings {
        token,
        host: get("SHELLGATE_HOST", "127.0.0.1"),
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
        shell: get("SHELLGATE_SHELL", "/bin/sh"),
        backup_on_write: matches!(get("SHELLGATE_BACKUP_ON_WRITE", "true").to_lowercase().as_str(), "1" | "true" | "yes"),
        env_file: path.to_string_lossy().to_string(),
        redact: !matches!(get("SHELLGATE_REDACT", "1").trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        redact_domains: split(&get("SHELLGATE_REDACT_DOMAINS", "")),
    })
}
