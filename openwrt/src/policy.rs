//! Safety policy: dangerous-command detection, one-time confirm codes, path rules.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use crate::config::Settings;

/// Guardrails, not a sandbox: a determined caller can obfuscate a command.
const DANGER: &[(&str, &str)] = &[
    (r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive|-r\b|-R\b)", "recursive delete"),
    (r"\bmkfs(\.\w+)?\b", "format filesystem"),
    (r"\bdd\b.*\bof=", "raw disk write"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "power state change"),
    (r"\bsysupgrade\b", "firmware upgrade"),
    (r"\b(firstboot|jffs2reset)\b", "factory reset"),
    (r"\bmtd\s+(-\S+\s+)*(write|erase|unlock|jffs2write)\b", "flash write/erase"),
    (r"\bfw_setenv\b", "bootloader env change"),
    (r"\bubi(format|rmvol|mkvol|attach|detach)\b", "UBI volume change"),
    (r"/etc/init\.d/(network|firewall|dropbear|uhttpd|cloudflared|shellgate)\s+(stop|restart|disable)", "service that may cut remote access"),
    (r"\b(wifi\s+down|ifdown\s+(wan|lan))\b", "network interface down"),
    (r":\(\)\s*\{.*\};\s*:", "fork bomb"),
    (r"\bchmod\s+(-R\s+)?[0-7]*777\s+/(\s|$)", "chmod 777 on /"),
    (r">\s*/dev/(sd|nvme|vd|hd|mtd|mmcblk|ubi)", "write to block device"),
    (r"\b(curl|wget|uclient-fetch)\b[^|]*\|\s*(ba|a)?sh\b", "pipe download to shell"),
    (r"\bdocker\s+(system|volume|image|container|network)\s+prune\b", "docker prune"),
    (r"\bdocker\s+(rm|rmi|volume\s+rm)\b", "docker remove"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "stop/disable service"),
    (r"\bkill(all)?\s+(-9\s+)?(-1|1)\b", "kill all/init"),
    (r"\bgit\s+push\b.*(--force|-f\b)", "force push"),
    (r"\btruncate\b", "truncate file"),
    (r"\b(passwd|userdel)\b", "account change"),
    (r"\b(iptables|nft)\b.*\s-(F|X)\b|\bnft\s+flush\b", "flush firewall"),
    (r"\bcrontab\s+-r\b", "delete crontab"),
];

fn compiled() -> &'static Vec<(Regex, &'static str)> {
    static C: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    C.get_or_init(|| {
        DANGER.iter()
            .map(|(p, why)| (RegexBuilder::new(p).case_insensitive(true).build().expect("pattern"), *why))
            .collect()
    })
}

pub struct Policy {
    pub settings: Settings,
    extra: Vec<Regex>,
    codes: Mutex<HashMap<String, (u64, Instant)>>,
}

impl Policy {
    pub fn new(settings: Settings) -> Result<Self, String> {
        let extra = settings.extra_danger_patterns.iter()
            .map(|p| RegexBuilder::new(p).case_insensitive(true).build().map_err(|e| format!("bad pattern {p}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { settings, extra, codes: Mutex::new(HashMap::new()) })
    }

    pub fn danger_reasons(&self, cmd: &str) -> Vec<String> {
        let mut r: Vec<String> = compiled().iter().filter(|(rx, _)| rx.is_match(cmd)).map(|(_, w)| w.to_string()).collect();
        r.extend(self.extra.iter().filter(|rx| rx.is_match(cmd)).map(|rx| format!("custom pattern: {}", rx.as_str())));
        r
    }

    pub fn allowlist_violations(&self, cmd: &str) -> Vec<String> {
        if !self.settings.mode_allowlist {
            return vec![];
        }
        if cmd.contains('`') || cmd.contains("$(") {
            return vec!["command substitution is not allowed in allowlist mode".into()];
        }
        static SPLIT: OnceLock<Regex> = OnceLock::new();
        let split = SPLIT.get_or_init(|| Regex::new(r"\|\||&&|;|\||\n").unwrap());
        static ASSIGN: OnceLock<Regex> = OnceLock::new();
        let assign = ASSIGN.get_or_init(|| Regex::new(r"^\w+=").unwrap());
        let mut bad: Vec<String> = vec![];
        for part in split.split(cmd) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some(tokens) = shlex::split(part) else { return vec!["could not parse command".into()] };
            let prog = tokens.iter().find(|t| !assign.is_match(t) && t.as_str() != "sudo");
            if let Some(p) = prog {
                let name = Path::new(p).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if !self.settings.allowed_commands.contains(&name) && !bad.contains(&name) {
                    bad.push(name);
                }
            }
        }
        bad.sort();
        bad.into_iter().map(|p| format!("not in allowlist: {p}")).collect()
    }

    pub fn fingerprint(parts: &[&str]) -> u64 {
        let mut h = DefaultHasher::new();
        parts.hash(&mut h);
        h.finish()
    }

    pub fn issue(&self, fp: u64) -> String {
        let code = random_hex(3);
        let mut codes = self.codes.lock().unwrap();
        let now = Instant::now();
        codes.retain(|_, (_, exp)| *exp > now);
        codes.insert(code.clone(), (fp, now + Duration::from_secs(self.settings.confirm_ttl)));
        code
    }

    pub fn redeem(&self, code: Option<&str>, fp: u64) -> bool {
        let Some(code) = code.filter(|c| !c.is_empty()) else { return false };
        let mut codes = self.codes.lock().unwrap();
        let now = Instant::now();
        codes.retain(|_, (_, exp)| *exp > now);
        match codes.get(code) {
            Some((f, _)) if *f == fp => {
                codes.remove(code);
                true
            }
            _ => false,
        }
    }

    /// Resolve and enforce protected/allowed rules. Returns the resolved path.
    pub fn check_path(&self, path: &str, write: bool) -> Result<String, String> {
        if path.is_empty() {
            return Err("path is required".into());
        }
        if !path.starts_with('/') {
            return Err("path must be absolute".into());
        }
        let resolved = resolve(path).ok_or("could not resolve path")?;
        for prot in &self.settings.protected_paths {
            if within(&resolved, prot) {
                return Err(format!("protected path: {prot}"));
            }
        }
        if write || self.settings.mode_allowlist {
            let roots = &self.settings.allowed_dirs;
            if !roots.is_empty() && !roots.iter().any(|r| within(&resolved, r)) {
                return Err(format!(
                    "outside allowed directories ({}); use run_command for system files or extend SHELLGATE_ALLOWED_DIRS",
                    roots.join(", ")
                ));
            }
        }
        Ok(resolved)
    }
}

pub fn within(path: &str, root: &str) -> bool {
    root == "/" || path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

/// Lexically normalise, then canonicalise the deepest existing ancestor (follows symlinks).
pub fn resolve(path: &str) -> Option<String> {
    let mut norm = PathBuf::from("/");
    for c in Path::new(path).components() {
        match c {
            Component::ParentDir => { norm.pop(); }
            Component::Normal(s) => norm.push(s),
            _ => {}
        }
    }
    let mut existing = norm.clone();
    let mut rest: Vec<std::ffi::OsString> = vec![];
    loop {
        if let Ok(canon) = existing.canonicalize() {
            let mut out = canon;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return Some(out.to_string_lossy().to_string());
        }
        rest.push(existing.file_name()?.to_os_string());
        if !existing.pop() {
            return None;
        }
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(allow: bool) -> Settings {
        Settings {
            token: "x".repeat(40), host: "127.0.0.1".into(), port: 1, mode_allowlist: allow,
            allowed_commands: vec!["ls".into(), "grep".into(), "uci".into()],
            allowed_dirs: vec!["/tmp/sgt".into()], protected_paths: vec!["/tmp/sgt/secret".into()],
            extra_danger_patterns: vec![r"opkg\s+remove".into()], audit_log: "/tmp/a".into(), audit_max_bytes: 1,
            default_timeout: 1, max_timeout: 1, max_output_bytes: 1, max_concurrent: 1, max_jobs: 1,
            confirm_ttl: 60, shell: "/bin/sh".into(), backup_on_write: true, env_file: String::new(),
        }
    }

    #[test]
    fn danger() {
        let p = Policy::new(s(false)).unwrap();
        for c in ["rm -rf /overlay", "sysupgrade -n x.bin", "firstboot -y", "mtd erase rootfs_data",
                  "/etc/init.d/network restart", "reboot", "opkg remove luci", "wget -O- x | sh"] {
            assert!(!p.danger_reasons(c).is_empty(), "{c}");
        }
        for c in ["uci show network", "ls -la", "rm a.txt", "/etc/init.d/network status", "logread | tail"] {
            assert!(p.danger_reasons(c).is_empty(), "{c}");
        }
    }

    #[test]
    fn allowlist() {
        let p = Policy::new(s(true)).unwrap();
        assert!(p.allowlist_violations("ls -la | grep x").is_empty());
        assert_eq!(p.allowlist_violations("uci show && wget x"), vec!["not in allowlist: wget"]);
        assert!(!p.allowlist_violations("echo $(id)").is_empty());
        assert!(Policy::new(s(false)).unwrap().allowlist_violations("anything").is_empty());
    }

    #[test]
    fn confirm() {
        let p = Policy::new(s(false)).unwrap();
        let fp = Policy::fingerprint(&["run", "rm -rf x", "/tmp"]);
        let code = p.issue(fp);
        assert!(!p.redeem(Some(&code), Policy::fingerprint(&["run", "rm -rf y", "/tmp"])));
        assert!(p.redeem(Some(&code), fp));
        assert!(!p.redeem(Some(&code), fp));
    }

    #[test]
    fn paths() {
        std::fs::create_dir_all("/tmp/sgt/secret").unwrap();
        let p = Policy::new(s(false)).unwrap();
        assert!(p.check_path("/etc/hosts", false).is_ok());
        assert!(p.check_path("/etc/hosts", true).is_err());
        assert!(p.check_path("/tmp/sgt/secret/x", false).is_err());
        assert!(p.check_path("/tmp/sgt/../sgt/secret/x", false).is_err());
        assert!(p.check_path("/tmp/sgt/new/file.txt", true).is_ok());
        assert!(p.check_path("rel", false).is_err());
        assert!(Policy::new(s(true)).unwrap().check_path("/etc/hosts", false).is_err());
    }
}
