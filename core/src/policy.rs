//! Safety policy: dangerous-command detection, one-time confirm codes, path rules.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
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
    (r"\bshutil\.rmtree\b", "recursive delete (python)"),
    // ---- Windows (cmd / PowerShell); harmless to check on Linux too
    (r"\bformat(\.com)?\s+[a-z]:", "format drive (Windows)"),
    (r"\bdiskpart\b", "disk partitioning (diskpart)"),
    (r"(?m)^\s*clean(\s+all)?\s*$", "diskpart clean (wipes disk)"),
    (r"\b(del|erase)\b[^|&\n]*\s/s\b", "recursive delete (del /s)"),
    (r"\b(rd|rmdir)\b[^|&\n]*\s/s\b", "recursive delete (rd /s)"),
    (r"\b(Remove-Item|ri|rm|rmdir|rd|del|erase)\b[^|;\n]*\s-r(e(c(u(r(se?)?)?)?)?)?\b", "recursive delete (PowerShell -Recurse)"),
    (r"\bbcdedit(\.exe)?\s+/(set|delete|deletevalue|create|copy|import|default|bootsequence|displayorder|timeout|store|toolsdisplayorder|bootems|ems|debug)\b", "boot configuration change (bcdedit)"),
    (r"\b(bcdboot|bootsect)(\.exe)?\b", "boot sector / boot files change"),
    (r"\b(Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition|Set-Disk)\b", "disk/volume wipe (PowerShell)"),
    (r"\b(Stop-Computer|Restart-Computer)\b", "power state change"),
    (r"\breg(\.exe)?\s+(delete|import|restore|load|unload)\b", "registry change (reg)"),
    (r"\bRemove-ItemProperty\b|\bRemove-Item\b[^|;\n]*\bHK(LM|CU|CR|U|CC)[:\\]", "registry change (PowerShell)"),
    (r"\bcipher(\.exe)?\s+/w\b", "wipe free space (cipher /w)"),
    (r"\bvssadmin(\.exe)?\s+(delete|resize)\b|\bwmic\b.*\bshadowcopy\b.*\bdelete\b", "delete shadow copies"),
    (r"\bmanage-bde(\.exe)?\s+-(off|on|lock|forcerecovery|protectors\s+-delete)\b", "BitLocker change"),
    (r"\b(net\s+stop|sc(\.exe)?\s+(stop|delete|config)|Stop-Service|Set-Service)\b", "stop/change Windows service"),
    (r"\btaskkill\b.*\b(csrss|wininit|winlogon|lsass|smss|services|cloudflared|shellgate)\b", "kill critical / remote-access process"),
    (r"\bDisable-NetAdapter\b|\bnetsh\b.*\b(disable|reset)\b", "network change that may cut remote access"),
    (r"\bwsl(\.exe)?\s+--(shutdown|unregister)\b", "WSL shutdown/unregister"),
    (r"\\\\\.\\(PhysicalDrive|Harddisk)", "raw disk access"),
    (r"\b(takeown)(\.exe)?\b[^|&\n]*\s/r\b", "recursive ownership change"),
];

pub const INTERPRETERS: &[&str] = &["sh", "bash", "ash", "dash", "zsh", "python", "python3", "powershell", "pwsh", "cmd", "diskpart"];

fn split_re() -> &'static Regex {
    static SPLIT: OnceLock<Regex> = OnceLock::new();
    SPLIT.get_or_init(|| Regex::new(r"\|\||&&|;|\||\n").unwrap())
}

fn assign_re() -> &'static Regex {
    static ASSIGN: OnceLock<Regex> = OnceLock::new();
    ASSIGN.get_or_init(|| Regex::new(r"^\w+=").unwrap())
}

fn base_name(p: &str) -> String {
    // accept both separators so Windows-style paths work on every host
    let last = p.rsplit(['/', '\\']).next().unwrap_or(p).to_lowercase();
    last.strip_suffix(".exe").map(str::to_string).unwrap_or(last)
}

/// True when the command runs a shell/python that will read code from stdin (e.g. ssh host bash -s).
pub fn feeds_interpreter(cmd: &str) -> bool {
    cmd.split(|c: char| c.is_whitespace() || ";|&()".contains(c))
        .filter(|w| !w.is_empty())
        .any(|w| INTERPRETERS.contains(&base_name(w).as_str()))
}

/// Script file extensions a command runs directly, without naming an interpreter.
const SCRIPT_EXTS: &[&str] = &[".sh", ".cmd", ".bat", ".ps1", ".py"];

fn is_abs(p: &str) -> bool {
    p.starts_with('/') || p.starts_with('\\') || (p.len() > 2 && p.as_bytes()[1] == b':' && (p.as_bytes()[2] == b'\\' || p.as_bytes()[2] == b'/'))
}

/// Local script files a command would execute: `sh x.sh`, `bash -x ./y`, `. ./env`, `./run.sh`,
/// `"X:\tools\win-disk.cmd" layout ...`, `cmd /c fix.bat`, or a bare `win-disk.cmd` found on PATH.
pub fn referenced_scripts(cmd: &str, cwd: &str, max_bytes: u64) -> Vec<(String, String)> {
    let mut found = vec![];
    for part in split_re().split(cmd) {
        // shlex treats a backslash as an escape; Windows paths keep theirs when quoted, so protect
        // unquoted ones by doubling them first
        let Some(mut tokens) = shlex::split(&part.replace('\\', "\\\\")) else { continue };
        while !tokens.is_empty() && (assign_re().is_match(&tokens[0]) || ["sudo", "exec", "nohup", "env", "call", "start"].contains(&tokens[0].to_lowercase().as_str())) {
            tokens.remove(0);
        }
        if tokens.is_empty() {
            continue;
        }
        let mut cands: Vec<String> = vec![];
        let t0 = tokens[0].to_lowercase();
        if tokens[0].contains('/') || tokens[0].contains('\\') || SCRIPT_EXTS.iter().any(|e| t0.ends_with(e)) {
            cands.push(tokens[0].clone());
        }
        let first = base_name(&tokens[0]);
        if INTERPRETERS.contains(&first.as_str()) || tokens[0] == "source" || tokens[0] == "." {
            // cmd takes /c /k /q style switches, the others -x style ones
            if let Some(t) = tokens[1..].iter().find(|t| !t.starts_with('-') && !(first == "cmd" && t.starts_with('/'))) {
                cands.push(t.clone());
            }
        }
        for c in cands {
            let c = if let Some(rest) = c.strip_prefix('~') {
                format!("{}{}", std::env::var("HOME").unwrap_or_default(), rest)
            } else { c };
            let mut paths = vec![if is_abs(&c) { PathBuf::from(&c) } else { Path::new(cwd).join(&c) }];
            if !c.contains('/') && !c.contains('\\') {
                if let Some(path) = std::env::var_os("PATH") {
                    paths.extend(std::env::split_paths(&path).map(|d| d.join(&c)));
                }
            }
            for p in paths {
                let Ok(m) = std::fs::metadata(&p) else { continue };
                if m.is_file() && m.len() <= max_bytes {
                    if let Ok(bytes) = std::fs::read(&p) {
                        found.push((p.to_string_lossy().to_string(), String::from_utf8_lossy(&bytes).into_owned()));
                    }
                }
                break;
            }
        }
    }
    found
}

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

    /// Scan a whole script/command: the text as one piece and every (continued) line on its own.
    pub fn text_danger_reasons(&self, text: &str) -> Vec<String> {
        static CONT: OnceLock<Regex> = OnceLock::new();
        let joined = CONT.get_or_init(|| Regex::new(r"\\\r?\n").unwrap()).replace_all(text, " ").to_string();
        let mut seen: Vec<String> = vec![];
        for chunk in std::iter::once(joined.as_str()).chain(joined.lines()) {
            if chunk.trim().is_empty() {
                continue;
            }
            for why in self.danger_reasons(chunk) {
                if !seen.contains(&why) {
                    seen.push(why);
                }
            }
        }
        seen
    }

    pub fn allowlist_violations(&self, cmd: &str) -> Vec<String> {
        if !self.settings.mode_allowlist {
            return vec![];
        }
        if cmd.contains('`') || cmd.contains("$(") {
            return vec!["command substitution is not allowed in allowlist mode".into()];
        }
        let (split, assign) = (split_re(), assign_re());
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

    pub fn fingerprint<S: AsRef<str>>(parts: &[S]) -> u64 {
        let mut h = DefaultHasher::new();
        for p in parts {
            p.as_ref().hash(&mut h);
        }
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
        if !is_absolute(path) {
            return Err("path must be absolute".into());
        }
        let resolved = resolve(path).ok_or("could not resolve path")?;
        self.check_protected(&resolved)?;
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

    /// Refuse protected paths: the configured list plus any Windows registry hive directory
    /// (`.../Windows/System32/config`, which holds SAM, SYSTEM, SECURITY, SOFTWARE), also when a
    /// Windows disk is mounted under Linux.
    pub fn check_protected(&self, resolved: &str) -> Result<(), String> {
        for prot in &self.settings.protected_paths {
            if within(resolved, prot) {
                return Err(format!("protected path: {prot}"));
            }
        }
        if is_registry_hive_path(resolved) {
            return Err("protected path: Windows registry hives (Windows/System32/config)".into());
        }
        Ok(())
    }
}

/// True for anything inside a `Windows/System32/config` directory (registry hives) on any host.
pub fn is_registry_hive_path(p: &str) -> bool {
    let k = format!("{}/", p.replace('\\', "/").to_lowercase().trim_end_matches('/'));
    k.contains("/windows/system32/config/")
}

/// Absolute on this platform (`/x` on Unix, `C:\x` or `\\server\share` on Windows).
pub fn is_absolute(p: &str) -> bool {
    Path::new(p).is_absolute()
}

pub fn within(path: &str, root: &str) -> bool {
    #[cfg(unix)]
    {
        root == "/" || path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
    }
    #[cfg(windows)]
    {
        let (p, r) = (crate::platform::path_key(path), crate::platform::path_key(root));
        let r = r.trim_end_matches('\\');
        p == r || p.starts_with(&format!("{r}\\"))
    }
}

/// Lexically normalise, then canonicalise the deepest existing ancestor (follows symlinks).
pub fn resolve(path: &str) -> Option<String> {
    let mut norm = PathBuf::new();
    #[cfg(unix)]
    norm.push("/");
    for c in Path::new(path).components() {
        match c {
            Component::Prefix(p) => norm.push(p.as_os_str()),
            Component::RootDir => norm.push(std::path::MAIN_SEPARATOR_STR),
            Component::ParentDir => {
                // never climb above the root / drive
                if norm.parent().is_some() {
                    norm.pop();
                }
            }
            Component::Normal(s) => norm.push(s),
            Component::CurDir => {}
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
            return Some(crate::platform::clean_display(&out));
        }
        rest.push(existing.file_name()?.to_os_string());
        if !existing.pop() {
            return None;
        }
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        // no OS randomness: refuse to hand out predictable codes/tokens
        panic!("no OS random source available");
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
        let mut st = Settings::for_tests();
        st.mode_allowlist = allow;
        st.allowed_commands = vec!["ls".into(), "grep".into(), "uci".into()];
        st.allowed_dirs = vec!["/tmp/sgt".into()];
        st.protected_paths = vec!["/tmp/sgt/secret".into()];
        st.extra_danger_patterns = vec![r"opkg\s+remove".into()];
        st
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
    fn windows_danger() {
        let p = Policy::new(s(false)).unwrap();
        for c in ["format D: /q /y", "FORMAT.COM e: /FS:NTFS", "diskpart /s wipe.txt", "del /f /s /q C:\\Users\\x",
                  "erase /s *.tmp", "rd /s /q C:\\data", "rmdir /S C:\\x", "bcdedit /set {default} safeboot minimal",
                  "bcdedit /delete {current}", "bcdboot C:\\Windows", "Remove-Item C:\\x -Recurse -Force",
                  "ri .\\build -r", "rm -Recurse -Force C:\\tmp", "Format-Volume -DriveLetter D", "Clear-Disk -Number 1 -RemoveData",
                  "shutdown /r /t 0", "Stop-Computer -Force", "Restart-Computer", "reg delete HKLM\\Software\\X /f",
                  "reg.exe import x.reg", "Remove-ItemProperty -Path HKCU:\\X -Name Y", "cipher /w:C:",
                  "vssadmin delete shadows /all", "net stop cloudflared", "sc.exe delete shellgate", "Stop-Service sshd",
                  "taskkill /f /im cloudflared.exe", "Disable-NetAdapter -Name Ethernet", "wsl --shutdown",
                  "dd if=x of=\\\\.\\PhysicalDrive1", "manage-bde -off C:", "takeown /f C:\\x /r"] {
            assert!(!p.danger_reasons(c).is_empty(), "{c}");
        }
        // a lone `clean` line in a diskpart script fed through stdin
        assert!(!p.text_danger_reasons("select disk 1\nclean\ncreate partition primary\n").is_empty());
        for c in ["dir /s C:\\", "bcdedit /enum", "Get-Disk", "Get-ChildItem -Recurse", "Format-List", "reg query HKLM\\Software",
                  "del a.txt", "sc query", "ipconfig /all", "Get-Volume", "Get-Service", "tasklist", "make clean"] {
            assert!(p.danger_reasons(c).is_empty(), "{c}");
        }
        assert!(feeds_interpreter("powershell.exe -Command -"));
        assert!(feeds_interpreter("diskpart"));
    }

    #[test]
    fn registry_hives_protected() {
        assert!(is_registry_hive_path("C:\\Windows\\System32\\config\\SAM"));
        assert!(is_registry_hive_path("/mnt/win/Windows/System32/config/SYSTEM"));
        assert!(is_registry_hive_path("/mnt/win/WINDOWS/system32/CONFIG"));
        assert!(!is_registry_hive_path("/mnt/win/Windows/System32/drivers/etc/hosts"));
        std::fs::create_dir_all("/tmp/sgt").unwrap();
        let p = Policy::new(s(false)).unwrap();
        assert!(p.check_path("/tmp/sgt/Windows/System32/config/SAM", false).is_err());
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
    fn script_scanning() {
        let p = Policy::new(s(false)).unwrap();
        assert!(p.text_danger_reasons("#!/bin/sh\necho start\nrm -rf build\necho done\n").contains(&"recursive delete".to_string()));
        assert!(p.text_danger_reasons("echo a\nls -la\n").is_empty());
        assert!(!p.text_danger_reasons("rm \\\n  -rf /x").is_empty());
        assert!(!p.text_danger_reasons("import shutil\nshutil.rmtree('/srv')").is_empty());
        assert!(feeds_interpreter("ssh router bash -s"));
        assert!(feeds_interpreter("/usr/bin/python3 -"));
        assert!(!feeds_interpreter("cat > /tmp/notes.txt"));
        let d = format!("/tmp/sgt-ref-{}", random_hex(4));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/x.sh"), "echo hi\nreboot\n").unwrap();
        let f = referenced_scripts("sh x.sh", &d, 1_000_000);
        assert_eq!(f.len(), 1);
        assert!(f[0].1.contains("reboot"));
        assert!(!referenced_scripts("FOO=1 bash -e ./x.sh arg", &d, 1_000_000).is_empty());
        assert!(referenced_scripts("echo x.sh", &d, 1_000_000).is_empty());
        // Windows-style: a .cmd run by path or by bare name on PATH, and through cmd /c
        std::fs::write(format!("{d}/win-disk.cmd"), "@echo off\r\ndiskpart /s %TEMP%\\dp.txt\r\n").unwrap();
        assert!(!referenced_scripts(&format!("\"{d}/win-disk.cmd\" layout 0 uefi --apply"), "/", 1_000_000).is_empty());
        assert!(!referenced_scripts("win-disk.cmd layout 0", &d, 1_000_000).is_empty());
        assert!(!referenced_scripts("cmd /c win-disk.cmd layout 0", &d, 1_000_000).is_empty());
        assert!(!referenced_scripts("call win-disk.cmd boot W: S:", &d, 1_000_000).is_empty());
        std::fs::remove_dir_all(&d).unwrap();
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
