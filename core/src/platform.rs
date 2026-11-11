//! Everything that differs between Unix (OpenWrt / Linux, incl. static musl) and Windows.
//! The rest of the code calls these helpers and stays platform-neutral.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tokio::process::{Child, Command};

// ---------------------------------------------------------------- paths and home

/// Running with root / administrator rights.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::agent_win::is_elevated()
    }
}

pub fn home() -> String {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "/root".into())
    }
    #[cfg(windows)]
    {
        let prof = std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty())
            .or_else(|| std::env::var("HOME").ok().filter(|h| !h.is_empty()));
        match prof {
            // WinPE and services run as SYSTEM, whose profile lives under the (protected)
            // System32\config directory: use the public profile or the temp dir instead.
            Some(h) if !is_system_profile(&h) => h,
            _ => {
                let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
                let public = format!("{drive}\\Users\\Public");
                if Path::new(&public).is_dir() {
                    public
                } else {
                    temp_dirs().into_iter().next().unwrap_or_else(|| format!("{drive}\\"))
                }
            }
        }
    }
}

/// `true` for the LocalSystem profile (`...\System32\config\systemprofile`).
pub fn is_system_profile(p: &str) -> bool {
    p.replace('/', "\\").to_lowercase().contains("\\system32\\config\\systemprofile")
}

#[cfg_attr(unix, allow(dead_code))]
/// Temp directories worth allowing: %TEMP%, %TMP% and the process temp dir, existing ones only.
pub fn temp_dirs() -> Vec<String> {
    let mut v: Vec<String> = vec![];
    let cands = [std::env::var("TEMP").ok(), std::env::var("TMP").ok(), Some(std::env::temp_dir().to_string_lossy().to_string())];
    for c in cands.into_iter().flatten() {
        let c = c.trim_end_matches(['\\', '/']).to_string();
        if !c.is_empty() && Path::new(&c).is_dir() && !v.iter().any(|x| path_key(x) == path_key(&c)) && !is_system_profile(&c) {
            v.push(c);
        }
    }
    v
}

// ---------------------------------------------------------------- WinPE

/// Running inside Windows PE (official WinPE, Windows Setup, FirPE, HotPE, WePE, ...):
/// every WinPE has `HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`.
pub fn is_winpe() -> bool {
    #[cfg(windows)]
    {
        static PE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PE.get_or_init(|| reg_key_exists("SYSTEM\\CurrentControlSet\\Control\\MiniNT"))
    }
    #[cfg(unix)]
    {
        false
    }
}

#[cfg(windows)]
fn reg_key_exists(sub: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
    let w = wide(sub);
    let mut h: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, w.as_ptr(), 0, KEY_READ, &mut h) };
    if rc == 0 {
        unsafe { RegCloseKey(h) };
        true
    } else {
        false
    }
}

/// A REG_SZ value under HKLM, e.g. ProductName / CurrentBuild of the running Windows.
#[cfg(windows)]
pub fn reg_sz(sub: &str, name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let (ws, wn) = (wide(sub), wide(name));
    let mut buf = vec![0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, ws.as_ptr(), wn.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(),
                     buf.as_mut_ptr() as *mut _, &mut len)
    };
    if rc != 0 {
        return None;
    }
    let n = (len as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]);
    Some(s.trim_end_matches('\0').to_string())
}

/// "Windows 10 Pro 22H2 (build 19045)" from the CurrentVersion registry values (null on Linux).
#[cfg_attr(unix, allow(dead_code))]
pub fn windows_version() -> Option<String> {
    #[cfg(windows)]
    {
        const K: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        Some(format_windows_version(reg_sz(K, "ProductName"), reg_sz(K, "DisplayVersion").or_else(|| reg_sz(K, "ReleaseId")),
                                    reg_sz(K, "CurrentBuild").or_else(|| reg_sz(K, "CurrentBuildNumber"))))
    }
    #[cfg(unix)]
    {
        None
    }
}

#[cfg_attr(unix, allow(dead_code))]
fn format_windows_version(product: Option<String>, display: Option<String>, build: Option<String>) -> String {
    let mut s = product.filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "Windows".into());
    if let Some(d) = display.filter(|d| !d.trim().is_empty()) {
        s.push(' ');
        s.push_str(d.trim());
    }
    if let Some(b) = build.filter(|b| !b.trim().is_empty()) {
        s.push_str(&format!(" (build {})", b.trim()));
    }
    s
}

/// Whether Windows PowerShell can actually run here. Many WinPE builds have no PowerShell, and
/// some ship a powershell.exe that cannot start (missing .NET). Probed once with `exit 7`.
pub fn powershell_usable() -> bool {
    #[cfg(windows)]
    {
        static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *OK.get_or_init(|| {
            use std::os::windows::process::CommandExt;
            let Some(exe) = which("powershell") else { return false };
            let mut c = std::process::Command::new(exe);
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 7"])
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            let Ok(mut child) = c.spawn() else { return false };
            let t0 = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => return st.code() == Some(7),
                    Ok(None) if t0.elapsed() < std::time::Duration::from_secs(20) => std::thread::sleep(std::time::Duration::from_millis(100)),
                    _ => {
                        let _ = child.kill();
                        return false;
                    }
                }
            }
        })
    }
    #[cfg(unix)]
    {
        false
    }
}

/// Separator used in path strings we build and compare.
#[cfg(unix)]
pub const SEP: char = '/';
#[cfg(windows)]
pub const SEP: char = '\\';

/// PATH list separator.
#[cfg(unix)]
pub const PATH_LIST_SEP: char = ':';
#[cfg(windows)]
pub const PATH_LIST_SEP: char = ';';

/// Strip the `\\?\` verbatim prefix that `canonicalize` adds on Windows.
pub fn clean_display(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    #[cfg(windows)]
    {
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return rest.to_string();
        }
    }
    s
}

/// Comparison key: on Windows paths are case-insensitive and either slash works.
pub fn path_key(p: &str) -> String {
    #[cfg(windows)]
    {
        p.replace('/', "\\").to_lowercase()
    }
    #[cfg(unix)]
    {
        p.to_string()
    }
}

// ---------------------------------------------------------------- private files

/// Create a directory readable only by the service user (best effort on Windows,
/// where the per-user profile/temp ACLs already restrict access).
pub fn create_private_dir(p: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(p)
    }
    #[cfg(windows)]
    {
        fs::DirBuilder::new().create(p)
    }
}

pub fn make_dir_private(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        let _ = p;
    }
}

/// OpenOptions that create new files as 0600 on Unix.
pub fn private_opts() -> fs::OpenOptions {
    #[allow(unused_mut)]
    let mut o = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Copy the permission bits of `from` (if it exists) onto `to`; default 0644 on Unix.
pub fn copy_mode(from: &str, to: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = fs::metadata(from).map(|m| m.mode() & 0o7777).unwrap_or(0o644);
        fs::set_permissions(to, fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let _ = (from, to);
        Ok(())
    }
}

pub fn is_executable(p: &Path) -> bool {
    let Ok(m) = fs::metadata(p) else { return false };
    if !m.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        true
    }
}

/// Find a program on PATH (on Windows also tries PATHEXT extensions).
pub fn which(name: &str) -> Option<String> {
    #[cfg(unix)]
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    #[cfg(windows)]
    let path = std::env::var("PATH").unwrap_or_default();
    #[cfg(unix)]
    let exts: Vec<String> = vec![String::new()];
    #[cfg(windows)]
    let exts: Vec<String> = {
        let mut v = vec![String::new()];
        let pe = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        v.extend(pe.split(';').filter(|e| !e.is_empty()).map(|e| e.to_lowercase()));
        v
    };
    for d in path.split(PATH_LIST_SEP).filter(|d| !d.is_empty()) {
        for e in &exts {
            let p = Path::new(d).join(format!("{name}{e}"));
            if is_executable(&p) {
                return Some(p.to_string_lossy().to_string());
            }
        }
    }
    None
}

pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}

// ---------------------------------------------------------------- processes

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// A command whose whole process tree we can kill later (own process group on Unix,
/// own console process group and no window on Windows).
pub fn new_command(prog: &str) -> Command {
    let mut c = Command::new(prog);
    c.kill_on_drop(true);
    #[cfg(unix)]
    {
        c.process_group(0);
    }
    #[cfg(windows)]
    {
        c.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    c
}

/// Build the command that runs `cmd` through the configured shell.
/// Unix: `<shell> -c <cmd>`. Windows: `cmd /D /S /C "<cmd>"` (cmd line passed verbatim) or,
/// when SHELLGATE_SHELL is powershell/pwsh, `powershell -NoProfile -NonInteractive -Command <cmd>`.
pub fn shell_command(shell: &str, cmd: &str) -> Command {
    #[cfg(unix)]
    {
        let mut c = new_command(shell);
        c.arg("-c").arg(cmd);
        c
    }
    #[cfg(windows)]
    {
        let base = Path::new(shell).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
        if base == "powershell" || base == "pwsh" {
            let mut c = new_command(shell);
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]);
            c
        } else {
            let mut c = new_command(shell);
            c.raw_arg(format!("/D /S /C \"{cmd}\""));
            c
        }
    }
}

/// Default shell for run_command / start_job.
pub fn default_shell() -> String {
    #[cfg(unix)]
    {
        if cfg!(target_os = "android") { "/system/bin/sh".into() } else { "/bin/sh".into() }
    }
    #[cfg(windows)]
    {
        std::env::var("ComSpec").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "cmd.exe".into())
    }
}

/// Stop a child and everything it started. Unix: SIGTERM to the group, SIGKILL after 3 s.
/// Windows: `taskkill /T /F /PID <pid>` (whole tree), then TerminateProcess as a fallback.
pub async fn terminate(child: &mut Child) {
    let pid = child.id();
    #[cfg(unix)]
    {
        let kill_group = |sig: i32| {
            if let Some(pid) = pid {
                unsafe { libc::kill(-(pid as i32), sig) };
            }
        };
        kill_group(libc::SIGTERM);
        if tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await.is_err() {
            kill_group(libc::SIGKILL);
            let _ = child.wait().await;
        }
    }
    #[cfg(windows)]
    {
        if let Some(pid) = pid {
            let mut tk = Command::new("taskkill");
            tk.args(["/T", "/F", "/PID", &pid.to_string()])
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), tk.status()).await;
        }
        if tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await.is_err() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

/// Resolves when the service is asked to stop (SIGTERM / Ctrl+C on Unix, Ctrl+C / console close on Windows).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
    }
    #[cfg(windows)]
    {
        let mut close = tokio::signal::windows::ctrl_close().ok();
        let mut brk = tokio::signal::windows::ctrl_break().ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async { match close.as_mut() { Some(c) => { c.recv().await; } None => std::future::pending::<()>().await } } => {},
            _ = async { match brk.as_mut() { Some(b) => { b.recv().await; } None => std::future::pending::<()>().await } } => {},
        }
    }
}

// ---------------------------------------------------------------- disks

/// (total_bytes, free_bytes_for_us) of the filesystem holding `path`.
pub fn disk_space(path: &str) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(path).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        let f = st.f_frsize as u64;
        Some((st.f_blocks as u64 * f, st.f_bavail as u64 * f))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let w = wide(path);
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
        if ok == 0 {
            return None;
        }
        Some((total, avail))
    }
}

#[cfg(windows)]
pub fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// A mounted volume with its label and filesystem type, as far as we can tell.
#[derive(Clone, Debug)]
pub struct Volume {
    pub root: String,
    pub label: String,
    pub fs_type: String,
    pub device: String,
}

/// Unescape the octal escapes /proc/mounts uses for spaces etc. (`\040`).
#[cfg(unix)]
pub fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Unescape udev's `\x20`-style escapes in /dev/disk/by-label names.
#[cfg(unix)]
pub fn unescape_udev(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
            if let Ok(v) = u8::from_str_radix(&s[i + 2..i + 4], 16) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// (device, mountpoint, fstype) from /proc/mounts.
#[cfg(unix)]
pub fn mounts() -> Vec<(String, String, String)> {
    let text = fs::read_to_string("/proc/self/mounts").or_else(|_| fs::read_to_string("/proc/mounts")).unwrap_or_default();
    text.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        let (d, m, t) = (it.next()?, it.next()?, it.next()?);
        Some((unescape_mount(d), unescape_mount(m), t.to_string()))
    }).collect()
}

/// Block devices by filesystem label: (label, /dev/xxx). Linux udev only.
#[cfg(unix)]
pub fn labeled_devices() -> Vec<(String, String)> {
    let mut v = vec![];
    if let Ok(rd) = fs::read_dir("/dev/disk/by-label") {
        for e in rd.flatten() {
            let label = unescape_udev(&e.file_name().to_string_lossy());
            if let Ok(dev) = fs::canonicalize(e.path()) {
                v.push((label, dev.to_string_lossy().to_string()));
            }
        }
    }
    v
}

/// Every mounted volume we can see, with labels where known.
pub fn volumes() -> Vec<Volume> {
    #[cfg(unix)]
    {
        let labels = labeled_devices();
        mounts().into_iter().filter(|(d, _, _)| d.starts_with("/dev/")).map(|(dev, mnt, t)| {
            let real = fs::canonicalize(&dev).map(|p| p.to_string_lossy().to_string()).unwrap_or(dev.clone());
            let label = labels.iter().find(|(_, d)| *d == real).map(|(l, _)| l.clone()).unwrap_or_default();
            Volume { root: mnt, label, fs_type: t, device: real }
        }).collect()
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetLogicalDrives, GetVolumeInformationW};
        let mask = unsafe { GetLogicalDrives() };
        let mut out = vec![];
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let root = format!("{}:\\", (b'A' + i as u8) as char);
            let w = wide(&root);
            let mut name = [0u16; 261];
            let mut fsn = [0u16; 261];
            let (mut serial, mut maxlen, mut flags) = (0u32, 0u32, 0u32);
            let ok = unsafe {
                GetVolumeInformationW(w.as_ptr(), name.as_mut_ptr(), name.len() as u32, &mut serial, &mut maxlen,
                                      &mut flags, fsn.as_mut_ptr(), fsn.len() as u32)
            };
            if ok == 0 {
                continue; // empty card reader, CD drive without media, ...
            }
            let s = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
            out.push(Volume { label: s(&name), fs_type: s(&fsn), device: root.trim_end_matches('\\').to_string(), root });
        }
        out
    }
}

// ---------------------------------------------------------------- system info

/// Windows-only pieces of system_info: memory (MB), uptime (s), hostname.
#[cfg(windows)]
pub fn win_sysinfo() -> (u64, u64, u64, String) {
    use windows_sys::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut ms: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let (total, avail) = if unsafe { GlobalMemoryStatusEx(&mut ms) } != 0 {
        (ms.ullTotalPhys / 1048576, ms.ullAvailPhys / 1048576)
    } else {
        (0, 0)
    };
    let up = unsafe { GetTickCount64() } / 1000;
    (total, avail, up, std::env::var("COMPUTERNAME").unwrap_or_default())
}

/// Windows: when started by double-click the console window closes as soon as we exit, so keep
/// it open on a fatal error until the user presses Enter. No-op elsewhere or inside a terminal.
pub fn pause_if_double_clicked() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::GetConsoleProcessList;
        let mut ids = [0u32; 4];
        let n = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
        if n == 1 {
            eprintln!("\nPress Enter to close this window / 按回车键关闭窗口");
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
        }
    }
}

/// Encode text in the console (OEM) code page, as cmd.exe reads .cmd files. `None` when some
/// character has no exact representation there (the caller then falls back to UTF-8 + chcp 65001).
#[cfg(windows)]
pub fn encode_oem(s: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::Globalization::{GetOEMCP, WideCharToMultiByte, WC_NO_BEST_FIT_CHARS};
    if s.is_ascii() {
        return Some(s.as_bytes().to_vec());
    }
    let w: Vec<u16> = s.encode_utf16().collect();
    if w.len() >= i32::MAX as usize / 4 {
        return None;
    }
    unsafe {
        let cp = GetOEMCP();
        if cp == 65001 {
            return Some(s.as_bytes().to_vec());
        }
        let mut used = 0i32;
        let n = WideCharToMultiByte(cp, WC_NO_BEST_FIT_CHARS, w.as_ptr(), w.len() as i32, std::ptr::null_mut(), 0,
                                    std::ptr::null(), &mut used);
        if n <= 0 || used != 0 {
            return None;
        }
        let mut out = vec![0u8; n as usize];
        let m = WideCharToMultiByte(cp, WC_NO_BEST_FIT_CHARS, w.as_ptr(), w.len() as i32, out.as_mut_ptr(), n,
                                    std::ptr::null(), &mut used);
        if m <= 0 || used != 0 {
            return None;
        }
        out.truncate(m as usize);
        Some(out)
    }
}

/// Marker `exec` puts between the kept head and tail of over-long output.
pub const TRUNC_MARKER: &[u8] = b"\n...[output truncated]...\n";

/// Validate `seg` as UTF-8, tolerating a multi-byte character cut off at its edges: up to 3
/// stray continuation bytes at the start (only when `ragged_start`) and an unfinished
/// sequence at the end. The cut-off bytes become U+FFFD. `None` when the bytes are not UTF-8.
fn utf8_ragged(seg: &[u8], ragged_start: bool) -> Option<String> {
    let mut out = String::with_capacity(seg.len());
    let mut b = seg;
    if ragged_start {
        let lead = b.iter().take(3).take_while(|&&c| c & 0xC0 == 0x80).count();
        if lead > 0 {
            out.push('\u{FFFD}');
            b = &b[lead..];
        }
    }
    match std::str::from_utf8(b) {
        Ok(s) => out.push_str(s),
        // error_len() == None: the only problem is an unfinished sequence at the very end
        Err(e) if e.error_len().is_none() => {
            out.push_str(std::str::from_utf8(&b[..e.valid_up_to()]).ok()?);
            out.push('\u{FFFD}');
        }
        Err(_) => return None,
    }
    Some(out)
}

/// UTF-8 decode of (possibly truncated) output: each piece between truncation markers may
/// have a character cut at its edges, but must otherwise be valid UTF-8.
fn utf8_pieces(b: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(b.len());
    let mut rest = b;
    let mut first = true;
    loop {
        let at = rest.windows(TRUNC_MARKER.len()).position(|w| w == TRUNC_MARKER);
        let piece = &rest[..at.unwrap_or(rest.len())];
        out.push_str(&utf8_ragged(piece, !first)?);
        match at {
            Some(i) => {
                out.push_str(std::str::from_utf8(TRUNC_MARKER).unwrap());
                rest = &rest[i + TRUNC_MARKER.len()..];
                first = false;
            }
            None => return Some(out),
        }
    }
}

/// Decode child-process output. Windows console tools (cmd, ping, PowerShell 5.1) write in the
/// OEM code page (936/GBK on Chinese systems), not UTF-8. UTF-8 is tried first (a character cut
/// by head/tail truncation or a killed process does not count against it); only bytes that are
/// really not UTF-8 are decoded with the OEM code page.
pub fn decode_output(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    if let Some(s) = utf8_pieces(b) {
        return s;
    }
    #[cfg(windows)]
    {
        decode_mixed(b, oem_decode)
    }
    #[cfg(not(windows))]
    {
        String::from_utf8_lossy(b).into_owned()
    }
}

/// Mixed output (e.g. `ipconfig` in GBK followed by a tool that writes UTF-8, or a UTF-8 script
/// echoed by cmd): decode line by line, UTF-8 where a line is valid UTF-8, else the OEM code page.
#[cfg_attr(not(windows), allow(dead_code))]
fn decode_mixed(b: &[u8], oem: impl Fn(&[u8]) -> String) -> String {
    let mut out = String::with_capacity(b.len() + b.len() / 2);
    for line in b.split_inclusive(|&c| c == b'\n') {
        match std::str::from_utf8(line) {
            // Output already mixes in OEM text, so a line whose only non-ASCII is two-byte
            // sequences is far more likely GBK that happens to parse as UTF-8 (写 = D0 B4 = "д")
            // than Cyrillic/Latin-1 UTF-8; CJK UTF-8 always has three-byte sequences.
            Ok(s) if line.is_ascii() || line.iter().any(|&c| c >= 0xE0) => out.push_str(s),
            _ => out.push_str(&oem(line)),
        }
    }
    out
}

#[cfg(windows)]
fn oem_decode(b: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
    if !b.is_empty() && b.len() < i32::MAX as usize {
        unsafe {
            let cp = GetOEMCP();
            let n = MultiByteToWideChar(cp, 0, b.as_ptr(), b.len() as i32, std::ptr::null_mut(), 0);
            if n > 0 {
                let mut w = vec![0u16; n as usize];
                let m = MultiByteToWideChar(cp, 0, b.as_ptr(), b.len() as i32, w.as_mut_ptr(), n);
                if m > 0 {
                    return String::from_utf16_lossy(&w[..m as usize]);
                }
            }
        }
    }
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_mixed_gbk_line_that_parses_as_utf8() {
        // "写" in GBK is D0 B4, valid UTF-8 for Cyrillic "д"; "中" in GBK is D6 D0 (not UTF-8)
        let b = [0xD6, 0xD0, b'\n', b'+', b' ', 0xD0, 0xB4, b' ', b'x', b'\n', 0xE4, 0xB8, 0xAD, b'\n', b'o', b'k', b'\n'];
        let oem = |l: &[u8]| l.iter().map(|&c| if c >= 0x80 { '#' } else { c as char }).collect::<String>();
        assert_eq!(decode_mixed(&b, oem), "##\n+ ## x\n中\nok\n");
    }

    #[test]
    fn decode_plain_utf8() {
        assert_eq!(decode_output("ping 正常 ok\n".as_bytes()), "ping 正常 ok\n");
        assert_eq!(decode_output(b""), "");
    }

    #[test]
    fn decode_truncated_utf8_cut_chars_stays_utf8() {
        // "中" = E4 B8 AD, "文" = E6 96 87; head ends mid-"中", tail starts mid-"文"
        let mut b = b"abc".to_vec();
        b.extend_from_slice(&"中".as_bytes()[..2]); // E4 B8: unfinished
        b.extend_from_slice(TRUNC_MARKER);
        b.extend_from_slice(&"文字".as_bytes()[2..]); // 87 + "字"
        let s = decode_output(&b);
        assert!(s.starts_with("abc\u{FFFD}"), "{s:?}");
        assert!(s.ends_with("...[output truncated]...\n\u{FFFD}字"), "{s:?}");
        assert_eq!(s.matches('\u{FFFD}').count(), 2, "{s:?}");
    }

    #[test]
    fn decode_head_cut_before_marker() {
        let mut b = "日志：".as_bytes().to_vec();
        b.extend_from_slice(&"错误".as_bytes()[..1]);
        b.extend_from_slice(TRUNC_MARKER);
        b.extend_from_slice("完成\r\n".as_bytes());
        assert_eq!(decode_output(&b), "日志：\u{FFFD}\n...[output truncated]...\n完成\r\n");
    }

    #[test]
    fn decode_killed_mid_char_at_end() {
        let mut b = "进度 50%".as_bytes().to_vec();
        b.extend_from_slice(&"完".as_bytes()[..2]);
        assert_eq!(decode_output(&b), "进度 50%\u{FFFD}");
    }

    #[test]
    fn decode_invalid_in_middle_is_not_utf8() {
        // GBK "中文" = D6 D0 CE C4: not UTF-8 anywhere, so the ragged-edge path must refuse it
        let gbk = [b'o', b'k', b' ', 0xD6, 0xD0, 0xCE, 0xC4, b'\r', b'\n'];
        assert!(utf8_pieces(&gbk).is_none());
        let mut b = "head".as_bytes().to_vec();
        b.extend_from_slice(TRUNC_MARKER);
        b.extend_from_slice(&gbk);
        assert!(utf8_pieces(&b).is_none());
        // the first piece may not start with stray continuation bytes
        assert!(utf8_pieces(&[0x87, b'a']).is_none());
        #[cfg(not(windows))]
        assert_eq!(decode_output(&gbk), String::from_utf8_lossy(&gbk));
    }

    #[test]
    fn decode_mixed_lines() {
        // GBK line from ipconfig, then a UTF-8 line from another tool: each line keeps its own encoding
        let fake_oem = |l: &[u8]| format!("<oem:{}>", l.len());
        let mut b = vec![0xD6, 0xD0, 0xCE, 0xC4, b'\r', b'\n'];
        b.extend_from_slice("找不到命令\r\n".as_bytes());
        b.extend_from_slice(b"ok");
        assert_eq!(decode_mixed(&b, fake_oem), "<oem:6>找不到命令\r\nok");
        assert_eq!(decode_mixed(b"", fake_oem), "");
    }

    #[test]
    fn windows_version_text() {
        assert_eq!(format_windows_version(Some("Windows 10 Pro".into()), Some("22H2".into()), Some("19045".into())),
                   "Windows 10 Pro 22H2 (build 19045)");
        assert_eq!(format_windows_version(None, None, Some("26100".into())), "Windows (build 26100)");
        assert_eq!(format_windows_version(Some(" ".into()), Some("".into()), None), "Windows");
    }

    #[test]
    fn system_profile_detected() {
        assert!(is_system_profile("X:\\Windows\\System32\\config\\systemprofile"));
        assert!(is_system_profile("C:\\WINDOWS\\system32\\config\\systemprofile\\"));
        assert!(!is_system_profile("C:\\Users\\Bob"));
    }

    #[test]
    fn decode_more_than_three_stray_bytes_rejected() {
        let mut b = b"a".to_vec();
        b.extend_from_slice(TRUNC_MARKER);
        b.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, b'x']);
        assert!(utf8_pieces(&b).is_none());
    }
}
