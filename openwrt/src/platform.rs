//! Everything that differs between Unix (OpenWrt / Linux, incl. static musl) and Windows.
//! The rest of the code calls these helpers and stays platform-neutral.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tokio::process::{Child, Command};

// ---------------------------------------------------------------- paths and home

pub fn home() -> String {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().filter(|h| !h.is_empty()).unwrap_or_else(|| "/root".into())
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty())
            .or_else(|| std::env::var("HOME").ok().filter(|h| !h.is_empty()))
            .unwrap_or_else(|| "C:\\".into())
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
        "/bin/sh".into()
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
