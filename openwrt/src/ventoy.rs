//! Ventoy stick management: find the data partition, list / download / remove images,
//! read and write `ventoy/ventoy.json`. Nothing here goes through a shell.

use std::fs;
#[cfg(feature = "download")]
use std::io::Read;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
#[cfg(feature = "download")]
use sha2::{Digest, Sha256};

use crate::platform;

pub const LABEL: &str = "Ventoy";
pub const EFI_LABEL: &str = "VTOYEFI";
pub const IMAGE_EXTS: &[&str] = &["iso", "wim", "img", "vhd", "vhdx", "efi", "vtoy"];
pub const CONFIG_REL: &str = "ventoy/ventoy.json";
const PARTIAL_EXT: &str = "sgdownload";
#[cfg_attr(not(feature = "download"), allow(dead_code))]
const FAT32_MAX: u64 = 4 * 1024 * 1024 * 1024 - 1;

#[derive(Clone, Debug)]
pub struct Root {
    pub path: String,
    pub source: String,
    pub device: String,
    pub fs_type: String,
}

fn fs_type_of(path: &str) -> (String, String) {
    let key = platform::path_key(path);
    let mut best: Option<platform::Volume> = None;
    for v in platform::volumes() {
        let r = platform::path_key(&v.root);
        if crate::policy::within(&key, &r) && best.as_ref().map(|b| b.root.len() < v.root.len()).unwrap_or(true) {
            best = Some(v);
        }
    }
    best.map(|v| (v.fs_type, v.device)).unwrap_or_default()
}

/// Find the Ventoy data partition. `configured` (SHELLGATE_VENTOY_ROOT / VENTOY_ROOT) wins;
/// otherwise the mounted volume labelled "Ventoy" (Linux: /dev/disk/by-label, Windows: drive label).
pub fn find_root(configured: &str) -> Result<Root, String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let p = Path::new(configured);
        if !p.is_dir() {
            return Err(format!("configured Ventoy root does not exist or is not a directory: {configured}"));
        }
        let path = crate::policy::resolve(configured).unwrap_or_else(|| configured.to_string());
        let (fs_type, device) = fs_type_of(&path);
        return Ok(Root { path, source: "config".into(), device, fs_type });
    }
    let vols = platform::volumes();
    if let Some(v) = vols.iter().find(|v| v.label.eq_ignore_ascii_case(LABEL)) {
        return Ok(Root { path: v.root.clone(), source: "label".into(), device: v.device.clone(), fs_type: v.fs_type.clone() });
    }
    #[cfg(unix)]
    {
        // labelled but not mounted?
        if let Some((_, dev)) = platform::labeled_devices().into_iter().find(|(l, _)| l.eq_ignore_ascii_case(LABEL)) {
            return Err(format!("Ventoy partition {dev} is not mounted; call ventoy_info with mount=true \
                                (mounts it at /mnt/ventoy) or set ventoy_root in the config"));
        }
    }
    Err("no Ventoy partition found (no mounted volume labelled \"Ventoy\"); plug in the stick or set ventoy_root in the config".into())
}

/// Linux: mount the labelled partition at /mnt/ventoy (no shell; uses `mount`).
#[cfg(unix)]
pub fn mount_args() -> Option<(String, Vec<String>)> {
    let (_, dev) = platform::labeled_devices().into_iter().find(|(l, _)| l.eq_ignore_ascii_case(LABEL))?;
    Some((dev, vec!["/mnt/ventoy".into()]))
}

/// Ventoy version from the VTOYEFI partition's grub.cfg, when that partition is reachable.
pub fn version(root: &Root) -> Option<String> {
    let mut cands: Vec<PathBuf> = vec![];
    for v in platform::volumes() {
        if v.label.eq_ignore_ascii_case(EFI_LABEL) {
            cands.push(Path::new(&v.root).join("grub").join("grub.cfg"));
        }
    }
    // some setups copy ventoy_version next to ventoy.json
    cands.push(Path::new(&root.path).join("ventoy").join("ventoy_version"));
    for c in cands {
        let Ok(text) = fs::read_to_string(&c) else { continue };
        for line in text.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("set VENTOY_VERSION=") {
                return Some(rest.trim_matches(['"', '\'']).to_string());
            }
            if c.file_name().map(|n| n == "ventoy_version").unwrap_or(false) && !l.is_empty() {
                return Some(l.to_string());
            }
        }
    }
    None
}

pub fn info(root: &Root) -> Value {
    let (total, free) = platform::disk_space(&root.path).unwrap_or((0, 0));
    let cfg = Path::new(&root.path).join(CONFIG_REL);
    json!({
        "status": "ok",
        "root": root.path,
        "found_by": root.source,
        "device": root.device,
        "filesystem": root.fs_type,
        "total_bytes": total,
        "free_bytes": free,
        "total_gb": gb(total),
        "free_gb": gb(free),
        "ventoy_version": version(root),
        "ventoy_json": platform::clean_display(&cfg),
        "ventoy_json_exists": cfg.is_file(),
        "fat32_4gb_limit": is_fat32(&root.fs_type),
    })
}

fn gb(b: u64) -> f64 {
    (b as f64 / 1e9 * 100.0).round() / 100.0
}

fn is_fat32(fs_type: &str) -> bool {
    matches!(fs_type.to_lowercase().as_str(), "vfat" | "fat32" | "fat" | "msdos")
}

pub fn is_image(name: &str) -> bool {
    Path::new(name).extension().map(|e| IMAGE_EXTS.contains(&e.to_string_lossy().to_lowercase().as_str())).unwrap_or(false)
}

/// A path relative to the Ventoy root: no absolute paths, no `..`, no drive prefixes.
pub fn safe_rel(rel: &str) -> Result<PathBuf, String> {
    let rel = rel.trim().trim_start_matches(['/', '\\']);
    if rel.is_empty() {
        return Ok(PathBuf::new());
    }
    let mut out = PathBuf::new();
    for part in rel.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return Err(format!("path must stay inside the Ventoy partition: {rel}"));
        }
        out.push(part);
    }
    if out.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("bad relative path: {rel}"));
    }
    Ok(out)
}

fn mtime(m: &fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
}

fn rel_display(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).map(|r| r.to_string_lossy().replace('\\', "/")).unwrap_or_else(|_| p.to_string_lossy().to_string())
}

/// Every image file under the root (depth-limited), skipping protected paths and system folders.
pub fn list(root: &Root, protected: &dyn Fn(&str) -> bool) -> Value {
    let base = PathBuf::from(&root.path);
    let mut items: Vec<Value> = vec![];
    let mut partial: Vec<Value> = vec![];
    let mut stack = vec![(base.clone(), 0usize)];
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut total: u64 = 0;
    while let Some((dir, depth)) = stack.pop() {
        if Instant::now() > deadline || items.len() >= 5000 {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let ps = p.to_string_lossy().to_string();
            if protected(&ps) {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(m) = fs::symlink_metadata(&p) else { continue };
            if m.is_dir() {
                let low = name.to_lowercase();
                if depth < 8 && low != "system volume information" && low != "$recycle.bin" && !low.starts_with('.') {
                    stack.push((p, depth + 1));
                }
                continue;
            }
            if !m.is_file() {
                continue;
            }
            if name.ends_with(&format!(".{PARTIAL_EXT}")) {
                partial.push(json!({"path": rel_display(&base, &p), "size_bytes": m.len()}));
                continue;
            }
            if !is_image(&name) {
                continue;
            }
            total += m.len();
            items.push(json!({
                "path": rel_display(&base, &p),
                "type": Path::new(&name).extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default(),
                "size_bytes": m.len(),
                "size_gb": gb(m.len()),
                "modified_unix": mtime(&m),
                "modified": rfc3339(mtime(&m)),
            }));
        }
    }
    items.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let (cap, free) = platform::disk_space(&root.path).unwrap_or((0, 0));
    json!({"status": "ok", "root": root.path, "count": items.len(), "images": items, "images_total_gb": gb(total),
           "free_gb": gb(free), "total_gb": gb(cap), "incomplete_downloads": partial})
}

fn rfc3339(secs: u64) -> String {
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Resolve an image path given relative to the root; must exist, be a file and an image type.
pub fn image_path(root: &Root, rel: &str) -> Result<PathBuf, String> {
    let r = safe_rel(rel)?;
    if r.as_os_str().is_empty() {
        return Err("path is required (relative to the Ventoy partition, e.g. iso/ubuntu.iso)".into());
    }
    let p = Path::new(&root.path).join(&r);
    let m = fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", r.display()))?;
    if !m.is_file() {
        return Err(format!("not a regular file: {}", r.display()));
    }
    if !is_image(&p.to_string_lossy()) {
        return Err(format!("not an image file ({}): {}", IMAGE_EXTS.join(", "), r.display()));
    }
    Ok(p)
}

// ---------------------------------------------------------------- ventoy.json

pub fn config_path(root: &Root) -> PathBuf {
    Path::new(&root.path).join("ventoy").join("ventoy.json")
}

pub fn config_get(root: &Root) -> Result<Value, String> {
    let p = config_path(root);
    if !p.is_file() {
        return Ok(json!({"status": "ok", "path": platform::clean_display(&p), "exists": false, "content": null}));
    }
    let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let parsed: Result<Value, _> = serde_json::from_str(text.trim_start_matches('\u{feff}'));
    Ok(json!({
        "status": "ok", "path": platform::clean_display(&p), "exists": true, "text": text,
        "valid_json": parsed.is_ok(),
        "json": parsed.as_ref().ok(),
        "parse_error": parsed.as_ref().err().map(|e| e.to_string()),
    }))
}

/// Validate, back up the old file as `ventoy.json.bak-<UTC timestamp>`, then write atomically.
pub fn config_set(root: &Root, content: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(content).map_err(|e| format!("not valid JSON, nothing written: {e}"))?;
    if !v.is_object() {
        return Err("ventoy.json must be a JSON object at the top level; nothing written".into());
    }
    let p = config_path(root);
    let dir = p.parent().ok_or("bad path")?;
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut backup = None;
    if p.is_file() {
        let ts = crate::audit::now_rfc3339().replace([':', '-'], "");
        let mut bak = dir.join(format!("ventoy.json.bak-{ts}"));
        let mut i = 1;
        while bak.exists() {
            bak = dir.join(format!("ventoy.json.bak-{ts}-{i}"));
            i += 1;
        }
        fs::copy(&p, &bak).map_err(|e| format!("backup failed, nothing written: {e}"))?;
        backup = Some(platform::clean_display(&bak));
    }
    let tmp = dir.join(format!(".ventoy.json.{}.sgtmp", crate::policy::random_hex(4)));
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &p)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("write failed: {e}"));
    }
    Ok(json!({"status": "ok", "path": platform::clean_display(&p), "bytes": content.len(), "backup": backup}))
}

// ---------------------------------------------------------------- downloads

pub struct Download {
    pub id: String,
    pub url: String,
    pub dest: PathBuf,
    pub started_at: Instant,
    pub started_unix: u64,
    pub bytes: AtomicU64,
    pub total: AtomicU64,
    pub cancel: AtomicBool,
    pub state: Mutex<(String, Option<String>, Option<String>)>, // (status, error, sha256)
    pub finished_at: Mutex<Option<Instant>>,
}

impl Download {
    pub fn summary(&self, root: &str) -> Value {
        let (status, error, sha) = self.state.lock().unwrap().clone();
        let bytes = self.bytes.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let end = self.finished_at.lock().unwrap().unwrap_or_else(Instant::now);
        let secs = (end - self.started_at).as_secs_f64().max(0.001);
        json!({
            "task_id": self.id,
            "url": self.url,
            "path": rel_display(Path::new(root), &self.dest),
            "status": status,
            "error": error,
            "sha256": sha,
            "bytes": bytes,
            "total_bytes": if total > 0 { Some(total) } else { None },
            "percent": if total > 0 { Some(((bytes as f64 / total as f64) * 1000.0).round() / 10.0) } else { None },
            "mb_per_s": ((bytes as f64 / 1e6 / secs) * 10.0).round() / 10.0,
            "runtime_s": secs.round(),
            "started_unix": self.started_unix,
        })
    }
    pub fn running(&self) -> bool {
        self.state.lock().unwrap().0 == "running"
    }
    fn finish(&self, status: &str, error: Option<String>, sha: Option<String>) {
        *self.state.lock().unwrap() = (status.into(), error, sha);
        *self.finished_at.lock().unwrap() = Some(Instant::now());
    }
}

/// File name for a download: the given one, else the last URL path segment.
pub fn download_name(url: &str, name: Option<&str>) -> Result<String, String> {
    let n = match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => {
            let no_q = url.split(['?', '#']).next().unwrap_or(url);
            let seg = no_q.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            percent_decode(seg)
        }
    };
    if n.is_empty() || n.contains(['/', '\\', ':', '\0']) || n == "." || n == ".." || n.starts_with('.') {
        return Err(format!("bad file name {n:?}; pass `filename` explicitly"));
    }
    if !is_image(&n) {
        return Err(format!("file name {n:?} is not an image type ({}); pass `filename` explicitly", IMAGE_EXTS.join(", ")));
    }
    Ok(n)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn new_download(id: String, url: String, dest: PathBuf) -> Arc<Download> {
    Arc::new(Download {
        id, url, dest, started_at: Instant::now(),
        started_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        bytes: AtomicU64::new(0), total: AtomicU64::new(0), cancel: AtomicBool::new(false),
        state: Mutex::new(("running".into(), None, None)), finished_at: Mutex::new(None),
    })
}

/// Blocking download into `<dest>.sgdownload`, hashed on the fly; renamed into place only when
/// complete and (if given) the sha256 matches. Any failure removes the partial file.
#[cfg(not(feature = "download"))]
pub fn run_download(d: &Download, _expected_sha: Option<String>, _fs_type: &str, _free: u64) {
    d.finish("failed", Some("this build has no download support (built without the `download` feature)".into()), None);
}

#[cfg(feature = "download")]
pub fn run_download(d: &Download, expected_sha: Option<String>, fs_type: &str, free: u64) {
    let tmp = PathBuf::from(format!("{}.{PARTIAL_EXT}", d.dest.display()));
    let result = (|| -> Result<String, String> {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .redirects(10)
            .try_proxy_from_env(true)
            .user_agent(concat!("shellgate/", env!("CARGO_PKG_VERSION")))
            .build();
        let resp = agent.get(&d.url).call().map_err(|e| format!("request failed: {e}"))?;
        let len: u64 = resp.header("Content-Length").and_then(|v| v.parse().ok()).unwrap_or(0);
        d.total.store(len, Ordering::Relaxed);
        if len > 0 {
            if len > FAT32_MAX && is_fat32(fs_type) {
                return Err(format!("file is {} bytes but the Ventoy partition is FAT32 (max 4 GiB per file)", len));
            }
            if free > 0 && len + 64 * 1024 * 1024 > free {
                return Err(format!("not enough free space: need {} MB, have {} MB", len / 1_000_000, free / 1_000_000));
            }
        }
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        let mut reader = resp.into_reader();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut n_total: u64 = 0;
        loop {
            if d.cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let n = reader.read(&mut buf).map_err(|e| format!("download interrupted: {e}"))?;
            if n == 0 {
                break;
            }
            if is_fat32(fs_type) && n_total + n as u64 > FAT32_MAX {
                return Err("file exceeds 4 GiB, which FAT32 cannot store".into());
            }
            f.write_all(&buf[..n]).map_err(|e| format!("write failed: {e}"))?;
            hasher.update(&buf[..n]);
            n_total += n as u64;
            d.bytes.store(n_total, Ordering::Relaxed);
        }
        if len > 0 && n_total != len {
            return Err(format!("incomplete download: got {n_total} of {len} bytes"));
        }
        f.sync_all().map_err(|e| format!("sync failed: {e}"))?;
        drop(f);
        let got: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if let Some(exp) = expected_sha {
            if !got.eq_ignore_ascii_case(&exp) {
                return Err(format!("sha256 mismatch: expected {exp}, got {got}; file deleted"));
            }
        }
        if d.dest.exists() {
            return Err("destination appeared while downloading; not overwritten".into());
        }
        fs::rename(&tmp, &d.dest).map_err(|e| format!("rename failed: {e}"))?;
        Ok(got)
    })();
    match result {
        Ok(sha) => d.finish("done", None, Some(sha)),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            let status = if e == "cancelled" { "cancelled" } else { "failed" };
            d.finish(status, Some(e), None);
        }
    }
}

pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths() {
        assert_eq!(safe_rel("iso/ubuntu.iso").unwrap(), PathBuf::from("iso").join("ubuntu.iso"));
        assert_eq!(safe_rel("/iso\\win.iso").unwrap(), PathBuf::from("iso").join("win.iso"));
        assert!(safe_rel("../etc/passwd").is_err());
        assert!(safe_rel("iso/../../x.iso").is_err());
        assert!(safe_rel("C:\\x.iso").is_err());
        assert_eq!(safe_rel("").unwrap(), PathBuf::new());
    }

    #[test]
    fn names() {
        assert_eq!(download_name("https://x.org/a/ubuntu-24.04.iso?x=1", None).unwrap(), "ubuntu-24.04.iso");
        assert_eq!(download_name("https://x.org/a/My%20Disk.img", None).unwrap(), "My Disk.img");
        assert!(download_name("https://x.org/a/setup.exe", None).is_err());
        assert!(download_name("https://x.org/download", None).is_err());
        assert_eq!(download_name("https://x.org/download", Some("w.iso")).unwrap(), "w.iso");
        assert!(download_name("https://x.org/a.iso", Some("../a.iso")).is_err());
        assert!(is_image("A.VHDX") && is_image("x.vtoy") && !is_image("x.txt"));
        assert!(valid_sha256(&"a".repeat(64)) && !valid_sha256("abc"));
    }

    #[test]
    fn config_roundtrip_and_backup() {
        let d = std::env::temp_dir().join(format!("sg-vt-{}", crate::policy::random_hex(4)));
        fs::create_dir_all(&d).unwrap();
        let root = Root { path: d.to_string_lossy().to_string(), source: "test".into(), device: String::new(), fs_type: String::new() };
        assert_eq!(config_get(&root).unwrap()["exists"], false);
        assert!(config_set(&root, "{not json").is_err());
        assert!(config_set(&root, "[1,2]").is_err());
        let r1 = config_set(&root, "{\"control\":[]}").unwrap();
        assert!(r1["backup"].is_null());
        let r2 = config_set(&root, "{\"control\":[{\"VTOY_DEFAULT_MENU_MODE\":\"1\"}]}").unwrap();
        let bak = r2["backup"].as_str().unwrap();
        assert_eq!(fs::read_to_string(bak).unwrap(), "{\"control\":[]}");
        let g = config_get(&root).unwrap();
        assert_eq!(g["valid_json"], true);
        assert_eq!(g["json"]["control"][0]["VTOY_DEFAULT_MENU_MODE"], "1");
        fs::create_dir_all(d.join("iso")).unwrap();
        fs::write(d.join("iso").join("a.iso"), b"1234").unwrap();
        fs::write(d.join("b.txt"), b"x").unwrap();
        fs::write(d.join("c.img.sgdownload"), b"xx").unwrap();
        let l = list(&root, &|_| false);
        assert_eq!(l["count"], 1);
        assert_eq!(l["images"][0]["path"], "iso/a.iso");
        assert_eq!(l["incomplete_downloads"].as_array().unwrap().len(), 1);
        assert!(image_path(&root, "iso/a.iso").is_ok());
        assert!(image_path(&root, "b.txt").is_err());
        assert!(image_path(&root, "../x.iso").is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
