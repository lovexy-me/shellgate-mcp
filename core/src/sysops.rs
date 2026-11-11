//! System maintenance, OpenWrt firmware flashing and Linux reinstall (Unix only).
//!
//! The work is done by small POSIX sh scripts (busybox ash on OpenWrt), so the same code covers
//! Debian/Ubuntu (apt), Fedora/RHEL (dnf/yum), Arch (pacman), openSUSE (zypper), Alpine (apk)
//! and OpenWrt (opkg, or apk on 25.x). The tools return the script's JSON-ish key=value report.
use serde_json::{json, Value};

/// Shell prefix that makes a command run as root, or an error when that is not possible.
pub fn root_prefix(sudo_allow: &[String]) -> Result<&'static str, String> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return Ok("");
        }
    }
    if sudo_allow.iter().any(|x| x == "*") {
        return Ok("sudo -n ");
    }
    Err("this needs root: run ShellGate as root, or allow sudo with SHELLGATE_SUDO_ALLOW=* (and a NOPASSWD sudoers rule)".into())
}

/// Common header of every script: package manager and OpenWrt detection.
const HEAD: &str = r#"
set -u
R="${SG_ROOT:-}"
PM=none
for p in opkg apk apt-get dnf yum pacman zypper; do command -v $p >/dev/null 2>&1 && { PM=$p; break; }; done
OWRT=0; [ -f /etc/openwrt_release ] && OWRT=1
if [ $OWRT = 1 ]; then command -v opkg >/dev/null 2>&1 && PM=opkg || { command -v apk >/dev/null 2>&1 && PM=apk; }; fi
[ "$PM" = apt-get ] && export DEBIAN_FRONTEND=noninteractive
"#;

pub const MAINTAIN: &str = r#"
act="$1"; shift
pk="$*"
case "$act" in
status)
  echo "os=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  [ $OWRT = 1 ] && echo "openwrt=$( . /etc/openwrt_release; echo "$DISTRIB_DESCRIPTION")"
  echo "kernel=$(uname -r)"; echo "pkg_manager=$PM"
  echo "uptime_s=$(cut -d. -f1 /proc/uptime)"; echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
  awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "mem_total_mb=%d\nmem_avail_mb=%d\n",t/1024,a/1024}' /proc/meminfo
  df -P / /overlay /tmp 2>/dev/null | awk 'NR>1 && !seen[$1 $6]++ && !d[$1]++{printf "disk %s used=%s%% avail_kb=%s\n",$6,$5+0,$4}'
  [ -f /var/run/reboot-required ] && echo "reboot_required=yes"
  if command -v systemctl >/dev/null 2>&1; then echo "failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"; fi
  ;;
check_updates)
  case $PM in
  apt-get) $R apt-get update -qq >/dev/null 2>&1 || echo "warning=apt-get update failed"; apt list --upgradable 2>/dev/null | sed 1d ;;
  dnf|yum) $R $PM -q check-update; true ;;
  pacman) $R pacman -Sy >/dev/null 2>&1; pacman -Qu; true ;;
  zypper) $R zypper -q refresh >/dev/null 2>&1; zypper -q list-updates ;;
  apk) $R apk update -q >/dev/null 2>&1; apk version -l '<' ;;
  opkg) opkg update >/dev/null 2>&1 || echo "warning=opkg update failed"; opkg list-upgradable ;;
  *) echo "error=no supported package manager"; exit 2 ;;
  esac
  ;;
upgrade)
  case $PM in
  apt-get) $R apt-get update -qq && if [ -n "$pk" ]; then $R apt-get install -y --only-upgrade $pk; else $R apt-get -y -o Dpkg::Options::=--force-confold full-upgrade; fi ;;
  dnf|yum) $R $PM -y upgrade $pk ;;
  pacman) $R pacman -Syu --noconfirm $pk ;;
  zypper) $R zypper -n update $pk ;;
  apk) $R apk upgrade $pk ;;
  opkg) opkg update >/dev/null && { [ -n "$pk" ] || pk=$(opkg list-upgradable | cut -d' ' -f1 | tr '\n' ' '); }; [ -z "$pk" ] && echo "nothing to upgrade" || opkg upgrade $pk ;;
  *) echo "error=no supported package manager"; exit 2 ;;
  esac
  [ -f /var/run/reboot-required ] && echo "reboot_required=yes"; true
  ;;
clean)
  b=$(df -Pk / | awk 'NR==2{print $4}')
  case $PM in
  apt-get) $R apt-get -y autoremove --purge >/dev/null; $R apt-get clean ;;
  dnf|yum) $R $PM -y autoremove >/dev/null; $R $PM clean all >/dev/null ;;
  pacman) $R pacman -Sc --noconfirm >/dev/null ;;
  zypper) $R zypper -n clean >/dev/null ;;
  apk) $R apk cache clean >/dev/null 2>&1 ;;
  esac
  command -v journalctl >/dev/null 2>&1 && $R journalctl --vacuum-time=14d >/dev/null 2>&1
  [ $OWRT = 1 ] && rm -f /tmp/opkg-lists/* 2>/dev/null
  a=$(df -Pk / | awk 'NR==2{print $4}')
  echo "freed_kb=$((a-b))"
  ;;
services)
  if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}'; echo "--- failed"; systemctl --failed --no-legend --plain
  elif [ -d /etc/init.d ]; then for s in /etc/init.d/*; do n=${s##*/}; if $s enabled 2>/dev/null; then e=enabled; else e=disabled; fi; r=stopped; $s running >/dev/null 2>&1 && r=running; echo "$n $e $r"; done
  fi
  ;;
logs)
  if command -v journalctl >/dev/null 2>&1; then $R journalctl -p warning -n 80 --no-pager -o short-iso; else logread 2>/dev/null | tail -n 80 || dmesg | tail -n 80; fi
  ;;
*) echo "error=unknown action $act"; exit 2 ;;
esac
"#;

pub const BACKUP: &str = r#"
out="$1"; mkdir -p "$(dirname "$out")"
if [ $OWRT = 1 ]; then
  sysupgrade -b "$out" >/dev/null || { echo "error=sysupgrade -b failed"; exit 1; }
  echo "kind=openwrt-sysupgrade"
else
  l=/tmp/.sg-pkglist.$$
  case $PM in apt-get) dpkg --get-selections >$l ;; dnf|yum) rpm -qa >$l ;; pacman) pacman -Qqe >$l ;; apk) cat /etc/apk/world >$l ;; *) : >$l ;; esac
  $R tar czf "$out" -C / etc -C /tmp "$(basename $l)" 2>/dev/null; rc=$?; rm -f $l
  [ $rc -le 1 ] || { echo "error=tar failed ($rc)"; exit 1; }
  [ -n "$R" ] && $R chown "$(id -u):$(id -g)" "$out"
  echo "kind=etc-tarball"
fi
chmod 600 "$out"
echo "path=$out"; echo "size=$(wc -c <"$out" | tr -d ' ')"
"#;

pub const FW_CHECK: &str = r#"
f="$1"
[ $OWRT = 1 ] || { echo "error=not OpenWrt"; exit 2; }
[ -f "$f" ] || { echo "error=no such file $f"; exit 2; }
echo "board=$(cat /tmp/sysinfo/board_name 2>/dev/null)"
echo "current=$( . /etc/openwrt_release; echo "$DISTRIB_DESCRIPTION")"
echo "size=$(wc -c <"$f" | tr -d ' ')"
echo "mem_avail_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
echo "tmp_avail_kb=$(df -Pk /tmp | awk 'NR==2{print $4}')"
command -v fwtool >/dev/null 2>&1 && fwtool -q -i /tmp/.sg-fwmeta "$f" 2>/dev/null && { echo "metadata=$(tr -d '\n' </tmp/.sg-fwmeta | cut -c1-600)"; rm -f /tmp/.sg-fwmeta; }
o=$(sysupgrade -T "$f" 2>&1); rc=$?
echo "sysupgrade_test_rc=$rc"
echo "$o" | tail -n 8 | sed 's/^/test: /'
"#;

pub const FW_FLASH: &str = r#"
f="$1"; keep="$2"
[ $OWRT = 1 ] || { echo "error=not OpenWrt"; exit 2; }
sysupgrade -T "$f" >/dev/null 2>&1 || { echo "error=sysupgrade -T rejected the image"; exit 1; }
n=""; [ "$keep" = 1 ] || n="-n"
shift 2
if [ "$keep" = 1 ] && [ $# -gt 0 ]; then
  for k in "$@" /etc/init.d/shellgate $(ls /etc/rc.d/*shellgate 2>/dev/null); do
    [ -e "$k" ] || continue
    grep -qxF "$k" /etc/sysupgrade.conf 2>/dev/null || echo "$k" >> /etc/sysupgrade.conf
    echo "kept=$k"
  done
fi
( sleep 3; sysupgrade $n "$f" ) </dev/null >/tmp/sg-sysupgrade.log 2>&1 &
echo "started=yes"
"#;

pub const REINSTALL: &str = r#"
url="$1"; dir="$2"; shift 2
[ $OWRT = 1 ] && { echo "error=use firmware_flash on OpenWrt"; exit 2; }
mkdir -p "$dir"; s="$dir/reinstall.sh"
if command -v curl >/dev/null 2>&1; then curl -fsSL -m 120 -o "$s" "$url"; else wget -q -T 120 -O "$s" "$url"; fi || { echo "error=download failed: $url"; exit 1; }
head -c 200 "$s" | grep -q '^#!' || { echo "error=downloaded file is not a script"; exit 1; }
echo "script_sha256=$(sha256sum "$s" | cut -d' ' -f1)"
cd "$dir" && $R bash "$s" "$@" </dev/null 2>&1 | tail -n 25
rc=$?
echo "reinstall_rc=$rc"
"#;

pub fn script(body: &str) -> String {
    format!("{HEAD}{body}")
}

/// Distros the reinstall script (bin456789/reinstall) accepts as its first argument.
pub const DISTROS: &[&str] = &["debian", "ubuntu", "alpine", "centos", "almalinux", "rocky", "oracle", "fedora", "opensuse",
    "arch", "gentoo", "kali", "anolis", "opencloudos", "openeuler", "redhat", "nixos", "aosc", "fnos", "netboot.xyz", "dd", "windows"];

pub const REINSTALL_URL: &str = "https://cnb.cool/bin456789/reinstall/-/git/raw/main/reinstall.sh";

/// Parse the scripts' `key=value` lines into JSON, keeping other lines as `lines`.
pub fn parse_report(stdout: &str) -> Value {
    let mut m = serde_json::Map::new();
    let mut lines = vec![];
    for l in stdout.lines() {
        match l.split_once('=') {
            Some((k, v)) if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
                match m.get_mut(k) {
                    Some(Value::Array(a)) => a.push(json!(v)),
                    Some(old) => *old = json!([old.clone(), v]),
                    None => { m.insert(k.to_string(), json!(v)); }
                }
            }
            _ if !l.trim().is_empty() => lines.push(l.to_string()),
            _ => {}
        }
    }
    if !lines.is_empty() {
        m.insert("lines".into(), json!(lines));
    }
    Value::Object(m)
}

pub fn definitions() -> Vec<Value> {
    let s = |d: &str| json!({"type": "string", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let confirm = s("One-time code from a previous confirmation_required answer, only after the user agreed");
    let obj = |p: Value, r: &[&str]| json!({"type": "object", "properties": p, "required": r});
    vec![
        json!({"name": "sys_maintain", "description": "Routine upkeep of a Linux or OpenWrt host with its own package manager (apt, dnf/yum, pacman, zypper, apk, opkg). action: status (OS, kernel, memory, disk, reboot needed, failed services), check_updates (refresh lists, show upgradable packages), upgrade (all, or the listed packages; asks for confirmation), clean (autoremove, package cache, journal older than 14 days; reports space freed), services (running and failed services / init scripts), logs (recent warnings). Needs root: ShellGate as root, or SHELLGATE_SUDO_ALLOW=*. On OpenWrt prefer firmware_flash over upgrading every package.",
            "inputSchema": obj(json!({"action": s("status | check_updates | upgrade | clean | services | logs"), "packages": s("upgrade only these (space-separated, optional)"), "timeout": i("seconds (default 600 for upgrade)"), "confirm_code": confirm.clone()}), &["action"])}),
        json!({"name": "config_backup", "description": "Back up the system configuration before a risky change: on OpenWrt `sysupgrade -b` (the archive sysupgrade restores), elsewhere a tarball of /etc plus the installed package list. Saved under ShellGate's state dir (or path); returns path, size and sha256. Fetch it off the box with read_binary.",
            "inputSchema": obj(json!({"path": s("where to write the .tar.gz (optional)")}), &[])}),
        json!({"name": "firmware_check", "description": "OpenWrt: check a firmware image before flashing: board name, current release, image size against free RAM and /tmp, sha256 against the expected value, image metadata (fwtool) and `sysupgrade -T` (the image's own compatibility test). Put the image in /tmp first (write_binary or http download).",
            "inputSchema": obj(json!({"path": s("firmware image on this device, e.g. /tmp/openwrt-...-sysupgrade.bin"), "sha256": s("expected sha256 from the release's sha256sums (recommended)")}), &["path"])}),
        json!({"name": "firmware_flash", "description": "OpenWrt: flash a firmware image with sysupgrade. Always asks for confirmation. First verifies the sha256 (required) and `sysupgrade -T`, saves a config backup with config_backup (on OpenWrt that lands in RAM: copy it off the box with read_binary before confirming if you want to keep it), then starts sysupgrade detached; the device reboots and ShellGate drops for a few minutes. With keep_config (default) ShellGate keeps itself: its binary, config and init script are added to /etc/sysupgrade.conf so the new firmware comes back with ShellGate running. keep_config=false wipes settings (sysupgrade -n) and ShellGate with them. After it comes back, check system_info.",
            "inputSchema": obj(json!({"path": s("firmware image on this device"), "sha256": s("expected sha256 of the image"), "keep_config": b("keep settings (default true)"), "confirm_code": confirm.clone()}), &["path", "sha256"])}),
        json!({"name": "os_reinstall", "description": "Linux: reinstall the operating system over the network with the reinstall script (bin456789/reinstall; picks mirrors in mainland China itself). Wipes the system disk. Always asks for confirmation. Downloads the script, runs it with the distro and options (it prepares the installer and boot entry), then reboots when reboot=true; the install runs unattended for 5 to 30 minutes and the new system has SSH only (no ShellGate). Give ssh_key (preferred) or password for the new root login. Not for WSL (use wsl --unregister/--install from Windows) or OpenWrt (firmware_flash).",
            "inputSchema": obj(json!({"distro": s("debian, ubuntu, alpine, almalinux, rocky, fedora, arch, opensuse, centos, ... or dd / windows"), "release": s("version, e.g. 12 for debian, 24.04 for ubuntu (optional)"), "ssh_key": s("public key or URL (github:user, http...) for root on the new system"), "password": s("root password for the new system (use ssh_key when you can)"), "extra": s("more reinstall.sh options, e.g. --ssh-port 2222 or --img URL for dd (optional)"), "script_url": s("reinstall.sh source (default: the cnb.cool mirror of bin456789/reinstall)"), "reboot": b("reboot into the installer when the script succeeds (default false)"), "confirm_code": confirm}), &["distro"])}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_parsing() {
        let v = parse_report("os=Debian 12\nfreed_kb=12\nsome line\n\nkept=a\nkept=b\nkept=c\n");
        assert_eq!(v["kept"], json!(["a", "b", "c"]));
        assert_eq!(v["os"], "Debian 12");
        assert_eq!(v["freed_kb"], "12");
        assert_eq!(v["lines"][0], "some line");
    }

    #[test]
    fn scripts_parse_with_sh() {
        for body in [MAINTAIN, BACKUP, FW_CHECK, FW_FLASH, REINSTALL] {
            let st = std::process::Command::new("sh").arg("-n").arg("-c").arg(script(body)).status().unwrap();
            assert!(st.success());
        }
    }

    #[test]
    fn status_runs_here() {
        let out = std::process::Command::new("sh").arg("-c").arg(script(MAINTAIN)).arg("sg").arg("status").output().unwrap();
        let v = parse_report(&String::from_utf8_lossy(&out.stdout));
        assert!(v["kernel"].as_str().is_some_and(|k| !k.is_empty()), "{v}");
        assert!(v.get("pkg_manager").is_some());
    }
}
