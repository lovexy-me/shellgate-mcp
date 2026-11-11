//! Rescue-stick networking helpers: a supervised `cloudflared tunnel run` (tunnel mode) and a
//! tiny mDNS responder that answers `<name>.local` A queries (lan mode).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use crate::config::{NetMode, Settings};
use crate::platform;

// ---------------------------------------------------------------- cloudflared

fn find_cloudflared(configured: &str) -> Option<String> {
    if !configured.is_empty() {
        return Path::new(configured).is_file().then(|| configured.to_string());
    }
    let exe = if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" };
    if let Some(d) = platform::exe_dir() {
        let p = d.join(exe);
        if p.is_file() {
            return Some(p.to_string_lossy().to_string());
        }
    }
    platform::which("cloudflared")
}

/// Keep `cloudflared tunnel --no-autoupdate run` alive. The tunnel token is passed through the
/// TUNNEL_TOKEN environment variable, never on the command line (so it is not visible in `ps`).
/// Output goes to `<state_dir>/cloudflared.log`, which sits in a protected directory.
pub async fn supervise_cloudflared(s: Settings) {
    use crate::events::{ev, TUNNEL_PID, TUNNEL_RESTARTS, TUNNEL_RUNNING};
    use std::sync::atomic::Ordering;
    let Some(bin) = find_cloudflared(&s.cloudflared) else {
        ev(format!("tunnel mode: cloudflared not found (put cloudflared next to shellgate, on PATH, or set cloudflared=); \
                   ShellGate keeps listening on {}:{} only", s.host, s.port));
        return;
    };
    let log_path = Path::new(&s.state_dir).join("cloudflared.log");
    let _ = std::fs::create_dir_all(&s.state_dir);
    // keep the log from growing without bound on phones and sticks
    if std::fs::metadata(&log_path).map(|m| m.len() > 2_000_000).unwrap_or(false) {
        let _ = std::fs::rename(&log_path, log_path.with_extension("log.1"));
    }
    let mut backoff = 5u64;
    loop {
        let log = platform::private_opts().create(true).append(true).open(&log_path);
        let pair = log.and_then(|f| Ok((f.try_clone()?, f)));
        let (out, err) = match pair {
            Ok((a, b)) => (Stdio::from(a), Stdio::from(b)),
            Err(_) => (Stdio::null(), Stdio::null()),
        };
        let mut c = platform::new_command(&bin);
        c.args(["tunnel", "--no-autoupdate"]);
        if no_system_resolv_conf() {
            // Android has no /etc/resolv.conf, so Go's built-in resolver asks [::1]:53 and edge
            // discovery fails ("lookup _v2-origintunneld._tcp.argotunnel.com on [::1]:53 ...
            // connection refused"). Use the platform resolver (cgo/bionic) for cloudflared's own
            // lookups, and resolve the edge here (libc getaddrinfo works) and hand cloudflared
            // the addresses, so it does not need the SRV lookup at all.
            c.env("GODEBUG", "netdns=cgo");
            let edges = resolve_edges().await;
            if edges.is_empty() {
                ev("tunnel mode: could not resolve region1/region2.v2.argotunnel.com here either; check the phone's network");
            } else {
                ev(format!("tunnel mode: no /etc/resolv.conf, giving cloudflared {} edge address(es)", edges.len()));
            }
            for e in &edges {
                c.arg("--edge").arg(e);
            }
        }
        c.arg("run")
            .env("TUNNEL_TOKEN", &s.tunnel_token)
            .stdin(Stdio::null()).stdout(out).stderr(err);
        let started = std::time::Instant::now();
        match c.spawn() {
            Ok(mut child) => {
                TUNNEL_RUNNING.store(true, Ordering::Relaxed);
                TUNNEL_PID.store(child.id().unwrap_or(0), Ordering::Relaxed);
                ev(format!("tunnel mode: cloudflared started (pid {:?}), log: {}", child.id(), log_path.display()));
                let st = child.wait().await;
                TUNNEL_RUNNING.store(false, Ordering::Relaxed);
                TUNNEL_PID.store(0, Ordering::Relaxed);
                TUNNEL_RESTARTS.fetch_add(1, Ordering::Relaxed);
                ev(format!("tunnel mode: cloudflared exited ({st:?}); restarting in {backoff}s"));
            }
            Err(e) => ev(format!("tunnel mode: cannot start {bin}: {e}; retrying in {backoff}s")),
        }
        if started.elapsed() > Duration::from_secs(120) {
            backoff = 5;
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// Stop the supervised cloudflared (on stop / restart), so it does not outlive ShellGate and keep
/// the tunnel up, or pile up one extra copy per restart.
pub fn stop_tunnel() {
    let pid = crate::events::TUNNEL_PID.swap(0, std::sync::atomic::Ordering::SeqCst);
    if pid == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new("taskkill");
        c.args(["/F", "/T", "/PID", &pid.to_string()]);
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let _ = c.status();
    }
}

/// True where Go programs cannot find a DNS server on their own (Android: no /etc/resolv.conf).
fn no_system_resolv_conf() -> bool {
    cfg!(target_os = "android") || (cfg!(unix) && !Path::new("/etc/resolv.conf").exists())
}

/// Cloudflare tunnel edge addresses (port 7844) resolved with the platform resolver, IPv4 first.
async fn resolve_edges() -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for h in ["region1.v2.argotunnel.com:7844", "region2.v2.argotunnel.com:7844"] {
        if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host(h)).await {
            for a in addrs.take(4) {
                let s = a.to_string();
                if a.is_ipv4() { if !v4.contains(&s) { v4.push(s) } } else if !v6.contains(&s) { v6.push(s) }
            }
        }
    }
    v4.extend(v6);
    v4
}

/// Tunnel state read from the tail of cloudflared.log: connections registered since the last
/// start, and the last error line (redacted by the caller).
pub fn tunnel_log_state(state_dir: &str) -> (u32, Option<String>, Vec<String>) {
    let p = Path::new(state_dir).join("cloudflared.log");
    let text = std::fs::read(&p).map(|b| {
        let start = b.len().saturating_sub(64 * 1024);
        String::from_utf8_lossy(&b[start..]).to_string()
    }).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.iter().rposition(|l| l.contains("Starting tunnel") || l.contains("Starting metrics server")).unwrap_or(0);
    let mut conns: i32 = 0;
    let mut last_err = None;
    for l in &lines[from..] {
        if l.contains("Registered tunnel connection") { conns += 1; }
        if l.contains("Unregistered tunnel connection") || l.contains("Connection terminated") { conns -= 1; }
        if l.contains(" ERR ") { last_err = Some(l.to_string()); }
    }
    let tail = lines.iter().rev().take(40).rev().map(|l| l.to_string()).collect();
    (conns.max(0) as u32, last_err, tail)
}

// ---------------------------------------------------------------- WinPE network

/// What to do about the network in WinPE: (start networking, turn the firewall off).
/// Only for net=lan|tunnel with `pe_network` on: networking when there is no usable IPv4 yet,
/// the firewall only in lan mode (a tunnel needs no inbound connections).
pub fn pe_net_plan(is_pe: bool, net: NetMode, enabled: bool, has_ip: bool) -> (bool, bool) {
    if !is_pe || !enabled || net == NetMode::Local {
        return (false, false);
    }
    (!has_ip, net == NetMode::Lan)
}

/// One line to stderr and to `<state_dir>/pe-network.log`.
fn pe_log(state_dir: &str, msg: &str) {
    eprintln!("winpe: {msg}");
    if state_dir.is_empty() {
        return;
    }
    let _ = std::fs::create_dir_all(state_dir);
    if let Ok(mut f) = platform::private_opts().create(true).append(true).open(Path::new(state_dir).join("pe-network.log")) {
        use std::io::Write;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "{ts} {msg}");
    }
}

#[cfg_attr(unix, allow(dead_code))]
async fn wpeutil(arg: &str) -> String {
    let Some(exe) = platform::which("wpeutil") else { return "wpeutil not found".into() };
    let mut c = platform::new_command(&exe);
    c.arg(arg).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    match tokio::time::timeout(Duration::from_secs(120), c.output()).await {
        Ok(Ok(o)) => {
            let text = platform::decode_output(&[o.stdout, o.stderr].concat());
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            format!("exit {:?}{}{}", o.status.code(), if text.is_empty() { "" } else { ": " }, text.chars().take(200).collect::<String>())
        }
        Ok(Err(e)) => format!("cannot run: {e}"),
        Err(_) => "timed out after 120 s".into(),
    }
}

/// WinPE without wpeinit (official WinPE / Windows Setup started some other way, or a PE whose
/// shell skipped it) has no network: bring it up, and in lan mode open the firewall.
pub async fn winpe_network(s: Settings) {
    let has_ip = primary_ipv4().is_some();
    let (init, fw_off) = pe_net_plan(platform::is_winpe(), s.net, s.pe_network, has_ip);
    if !init && !fw_off {
        return;
    }
    if init {
        pe_log(&s.state_dir, "no IPv4 address: running wpeutil InitializeNetwork");
        let r = wpeutil("InitializeNetwork").await;
        pe_log(&s.state_dir, &format!("wpeutil InitializeNetwork -> {r}"));
        let t0 = std::time::Instant::now();
        while primary_ipv4().is_none() && t0.elapsed() < Duration::from_secs(90) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match primary_ipv4() {
            Some(ip) => pe_log(&s.state_dir, &format!("IPv4 address {ip} after {} s", t0.elapsed().as_secs())),
            None => pe_log(&s.state_dir, "still no IPv4 address after 90 s (no driver for the network card, or no DHCP?)"),
        }
    } else if s.pe_network {
        pe_log(&s.state_dir, "IPv4 address present; not initialising the network");
    }
    if fw_off {
        let r = wpeutil("DisableFirewall").await;
        pe_log(&s.state_dir, &format!("lan mode: wpeutil DisableFirewall -> {r}"));
    }
}

// ---------------------------------------------------------------- mDNS

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The IPv4 address other LAN hosts should use to reach us (address of the default-route interface).
/// All IPv4 addresses that look like a LAN (for lan_scan defaults and the admin page).
pub fn lan_ipv4s() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = vec![];
    if let Some(ip) = primary_ipv4() { v.push(ip); }
    v
}

pub fn primary_ipv4() -> Option<Ipv4Addr> {
    for target in ["224.0.0.251:5353", "192.168.255.255:9", "10.255.255.255:9"] {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            if s.connect(target).is_ok() {
                if let Ok(SocketAddr::V4(a)) = s.local_addr() {
                    if usable_lan_ip(a.ip()) {
                        return Some(*a.ip());
                    }
                }
            }
        }
    }
    None
}

/// An address other machines can reach: not 0.0.0.0, loopback, or link-local (169.254/16,
/// which Windows assigns while DHCP has not answered).
pub fn usable_lan_ip(ip: &Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local()
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Read a (possibly compressed) DNS name at `pos`; returns (lowercase name, position after it).
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = vec![];
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            pos = ptr;
            continue;
        }
        let l = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(l).to_lowercase());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

/// Questions in a query: (name, qtype, unicast-response bit).
pub fn parse_query(msg: &[u8]) -> Option<(u16, Vec<(String, u16, bool)>)> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let mut pos = 12;
    let mut qs = vec![];
    for _ in 0..qd.min(32) {
        let (name, p) = read_name(msg, pos)?;
        let qtype = u16::from_be_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
        let qclass = u16::from_be_bytes([*msg.get(p + 2)?, *msg.get(p + 3)?]);
        qs.push((name, qtype, qclass & 0x8000 != 0));
        pos = p + 4;
    }
    Some((id, qs))
}

/// An authoritative A-record answer for `fqdn`. `question` echoes the query for legacy unicast.
pub fn build_answer(id: u16, fqdn: &str, ip: Ipv4Addr, question: bool) -> Vec<u8> {
    let mut m = vec![];
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x8400u16.to_be_bytes()); // QR + AA
    m.extend_from_slice(&(question as u16).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    if question {
        encode_name(fqdn, &mut m);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
    }
    encode_name(fqdn, &mut m);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&(if question { 0x0001u16 } else { 0x8001u16 }).to_be_bytes()); // IN (+cache flush)
    m.extend_from_slice(&120u32.to_be_bytes());
    m.extend_from_slice(&4u16.to_be_bytes());
    m.extend_from_slice(&ip.octets());
    m
}

fn mdns_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    let _ = s.set_reuse_port(true);
    s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())?;
    s.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    s.set_multicast_loop_v4(true)?;
    s.set_multicast_ttl_v4(255)?;
    Ok(s.into())
}

/// Answer `<name>.local` A queries on the LAN (runs on its own thread; best effort).
/// Waits until the machine has a LAN address (WinPE brings the network up late), retries the
/// socket when it cannot be opened yet, and re-announces when the address changes.
pub fn spawn_mdns(name: String) {
    let fqdn = format!("{}.local", name.to_lowercase());
    std::thread::spawn(move || {
        let mut waited = false;
        while primary_ipv4().is_none() {
            if !waited {
                eprintln!("mDNS: waiting for a LAN address before answering {fqdn}");
                waited = true;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        let mut delay = 2u64;
        let mut tries = 0u32;
        let sock = loop {
            match mdns_socket() {
                Ok(s) => break s,
                Err(e) => {
                    tries += 1;
                    if tries == 1 || tries % 10 == 0 {
                        eprintln!("mDNS: cannot listen on udp/5353 ({e}); retrying (attempt {tries}); meanwhile use the IP address");
                    }
                    std::thread::sleep(Duration::from_secs(delay));
                    delay = (delay * 2).min(30);
                }
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
        let group = SocketAddr::V4(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
        let announce = |ip: Ipv4Addr| {
            // twice so caches pick us up
            for _ in 0..2 {
                let _ = sock.send_to(&build_answer(0, &fqdn, ip, false), group);
                std::thread::sleep(Duration::from_millis(500));
            }
        };
        let mut last = primary_ipv4();
        if let Some(ip) = last {
            announce(ip);
            eprintln!("mDNS: answering {fqdn} -> {ip}");
        }
        let mut buf = [0u8; 1500];
        let mut checked = std::time::Instant::now();
        let mut now = last;
        loop {
            let got = sock.recv_from(&mut buf);
            if checked.elapsed() >= Duration::from_secs(5) {
                now = primary_ipv4();
                checked = std::time::Instant::now();
            }
            if now != last {
                if let Some(ip) = now {
                    eprintln!("mDNS: address changed, answering {fqdn} -> {ip}");
                    announce(ip);
                }
                last = now;
            }
            let (n, from) = match got {
                Ok(v) => v,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                Err(_) => {
                    // e.g. WSAECONNRESET after an ICMP unreachable, or the adapter went away
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };
            let Some((id, qs)) = parse_query(&buf[..n]) else { continue };
            for (qname, qtype, unicast) in qs {
                if qname != fqdn || !(qtype == 1 || qtype == 255) {
                    continue;
                }
                let Some(ip) = now else { continue };
                if from.port() != MDNS_PORT {
                    // legacy one-shot resolver: unicast reply with the query id and question
                    let _ = sock.send_to(&build_answer(id, &fqdn, ip, true), from);
                } else if unicast {
                    let _ = sock.send_to(&build_answer(0, &fqdn, ip, false), from);
                } else {
                    let _ = sock.send_to(&build_answer(0, &fqdn, ip, false), group);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        encode_name(name, &mut m);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn parse_and_answer() {
        let (id, qs) = parse_query(&query("Ventoy-Rescue.local", 1)).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(qs, vec![("ventoy-rescue.local".to_string(), 1, false)]);
        let a = build_answer(id, "ventoy-rescue.local", Ipv4Addr::new(192, 168, 1, 50), true);
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(&a[a.len() - 4..], &[192, 168, 1, 50]);
        // a response must not be parsed as a query
        assert!(parse_query(&a).is_none());
        // compressed name pointer
        let mut m = query("ventoy-rescue.local", 1);
        m[5] = 2;
        m.extend_from_slice(&[0xC0, 12, 0, 28, 0, 1]);
        let (_, qs) = parse_query(&m).unwrap();
        assert_eq!(qs[1], ("ventoy-rescue.local".to_string(), 28, false));
    }

    #[test]
    fn lan_ip_filter() {
        assert!(usable_lan_ip(&Ipv4Addr::new(192, 168, 1, 20)));
        assert!(!usable_lan_ip(&Ipv4Addr::new(169, 254, 3, 4)));
        assert!(!usable_lan_ip(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!usable_lan_ip(&Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn winpe_network_plan() {
        // not WinPE, switched off, or local mode: leave the network alone
        assert_eq!(pe_net_plan(false, NetMode::Lan, true, false), (false, false));
        assert_eq!(pe_net_plan(true, NetMode::Lan, false, false), (false, false));
        assert_eq!(pe_net_plan(true, NetMode::Local, true, false), (false, false));
        // lan: init only without an address, firewall off either way
        assert_eq!(pe_net_plan(true, NetMode::Lan, true, false), (true, true));
        assert_eq!(pe_net_plan(true, NetMode::Lan, true, true), (false, true));
        // tunnel: outbound only, firewall untouched
        assert_eq!(pe_net_plan(true, NetMode::Tunnel, true, false), (true, false));
        assert_eq!(pe_net_plan(true, NetMode::Tunnel, true, true), (false, false));
    }

    #[test]
    fn mdns_end_to_end_unicast() {
        // a legacy (non-5353) query on loopback multicast must get a unicast answer
        let name = format!("sg-test-{}", crate::policy::random_hex(3));
        spawn_mdns(name.clone());
        std::thread::sleep(Duration::from_millis(300));
        let c = UdpSocket::bind("0.0.0.0:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let q = query(&format!("{name}.local"), 1);
        let mut got = None;
        for _ in 0..3 {
            let _ = c.send_to(&q, "224.0.0.251:5353");
            let mut b = [0u8; 512];
            if let Ok((n, _)) = c.recv_from(&mut b) {
                got = Some(b[..n].to_vec());
                break;
            }
        }
        match (got, primary_ipv4()) {
            (Some(ans), Some(ip)) => assert_eq!(&ans[ans.len() - 4..], &ip.octets()),
            (None, None) => {} // sandbox without a usable LAN interface
            (g, ip) => panic!("unexpected mdns result: answer={g:?} ip={ip:?}"),
        }
    }
}
