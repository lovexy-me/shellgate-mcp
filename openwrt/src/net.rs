//! Rescue-stick networking helpers: a supervised `cloudflared tunnel run` (tunnel mode) and a
//! tiny mDNS responder that answers `<name>.local` A queries (lan mode).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use crate::config::Settings;
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
    let Some(bin) = find_cloudflared(&s.cloudflared) else {
        eprintln!("tunnel mode: cloudflared not found (put cloudflared next to shellgate, on PATH, or set cloudflared=); \
                   ShellGate keeps listening on {}:{} only", s.host, s.port);
        return;
    };
    let log_path = Path::new(&s.state_dir).join("cloudflared.log");
    let _ = std::fs::create_dir_all(&s.state_dir);
    let mut backoff = 5u64;
    loop {
        let log = platform::private_opts().create(true).append(true).open(&log_path);
        let pair = log.and_then(|f| Ok((f.try_clone()?, f)));
        let (out, err) = match pair {
            Ok((a, b)) => (Stdio::from(a), Stdio::from(b)),
            Err(_) => (Stdio::null(), Stdio::null()),
        };
        let mut c = platform::new_command(&bin);
        c.args(["tunnel", "--no-autoupdate", "run"])
            .env("TUNNEL_TOKEN", &s.tunnel_token)
            .stdin(Stdio::null()).stdout(out).stderr(err);
        let started = std::time::Instant::now();
        match c.spawn() {
            Ok(mut child) => {
                eprintln!("tunnel mode: cloudflared started (pid {:?}), log: {}", child.id(), log_path.display());
                let st = child.wait().await;
                eprintln!("tunnel mode: cloudflared exited ({st:?}); restarting in {backoff}s");
            }
            Err(e) => eprintln!("tunnel mode: cannot start {bin}: {e}; retrying in {backoff}s"),
        }
        if started.elapsed() > Duration::from_secs(120) {
            backoff = 5;
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

// ---------------------------------------------------------------- mDNS

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The IPv4 address other LAN hosts should use to reach us (address of the default-route interface).
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    for target in ["224.0.0.251:5353", "192.168.255.255:9", "10.255.255.255:9"] {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            if s.connect(target).is_ok() {
                if let Ok(SocketAddr::V4(a)) = s.local_addr() {
                    if !a.ip().is_unspecified() && !a.ip().is_loopback() {
                        return Some(*a.ip());
                    }
                }
            }
        }
    }
    None
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
pub fn spawn_mdns(name: String) {
    let fqdn = format!("{}.local", name.to_lowercase());
    std::thread::spawn(move || {
        let sock = match mdns_socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mDNS: cannot listen on udp/5353 ({e}); {fqdn} will not resolve, use the IP address");
                return;
            }
        };
        let group = SocketAddr::V4(SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
        // announce twice so caches pick us up
        for _ in 0..2 {
            if let Some(ip) = primary_ipv4() {
                let _ = sock.send_to(&build_answer(0, &fqdn, ip, false), group);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        match primary_ipv4() {
            Some(ip) => eprintln!("mDNS: answering {fqdn} -> {ip}"),
            None => eprintln!("mDNS: answering {fqdn} (no LAN address yet)"),
        }
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
            let Some((id, qs)) = parse_query(&buf[..n]) else { continue };
            for (qname, qtype, unicast) in qs {
                if qname != fqdn || !(qtype == 1 || qtype == 255) {
                    continue;
                }
                let Some(ip) = primary_ipv4() else { continue };
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
