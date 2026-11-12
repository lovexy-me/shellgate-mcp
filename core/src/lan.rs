//! LAN helpers for hosts without the usual tools (Android phones, WinPE): a TCP connect sweep
//! (`lan_scan`) and a plain HTTP client (`http_request`). Nothing here needs root.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

pub const DEFAULT_PORTS: &[u16] = &[22, 23, 80, 443, 445, 554, 3389, 5555, 5900, 8080, 8443, 9000];

/// Well-known meaning of a port, to make scan results readable.
pub fn port_hint(p: u16) -> &'static str {
    match p {
        22 => "ssh",
        23 => "telnet",
        80 | 8080 => "http",
        443 | 8443 => "https",
        445 => "smb (Windows share)",
        554 => "rtsp (camera)",
        3389 => "rdp (Windows remote desktop)",
        5555 => "adb (Android TV / phone, network debugging)",
        5900 => "vnc",
        8790 => "shellgate",
        9000 => "web ui",
        _ => "",
    }
}

/// Parse `192.168.1.0/24`, `192.168.1.10-40`, or one address into a host list (max 1024).
pub fn parse_targets(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let spec = spec.trim();
    if let Some((base, bits)) = spec.split_once('/') {
        let base: Ipv4Addr = base.trim().parse().map_err(|_| format!("bad address: {base}"))?;
        let bits: u32 = bits.trim().parse().map_err(|_| format!("bad prefix: {bits}"))?;
        if !(20..=32).contains(&bits) {
            return Err("prefix must be /20 to /32 (at most 4096 addresses, 1024 scanned)".into());
        }
        let mask = if bits == 32 { u32::MAX } else { !(u32::MAX >> bits) };
        let net = u32::from(base) & mask;
        let size = 1u32 << (32 - bits);
        let hosts: Vec<Ipv4Addr> = if size <= 2 {
            (0..size).map(|i| Ipv4Addr::from(net + i)).collect()
        } else {
            (1..size - 1).map(|i| Ipv4Addr::from(net + i)).collect()
        };
        return Ok(hosts.into_iter().take(1024).collect());
    }
    if let Some((a, b)) = spec.split_once('-') {
        let a: Ipv4Addr = a.trim().parse().map_err(|_| format!("bad address: {a}"))?;
        let b = b.trim();
        let end: Ipv4Addr = if b.contains('.') {
            b.parse().map_err(|_| format!("bad address: {b}"))?
        } else {
            let o = a.octets();
            Ipv4Addr::new(o[0], o[1], o[2], b.parse().map_err(|_| format!("bad range end: {b}"))?)
        };
        let (s, e) = (u32::from(a), u32::from(end));
        if e < s || e - s > 1023 {
            return Err("range must be ascending and at most 1024 addresses".into());
        }
        return Ok((s..=e).map(Ipv4Addr::from).collect());
    }
    Ok(vec![spec.parse().map_err(|_| format!("bad address: {spec}"))?])
}

/// The /24 around each local LAN address.
pub fn default_targets() -> Vec<String> {
    crate::net::lan_ipv4s().iter().map(|ip| {
        let o = ip.octets();
        format!("{}.{}.{}.0/24", o[0], o[1], o[2])
    }).collect()
}

pub async fn scan(targets: Vec<Ipv4Addr>, ports: Vec<u16>, timeout_ms: u64, concurrency: usize) -> Value {
    let started = Instant::now();
    let sem = Arc::new(Semaphore::new(concurrency.clamp(8, 512)));
    let mut tasks = vec![];
    for ip in &targets {
        for &port in &ports {
            let sem = sem.clone();
            let ip = *ip;
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire_owned().await.ok()?;
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                let t0 = Instant::now();
                match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Some((ip, port, t0.elapsed().as_millis() as u64, true)),
                    // a refused connection still proves the host is up
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some((ip, port, t0.elapsed().as_millis() as u64, false)),
                    _ => None,
                }
            }));
        }
    }
    let mut hosts: std::collections::BTreeMap<u32, (Vec<Value>, u64)> = Default::default();
    for t in tasks {
        if let Ok(Some((ip, port, ms, open))) = t.await {
            let e = hosts.entry(u32::from(ip)).or_insert((vec![], ms));
            e.1 = e.1.min(ms);
            if open {
                e.0.push(json!({"port": port, "service": port_hint(port)}));
            }
        }
    }
    let list: Vec<Value> = hosts.into_iter().map(|(ip, (mut open, ms))| {
        open.sort_by_key(|v| v["port"].as_u64());
        json!({"ip": Ipv4Addr::from(ip).to_string(), "open": open, "rtt_ms": ms})
    }).collect();
    json!({
        "status": "ok",
        "scanned_hosts": targets.len(),
        "ports": ports,
        "hosts_up": list.len(),
        "hosts": list,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "note": "TCP connect sweep: hosts that answer on none of the ports (or drop refused packets) are not listed.",
    })
}

/// Blocking HTTP request (call from spawn_blocking). Self-signed HTTPS (routers, TVs) needs insecure=true.
pub fn http_request(method: &str, url: &str, headers: &[(String, String)], body: Option<&str>, timeout_s: u64,
                    insecure: bool, max_bytes: usize) -> Result<Value, String> {
    let lower = url.to_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err("url must start with http:// or https://".into());
    }
    let mut b = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_s.clamp(1, 120)))
        .redirects(5);
    if insecure {
        b = b.tls_config(Arc::new(insecure_tls()));
    }
    let agent = b.build();
    let mut req = agent.request(&method.to_uppercase(), url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let t0 = Instant::now();
    let resp = match body {
        Some(b) => req.send_string(b),
        None => req.call(),
    };
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(format!("request failed: {e}")),
    };
    let status = resp.status();
    let ctype = resp.header("content-type").unwrap_or("").to_string();
    let mut hdrs = serde_json::Map::new();
    for n in resp.headers_names() {
        if let Some(v) = resp.header(&n) {
            hdrs.insert(n, json!(v));
        }
    }
    let mut buf = vec![];
    use std::io::Read;
    let mut rd = resp.into_reader().take(max_bytes as u64 + 1);
    rd.read_to_end(&mut buf).map_err(|e| format!("reading body: {e}"))?;
    let truncated = buf.len() > max_bytes;
    buf.truncate(max_bytes);
    let text = String::from_utf8(buf.clone());
    let mut v = json!({"status": "ok", "http_status": status, "content_type": ctype, "headers": hdrs,
                       "elapsed_ms": t0.elapsed().as_millis() as u64, "truncated": truncated});
    match text {
        Ok(t) => v["body"] = json!(t),
        Err(_) => {
            v["body_base64"] = json!(b64(&buf));
            v["note"] = json!("binary body, returned as base64");
        }
    }
    Ok(v)
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn insecure_tls() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
                              _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime)
                              -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                                  -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                                  -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions().expect("tls versions")
        .dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(parse_targets("192.168.1.0/30").unwrap().len(), 2);
        assert_eq!(parse_targets("192.168.1.0/24").unwrap().len(), 254);
        assert_eq!(parse_targets("192.168.1.10-12").unwrap().len(), 3);
        assert_eq!(parse_targets("10.0.0.5").unwrap(), vec![Ipv4Addr::new(10, 0, 0, 5)]);
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("10.0.0.9-3").is_err());
    }

    #[test]
    fn base64() {
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64(b"hi"), "aGk=");
        assert_eq!(b64(b"abc"), "YWJj");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scan_local_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let v = scan(vec![Ipv4Addr::LOCALHOST], vec![port], 500, 8).await;
        assert_eq!(v["hosts_up"], 1);
        assert_eq!(v["hosts"][0]["open"][0]["port"], port);
    }
}
