//! Binary transfer helpers: base64, SHA-256 of files, text detection (read_binary / write_binary).

use sha2::{Digest, Sha256};
use std::io::Read;

pub const CHUNK_DEFAULT: u64 = 262_144;
pub const CHUNK_MAX: u64 = 1_048_576;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Strict standard base64 (whitespace ignored, padding required like Python's validate=True).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.len() % 4 != 0 {
        return Err("data is not valid base64: length is not a multiple of 4".into());
    }
    let val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let quads = s.len() / 4;
    for (qi, q) in s.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && qi + 1 != quads) || q[..4 - pad].contains(&b'=') {
            return Err("data is not valid base64: bad padding".into());
        }
        let mut n = 0u32;
        for (i, &b) in q.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { val(b).ok_or("data is not valid base64: bad character")? };
            n = n << 6 | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Ok(out)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn sha256_file(p: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// First 8 KB has no NUL and is UTF-8 (allowing a character cut at the edge): a text file.
pub fn looks_text(p: &str) -> Result<bool, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
    let mut head = vec![0u8; 8192];
    let mut n = 0;
    while n < head.len() {
        let k = f.read(&mut head[n..]).map_err(|e| e.to_string())?;
        if k == 0 { break; }
        n += k;
    }
    let head = &head[..n];
    if head.contains(&0) {
        return Ok(false);
    }
    Ok((0..4).any(|cut| cut <= head.len() && std::str::from_utf8(&head[..head.len() - cut]).is_ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for n in 0..300 {
            let d: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&d)).unwrap(), d);
        }
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert!(b64_decode("aGVsbG8").is_err());
        assert!(b64_decode("aGV=bG8=").is_err());
        assert!(b64_decode("aGVs*G8=").is_err());
    }

    #[test]
    fn sha() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
