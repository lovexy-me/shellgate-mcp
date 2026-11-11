//! Output redaction, identical in behaviour to src/shellgate/redact.py.
//!
//! Every rule is "candidate regex + boundary/validity check in code" (the regex crate has no
//! look-around). Placeholders: <ip> <ipv6> <mac> <key> <token> <uuid> <x> <domain>, and with pii on
//! <email> <phone> <imei> <serial> <ssid>. tests/redact_corpus.tsv is shared with the Python build.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::Value;

pub const ORDER: &[&str] = &["ip", "ipv6", "mac", "key", "token", "uuid", "secret", "domain", "pii"];
const SECRET_NAMES: &str = "password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key\
|preshared[_-]?key|psk|authorization|bearer|key";
const NEED_SEP: &[&str] = &["key", "token", "psk", "secret", "bearer"];

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Counts(pub BTreeMap<&'static str, usize>);

impl Counts {
    fn hit(&mut self, kind: &'static str) {
        *self.0.entry(kind).or_insert(0) += 1;
    }
    pub fn is_empty(&self) -> bool {
        self.0.values().all(|v| *v == 0)
    }
    pub fn footer(&self) -> String {
        let parts: Vec<String> = ORDER.iter()
            .filter_map(|k| self.0.get(k).filter(|n| **n > 0).map(|n| format!("{k}={n}")))
            .collect();
        if parts.is_empty() { String::new() } else { format!("[redacted: {}]", parts.join(" ")) }
    }
}

struct Rx {
    pem: Regex,
    kv: Regex,
    uci: Regex,
    bearer: Regex,
    jwt: Regex,
    uuid: Regex,
    ipv4: Regex,
    ipv4_prefix: Regex,
    ipv4_underscore: Regex,
    version_ctx: Regex,
    ipv6: Regex,
    ipv6_port: Regex,
    ipv6_looks_global: Regex,
    mac: Regex,
    bridge_id: Regex,
    run: Regex,
}

fn rx() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx {
        pem: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----").unwrap(),
        kv: Regex::new(&format!(
            r#"(?i)([A-Za-z0-9_.-]*?)({SECRET_NAMES})(["']?[ \t]*[:=][ \t]*)("[^"\n]*"|'[^'\n]*'|(?:bearer|basic)[ \t]+[^\s"',;]+|[^\s"',;]+)"#
        )).unwrap(),
        uci: Regex::new(&format!(
            r#"(?i)\b(option|list)([ \t]+)({SECRET_NAMES})([ \t]+)('[^'\n]*'|"[^"\n]*"|[^\s'"]+)"#
        )).unwrap(),
        bearer: Regex::new(r"(?i)\b(bearer)([ \t]+)([A-Za-z0-9._~+/=-]{8,})").unwrap(),
        jwt: Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap(),
        uuid: Regex::new(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}").unwrap(),
        ipv4: Regex::new(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}").unwrap(),
        // partial prefixes: "198.51.100." "198.51.100.x" "198.51.100.*" "198.51.100/24" "198.51.*.*"
        ipv4_prefix: Regex::new(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}(?:\.[*xX]){0,2}\.?(?:/[0-9]{1,2})?").unwrap(),
        // identifier form: Allow_198_51_100_Net, from_203_0_113_7
        ipv4_underscore: Regex::new(r"[0-9]{1,3}(?:_[0-9]{1,3}){2,3}").unwrap(),
        version_ctx: Regex::new(r"(?i)(?:\b(?:version|ver|release|build|kernel|firmware|fw|v|rev|revision|driver|bios)[ \t]*[:=]?[ \t]*|[ \t(][A-Za-z][A-Za-z0-9_.-]{1,30}/)$").unwrap(),
        ipv6: Regex::new(r"[0-9A-Fa-f]{0,5}(?::[0-9A-Fa-f]{0,5}){2,8}(?:%[A-Za-z0-9_.-]+)?").unwrap(),
        ipv6_port: Regex::new(r"^(.*[0-9A-Fa-f:]):([0-9]{1,5})$").unwrap(),
        ipv6_looks_global: Regex::new(r"(?:^|:)[23][0-9A-Fa-f]{3}(?::[0-9A-Fa-f]{0,5}){3,}").unwrap(),
        mac: Regex::new(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}").unwrap(),
        // Linux bridge id: 8000.0242ac110002 (priority.mac)
        bridge_id: Regex::new(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{12}").unwrap(),
        run: Regex::new(r"[A-Za-z0-9+/_-]+={0,2}").unwrap(),
    })
}

// ---------------------------------------------------------------- extra rules (v0.2.7)
// Same table as _EXTRA_SPEC in redact.py: (name, pattern, group (0 = whole), replacement, kind,
// left, right, pii). left/right: None = no check; Some(set) = the neighbouring char must not be an
// ASCII letter/digit/underscore nor in set. Replacement "=" keeps quotes (<x>).
type ExtraSpec = (&'static str, &'static str, usize, &'static str, &'static str, Option<&'static str>, Option<&'static str>, bool);
const EXTRA_SPEC: &[ExtraSpec] = &[
    ("crypt", r"\$(?:1|2[abxy]|5|6|y|gy|7|apr1)\$[./A-Za-z0-9$=,+-]{8,}", 0, "<x>", "secret", Some("$"), None, false),
    ("aws_secret", r"[A-Za-z0-9/+]{40}", 0, "<x>", "secret", Some("/+="), Some("/+="), false),
    ("prefixed", concat!(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}",
        r"|sk-(?:proj-|ant-(?:api[0-9]+-)?|or-v1-|svcacct-)?[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{40,}",
        r"|xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}",
        r"|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}",
        r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"), 0, "<token>", "token", Some("-"), Some(""), false),
    ("url_userinfo", r"([A-Za-z][A-Za-z0-9+.-]{1,15}://)([^\s/@:<>]*):([^\s/@<>]+)@", 3, "<x>", "secret", None, None, false),
    ("proxy_userinfo", r"(?i)(?:^|[^A-Za-z0-9+.-])((?:ss|ssr|trojan|hysteria2?|hy2|tuic|anytls|socks5?h?)://)([^\s@/:<>]+)@", 2, "<x>", "secret", Some(""), None, false),
    ("vmess", r"(?:^|[^A-Za-z0-9+.-])(vmess://)([A-Za-z0-9+/=_-]{16,})", 2, "<x>", "secret", Some(""), None, false),
    ("mysql_p", r#"\b(?:mysql\w*|mariadb[\w-]*)[^\n]*?[ \t]-p([^\s'"<]\S*|'[^'\n]*'|"[^"\n]*")"#, 1, "=", "secret", None, None, false),
    ("sshpass_p", r#"\bsshpass\b[^\n]*?[ \t]-p[ \t]*([^\s'"<]\S*|'[^'\n]*'|"[^"\n]*")"#, 1, "=", "secret", None, None, false),
    ("user_pass_flag", r#"(?m)(?:^|[ \t])(?:-u|--user|--proxy-user|--http-user)(?:[ \t]+|=)['"]?([^\s:'"<]+):([^\s'"]+)"#, 2, "<x>", "secret", None, None, false),
    ("smb_user_pass", r#"(?m)(?:^|[ \t])-U[ \t]*['"]?([^\s%'"]+)%([^\s'"]+)"#, 2, "<x>", "secret", None, None, false),
    ("secret_flag", concat!(r"(?im)(?:^|[ \t])--?(?:password|passwd|pass|pwd|token|secret|api-?key|auth-?key|access-?token",
        r"|psk|cookie|http-password|ftp-password|proxy-password|tunnel-token)(?:[ \t]+|=)",
        r#"([^\s'"<-][^\s'"]*|'[^'\n]*'|"[^"\n]*")"#), 1, "=", "secret", None, None, false),
    ("wifi_conf", concat!(r"(?im)^([ \t]*(?:WPAPSK[0-9]*|WPA_PSK[0-9]*|PSK_KEYS|RADIUS_Key[0-9]*|WEP_?KEY[0-9_]*",
        r"|Key[1-4]Str[0-9]*|sae_password|wpa_passphrase|wpa_psk)[ \t]*=[ \t]*)([^\r\n]+)"), 2, "<x>", "secret", None, None, false),
    ("netsh_key", r"(?im)^([ \t]*(?:Key Content|关键内容|密钥内容)[ \t]*:[ \t]*)([^\r\n]+)", 2, "<x>", "secret", None, None, false),
    ("cookie_header", r"(?im)^([ \t<>]*(?:set-cookie|cookie)[ \t]*:[ \t]*)([^\r\n]+)", 2, "<x>", "secret", None, None, false),
    ("cookie_quoted", r#"(?i)(["'](?:set-)?cookie["'][ \t]*:[ \t]*)("[^"\n]*"|'[^'\n]*')"#, 2, "=", "secret", None, None, false),
    ("chap_secrets", r#"(?m)^([ \t]*"[^"\n]+"[ \t]+(?:\*|"[^"\n]*"|[^\s"]+)[ \t]+)("[^"\n]+")"#, 2, "=", "secret", None, None, false),
    ("hex_in_key_ctx", r"(?i)\b(?:key|token|secret|password|passwd|psk|hmac|apikey)\b[^\n]{0,24}?([0-9a-fA-F]{32,128})", 1, "<x>", "secret", Some(""), Some(""), false),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,})", 0, "<email>", "pii", Some(".%+-"), Some(""), true),
    ("cn_mobile", r"(?:\+?86[- ]?)?1[3-9][0-9](?:[- ]?[0-9]{4}){2}", 0, "<phone>", "pii", Some("._+/:-"), Some("._"), true),
    ("imei", r"(?i)\b(?:imei|meid)[0-9]?[^\n0-9<]{0,12}([0-9]{14,17})", 1, "<imei>", "pii", Some(""), Some(""), true),
    ("serial", r#"(?i)(ro\.(?:boot\.)?serialno|\bserial[ _]?(?:number|no)?)([\]"']?[ \t]*[:=][ \t]*[\["']?)([A-Za-z0-9][A-Za-z0-9._-]{5,})"#, 3, "<serial>", "pii", None, Some(""), true),
    ("ssid", r#"(?im)(^[ \t]*|[ \t,{;"'])(e?ssid[ \t]*[0-9]*)(["']?[ \t]*[:=][ \t]*|[ \t]+)("[^"\n]*"|'[^'\n]*'|[^\r\n,;}"'<]+)"#, 4, "<ssid>", "pii", None, None, true),
];
const LOCAL_TLDS: &[&str] = &["local", "lan", "home", "internal", "localdomain", "arpa", "localhost", "intranet"];

struct Extra {
    name: &'static str,
    re: Regex,
    group: usize,
    rep: &'static str,
    kind: &'static str,
    left: Option<&'static str>,
    right: Option<&'static str>,
    pii: bool,
}

fn extras() -> &'static Vec<Extra> {
    static E: OnceLock<Vec<Extra>> = OnceLock::new();
    E.get_or_init(|| EXTRA_SPEC.iter().map(|&(name, p, group, rep, kind, left, right, pii)| Extra {
        name, re: Regex::new(p).unwrap_or_else(|e| panic!("extra rule {name}: {e}")), group, rep, kind, left, right, pii,
    }).collect())
}

fn blocked(c: Option<char>, set: Option<&str>) -> bool {
    set.is_some_and(|s| is_word(c) || is_in(c, s))
}

fn extra_ok(name: &str, m: &Captures, g: usize, t: &str) -> bool {
    let mg = m.get(g).unwrap();
    let v = mg.as_str();
    match name {
        "aws_secret" => {
            if !(v.bytes().any(|b| b.is_ascii_uppercase()) && v.bytes().any(|b| b.is_ascii_lowercase())
                && v.bytes().any(|b| b.is_ascii_digit()) && (v.contains('/') || v.contains('+'))) {
                return false;
            }
            let m0 = m.get(0).unwrap();
            let ls = t[..m0.start()].rfind('\n').map_or(0, |i| i + 1);
            let le = t[m0.end()..].find('\n').map_or(t.len(), |i| m0.end() + i);
            let line = t[ls..le].to_lowercase();
            line.contains("aws") || line.contains("akia") || line.contains("asia")
        }
        "email" => {
            let local = v.split('@').next().unwrap_or("");
            let tld = m.get(1).unwrap().as_str().to_lowercase();
            !local.eq_ignore_ascii_case("git") && !LOCAL_TLDS.contains(&tld.as_str())
        }
        "user_pass_flag" => {
            let user = m.get(1).unwrap().as_str();
            let digits = |x: &str| !x.is_empty() && x.chars().all(|c| c.is_ascii_digit());
            !(digits(user) && digits(v))
        }
        "ssid" => !v.trim().trim_matches(|c| c == '\'' || c == '"').trim().is_empty(),
        _ => true,
    }
}

fn extra_rep(name: &str, rep: &str, v: &str) -> String {
    if rep == "=" {
        return mask_value(v);
    }
    let q = v.chars().next();
    if let Some(q) = q.filter(|c| *c == '\'' || *c == '"') {
        if v.len() >= 2 && v.ends_with(q) && (name == "ssid" || name == "serial") {
            return format!("{q}{rep}{q}");
        }
    }
    if name == "ssid" {
        return format!("{rep}{}", &v[v.trim_end().len()..]);
    }
    rep.to_string()
}

/// Up to 40 chars before i; a leading space stands for the start of the text.
fn ctx(t: &str, i: usize) -> String {
    let mut st = i.saturating_sub(40);
    while !t.is_char_boundary(st) { st += 1; }
    format!("{}{}", if st == 0 { " " } else { "" }, &t[st..i])
}

fn before(t: &str, i: usize) -> Option<char> {
    t[..i].chars().next_back()
}
fn after(t: &str, j: usize) -> Option<char> {
    t[j..].chars().next()
}
fn is_alnum(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric())
}
fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}
fn is_in(c: Option<char>, set: &str) -> bool {
    c.is_some_and(|c| set.contains(c))
}

/// Replace each match with f(caps, text); None keeps the original.
fn sub<F: FnMut(&Captures, &str) -> Option<String>>(re: &Regex, text: &str, mut f: F) -> String {
    let mut out = String::new();
    let mut last = 0;
    let mut changed = false;
    for caps in re.captures_iter(text) {
        let m = caps.get(0).unwrap();
        if let Some(rep) = f(&caps, text) {
            out.push_str(&text[last..m.start()]);
            out.push_str(&rep);
            last = m.end();
            changed = true;
        }
    }
    if !changed {
        return text.to_string();
    }
    out.push_str(&text[last..]);
    out
}

/// s[i-1] is ':'; true when it ends a label such as "Sta:" rather than a hex chain.
fn label_colon(s: &str, i: usize) -> bool {
    let b = s.as_bytes();
    if i == 0 || b[i - 1] != b':' {
        return false;
    }
    let mut j = i - 1;
    while j > 0 && b[j - 1].is_ascii_alphanumeric() {
        j -= 1;
    }
    let seg = &b[j..i - 1];
    !seg.is_empty() && !seg.iter().all(|c| c.is_ascii_hexdigit()) && (j == 0 || b[j - 1] != b':')
}

fn is_placeholder(v: &str) -> bool {
    let v = v.trim_matches(|c| c == '\'' || c == '"');
    v.len() >= 3 && v.starts_with('<') && v.ends_with('>')
}

fn mask_value(v: &str) -> String {
    let first = v.chars().next();
    if let Some(q) = first.filter(|c| *c == '\'' || *c == '"') {
        if v.len() >= 2 && v.ends_with(q) {
            return format!("{q}<x>{q}");
        }
    }
    "<x>".into()
}

/// Some(true) = redact, Some(false) = keep, None = not an IPv4 address.
pub fn ipv4_is_public(addr: &str) -> Option<bool> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        o[i] = p.parse().ok()?;
        if o[i] > 255 {
            return None;
        }
    }
    let [a, b, _, _] = o;
    let n = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
    if a == 0 || a == 10 || a == 127 {
        return Some(false);
    }
    if (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254) {
        return Some(false);
    }
    if a == 100 && (64..=127).contains(&b) {
        return Some(false);
    }
    if (224..=239).contains(&a) || n == 0xFFFF_FFFF {
        return Some(false);
    }
    if a == 255 {
        let inv = !n;
        if inv & inv.wrapping_add(1) == 0 {
            return Some(false);
        }
    }
    Some(true)
}

/// Some(true) for 2000::/3 global unicast, Some(false) for other valid addresses, None if invalid.
pub fn ipv6_is_global(addr: &str) -> Option<bool> {
    let a = addr.split('%').next().unwrap_or("");
    let ip: Ipv6Addr = a.parse().ok()?;
    Some(ip.segments()[0] >> 13 == 0b001)
}

pub struct Redactor {
    pub enabled: bool,
    domain: Option<Regex>,
    /// exact secret values this server knows (its own access token, tunnel token): always masked
    secrets: Vec<String>,
    /// personal data rules (email, CN mobile, IMEI, serial, SSID); SHELLGATE_REDACT_PII=0 turns them off
    pii: bool,
}

impl Redactor {
    pub fn new(enabled: bool, domains: &[String]) -> Self {
        let mut suffixes: Vec<String> = domains.iter()
            .map(|d| d.trim().trim_matches('.').to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        suffixes.sort();
        suffixes.dedup();
        suffixes.sort_by(|a, b| b.len().cmp(&a.len()));
        let domain = (!suffixes.is_empty()).then(|| {
            let alts: Vec<String> = suffixes.iter().map(|s| regex::escape(s)).collect();
            Regex::new(&format!(r"(?i)(?:[A-Za-z0-9-]+\.)*(?:{})", alts.join("|"))).unwrap()
        });
        Self { enabled, domain, secrets: Vec::new(), pii: true }
    }

    pub fn with_secrets(mut self, secrets: &[String]) -> Self {
        let mut v: Vec<String> = secrets.iter().filter(|x| x.len() >= 12).cloned().collect();
        v.sort();
        v.dedup();
        v.sort_by(|a, b| b.len().cmp(&a.len()));
        self.secrets = v;
        self
    }

    pub fn with_pii(mut self, on: bool) -> Self {
        self.pii = on;
        self
    }

    fn extra(&self, text: String, c: &mut Counts) -> String {
        let mut t = text;
        for e in extras() {
            if e.pii && !self.pii {
                continue;
            }
            t = sub(&e.re, &t, |m, s| {
                let mg = m.get(e.group)?;
                let v = mg.as_str();
                if v.is_empty() || is_placeholder(v) {
                    return None;
                }
                if blocked(before(s, mg.start()), e.left) || blocked(after(s, mg.end()), e.right) {
                    return None;
                }
                if !extra_ok(e.name, m, e.group, s) {
                    return None;
                }
                c.hit(e.kind);
                let m0 = m.get(0).unwrap();
                Some(format!("{}{}{}", &s[m0.start()..mg.start()], extra_rep(e.name, e.rep, v), &s[mg.end()..m0.end()]))
            });
        }
        t
    }

    pub fn text(&self, text: &str, c: &mut Counts) -> String {
        if !self.enabled || text.is_empty() {
            return text.to_string();
        }
        let r = rx();
        let mut t = sub(&r.pem, text, |_, _| { c.hit("key"); Some("<key>".into()) });
        for sec in &self.secrets {
            let n = t.matches(sec.as_str()).count();
            if n > 0 {
                for _ in 0..n { c.hit("secret"); }
                t = t.replace(sec.as_str(), "<x>");
            }
        }
        t = self.extra(t, c);

        t = sub(&r.kv, &t, |m, s| {
            let (prefix, value) = (m.get(1).unwrap().as_str(), m.get(4).unwrap().as_str());
            let name = m.get(2).unwrap().as_str().to_lowercase();
            if !prefix.is_empty() && !prefix.ends_with(['_', '.', '-']) && NEED_SEP.contains(&name.as_str()) {
                return None;
            }
            let b = before(s, m.get(0).unwrap().start());
            if is_word(b) || is_in(b, ".-") {
                return None;
            }
            if is_placeholder(value) || value == "''" || value == "\"\"" {
                return None;
            }
            c.hit("secret");
            Some(format!("{}{}{}{}", prefix, &m[2], &m[3], mask_value(value)))
        });
        t = sub(&r.uci, &t, |m, _| {
            let value = m.get(5).unwrap().as_str();
            if is_placeholder(value) || value == "''" || value == "\"\"" {
                return None;
            }
            c.hit("secret");
            Some(format!("{}{}{}{}{}", &m[1], &m[2], &m[3], &m[4], mask_value(value)))
        });
        t = sub(&r.bearer, &t, |m, _| {
            if is_placeholder(&m[3]) {
                return None;
            }
            c.hit("secret");
            Some(format!("{}{}<x>", &m[1], &m[2]))
        });
        t = sub(&r.jwt, &t, |m, s| {
            let b = before(s, m.get(0).unwrap().start());
            if is_word(b) || is_in(b, "-") {
                return None;
            }
            c.hit("token");
            Some("<token>".into())
        });
        if let Some(d) = &self.domain {
            t = sub(d, &t, |m, s| {
                let m0 = m.get(0).unwrap();
                let (b, a) = (before(s, m0.start()), after(s, m0.end()));
                if is_alnum(b) || is_in(b, ".-_") || is_word(a) || is_in(a, "-") {
                    return None;
                }
                if a == Some('.') && is_alnum(after(s, m0.end() + 1)) {
                    return None;
                }
                c.hit("domain");
                Some("<domain>".into())
            });
        }
        t = sub(&r.uuid, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let (b, a) = (before(s, m0.start()), after(s, m0.end()));
            if is_word(b) || is_in(b, "-") || is_word(a) || is_in(a, "-") {
                return None;
            }
            c.hit("uuid");
            Some("<uuid>".into())
        });
        t = sub(&r.ipv4, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let b = before(s, m0.start());
            if is_alnum(b) || is_in(b, "._") {
                return None;
            }
            let a = after(s, m0.end());
            if a == Some('.') && after(s, m0.end() + 1).is_some_and(|c| c.is_ascii_digit()) {
                // tcpdump-style a.b.c.d.port: a 2-5 digit port (<= 65535), then a non-word, non-dot boundary
                let bytes = s.as_bytes();
                let mut j = m0.end() + 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() { j += 1; }
                let port = &s[m0.end() + 1..j];
                let n = after(s, j);
                if !(2..=5).contains(&port.len()) || port.parse::<u32>().map_or(true, |p| p > 65535)
                    || is_alnum(n) || n == Some('.') {
                    return None;
                }
            } else if is_alnum(a) {
                return None;
            }
            // version strings: 5.15.153.1-microsoft, "version 1.2.3.4", "ver: 1.0.0.12"
            if a == Some('-') && after(s, m0.end() + 1).is_some_and(|c| c.is_ascii_alphabetic()) {
                return None;
            }
            // file names: pkg-1.2.3.4.tar.gz, setup.10.0.1.2.exe (but 8.8.8.8.nip.io is an address)
            if a == Some('.') && after(s, m0.end() + 1).is_some_and(|c| c.is_ascii_alphabetic()) {
                let rest = &s[m0.end() + 1..];
                let word: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
                if !["nip", "sslip", "xip"].contains(&word.as_str()) {
                    return None;
                }
            }
            if r.version_ctx.is_match(&ctx(s, m0.start())) {
                return None;
            }
            if ipv4_is_public(m0.as_str()) == Some(true) {
                c.hit("ip");
                Some("<ip>".into())
            } else {
                None
            }
        });
        t = sub(&r.ipv4_prefix, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let whole = m0.as_str();
            let b = before(s, m0.start());
            if is_alnum(b) || is_in(b, ".") {
                return None;
            }
            let a = after(s, m0.end());
            if is_alnum(a) || is_in(a, "*/")
                || (a == Some('.') && after(s, m0.end() + 1).is_some_and(|c| c.is_ascii_digit())) {
                return None;
            }
            let (core, cidr) = match whole.split_once('/') {
                Some((x, y)) => (x, Some(y)),
                None => (whole, None),
            };
            let trailing = core.ends_with('.');
            let parts: Vec<&str> = core.trim_end_matches('.').split('.').collect();
            let n = parts.iter().take_while(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).count();
            let wild = parts.len() - n;
            if parts[n..].iter().any(|p| p.bytes().any(|b| b.is_ascii_digit())) || parts.len() > 4 {
                return None;
            }
            if parts[..n].iter().any(|p| p.parse::<u32>().map_or(true, |v| v > 255)) {
                return None;
            }
            if let Some(cv) = cidr {
                if cv.parse::<u32>().map_or(true, |v| v > 32) || n != 3 || wild > 0 || trailing {
                    return None;
                }
            }
            if !((n == 3 && (trailing || wild > 0 || cidr.is_some())) || (n == 2 && wild > 0)) {
                return None;
            }
            if r.version_ctx.is_match(&ctx(s, m0.start())) {
                return None;
            }
            let mut full: Vec<&str> = parts[..n].to_vec();
            while full.len() < 4 { full.push("0"); }
            if ipv4_is_public(&full.join(".")) != Some(true) {
                return None;
            }
            let num_len = parts[..n].join(".").len();
            c.hit("ip");
            Some(format!("<ip>{}", &whole[num_len..]))
        });
        t = sub(&r.ipv4_underscore, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let (b, a) = (before(s, m0.start()), after(s, m0.end()));
            if is_alnum(b) || is_alnum(a) {
                return None;
            }
            if (b == Some('_') && before(s, m0.start() - 1).is_some_and(|c| c.is_ascii_digit()))
                || (a == Some('_') && after(s, m0.end() + 1).is_some_and(|c| c.is_ascii_digit())) {
                return None;
            }
            let nums: Vec<&str> = m0.as_str().split('_').collect();
            if nums.iter().any(|p| p.parse::<u32>().map_or(true, |v| v > 255)) {
                return None;
            }
            if m0.as_str().len() - (nums.len() - 1) < 5 {
                return None;
            }
            let mut full = nums.clone();
            while full.len() < 4 { full.push("0"); }
            if ipv4_is_public(&full.join(".")) != Some(true) {
                return None;
            }
            c.hit("ip");
            Some("<ip>".into())
        });
        t = sub(&r.ipv6, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let cand = m0.as_str();
            if is_word(after(s, m0.end())) {
                return None;
            }
            let mut core = cand;
            let mut port = String::new();
            let mut whole = ipv6_is_global(core);
            if whole.is_none() {
                if let Some(pm) = r.ipv6_port.captures(cand) {
                    let a = pm.get(1).unwrap().as_str();
                    if ipv6_is_global(a).is_some() {
                        core = a;
                        port = format!(":{}", pm.get(2).unwrap().as_str());
                        whole = ipv6_is_global(core);
                    }
                }
            }
            let b = before(s, m0.start());
            let boundary_ok = !(is_word(b) || is_in(b, ":."));
            if boundary_ok && whole == Some(true) {
                c.hit("ipv6");
                return Some(format!("<ipv6>{}", port));
            }
            if boundary_ok && whole.is_some() {
                return None;
            }
            // "label:2001:db8::1" - try the part after each single colon
            let bytes = cand.as_bytes();
            for i in 0..bytes.len() {
                if bytes[i] != b':' || i + 1 >= bytes.len() || bytes[i + 1] == b':' || (i > 0 && bytes[i - 1] == b':') {
                    continue;
                }
                let rest = &cand[i + 1..];
                if (rest.contains("::") || rest.matches(':').count() == 7) && ipv6_is_global(rest) == Some(true) {
                    c.hit("ipv6");
                    return Some(format!("{}<ipv6>", &cand[..i + 1]));
                }
            }
            if r.ipv6_looks_global.is_match(cand) {
                c.hit("ipv6");
                return Some("<ipv6>".into());
            }
            None
        });
        t = sub(&r.mac, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let (b, a) = (before(s, m0.start()), after(s, m0.end()));
            let label = b == Some(':') && label_colon(s, m0.start());
            if (!label && (is_word(b) || is_in(b, ":-."))) || is_word(a) || is_in(a, ":-.") {
                return None;
            }
            let hex: String = m0.as_str().chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_lowercase();
            if hex == "000000000000" || hex == "ffffffffffff" {
                return None;
            }
            c.hit("mac");
            Some("<mac>".into())
        });
        t = sub(&r.bridge_id, &t, |m, s| {
            let m0 = m.get(0).unwrap();
            let (b, a) = (before(s, m0.start()), after(s, m0.end()));
            if is_word(b) || is_in(b, ":-.") || is_word(a) || is_in(a, ":-.") {
                return None;
            }
            let tail = m0.as_str()[5..].to_ascii_lowercase();
            if tail == "000000000000" || tail == "ffffffffffff" {
                return None;
            }
            c.hit("mac");
            Some(format!("{}<mac>", &m0.as_str()[..5]))
        });
        t = sub(&r.run, &t, |m, _| {
            let s = m.get(0).unwrap().as_str();
            if s.len() == 44 && s.ends_with('=') && !s[..43].contains('=')
                && s[..43].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
                c.hit("key");
                return Some("<key>".into());
            }
            let core = s.trim_end_matches('=');
            if core.len() >= 60 && !core.starts_with('/') && core.matches('/').count() <= 3
                && core.bytes().any(|b| b.is_ascii_uppercase())
                && core.bytes().any(|b| b.is_ascii_lowercase())
                && core.bytes().any(|b| b.is_ascii_digit()) {
                c.hit("token");
                return Some("<token>".into());
            }
            None
        });
        t
    }

    /// Redact every string inside a JSON value (keys are left alone).
    pub fn value(&self, v: &mut Value, c: &mut Counts) {
        if !self.enabled {
            return;
        }
        match v {
            Value::String(s) => {
                let r = self.text(s, c);
                if r != *s {
                    *s = r;
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.value(x, c)),
            Value::Object(m) => m.values_mut().for_each(|x| self.value(x, c)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(t: &str) -> (String, String) {
        let r = Redactor::new(true, &["example.org".into(), ".example.net".into()]);
        let mut c = Counts::default();
        let out = r.text(t, &mut c);
        (out, c.footer())
    }

    #[test]
    fn ipv4_per_token() {
        let (o, f) = red("src 192.168.1.10 dst 203.0.113.7 via 10.0.0.1 nat 198.51.100.2/24 cgn 100.64.1.1");
        assert_eq!(o, "src 192.168.1.10 dst <ip> via 10.0.0.1 nat <ip>/24 cgn 100.64.1.1");
        assert_eq!(f, "[redacted: ip=2]");
        for keep in ["127.0.0.1", "172.16.5.4", "172.31.255.1", "169.254.1.1", "0.0.0.0", "255.255.255.0",
                     "255.255.255.255", "224.0.0.251"] {
            assert_eq!(red(&format!("addr {keep}:80")).0, format!("addr {keep}:80"));
        }
        assert_eq!(red("172.32.0.1").0, "<ip>");
        assert_eq!(red("v1.2.3.4.5 and 999.1.1.1").1, "");
        assert_eq!(red("peer=203.0.113.9:51820,").0, "peer=<ip>:51820,");
        let v = "Linux version 5.15.153.1-microsoft-standard-WSL2, Version: 8.8.4.4, fw 1.1.1.1, ver=9.9.9.9";
        assert_eq!(red(v).0, v);
        assert_eq!(red("dns 8.8.4.4 conversion 8.8.8.8").0, "dns <ip> conversion <ip>");
        assert_eq!(red("range 8.8.8.8-9").0, "range <ip>-9");
    }

    #[test]
    fn ipv4_tcpdump_port_suffix() {
        let (o, f) = red("IP 198.51.100.7.58686 > 203.0.113.9.123: UDP, length 148\nIP 192.168.1.2.22 > 10.0.0.1.53: x\n  2 IP 203.0.113.9.58686");
        assert_eq!(o, "IP <ip>.58686 > <ip>.123: UDP, length 148\nIP 192.168.1.2.22 > 10.0.0.1.53: x\n  2 IP <ip>.58686");
        assert_eq!(f, "[redacted: ip=3]");
        for keep in ["1.2.3.4.5", "8.8.8.8.123456", "8.8.8.8.99999", "8.8.8.8.53.1", "8.8.8.8.53a", "v9.9.9.9.80"] {
            assert_eq!(red(keep).0, keep, "{keep}");
        }
    }

    #[test]
    fn mac_after_label_and_bridge_id() {
        let (o, f) = red("New Sta:02:42:ac:11:00:02 Del Sta:0a:1b:2c:3d:4e:5f\nbr-lan 7fff.0242ac110002 no eth0");
        assert_eq!(o, "New Sta:<mac> Del Sta:<mac>\nbr-lan 7fff.<mac> no eth0");
        assert_eq!(f, "[redacted: mac=3]");
        for keep in ["key sha1!! c9:6d:d9:2e:73:f9:93:c3:c1:d9:8f:59:60:cc:7c:96:1d:36:59:a4 from x",
                     "fe80::aa:bb:cc:dd:ee:ff", "x:aa:02:42:ac:11:00:02", "8000.000000000000",
                     "sha 1234.0242ac110002abcd"] {
            assert_eq!(red(keep).0, keep);
        }
    }

    #[test]
    fn ipv4_partial_prefixes() {
        for (src, want) in [
            ("WHITELIST=\"192.168.1. 198.51.100. 172.16. 203.0.113.\"", "WHITELIST=\"192.168.1. <ip>. 172.16. <ip>.\""),
            ("allow 198.51.100.x and 203.0.113.* and 198.51.*.*", "allow <ip>.x and <ip>.* and <ip>.*.*"),
            ("src 198.51.100/24 lan 192.168.1/24", "src <ip>/24 lan 192.168.1/24"),
            ("option name 'Allow_198_51_100_Net_To_vlmcsd'", "option name 'Allow_<ip>_Net_To_vlmcsd'"),
            ("--comment \"!fw4: from_203_0_113_7\"", "--comment \"!fw4: from_<ip>\""),
        ] {
            assert_eq!(red(src).0, want);
        }
        for keep in ["pkg 1.2.3.tar.gz", "openwrt-23.05.3", "version 22.03.5.", "v1.2.3.", "192.168.1.10 and 10.26.0.",
                     "backup_20261029", "rule_1_2_3", "a_1_2_3_4_5_6", "255.255.255.", "ratio 1.5 and 3.14.",
                     "100.64.1.", "file_v2_1_0", "1.2.3.4.5"] {
            assert_eq!(red(keep).0, keep);
        }
    }

    #[test]
    fn ipv6_with_port_and_fail_closed() {
        let t = "tcp 2001:db8:1101:694c:319a:4f87:3571:dc00:25932 x\ntcp 2409:8a00:111f:40d0::1:53 y\nudp [2001:db8::5]:51820 z\nfd00::1:53 fe80::e2ef:2ff:fe56:df30:53";
        let (o, _) = red(t);
        assert!(!o.contains("2001:db8") && !o.contains("2409:"), "{o}");
        assert!(o.contains("<ipv6>:25932"));
        assert!(o.contains("fd00::1:53") && o.contains("fe80::e2ef:2ff:fe56:df30:53"));
        assert_eq!(red("time 12:34:56 mac-ish c9:6d:d9:2e").0, "time 12:34:56 mac-ish c9:6d:d9:2e");
    }

    #[test]
    fn ipv6() {
        let (o, f) = red("inet6 2001:db8::1/64 scope global\ninet6 fe80::1%eth0 ::1 fd12:3456::9 addr:2001:db8:0:1::5");
        assert_eq!(o, "inet6 <ipv6>/64 scope global\ninet6 fe80::1%eth0 ::1 fd12:3456::9 addr:<ipv6>");
        assert_eq!(f, "[redacted: ipv6=2]");
        assert_eq!(red("at 12:34:56 and std::vector").1, "");
        assert_eq!(red("ipv6:240e::1").0, "ipv6:<ipv6>");
    }

    #[test]
    fn mac() {
        let (o, f) = red("link/ether 02:42:AC:11:00:02 brd ff:ff:ff:ff:ff:ff  hw 0A-1B-2C-3D-4E-5F");
        assert_eq!(o, "link/ether <mac> brd ff:ff:ff:ff:ff:ff  hw <mac>");
        assert_eq!(f, "[redacted: mac=2]");
    }

    #[test]
    fn keys_tokens_uuid() {
        let key = format!("{}E=", "Q".repeat(42));
        let (o, f) = red(&format!("peer: {key}\n  endpoint: 203.0.113.1:51820"));
        assert_eq!(o, "peer: <key>\n  endpoint: <ip>:51820");
        assert_eq!(f, "[redacted: ip=1 key=1]");
        assert_eq!(red("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX2hlcmU ok").0, "jwt <token> ok");
        assert_eq!(red(&format!("tok {}", "aZ9".repeat(21))).0, "tok <token>");
        let plain = format!("/usr/lib/{} sha256:{}", "a".repeat(80), "ab12".repeat(16));
        assert_eq!(red(&plain).0, plain);
        assert_eq!(red("UUID=123e4567-e89b-12d3-a456-426614174000 type").0, "UUID=<uuid> type");
        let pem = "x\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\ny";
        assert_eq!(red(pem).0, "x\n<key>\ny");
    }

    #[test]
    fn domains() {
        let (o, f) = red("https://a.b.example.org/x user@Example.ORG host.example.net notexample.org example.org.cn");
        assert_eq!(o, "https://<domain>/x <email> <domain> notexample.org example.org.cn");
        assert_eq!(f, "[redacted: domain=2 pii=1]");
        let mut c = Counts::default();
        assert_eq!(Redactor::new(true, &[]).text("a.example.org", &mut c), "a.example.org");
    }

    #[test]
    fn secrets() {
        for (src, want) in [
            ("password=hunter2", "password=<x>"),
            ("DB_PASSWORD='p w'", "DB_PASSWORD='<x>'"),
            (r#"{"api_key": "abc", "token":""}"#, r#"{"api_key": "<x>", "token":""}"#),
            ("Authorization: Bearer abc.def.ghi", "Authorization: <x>"),
            ("curl -H 'X: y' bearer abcdefgh12345", "curl -H 'X: y' bearer <x>"),
            ("PrivateKey = c2VjcmV0", "PrivateKey = <x>"),
            ("preshared_key: zzz", "preshared_key: <x>"),
            ("wireless.radio0.key='wifipass'", "wireless.radio0.key='<x>'"),
            ("\toption key 'wifipass'", "\toption key '<x>'"),
            ("monkey=1 tokens: 3 secret_name=a", "monkey=1 tokens: 3 secret_name=a"),
            ("mypassword: abc", "mypassword: <x>"),
        ] {
            assert_eq!(red(src).0, want, "{src}");
        }
    }

    #[test]
    fn idempotent_values_and_disabled() {
        let (once, _) = red("ip 203.0.113.5 password=x mac 02:00:00:00:00:01");
        let (twice, f) = red(&once);
        assert_eq!(once, twice);
        assert_eq!(f, "");
        let r = Redactor::new(true, &[]);
        let mut v = serde_json::json!({"stdout": "203.0.113.1", "list": ["02:42:ac:11:00:02"], "n": 3});
        let mut c = Counts::default();
        r.value(&mut v, &mut c);
        assert_eq!(v, serde_json::json!({"stdout": "<ip>", "list": ["<mac>"], "n": 3}));
        assert_eq!(c.footer(), "[redacted: ip=1 mac=1]");
        let off = Redactor::new(false, &["example.org".into()]);
        assert_eq!(off.text("203.0.113.1 a.example.org", &mut Counts::default()), "203.0.113.1 a.example.org");
    }

    #[test]
    fn shared_corpus() {
        let r = Redactor::new(true, &["example.com".to_string()]).with_secrets(&["known-secret-value-123456".to_string()]);
        let unesc = |x: &str| x.replace("\\n", "\n").replace("\\t", "\t");
        let mut n = 0;
        for line in include_str!("../../tests/redact_corpus.tsv").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 3, "bad corpus line: {line}");
            let mut c = Counts::default();
            assert_eq!(r.text(&unesc(f[1]), &mut c), unesc(f[2]), "corpus case {}", f[0]);
            n += 1;
        }
        assert!(n >= 80);
    }

    #[test]
    fn pii_off_and_short_secret() {
        let r = Redactor::new(true, &[]).with_pii(false).with_secrets(&["short".to_string()]);
        let s = "mail alice@gmail.com tel 13812345678 SSID: Home-5G a short word";
        assert_eq!(r.text(s, &mut Counts::default()), s);
    }
}
