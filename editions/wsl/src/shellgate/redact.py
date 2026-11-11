"""Output redaction: masks addresses, keys, tokens and secrets before text leaves the host.

Every rule is "candidate regex + boundary/validity check in code" (no look-around), so the
Rust build in core/src/redact.rs can implement exactly the same behaviour.

Placeholders: <ip> <ipv6> <mac> <key> <token> <uuid> <x> (secret values) <domain>,
and with pii on: <email> <phone> <imei> <serial> <ssid>.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any, Callable

ORDER = ("ip", "ipv6", "mac", "key", "token", "uuid", "secret", "domain", "pii")

_SECRET_NAMES = (r"password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key"
                 r"|preshared[_-]?key|psk|authorization|bearer|key")

_NEED_SEP = {"key", "token", "psk", "secret", "bearer"}

_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_KV = re.compile(
    r"(?i)([A-Za-z0-9_.-]*?)(" + _SECRET_NAMES + r")([\"']?[ \t]*[:=][ \t]*)"
    r"(\"[^\"\n]*\"|'[^'\n]*'|(?:bearer|basic)[ \t]+[^\s\"',;]+|[^\s\"',;]+)")
_UCI = re.compile(
    r"(?i)\b(option|list)([ \t]+)(" + _SECRET_NAMES + r")([ \t]+)('[^'\n]*'|\"[^\"\n]*\"|[^\s'\"]+)")
_BEARER = re.compile(r"(?i)\b(bearer)([ \t]+)([A-Za-z0-9._~+/=-]{8,})")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_IPV4 = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
# partial prefixes: "198.51.100." "198.51.100.x" "198.51.100.*" "198.51.100/24" "198.51.*.*"
_IPV4_PREFIX = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}(?:\.[*xX]){0,2}\.?(?:/[0-9]{1,2})?")
# identifier form: Allow_198_51_100_Net, from_203_0_113_7
_IPV4_UNDERSCORE = re.compile(r"[0-9]{1,3}(?:_[0-9]{1,3}){2,3}")
_VERSION_CTX = re.compile(r"(?i)\b(?:version|ver|release|build|kernel|firmware|fw|v)[ \t]*[:=]?[ \t]*$")
_IPV6 = re.compile(r"[0-9A-Fa-f]{0,5}(?::[0-9A-Fa-f]{0,5}){2,8}(?:%[A-Za-z0-9_.-]+)?")
_IPV6_PORT = re.compile(r"^(.*[0-9A-Fa-f:]):([0-9]{1,5})$")
# fail closed: anything that still looks like a global unicast address (2000::/3) is masked
_IPV6_LOOKS_GLOBAL = re.compile(r"(?:^|:)[23][0-9A-Fa-f]{3}(?::[0-9A-Fa-f]{0,5}){3,}")
_MAC = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"
                  r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
# Linux bridge id: 8000.0242ac110002 (priority.mac)
_BRIDGE_ID = re.compile(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{12}")
_RUN = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_B64 = re.compile(r"[A-Za-z0-9+/]{43}=")

_ALNUM = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_WORD = _ALNUM | {"_"}

# ---------------------------------------------------------------- extra rules (v0.2.7)
# (name, pattern, group to replace (0 = whole match), replacement, kind, left, right, pii)
# left/right: None = no boundary check; a string = the neighbouring char must not be an ASCII
# letter/digit/underscore nor any char in the string. Replacement "=" keeps quotes (<x>).
_EXTRA_SPEC = [
    ("crypt", r"\$(?:1|2[abxy]|5|6|y|gy|7|apr1)\$[./A-Za-z0-9$=,+-]{8,}", 0, "<x>", "secret", "$", None, False),
    ("aws_secret", r"[A-Za-z0-9/+]{40}", 0, "<x>", "secret", "/+=", "/+=", False),
    ("prefixed", r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}"
                 r"|sk-(?:proj-|ant-(?:api[0-9]+-)?|or-v1-|svcacct-)?[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{40,}"
                 r"|xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}"
                 r"|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}"
                 r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", 0, "<token>", "token", "-", "", False),
    ("url_userinfo", r"([A-Za-z][A-Za-z0-9+.-]{1,15}://)([^\s/@:<>]*):([^\s/@<>]+)@", 3, "<x>", "secret", None, None, False),
    ("proxy_userinfo", r"(?i)(?:^|[^A-Za-z0-9+.-])((?:ss|ssr|trojan|hysteria2?|hy2|tuic|anytls|socks5?h?)://)([^\s@/:<>]+)@", 2, "<x>", "secret", "", None, False),
    ("vmess", r"(?:^|[^A-Za-z0-9+.-])(vmess://)([A-Za-z0-9+/=_-]{16,})", 2, "<x>", "secret", "", None, False),
    ("mysql_p", r"\b(?:mysql\w*|mariadb[\w-]*)[^\n]*?[ \t]-p([^\s'\"<]\S*|'[^'\n]*'|\"[^\"\n]*\")", 1, "=", "secret", None, None, False),
    ("sshpass_p", r"\bsshpass\b[^\n]*?[ \t]-p[ \t]*([^\s'\"<]\S*|'[^'\n]*'|\"[^\"\n]*\")", 1, "=", "secret", None, None, False),
    ("user_pass_flag", r"(?m)(?:^|[ \t])(?:-u|--user|--proxy-user|--http-user)(?:[ \t]+|=)['\"]?([^\s:'\"<]+):([^\s'\"]+)", 2, "<x>", "secret", None, None, False),
    ("smb_user_pass", r"(?m)(?:^|[ \t])-U[ \t]*['\"]?([^\s%'\"]+)%([^\s'\"]+)", 2, "<x>", "secret", None, None, False),
    ("secret_flag", r"(?im)(?:^|[ \t])--?(?:password|passwd|pass|pwd|token|secret|api-?key|auth-?key|access-?token"
                    r"|psk|cookie|http-password|ftp-password|proxy-password|tunnel-token)(?:[ \t]+|=)"
                    r"([^\s'\"<-][^\s'\"]*|'[^'\n]*'|\"[^\"\n]*\")", 1, "=", "secret", None, None, False),
    ("wifi_conf", r"(?im)^([ \t]*(?:WPAPSK[0-9]*|WPA_PSK[0-9]*|PSK_KEYS|RADIUS_Key[0-9]*|WEP_?KEY[0-9_]*"
                  r"|Key[1-4]Str[0-9]*|sae_password|wpa_passphrase|wpa_psk)[ \t]*=[ \t]*)([^\r\n]+)", 2, "<x>", "secret", None, None, False),
    ("netsh_key", r"(?im)^([ \t]*(?:Key Content|关键内容|密钥内容)[ \t]*:[ \t]*)([^\r\n]+)", 2, "<x>", "secret", None, None, False),
    ("cookie_header", r"(?im)^([ \t<>]*(?:set-cookie|cookie)[ \t]*:[ \t]*)([^\r\n]+)", 2, "<x>", "secret", None, None, False),
    ("cookie_quoted", r"(?i)([\"'](?:set-)?cookie[\"'][ \t]*:[ \t]*)(\"[^\"\n]*\"|'[^'\n]*')", 2, "=", "secret", None, None, False),
    ("chap_secrets", r"(?m)^([ \t]*\"[^\"\n]+\"[ \t]+(?:\*|\"[^\"\n]*\"|[^\s\"]+)[ \t]+)(\"[^\"\n]+\")", 2, "=", "secret", None, None, False),
    ("hex_in_key_ctx", r"(?i)\b(?:key|token|secret|password|passwd|psk|hmac|apikey)\b[^\n]{0,24}?([0-9a-fA-F]{32,128})", 1, "<x>", "secret", "", "", False),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,})", 0, "<email>", "pii", ".%+-", "", True),
    ("cn_mobile", r"(?:\+?86[- ]?)?1[3-9][0-9](?:[- ]?[0-9]{4}){2}", 0, "<phone>", "pii", "._+/:-", "._", True),
    ("imei", r"(?i)\b(?:imei|meid)[0-9]?[^\n0-9<]{0,12}([0-9]{14,17})", 1, "<imei>", "pii", "", "", True),
    ("serial", r"(?i)(ro\.(?:boot\.)?serialno|\bserial[ _]?(?:number|no)?)([\]\"']?[ \t]*[:=][ \t]*[\[\"']?)([A-Za-z0-9][A-Za-z0-9._-]{5,})", 3, "<serial>", "pii", None, "", True),
    ("ssid", r"(?im)(^[ \t]*|[ \t,{;\"'])(e?ssid[ \t]*[0-9]*)([\"']?[ \t]*[:=][ \t]*|[ \t]+)(\"[^\"\n]*\"|'[^'\n]*'|[^\r\n,;}\"'<]+)", 4, "<ssid>", "pii", None, None, True),
]
_EXTRA = [(n, re.compile(p), g, r, k, lb, rb, pii) for n, p, g, r, k, lb, rb, pii in _EXTRA_SPEC]
_LOCAL_TLDS = {"local", "lan", "home", "internal", "localdomain", "arpa", "localhost", "intranet"}


def _blocked(ch: str, extra: str | None) -> bool:
    return extra is not None and ch != "" and (ch in _WORD or ch in extra)


def _extra_ok(name: str, m: re.Match[str], g: int, t: str) -> bool:
    v = m.group(g)
    if name == "aws_secret":
        if not (any(ch.isupper() for ch in v) and any(ch.islower() for ch in v)
                and any(ch.isdigit() for ch in v) and ("/" in v or "+" in v)):
            return False
        ls = t.rfind("\n", 0, m.start()) + 1
        le = t.find("\n", m.end())
        line = t[ls:le if le >= 0 else len(t)].lower()
        return "aws" in line or "akia" in line or "asia" in line
    if name == "email":
        local = v.split("@", 1)[0]
        return local.lower() != "git" and m.group(1).lower() not in _LOCAL_TLDS
    if name == "user_pass_flag":
        return not (m.group(1).isdigit() and v.isdigit())  # -u 1000:1000 is uid:gid
    if name == "ssid":
        return v.strip().strip("'\"").strip() != ""
    return True


def _rep(name: str, rep: str, v: str) -> str:
    if rep == "=":
        return _mask_value(v)
    if v[:1] in "'\"" and len(v) >= 2 and v[-1] == v[0] and name in {"ssid", "serial"}:
        return f"{v[0]}{rep}{v[0]}"
    if name == "ssid":
        return rep + v[len(v.rstrip()):]
    return rep


def _before(text: str, i: int) -> str:
    return text[i - 1] if i > 0 else ""


def _after(text: str, j: int) -> str:
    return text[j] if j < len(text) else ""


def _sub(rx: re.Pattern[str], text: str, fn: Callable[[re.Match[str], str], str | None]) -> str:
    """Replace each match with fn(match, text); None keeps the original."""
    out, last = [], 0
    for m in rx.finditer(text):
        rep = fn(m, text)
        if rep is None:
            continue
        out.append(text[last:m.start()])
        out.append(rep)
        last = m.end()
    if not out:
        return text
    out.append(text[last:])
    return "".join(out)


def _is_placeholder(v: str) -> bool:
    v = v.strip("'\"")
    return len(v) >= 3 and v.startswith("<") and v.endswith(">")


def _mask_value(v: str) -> str:
    if v[:1] in "'\"" and len(v) >= 2 and v[-1] == v[0]:
        return f"{v[0]}<x>{v[0]}"
    return "<x>"


def ipv4_is_public(addr: str) -> bool | None:
    """True = redact, False = keep, None = not an IPv4 address."""
    parts = addr.split(".")
    if len(parts) != 4 or any(not p.isdigit() or int(p) > 255 for p in parts):
        return None
    a, b, c, d = (int(p) for p in parts)
    n = (a << 24) | (b << 16) | (c << 8) | d
    if a in (0, 10, 127):
        return False
    if (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if 224 <= a <= 239 or n == 0xFFFFFFFF:  # multicast, broadcast
        return False
    if a == 255:  # netmask shape: contiguous ones
        inv = (~n) & 0xFFFFFFFF
        if inv & (inv + 1) == 0:
            return False
    return True


def ipv6_is_global(addr: str) -> bool | None:
    try:
        ip = ipaddress.IPv6Address(addr.split("%", 1)[0])
    except ValueError:
        return None
    return (int(ip) >> 125) == 0b001  # 2000::/3 global unicast; ::1, fe80::/10, fc00::/7 etc. kept


class Redactor:
    def __init__(self, enabled: bool = True, domains: list[str] | None = None,
                 secrets: list[str] | None = None, pii: bool = True) -> None:
        self.enabled = enabled
        self.pii = pii
        # exact secret values this server knows (its own access token, tunnel token): always masked
        self._secrets = sorted({x for x in (secrets or []) if len(x) >= 12}, key=len, reverse=True)
        suffixes = sorted({d.strip().strip(".").lower() for d in (domains or []) if d.strip().strip(".")},
                          key=len, reverse=True)
        self._domain = (re.compile(r"(?i)(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(map(re.escape, suffixes)) + ")")
                        if suffixes else None)

    # ------------------------------------------------------------------ text
    def text(self, text: str, counts: Counter | None = None) -> tuple[str, Counter]:
        c = counts if counts is not None else Counter()
        if not self.enabled or not text:
            return text, c

        def hit(kind: str, rep: str) -> str:
            c[kind] += 1
            return rep

        text = _sub(_PEM, text, lambda m, t: hit("key", "<key>"))
        for sec in self._secrets:
            if sec in text:
                c["secret"] += text.count(sec)
                text = text.replace(sec, "<x>")
        text = self._extra(text, c)

        def kv(m: re.Match[str], t: str) -> str | None:
            prefix, name, value = m.group(1), m.group(2).lower(), m.group(4)
            # short/common names must be their own component (monkey= is not a key, wg_key= is)
            if prefix and prefix[-1] not in "_.-" and name in _NEED_SEP:
                return None
            if _before(t, m.start()) in _WORD | {".", "-"}:
                return None
            if _is_placeholder(value) or value in ("''", '""'):
                return None
            return hit("secret", m.group(1) + m.group(2) + m.group(3) + _mask_value(value))
        text = _sub(_KV, text, kv)

        def uci(m: re.Match[str], t: str) -> str | None:
            value = m.group(5)
            if _is_placeholder(value) or value in ("''", '""'):
                return None
            return hit("secret", "".join(m.group(1, 2, 3, 4)) + _mask_value(value))
        text = _sub(_UCI, text, uci)
        text = _sub(_BEARER, text, lambda m, t: None if _is_placeholder(m.group(3))
                    else hit("secret", m.group(1) + m.group(2) + "<x>"))

        def jwt(m: re.Match[str], t: str) -> str | None:
            if _before(t, m.start()) in _WORD | {"-"}:
                return None
            return hit("token", "<token>")
        text = _sub(_JWT, text, jwt)

        if self._domain is not None:
            def dom(m: re.Match[str], t: str) -> str | None:
                b, a = _before(t, m.start()), _after(t, m.end())
                if b in _ALNUM | {".", "-", "_"} or a in _WORD | {"-"}:
                    return None
                if a == "." and _after(t, m.end() + 1) in _ALNUM:
                    return None
                return hit("domain", "<domain>")
            text = _sub(self._domain, text, dom)

        def uuid(m: re.Match[str], t: str) -> str | None:
            if _before(t, m.start()) in _WORD | {"-"} or _after(t, m.end()) in _WORD | {"-"}:
                return None
            return hit("uuid", "<uuid>")
        text = _sub(_UUID, text, uuid)

        def ip4(m: re.Match[str], t: str) -> str | None:
            if _before(t, m.start()) in _ALNUM | {".", "_"}:
                return None
            a = _after(t, m.end())
            if a == "." and _after(t, m.end() + 1) in "0123456789" and _after(t, m.end() + 1):
                # tcpdump-style a.b.c.d.port: a 2-5 digit port (<= 65535), then a non-word, non-dot boundary
                j = m.end() + 1
                while j < len(t) and t[j].isdigit():
                    j += 1
                port = t[m.end() + 1:j]
                if not 2 <= len(port) <= 5 or int(port) > 65535 or _after(t, j) in _ALNUM | {"."}:
                    return None
            elif a in _ALNUM:
                return None
            # version strings: 5.15.153.1-microsoft, "version 1.2.3.4", "ver: 1.0.0.12"
            if a == "-" and _after(t, m.end() + 1).isascii() and _after(t, m.end() + 1).isalpha():
                return None
            if _VERSION_CTX.search(t[max(0, m.start() - 24):m.start()]):
                return None
            return hit("ip", "<ip>") if ipv4_is_public(m.group()) else None
        text = _sub(_IPV4, text, ip4)

        def ip4_prefix(m: re.Match[str], t: str) -> str | None:
            s = m.group()
            if _before(t, m.start()) in _ALNUM | {"."}:
                return None
            a = _after(t, m.end())
            if a in _ALNUM or a in ("*", "/") or (a == "." and _after(t, m.end() + 1).isdigit()):
                return None
            core, _, cidr = s.partition("/")
            trailing = core.endswith(".")
            parts = core.rstrip(".").split(".")
            nums = [p for p in parts if p.isdigit()]
            wild = len(parts) - len(nums)
            if parts[:len(nums)] != nums or len(parts) > 4 or any(int(p) > 255 for p in nums):
                return None
            if cidr and (int(cidr) > 32 or len(nums) != 3 or wild or trailing):
                return None
            n = len(nums)
            if not ((n == 3 and (trailing or wild or cidr)) or (n == 2 and wild)):
                return None
            if _VERSION_CTX.search(t[max(0, m.start() - 24):m.start()]):
                return None
            if not ipv4_is_public(".".join(nums + ["0"] * (4 - n))):
                return None
            return hit("ip", "<ip>") + s[len(".".join(nums)):]
        text = _sub(_IPV4_PREFIX, text, ip4_prefix)

        def ip4_underscore(m: re.Match[str], t: str) -> str | None:
            s = m.group()
            b, a = _before(t, m.start()), _after(t, m.end())
            if b in _ALNUM or a in _ALNUM:
                return None
            if (b == "_" and _before(t, m.start() - 1).isdigit()) or (a == "_" and _after(t, m.end() + 1).isdigit()):
                return None
            nums = s.split("_")
            if any(int(p) > 255 for p in nums) or len(s) - len(nums) + 1 < 5:
                return None
            if not ipv4_is_public(".".join(nums + ["0"] * (4 - len(nums)))):
                return None
            return hit("ip", "<ip>")
        text = _sub(_IPV4_UNDERSCORE, text, ip4_underscore)

        def ip6(m: re.Match[str], t: str) -> str | None:
            cand, start = m.group(), m.start()
            if _after(t, m.end()) in _WORD:
                return None
            core, port = cand, ""
            whole = ipv6_is_global(core)
            if whole is None:
                pm = _IPV6_PORT.match(cand)  # netstat style "2001:db8::1:443"
                if pm and ipv6_is_global(pm.group(1)) is not None:
                    core, port = pm.group(1), ":" + pm.group(2)
                    whole = ipv6_is_global(core)
            boundary_ok = _before(t, start) not in _WORD | {":", "."}
            if boundary_ok and whole:
                return hit("ipv6", "<ipv6>") + port
            if boundary_ok and whole is not None:
                return None  # a complete non-global address such as fd12:3456::9
            # "label:2001:db8::1" - try the part after each single colon
            for i, ch in enumerate(cand):
                if ch != ":" or i + 1 >= len(cand) or cand[i + 1] == ":" or (i > 0 and cand[i - 1] == ":"):
                    continue
                rest = cand[i + 1:]
                if ("::" in rest or rest.count(":") == 7) and ipv6_is_global(rest):
                    return cand[:i + 1] + hit("ipv6", "<ipv6>")
            if _IPV6_LOOKS_GLOBAL.search(cand):
                return hit("ipv6", "<ipv6>")
            return None
        text = _sub(_IPV6, text, ip6)

        def label_colon(t: str, i: int) -> bool:
            """t[i-1] is ':'; True when it ends a label such as 'Sta:' rather than a hex chain."""
            j = i - 1
            while j > 0 and t[j - 1] in _ALNUM:
                j -= 1
            seg = t[j:i - 1]
            return bool(seg) and not all(ch in "0123456789abcdefABCDEF" for ch in seg) and _before(t, j) != ":"

        def mac(m: re.Match[str], t: str) -> str | None:
            edge = _WORD | {":", "-", "."}
            b = _before(t, m.start())
            if (b in edge and not (b == ":" and label_colon(t, m.start()))) or _after(t, m.end()) in edge:
                return None
            hexits = re.sub(r"[^0-9A-Fa-f]", "", m.group()).lower()
            if hexits in ("000000000000", "ffffffffffff"):
                return None
            return hit("mac", "<mac>")
        text = _sub(_MAC, text, mac)

        def bridge(m: re.Match[str], t: str) -> str | None:
            edge = _WORD | {":", "-", "."}
            if _before(t, m.start()) in edge or _after(t, m.end()) in edge:
                return None
            if m.group()[5:].lower() in ("000000000000", "ffffffffffff"):
                return None
            return m.group()[:5] + hit("mac", "<mac>")
        text = _sub(_BRIDGE_ID, text, bridge)

        def run(m: re.Match[str], t: str) -> str | None:
            s = m.group()
            if len(s) == 44 and _B64.fullmatch(s):
                return hit("key", "<key>")
            core = s.rstrip("=")
            if (len(core) >= 60 and not core.startswith("/") and core.count("/") <= 3
                    and any(ch.isupper() for ch in core) and any(ch.islower() for ch in core)
                    and any(ch.isdigit() for ch in core)):
                return hit("token", "<token>")
            return None
        text = _sub(_RUN, text, run)
        return text, c

    def _extra(self, text: str, c: Counter) -> str:
        for name, rx, g, rep, kind, lb, rb, pii in _EXTRA:
            if pii and not self.pii:
                continue

            def fn(m: re.Match[str], t: str, name=name, g=g, rep=rep, kind=kind, lb=lb, rb=rb) -> str | None:
                v = m.group(g)
                if not v or _is_placeholder(v):
                    return None
                if _blocked(_before(t, m.start(g)), lb) or _blocked(_after(t, m.end(g)), rb):
                    return None
                if not _extra_ok(name, m, g, t):
                    return None
                c[kind] += 1
                return t[m.start():m.start(g)] + _rep(name, rep, v) + t[m.end(g):m.end()]
            text = _sub(rx, text, fn)
        return text

    # --------------------------------------------------------------- objects
    def value(self, obj: Any, counts: Counter | None = None) -> tuple[Any, Counter]:
        c = counts if counts is not None else Counter()
        if not self.enabled:
            return obj, c
        if isinstance(obj, str):
            return self.text(obj, c)[0], c
        if isinstance(obj, dict):
            return {k: self.value(v, c)[0] for k, v in obj.items()}, c
        if isinstance(obj, (list, tuple)):
            return [self.value(v, c)[0] for v in obj], c
        return obj, c


def footer(counts: Counter) -> str:
    parts = [f"{k}={counts[k]}" for k in ORDER if counts.get(k)]
    return f"[redacted: {' '.join(parts)}]" if parts else ""
