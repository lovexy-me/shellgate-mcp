"""Redaction rules. Addresses use documentation ranges (RFC 5737 / RFC 3849) and example.* domains."""
import pytest

from shellgate.redact import Redactor, footer

R = Redactor(True, ["example.org", ".example.net"])


def red(text):
    out, counts = R.text(text)
    return out, footer(counts)


def test_ipv4_per_token_private_and_public_same_line():
    out, f = red("src 192.168.1.10 dst 203.0.113.7 via 10.0.0.1 nat 198.51.100.2/24 cgn 100.64.1.1")
    assert out == "src 192.168.1.10 dst <ip> via 10.0.0.1 nat <ip>/24 cgn 100.64.1.1"
    assert f == "[redacted: ip=2]"


@pytest.mark.parametrize("keep", ["127.0.0.1", "172.16.5.4", "172.31.255.1", "169.254.1.1", "0.0.0.0",
                                  "255.255.255.0", "255.255.255.255", "224.0.0.251"])
def test_ipv4_kept(keep):
    assert red(f"addr {keep}:80")[0] == f"addr {keep}:80"


def test_ipv4_edges():
    assert red("172.32.0.1")[0] == "<ip>"                # just outside 172.16/12
    assert red("v1.2.3.4.5 and 999.1.1.1")[1] == ""      # not addresses
    assert red("peer=203.0.113.9:51820,")[0] == "peer=<ip>:51820,"


def test_ipv6():
    out, f = red("inet6 2001:db8::1/64 scope global\ninet6 fe80::1%eth0 ::1 fd12:3456::9 addr:2001:db8:0:1::5")
    assert out == "inet6 <ipv6>/64 scope global\ninet6 fe80::1%eth0 ::1 fd12:3456::9 addr:<ipv6>"
    assert f == "[redacted: ipv6=2]"
    assert red("at 12:34:56 and std::vector")[1] == ""
    assert red("ipv6:240e::1")[0] == "ipv6:<ipv6>"


def test_mac():
    out, f = red("link/ether 02:42:AC:11:00:02 brd ff:ff:ff:ff:ff:ff  hw 0A-1B-2C-3D-4E-5F")
    assert out == "link/ether <mac> brd ff:ff:ff:ff:ff:ff  hw <mac>"
    assert f == "[redacted: mac=2]"


def test_wireguard_key_and_tokens():
    key = "Q" * 42 + "E="
    out, f = red(f"peer: {key}\n  endpoint: 203.0.113.1:51820")
    assert out == "peer: <key>\n  endpoint: <ip>:51820" and "key=1" in f and "ip=1" in f
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX2hlcmU"
    assert red(f"jwt {jwt} ok")[0] == "jwt <token> ok"
    long_tok = "aZ9" * 21
    assert red(f"tok {long_tok}")[0] == "tok <token>"
    # paths, hex digests and short words survive
    plain = "/usr/lib/" + "a" * 80 + " sha256:" + "ab12" * 16
    assert red(plain)[0] == plain


def test_uuid():
    assert red("UUID=123e4567-e89b-12d3-a456-426614174000 type")[0] == "UUID=<uuid> type"


def test_domain_suffix():
    out, f = red("https://a.b.example.org/x user@Example.ORG host.example.net notexample.org example.org.cn")
    assert out == "https://<domain>/x user@<domain> <domain> notexample.org example.org.cn"
    assert f == "[redacted: domain=3]"
    assert Redactor(True, []).text("a.example.org")[0] == "a.example.org"


@pytest.mark.parametrize("src,want", [
    ("password=hunter2", "password=<x>"),
    ("DB_PASSWORD='p w'", "DB_PASSWORD='<x>'"),
    ('{"api_key": "abc", "token":""}', '{"api_key": "<x>", "token":""}'),
    ("Authorization: Bearer abc.def.ghi", "Authorization: <x>"),
    ("curl -H 'X: y' bearer abcdefgh12345", "curl -H 'X: y' bearer <x>"),
    ("PrivateKey = c2VjcmV0", "PrivateKey = <x>"),
    ("preshared_key: zzz", "preshared_key: <x>"),
    ("wireless.radio0.key='wifipass'", "wireless.radio0.key='<x>'"),
    ("\toption key 'wifipass'", "\toption key '<x>'"),
    ("monkey=1 tokens: 3 secret_name=a", "monkey=1 tokens: 3 secret_name=a"),
    ("mypassword: abc", "mypassword: <x>"),
])
def test_secrets(src, want):
    assert red(src)[0] == want


def test_pem_block():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----"
    assert red(f"x\n{pem}\ny")[0] == "x\n<key>\ny"


def test_idempotent_and_footer_only_when_needed():
    once, _ = red("ip 203.0.113.5 password=x mac 02:00:00:00:00:01")
    twice, f = red(once)
    assert once == twice and f == ""
    assert red("nothing to see")[1] == ""


def test_nested_values_and_disabled():
    obj, counts = R.value({"stdout": "203.0.113.1", "list": ["02:42:ac:11:00:02"], "n": 3})
    assert obj == {"stdout": "<ip>", "list": ["<mac>"], "n": 3}
    assert footer(counts) == "[redacted: ip=1 mac=1]"
    off = Redactor(False, ["example.org"])
    assert off.text("203.0.113.1 a.example.org")[0] == "203.0.113.1 a.example.org"


def test_version_strings_not_ip():
    from shellgate.redact import Redactor
    r = Redactor(True, [])
    v = "Linux version 5.15.153.1-microsoft-standard-WSL2, Version: 8.8.4.4, fw 1.1.1.1, ver=9.9.9.9"
    assert r.text(v)[0] == v
    assert r.text("dns 8.8.4.4 conversion 8.8.8.8")[0] == "dns <ip> conversion <ip>"
    assert r.text("range 8.8.8.8-9")[0] == "range <ip>-9"


def test_ipv6_with_port_and_fail_closed():
    from shellgate.redact import Redactor
    r = Redactor(True, [])
    t = ("tcp 2001:db8:1101:694c:319a:4f87:3571:dc00:25932 x\ntcp 2409:8a00:111f:40d0::1:53 y\n"
         "udp [2001:db8::5]:51820 z\nfd00::1:53 fe80::e2ef:2ff:fe56:df30:53")
    o = r.text(t)[0]
    assert "2001:db8" not in o and "2409:" not in o, o
    assert "<ipv6>:25932" in o
    assert "fd00::1:53" in o and "fe80::e2ef:2ff:fe56:df30:53" in o
    assert r.text("time 12:34:56 mac-ish c9:6d:d9:2e")[0] == "time 12:34:56 mac-ish c9:6d:d9:2e"


@pytest.mark.parametrize("src,want", [
    ('WHITELIST="192.168.1. 198.51.100. 172.16. 203.0.113."', 'WHITELIST="192.168.1. <ip>. 172.16. <ip>."'),
    ("allow 198.51.100.x and 203.0.113.* and 198.51.*.*", "allow <ip>.x and <ip>.* and <ip>.*.*"),
    ("src 198.51.100/24 lan 192.168.1/24", "src <ip>/24 lan 192.168.1/24"),
    ("option name 'Allow_198_51_100_Net_To_vlmcsd'", "option name 'Allow_<ip>_Net_To_vlmcsd'"),
    ('--comment "!fw4: from_203_0_113_7"', '--comment "!fw4: from_<ip>"'),
])
def test_ipv4_partial_prefixes_redacted(src, want):
    assert red(src)[0] == want


@pytest.mark.parametrize("keep", [
    "pkg 1.2.3.tar.gz", "openwrt-23.05.3", "version 22.03.5.", "v1.2.3.", "192.168.1.10 and 10.26.0.",
    "backup_20261029", "rule_1_2_3", "a_1_2_3_4_5_6", "255.255.255.", "ratio 1.5 and 3.14.",
    "100.64.1.", "file_v2_1_0", "1.2.3.4.5",
])
def test_ipv4_partial_prefixes_kept(keep):
    assert red(keep)[0] == keep


def test_mac_after_label_and_bridge_id():
    out, f = red("New Sta:02:42:ac:11:00:02 Del Sta:0a:1b:2c:3d:4e:5f\nbr-lan 7fff.0242ac110002 no eth0")
    assert out == "New Sta:<mac> Del Sta:<mac>\nbr-lan 7fff.<mac> no eth0"
    assert f == "[redacted: mac=3]"


@pytest.mark.parametrize("keep", [
    "key sha1!! c9:6d:d9:2e:73:f9:93:c3:c1:d9:8f:59:60:cc:7c:96:1d:36:59:a4 from x",
    "fe80::aa:bb:cc:dd:ee:ff", "x:aa:02:42:ac:11:00:02", "8000.000000000000", "sha 1234.0242ac110002abcd",
])
def test_mac_label_kept(keep):
    assert red(keep)[0] == keep
