"""Rescue-stick features of the Rust build: config auto-discovery on the Ventoy partition,
lan / tunnel network modes and the ventoy_* tools. Runs only against SHELLGATE_BIN."""
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BIN = os.environ.get("SHELLGATE_BIN")
pytestmark = pytest.mark.skipif(not BIN, reason="Rust binary only (set SHELLGATE_BIN)")

# test-only value generated per run; never a real credential
TOKEN = hashlib.sha256(os.urandom(16)).hexdigest()[:48]

for _k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start(env, log):
    proc = subprocess.Popen([BIN], env=env, stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{env['SHELLGATE_PORT']}"
    for _ in range(50):
        try:
            if httpx.get(url + "/health").status_code == 200:
                return proc, url
        except httpx.HTTPError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError(open(log.name).read())


@pytest.fixture(scope="module")
def files_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("www")
    (d / "tiny.iso").write_bytes(b"ISO" * 100000)
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(d), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hashlib.sha256((d / "tiny.iso").read_bytes()).hexdigest()
    srv.shutdown()


@pytest.fixture(scope="module")
def lan_server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("vt")
    root = tmp / "ventoy"
    (root / "shellgate").mkdir(parents=True)
    # the whole config: token + network mode, found automatically under <Ventoy>/shellgate/
    (root / "shellgate" / "shellgate.env").write_text(f"token={TOKEN}\nnet=lan\nmdns=0\n")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHELLGATE_")}
    env.update(VENTOY_ROOT=str(root), SHELLGATE_PORT=str(port), SHELLGATE_STATE_DIR=str(tmp / "state"),
               SHELLGATE_ALLOWED_DIRS=str(tmp))
    log = open(tmp / "server.log", "w")
    proc, url = _start(env, log)
    yield url, root, tmp
    proc.terminate()
    proc.wait(5)


async def _call(server_url, name, **args):
    async with streamablehttp_client(server_url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(name, args)
            return json.loads(res.content[0].text)


def test_lan_mode_binds_all_and_requires_token(lan_server):
    url, root, tmp = lan_server
    log = (tmp / "server.log").read_text()
    assert "net=lan" in log and "0.0.0.0" in log
    assert str(root / "shellgate" / "shellgate.env") in log
    assert httpx.post(url + "/mcp", json={}).status_code == 401
    # reachable on a non-loopback address too, still behind the token
    ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 9))
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    if ip and not ip.startswith("127."):
        port = url.rsplit(":", 1)[1]
        assert httpx.get(f"http://{ip}:{port}/health").status_code == 200
        assert httpx.post(f"http://{ip}:{port}/mcp", json={}).status_code == 401


async def test_tools_listed(lan_server):
    url, *_ = lan_server
    async with streamablehttp_client(url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
    assert {"ventoy_info", "ventoy_list", "ventoy_add", "ventoy_add_status", "ventoy_remove",
            "ventoy_config_get", "ventoy_config_set"} <= names


async def test_config_on_stick_is_protected(lan_server):
    url, root, _ = lan_server
    r = await _call(url, "read_file", path=str(root / "shellgate" / "shellgate.env"))
    assert r["status"] == "error" and "protected" in r["error"]
    assert TOKEN not in json.dumps(await _call(url, "audit_tail", n=50))


async def test_info_and_config(lan_server):
    url, root, _ = lan_server
    info = await _call(url, "ventoy_info")
    assert info["status"] == "ok" and info["root"] == str(root) and info["found_by"] == "config"
    assert info["ventoy_json_exists"] is False and info["total_bytes"] > 0
    bad = await _call(url, "ventoy_config_set", content="{broken")
    assert bad["status"] == "error" and not (root / "ventoy" / "ventoy.json").exists()
    ok1 = await _call(url, "ventoy_config_set", content='{"control": []}')
    assert ok1["status"] == "ok" and ok1["backup"] is None
    ok2 = await _call(url, "ventoy_config_set", content='{"control": [{"VTOY_DEFAULT_MENU_MODE": "1"}]}')
    assert ok2["backup"] and ".bak-" in ok2["backup"]
    assert open(ok2["backup"]).read() == '{"control": []}'
    got = await _call(url, "ventoy_config_get")
    assert got["valid_json"] is True and got["json"]["control"][0]["VTOY_DEFAULT_MENU_MODE"] == "1"
    assert (await _call(url, "ventoy_info"))["ventoy_json_exists"] is True


async def _wait(url, tid):
    for _ in range(100):
        st = await _call(url, "ventoy_add_status", task_id=tid)
        if st["status"] != "running":
            return st
        time.sleep(0.1)
    raise AssertionError("download did not finish")


async def test_add_list_remove(lan_server, files_server):
    url, root, _ = lan_server
    base, sha = files_server
    bad = await _call(url, "ventoy_add", url=base + "/tiny.iso", subdir="iso", filename="bad.iso", sha256="0" * 64)
    st = await _wait(url, bad["task_id"])
    assert st["status"] == "failed" and "sha256 mismatch" in st["error"]
    assert not (root / "iso" / "bad.iso").exists() and not list((root / "iso").glob("*.sgdownload"))

    r = await _call(url, "ventoy_add", url=base + "/tiny.iso", subdir="iso", sha256=sha.upper())
    st = await _wait(url, r["task_id"])
    assert st["status"] == "done" and st["sha256"] == sha and st["path"] == "iso/tiny.iso"
    assert (root / "iso" / "tiny.iso").stat().st_size == 300000

    again = await _call(url, "ventoy_add", url=base + "/tiny.iso", subdir="iso")
    assert again["status"] == "error" and "already exists" in again["error"]
    assert (await _call(url, "ventoy_add", url=base + "/x.exe"))["status"] == "error"
    assert (await _call(url, "ventoy_add", url="file:///etc/passwd"))["status"] == "error"
    assert (await _call(url, "ventoy_add", url=base + "/tiny.iso", subdir="../out"))["status"] == "error"

    lst = await _call(url, "ventoy_list")
    assert [i["path"] for i in lst["images"]] == ["iso/tiny.iso"] and lst["images"][0]["size_bytes"] == 300000

    assert (await _call(url, "ventoy_remove", path="../ventoy/iso/tiny.iso"))["status"] == "error"
    c = await _call(url, "ventoy_remove", path="iso/tiny.iso")
    assert c["status"] == "confirmation_required" and (root / "iso" / "tiny.iso").exists()
    wrong = await _call(url, "ventoy_remove", path="iso/tiny.iso", confirm_code="000000")
    assert wrong["status"] == "confirmation_required"
    c2 = await _call(url, "ventoy_remove", path="iso/tiny.iso")
    done = await _call(url, "ventoy_remove", path="iso/tiny.iso", confirm_code=c2["confirm_code"])
    assert done["status"] == "ok" and not (root / "iso" / "tiny.iso").exists()


def test_tunnel_mode_passes_token_by_env(tmp_path):
    """tunnel mode supervises cloudflared; the tunnel token goes in the environment, not argv."""
    fake = tmp_path / "cloudflared"
    out = tmp_path / "fake.out"
    fake.write_text(f"#!/bin/sh\necho \"args=$*\" > {out}\necho \"tok=${{TUNNEL_TOKEN:+set}}\" >> {out}\nsleep 30\n")
    fake.chmod(0o755)
    cfg = tmp_path / "cfg" / "shellgate.env"
    cfg.parent.mkdir()
    tunnel_value = "tunnel-" + hashlib.sha256(os.urandom(8)).hexdigest()  # dummy, test only
    cfg.write_text(f"token={TOKEN}\ntunnel_token={tunnel_value}\ncloudflared={fake}\n")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHELLGATE_")}
    env.update(SHELLGATE_ENV_FILE=str(cfg), SHELLGATE_PORT=str(port), SHELLGATE_STATE_DIR=str(tmp_path / "state"))
    log = open(tmp_path / "server.log", "w")
    proc, url = _start(env, log)
    try:
        for _ in range(50):
            if out.exists() and "tok=" in out.read_text():
                break
            time.sleep(0.1)
        text = out.read_text()
        assert "args=tunnel --no-autoupdate run" in text and "tok=set" in text
        assert tunnel_value not in text
        assert "net=tunnel" in (tmp_path / "server.log").read_text()
        assert "127.0.0.1" in (tmp_path / "server.log").read_text()
    finally:
        proc.terminate()
        proc.wait(5)


def test_refuses_missing_or_template_token(tmp_path):
    cfg = tmp_path / "shellgate.env"
    cfg.write_text("token=CHANGE_ME_CHANGE_ME_CHANGE_ME_CHANGE_ME\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHELLGATE_")}
    env.update(SHELLGATE_ENV_FILE=str(cfg), SHELLGATE_PORT=str(_free_port()))
    r = subprocess.run([BIN], env=env, capture_output=True, text=True, timeout=10)
    assert r.returncode == 2 and "template" in r.stderr
    cfg.write_text("# empty\n")
    r = subprocess.run([BIN], env=env, capture_output=True, text=True, timeout=10)
    assert r.returncode == 2


def test_init_config_and_gen_token(tmp_path):
    t = subprocess.run([BIN, "--gen-token"], capture_output=True, text=True).stdout.strip()
    assert len(t) == 48 and all(c in "0123456789abcdef" for c in t)
    p = tmp_path / "stick" / "shellgate" / "shellgate.env"
    r = subprocess.run([BIN, "--init-config", str(p)], capture_output=True, text=True)
    assert r.returncode == 0
    body = p.read_text()
    tok = [l for l in body.splitlines() if l.startswith("token=")][0][6:]
    assert len(tok) == 48 and tok in r.stdout
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    assert subprocess.run([BIN, "--init-config", str(p)], capture_output=True, text=True).returncode == 2


async def test_truncated_utf8_output_stays_utf8(lan_server):
    url, *_ = lan_server
    # 'a' + 40000 x "中" (120001 bytes): the default 100000-byte head/tail cut lands mid-character twice
    r = await _call(url, "run_command", command="printf a; yes 中 | tr -d '\\n' | head -c 120000")
    out = r["stdout"]
    assert r["exit_code"] == 0 and "[output truncated]" in out
    assert out.startswith("a中中") and out.endswith("中中") and out.count("\ufffd") == 2


async def test_job_survives_non_utf8_line(lan_server):
    url, *_ = lan_server
    j = await _call(url, "start_job", command="printf 'x\\377y\\n'; echo after")
    time.sleep(1)
    out = await _call(url, "job_output", job_id=j["job_id"])
    assert "after" in out["output"] and "x\ufffdy" in out["output"]
