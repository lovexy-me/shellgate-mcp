"""Start a real server and drive it with the official MCP client."""
import json
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402

TOKEN = "t" * 48
# Set SHELLGATE_BIN=/path/to/shellgate to run the same suite against the Rust (OpenWrt) build.
BIN = os.environ.get("SHELLGATE_BIN")

# Talk to the local server directly, never through a configured HTTP proxy.
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sg")
    work = tmp / "work"
    work.mkdir()
    port = _free_port()
    env = dict(os.environ, SHELLGATE_TOKEN=TOKEN, SHELLGATE_PORT=str(port),
               SHELLGATE_ENV_FILE=str(tmp / "cfg" / "env"),
               SHELLGATE_STATE_DIR=str(tmp / "state"),
               SHELLGATE_ALLOWED_DIRS=str(work))
    cmd = [BIN] if BIN else [sys.executable, "-m", "shellgate"]
    proc = subprocess.Popen(cmd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if httpx.get(url + "/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError(proc.stdout.read().decode())
    yield url, work, tmp
    proc.terminate()
    proc.wait(5)


def test_health_and_auth(server):
    url, *_ = server
    assert httpx.get(url + "/health").json()["status"] == "ok"
    assert httpx.post(url + "/mcp", json={}).status_code == 401
    assert httpx.post(url + "/mcp", json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401


async def _call(url, name, **args):
    async with streamablehttp_client(url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(name, args)
            return json.loads(res.content[0].text)


async def test_tools_listed(server):
    url, *_ = server
    async with streamablehttp_client(url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
    assert {"run_command", "start_job", "read_file", "edit_file", "system_info"} <= names
    if not BIN:
        assert "docker_ps" in names


async def test_run_command(server):
    url, work, _ = server
    r = await _call(url, "run_command", command="echo hello && pwd", cwd=str(work))
    assert r["exit_code"] == 0 and "hello" in r["stdout"] and str(work) in r["stdout"]


async def test_timeout(server):
    url, *_ = server
    r = await _call(url, "run_command", command="sleep 5", timeout=1)
    assert r["timed_out"] is True


async def test_confirmation_flow(server):
    url, work, _ = server
    (work / "junk").mkdir()
    r = await _call(url, "run_command", command="rm -rf junk", cwd=str(work))
    assert r["status"] == "confirmation_required" and (work / "junk").exists()
    bad = await _call(url, "run_command", command="rm -rf junk", cwd=str(work), confirm_code="000000")
    assert bad["status"] == "confirmation_required"
    ok = await _call(url, "run_command", command="rm -rf junk", cwd=str(work), confirm_code=r["confirm_code"])
    assert ok["exit_code"] == 0 and not (work / "junk").exists()


async def test_file_tools(server):
    url, work, _ = server
    f = str(work / "a.conf")
    assert (await _call(url, "write_file", path=f, content="PORT=1\n"))["status"] == "ok"
    e = await _call(url, "edit_file", path=f, old_string="PORT=1", new_string="PORT=2")
    assert e["status"] == "ok" and e["backup"]
    assert "PORT=2" in (await _call(url, "read_file", path=f))["content"]
    assert (await _call(url, "search_files", pattern="PORT", path=str(work)))["matches"]
    denied = await _call(url, "write_file", path="/etc/evil", content="x")
    assert denied["status"] == "error" and "outside allowed" in denied["error"]


async def test_protected_config(server):
    url, _, tmp = server
    (tmp / "cfg").mkdir(exist_ok=True)
    (tmp / "cfg" / "env").write_text("SHELLGATE_TOKEN=secret")
    r = await _call(url, "read_file", path=str(tmp / "cfg" / "env"))
    assert r["status"] == "error" and "protected" in r["error"]


async def test_jobs(server):
    url, *_ = server
    j = await _call(url, "start_job", command="for i in 1 2 3; do echo line$i; sleep 0.2; done; read x; echo got$x")
    jid = j["job_id"]
    time.sleep(1)
    await _call(url, "job_input", job_id=jid, data="42")
    time.sleep(0.5)
    out = await _call(url, "job_output", job_id=jid)
    assert "line3" in out["output"] and "got42" in out["output"] and out["status"] == "exited"
    assert any(x["job_id"] == jid for x in (await _call(url, "list_jobs"))["jobs"])


async def test_system_info_and_audit(server):
    url, *_ = server
    assert (await _call(url, "system_info"))["mem_mb"]["total"] > 0
    entries = (await _call(url, "audit_tail", n=50))["entries"]
    assert any(e["tool"] == "run_command" for e in entries)
