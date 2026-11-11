"""Linux desktop tools of the Rust build against a virtual X server (Xvfb + xdotool + wmctrl)."""
import base64
import json
import os
import shutil
import subprocess
import time

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from test_e2e import BIN, TOKEN, _free_port

pytestmark = pytest.mark.skipif(not BIN or not all(shutil.which(x) for x in ("Xvfb", "xdotool", "import")),
                                reason="needs SHELLGATE_BIN, Xvfb, xdotool and imagemagick")


@pytest.fixture(scope="module")
def desk(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("desk")
    disp = ":97"
    xvfb = subprocess.Popen(["Xvfb", disp, "-screen", "0", "800x600x24", "-nolisten", "tcp", "-noreset"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    port = _free_port()
    env = dict(os.environ, SHELLGATE_TOKEN=TOKEN, SHELLGATE_PORT=str(port), SHELLGATE_DESKTOP="1",
               SHELLGATE_ENV_FILE=str(tmp / "env"), SHELLGATE_STATE_DIR=str(tmp / "state"),
               SHELLGATE_ALLOWED_DIRS=str(tmp), DISPLAY=disp)
    env.pop("WAYLAND_DISPLAY", None)
    proc = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if httpx.get(url + "/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    yield url, disp
    proc.terminate()
    xvfb.terminate()


async def _call(url, name, **args):
    async with streamablehttp_client(url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(name, args)
            return json.loads(res.content[0].text), res.content[1:]


async def test_listed(desk):
    url, _ = desk
    async with streamablehttp_client(url + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
    assert {"desktop_screenshot", "desktop_input", "desktop_windows"} <= names and "desktop_tree" not in names


async def test_screenshot(desk):
    url, _ = desk
    r, extra = await _call(url, "desktop_screenshot", only_if_changed=False)
    assert r["changed"] is True and r["width"] == 800 and r["height"] == 600
    assert extra and base64.b64decode(extra[0].data)[:4] == b"\x89PNG"
    again, _ = await _call(url, "desktop_screenshot")
    assert again["changed"] is False
    part, _ = await _call(url, "desktop_screenshot", region=[10, 20, 100, 50], only_if_changed=False)
    assert part["width"] == 100 and part["height"] == 50 and part["origin"] == [10, 20]


async def test_input_moves_mouse(desk):
    url, disp = desk
    r, _ = await _call(url, "desktop_input", coords="physical",
                       actions=[{"type": "move", "x": 123, "y": 45}, {"type": "wait", "ms": 50}, {"type": "key", "keys": "shift"}])
    assert r["status"] == "ok" and r["done"] == 3
    # Xvfb resets (pointer back to the centre) when its last client disconnects, hence -noreset above
    loc = subprocess.run(["xdotool", "getmouselocation"], env={**os.environ, "DISPLAY": disp},
                         capture_output=True, text=True, timeout=10).stdout
    assert loc.startswith("x:123 y:45"), loc


async def test_risky_combo_needs_confirm(desk):
    url, _ = desk
    r, _ = await _call(url, "desktop_input", actions=[{"type": "key", "keys": "alt+f4"}])
    assert r["status"] == "confirmation_required"


async def test_tree_not_available(desk):
    url, _ = desk
    r, _ = await _call(url, "desktop_tree")
    assert r["status"] == "error" and "Linux" in r["error"]
