"""Guarded changes: snapshot files, run a command, and restore the files (then run a reload
command) unless the change is confirmed in time. Same design and on-disk format as
core/src/guard.rs: state in <state_dir>/guard/<id>/ (meta.json + copies), so a pending rollback
survives a ShellGate restart or a reboot (recover() re-arms it at startup)."""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

MAX_FILES = 20
MAX_FILE_BYTES = 5_000_000
MIN_TIMEOUT, MAX_TIMEOUT, DEFAULT_TIMEOUT = 15, 900, 120

_LOCK = threading.Lock()
_TASKS: set[asyncio.Task] = set()


def now() -> int:
    return int(time.time())


def root(state_dir: str) -> Path:
    return Path(state_dir) / "guard"


def read_meta(d: Path) -> dict:
    return json.loads((d / "meta.json").read_text())


def _write_meta(d: Path, m: dict) -> None:
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(m, indent=2))
    os.replace(tmp, d / "meta.json")


def snapshot(state_dir: str, files: list[str], command: str, reload: str, timeout: int) -> tuple[str, Path, dict]:
    if not files:
        raise ValueError("files: list the files the command changes (they are restored on rollback)")
    if len(files) > MAX_FILES:
        raise ValueError(f"at most {MAX_FILES} files")
    gid = f"g{now()}-{secrets.token_hex(2)}"
    d = root(state_dir) / gid
    root(state_dir).mkdir(parents=True, exist_ok=True)
    d.mkdir(mode=0o700)
    entries = []
    try:
        for i, f in enumerate(files):
            p = Path(f)
            if p.is_dir():
                raise ValueError(f"{f} is a directory; list files")
            existed = p.is_file()
            if existed:
                if p.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError(f"{f} is larger than 5 MB")
                shutil.copyfile(p, d / f"f{i}")
            entries.append({"path": f, "existed": existed, "backup": f"f{i}"})
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        raise
    meta = {"id": gid, "command": command, "reload": reload, "files": entries,
            "created": now(), "deadline": now() + timeout, "status": "pending"}
    _write_meta(d, meta)
    return gid, d, meta


def _read(path: str) -> bytes | None:
    try:
        return Path(path).read_bytes()
    except OSError:
        return None


def changed_files(d: Path, meta: dict) -> list[str]:
    out = []
    for f in meta.get("files", []):
        then = (d / f["backup"]).read_bytes() if f.get("existed") else None
        if _read(f["path"]) != then:
            out.append(f["path"])
    return out


def restore_files(d: Path, meta: dict) -> list[str]:
    restored, errors = [], []
    for f in meta.get("files", []):
        path = f["path"]
        if f.get("existed"):
            want = (d / f["backup"]).read_bytes()
            if _read(path) == want:
                continue
            tmp = path + ".sgguard"
            try:
                Path(tmp).write_bytes(want)
                try:
                    shutil.copymode(path, tmp)
                except OSError:
                    pass
                os.replace(tmp, path)
                restored.append(path)
            except OSError as e:
                Path(tmp).unlink(missing_ok=True)
                errors.append(f"{path}: {e}")
        elif Path(path).exists():
            try:
                Path(path).unlink()
                restored.append(path)
            except OSError as e:
                errors.append(f"{path}: {e}")
    if errors:
        raise OSError("; ".join(errors))
    return restored


def transition(d: Path, to: str) -> dict:
    with _LOCK:
        m = read_meta(d)
        if m.get("status") != "pending":
            raise ValueError(f"guard {m.get('id')} is already {m.get('status')}")
        before = dict(m)
        m["status"], m["closed"] = to, now()
        _write_meta(d, m)
        return before


async def rollback(d: Path, shell: str, why: str) -> dict:
    meta = transition(d, "rolling_back")
    try:
        restored: object = restore_files(d, meta)
        status = "rolled_back"
    except Exception as e:  # noqa: BLE001
        restored, status = {"error": str(e)}, "rollback_failed"
    reload_out = None
    if meta.get("reload"):
        try:
            p = await asyncio.create_subprocess_exec(shell, "-c", meta["reload"], stdin=asyncio.subprocess.DEVNULL,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            _, err = await asyncio.wait_for(p.communicate(), 90)
            reload_out = {"exit_code": p.returncode, "stderr": err.decode(errors="replace")[:2000]}
        except asyncio.TimeoutError:
            reload_out = {"error": "reload timed out after 90 s"}
        except OSError as e:
            reload_out = {"error": str(e)}
    result = {"why": why, "restored": restored, "reload": reload_out, "at": now()}
    with _LOCK:
        m = read_meta(d)
        m["status"], m["rollback"] = status, result
        _write_meta(d, m)
    return {"status": status, "id": meta["id"], "rollback": result}


def arm(d: Path, shell: str, deadline: int) -> None:
    async def wait() -> None:
        await asyncio.sleep(max(0, deadline - now()))
        try:
            if read_meta(d).get("status") == "pending":
                await rollback(d, shell, "deadline passed without guarded_confirm")
        except Exception as e:  # noqa: BLE001
            with _LOCK:
                try:
                    m = read_meta(d)
                    m["rollback_error"] = str(e)
                    _write_meta(d, m)
                except Exception:  # noqa: BLE001
                    pass
    t = asyncio.get_running_loop().create_task(wait())
    _TASKS.add(t)
    t.add_done_callback(_TASKS.discard)


def recover(state_dir: str, shell: str) -> int:
    """Re-arm pending guards (overdue ones roll back at once); drop closed ones older than 7 days."""
    n = 0
    base = root(state_dir)
    if not base.is_dir():
        return 0
    for d in base.iterdir():
        try:
            m = read_meta(d)
        except Exception:  # noqa: BLE001
            continue
        st = m.get("status")
        if st in ("pending", "rolling_back"):
            if st == "rolling_back":
                with _LOCK:
                    m["status"] = "pending"
                    _write_meta(d, m)
            arm(d, shell, 0 if st == "rolling_back" else int(m.get("deadline", 0)))
            n += 1
        elif int(m.get("created", 0)) + 7 * 86400 < now():
            shutil.rmtree(d, ignore_errors=True)
    return n


def find(state_dir: str, gid: str) -> Path:
    if not gid or not all(c.isalnum() or c == "-" for c in gid):
        raise ValueError("bad guard id")
    d = root(state_dir) / gid
    if not (d / "meta.json").is_file():
        raise FileNotFoundError(f"no guard {gid}")
    return d


def listing(state_dir: str) -> list[dict]:
    out = []
    base = root(state_dir)
    for d in base.iterdir() if base.is_dir() else []:
        try:
            m = read_meta(d)
        except Exception:  # noqa: BLE001
            continue
        out.append({"id": m.get("id"), "status": m.get("status"), "command": m.get("command"),
                    "deadline": m.get("deadline"),
                    "seconds_left": max(0, m.get("deadline", 0) - now()) if m.get("status") == "pending" else None})
    out.sort(key=lambda x: x["id"] or "", reverse=True)
    return out[:20]
