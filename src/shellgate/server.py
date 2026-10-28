"""ShellGate MCP server: token-protected shell and file tools over Streamable HTTP."""
from __future__ import annotations

import argparse
import asyncio
import functools
import hmac
import json
import os
import platform
import shutil
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import __version__
from .audit import AuditLog, client_ip
from .config import Settings, load_settings
from .policy import ConfirmStore, allowlist_violations, check_path, danger_reasons
from .runner import JobManager, run_once

INSTRUCTIONS = """\
ShellGate runs commands and edits files on the user's own Linux (WSL2) machine.
- Commands run as the service user in a fresh login shell; cwd and env do not persist between calls.
- Long tasks (builds, docker pulls, updates): use start_job, then poll job_output.
- If a tool answers status=confirmation_required, show the user the command and reasons,
  and only call again with confirm_code after the user explicitly agrees.
- Windows is reachable from WSL via powershell.exe / cmd.exe in run_command.
- Prefer read_file/edit_file over sed/cat for files under the allowed directories.
"""


def build_server(settings: Settings) -> tuple[FastMCP, AuditLog]:
    audit = AuditLog(settings.audit_log)
    confirms = ConfirmStore(settings.confirm_ttl)
    jobs = JobManager(settings)
    sem = asyncio.Semaphore(settings.max_concurrent)
    home = str(Path.home())

    mcp = FastMCP(
        "shellgate",
        instructions=INSTRUCTIONS,
        host=settings.host,
        port=settings.port,
        stateless_http=True,
        # Every request needs the bearer token, which a DNS-rebinding page can't supply,
        # and the tunnel hostname varies per install, so Host-header pinning is off.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    def audited(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                result = await fn(*args, **kwargs)
                status = result.get("status", "ok") if isinstance(result, dict) else "ok"
                extra = {}
                if isinstance(result, dict) and "exit_code" in result:
                    extra["exit_code"] = result["exit_code"]
                audit.write(fn.__name__, kwargs, status, int((time.monotonic() - start) * 1000), **extra)
                return result
            except Exception as e:  # noqa: BLE001 - report every failure to the client and audit
                audit.write(fn.__name__, kwargs, "error", int((time.monotonic() - start) * 1000),
                            error=f"{type(e).__name__}: {e}")
                return {"status": "error", "error": f"{type(e).__name__}: {e}"}
        return wrapper

    def resolve_cwd(cwd: str | None) -> str:
        path = Path(os.path.expanduser(cwd or home))
        if not path.is_dir():
            raise FileNotFoundError(f"cwd does not exist: {path}")
        return str(path.resolve())

    def gate(kind: str, command: str, cwd: str, confirm_code: str | None) -> dict | None:
        """Return a refusal/confirmation dict, or None when the command may run."""
        violations = allowlist_violations(command, settings)
        if violations:
            return {"status": "denied", "reasons": violations}
        reasons = danger_reasons(command, settings)
        if not reasons:
            return None
        fp = confirms.fingerprint(kind, command, cwd)
        if confirms.redeem(confirm_code, fp):
            return None
        return {
            "status": "confirmation_required",
            "reasons": reasons,
            "command": command,
            "cwd": cwd,
            "confirm_code": confirms.issue(fp),
            "expires_in_s": settings.confirm_ttl,
            "next": "Ask the user. Only if they explicitly agree, call again with the same "
                    "command, cwd and this confirm_code.",
        }

    # ------------------------------------------------------------------ commands
    @mcp.tool()
    @audited
    async def run_command(command: str, cwd: str | None = None, timeout: int | None = None,
                          confirm_code: str | None = None) -> dict:
        """Run a shell command (bash -lc) and wait for it. Returns exit_code, stdout, stderr.

        timeout is in seconds (default 60, max 600). For longer work use start_job.
        """
        wd = resolve_cwd(cwd)
        if (blocked := gate("run", command, wd, confirm_code)):
            return blocked
        t = max(1, min(timeout or settings.default_timeout, settings.max_timeout))
        return {"status": "ok", **await run_once(command, wd, t, settings, sem)}

    @mcp.tool()
    @audited
    async def start_job(command: str, cwd: str | None = None, confirm_code: str | None = None) -> dict:
        """Start a long-running command in the background. Returns job_id; poll with job_output."""
        wd = resolve_cwd(cwd)
        if (blocked := gate("job", command, wd, confirm_code)):
            return blocked
        job = await jobs.start(command, wd)
        return {"status": "ok", **job.summary()}

    @mcp.tool()
    @audited
    async def job_output(job_id: str, tail: int = 100) -> dict:
        """Return a background job's status and the last `tail` lines of output (max 2000)."""
        job = jobs.get(job_id)
        tail = max(1, min(tail, 2000))
        return {"status": "ok", **job.summary(), "output": "\n".join(list(job.lines)[-tail:])}

    @mcp.tool()
    @audited
    async def job_input(job_id: str, data: str, newline: bool = True) -> dict:
        """Write text to a running job's stdin (e.g. answer a prompt)."""
        await jobs.write_stdin(job_id, data, newline)
        return {"status": "ok"}

    @mcp.tool()
    @audited
    async def list_jobs() -> dict:
        """List background jobs."""
        return {"status": "ok", "jobs": [j.summary() for j in jobs.jobs.values()]}

    @mcp.tool()
    @audited
    async def cancel_job(job_id: str) -> dict:
        """Stop a background job (SIGTERM, then SIGKILL)."""
        job = await jobs.cancel(job_id)
        return {"status": "ok", **job.summary()}

    # --------------------------------------------------------------------- files
    @mcp.tool()
    @audited
    async def read_file(path: str, offset: int = 1, limit: int = 500) -> dict:
        """Read a text file with line numbers. offset is 1-based; limit max 5000 lines."""
        p = check_path(path, settings)
        limit = max(1, min(limit, 5000))
        with open(p, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(offset, 1) - 1
        chunk = lines[start:start + limit]
        body = "".join(f"{i:>6}\t{l[:4000]}" for i, l in enumerate(chunk, start + 1))
        return {"status": "ok", "path": p, "total_lines": len(lines),
                "truncated": start + limit < len(lines), "content": body}

    def _backup(p: str) -> str | None:
        if settings.backup_on_write and os.path.isfile(p):
            bak = f"{p}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(p, bak)
            return bak
        return None

    @mcp.tool()
    @audited
    async def write_file(path: str, content: str, append: bool = False) -> dict:
        """Create, overwrite or append to a file in an allowed directory. Overwrites keep a .bak copy."""
        p = check_path(path, settings, write=True)
        if len(content.encode()) > 10_000_000:
            raise ValueError("content larger than 10 MB")
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        bak = None if append else _backup(p)
        with open(p, "a" if append else "w", encoding="utf-8") as f:
            f.write(content)
        return {"status": "ok", "path": p, "bytes": len(content.encode()), "backup": bak}

    @mcp.tool()
    @audited
    async def edit_file(path: str, old_string: str, new_string: str, replace_all: bool = False) -> dict:
        """Replace exact text in a file. old_string must be unique unless replace_all. Keeps a .bak copy."""
        p = check_path(path, settings, write=True)
        text = Path(p).read_text(encoding="utf-8")
        count = text.count(old_string)
        if count == 0:
            raise ValueError("old_string not found")
        if count > 1 and not replace_all:
            raise ValueError(f"old_string matches {count} times; add context or set replace_all")
        bak = _backup(p)
        Path(p).write_text(text.replace(old_string, new_string) if replace_all
                           else text.replace(old_string, new_string, 1), encoding="utf-8")
        return {"status": "ok", "path": p, "replacements": count if replace_all else 1, "backup": bak}

    @mcp.tool()
    @audited
    async def list_dir(path: str, show_hidden: bool = False) -> dict:
        """List a directory: name, type, size, modified time."""
        p = check_path(path, settings)
        entries = []
        for e in sorted(os.scandir(p), key=lambda e: e.name):
            if not show_hidden and e.name.startswith("."):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            entries.append({
                "name": e.name,
                "type": "dir" if e.is_dir(follow_symlinks=False) else "link" if e.is_symlink() else "file",
                "size": st.st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            })
            if len(entries) >= 1000:
                break
        return {"status": "ok", "path": p, "entries": entries}

    @mcp.tool()
    @audited
    async def search_files(pattern: str, path: str, glob: str | None = None, max_results: int = 200) -> dict:
        """Search file contents for a regex (ripgrep when installed). Returns file:line:text matches."""
        p = check_path(path, settings)
        max_results = max(1, min(max_results, 2000))
        if shutil.which("rg"):
            args = ["rg", "-n", "--no-heading", "--max-columns", "300", "-m", "50", pattern, p]
            for prot in settings.protected_paths:
                args[1:1] = ["--glob", f"!{prot}/**"]
            if glob:
                args[1:1] = ["--glob", glob]
            proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.DEVNULL)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), 60)
            except asyncio.TimeoutError:
                proc.kill()
                raise TimeoutError("search took longer than 60s; narrow the path")
            lines = out.decode(errors="replace").splitlines()
        else:
            import re
            rx, lines = re.compile(pattern), []
            for root, _, files in os.walk(p):
                for name in files:
                    if glob and not Path(name).match(glob):
                        continue
                    fp = os.path.join(root, name)
                    try:
                        check_path(fp, settings)
                        with open(fp, encoding="utf-8", errors="ignore") as f:
                            for n, l in enumerate(f, 1):
                                if rx.search(l):
                                    lines.append(f"{fp}:{n}:{l.rstrip()[:300]}")
                    except (OSError, PermissionError, ValueError):
                        continue
                    if len(lines) >= max_results:
                        break
        return {"status": "ok", "matches": lines[:max_results], "truncated": len(lines) > max_results}

    # -------------------------------------------------------------------- system
    @mcp.tool()
    @audited
    async def system_info() -> dict:
        """Host overview: OS, kernel, uptime, load, memory, disk usage, WSL detection."""
        info: dict[str, Any] = {"status": "ok", "hostname": platform.node(), "kernel": platform.release(),
                                "wsl": "microsoft" in platform.release().lower()}
        try:
            info["os"] = dict(l.split("=", 1) for l in Path("/etc/os-release").read_text().splitlines()
                              if "=" in l).get("PRETTY_NAME", "").strip('"')
            info["uptime_h"] = round(float(Path("/proc/uptime").read_text().split()[0]) / 3600, 1)
            info["load"] = os.getloadavg()
            mem = {l.split(":")[0]: int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines()}
            info["mem_mb"] = {"total": mem["MemTotal"] // 1024, "available": mem["MemAvailable"] // 1024,
                              "swap_free": mem.get("SwapFree", 0) // 1024}
        except OSError:
            pass
        du = shutil.disk_usage("/")
        info["disk_root_gb"] = {"total": round(du.total / 1e9, 1), "free": round(du.free / 1e9, 1)}
        return info

    async def _docker(*args: str, timeout: int = 60) -> dict:
        if not shutil.which("docker"):
            raise FileNotFoundError("docker CLI not found")
        async with sem:
            proc = await asyncio.create_subprocess_exec("docker", *args, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout)
            except asyncio.TimeoutError:
                proc.kill()
                raise TimeoutError(f"docker {args[0]} timed out")
        return {"exit_code": proc.returncode, "stdout": out.decode(errors="replace")[-settings.max_output_bytes:],
                "stderr": err.decode(errors="replace")[-5000:]}

    @mcp.tool()
    @audited
    async def docker_ps(all: bool = False) -> dict:
        """List Docker containers with status, image and ports."""
        r = await _docker("ps", *(["-a"] if all else []), "--format", "{{json .}}")
        rows = [json.loads(l) for l in r["stdout"].splitlines() if l.strip()]
        keep = ("Names", "Image", "State", "Status", "Ports")
        return {"status": "ok", "containers": [{k: row.get(k) for k in keep} for row in rows],
                "stderr": r["stderr"]}

    @mcp.tool()
    @audited
    async def docker_logs(container: str, tail: int = 200, since: str | None = None) -> dict:
        """Show a container's recent logs. since accepts e.g. '10m', '2h'."""
        args = ["logs", "--tail", str(max(1, min(tail, 5000)))]
        if since:
            args += ["--since", since]
        r = await _docker(*args, "--", container)
        return {"status": "ok", "exit_code": r["exit_code"], "logs": r["stdout"] + r["stderr"]}

    @mcp.tool()
    @audited
    async def docker_restart(container: str) -> dict:
        """Restart a container."""
        r = await _docker("restart", "--", container, timeout=120)
        return {"status": "ok", **r}

    @mcp.tool()
    @audited
    async def docker_stats() -> dict:
        """One-shot CPU / memory usage per running container."""
        r = await _docker("stats", "--no-stream", "--format", "{{json .}}")
        rows = [json.loads(l) for l in r["stdout"].splitlines() if l.strip()]
        keep = ("Name", "CPUPerc", "MemUsage", "MemPerc")
        return {"status": "ok", "stats": [{k: row.get(k) for k in keep} for row in rows]}

    @mcp.tool()
    @audited
    async def audit_tail(n: int = 20) -> dict:
        """Show the last n audit log entries (what was run through ShellGate)."""
        return {"status": "ok", "entries": audit.tail(max(1, min(n, 200)))}

    return mcp, audit


class BearerAuth:
    """Pure ASGI middleware: /health is open; everything else needs the bearer token."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        ip = headers.get(b"cf-connecting-ip", b"").decode() or (scope.get("client") or ("", 0))[0]
        client_ip.set(ip)
        if scope["path"] == "/health":
            return await self._json(send, 200, {"status": "ok", "service": "shellgate", "version": __version__})
        supplied = headers.get(b"authorization", b"")
        if not hmac.compare_digest(supplied, self.expected):
            return await self._json(send, 401, {"error": "unauthorized"},
                                    extra=[(b"www-authenticate", b'Bearer realm="shellgate"')])
        return await self.app(scope, receive, send)

    @staticmethod
    async def _json(send, status: int, body: dict, extra: list | None = None) -> None:
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(data)).encode())] + (extra or [])})
        await send({"type": "http.response.body", "body": data})


def create_app(settings: Settings):
    mcp, _ = build_server(settings)
    return BearerAuth(mcp.streamable_http_app(), settings.token)


def main() -> None:
    parser = argparse.ArgumentParser(prog="shellgate", description="ShellGate MCP server")
    parser.add_argument("--env-file", help="path to env file (default ~/.config/shellgate/env)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()
    settings = load_settings(args.env_file)
    if settings.host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"WARNING: listening on {settings.host}; prefer 127.0.0.1 behind a tunnel.")
    import uvicorn
    print(f"ShellGate {__version__} on http://{settings.host}:{settings.port}/mcp "
          f"(mode={settings.mode}, audit={settings.audit_log})")
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port,
                log_level="warning", proxy_headers=False)


if __name__ == "__main__":
    main()
