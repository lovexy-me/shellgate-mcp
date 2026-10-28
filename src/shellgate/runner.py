"""Command execution: one-shot commands and background jobs."""
from __future__ import annotations

import asyncio
import os
import secrets
import signal
import time
from collections import deque
from dataclasses import dataclass, field

from .config import Settings


def _clip(data: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(data) > limit
    if truncated:
        # keep head and tail, which is where useful output usually is
        half = limit // 2
        data = data[:half] + b"\n...[output truncated]...\n" + data[-half:]
    return data.decode("utf-8", errors="replace"), truncated


async def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), 3)
        except asyncio.TimeoutError:
            os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


async def run_process(argv: list[str], cwd: str, timeout: int, settings: Settings, sem: asyncio.Semaphore,
                      stdin: str | None = None) -> dict:
    """Run argv in its own process group; stdin text (if any) is written then closed."""
    async with sem:
        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group so timeouts kill children too
        )
        timed_out = False

        async def feed() -> None:
            assert proc.stdin
            try:
                proc.stdin.write(stdin.encode())
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        writer = asyncio.create_task(feed()) if stdin is not None else None
        # read in tasks so output produced before a timeout is kept
        readers = [asyncio.create_task(proc.stdout.read()), asyncio.create_task(proc.stderr.read())]
        try:
            await asyncio.wait_for(proc.wait(), timeout)
        except asyncio.TimeoutError:
            timed_out = True
            await _kill_group(proc)
            await proc.wait()
        if writer:
            writer.cancel()
        try:
            out, err = await asyncio.wait_for(asyncio.gather(*readers), 5)
        except asyncio.TimeoutError:  # a grandchild escaped the group and holds the pipe open
            for r in readers:
                r.cancel()
            out, err = b"", b""
        stdout, t1 = _clip(out or b"", settings.max_output_bytes)
        stderr, t2 = _clip(err or b"", settings.max_output_bytes)
        return {
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "truncated": t1 or t2,
            "duration_ms": int((time.monotonic() - start) * 1000),
        }


async def run_once(command: str, cwd: str, timeout: int, settings: Settings, sem: asyncio.Semaphore,
                   stdin: str | None = None) -> dict:
    return await run_process([settings.shell, "-lc", command], cwd, timeout, settings, sem, stdin)


@dataclass
class Job:
    id: str
    command: str
    cwd: str
    proc: asyncio.subprocess.Process
    started: float = field(default_factory=time.time)
    lines: deque = field(default_factory=lambda: deque(maxlen=5000))
    finished: float | None = None
    reader: asyncio.Task | None = None

    @property
    def status(self) -> str:
        if self.proc.returncode is None:
            return "running"
        return "exited"

    def summary(self) -> dict:
        return {
            "job_id": self.id,
            "command": self.command,
            "cwd": self.cwd,
            "status": self.status,
            "exit_code": self.proc.returncode,
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started)),
            "runtime_s": round((self.finished or time.time()) - self.started, 1),
            "output_lines": len(self.lines),
        }


class JobManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.jobs: dict[str, Job] = {}

    def _prune(self) -> None:
        # forget finished jobs beyond the limit, oldest first
        done = sorted((j for j in self.jobs.values() if j.status != "running"), key=lambda j: j.started)
        while len(self.jobs) >= self.settings.max_jobs and done:
            self.jobs.pop(done.pop(0).id, None)

    async def start(self, command: str, cwd: str) -> Job:
        self._prune()
        running = sum(1 for j in self.jobs.values() if j.status == "running")
        if running >= self.settings.max_jobs:
            raise RuntimeError(f"too many running jobs ({running}); cancel one first")
        proc = await asyncio.create_subprocess_exec(
            self.settings.shell, "-lc", command,
            cwd=cwd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        job = Job(id=secrets.token_hex(4), command=command, cwd=cwd, proc=proc)
        job.reader = asyncio.create_task(self._read(job))
        self.jobs[job.id] = job
        return job

    async def _read(self, job: Job) -> None:
        assert job.proc.stdout
        async for raw in job.proc.stdout:
            job.lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))
        await job.proc.wait()
        job.finished = time.time()

    def get(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(f"unknown job_id: {job_id}")
        return job

    async def write_stdin(self, job_id: str, data: str, newline: bool) -> None:
        job = self.get(job_id)
        if job.status != "running" or not job.proc.stdin:
            raise RuntimeError("job is not running")
        job.proc.stdin.write((data + ("\n" if newline else "")).encode())
        await job.proc.stdin.drain()

    async def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job.status == "running":
            await _kill_group(job.proc)
        return job
