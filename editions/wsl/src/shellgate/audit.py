"""Append-only JSON Lines audit log with size-based rotation."""
from __future__ import annotations

import json
import os
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any

client_ip: ContextVar[str] = ContextVar("client_ip", default="")

_MAX_FIELD = 2000


def _trim(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_FIELD:
        return value[:_MAX_FIELD] + f"...[{len(value)} chars]"
    if isinstance(value, dict):
        return {k: _trim(v) for k, v in value.items()}
    return value


class AuditLog:
    def __init__(self, path: str, max_bytes: int = 10_000_000, backups: int = 5) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

    def write(self, tool: str, args: dict[str, Any], result: str, duration_ms: int, **extra: Any) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "ip": client_ip.get(),
            "tool": tool,
            "args": _trim(args),
            "result": result,
            "duration_ms": duration_ms,
            **{k: _trim(v) for k, v in extra.items()},
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)

    def tail(self, n: int) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        return [json.loads(l) for l in lines if l.strip()]

    def _rotate(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_suffix(f".jsonl.{i}")
            if src.exists():
                src.rename(self.path.with_suffix(f".jsonl.{i + 1}"))
        self.path.rename(self.path.with_suffix(".jsonl.1"))
