"""Safety policy: dangerous-command detection, one-time confirm codes, path rules."""
from __future__ import annotations

import hashlib
import re
import secrets
import shlex
import threading
import time
from pathlib import Path

from .config import Settings

# Patterns that need an explicit confirm code before running.
# These are guardrails, not a sandbox: a determined caller can obfuscate a command.
DANGER_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive|-r\b|-R\b)", "recursive delete"),
    (r"\bmkfs(\.\w+)?\b", "format filesystem"),
    (r"\bdd\b.*\bof=", "raw disk write"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "power state change"),
    (r"\bwsl(\.exe)?\s+--(shutdown|terminate|unregister)", "WSL shutdown/unregister"),
    (r":\(\)\s*\{.*\};\s*:", "fork bomb"),
    (r"\bchmod\s+(-R\s+)?[0-7]*777\s+/(\s|$)", "chmod 777 on /"),
    (r"\bchown\s+-R\b.*\s/(\s|$)", "recursive chown on /"),
    (r">\s*/dev/(sd|nvme|vd|hd)", "write to block device"),
    (r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b", "pipe download to shell"),
    (r"\bdocker\s+(system|volume|image|container|network)\s+prune\b", "docker prune"),
    (r"\bdocker\s+(rm|rmi|volume\s+rm)\b", "docker remove"),
    (r"\bdocker\s+compose\b.*\bdown\b.*(-v|--volumes)", "compose down with volumes"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "stop/disable service"),
    (r"\bkill(all)?\s+(-9\s+)?(-1|1)\b", "kill all/init"),
    (r"\bgit\s+push\b.*(--force|-f\b)", "force push"),
    (r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f)", "discard git changes"),
    (r"\btruncate\b", "truncate file"),
    (r"\b(userdel|passwd|visudo)\b", "account/sudo change"),
    (r"\biptables\b.*-(F|X)\b", "flush firewall"),
    (r"\bufw\s+(disable|reset)\b", "disable firewall"),
    (r"\bcrontab\s+-r\b", "delete crontab"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), why) for p, why in DANGER_PATTERNS]


def danger_reasons(command: str, settings: Settings) -> list[str]:
    reasons = [why for rx, why in _COMPILED if rx.search(command)]
    reasons += [f"custom pattern: {rx.pattern}" for rx in settings.danger_regexes if rx.search(command)]
    return reasons


_SPLIT_RE = re.compile(r"\|\||&&|;|\||\n|`|\$\(")


def allowlist_violations(command: str, settings: Settings) -> list[str]:
    """In allowlist mode every program in the pipeline must be allowlisted.

    Command substitution ($(...) and backticks) is refused outright in allowlist mode.
    """
    if settings.mode != "allowlist":
        return []
    if "`" in command or "$(" in command:
        return ["command substitution is not allowed in allowlist mode"]
    bad: list[str] = []
    for part in _SPLIT_RE.split(command):
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part)
        except ValueError:
            return ["could not parse command"]
        # skip leading VAR=value assignments and sudo
        while tokens and (re.match(r"^\w+=", tokens[0]) or tokens[0] == "sudo"):
            tokens = tokens[1:]
        if not tokens:
            continue
        prog = Path(tokens[0]).name
        if prog not in settings.allowed_commands:
            bad.append(prog)
    return [f"not in allowlist: {p}" for p in sorted(set(bad))]


class ConfirmStore:
    """One-time, short-lived codes bound to an exact action fingerprint."""

    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self._codes: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def fingerprint(*parts: object) -> str:
        return hashlib.sha256("\x00".join(map(str, parts)).encode()).hexdigest()

    def issue(self, fp: str) -> str:
        code = secrets.token_hex(3)
        with self._lock:
            self._purge()
            self._codes[code] = (fp, time.time() + self.ttl)
        return code

    def redeem(self, code: str | None, fp: str) -> bool:
        if not code:
            return False
        with self._lock:
            self._purge()
            entry = self._codes.get(code)
            if not entry or not secrets.compare_digest(entry[0], fp):
                return False
            del self._codes[code]
            return True

    def _purge(self) -> None:
        now = time.time()
        for c in [c for c, (_, exp) in self._codes.items() if exp < now]:
            del self._codes[c]


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def check_path(path: str, settings: Settings, *, write: bool = False) -> str:
    """Resolve a path and enforce protected/allowed rules. Returns the resolved path."""
    if not path:
        raise ValueError("path is required")
    p = Path(path).expanduser()
    if not p.is_absolute():
        raise ValueError("path must be absolute")
    resolved = str(p.resolve())
    for prot in settings.protected_paths:
        if _within(resolved, prot):
            raise PermissionError(f"protected path: {prot}")
    # Reads: anywhere (full mode) or inside allowed dirs (allowlist mode).
    # Writes: always inside allowed dirs.
    if write or settings.mode == "allowlist":
        roots = settings.allowed_dirs or ["/"]
        if not any(_within(resolved, r) for r in roots):
            raise PermissionError(
                f"outside allowed directories ({', '.join(roots)}); "
                "use run_command for system files or extend SHELLGATE_ALLOWED_DIRS"
            )
    return resolved
