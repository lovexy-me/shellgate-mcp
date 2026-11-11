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
    (r"\bshutil\.rmtree\b", "recursive delete (python)"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), why) for p, why in DANGER_PATTERNS]


# ---- read-only commands: their arguments are text, not actions (v0.2.7)
# "grep shutdown log", "cat /etc/passwd", "journalctl | grep reboot" must not ask for a confirm code.
# A segment run by one of these commands is scanned as just its name plus any redirection, unless
# its output is piped into a command that is not read-only (echo reboot | sh, cat x | ssh host),
# or it contains a command substitution. Same algorithm as inert_view in core/src/policy.rs.
INERT_COMMANDS = {
    "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "cat", "zcat", "bzcat", "xzcat", "less", "more",
    "head", "tail", "tac", "echo", "printf", "ls", "dir", "wc", "sort", "uniq", "cut", "tr", "column",
    "nl", "journalctl", "logread", "dmesg", "man", "which", "whereis", "type", "file", "stat", "du",
    "df", "free", "uptime", "ps", "pgrep", "pidof", "id", "whoami", "hostname", "date", "history",
    "jq", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "basename", "dirname", "readlink",
    "realpath", "strings", "hexdump", "od", "xxd", "rev", "find", "findstr", "where", "select-string",
    "sls", "get-content", "gc", "write-output", "write-host", "get-childitem", "gci", "get-process",
    "get-service", "get-winevent", "get-eventlog",
}
_WRAPPERS = {"sudo", "doas", "env", "nice", "nohup", "time", "command", "busybox"}
_FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _segments(cmd: str) -> list[tuple[str, str]]:
    """Split at unquoted | || && ; & ( ) and newlines: [(segment, separator after it)]."""
    out: list[tuple[str, str]] = []
    cur: list[str] = []
    q = ""
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if q:
            cur.append(ch)
            if ch == "\\" and q == '"' and i + 1 < n:
                cur.append(cmd[i + 1])
                i += 1
            elif ch == q:
                q = ""
        elif ch == "\\" and i + 1 < n:
            cur.append(ch + cmd[i + 1])
            i += 1
        elif ch in "'\"":
            q = ch
            cur.append(ch)
        elif ch in "|&;()\n":
            sep = ch
            if ch in "|&" and i + 1 < n and cmd[i + 1] == ch:
                sep = ch * 2
                i += 1
            out.append(("".join(cur), sep))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append(("".join(cur), ""))
    return out


def _words(seg: str) -> list[str] | None:
    # backslashes doubled so Windows paths (C:\\Windows\\System32\\findstr.exe) survive the split
    try:
        return shlex.split(seg.replace("\\", "\\\\"), posix=True)
    except ValueError:
        return None


def _cmd_word(words: list[str]) -> str | None:
    i = 0
    while i < len(words) and _ASSIGN.match(words[i]):
        i += 1
    while i < len(words) and words[i].lower() in _WRAPPERS:
        i += 1
        if i < len(words) and words[i].startswith("-"):
            return None  # sudo -u x ... : do not guess
        while i < len(words) and _ASSIGN.match(words[i]):
            i += 1
    if i >= len(words):
        return None
    w = words[i].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return w[:-4] if w.endswith(".exe") else w


def _is_inert(seg: str) -> bool:
    if "$(" in seg or "`" in seg or "<(" in seg or ">(" in seg:
        return False
    words = _words(seg)
    if not words:
        return False
    w = _cmd_word(words)
    if w not in INERT_COMMANDS:
        return False
    if w == "find" and any(x in _FIND_ACTIONS for x in words):
        return False
    return True


def _redirect_part(seg: str) -> str:
    q = ""
    for i, ch in enumerate(seg):
        if q:
            if ch == q:
                q = ""
        elif ch in "'\"":
            q = ch
        elif ch == ">":
            return seg[i:]
    return ""


def inert_view(cmd: str) -> str:
    segs = _segments(cmd)
    inert = [_is_inert(s) for s, _ in segs]
    out: list[str] = []
    for k, (seg, sep) in enumerate(segs):
        feeds = sep == "|" and k + 1 < len(segs) and not inert[k + 1]
        if inert[k] and not feeds:
            words = _words(seg) or []
            red = _redirect_part(seg)
            out.append(f"{_cmd_word(words)} {red}".rstrip() + (" " if sep else ""))
        else:
            out.append(seg)
        out.append(sep)
    return "".join(out)


def danger_reasons(command: str, settings: Settings) -> list[str]:
    command = inert_view(command)
    reasons = [why for rx, why in _COMPILED if rx.search(command)]
    reasons += [f"custom pattern: {rx.pattern}" for rx in settings.danger_regexes if rx.search(command)]
    return reasons


INTERPRETERS = {"sh", "bash", "ash", "dash", "zsh", "python", "python3"}
_WORDS_RE = re.compile(r"[\s;|&()]+")


def text_danger_reasons(text: str, settings: Settings) -> list[str]:
    """Scan a whole script/command: the text as one piece and every (continued) line on its own."""
    joined = re.sub(r"\\\r?\n", " ", text)
    seen: list[str] = []
    for chunk in [joined, *joined.splitlines()]:
        if not chunk.strip():
            continue
        for why in danger_reasons(chunk, settings):
            if why not in seen:
                seen.append(why)
    return seen


def feeds_interpreter(command: str) -> bool:
    """True when the command runs a shell/python that will read code from stdin (e.g. ssh host bash -s)."""
    return any(Path(w).name in INTERPRETERS for w in _WORDS_RE.split(command) if w)


def referenced_scripts(command: str, cwd: str, max_bytes: int = 1_000_000) -> list[tuple[str, str]]:
    """Local script files a command would execute: `sh x.sh`, `bash -x ./y`, `. ./env`, `./run.sh`."""
    found: list[tuple[str, str]] = []
    for part in _SPLIT_RE.split(command):
        try:
            tokens = shlex.split(part)
        except ValueError:
            continue
        while tokens and (re.match(r"^\w+=", tokens[0]) or tokens[0] in {"sudo", "exec", "nohup", "env"}):
            tokens = tokens[1:]
        if not tokens:
            continue
        cands: list[str] = []
        if "/" in tokens[0]:
            cands.append(tokens[0])
        if Path(tokens[0]).name in INTERPRETERS | {"source", "."}:
            rest = [t for t in tokens[1:] if not t.startswith("-")]
            if rest:
                cands.append(rest[0])
        for c in cands:
            fp = Path(c).expanduser()
            fp = fp if fp.is_absolute() else Path(cwd) / fp
            try:
                if fp.is_file() and fp.stat().st_size <= max_bytes:
                    found.append((str(fp), fp.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    return found


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


# ---- allowlisted sudo (v0.2.7): run_command sudo=true runs `sudo -n -- <argv>` (no shell) only when
# the command is one plain command whose words start with an entry of SHELLGATE_SUDO_ALLOW.
# Same rules as sudo_argv in core/src/policy.rs; tests/sudo_corpus.tsv is shared.
_SUDO_META = set(";|&`$<>\n(){}*?[]~!#")


def sudo_argv(command: str, allow: list[str]) -> list[str]:
    if not allow:
        raise PermissionError("sudo is off: list the allowed commands in SHELLGATE_SUDO_ALLOW (\";\"-separated)")
    if any(c in _SUDO_META for c in command):
        raise PermissionError("a sudo command must be one plain command: no shell operators, variables or globs")
    try:
        argv = shlex.split(command)
    except ValueError as e:
        raise PermissionError(f"cannot parse the command: {e}") from None
    if not argv:
        raise PermissionError("empty command")
    for entry in allow:
        want = entry.split()
        if want and argv[:len(want)] == want:
            return argv
    raise PermissionError(f"not in SHELLGATE_SUDO_ALLOW: {' '.join(argv[:3])}")
