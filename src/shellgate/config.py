"""Configuration loaded from environment variables (optionally via an env file)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ENV_FILE = Path.home() / ".config" / "shellgate" / "env"


def _load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE loader. Existing environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _expand(p: str) -> str:
    return str(Path(os.path.expandvars(os.path.expanduser(p))).resolve())


@dataclass
class Settings:
    token: str
    host: str = "127.0.0.1"
    port: int = 8790
    mode: str = "full"  # "full" or "allowlist"
    allowed_commands: list[str] = field(default_factory=list)
    allowed_dirs: list[str] = field(default_factory=list)
    protected_paths: list[str] = field(default_factory=list)
    extra_danger_patterns: list[str] = field(default_factory=list)
    audit_log: str = ""
    default_timeout: int = 60
    max_timeout: int = 600
    max_output_bytes: int = 100_000
    max_concurrent: int = 4
    max_jobs: int = 8
    confirm_ttl: int = 300
    shell: str = "/bin/bash"
    backup_on_write: bool = True
    env_file: str = ""

    @property
    def danger_regexes(self) -> list[re.Pattern[str]]:
        return [re.compile(p, re.IGNORECASE) for p in self.extra_danger_patterns]


def load_settings(env_file: str | None = None) -> Settings:
    path = Path(env_file or os.environ.get("SHELLGATE_ENV_FILE", "") or DEFAULT_ENV_FILE)
    _load_env_file(path)
    env = os.environ.get

    token = env("SHELLGATE_TOKEN", "")
    if len(token) < 32:
        raise SystemExit(
            "SHELLGATE_TOKEN is missing or shorter than 32 characters. "
            "Generate one with: python3 -c 'import secrets;print(secrets.token_urlsafe(40))'"
        )

    mode = env("SHELLGATE_MODE", "full").lower()
    if mode not in {"full", "allowlist"}:
        raise SystemExit("SHELLGATE_MODE must be 'full' or 'allowlist'")

    home = str(Path.home())
    state_dir = Path(env("SHELLGATE_STATE_DIR", f"{home}/.local/state/shellgate"))
    audit_log = env("SHELLGATE_AUDIT_LOG", str(state_dir / "audit.jsonl"))

    protected = [
        str(path.parent),            # our own config + token
        str(Path(audit_log).parent),  # audit log can't be tampered with via file tools
        f"{home}/.ssh",
        f"{home}/.cloudflared",
        f"{home}/.gnupg",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ] + _split(env("SHELLGATE_PROTECTED_PATHS", ""))

    allowed_dirs = _split(env("SHELLGATE_ALLOWED_DIRS", f"{home},/tmp"))

    return Settings(
        token=token,
        host=env("SHELLGATE_HOST", "127.0.0.1"),
        port=int(env("SHELLGATE_PORT", "8790")),
        mode=mode,
        allowed_commands=_split(env("SHELLGATE_ALLOWED_COMMANDS", "")),
        allowed_dirs=[_expand(d) for d in allowed_dirs],
        protected_paths=[_expand(p) for p in protected],
        extra_danger_patterns=_split(env("SHELLGATE_DANGER_PATTERNS", "")),
        audit_log=_expand(audit_log),
        default_timeout=int(env("SHELLGATE_DEFAULT_TIMEOUT", "60")),
        max_timeout=int(env("SHELLGATE_MAX_TIMEOUT", "600")),
        max_output_bytes=int(env("SHELLGATE_MAX_OUTPUT_BYTES", "100000")),
        max_concurrent=int(env("SHELLGATE_MAX_CONCURRENT", "4")),
        max_jobs=int(env("SHELLGATE_MAX_JOBS", "8")),
        confirm_ttl=int(env("SHELLGATE_CONFIRM_TTL", "300")),
        shell=env("SHELLGATE_SHELL", "/bin/bash"),
        backup_on_write=env("SHELLGATE_BACKUP_ON_WRITE", "true").lower() in {"1", "true", "yes"},
        env_file=str(path),
    )
