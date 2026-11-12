"""The repository is public: no filled-in token, tunnel token or password may be committed."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = [
    # token=/tunnel_token=/SHELLGATE_TOKEN= followed by a long literal value
    re.compile(r"(?im)^\s*(shellgate_)?(tunnel_)?token\s*=\s*['\"]?[A-Za-z0-9_\-+/=]{24,}"),
    # Cloudflare tunnel tokens are base64 JSON: eyJhIjoi...
    re.compile(r"eyJhIjoi[A-Za-z0-9+/=]{20,}"),
    # a PEM private key with real-looking body (test fixtures use a few placeholder bytes)
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(\\n)?[A-Za-z0-9+/=]{64,}"),
]


def test_no_secrets_in_tracked_files():
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    hits = []
    for f in files:
        p = ROOT / f
        if not p.is_file() or p.stat().st_size > 2_000_000 or f.endswith(".lock"):
            continue
        text = p.read_text(errors="ignore")
        for rx in PATTERNS:
            for m in rx.finditer(text):
                hits.append(f"{f}: {m.group(0)[:40]}")
    assert not hits, "possible secrets committed:\n" + "\n".join(hits)
