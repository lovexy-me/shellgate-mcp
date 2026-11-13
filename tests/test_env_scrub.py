"""The env file stays in memory; children never see ShellGate's token."""
import asyncio
import os

from shellgate import config
from shellgate.runner import run_process


def test_env_file_not_in_environ(tmp_path, monkeypatch):
    f = tmp_path / "env"
    f.write_text("\ufeffSHELLGATE_TOKEN=" + "t" * 40 + "\nSHELLGATE_ZZ_PYTEST=1\n", encoding="utf-8")
    monkeypatch.delenv("SHELLGATE_TOKEN", raising=False)
    s = config.load_settings(str(f))
    assert s.token == "t" * 40
    assert "SHELLGATE_TOKEN" not in os.environ
    assert "SHELLGATE_ZZ_PYTEST" not in os.environ
    assert config.var("SHELLGATE_ZZ_PYTEST") == "1"


def test_child_env_has_no_tokens(monkeypatch):
    secret = "py-envtest-0123456789abcdef-secret"
    monkeypatch.setenv("SHELLGATE_TOKEN", secret)
    monkeypatch.setenv("TUNNEL_TOKEN", "tunnel-envtest-0123456789abcdef")
    monkeypatch.setenv("SG_ENVTEST_COPY", "Bearer " + secret)
    monkeypatch.setenv("SG_ENVTEST_KEEP", "kept-value")
    env = config.child_env()
    assert env.get("SG_ENVTEST_KEEP") == "kept-value"
    assert not any(k.startswith("SHELLGATE_") for k in env)
    assert "TUNNEL_TOKEN" not in env and "SG_ENVTEST_COPY" not in env
    r = asyncio.run(run_process(["sh", "-c", "env; set"], "/", 20, config.Settings(token="x" * 40), asyncio.Semaphore(1)))
    out = str(r)
    assert "kept-value" in out
    assert secret not in out and "SHELLGATE_TOKEN" not in out and "TUNNEL_TOKEN" not in out
