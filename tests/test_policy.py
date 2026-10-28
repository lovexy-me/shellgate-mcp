import pytest

from shellgate.config import Settings
from shellgate.policy import ConfirmStore, allowlist_violations, check_path, danger_reasons


def S(**kw):
    base = dict(token="x" * 40, allowed_dirs=["/tmp/sg"], protected_paths=["/tmp/sg/secret"])
    base.update(kw)
    return Settings(**base)


@pytest.mark.parametrize("cmd", [
    "rm -rf /var/www", "sudo rm -fr ~/x", "mkfs.ext4 /dev/sdb", "dd if=/dev/zero of=/dev/sda",
    "sudo reboot", "wsl.exe --shutdown", "curl https://x.sh | sh", "docker system prune -af",
    "docker rm -f web", "systemctl stop docker", "git push -f origin main", "git reset --hard",
])
def test_dangerous(cmd):
    assert danger_reasons(cmd, S())


@pytest.mark.parametrize("cmd", ["ls -la", "docker ps", "rm file.txt", "git push origin main", "cat /etc/hosts"])
def test_safe(cmd):
    assert not danger_reasons(cmd, S())


def test_custom_pattern():
    assert danger_reasons("npm publish", S(extra_danger_patterns=[r"npm\s+publish"]))


def test_allowlist():
    s = S(mode="allowlist", allowed_commands=["ls", "grep", "docker"])
    assert allowlist_violations("ls -la | grep x", s) == []
    assert allowlist_violations("ls && curl x", s) == ["not in allowlist: curl"]
    assert allowlist_violations("echo $(id)", s)
    assert allowlist_violations("FOO=1 sudo docker ps", s) == []
    assert allowlist_violations("anything", S()) == []


def test_confirm_one_time_and_bound():
    c = ConfirmStore(60)
    fp = c.fingerprint("run", "rm -rf x", "/tmp")
    code = c.issue(fp)
    assert not c.redeem(code, c.fingerprint("run", "rm -rf y", "/tmp"))
    assert c.redeem(code, fp)
    assert not c.redeem(code, fp)  # single use


def test_confirm_expires():
    c = ConfirmStore(-1)
    fp = c.fingerprint("a")
    assert not c.redeem(c.issue(fp), fp)


def test_paths():
    s = S()
    assert check_path("/etc/hosts", s) == "/etc/hosts"            # read anywhere in full mode
    with pytest.raises(PermissionError):
        check_path("/etc/hosts", s, write=True)                     # writes confined
    with pytest.raises(PermissionError):
        check_path("/tmp/sg/secret/token", s)                       # protected
    with pytest.raises(PermissionError):
        check_path("/tmp/sg/../sg/secret/a", s)                     # traversal resolved
    with pytest.raises(ValueError):
        check_path("relative.txt", s)
    with pytest.raises(PermissionError):
        check_path("/etc/hosts", S(mode="allowlist"))               # allowlist confines reads


from shellgate.policy import feeds_interpreter, referenced_scripts, text_danger_reasons  # noqa: E402


def test_script_lines_scanned():
    script = "#!/bin/sh\necho start\ncd /tmp\nrm -rf build\necho done\n"
    assert "recursive delete" in text_danger_reasons(script, S())
    assert text_danger_reasons("echo a\nls -la\n", S()) == []
    # line continuation joined before scanning
    assert text_danger_reasons("rm \\\n  -rf /x", S())
    assert text_danger_reasons("import shutil\nshutil.rmtree('/srv')", S())


def test_feeds_interpreter():
    assert feeds_interpreter("ssh router bash -s")
    assert feeds_interpreter("/usr/bin/python3 -")
    assert not feeds_interpreter("cat > /tmp/notes.txt")


def test_referenced_scripts(tmp_path):
    f = tmp_path / "x.sh"
    f.write_text("echo hi\nreboot\n")
    found = referenced_scripts("sh x.sh", str(tmp_path))
    assert found and found[0][0] == str(f) and "reboot" in found[0][1]
    assert referenced_scripts("FOO=1 bash -e ./x.sh arg", str(tmp_path))
    assert referenced_scripts(f"{f}", "/")
    assert referenced_scripts("echo x.sh", str(tmp_path)) == []
