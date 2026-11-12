"""Python guard module: overdue rollback after a restart (the Rust side has the same test)."""
import asyncio
import json

from shellgate import guard


def test_recover_rolls_back_overdue(tmp_path):
    state = tmp_path / "state"
    f = tmp_path / "net.conf"
    f.write_text("old\n")
    new = tmp_path / "created.conf"
    gid, d, meta = guard.snapshot(str(state), [str(f), str(new)], "edit", f"touch {tmp_path / 'reloaded'}", 15)
    f.write_text("new\n")
    new.write_text("x")
    assert guard.changed_files(d, meta) == [str(f), str(new)]
    # simulate a restart after the deadline passed
    m = json.loads((d / "meta.json").read_text())
    m["deadline"] = guard.now() - 5
    (d / "meta.json").write_text(json.dumps(m))

    async def main():
        assert guard.recover(str(state), "/bin/sh") == 1
        for _ in range(50):
            if guard.read_meta(d)["status"] != "pending" and guard.read_meta(d)["status"] != "rolling_back":
                break
            await asyncio.sleep(0.1)
    asyncio.run(main())
    assert guard.read_meta(d)["status"] == "rolled_back"
    assert f.read_text() == "old\n" and not new.exists() and (tmp_path / "reloaded").exists()


def test_keep_then_rollback_refused(tmp_path):
    f = tmp_path / "a"
    f.write_text("1")
    gid, d, _ = guard.snapshot(str(tmp_path / "s"), [str(f)], "x", "", 15)
    guard.transition(d, "kept")
    try:
        asyncio.run(guard.rollback(d, "/bin/sh", "late"))
        raise AssertionError("rollback after keep must fail")
    except ValueError as e:
        assert "already kept" in str(e)
    assert guard.find(str(tmp_path / "s"), gid) == d
