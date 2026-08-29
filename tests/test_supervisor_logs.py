from __future__ import annotations

import importlib.util
import io
import os
import subprocess
from pathlib import Path

import pytest


class _AvailableBytesStream:
    def __init__(self) -> None:
        self._chunks = iter((b"startup\n", b"ready\n", b""))

    def read(self, _size: int) -> bytes:
        raise AssertionError("blocking read must not be selected when read1 is available")

    def read1(self, _size: int) -> bytes:
        return next(self._chunks)


def _load_supervisor() -> object:
    path = Path(__file__).parents[1] / "scripts" / "supervisor.py"
    spec = importlib.util.spec_from_file_location("kp_supervisor", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_child_output_is_rotated_and_bounded(tmp_path: Path) -> None:
    supervisor = _load_supervisor()
    supervisor.LOG_MAX_BYTES = 10
    supervisor.LOG_BACKUP_COUNT = 2
    log_path = tmp_path / "worker.log"

    supervisor._pump_output(io.BytesIO(b"a" * 8 + b"b" * 8 + b"c" * 8), log_path)

    retained = (
        log_path.with_suffix(".log.2").read_bytes()
        + log_path.with_suffix(".log.1").read_bytes()
        + log_path.read_bytes()
    )
    assert retained == b"a" * 8 + b"b" * 8 + b"c" * 8
    assert all(path.stat().st_size <= 10 for path in tmp_path.iterdir())
    assert sum(path.stat().st_size for path in tmp_path.iterdir()) <= 30


def test_supervisor_writes_line_oriented_pidfiles() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "supervisor.py").read_text(encoding="utf-8")

    assert 'pid_file.write(f"{proc.pid}\\n")' in source
    assert "os.replace(temporary_pid_path, pid_path)" in source


def test_child_output_uses_available_bytes_without_waiting_for_a_full_buffer(tmp_path: Path) -> None:
    supervisor = _load_supervisor()
    log_path = tmp_path / "child.log"

    supervisor._pump_output(_AvailableBytesStream(), log_path)

    assert log_path.read_bytes() == b"startup\nready\n"


def test_rotation_preserves_every_existing_evidence_archive(tmp_path: Path) -> None:
    supervisor = _load_supervisor()
    supervisor.LOG_BACKUP_COUNT = 1
    log_path = tmp_path / "child.log"
    log_path.write_bytes(b"current")
    log_path.with_suffix(".log.1").write_bytes(b"one")
    log_path.with_suffix(".log.2").write_bytes(b"two")
    log_path.with_suffix(".log.3").write_bytes(b"three")

    supervisor._rotate_logs(log_path)

    assert log_path.with_suffix(".log.1").read_bytes() == b"current"
    assert log_path.with_suffix(".log.2").read_bytes() == b"one"
    assert log_path.with_suffix(".log.3").read_bytes() == b"two"
    assert log_path.with_suffix(".log.4").read_bytes() == b"three"


def test_partial_child_start_is_stopped_before_failure_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _load_supervisor()
    stopped: list[str] = []

    class _Proc:
        pid = 42

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            stopped.append("terminate")

        def wait(self, *, timeout: int) -> int:
            assert timeout == 5
            return 0

    def fake_spawn(name: str, _argv: list[str]) -> _Proc:
        if name == "second":
            raise OSError("spawn failed")
        return _Proc()

    monkeypatch.setattr(supervisor, "CHILDREN", {"first": ["one"], "second": ["two"]})
    monkeypatch.setattr(supervisor, "RUN_DIR", tmp_path)
    monkeypatch.setattr(supervisor, "_spawn", fake_spawn)
    procs: dict[str, object] = {}

    with pytest.raises(OSError, match="spawn failed"):
        supervisor._start_all(procs)

    assert stopped == ["terminate"]
    assert procs == {}


def test_supervisor_detects_unexpected_child_exit() -> None:
    supervisor = _load_supervisor()

    class _Proc:
        def __init__(self, status: int | None) -> None:
            self.status = status

        def poll(self) -> int | None:
            return self.status

    assert supervisor._unexpected_exit({"live": _Proc(None)}) is None
    assert supervisor._unexpected_exit({"failed": _Proc(17)}) == ("failed", 17)


def test_supervisor_uses_frozen_environment_without_dependency_mutation() -> None:
    supervisor = _load_supervisor()

    assert all(argv[:4] == ["uv", "run", "--frozen", "--no-sync"] for argv in supervisor.CHILDREN.values())


def test_spawn_failure_after_process_creation_stops_the_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _load_supervisor()
    stopped: list[str] = []

    class _Proc:
        pid = 4242
        stdout = io.BytesIO()

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            stopped.append("terminate")

        def wait(self, *, timeout: int) -> int:
            assert timeout == 5
            return 0

    class _Thread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

    proc = _Proc()
    monkeypatch.setattr(supervisor, "RUN_DIR", tmp_path)
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda *_args, **_kwargs: proc)
    monkeypatch.setattr(supervisor.threading, "Thread", _Thread)
    temporary = tmp_path / f".test.pid.{os.getpid()}.{proc.pid}.tmp"
    temporary.write_text("collision", encoding="utf-8")

    with pytest.raises(FileExistsError):
        supervisor._spawn("test", ["uv"])

    assert stopped == ["terminate"]
    assert not (tmp_path / "test.pid").exists()
    assert temporary.read_text(encoding="utf-8") == "collision"


def test_stop_retains_unconfirmed_children_and_their_pid_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _load_supervisor()

    class _Proc:
        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            pass

        def wait(self, *, timeout: int) -> int:
            assert timeout == 5
            raise subprocess.TimeoutExpired("child", timeout)

        def kill(self) -> None:
            pass

    proc = _Proc()
    pidfile = tmp_path / "child.pid"
    pidfile.write_text("42\n", encoding="utf-8")
    monkeypatch.setattr(supervisor, "RUN_DIR", tmp_path)
    procs: dict[str, object] = {"child": proc}

    assert supervisor._stop(procs) is False
    assert procs == {"child": proc}
    assert pidfile.read_text(encoding="utf-8") == "42\n"
