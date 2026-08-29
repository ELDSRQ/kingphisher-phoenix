#!/usr/bin/env python3
"""Supervisor for the Kingphisher-Phoenix local stack.

Runs the operator API, tracking API, and all workers as child processes and
restarts them together when the console asks for a restart. It is the process
behind the GUI: the browser console's "restart" writes a marker file and this
supervisor reacts, so no CLI interaction is required.

Marker files (all relative to the project root):
  data/run/restart        touch to restart the whole stack

Child pids are written to data/run/<name>.pid and logs to data/logs/<name>.log.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_DIR = PROJECT_ROOT / "data" / "run"
LOG_DIR = PROJECT_ROOT / "data" / "logs"

# name -> argv (uv run in the project venv keeps the exact workspace env)
CHILDREN: dict[str, list[str]] = {
    "operator-api": ["uv", "run", "--frozen", "--no-sync", "kp-operator-api"],
    "tracking-api": ["uv", "run", "--frozen", "--no-sync", "kp-tracking-api"],
    "worker-ingestion": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "ingestion"],
    "worker-generation": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "generation"],
    "worker-delivery": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "delivery"],
    "worker-retention": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "retention"],
    "worker-mailbox": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "mailbox"],
    "worker-reminder": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "reminder"],
    "worker-alert": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "alert"],
    "worker-directory": ["uv", "run", "--frozen", "--no-sync", "kp-worker", "directory"],
}

POLL_INTERVAL = 2.0
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 3


def _log(message: str) -> None:
    sys.stdout.write(f"[supervisor] {message}\n")
    sys.stdout.flush()


def _rotate_logs(log_path: Path) -> None:
    # Logs are operational evidence. Never discard the oldest archive merely
    # to satisfy a size cap: shift every existing numbered archive upward and
    # leave capacity decisions to an explicit, reviewed retention workflow.
    first_available = 1
    while log_path.with_suffix(f"{log_path.suffix}.{first_available}").exists():
        first_available += 1
    for index in range(first_available - 1, 0, -1):
        source = log_path.with_suffix(f"{log_path.suffix}.{index}")
        source.rename(log_path.with_suffix(f"{log_path.suffix}.{index + 1}"))
    if log_path.exists():
        log_path.rename(log_path.with_suffix(f"{log_path.suffix}.1"))


def _open_log(log_path: Path) -> object:
    descriptor = os.open(log_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "ab", buffering=0)


def _pump_output(stream: object, log_path: Path) -> None:
    source: Any = stream
    # Buffered pipe `.read(size)` may wait for the entire 64 KiB request while
    # a long-running child remains open, hiding startup failures and request
    # logs for hours.  `read1` returns the bytes currently available; in-memory
    # test streams retain the ordinary read fallback.
    read_chunk = getattr(source, "read1", source.read)
    log = _open_log(log_path)
    try:
        size = log.tell()  # type: ignore[attr-defined]
        while chunk := read_chunk(min(64 * 1024, LOG_MAX_BYTES)):
            if size + len(chunk) > LOG_MAX_BYTES:
                log.close()  # type: ignore[attr-defined]
                _rotate_logs(log_path)
                log = _open_log(log_path)  # noqa: PLW2901
                size = 0
            log.write(chunk)  # type: ignore[attr-defined]
            size += len(chunk)
    finally:
        log.close()  # type: ignore[attr-defined]


def _spawn(name: str, argv: list[str]) -> subprocess.Popen[bytes]:
    log_path = LOG_DIR / f"{name}.log"
    proc = subprocess.Popen(  # noqa: S603 - argv is a hardcoded constant list above
        argv,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=os.environ.copy(),
    )
    pid_path = RUN_DIR / f"{name}.pid"
    temporary_pid_path = RUN_DIR / f".{name}.pid.{os.getpid()}.{proc.pid}.tmp"
    temporary_pid_created = False
    try:
        if proc.stdout is None:  # pragma: no cover - PIPE guarantees stdout
            raise RuntimeError("child output pipe was not created")
        threading.Thread(
            target=_pump_output,
            args=(proc.stdout, log_path),
            name=f"log-{name}",
            daemon=True,
        ).start()
        # Publish a complete line-oriented PID atomically. A crash must never
        # leave a truncated file that hides an otherwise live child process.
        descriptor = os.open(
            temporary_pid_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        temporary_pid_created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as pid_file:
            pid_file.write(f"{proc.pid}\n")
            pid_file.flush()
            os.fsync(pid_file.fileno())
        os.replace(temporary_pid_path, pid_path)
        temporary_pid_created = False
    except BaseException:
        if temporary_pid_created:
            temporary_pid_path.unlink(missing_ok=True)
        if not _terminate(name, proc):
            _log(f"could not stop orphaned {name} after startup failed")
        raise
    _log(f"started {name} (pid {proc.pid})")
    return proc


def _terminate(name: str, proc: subprocess.Popen[bytes]) -> bool:
    """Stop one child and return only after its exit is confirmed."""

    if proc.poll() is not None:
        return True
    try:
        proc.terminate()
    except ProcessLookupError:
        return True
    except OSError as error:
        _log(f"could not signal {name} to stop: {error}")
        return False
    try:
        proc.wait(timeout=5)
        return True
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        return True
    except OSError as error:
        _log(f"could not force-stop {name}: {error}")
        return False
    try:
        proc.wait(timeout=5)
        return True
    except subprocess.TimeoutExpired:
        _log(f"could not confirm {name} stopped after kill")
        return False


def _stop(procs: dict[str, subprocess.Popen[bytes]]) -> bool:
    remaining: dict[str, subprocess.Popen[bytes]] = {}
    for name, proc in procs.items():
        if not _terminate(name, proc):
            remaining[name] = proc
            continue
        (RUN_DIR / f"{name}.pid").unlink(missing_ok=True)
        _log(f"stopped {name}")
    procs.clear()
    procs.update(remaining)
    return not remaining


def _start_all(procs: dict[str, subprocess.Popen[bytes]]) -> None:
    """Start one complete generation of children or stop the partial set."""

    try:
        for name, argv in CHILDREN.items():
            procs[name] = _spawn(name, argv)
    except BaseException as error:
        if not _stop(procs):
            raise RuntimeError("partial child generation could not be stopped; refusing to continue") from error
        raise


def _unexpected_exit(
    procs: dict[str, subprocess.Popen[bytes]],
) -> tuple[str, int] | None:
    for name, proc in procs.items():
        return_code = proc.poll()
        if return_code is not None:
            return name, return_code
    return None


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    restart_marker = RUN_DIR / "restart"
    restart_marker.unlink(missing_ok=True)

    procs: dict[str, subprocess.Popen[bytes]] = {}

    _start_all(procs)

    def _stop_all() -> bool:
        stopped = _stop(procs)
        if stopped:
            restart_marker.unlink(missing_ok=True)
        return stopped

    def _on_signal(signum: int, _frame: object) -> None:
        _log(f"received {signal.Signals(signum).name}; stopping")
        sys.exit(0 if _stop_all() else 1)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            if restart_marker.exists():
                _log("restart marker found; restarting stack")
                if not _stop_all():
                    _log("restart aborted because the prior generation did not stop")
                    return 1
                _start_all(procs)
                continue
            failed_child = _unexpected_exit(procs)
            if failed_child is not None:
                name, return_code = failed_child
                _log(f"{name} exited unexpectedly (status {return_code}); stopping stack")
                if not _stop_all():
                    _log("one or more children remain live after the stack failure")
                return 1
    except KeyboardInterrupt:
        return 0 if _stop_all() else 1


if __name__ == "__main__":
    raise SystemExit(main())
