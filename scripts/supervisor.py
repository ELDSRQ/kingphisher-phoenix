#!/usr/bin/env python3
"""Supervisor for the Kingphisher-Phoenix local stack.

Runs the operator API, tracking API, and all workers as child processes and
restarts them together when the console asks for a restart. It is the process
behind the GUI: the browser console's "restart" writes a marker file and this
supervisor reacts, so no CLI interaction is required.

Marker files (all relative to the project root):
  data/run/restart        touch to restart the whole stack
  data/run/stop           touch to stop everything and exit

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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_DIR = PROJECT_ROOT / "data" / "run"
LOG_DIR = PROJECT_ROOT / "data" / "logs"

# name -> argv (uv run in the project venv keeps the exact workspace env)
CHILDREN: dict[str, list[str]] = {
    "operator-api": ["uv", "run", "kp-operator-api"],
    "tracking-api": ["uv", "run", "kp-tracking-api"],
    "worker-ingestion": ["uv", "run", "kp-worker", "ingestion"],
    "worker-generation": ["uv", "run", "kp-worker", "generation"],
    "worker-delivery": ["uv", "run", "kp-worker", "delivery"],
    "worker-retention": ["uv", "run", "kp-worker", "retention"],
    "worker-mailbox": ["uv", "run", "kp-worker", "mailbox"],
    "worker-reminder": ["uv", "run", "kp-worker", "reminder"],
    "worker-alert": ["uv", "run", "kp-worker", "alert"],
    "worker-directory": ["uv", "run", "kp-worker", "directory"],
}

POLL_INTERVAL = 2.0
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 3


def _log(message: str) -> None:
    sys.stdout.write(f"[supervisor] {message}\n")
    sys.stdout.flush()


def _rotate_logs(log_path: Path) -> None:
    oldest = log_path.with_suffix(f"{log_path.suffix}.{LOG_BACKUP_COUNT}")
    oldest.unlink(missing_ok=True)
    for index in range(LOG_BACKUP_COUNT - 1, 0, -1):
        source = log_path.with_suffix(f"{log_path.suffix}.{index}")
        if source.exists():
            source.replace(log_path.with_suffix(f"{log_path.suffix}.{index + 1}"))
    if log_path.exists():
        log_path.replace(log_path.with_suffix(f"{log_path.suffix}.1"))


def _pump_output(stream: object, log_path: Path) -> None:
    source = stream
    log = log_path.open("ab", buffering=0)
    try:
        log_path.chmod(0o600)
        size = log.tell()
        while chunk := source.read(min(64 * 1024, LOG_MAX_BYTES)):  # type: ignore[attr-defined]
            if size + len(chunk) > LOG_MAX_BYTES:
                log.close()
                _rotate_logs(log_path)
                log = log_path.open("ab", buffering=0)  # noqa: PLW2901
                log_path.chmod(0o600)
                size = 0
            log.write(chunk)
            size += len(chunk)
    finally:
        log.close()


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
    if proc.stdout is None:  # pragma: no cover - PIPE guarantees stdout
        raise RuntimeError("child output pipe was not created")
    threading.Thread(
        target=_pump_output,
        args=(proc.stdout, log_path),
        name=f"log-{name}",
        daemon=True,
    ).start()
    (RUN_DIR / f"{name}.pid").write_text(str(proc.pid), encoding="utf-8")
    _log(f"started {name} (pid {proc.pid})")
    return proc


def _stop(procs: dict[str, subprocess.Popen[bytes]]) -> None:
    for name, proc in procs.items():
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                continue
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        (RUN_DIR / f"{name}.pid").unlink(missing_ok=True)
        _log(f"stopped {name}")
    procs.clear()


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    restart_marker = RUN_DIR / "restart"
    stop_marker = RUN_DIR / "stop"
    for marker in (restart_marker, stop_marker):
        marker.unlink(missing_ok=True)

    procs: dict[str, subprocess.Popen[bytes]] = {}

    def _start_all() -> None:
        for name, argv in CHILDREN.items():
            procs[name] = _spawn(name, argv)

    _start_all()

    def _stop_all() -> None:
        _stop(procs)
        for marker in (restart_marker, stop_marker):
            marker.unlink(missing_ok=True)

    def _on_signal(signum: int, _frame: object) -> None:
        _log(f"received {signal.Signals(signum).name}; stopping")
        _stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            if stop_marker.exists():
                _log("stop marker found")
                _stop_all()
                return 0
            if restart_marker.exists():
                _log("restart marker found; restarting stack")
                _stop_all()
                _start_all()
    except KeyboardInterrupt:
        _stop_all()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
