from __future__ import annotations

import importlib.util
import io
from pathlib import Path


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
