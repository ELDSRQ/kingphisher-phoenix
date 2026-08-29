from __future__ import annotations

from pathlib import Path


def test_owned_worker_sources_do_not_enable_traceback_logging() -> None:
    root = Path(__file__).resolve().parents[3]
    for relative in (
        "packages/database/src/kp_database/outbox.py",
        "apps/workers/src/kp_workers/jobs.py",
        "apps/workers/src/kp_workers/supervisor.py",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        assert ".exception(" not in source
        assert "exc_info=True" not in source
