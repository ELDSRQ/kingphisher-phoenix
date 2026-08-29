"""Pytest plugin that turns an integration-test skip into a failed gate."""

from __future__ import annotations

import pytest
from _pytest.main import Session
from _pytest.terminal import TerminalReporter


def pytest_sessionfinish(session: Session, exitstatus: int | pytest.ExitCode) -> None:
    reporter: TerminalReporter | None = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = reporter.stats.get("skipped", []) if reporter is not None else []
    if not skipped:
        return
    if reporter is not None:
        reporter.write_sep("=", f"release gate rejected {len(skipped)} skipped test(s)", red=True)
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
