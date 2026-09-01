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
        for report in skipped:
            reason = ""
            longrepr = getattr(report, "longrepr", None)
            if isinstance(longrepr, tuple) and len(longrepr) == 3:
                reason = str(longrepr[2])
            reporter.write_line(f"  SKIPPED {getattr(report, 'nodeid', '?')} :: {reason}", red=True)
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
