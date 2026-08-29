"""Run the operator-console behavioral smoke harness as part of the gate.

The console is a static SPA with no JS build or browser test runner in this
repository. ``apps/operator-ui/tests/chart-smoke.mjs`` executes ``el``,
``svg`` and ``ledgerTrendChart`` from ``app.js`` against a minimal DOM shim and
asserts the produced DOM is structurally correct and free of inline handlers or
styles the console's strict CSP would block.

This test shells out to ``node`` so a self-contained behavioral check runs in
the hermetic suite (no browser required). If ``node`` is unavailable the test
is skipped rather than failed, because the Python-only CI/lint gates still pass
and the CSP source-compatibility contract is covered deterministically by
``test_console_csp_contract.py``. When node is present, an exit code of zero is
required; a brace-extraction or behavior regressions thus fail fast here instead
of being discovered only in the later browser/WCAG lane.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_HARNESS = _REPOSITORY_ROOT / "apps" / "operator-ui" / "tests" / "chart-smoke.mjs"

pytestmark = pytest.mark.console_ui


def test_console_behavior_smoke_harness_exists() -> None:
    # A missing harness would make the gate silently vacuous; the CSP contract
    # test already pins the source shapes, so this guard keeps them in sync.
    assert _HARNESS.is_file()


def test_console_behavior_smoke_runs_clean() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    # S603 (bandit): the argv is a fixed node binary plus a module-constant
    # harness path — there is no attacker-controlled input in the command line,
    # and check=False lets us assert the exit code with the harness's own output.
    result = subprocess.run(  # noqa: S603
        [node, str(_HARNESS)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"console behavior harness failed (exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
    )
    assert "chart-smoke OK" in result.stdout
