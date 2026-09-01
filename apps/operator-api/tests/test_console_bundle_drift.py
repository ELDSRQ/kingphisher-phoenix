"""Console bundle drift gate.

The operator console is authored as ES modules in apps/operator-ui/src/console-js/
and bundled to the committed apps/operator-ui/src/console/app.js that the API
server mounts at /console. Source-wiring contract tests read the authored
modules; this gate closes the loop: a source edit that is not rebuilt and
committed together fails here, so the served bundle can never silently drift
from the sources under test.

Skips only if node or the esbuild binary is unavailable (mirrors the
behavioral harness), so hermetic CI still enforces the gate when the JS
toolchain is present.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CONSOLE_DIR = _REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console"
_CONSOLE_SRC_DIR = _REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console-js"
_COMMITTED_BUNDLE = _CONSOLE_DIR / "app.js"
_ESBUILD = _REPOSITORY_ROOT / "apps" / "operator-ui" / "node_modules" / ".bin" / "esbuild"

pytestmark = pytest.mark.console_ui


@pytest.mark.requires_esbuild
def test_committed_console_bundle_matches_a_fresh_build() -> None:
    entry = _CONSOLE_SRC_DIR / "app.js"
    assert entry.is_file(), "console entry module is missing"
    assert _COMMITTED_BUNDLE.is_file(), "committed console bundle is missing"

    # cwd must match the build script (apps/operator-ui): esbuild embeds the
    # module paths as source comments relative to the working directory, so a
    # rebuild from any other cwd would differ from the committed bundle.
    ui_dir = _CONSOLE_SRC_DIR.parent.parent  # apps/operator-ui
    # S603: subprocess with a fixed list of constant arguments (the pinned esbuild
    # binary, a constant entry path, and constant flags) — no attacker-controlled
    # input reaches the command, matching the D2 harness's node invocation.
    rebuilt = subprocess.run(  # noqa: S603
        [
            str(_ESBUILD),
            str(entry.relative_to(ui_dir)),
            "--bundle",
            "--format=iife",
            "--minify=false",
            "--legal-comments=inline",
            "--log-level=warning",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=ui_dir,
    ).stdout.encode("utf-8")

    committed = _COMMITTED_BUNDLE.read_bytes()
    assert rebuilt == committed, (
        "apps/operator-ui/src/console/app.js is stale: it does not match a fresh build of "
        "apps/operator-ui/src/console-js/. Run `cd apps/operator-ui && npm run build` and "
        "commit the rebuilt bundle together with the source change."
    )
