from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path

import pytest
from kp_telemetry.settings import local_dotenv_file

ROOT = Path(__file__).parents[1]
GATE = ROOT / "scripts" / "run-hermetic-tests.sh"


def test_local_dotenv_can_be_explicitly_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KP_DISABLE_DOTENV", "1")
    assert local_dotenv_file() is None
    monkeypatch.delenv("KP_DISABLE_DOTENV")
    assert local_dotenv_file() == ".env"


def test_hermetic_gate_drops_host_configuration_and_uses_inert_endpoints(tmp_path: Path) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    evidence = tmp_path / "kp-hermetic-evidence.txt"
    fake_uv = binaries / "uv"
    fake_uv.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'printf \'%s\\n\' "${KP_DISABLE_DOTENV:-}" "${KP_TEST_PROFILE:-}" "${DATABASE_URL:-}" '
        '"${AUDIT_DATABASE_URL:-}" "${DATABASE_URL_TEST:-}" '
        '"${AUDIT_DATABASE_URL_TEST:-}" "${OPERATOR_API_DATABASE_URL:-}" '
        '"${OPERATOR_API_AUDIT_DATABASE_URL:-}" '
        '"${TRACKING_API_DATABASE_URL:-}" "${KP_WORKER_DATABASE_URL:-}" '
        '"${KP_WORKER_AUDIT_DATABASE_URL:-}" '
        '"${REDIS_URL:-}" "${OPERATOR_API_REDIS_URL:-}" '
        '"${TRACKING_API_REDIS_URL:-}" "${KP_WORKER_REDIS_URL:-}" '
        '"${PYTEST_ADDOPTS:-missing}" "$*" > "$TMPDIR/kp-hermetic-evidence.txt"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "AUDIT_DATABASE_URL": "postgresql://live-audit.invalid/application",
            "DATABASE_URL": "postgresql://live.invalid/application",
            "PATH": f"{binaries}{os.pathsep}{environment['PATH']}",
            "PYTEST_ADDOPTS": "-k never_run_the_suite",
            "REDIS_URL": "redis://live.invalid/0",
            "TMPDIR": str(tmp_path),
        }
    )

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE), "all"], cwd=ROOT, env=environment, check=False
    )

    assert result.returncode == 0
    values = evidence.read_text(encoding="utf-8").splitlines()
    assert values[0] == "1"
    assert values[1] == "hermetic"
    assert all("127.0.0.1:1" in value for value in values[2:15])
    assert values[15] == "missing"
    # The runner appends conditional deselections that must be mirrored here:
    # macos_only off Darwin (controller recovery tooling), and requires_zsh /
    # requires_node where those interpreters are absent. Building the expected
    # string with the same conditions keeps this test correct on every host.
    import shutil

    suffix = ""
    if platform.system() != "Darwin":
        suffix += " and not macos_only"
    if shutil.which("zsh") is None:
        suffix += " and not requires_zsh"
    if shutil.which("node") is None:
        suffix += " and not requires_node"
    assert values[16] == (
        "run --frozen --no-sync python -m pytest -m "
        f"not postgres and not redis and not e2e and not azure_live{suffix} -p tests.no_skips_plugin"
    )
    assert all("live.invalid" not in value for value in values)


def test_test_modules_never_load_the_runtime_dotenv() -> None:
    offenders: list[str] = []
    dotenv_import = "from dotenv import " + "load_dotenv"
    for parent in (ROOT / "apps", ROOT / "packages", ROOT / "tests"):
        for path in parent.rglob("test*.py"):
            if dotenv_import in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_all_application_settings_honor_the_dotenv_disable_switch() -> None:
    settings_sources = (
        ROOT / "apps/operator-api/src/kp_operator_api/config.py",
        ROOT / "apps/operator-api/src/kp_operator_api/main.py",
        ROOT / "apps/tracking-api/src/kp_tracking_api/config.py",
        ROOT / "apps/workers/src/kp_workers/config.py",
    )
    for path in settings_sources:
        source = path.read_text(encoding="utf-8")
        assert 'env_file=".env"' not in source
        assert "env_file=local_dotenv_file()" in source


def test_postgres_availability_probes_connect_only_in_the_postgres_profile() -> None:
    probe_pattern = re.compile(r"def _(db_available|eligible_database)\(\) -> bool:\n(?P<body>(?:    .*\n){1,3})")
    for parent in (ROOT / "apps", ROOT / "packages"):
        for path in parent.rglob("test*.py"):
            source = path.read_text(encoding="utf-8")
            for match in probe_pattern.finditer(source):
                assert 'os.environ.get("KP_TEST_PROFILE") != "postgres"' in match.group("body"), path
