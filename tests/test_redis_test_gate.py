from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
GATE = ROOT / "scripts" / "run-redis-tests.sh"
TEST_URL = "redis://test@localhost:6379/15"


def _fake_environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir(parents=True)
    evidence = tmp_path / "redis-gate.txt"
    fake_uv = binaries / "uv"
    fake_uv.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "printf '%s|%s|%s|%s|%s|%s|%s|%s\\n' \"${REDIS_URL:-}\" "
        '"${OPERATOR_API_REDIS_URL:-}" "${TRACKING_API_REDIS_URL:-}" '
        '"${KP_WORKER_REDIS_URL:-}" "${KP_DISABLE_DOTENV:-}" '
        '"${KP_TEST_PROFILE:-}" "${PYTEST_ADDOPTS:-missing}" "$*" '
        '> "$TMPDIR/redis-gate.txt"\n'
        '[ ! -f "$TMPDIR/redis-status" ] || exit "$(cat "$TMPDIR/redis-status")"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "KP_WORKER_REDIS_URL": "redis://runtime@localhost:6379/0",
            "OPERATOR_API_REDIS_URL": "redis://runtime@localhost:6379/0",
            "PATH": f"{binaries}{os.pathsep}{environment['PATH']}",
            "PYTEST_ADDOPTS": "-k never-run-the-gate",
            "REDIS_URL": "redis://runtime@localhost:6379/0",
            "REDIS_URL_TEST": TEST_URL,
            "TMPDIR": str(tmp_path),
            "TRACKING_API_REDIS_URL": "redis://runtime@localhost:6379/0",
        }
    )
    return environment, evidence


def test_redis_gate_scrubs_runtime_environment_and_selects_database_15(tmp_path: Path) -> None:
    environment, evidence = _fake_environment(tmp_path)

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    values = evidence.read_text(encoding="utf-8").split("|")
    assert values[:4] == [TEST_URL] * 4
    assert values[4:7] == ["1", "redis", "missing"]
    assert values[7].strip() == ("run --frozen --no-sync python -m pytest -m redis -p tests.no_skips_plugin")
    assert "runtime" not in evidence.read_text(encoding="utf-8")


def test_redis_gate_preserves_test_status(tmp_path: Path) -> None:
    environment, _evidence = _fake_environment(tmp_path)
    (tmp_path / "redis-status").write_text("19", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False
    )

    assert result.returncode == 19


@pytest.mark.parametrize(
    "test_url",
    [
        "redis://test@localhost:6379/015",
        "redis://test@localhost:6379/+15",
        "redis://test@localhost:6379/%31%35",
        "redis://test@localhost:6379/15?db=0",
        "redis://test@localhost:bad/15",
        "http://localhost:6379/15",
    ],
)
def test_redis_gate_rejects_noncanonical_test_target(tmp_path: Path, test_url: str) -> None:
    environment, evidence = _fake_environment(tmp_path)
    environment["REDIS_URL_TEST"] = test_url

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "dedicated Redis database 15" in result.stderr
    assert "test@" not in result.stderr
    assert not evidence.exists()


@pytest.mark.parametrize(
    "runtime_url",
    [
        "redis://runtime@remote.invalid:6379/14",
        "redis://runtime@remote.invalid:6379/15",
        "redis://runtime@localhost:6379/014",
        "redis://runtime@localhost:6379/+15",
        "redis://runtime@localhost:6379/%31%35",
        "redis://runtime@localhost:6379/%2F15",
        "redis://runtime@localhost:6379//15",
        "redis://runtime@localhost:6379/0?db=15",
        "redis://runtime@localhost:bad/0",
    ],
)
def test_redis_gate_rejects_reserved_or_ambiguous_runtime_target(tmp_path: Path, runtime_url: str) -> None:
    environment, evidence = _fake_environment(tmp_path)
    environment["REDIS_URL"] = runtime_url

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "application queues must not use reserved databases" in result.stderr
    assert "runtime@" not in result.stderr
    assert not evidence.exists()


def test_redis_gate_never_flushes_preserved_data() -> None:
    source = GATE.read_text(encoding="utf-8")
    assert "flushdb" not in source.lower()
    assert "flushall" not in source.lower()
