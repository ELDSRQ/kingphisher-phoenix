from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
GATE = ROOT / "scripts" / "run-postgres-tests.sh"
APP_TEST_URL = "postgresql+psycopg://test_app:test@localhost:5432/kingphisher_test"
AUDIT_TEST_URL = "postgresql+psycopg://test_audit:test@localhost:5432/kingphisher_test"
APP_RUNTIME_URL = "postgresql+psycopg://runtime:runtime@localhost:5432/kingphisher"
AUDIT_RUNTIME_URL = "postgresql+psycopg://runtime_audit:runtime@localhost:5432/kingphisher"


def _fake_environment(tmp_path: Path, test_url: str = "redis://test@localhost:6379/14") -> tuple[dict[str, str], Path]:
    binaries = tmp_path / "bin"
    binaries.mkdir(parents=True)
    log = tmp_path / "uv.log"
    uv = binaries / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'case "$*" in *"python -m pytest"*) kind=pytest ;; *) kind=cleanup ;; esac\n'
        'printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\\n" "$kind" "${REDIS_URL:-}" '
        '"${OPERATOR_API_REDIS_URL:-}" "${TRACKING_API_REDIS_URL:-}" "${KP_WORKER_REDIS_URL:-}" '
        '"${DATABASE_URL:-}" "${AUDIT_DATABASE_URL:-}" "${OPERATOR_API_DATABASE_URL:-}" '
        '"${OPERATOR_API_AUDIT_DATABASE_URL:-}" "${TRACKING_API_DATABASE_URL:-}" '
        '"${KP_WORKER_DATABASE_URL:-}" "${KP_WORKER_AUDIT_DATABASE_URL:-}" "${KP_DISABLE_DOTENV:-}" '
        '"${KP_TEST_PROFILE:-}" "${PYTEST_ADDOPTS:-missing}" >> "$TMPDIR/uv.log"\n'
        '[ "$kind" != pytest ] || { [ ! -f "$TMPDIR/pytest-status" ] || exit "$(cat "$TMPDIR/pytest-status")"; }\n'
        "exit 0\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "AUDIT_DATABASE_URL": AUDIT_RUNTIME_URL,
            "AUDIT_DATABASE_URL_TEST": AUDIT_TEST_URL,
            "DATABASE_URL": APP_RUNTIME_URL,
            "DATABASE_URL_TEST": APP_TEST_URL,
            "KP_WORKER_AUDIT_DATABASE_URL": AUDIT_RUNTIME_URL,
            "KP_WORKER_DATABASE_URL": APP_RUNTIME_URL,
            "OPERATOR_API_AUDIT_DATABASE_URL": AUDIT_RUNTIME_URL,
            "OPERATOR_API_DATABASE_URL": APP_RUNTIME_URL,
            "PATH": f"{binaries}{os.pathsep}{environment['PATH']}",
            "REDIS_URL": "redis://runtime@localhost:6379/0",
            "REDIS_URL_POSTGRES_TEST": test_url,
            "TMPDIR": str(tmp_path),
            "TRACKING_API_DATABASE_URL": APP_RUNTIME_URL,
            "PYTEST_ADDOPTS": "-k never-run-the-gate",
        }
    )
    for name in ("OPERATOR_API_REDIS_URL", "TRACKING_API_REDIS_URL", "KP_WORKER_REDIS_URL"):
        environment.pop(name, None)
    return environment, log


def test_postgres_gate_isolates_and_clears_test_queue_before_and_after(tmp_path: Path) -> None:
    environment, log = _fake_environment(tmp_path)

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 3
    assert calls[0].startswith("cleanup|") and calls[2].startswith("cleanup|")
    assert calls[1].startswith("pytest|")
    assert calls[0].count("redis://test@localhost:6379/14") == 1
    assert calls[1].count("redis://test@localhost:6379/14") == 4
    assert calls[2].count("redis://test@localhost:6379/14") == 1
    assert all("redis://runtime@localhost:6379/0" not in call for call in calls)
    pytest_values = calls[1].split("|")
    assert pytest_values[5:] == [
        APP_TEST_URL,
        AUDIT_TEST_URL,
        APP_TEST_URL,
        AUDIT_TEST_URL,
        APP_TEST_URL,
        APP_TEST_URL,
        AUDIT_TEST_URL,
        "1",
        "postgres",
        "missing",
    ]
    assert all(APP_RUNTIME_URL not in call and AUDIT_RUNTIME_URL not in call for call in calls[1:2])


def test_postgres_gate_cleans_after_a_failed_test_run(tmp_path: Path) -> None:
    environment, log = _fake_environment(tmp_path)
    (tmp_path / "pytest-status").write_text("17", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False
    )

    assert result.returncode == 17
    assert len(log.read_text(encoding="utf-8").splitlines()) == 3


def test_postgres_gate_rejects_nonreserved_or_runtime_redis_database(tmp_path: Path) -> None:
    for test_url in (
        "redis://test@localhost:6379/13",
        "redis://other@localhost:6379/0",
        "redis://test@localhost:6379/14?db=0",
        "redis://test@localhost:bad/14",
    ):
        environment, log = _fake_environment(tmp_path / test_url.rsplit("/", 1)[-1], test_url)
        result = subprocess.run(  # noqa: S603 - repository-owned gate
            ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
        )
        assert result.returncode == 2
        assert "dedicated Redis database 14" in result.stderr
        assert not log.exists()


@pytest.mark.parametrize(
    "runtime_url",
    [
        "redis://runtime@localhost:6379/014",
        "redis://runtime@localhost:6379/+14",
        "redis://runtime@localhost:6379/%31%34",
        "redis://runtime@localhost:6379/%2F14",
        "redis://runtime@localhost:6379//14",
        "redis://runtime@localhost.:6379/14",
        "redis://runtime@cache.localhost:6379/14",
        "redis://runtime@127.0.0.1:6379/14",
        "redis://runtime@127.1:6379/14",
        "redis://runtime@2130706433:6379/14",
        "redis://runtime@%31%32%37.0.0.1:6379/14",
        "redis://runtime@[::1]:6379/14",
        "rediss://runtime@127.0.0.1:6379/14",
        "redis://runtime@remote.invalid:6379/15",
    ],
)
def test_postgres_gate_rejects_redis_client_equivalent_runtime_target(tmp_path: Path, runtime_url: str) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["REDIS_URL"] = runtime_url

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "dedicated Redis database 14" in result.stderr
    assert "runtime" not in result.stderr
    assert not log.exists()


def test_postgres_gate_rejects_url_equivalent_application_database(tmp_path: Path) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["DATABASE_URL"] = "postgresql://runtime:do-not-print@LOCALHOST/kingphisher_test"

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "must not match an application database" in result.stderr
    assert "do-not-print" not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    "runtime_host",
    ["localhost.", "db.localhost", "127.0.0.1", "127.1", "2130706433", "%31%32%37.0.0.1", "[::1]"],
)
def test_postgres_gate_rejects_loopback_alias_for_application_database(tmp_path: Path, runtime_host: str) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["DATABASE_URL"] = f"postgresql://runtime:do-not-print@{runtime_host}:5432/kingphisher_test"

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "must not match an application database" in result.stderr
    assert "do-not-print" not in result.stderr
    assert not log.exists()


def test_postgres_gate_rejects_audit_alias_collision(tmp_path: Path) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["OPERATOR_API_AUDIT_DATABASE_URL"] = (
        "postgresql+psycopg://runtime_audit:do-not-print@localhost:5432/kingphisher_test"
    )

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "must not match an application database" in result.stderr
    assert "do-not-print" not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize("database_name", ["kingphisher", "postgres", "template1", "other_test"])
def test_postgres_gate_rejects_unreviewed_database_name(tmp_path: Path, database_name: str) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["DATABASE_URL_TEST"] = f"postgresql://test_app:test@localhost:5432/{database_name}"
    environment["AUDIT_DATABASE_URL_TEST"] = f"postgresql://test_audit:test@localhost:5432/{database_name}"

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "dedicated kingphisher_test database" in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    ("variable_name", "value"),
    [
        ("DATABASE_URL_TEST", "mysql://test_app:secret@localhost/kingphisher_test"),
        ("DATABASE_URL_TEST", "postgresql://test_app:secret@localhost:bad/kingphisher_test"),
        ("AUDIT_DATABASE_URL_TEST", "postgresql://test_audit:secret@localhost/kingphisher_test?sslmode=require"),
        ("AUDIT_DATABASE_URL_TEST", "postgresql://test_audit:secret@localhost/kingphisher_test#fragment"),
        ("KP_WORKER_DATABASE_URL", "postgresql://runtime:secret@localhost:bad/kingphisher"),
        (
            "DATABASE_URL",
            "postgresql://runtime:secret@wrong.invalid/other?host=localhost&port=5432&dbname=kingphisher_test",
        ),
        (
            "AUDIT_DATABASE_URL",
            "postgresql://runtime:secret@wrong.invalid/other?hostaddr=127.0.0.1&dbname=kingphisher_test",
        ),
    ],
)
def test_postgres_gate_rejects_malformed_or_ambiguous_database_url(
    tmp_path: Path, variable_name: str, value: str
) -> None:
    environment, log = _fake_environment(tmp_path)
    environment[variable_name] = value

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert "PostgreSQL test URLs" in result.stderr
    assert "secret" not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    ("audit_url", "expected_fragment"),
    [
        (
            "postgresql://test_app:test@localhost:5432/kingphisher_test",
            "distinct roles",
        ),
        (
            "postgresql://test_audit:test@localhost:5433/kingphisher_test",
            "dedicated kingphisher_test database",
        ),
    ],
)
def test_postgres_gate_requires_distinct_roles_on_one_target(
    tmp_path: Path, audit_url: str, expected_fragment: str
) -> None:
    environment, log = _fake_environment(tmp_path)
    environment["AUDIT_DATABASE_URL_TEST"] = audit_url

    result = subprocess.run(  # noqa: S603 - repository-owned gate
        ["/bin/bash", str(GATE)], cwd=ROOT, env=environment, check=False, capture_output=True, text=True
    )

    assert result.returncode == 2
    assert expected_fragment in result.stderr
    assert not log.exists()
