from __future__ import annotations

import ast
import os
import re
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
READINESS = ROOT / "scripts" / "operational_readiness.sh"
VERIFY_INSTALL = ROOT / "scripts" / "verify_install.sh"
POSTGRES_GATE = ROOT / "scripts" / "run-postgres-tests.sh"
REDIS_GATE = ROOT / "scripts" / "run-redis-tests.sh"


def _supervisor_children() -> list[str]:
    tree = ast.parse((ROOT / "scripts" / "supervisor.py").read_text(encoding="utf-8"))
    for statement in tree.body:
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "CHILDREN"
        ):
            value = ast.literal_eval(statement.value)
            assert isinstance(value, dict)
            return list(value)
    raise AssertionError("scripts/supervisor.py does not declare CHILDREN")


def _shell_array(script: str, name: str) -> list[str]:
    match = re.search(rf"^{name}=\(\s*(.*?)^\)", script, flags=re.MULTILINE | re.DOTALL)
    assert match is not None, name
    return shlex.split(match.group(1), comments=True)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _readiness_env(tmp_path: Path, extra_lines: tuple[str, ...] = ()) -> Path:
    env_file = tmp_path / "readiness.env"
    env_file.write_text(
        "\n".join(
            (
                "POSTGRES_PASSWORD=test-postgres",
                "REDIS_PASSWORD=test-redis",
                "AUDIT_WRITER_PASSWORD=test-audit",
                "MAILPIT_API_PASSWORD=test-mailpit",
                "DATABASE_URL_TEST=test://dedicated",
                "REDIS_URL=redis://test-redis@dedicated/0",
                "KP_CONSOLE_PASSWORD=test-console",
                f"OPERATOR_API_AUDIT_HMAC_KEY={'1' * 64}",
                f"OPERATOR_API_CIPHERTEXT_KEK={'2' * 64}",
                f"OPERATOR_API_CONSOLE_JWT_SECRET={'3' * 64}",
            )
            + extra_lines
        )
        + "\n",
        encoding="utf-8",
    )
    return env_file


def _run_readiness(
    tmp_path: Path,
    *,
    df_script: str,
    docker_script: str,
    gate_exit: int = 99,
    readiness_extra: tuple[str, ...] = (),
    make_script: str | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    gate_log = tmp_path / "gate.log"
    _write_executable(bin_dir / "df", df_script)
    _write_executable(bin_dir / "docker", docker_script)
    for command in ("make", "uv"):
        if command == "make" and make_script is not None:
            content = make_script.replace('"$KP_TEST_GATE_LOG"', shlex.quote(str(gate_log)))
        else:
            content = f"#!/bin/sh\nprintf '{command} %s\\n' \"$*\" >> {shlex.quote(str(gate_log))}\nexit {gate_exit}\n"
        _write_executable(
            bin_dir / command,
            content,
        )
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": "",
            "DOCKER_HOST": "unix:///definitely-not-present",
            "KP_READINESS_DOCKER_TIMEOUT_SECONDS": "2",
            "KP_READINESS_ENV_FILE": str(_readiness_env(tmp_path, readiness_extra)),
            "KP_TEST_DOCKER_LOG": str(docker_log),
            "KP_TEST_GATE_LOG": str(gate_log),
            "OPERATOR_API_DATABASE_URL": "",
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
        }
    )
    return subprocess.run(  # noqa: S603 - executes the repository-owned readiness script
        ["/bin/bash", str(READINESS)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_verify_install_tracks_the_local_supervisor_child_topology() -> None:
    verifier = VERIFY_INSTALL.read_text(encoding="utf-8")
    verified = _shell_array(verifier, "local_supervisor_api_children") + _shell_array(
        verifier, "local_supervisor_worker_children"
    )
    assert verified == _supervisor_children()
    assert "audit-anchor" not in verified
    assert "http://127.0.0.1:8000/readyz" in verifier
    assert "http://127.0.0.1:8001/readyz" in verifier
    assert "/healthz" not in verifier
    assert verifier.count('IFS= read -r pid < "$pidfile" || [[ -n "$pid" ]]') == 2
    assert "bounded 30 uv run --frozen --no-sync python scripts/verify_audit.py" in verifier


def test_readiness_rejects_low_disk_before_contacting_docker(tmp_path: Path) -> None:
    result = _run_readiness(
        tmp_path,
        df_script=(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/mock 10 9 1 90%% /\\n'\n"
        ),
        docker_script='#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$KP_TEST_DOCKER_LOG"\nexit 97\n',
    )
    assert result.returncode == 1
    assert "operational readiness requires at least" in result.stderr
    assert not (tmp_path / "docker.log").exists()
    assert not (tmp_path / "gate.log").exists()


def test_readiness_dotenv_cannot_redirect_tools_or_docker_daemon(tmp_path: Path) -> None:
    result = _run_readiness(
        tmp_path,
        df_script=(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
            "/mock 8000000 100 7999900 1%% /\\n'\n"
        ),
        docker_script=(
            "#!/bin/sh\n"
            '[ "$DOCKER_HOST" = "unix:///definitely-not-present" ] || exit 92\n'
            'case "$*" in\n'
            "  info|'compose config --quiet') exit 0 ;;\n"
            "  'compose ps postgres'|'compose ps redis'|'compose ps mailpit') "
            "printf 'service Up (healthy)\\n'; exit 0 ;;\n"
            "  'compose ps --status running --quiet otel-collector'|"
            "'compose ps --status running --quiet mock-idp'|"
            "'compose ps --status running --quiet mock-graph'|"
            "'compose ps --status running --quiet mock-ai') printf 'container-id\\n'; exit 0 ;;\n"
            "esac\n"
            "exit 97\n"
        ),
        readiness_extra=(
            "PATH=/credential-controlled/bin",
            "DOCKER_HOST=tcp://attacker.invalid:2375",
            "PYTEST_ADDOPTS=-k never_run_real_tests",
            "MAKEFLAGS=-n",
            "KP_READINESS_GATE_TIMEOUT_SECONDS=60",
        ),
    )

    assert result.returncode == 99
    assert "verify database is at all migration heads" in result.stdout


def test_readiness_rejects_an_unhealthy_service_before_expensive_gates(tmp_path: Path) -> None:
    result = _run_readiness(
        tmp_path,
        df_script=(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
            "/mock 8000000 100 7999900 1%% /\\n'\n"
        ),
        docker_script=(
            "#!/bin/sh\n"
            'printf \'%s\\n\' "$*" >> "$KP_TEST_DOCKER_LOG"\n'
            'case "$*" in\n'
            "  info|'compose config --quiet') exit 0 ;;\n"
            "  'compose ps postgres') printf 'postgres Up (unhealthy)\\n'; exit 0 ;;\n"
            "esac\n"
            "exit 0\n"
        ),
    )
    assert result.returncode == 1
    assert "required service 'postgres' is not healthy" in result.stderr
    docker_calls = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "info" in docker_calls
    assert "compose config --quiet" in docker_calls
    assert "compose ps postgres" in docker_calls
    assert not (tmp_path / "gate.log").exists()


def test_e2e_gate_rejects_skips_and_requires_explicit_lifecycle_opt_in() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    hermetic_target = makefile.split("test:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert "scripts/run-hermetic-tests.sh all" in hermetic_target
    hermetic_gate = (ROOT / "scripts" / "run-hermetic-tests.sh").read_text(encoding="utf-8")
    assert "not e2e" in hermetic_gate
    assert "not azure_live" in hermetic_gate
    assert "not postgres" in hermetic_gate
    assert "not redis" in hermetic_gate
    assert "-p tests.no_skips_plugin" in hermetic_gate
    postgres_target = makefile.split("test-postgres:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert "DATABASE_URL_TEST" in postgres_target
    assert "AUDIT_DATABASE_URL_TEST" in postgres_target
    assert "REDIS_URL_POSTGRES_TEST" in postgres_target
    assert "scripts/run-postgres-tests.sh" in postgres_target
    postgres_gate = POSTGRES_GATE.read_text(encoding="utf-8")
    assert "-m postgres" in postgres_gate
    assert "-p tests.no_skips_plugin" in postgres_gate
    assert "flushdb" in postgres_gate
    redis_target = makefile.split("test-redis:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert "REDIS_URL_TEST" in redis_target
    assert "scripts/run-redis-tests.sh" in redis_target
    redis_gate = REDIS_GATE.read_text(encoding="utf-8")
    assert "-m redis" in redis_gate
    assert "-p tests.no_skips_plugin" in redis_gate
    target = makefile.split("test-e2e:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert "KP_E2E_PASSWORD" in target
    assert "KP_E2E_LIFECYCLE" in target
    assert "-p tests.no_skips_plugin" in target

    readiness = READINESS.read_text(encoding="utf-8")
    assert "KP_E2E_LIFECYCLE=1 make test-e2e" in readiness
    assert readiness.index("available_kib=") < readiness.index("docker info")
    assert readiness.index('require_healthy_service "$service"') < readiness.index("make test")


def test_readiness_runs_each_strict_profile_after_service_preflight_without_leaking_urls(tmp_path: Path) -> None:
    database_url = "test://dedicated"
    audit_url = "postgresql+psycopg://audit_writer:test-audit@localhost:5432/kingphisher_test"
    redis_url = "redis://test-redis@dedicated/0"
    result = _run_readiness(
        tmp_path,
        df_script=(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
            "/mock 8000000 100 7999900 1%% /\\n'\n"
        ),
        docker_script=(
            "#!/bin/sh\n"
            'printf \'%s\\n\' "$*" >> "$KP_TEST_DOCKER_LOG"\n'
            'case "$*" in\n'
            "  info|'compose config --quiet') exit 0 ;;\n"
            "  'compose ps postgres'|'compose ps redis'|'compose ps mailpit') "
            "printf 'service Up (healthy)\\n'; exit 0 ;;\n"
            "  'compose ps --status running --quiet otel-collector'|"
            "'compose ps --status running --quiet mock-idp'|"
            "'compose ps --status running --quiet mock-graph'|"
            "'compose ps --status running --quiet mock-ai') printf 'container-id\\n'; exit 0 ;;\n"
            "esac\n"
            "exit 97\n"
        ),
        gate_exit=0,
    )

    assert result.returncode == 0, result.stderr
    gate_calls = (tmp_path / "gate.log").read_text(encoding="utf-8").splitlines()
    assert gate_calls == [
        "uv run alembic -c packages/database/alembic.ini current --check-heads",
        "make lint",
        "make typecheck",
        "make test",
        "make test-postgres",
        "make test-redis",
        "make verify-audit",
        "make verify-install",
        "make test-e2e",
    ]
    output = result.stdout + result.stderr + "\n" + "\n".join(gate_calls)
    assert database_url not in output
    assert audit_url not in output
    assert redis_url not in output

    readiness = READINESS.read_text(encoding="utf-8")
    assert readiness.index('require_running_service "$service"') < readiness.index("make test")
    assert readiness.index("make test") < readiness.index("make test-postgres")
    assert readiness.index("make test-postgres") < readiness.index("make test-redis")
    assert readiness.index("make test-redis") < readiness.index("make test-e2e")
    assert 'REDIS_URL_TEST="$REDIS_URL_TEST" make test-redis' in readiness
    assert 'REDIS_URL_POSTGRES_TEST="$REDIS_URL_POSTGRES_TEST" make test-postgres' in readiness
    assert "derive_redis_test_url 14" in readiness
    assert "derive_redis_test_url 15" in readiness
    assert "Unknown keys are deliberately ignored" in readiness
    assert "PYTEST_ADDOPTS" not in readiness
    assert "subprocess.run" in readiness


def test_hermetic_gate_drops_hostile_runtime_env_but_live_gates_keep_required_bindings(
    tmp_path: Path,
) -> None:
    make_script = """#!/bin/sh
set -eu
case "$*" in
  test)
    [ "${KP_DISABLE_DOTENV:-}" = 1 ]
    [ -z "${KP_WORKER_REPORTED_MAILBOX_URL:-}" ]
    [ -z "${KP_WORKER_MAILPIT_API_URL:-}" ]
    [ -z "${DATABASE_URL_TEST:-}" ]
    [ -z "${AUDIT_DATABASE_URL_TEST:-}" ]
    [ -z "${REDIS_URL:-}" ]
    [ -z "${KP_E2E_PASSWORD:-}" ]
    ;;
  test-postgres)
    [ -n "${DATABASE_URL_TEST:-}" ]
    [ -n "${AUDIT_DATABASE_URL_TEST:-}" ]
    case "${REDIS_URL_POSTGRES_TEST:-}" in */14) ;; *) exit 80 ;; esac
    ;;
  test-redis)
    case "${REDIS_URL_TEST:-}" in */15) ;; *) exit 81 ;; esac
    ;;
  test-e2e)
    [ -n "${KP_E2E_PASSWORD:-}" ]
    [ "${KP_E2E_LIFECYCLE:-}" = 1 ]
    ;;
esac
printf 'make %s\\n' "$*" >> "$KP_TEST_GATE_LOG"
"""
    result = _run_readiness(
        tmp_path,
        df_script=(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
            "/mock 8000000 100 7999900 1%% /\\n'\n"
        ),
        docker_script=(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  info|'compose config --quiet') exit 0 ;;\n"
            "  'compose ps postgres'|'compose ps redis'|'compose ps mailpit') "
            "printf 'service Up (healthy)\\n'; exit 0 ;;\n"
            "  'compose ps --status running --quiet otel-collector'|"
            "'compose ps --status running --quiet mock-idp'|"
            "'compose ps --status running --quiet mock-graph'|"
            "'compose ps --status running --quiet mock-ai') printf 'container-id\\n'; exit 0 ;;\n"
            "esac\n"
            "exit 97\n"
        ),
        gate_exit=0,
        make_script=make_script,
        readiness_extra=(
            "KP_WORKER_REPORTED_MAILBOX_URL=https://mail.attacker.invalid",
            "KP_WORKER_MAILPIT_API_URL=https://mailpit.attacker.invalid/api/v1",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "Operational readiness gate passed" in result.stdout
