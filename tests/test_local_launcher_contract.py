from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap_env.sh"
INSTALLER = ROOT / "scripts" / "install.sh"
RUN_CONSOLE = ROOT / "scripts" / "run_console.sh"
BUILD_LAUNCHER = ROOT / "scripts" / "build_launcher_app.sh"
BASH = shutil.which("bash") or "/bin/bash"


def _bash(
    script: str,
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed shell and test-owned scripts/arguments
        [BASH, "-c", script, "launcher-contract", *args],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _fake_docker_inventory(tmp_path: Path, volume_name: str = "") -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2\" = 'volume ls' ]; then\n"
        '  [ -z "${FAKE_PRESERVED_VOLUME:-}" ] || printf \'%s\\n\' "$FAKE_PRESERVED_VOLUME"\n'
        "  exit 0\n"
        "fi\n"
        "exit 9\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
    environment["FAKE_PRESERVED_VOLUME"] = volume_name
    return environment


def test_bootstrap_updates_env_atomically_and_idempotently(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "POSTGRES_PASSWORD=postgres-kept\n"
        "REDIS_PASSWORD=\n"
        "AUDIT_WRITER_PASSWORD=audit-kept\n"
        "OPERATOR_API_AUDIT_HMAC_KEY=\n"
        "OPERATOR_API_CIPHERTEXT_KEK=\n"
        "CUSTOM_VALUE=literal-$-value\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)
    command = 'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env'

    environment = _fake_docker_inventory(tmp_path)
    first = _bash(command, str(ROOT), str(env_file), str(BOOTSTRAP), env=environment)
    assert first.returncode == 0, first.stderr
    assert first.stdout == ""
    first_content = env_file.read_text(encoding="utf-8")
    second = _bash(command, str(ROOT), str(env_file), str(BOOTSTRAP), env=environment)

    assert second.returncode == 0, second.stderr
    assert second.stdout == ""
    assert env_file.read_text(encoding="utf-8") == first_content
    assert first_content.count("POSTGRES_PASSWORD=") == 1
    assert "POSTGRES_PASSWORD=postgres-kept" in first_content
    assert "CUSTOM_VALUE=literal-$-value" in first_content
    assert "TRACKING_TOKEN_HMAC_KEY=" in first_content
    assert "TRAINING_TOKEN_HMAC_KEY=" in first_content
    values = dict(line.split("=", 1) for line in first_content.splitlines() if "=" in line)
    assert len(values["TRACKING_TOKEN_HMAC_KEY"]) == 64
    assert len(values["TRAINING_TOKEN_HMAC_KEY"]) == 64
    assert values["TRACKING_TOKEN_HMAC_KEY"] != values["TRAINING_TOKEN_HMAC_KEY"]
    assert "TRACKING_API_CORRECTIONS_SECRET=" not in first_content
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o640
    assert not list(tmp_path.glob(".env.tmp.*"))


@pytest.mark.parametrize("mailbox_provider", ["", "mailpit"])
@pytest.mark.parametrize("email_provider", ["", "smtp"])
@pytest.mark.parametrize("quote", ["", "'", '"'])
def test_bootstrap_migrates_only_legacy_host_mailpit_aliases(
    tmp_path: Path,
    quote: str,
    email_provider: str,
    mailbox_provider: str,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPERATOR_API_DEPLOYMENT_MODE=single_tenant\n"
        "OPERATOR_API_OIDC_MODE=dev\n"
        f"KP_WORKER_EMAIL_PROVIDER={email_provider}\n"
        f"KP_WORKER_SMTP_ADDRESS={quote}{quote}\n"
        f"KP_WORKER_MAILPIT_SMTP={quote}mailpit:1025{quote}\n"
        f"KP_WORKER_REPORTED_MAILBOX_PROVIDER={mailbox_provider}\n"
        f"KP_WORKER_MAILPIT_API_URL={quote}http://mailpit:8025{quote}\n"
        f"KP_WORKER_REPORTED_MAILBOX_URL={quote}http://mailpit:8025{quote}\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; _migrate_legacy_local_mailpit_aliases',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert env_file.read_text(encoding="utf-8").splitlines() == [
        "OPERATOR_API_DEPLOYMENT_MODE=single_tenant",
        "OPERATOR_API_OIDC_MODE=dev",
        f"KP_WORKER_EMAIL_PROVIDER={email_provider}",
        f"KP_WORKER_SMTP_ADDRESS={quote}{quote}",
        "KP_WORKER_MAILPIT_SMTP=localhost:1025",
        f"KP_WORKER_REPORTED_MAILBOX_PROVIDER={mailbox_provider}",
        "KP_WORKER_MAILPIT_API_URL=http://localhost:8025",
        "KP_WORKER_REPORTED_MAILBOX_URL=",
    ]
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o640
    assert not list(tmp_path.glob(".env.tmp.*"))


def test_bootstrap_wires_legacy_mailpit_migration_before_defaults(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPERATOR_API_DEPLOYMENT_MODE=single_tenant\n"
        "OPERATOR_API_OIDC_MODE=dev\n"
        "KP_WORKER_EMAIL_PROVIDER=smtp\n"
        "KP_WORKER_SMTP_ADDRESS=\n"
        "KP_WORKER_MAILPIT_SMTP=mailpit:1025\n"
        "KP_WORKER_REPORTED_MAILBOX_PROVIDER=mailpit\n"
        "KP_WORKER_MAILPIT_API_URL=http://mailpit:8025\n"
        "KP_WORKER_REPORTED_MAILBOX_URL=http://mailpit:8025\n",
        encoding="utf-8",
    )

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
        env=_fake_docker_inventory(tmp_path),
    )

    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines() if "=" in line)
    assert values["KP_WORKER_MAILPIT_SMTP"] == "localhost:1025"
    assert values["KP_WORKER_MAILPIT_API_URL"] == "http://localhost:8025"
    assert values["KP_WORKER_REPORTED_MAILBOX_URL"] == ""


@pytest.mark.parametrize("quote", ["", "'", '"'])
@pytest.mark.parametrize("email_provider", ["", "smtp"])
def test_bootstrap_clears_only_redundant_preferred_local_smtp(
    tmp_path: Path,
    quote: str,
    email_provider: str,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPERATOR_API_DEPLOYMENT_MODE=single_tenant\n"
        "OPERATOR_API_OIDC_MODE=dev\n"
        f"KP_WORKER_EMAIL_PROVIDER={email_provider}\n"
        f"KP_WORKER_SMTP_ADDRESS={quote}localhost:1025{quote}\n"
        f"KP_WORKER_MAILPIT_SMTP={quote}localhost:1025{quote}\n"
        "KP_WORKER_REPORTED_MAILBOX_PROVIDER=mailpit\n"
        "KP_WORKER_MAILPIT_API_URL=http://localhost:8025\n"
        "KP_WORKER_REPORTED_MAILBOX_URL=\n",
        encoding="utf-8",
    )

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; _migrate_legacy_local_mailpit_aliases',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
    )

    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines())
    assert values["KP_WORKER_SMTP_ADDRESS"] == ""
    assert values["KP_WORKER_MAILPIT_SMTP"] == f"{quote}localhost:1025{quote}"


@pytest.mark.parametrize(
    "overrides",
    [
        {"OPERATOR_API_DEPLOYMENT_MODE": "managed"},
        {"OPERATOR_API_OIDC_MODE": "oidc"},
        {"KP_WORKER_RUNTIME_MODE": "production"},
        {"KP_WORKER_DEPLOYMENT_MODE": "managed"},
    ],
)
def test_legacy_mailpit_migration_preserves_managed_config(
    tmp_path: Path,
    overrides: dict[str, str],
) -> None:
    values = {
        "OPERATOR_API_DEPLOYMENT_MODE": "single_tenant",
        "OPERATOR_API_OIDC_MODE": "dev",
        "KP_WORKER_RUNTIME_MODE": "development",
        "KP_WORKER_EMAIL_PROVIDER": "smtp",
        "KP_WORKER_SMTP_ADDRESS": "",
        "KP_WORKER_MAILPIT_SMTP": "mailpit:1025",
        "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
        "KP_WORKER_MAILPIT_API_URL": "http://mailpit:8025",
        "KP_WORKER_REPORTED_MAILBOX_URL": "http://mailpit:8025",
    }
    values.update(overrides)
    env_file = tmp_path / ".env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    original = env_file.read_bytes()

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; _migrate_legacy_local_mailpit_aliases',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
    )

    assert result.returncode == 0, result.stderr
    assert env_file.read_bytes() == original


@pytest.mark.parametrize(
    "values",
    [
        {
            "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
            "KP_WORKER_SMTP_ADDRESS": "",
            "KP_WORKER_MAILPIT_SMTP": "mailpit:1025",
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
            "KP_WORKER_MAILPIT_API_URL": "http://localhost:8025",
            "KP_WORKER_REPORTED_MAILBOX_URL": "",
        },
        {
            "KP_WORKER_EMAIL_PROVIDER": "smtp",
            "KP_WORKER_SMTP_ADDRESS": "smtp.example.test:587",
            "KP_WORKER_MAILPIT_SMTP": "mailpit:1025",
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
            "KP_WORKER_MAILPIT_API_URL": "http://localhost:8025",
            "KP_WORKER_REPORTED_MAILBOX_URL": "",
        },
        {
            "KP_WORKER_EMAIL_PROVIDER": "smtp",
            "KP_WORKER_SMTP_ADDRESS": "",
            "KP_WORKER_MAILPIT_SMTP": "localhost:1025",
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
            "KP_WORKER_MAILPIT_API_URL": "http://mailpit:8025",
            "KP_WORKER_REPORTED_MAILBOX_URL": "http://mailpit:8025",
        },
        {
            "KP_WORKER_EMAIL_PROVIDER": "smtp",
            "KP_WORKER_SMTP_ADDRESS": "",
            "KP_WORKER_MAILPIT_SMTP": "localhost:1025",
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
            "KP_WORKER_MAILPIT_API_URL": "http://mailpit:8025",
            "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.microsoft.com",
        },
        {
            "KP_WORKER_EMAIL_PROVIDER": "smtp",
            "KP_WORKER_SMTP_ADDRESS": "",
            "KP_WORKER_MAILPIT_SMTP": "mailpit.internal:1025",
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
            "KP_WORKER_MAILPIT_API_URL": "http://mailpit.internal:8025",
            "KP_WORKER_REPORTED_MAILBOX_URL": "http://mailpit.internal:8025",
        },
    ],
)
def test_legacy_mailpit_migration_preserves_custom_and_nonexact_endpoints(
    tmp_path: Path,
    values: dict[str, str],
) -> None:
    context = {
        "OPERATOR_API_DEPLOYMENT_MODE": "single_tenant",
        "OPERATOR_API_OIDC_MODE": "dev",
        "KP_WORKER_RUNTIME_MODE": "development",
    }
    context.update(values)
    env_file = tmp_path / ".env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in context.items()), encoding="utf-8")
    original = env_file.read_bytes()

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; _migrate_legacy_local_mailpit_aliases',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
    )

    assert result.returncode == 0, result.stderr
    assert env_file.read_bytes() == original


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("OPERATOR_API_AUDIT_HMAC_KEY", "automatic rotation would invalidate audit evidence"),
        ("OPERATOR_API_CIPHERTEXT_KEK", "automatic rotation would make ciphertext unavailable"),
    ],
)
def test_bootstrap_preserves_existing_invalid_data_keys(
    tmp_path: Path,
    key: str,
    message: str,
) -> None:
    env_file = tmp_path / ".env"
    invalid_value = "preserve-this-existing-value"
    env_file.write_text(
        "POSTGRES_PASSWORD=postgres-kept\n"
        "REDIS_PASSWORD=redis-kept\n"
        "AUDIT_WRITER_PASSWORD=audit-kept\n"
        f"OPERATOR_API_AUDIT_HMAC_KEY={'1' * 64}\n"
        f"OPERATOR_API_CIPHERTEXT_KEK={'2' * 64}\n",
        encoding="utf-8",
    )
    content = env_file.read_text(encoding="utf-8").replace(
        f"{key}={'1' * 64 if key.endswith('HMAC_KEY') else '2' * 64}",
        f"{key}={invalid_value}",
    )
    env_file.write_text(content, encoding="utf-8")
    command = 'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env'

    result = _bash(
        command,
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
        env=_fake_docker_inventory(tmp_path),
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert f"{key}={invalid_value}" in env_file.read_text(encoding="utf-8")
    assert invalid_value not in result.stdout
    assert invalid_value not in result.stderr


def test_bootstrap_rejects_cross_service_key_drift_before_any_env_mutation(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"OPERATOR_API_AUDIT_HMAC_KEY={'1' * 64}\nKP_WORKER_AUDIT_HMAC_KEY={'2' * 64}\n",
        encoding="utf-8",
    )
    original = env_file.read_bytes()

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
        env=_fake_docker_inventory(tmp_path),
    )

    assert result.returncode != 0
    assert "OPERATOR_API_AUDIT_HMAC_KEY/KP_WORKER_AUDIT_HMAC_KEY mismatch" in result.stderr
    assert env_file.read_bytes() == original


def test_bootstrap_rejects_invalid_recovery_key_before_any_env_mutation(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("TRACKING_TOKEN_HMAC_KEY=invalid-but-preserved\n", encoding="utf-8")
    original = env_file.read_bytes()

    result = _bash(
        'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env',
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
        env=_fake_docker_inventory(tmp_path),
    )

    assert result.returncode != 0
    assert "invalid recovery key: TRACKING_TOKEN_HMAC_KEY" in result.stderr
    assert "invalid-but-preserved" not in result.stdout + result.stderr
    assert env_file.read_bytes() == original


@pytest.mark.parametrize("existing_env", [False, True])
def test_bootstrap_refuses_new_credentials_when_preserved_state_exists(
    tmp_path: Path,
    existing_env: bool,
) -> None:
    env_file = tmp_path / ".env"
    original = "POSTGRES_PASSWORD=postgres-kept\n" if existing_env else ""
    if existing_env:
        env_file.write_text(original, encoding="utf-8")
    command = 'PROJECT_ROOT="$1"; ENV_FILE="$2"; source "$3"; bootstrap_env'

    result = _bash(
        command,
        str(ROOT),
        str(env_file),
        str(BOOTSTRAP),
        env=_fake_docker_inventory(tmp_path, "legacy-project_postgres_data"),
    )

    assert result.returncode != 0
    assert "preserved PostgreSQL or Redis volumes exist" in result.stderr
    assert "restore the missing keys in .env" in result.stderr
    assert "missing recovery key: OPERATOR_API_CONSOLE_JWT_SECRET" in result.stderr
    assert "missing recovery key: KP_CONSOLE_PASSWORD" in result.stderr
    assert "legacy-project_postgres_data" not in result.stdout + result.stderr
    assert env_file.exists() is existing_env
    if existing_env:
        assert env_file.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("contents", ["", "not-a-pid\n", "0\n", "99999999\n"])
def test_pidfile_helper_rejects_invalid_or_stale_state(tmp_path: Path, contents: str) -> None:
    pidfile = tmp_path / "operator-api.pid"
    pidfile.write_text(contents, encoding="utf-8")
    result = _bash('PROJECT_ROOT="$1"; source "$2"; pidfile_is_live "$3"', str(ROOT), str(BOOTSTRAP), str(pidfile))
    assert result.returncode != 0


@pytest.mark.parametrize("suffix", ["", "\n"])
def test_pidfile_helper_accepts_a_live_numeric_process(tmp_path: Path, suffix: str) -> None:
    pidfile = tmp_path / "operator-api.pid"
    pidfile.write_text(f"{os.getpid()}{suffix}", encoding="utf-8")
    result = _bash('PROJECT_ROOT="$1"; source "$2"; pidfile_is_live "$3"', str(ROOT), str(BOOTSTRAP), str(pidfile))
    assert result.returncode == 0, result.stderr


def test_installer_has_bounded_honest_startup_contract() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "astral.sh/uv/" + "install.sh" not in source
    assert "| sh" not in source
    assert 'UV_MIN_VERSION="0.11.0"' in source
    assert 'bounded 900 "$UV_COMMAND" sync --frozen --all-packages' in source
    assert 'minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"' in source
    assert 'available_kib="$(bounded 10 df -Pk "$PROJECT_ROOT"' in source
    assert "Add disk capacity outside preserved project assets" in source
    assert 'bounded "$DOCKER_TIMEOUT_SECONDS" docker info' in source
    assert 'bounded 900 "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh"' in source
    assert 'INFRASTRUCTURE_START_TIMEOUT_SECONDS="${KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS:-900}"' in source
    assert 'bounded_seconds_are_valid "$INFRASTRUCTURE_START_TIMEOUT_SECONDS" 3600' in source
    assert 'bounded "$INFRASTRUCTURE_START_TIMEOUT_SECONDS" \\\n  dc up -d --no-recreate' in source
    assert "Existing containers, images, and pull/build progress were preserved" in source
    assert "compose_service_healthy postgres" in source
    assert "compose_service_healthy redis" in source
    assert '"$UV_COMMAND" run --frozen --no-sync python scripts/seed.py \\\n  || die' in source
    assert "http://127.0.0.1:8000/readyz" in source
    assert 'bounded 180 "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh"' in source
    assert "/healthz" not in source
    assert source.count('pidfile_is_live "$PROJECT_ROOT/data/run/operator-api.pid"') == 2
    assert "nohup bash scripts/run_console.sh" not in source
    assert 'nohup "$UV_COMMAND" run --frozen --no-sync python scripts/supervisor.py' in source
    assert source.count("\nrun_base_image_qualification\n") == 1
    assert source.count("\nrun_deployment_preflight prestart\n") == 1
    assert source.count("\nrun_deployment_preflight ready\n") == 1
    assert "preserve or reset" not in source
    assert "Settings > Restart / Stop" not in source
    assert "Console password" not in source
    assert "KP_CONSOLE_PASSWORD=" not in source
    assert source.index("require_disk_headroom", source.index('[ "$UV_CHECK_ONLY" -eq 0 ]')) < source.index(
        'bounded 900 "$UV_COMMAND" sync'
    )
    infrastructure_bootstrap = source.rindex("\nbootstrap_env \\")
    prestart_gate = source.index("\nrun_deployment_preflight prestart\n", infrastructure_bootstrap)
    image_gate = source.index("\nrun_base_image_qualification\n", infrastructure_bootstrap)
    ready_gate = source.index("\nrun_deployment_preflight ready\n", source.index("scripts/seed.py"))
    supervisor_start = source.index("starting operator API, tracking API, and worker services")
    assert (
        infrastructure_bootstrap
        < prestart_gate
        < image_gate
        < source.index('bounded "$INFRASTRUCTURE_START_TIMEOUT_SECONDS"')
    )
    assert ready_gate < supervisor_start
    assert source.index("assert_recovery_credentials_before_bootstrap") < source.index('bounded 900 "$UV_COMMAND" sync')


def _fake_uv(tmp_path: Path, output: str, exit_code: int = 0) -> Path:
    executable = tmp_path / "uv"
    executable.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{output}'\nexit {exit_code}\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _check_uv(
    executable: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS", None)
    environment["KP_UV_COMMAND"] = str(executable)
    if extra_env:
        environment.update(extra_env)
    return subprocess.run(  # noqa: S603 - fixed installer and test-owned executable
        [BASH, str(INSTALLER), "--check-uv"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _check_installer_disk(
    tmp_path: Path,
    *,
    minimum_free_gib: str,
    available_kib: int = 1024,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = _fake_uv(bin_dir, "uv 0.11.0")
    df = bin_dir / "df"
    df.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n"
        f"printf '%s\\n' '/dev/test 10000000 9999999 {available_kib} 99% /'\n",
        encoding="utf-8",
    )
    df.chmod(0o700)
    environment = os.environ.copy()
    environment.update(
        {
            "KP_LOCAL_MIN_FREE_GIB": minimum_free_gib,
            "KP_UV_COMMAND": str(uv),
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
        }
    )
    return subprocess.run(  # noqa: S603 - fixed installer and test-owned PATH tools
        [BASH, str(INSTALLER), "--skip-deps"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("version", ["0.11.0", "0.11.99", "1.0.0"])
def test_uv_preflight_accepts_compatible_versions(tmp_path: Path, version: str) -> None:
    result = _check_uv(_fake_uv(tmp_path, f"uv {version}"))

    assert result.returncode == 0, result.stderr
    assert f"uv {version}" in result.stdout
    assert "checking base tooling" in result.stdout
    assert "Docker" not in result.stdout


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("uv 0.10.9", "too old"),
        ("uv development-build", "unrecognized version"),
    ],
)
def test_uv_preflight_rejects_incompatible_versions(
    tmp_path: Path,
    output: str,
    expected: str,
) -> None:
    result = _check_uv(_fake_uv(tmp_path, output))

    assert result.returncode != 0
    assert expected in result.stderr
    assert "Docker" not in result.stdout


def test_uv_preflight_rejects_missing_or_broken_executable(tmp_path: Path) -> None:
    missing = _check_uv(tmp_path / "missing-uv")
    broken = _check_uv(_fake_uv(tmp_path, "uv 0.11.0", exit_code=7))

    assert missing.returncode != 0
    assert "trusted package manager" in missing.stderr
    assert "does not execute downloaded shell scripts" in missing.stderr
    assert broken.returncode != 0
    assert "uv could not run" in broken.stderr


def test_installer_accepts_default_and_bounded_infrastructure_start_timeouts(tmp_path: Path) -> None:
    executable = _fake_uv(tmp_path, "uv 0.11.0")

    default = _check_uv(executable)
    override = _check_uv(
        executable,
        extra_env={"KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS": "3600"},
    )

    assert default.returncode == 0, default.stderr
    assert override.returncode == 0, override.stderr


@pytest.mark.parametrize("timeout", ["0", "-1", "1.5", "900s", "3601", "0000001"])
def test_installer_rejects_invalid_infrastructure_start_timeout_before_work(
    tmp_path: Path,
    timeout: str,
) -> None:
    result = _check_uv(
        _fake_uv(tmp_path, "uv 0.11.0"),
        extra_env={"KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS": timeout},
    )

    assert result.returncode != 0
    assert (
        "KP_LOCAL_INFRASTRUCTURE_START_TIMEOUT_SECONDS must be a positive whole-second integer no greater than 3600"
    ) in result.stderr
    assert "uv 0.11.0" not in result.stdout
    assert "no project assets were changed" in result.stderr


@pytest.mark.parametrize("minimum", ["0", "-1", "1.5", "eight", "0008", "9999999"])
def test_installer_disk_headroom_rejects_non_positive_or_unbounded_configuration(
    tmp_path: Path,
    minimum: str,
) -> None:
    result = _check_installer_disk(tmp_path, minimum_free_gib=minimum)

    assert result.returncode != 0
    assert "KP_LOCAL_MIN_FREE_GIB must be a positive whole-GiB integer" in result.stderr
    assert "Docker" not in result.stdout


def test_installer_low_disk_fails_before_docker_and_only_recommends_capacity(tmp_path: Path) -> None:
    result = _check_installer_disk(tmp_path, minimum_free_gib="8", available_kib=1024)

    assert result.returncode != 0
    assert "Add disk capacity outside preserved project assets" in result.stderr
    assert "Docker" not in result.stdout
    for unsafe_recommendation in ("prune", "delete", "remove", "reset", "cleanup"):
        assert unsafe_recommendation not in result.stderr.lower()


def test_console_launcher_fails_closed_without_destructive_docker_actions() -> None:
    source = RUN_CONSOLE.read_text(encoding="utf-8")

    assert 'bounded "$DOCKER_TIMEOUT_SECONDS" docker info' in source
    assert 'minimum_free_gib="${KP_LOCAL_MIN_FREE_GIB:-8}"' in source
    assert 'available_kib="$(bounded 10 df -Pk "$PROJECT_ROOT"' in source
    assert "Add disk capacity outside preserved project assets" in source
    assert 'bounded 900 "$PROJECT_ROOT/scripts/operator/base-image-qualification/run.sh"' in source
    assert "bounded 120 dc up -d" in source
    assert "bounded 120 dc up -d --no-recreate" in source
    assert "Postgres never became healthy" in source
    assert "Redis never became healthy" in source
    assert "seed skipped" not in source
    assert "database migration failed" in source
    assert "demo seed failed" in source
    assert 'pidfile_is_live "$RUN_DIR/operator-api.pid"' in source
    assert "stack already running and ready" in source
    assert "no duplicate supervisor was launched" in source
    assert "http://127.0.0.1:8000/readyz" in source
    pid_fast_path = source.index('pidfile_is_live "$RUN_DIR/operator-api.pid"')
    assert pid_fast_path < source.index("require_disk_headroom", pid_fast_path)
    assert 'rm -f "$RUN_DIR/restart"' not in source
    assert "RUN_DIR/stop" not in source
    assert "docker compose restart" not in source
    assert "docker compose down" not in source
    assert "docker system prune" not in source
    assert "UV_PYTHON_DOWNLOADS=never uv sync --frozen --all-packages" in source
    assert "uv run --frozen --no-sync alembic" in source
    assert "uv run --frozen --no-sync python scripts/seed.py" in source
    assert 'bounded 180 "$PROJECT_ROOT/scripts/operator/deployment-preflight/run.sh"' in source
    start_infra = source.index("start_infra()")
    bootstrap = source.index("\n  bootstrap_env", start_infra)
    prestart_gate = source.index("\n  run_deployment_preflight prestart\n", start_infra)
    image_gate = source.index("\n  run_base_image_qualification\n", start_infra)
    assert bootstrap < prestart_gate < image_gate < source.index("bounded 120 dc up -d")
    ready_gate = source.index("\nrun_deployment_preflight ready\n", source.index("init_db"))
    assert ready_gate < source.index("\nlaunch_ui\n", ready_gate)
    assert "exec uv run --frozen --no-sync python scripts/supervisor.py" in source


@pytest.mark.parametrize("script", [INSTALLER, RUN_CONSOLE])
def test_local_deployment_paths_do_not_hide_cleanup_or_recreation(script: Path) -> None:
    source = script.read_text(encoding="utf-8")

    for forbidden in (
        "docker compose down",
        "docker compose rm",
        "docker system prune",
        "docker builder prune",
        "docker buildx prune",
        "docker volume rm",
        "docker image rm",
        "docker container rm",
        "rm -f",
        "preserve or reset",
    ):
        assert forbidden not in source
    assert "dc up -d --no-recreate" in source


def test_installer_cold_start_timeout_preserves_no_recreate_and_bounded_readiness() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert source.count("dc up -d --no-recreate") == 1
    assert "dc up -d --force-recreate" not in source
    assert "dc up -d --recreate" not in source
    assert "docker compose pull" not in source
    assert "for _ in $(seq 1 60); do" in source
    assert 'output="$(bounded "$DOCKER_TIMEOUT_SECONDS" dc ps "$1"' in source
    assert source.index("for _ in $(seq 1 60); do") < source.index("compose_service_healthy postgres \\")


@pytest.mark.parametrize("script", [INSTALLER, RUN_CONSOLE])
def test_local_deployment_paths_bound_operator_configured_docker_timeouts(script: Path) -> None:
    source = script.read_text(encoding="utf-8")

    assert 'bounded_seconds_are_valid "$DOCKER_TIMEOUT_SECONDS" 600' in source
    assert "KP_LOCAL_DOCKER_TIMEOUT_SECONDS must be a positive integer no greater than 600" in source


def test_environment_rewrite_is_portable_and_keeps_retired_secret_retired() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert "sed -i ''" not in source
    assert 'mktemp "${ENV_FILE}.tmp.XXXXXX"' in source
    assert 'cp -p "$ENV_FILE" "$temporary"' in source
    assert 'mv -f "$temporary" "$ENV_FILE"' in source
    assert "TRACKING_TOKEN_HMAC_KEY" in source
    assert "TRACKING_API_CORRECTIONS_SECRET" not in source


def test_generated_macos_launcher_validates_pid_and_preserves_gui_controls(
    tmp_path: Path,
) -> None:
    source = BUILD_LAUNCHER.read_text(encoding="utf-8")

    assert 'APP_DIR="$PROJECT_ROOT/Kingphisher Launcher.app"' in source
    assert "pidfile_is_live()" in source
    assert "*[!0-9]*" in source
    assert 'IFS= read -r pid < "$PID_FILE" || [ -n "$pid" ] || return 1' in source
    assert 'kill -0 "$pid"' in source
    assert "if pidfile_is_live; then" in source
    assert 'LOG_FILE="$PROJECT_ROOT/data/logs/launcher-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"' in source
    assert 'if ! "$LAUNCHER" >"$LOG_FILE" 2>&1; then' in source
    assert "Settings page via marker files" in source
    assert "umask 077" in source
    assert 'STAGING_DIR="$PROJECT_ROOT/Kingphisher Launcher.app.next"' in source
    assert 'mv "$APP_DIR" "$BACKUP_DIR"' in source
    assert 'mv "$BACKUP_DIR" "$APP_DIR"' in source
    assert 'cmp -s "$MACOS/launch" "$APP_DIR/Contents/MacOS/launch"' in source
    assert 'rm -- "$MACOS/launch" "$CONTENTS/Info.plist"' in source
    assert "restore_previous_launcher()" in source
    assert "publication_pending=1" in source
    assert "rm -rf" not in source
    assert source.index('zsh -n "$MACOS/launch"') < source.index('mv "$APP_DIR" "$BACKUP_DIR"')

    zsh = shutil.which("zsh")
    if zsh is None:
        pytest.skip("zsh is unavailable on this platform")
    launch_body = source.split("<<'EOF'\n", maxsplit=1)[1].split("\nEOF", maxsplit=1)[0]
    generated = tmp_path / "launch"
    generated.write_text(launch_body, encoding="utf-8")
    syntax = subprocess.run(  # noqa: S603 - local zsh parses a generated test file
        [zsh, "-n", str(generated)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax.returncode == 0, syntax.stderr
