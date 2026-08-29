from __future__ import annotations

import importlib.util
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/operator/deployment-preflight/deployment_preflight.py"
RUNNER_PATH = ROOT / "scripts/operator/deployment-preflight/run.sh"
COMPOSE_PATH = ROOT / "docker-compose.yml"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("deployment_preflight", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves postponed annotations through the registered module.
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


@dataclass(frozen=True)
class _Usage:
    total: int = 20 * 1024**3
    used: int = 4 * 1024**3
    free: int = 16 * 1024**3


class FakeRunner:
    def __init__(
        self,
        *,
        docker_result: Any | None = None,
        compose_result: Any | None = None,
        services_result: Any | None = None,
        volume_list_result: Any | None = None,
        volume_results: Mapping[str, Any] | None = None,
        migration_result: Any | None = None,
    ) -> None:
        result = MODULE.CommandResult
        self.docker_result = docker_result or result(
            0, json.dumps({"Version": "27.1.2", "Os": "linux", "Arch": "arm64"})
        )
        self.compose_result = compose_result or result(0, _compose_json())
        self.services_result = services_result or result(0, _service_json())
        self.volume_list_result = volume_list_result or result(
            0,
            "\n".join(
                (
                    json.dumps({"Name": "phishing-awareness-platform_postgres_data"}),
                    json.dumps({"Name": "phishing-awareness-platform_redis_data"}),
                )
            ),
        )
        self.volume_results = dict(
            volume_results
            or {
                "phishing-awareness-platform_postgres_data": result(0, _volume_inspect_json("postgres_data")),
                "phishing-awareness-platform_redis_data": result(0, _volume_inspect_json("redis_data")),
            }
        )
        self.migration_result = migration_result or result(0, "migration-log-not-reported\n0027 (head)\n")
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[Mapping[str, str]] = []

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
    ) -> Any:
        del cwd, timeout
        command = tuple(args)
        self.calls.append(command)
        self.environments.append(dict(env))
        if command[:2] == ("docker", "version"):
            return self.docker_result
        if command[:3] == ("docker", "compose", "config"):
            return self.compose_result
        if command[:3] == ("docker", "compose", "ps"):
            return self.services_result
        if command[:3] == ("docker", "volume", "ls"):
            return self.volume_list_result
        if command[:3] == ("docker", "volume", "inspect"):
            return self.volume_results.get(command[3], MODULE.CommandResult(1, error_code="command_failed"))
        if command[:2] == ("uv", "run"):
            return self.migration_result
        raise AssertionError(f"unexpected command shape: {command!r}")


def _compose_json(secret: str | None = None) -> str:
    captured_secret = secret or "not-reported-sensitive-value"
    return json.dumps(
        {
            "name": "phishing-awareness-platform",
            "services": {"postgres": {"environment": {"PASSWORD": captured_secret}}, "redis": {}},
            "volumes": {
                "postgres_data": {"name": "phishing-awareness-platform_postgres_data"},
                "redis_data": {"name": "phishing-awareness-platform_redis_data"},
            },
        }
    )


def _service_json(*, postgres_health: str = "healthy", redis_health: str = "healthy") -> str:
    return "\n".join(
        (
            json.dumps({"Service": "postgres", "State": "running", "Health": postgres_health}),
            json.dumps({"Service": "redis", "State": "running", "Health": redis_health}),
        )
    )


def _volume_inspect_json(key: str) -> str:
    return json.dumps(
        {
            "Name": f"phishing-awareness-platform_{key}",
            "Labels": {
                "com.docker.compose.project": "phishing-awareness-platform",
                "com.docker.compose.volume": key,
            },
        }
    )


def _report(tmp_path: Path, runner: FakeRunner, **kwargs: Any) -> dict[str, object]:
    return MODULE.run_preflight(
        tmp_path,
        runner=runner,
        disk_usage=kwargs.pop("disk_usage", lambda _path: _Usage()),
        now=lambda: datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        **kwargs,
    )


def _checks(report: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    return {item["check"]: item for item in report["checks"]}  # type: ignore[index, misc]


def test_preserved_healthy_stack_is_ready_and_reports_only_normalized_evidence(tmp_path: Path) -> None:
    secret = "do-not-leak-this-password"
    runner = FakeRunner(compose_result=MODULE.CommandResult(0, _compose_json(secret)))

    report = _report(tmp_path, runner)

    assert report["schema"] == "kp.deployment-preflight.v1"
    assert report["phase"] == "ready"
    assert report["result"] == "ready"
    assert report["preservation_policy"] == {
        "state": "preservation_required",
        "mutation_performed": False,
        "automatic_cleanup_allowed": False,
    }
    checks = _checks(report)
    assert checks["persistent_volumes"]["status"] == "pass"
    assert checks["postgres_readiness"]["status"] == "pass"
    assert checks["redis_readiness"]["status"] == "pass"
    assert checks["database_migration_head"]["status"] == "pass"
    assert checks["database_migration_head"]["evidence"]["current_revision"] == "0027"  # type: ignore[index]
    rendered = json.dumps(report) + MODULE.render_human(report)
    assert secret not in rendered
    assert "migration-log-not-reported" not in rendered


def test_commands_are_read_only_allowlisted_shapes() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    wrapper = RUNNER_PATH.read_text(encoding="utf-8")

    forbidden_command_fragments = (
        '"prune"',
        '"down"',
        '"rm"',
        '"reset"',
        '"delete"',
        '"recreate"',
        '"up"',
        '"pull"',
        '"build"',
    )
    assert not any(fragment in source for fragment in forbidden_command_fragments)
    assert "source " not in wrapper
    assert "docker " not in wrapper


def test_dotenv_is_inert_data_and_values_are_not_rendered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    marker = tmp_path / "must-not-exist"
    secret = "ultra-private"
    (tmp_path / ".env").write_text(
        (
            f"SECRET={secret}\nEVIL=$(touch {marker})\nSPACED=value with spaces\n"
            f"DERIVED=${{SECRET}}-suffix\nPATH=/tmp/hostile\nDOCKER_HOST=tcp://attacker.invalid:2375\n"
        ),
        encoding="utf-8",
    )
    runner = FakeRunner()

    report = _report(tmp_path, runner)

    assert not marker.exists()
    assert runner.environments
    assert runner.environments[0]["PATH"] == os.environ["PATH"]
    assert "DOCKER_HOST" not in runner.environments[0]
    assert all("EVIL" not in environment for environment in runner.environments)
    assert all("SPACED" not in environment for environment in runner.environments)
    assert all("DERIVED" not in environment for environment in runner.environments)
    assert secret not in json.dumps(report)
    assert str(marker) not in json.dumps(report)


def test_ambient_docker_endpoint_is_preserved_but_dotenv_cannot_override_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_host = "unix:///trusted/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", trusted_host)
    (tmp_path / ".env").write_text("DOCKER_HOST=tcp://untrusted.invalid:2375\n", encoding="utf-8")
    runner = FakeRunner()

    _report(tmp_path, runner)

    assert runner.environments
    assert all(environment["DOCKER_HOST"] == trusted_host for environment in runner.environments)


def test_each_command_receives_only_its_minimum_configuration(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "POSTGRES_PASSWORD=postgres-secret\n"
        "REDIS_PASSWORD=redis-secret\n"
        "AUDIT_WRITER_PASSWORD=audit-secret\n"
        "MAILPIT_API_PASSWORD=mailpit-secret\n"
        "DATABASE_URL=postgresql+psycopg://user:database-secret@localhost/database\n"
        "UNRELATED_SECRET=must-never-reach-a-child\n",
        encoding="utf-8",
    )
    runner = FakeRunner()

    _report(tmp_path, runner)

    compose_keys = {"POSTGRES_PASSWORD", "REDIS_PASSWORD", "AUDIT_WRITER_PASSWORD", "MAILPIT_API_PASSWORD"}
    for command, environment in zip(runner.calls, runner.environments, strict=True):
        assert "UNRELATED_SECRET" not in environment
        if command[:3] in {("docker", "compose", "config"), ("docker", "compose", "ps")}:
            assert compose_keys.issubset(environment)
            assert "DATABASE_URL" not in environment
        elif command[:2] == ("uv", "run"):
            assert "DATABASE_URL" in environment
            assert not compose_keys.intersection(environment)
        else:
            assert "DATABASE_URL" not in environment
            assert not compose_keys.intersection(environment)


def test_prestart_clean_initial_host_passes_without_creating_volumes_or_querying_database(tmp_path: Path) -> None:
    missing = MODULE.CommandResult(1, error_code="command_failed")
    runner = FakeRunner(
        services_result=MODULE.CommandResult(0, ""),
        volume_list_result=MODULE.CommandResult(0, ""),
        volume_results={
            "phishing-awareness-platform_postgres_data": missing,
            "phishing-awareness-platform_redis_data": missing,
        },
    )

    report = _report(tmp_path, runner, phase="prestart")

    checks = _checks(report)
    assert report["result"] == "ready"
    assert report["phase"] == "prestart"
    assert checks["preflight_phase"]["evidence"] == {"phase": "prestart", "inspection_only": True}
    assert checks["persistent_volumes"]["evidence"]["deployment_state"] == "clean_initial"  # type: ignore[index]
    assert "postgres_readiness" not in checks
    assert "redis_readiness" not in checks
    assert "database_migration_head" not in checks
    assert not any(call[:2] == ("uv", "run") for call in runner.calls)


def test_ready_clean_initial_host_blocks_until_required_services_are_running(tmp_path: Path) -> None:
    missing = MODULE.CommandResult(1, error_code="command_failed")
    runner = FakeRunner(
        services_result=MODULE.CommandResult(0, ""),
        volume_list_result=MODULE.CommandResult(0, ""),
        volume_results={
            "phishing-awareness-platform_postgres_data": missing,
            "phishing-awareness-platform_redis_data": missing,
        },
    )

    report = _report(tmp_path, runner)

    checks = _checks(report)
    assert report["phase"] == "ready"
    assert report["result"] == "blocked"
    assert checks["persistent_volumes"]["evidence"]["deployment_state"] == "clean_initial"  # type: ignore[index]
    assert checks["postgres_readiness"]["status"] == "fail"
    assert checks["redis_readiness"]["status"] == "fail"
    assert checks["database_migration_head"]["status"] == "not_applicable"
    assert not any(call[:2] == ("uv", "run") for call in runner.calls)


def test_prestart_stopped_preserved_stack_passes_without_health_or_migration_checks(tmp_path: Path) -> None:
    services = "\n".join(
        (
            json.dumps({"Service": "postgres", "State": "exited", "Health": ""}),
            json.dumps({"Service": "redis", "State": "exited", "Health": ""}),
        )
    )
    runner = FakeRunner(services_result=MODULE.CommandResult(0, services))

    report = _report(tmp_path, runner, phase="prestart")

    checks = _checks(report)
    assert report["result"] == "ready"
    assert checks["service_inventory"]["evidence"]["present_services"] == ["postgres", "redis"]  # type: ignore[index]
    assert checks["persistent_volumes"]["status"] == "pass"
    assert "postgres_readiness" not in checks
    assert "redis_readiness" not in checks
    assert "database_migration_head" not in checks
    assert not any(call[:2] == ("uv", "run") for call in runner.calls)


def test_ready_stopped_preserved_stack_blocks_and_does_not_query_migrations(tmp_path: Path) -> None:
    services = "\n".join(
        (
            json.dumps({"Service": "postgres", "State": "exited", "Health": ""}),
            json.dumps({"Service": "redis", "State": "exited", "Health": ""}),
        )
    )
    runner = FakeRunner(services_result=MODULE.CommandResult(0, services))

    report = _report(tmp_path, runner, phase="ready")

    checks = _checks(report)
    assert report["result"] == "blocked"
    assert checks["postgres_readiness"]["status"] == "fail"
    assert checks["redis_readiness"]["status"] == "fail"
    assert checks["database_migration_head"]["status"] == "not_applicable"
    assert not any(call[:2] == ("uv", "run") for call in runner.calls)


def test_partial_or_drifted_volume_inventory_blocks_without_repairing_it(tmp_path: Path) -> None:
    runner = FakeRunner(
        services_result=MODULE.CommandResult(0, ""),
        volume_list_result=MODULE.CommandResult(0, json.dumps({"Name": "phishing-awareness-platform_postgres_data"})),
        volume_results={
            "phishing-awareness-platform_postgres_data": MODULE.CommandResult(0, _volume_inspect_json("postgres_data")),
            "phishing-awareness-platform_redis_data": MODULE.CommandResult(1, error_code="command_failed"),
        },
    )

    report = _report(tmp_path, runner, phase="prestart")

    check = _checks(report)["persistent_volumes"]
    assert report["result"] == "blocked"
    assert report["phase"] == "prestart"
    assert check["status"] == "fail"
    assert check["evidence"]["missing_volume_keys"] == ["redis_data"]  # type: ignore[index]
    assert "do not recreate or remove" in str(check["safe_next_action"]).lower()


def test_checkout_move_cannot_hide_legacy_compose_state(tmp_path: Path) -> None:
    legacy = "old-checkout_postgres_data"
    runner = FakeRunner(volume_list_result=MODULE.CommandResult(0, json.dumps({"Name": legacy})))

    report = _report(tmp_path, runner, phase="prestart")

    check = _checks(report)["persistent_volumes"]
    assert report["result"] == "blocked"
    assert check["status"] == "fail"
    assert check["evidence"]["unrecognized_associated_volume_count"] == 1  # type: ignore[index]
    assert legacy not in json.dumps(report)


def test_compose_project_and_persistent_volume_names_are_frozen() -> None:
    source = COMPOSE_PATH.read_text(encoding="utf-8")

    assert source.startswith("name: phishing-awareness-platform\n")
    assert "    name: phishing-awareness-platform_postgres_data" in source
    assert "    name: phishing-awareness-platform_redis_data" in source


def test_low_disk_blocks_and_never_recommends_project_cleanup(tmp_path: Path) -> None:
    runner = FakeRunner()

    report = _report(tmp_path, runner, disk_usage=lambda _path: _Usage(free=1024))

    check = _checks(report)["disk_headroom"]
    assert report["result"] == "blocked"
    assert check["status"] == "fail"
    assert check["evidence"] == {"free_bytes": 1024, "minimum_free_bytes": 8 * 1024**3}
    assert "do not prune or delete" in str(check["safe_next_action"]).lower()


def test_unavailable_docker_fails_closed_with_bounded_error_and_stops_docker_checks(tmp_path: Path) -> None:
    runner = FakeRunner(docker_result=MODULE.CommandResult(127, error_code="command_not_found"))

    report = _report(tmp_path, runner)

    checks = _checks(report)
    assert report["result"] == "blocked"
    assert checks["docker_daemon"]["evidence"]["error_code"] == "command_not_found"  # type: ignore[index]
    assert len(runner.calls) == 1
    assert "stderr" not in json.dumps(report).lower()


def test_mixed_or_truncated_service_inventory_cannot_partially_parse_as_success(tmp_path: Path) -> None:
    runner = FakeRunner(services_result=MODULE.CommandResult(0, _service_json() + "\n{truncated"))

    report = _report(tmp_path, runner, phase="prestart")

    check = _checks(report)["service_inventory"]
    assert report["result"] == "blocked"
    assert check["status"] == "fail"
    assert check["evidence"]["error_code"] == "malformed_response"  # type: ignore[index]


def test_duplicate_stateful_service_identity_blocks_without_mutation(tmp_path: Path) -> None:
    inventory = "\n".join(
        (
            json.dumps({"Project": "phishing-awareness-platform", "Service": "postgres", "State": "running"}),
            json.dumps({"Project": "phishing-awareness-platform", "Service": "postgres", "State": "running"}),
            json.dumps({"Project": "phishing-awareness-platform", "Service": "redis", "State": "running"}),
        )
    )
    runner = FakeRunner(services_result=MODULE.CommandResult(0, inventory))

    report = _report(tmp_path, runner, phase="prestart")

    check = _checks(report)["service_inventory"]
    assert report["result"] == "blocked"
    assert check["evidence"]["duplicate_service_keys"] == ["postgres"]  # type: ignore[index]
    assert "do not recreate or remove" in str(check["safe_next_action"]).lower()


def test_invalid_compose_error_cannot_leak_captured_secret(tmp_path: Path) -> None:
    secret = "postgresql://admin:password@example.invalid/database"
    runner = FakeRunner(compose_result=MODULE.CommandResult(1, secret, "command_failed"))

    report = _report(tmp_path, runner)

    assert report["result"] == "blocked"
    assert secret not in json.dumps(report)
    assert len(runner.calls) == 2


def test_unhealthy_present_service_blocks_and_skips_migration_query(tmp_path: Path) -> None:
    runner = FakeRunner(services_result=MODULE.CommandResult(0, _service_json(postgres_health="unhealthy")))

    report = _report(tmp_path, runner)

    checks = _checks(report)
    assert report["result"] == "blocked"
    assert checks["postgres_readiness"]["status"] == "fail"
    assert checks["database_migration_head"]["status"] == "not_applicable"
    assert not any(call[:2] == ("uv", "run") for call in runner.calls)


def test_migration_drift_blocks_and_does_not_expose_database_output(tmp_path: Path) -> None:
    secret_dsn = "postgresql://operator:password@localhost/database"
    runner = FakeRunner(migration_result=MODULE.CommandResult(1, secret_dsn, "command_failed"))

    report = _report(tmp_path, runner)

    migration = _checks(report)["database_migration_head"]
    assert report["result"] == "blocked"
    assert migration["status"] == "fail"
    assert migration["evidence"] == {"queried": True, "error_code": "command_failed"}
    assert secret_dsn not in json.dumps(report)


def test_cli_json_is_single_machine_readable_document(monkeypatch: Any, capsys: Any) -> None:
    calls: list[dict[str, Any]] = []

    def fake_preflight(*_args: Any, **kwargs: Any) -> dict[str, object]:
        calls.append(kwargs)
        return {"result": "ready", "checks": []}

    monkeypatch.setattr(MODULE, "run_preflight", fake_preflight)

    assert MODULE.main(["--json", "--phase", "prestart"]) == 0

    output = capsys.readouterr().out
    assert json.loads(output) == {"checks": [], "result": "ready"}
    assert output.count("\n") == 1
    assert calls[0]["phase"] == "prestart"


def test_programmatic_preflight_rejects_unknown_phase(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="phase must be one of"):
        MODULE.run_preflight(tmp_path, runner=FakeRunner(), phase="startup")


@pytest.mark.parametrize("timeout", [0, 601])
def test_programmatic_preflight_rejects_unbounded_timeout(tmp_path: Path, timeout: int) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be between"):
        MODULE.run_preflight(tmp_path, runner=FakeRunner(), timeout_seconds=timeout)


def test_subprocess_runner_maps_timeout_without_retaining_output(monkeypatch: Any, tmp_path: Path) -> None:
    def timeout(*_args: Any, **_kwargs: Any) -> None:
        raise MODULE.subprocess.TimeoutExpired(cmd="docker", timeout=1, output="secret")

    monkeypatch.setattr(MODULE.subprocess, "run", timeout)

    result = MODULE.SubprocessRunner().run(("docker", "version"), cwd=tmp_path, env=os.environ, timeout=1)

    assert result == MODULE.CommandResult(124, error_code="timeout")


def test_subprocess_runner_rejects_oversized_output_without_retaining_it(monkeypatch: Any, tmp_path: Path) -> None:
    completed = MODULE.subprocess.CompletedProcess(
        args=("docker", "version"),
        returncode=0,
        stdout="s" * (MODULE.MAX_CAPTURE_CHARS + 1),
        stderr="",
    )
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *_args, **_kwargs: completed)

    result = MODULE.SubprocessRunner().run(("docker", "version"), cwd=tmp_path, env=os.environ, timeout=1)

    assert result == MODULE.CommandResult(125, error_code="output_limit_exceeded")
