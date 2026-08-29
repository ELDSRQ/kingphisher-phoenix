#!/usr/bin/env python3
"""Read-only local deployment preflight with recovery-safe evidence.

This module deliberately has no Docker mutation code.  It can inspect a clean
host, a stopped preserved stack, or a running stack, but it never creates,
recreates, removes, or prunes project state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

SCHEMA = "kp.deployment-preflight.v1"
DEFAULT_MINIMUM_FREE_BYTES = 8 * 1024**3
DEFAULT_TIMEOUT_SECONDS = 10
MAX_CAPTURE_CHARS = 1_048_576
MAX_TIMEOUT_SECONDS = 600
MAX_MINIMUM_FREE_GIB = 1_048_576
EXPECTED_PERSISTENT_VOLUMES = frozenset({"postgres_data", "redis_data"})
EXPECTED_PROJECT_NAME = "phishing-awareness-platform"
EXPECTED_VOLUME_NAMES = {
    "postgres_data": "phishing-awareness-platform_postgres_data",
    "redis_data": "phishing-awareness-platform_redis_data",
}
PREFLIGHT_PHASES = frozenset({"prestart", "ready"})
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SAFE_PROJECT_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
MIGRATION_HEAD = re.compile(r"(?m)^([0-9][A-Za-z0-9_]{0,127})\s+\(head\)\s*$")
DOTENV_DENYLIST = frozenset(
    {"BASH_ENV", "CDPATH", "ENV", "GLOBIGNORE", "IFS", "PATH", "PYTHONHOME", "PYTHONPATH", "SHELLOPTS"}
)
HOST_ENV_ALLOWLIST = frozenset(
    {
        "DOCKER_CERT_PATH",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
        "USER",
    }
)
COMPOSE_ENV_KEYS = frozenset({"AUDIT_WRITER_PASSWORD", "MAILPIT_API_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD"})
MIGRATION_ENV_KEYS = frozenset({"DATABASE_URL"})


@dataclass(frozen=True)
class CommandResult:
    """Bounded result from an allowlisted, read-only command."""

    returncode: int
    stdout: str = ""
    error_code: str | None = None


class CommandRunner(Protocol):
    """Injectable command boundary used by the deterministic test suite."""

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
    ) -> CommandResult: ...


class DiskUsage(Protocol):
    """Minimum disk-usage shape needed by the preflight."""

    @property
    def free(self) -> int: ...


class SubprocessRunner:
    """Execute only commands selected by the preflight functions below."""

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
    ) -> CommandResult:
        try:
            completed = subprocess.run(  # noqa: S603 - every caller supplies a fixed command shape
                list(args),
                cwd=cwd,
                env=dict(env),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(returncode=127, error_code="command_not_found")
        except subprocess.TimeoutExpired:
            return CommandResult(returncode=124, error_code="timeout")
        except (OSError, UnicodeError):
            return CommandResult(returncode=126, error_code="execution_unavailable")
        if len(completed.stdout) > MAX_CAPTURE_CHARS:
            return CommandResult(returncode=125, error_code="output_limit_exceeded")
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            error_code=None if completed.returncode == 0 else "command_failed",
        )


@dataclass(frozen=True)
class Check:
    """A normalized check that cannot accidentally contain raw command output."""

    check: str
    status: str
    summary: str
    evidence: dict[str, object]
    safe_next_action: str


def _check(
    name: str,
    status: str,
    summary: str,
    *,
    evidence: Mapping[str, object] | None = None,
    safe_next_action: str = "No action required.",
) -> Check:
    return Check(name, status, summary, dict(evidence or {}), safe_next_action)


def load_dotenv_as_data(path: Path) -> dict[str, str]:
    """Parse dotenv assignments without invoking a shell or evaluating syntax."""

    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        name = name.removeprefix("export ").strip()
        if not ENV_NAME.fullmatch(name):
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[name] = value

    # Expand only ${NAME} data references.  Shell substitutions, backticks,
    # commands, and unbraced dollar expressions remain inert literal text.
    for _ in range(len(values) + 1):
        changed = False
        for name, value in tuple(values.items()):
            expanded = INTERPOLATION.sub(lambda match: values.get(match.group(1), match.group(0)), value)
            if expanded != value:
                values[name] = expanded
                changed = True
        if not changed:
            break
    return values


def _command_env(project_root: Path, dotenv_keys: Collection[str] = ()) -> dict[str, str]:
    environment = {name: value for name, value in os.environ.items() if name in HOST_ENV_ALLOWLIST}
    dotenv = load_dotenv_as_data(project_root / ".env")
    environment.update(
        {
            name: value
            for name, value in dotenv.items()
            if name in dotenv_keys
            and name not in DOTENV_DENYLIST
            and not name.startswith("LD_")
            and not name.startswith("DYLD_")
            and not name.startswith("DOCKER_")
        }
    )
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    return environment


def _run(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    root: Path,
    env: Mapping[str, str],
    timeout: int,
) -> CommandResult:
    return runner.run(tuple(args), cwd=root, env=env, timeout=timeout)


def _parse_json_lines(raw: str) -> list[dict[str, object]] | None:
    """Parse Docker JSON without accepting truncated or mixed output."""

    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed if all(isinstance(item, dict) for item in parsed) else None

    items: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(item, dict):
            return None
        items.append(item)
    return items


def _disk_check(root: Path, minimum_free_bytes: int, disk_usage: Callable[[Path], DiskUsage]) -> Check:
    try:
        usage = disk_usage(root)
        free_bytes = int(usage.free)
    except (OSError, TypeError, ValueError, AttributeError):
        return _check(
            "disk_headroom",
            "fail",
            "Free disk space could not be measured.",
            evidence={"minimum_free_bytes": minimum_free_bytes},
            safe_next_action=(
                "Stop before deployment and have an operator add disk capacity; do not prune project assets."
            ),
        )
    status = "pass" if free_bytes >= minimum_free_bytes else "fail"
    return _check(
        "disk_headroom",
        status,
        "Deployment disk headroom is sufficient."
        if status == "pass"
        else "Deployment disk headroom is below the required minimum.",
        evidence={"free_bytes": free_bytes, "minimum_free_bytes": minimum_free_bytes},
        safe_next_action="No action required."
        if status == "pass"
        else "Stop before deployment and add capacity outside preserved project assets; do not prune or delete them.",
    )


def _docker_check(
    runner: CommandRunner, root: Path, env: Mapping[str, str], timeout: int
) -> tuple[Check, dict[str, object] | None]:
    result = _run(
        runner,
        ("docker", "version", "--format", "{{json .Server}}"),
        root=root,
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        return (
            _check(
                "docker_daemon",
                "fail",
                "Docker daemon metadata is unavailable.",
                evidence={"error_code": result.error_code or "command_failed", "inspection_only": True},
                safe_next_action="Start or grant access to Docker, then rerun this read-only preflight.",
            ),
            None,
        )
    try:
        server = json.loads(result.stdout)
    except json.JSONDecodeError:
        server = None
    if not isinstance(server, dict):
        return (
            _check(
                "docker_daemon",
                "fail",
                "Docker returned malformed daemon metadata.",
                evidence={"error_code": "malformed_response", "inspection_only": True},
                safe_next_action="Repair Docker daemon access, then rerun this read-only preflight.",
            ),
            None,
        )
    normalized = {
        "version": str(server.get("Version", "unknown"))[:64],
        "os": str(server.get("Os", "unknown"))[:32],
        "architecture": str(server.get("Arch", "unknown"))[:32],
    }
    return (
        _check(
            "docker_daemon",
            "pass",
            "Docker daemon is reachable through an inspection-only request.",
            evidence={**normalized, "inspection_only": True},
        ),
        server,
    )


def _compose_check(
    runner: CommandRunner, root: Path, env: Mapping[str, str], timeout: int
) -> tuple[Check, dict[str, object] | None]:
    result = _run(
        runner,
        ("docker", "compose", "config", "--format", "json"),
        root=root,
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        return (
            _check(
                "compose_configuration",
                "fail",
                "Compose configuration is missing, invalid, or unavailable.",
                evidence={"error_code": result.error_code or "command_failed"},
                safe_next_action="Correct the Compose configuration without changing persistent resources, then rerun.",
            ),
            None,
        )
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError:
        config = None
    if not isinstance(config, dict):
        return (
            _check(
                "compose_configuration",
                "fail",
                "Compose returned malformed configuration metadata.",
                evidence={"error_code": "malformed_response"},
                safe_next_action="Inspect Compose configuration locally, correct it, and rerun.",
            ),
            None,
        )
    project_name = config.get("name")
    volumes = config.get("volumes")
    if not isinstance(project_name, str) or not SAFE_PROJECT_NAME.fullmatch(project_name):
        return (
            _check(
                "compose_configuration",
                "fail",
                "Compose project identity is missing or unsafe to inspect.",
                evidence={"error_code": "invalid_project_identity"},
                safe_next_action="Set a simple Compose project name and rerun; do not rename existing volumes.",
            ),
            None,
        )
    if project_name != EXPECTED_PROJECT_NAME:
        return (
            _check(
                "compose_configuration",
                "fail",
                "Compose project identity does not match the frozen recovery identity.",
                evidence={"error_code": "project_identity_drift"},
                safe_next_action=(
                    "Restore the reviewed Compose project name; do not create parallel volumes under a new name."
                ),
            ),
            None,
        )
    if not isinstance(volumes, dict) or not EXPECTED_PERSISTENT_VOLUMES.issubset(volumes):
        return (
            _check(
                "compose_configuration",
                "fail",
                "Compose does not declare every required persistent volume.",
                evidence={"project_name": project_name, "required_volume_keys": sorted(EXPECTED_PERSISTENT_VOLUMES)},
                safe_next_action="Restore the persistent-volume declarations before any deployment action.",
            ),
            None,
        )
    return (
        _check(
            "compose_configuration",
            "pass",
            "Compose configuration is valid and declares required persistent state.",
            evidence={"project_name": project_name, "required_volume_keys": sorted(EXPECTED_PERSISTENT_VOLUMES)},
        ),
        config,
    )


def _expected_volume_names(config: Mapping[str, object]) -> dict[str, str] | None:
    raw_volumes = config.get("volumes")
    if not isinstance(raw_volumes, dict):
        return None
    result: dict[str, str] = {}
    for key in EXPECTED_PERSISTENT_VOLUMES:
        entry = raw_volumes.get(key)
        if not isinstance(entry, dict):
            return None
        name = entry.get("name")
        if not isinstance(name, str) or not SAFE_PROJECT_NAME.fullmatch(name):
            return None
        if name != EXPECTED_VOLUME_NAMES[key]:
            return None
        result[key] = name
    return result


def _service_inventory(
    runner: CommandRunner, root: Path, env: Mapping[str, str], timeout: int
) -> tuple[Check, dict[str, dict[str, object]] | None]:
    result = _run(
        runner,
        ("docker", "compose", "ps", "--all", "postgres", "redis", "--format", "json"),
        root=root,
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        return (
            _check(
                "service_inventory",
                "fail",
                "PostgreSQL and Redis service state could not be inspected.",
                evidence={"error_code": result.error_code or "command_failed", "inspection_only": True},
                safe_next_action="Restore Docker inspection access and rerun; do not recreate or remove services.",
            ),
            None,
        )
    items = _parse_json_lines(result.stdout)
    if items is None:
        return (
            _check(
                "service_inventory",
                "fail",
                "Docker returned malformed service inventory metadata.",
                evidence={"error_code": "malformed_response", "inspection_only": True},
                safe_next_action="Repair Docker inspection output and rerun; do not recreate or remove services.",
            ),
            None,
        )
    services: dict[str, dict[str, object]] = {}
    duplicate_services: set[str] = set()
    identity_drift_services: set[str] = set()
    for item in items:
        service = item.get("Service") or item.get("service")
        if isinstance(service, str) and service in {"postgres", "redis"}:
            if service in services:
                duplicate_services.add(service)
            project = item.get("Project") or item.get("project")
            if project is not None and project != EXPECTED_PROJECT_NAME:
                identity_drift_services.add(service)
            services[service] = item
    if duplicate_services or identity_drift_services:
        return (
            _check(
                "service_inventory",
                "fail",
                "PostgreSQL or Redis service identity is ambiguous or has drifted.",
                evidence={
                    "duplicate_service_keys": sorted(duplicate_services),
                    "identity_drift_service_keys": sorted(identity_drift_services),
                    "inspection_only": True,
                },
                safe_next_action=(
                    "Stop and reconcile the preserved container inventory; do not recreate or remove services."
                ),
            ),
            services,
        )
    return (
        _check(
            "service_inventory",
            "pass",
            "PostgreSQL and Redis service state was inspected without mutation.",
            evidence={"present_services": sorted(services), "inspection_only": True},
        ),
        services,
    )


def _project_volume_inventory(
    runner: CommandRunner,
    root: Path,
    env: Mapping[str, str],
    timeout: int,
    config: Mapping[str, object],
    services: Mapping[str, object],
) -> Check:
    project_name = config.get("name")
    names = _expected_volume_names(config)
    if not isinstance(project_name, str) or names is None:
        return _check(
            "persistent_volumes",
            "fail",
            "Expected volume identities could not be derived safely.",
            safe_next_action="Restore the reviewed Compose volume declarations before deployment.",
        )

    listed_items: list[dict[str, object]] = []
    for key in sorted(EXPECTED_PERSISTENT_VOLUMES):
        listed = _run(
            runner,
            (
                "docker",
                "volume",
                "ls",
                "--filter",
                f"label=com.docker.compose.volume={key}",
                "--format",
                "{{json .}}",
            ),
            root=root,
            env=env,
            timeout=timeout,
        )
        if listed.returncode != 0:
            return _check(
                "persistent_volumes",
                "fail",
                "Compose-managed state volume inventory could not be inspected.",
                evidence={"error_code": listed.error_code or "command_failed", "preservation_required": True},
                safe_next_action="Restore read-only Docker volume access; do not create, delete, or rename volumes.",
            )
        parsed = _parse_json_lines(listed.stdout)
        if parsed is None:
            return _check(
                "persistent_volumes",
                "fail",
                "Docker returned malformed state volume inventory metadata.",
                evidence={"error_code": "malformed_response", "preservation_required": True},
                safe_next_action="Repair Docker inspection output; do not create, delete, or rename volumes.",
            )
        listed_items.extend(parsed)
    associated_names = {str(item.get("Name")) for item in listed_items if isinstance(item.get("Name"), str)}
    legacy_names = associated_names - set(names.values())
    present: list[str] = []
    missing: list[str] = []
    identity_mismatch: list[str] = []
    for key, name in sorted(names.items()):
        inspected = _run(
            runner,
            ("docker", "volume", "inspect", name, "--format", "{{json .}}"),
            root=root,
            env=env,
            timeout=timeout,
        )
        if inspected.returncode != 0:
            missing.append(key)
            continue
        metadata = _parse_json_lines(inspected.stdout)
        if metadata is None:
            identity_mismatch.append(key)
            continue
        item = metadata[0] if len(metadata) == 1 else None
        labels = item.get("Labels") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or item.get("Name") != name
            or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != project_name
            or labels.get("com.docker.compose.volume") != key
        ):
            identity_mismatch.append(key)
            continue
        present.append(key)

    evidence: dict[str, object] = {
        "expected_volume_keys": sorted(names),
        "present_volume_keys": present,
        "missing_volume_keys": missing,
        "identity_mismatch_volume_keys": identity_mismatch,
        "associated_volume_count": len(associated_names),
        "unrecognized_associated_volume_count": len(legacy_names),
        "preservation_required": True,
        "inspection_only": True,
    }
    if not missing and not identity_mismatch and not legacy_names:
        return _check(
            "persistent_volumes",
            "pass",
            "All expected persistent volumes exist and remain preservation-required.",
            evidence=evidence,
        )
    if len(missing) == len(names) and not identity_mismatch and not associated_names and not services:
        evidence["deployment_state"] = "clean_initial"
        return _check(
            "persistent_volumes",
            "pass",
            "No prior project state was detected; this is a clean initial deployment boundary.",
            evidence=evidence,
            safe_next_action=(
                "Continue only through the reviewed deployment workflow; never run cleanup as initialization."
            ),
        )
    return _check(
        "persistent_volumes",
        "fail",
        "Persistent volume state is partial or has drifted; automatic deployment is blocked.",
        evidence=evidence,
        safe_next_action=(
            "Stop and reconcile the preserved volumes from inventory or backup; do not recreate or remove them."
        ),
    )


def _normalized_service_check(service: str, item: Mapping[str, object] | None) -> Check:
    if item is None:
        return _check(
            f"{service}_readiness",
            "fail",
            f"{service.capitalize()} is required but is not currently present.",
            evidence={"present": False},
            safe_next_action=(
                "Run the prestart phase before starting the preserved stack, then rerun the ready phase."
            ),
        )
    state = str(item.get("State") or item.get("state") or "unknown").lower()
    health = str(item.get("Health") or item.get("health") or "").lower()
    ready = state == "running" and health == "healthy"
    return _check(
        f"{service}_readiness",
        "pass" if ready else "fail",
        f"{service.capitalize()} is running and healthy."
        if ready
        else f"{service.capitalize()} is present but is not both running and healthy.",
        evidence={"present": True, "state": state[:32], "health": health[:32]},
        safe_next_action="No action required."
        if ready
        else (
            f"Inspect {service} logs and preserved storage; repair the cause without recreating "
            "the service or its volume."
        ),
    )


def _migration_check(
    runner: CommandRunner,
    root: Path,
    env: Mapping[str, str],
    timeout: int,
    postgres: Check,
) -> Check:
    if postgres.status != "pass":
        return _check(
            "database_migration_head",
            "not_applicable",
            "Migration head was not queried because PostgreSQL is not confirmed healthy.",
            evidence={"queried": False},
            safe_next_action="Confirm PostgreSQL readiness first; do not modify schema during preflight.",
        )
    result = _run(
        runner,
        (
            "uv",
            "run",
            "--frozen",
            "--no-sync",
            "alembic",
            "-c",
            "packages/database/alembic.ini",
            "current",
            "--check-heads",
        ),
        root=root,
        env=env,
        timeout=timeout,
    )
    if result.returncode != 0:
        return _check(
            "database_migration_head",
            "fail",
            "Database migration head is unavailable or does not match the application head.",
            evidence={"queried": True, "error_code": result.error_code or "command_failed"},
            safe_next_action=(
                "Review migration state and resume the approved migration step; never reset or drop the database."
            ),
        )
    head = MIGRATION_HEAD.search(result.stdout)
    if head is None:
        return _check(
            "database_migration_head",
            "fail",
            "Database migration command succeeded but did not identify a current head.",
            evidence={"queried": True, "error_code": "malformed_response"},
            safe_next_action="Inspect migration metadata without changing schema, then rerun this preflight.",
        )
    return _check(
        "database_migration_head",
        "pass",
        "Database is at the current application migration head.",
        evidence={
            "queried": True,
            "at_all_heads": True,
            "current_revision": head.group(1),
            "inspection_only": True,
        },
    )


def run_preflight(
    project_root: Path,
    *,
    runner: CommandRunner | None = None,
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    phase: str = "ready",
    disk_usage: Callable[[Path], DiskUsage] = shutil.disk_usage,
    now: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Collect normalized recovery evidence without mutating project state."""

    if phase not in PREFLIGHT_PHASES:
        raise ValueError(f"phase must be one of: {', '.join(sorted(PREFLIGHT_PHASES))}")
    if minimum_free_bytes <= 0:
        raise ValueError("minimum_free_bytes must be positive")
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
    root = project_root.resolve()
    command_runner = runner or SubprocessRunner()
    base_environment = _command_env(root)
    compose_environment = _command_env(root, COMPOSE_ENV_KEYS)
    migration_environment = _command_env(root, MIGRATION_ENV_KEYS)
    checks = [
        _check(
            "preflight_phase",
            "pass",
            "Pre-start preservation boundary selected."
            if phase == "prestart"
            else "Running-stack readiness boundary selected.",
            evidence={"phase": phase, "inspection_only": True},
            safe_next_action="Continue with read-only inspection.",
        ),
        _disk_check(root, minimum_free_bytes, disk_usage),
    ]

    docker_check, docker_metadata = _docker_check(command_runner, root, base_environment, timeout_seconds)
    checks.append(docker_check)
    if docker_metadata is not None:
        compose_check, config = _compose_check(command_runner, root, compose_environment, timeout_seconds)
        checks.append(compose_check)
        if config is not None:
            service_check, services = _service_inventory(command_runner, root, compose_environment, timeout_seconds)
            checks.append(service_check)
            if services is not None:
                checks.append(
                    _project_volume_inventory(
                        command_runner,
                        root,
                        base_environment,
                        timeout_seconds,
                        config,
                        services,
                    )
                )
                if phase == "ready":
                    postgres = _normalized_service_check("postgres", services.get("postgres"))
                    redis = _normalized_service_check("redis", services.get("redis"))
                    checks.extend((postgres, redis))
                    checks.append(
                        _migration_check(command_runner, root, migration_environment, timeout_seconds, postgres)
                    )

    blocked = any(item.status == "fail" for item in checks)
    timestamp = (now or (lambda: datetime.now(UTC)))().astimezone(UTC).isoformat().replace("+00:00", "Z")
    return {
        "schema": SCHEMA,
        "phase": phase,
        "generated_at": timestamp,
        "result": "blocked" if blocked else "ready",
        "preservation_policy": {
            "state": "preservation_required",
            "mutation_performed": False,
            "automatic_cleanup_allowed": False,
        },
        "checks": [asdict(item) for item in checks],
        "safe_next_action": next(
            (item.safe_next_action for item in checks if item.status == "fail"),
            "Start or resume the preserved Compose stack, then run the ready phase."
            if phase == "prestart"
            else "Continue with the reviewed deployment or resume workflow.",
        ),
    }


def render_human(report: Mapping[str, object]) -> str:
    """Render concise operator output from normalized evidence only."""

    lines = [
        f"Deployment preflight ({str(report.get('phase', 'ready'))}): {str(report.get('result', 'blocked')).upper()}"
    ]
    checks = report.get("checks")
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            lines.append(f"[{str(item.get('status', 'fail')).upper()}] {item.get('check')}: {item.get('summary')}")
    lines.append(f"Safe next action: {report.get('safe_next_action', 'Stop and inspect the preflight result.')}")
    lines.append("Preservation: no resources, volumes, images, caches, or databases were changed.")
    return "\n".join(lines)


def _bounded_positive_int(raw: str, *, maximum: int, option: str) -> int:
    value = int(raw)
    if value <= 0 or value > maximum:
        raise argparse.ArgumentTypeError(f"{option} must be a positive integer no greater than {maximum}")
    return value


def _minimum_free_gib(raw: str) -> int:
    return _bounded_positive_int(raw, maximum=MAX_MINIMUM_FREE_GIB, option="minimum free GiB")


def _timeout_seconds(raw: str) -> int:
    return _bounded_positive_int(raw, maximum=MAX_TIMEOUT_SECONDS, option="timeout seconds")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the non-destructive local deployment preflight.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--json", action="store_true", help="emit the machine-readable evidence document")
    parser.add_argument(
        "--phase",
        choices=sorted(PREFLIGHT_PHASES),
        default="ready",
        help=(
            "prestart inspects preserved state before Compose startup; "
            "ready requires healthy services and migration head"
        ),
    )
    parser.add_argument("--minimum-free-gib", type=_minimum_free_gib, default=8)
    parser.add_argument("--timeout-seconds", type=_timeout_seconds, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)

    report = run_preflight(
        args.root,
        phase=args.phase,
        minimum_free_bytes=args.minimum_free_gib * 1024**3,
        timeout_seconds=args.timeout_seconds,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(render_human(report))
    return 0 if report["result"] == "ready" else 1


if __name__ == "__main__":
    sys.exit(main())
