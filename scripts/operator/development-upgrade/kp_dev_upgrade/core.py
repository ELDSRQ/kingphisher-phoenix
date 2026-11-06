"""Private artifacts, fixed target identity and bounded subprocesses."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from alembic.config import Config
from alembic.script import ScriptDirectory
from dotenv import dotenv_values
from sqlalchemy.engine import make_url

NORMAL = Path("/home/builder/phishing-awareness-platform")
RELEASES = Path("/home/builder/kp-runtime-releases")
RUNS = Path("/home/builder/qualification")
SERVICE = "kp-supervisor.service"
UNIT = Path("/home/builder/.config/systemd/user/kp-supervisor.service")
HOST = "Docker"
ENGINE = "1e63b43c-027f-4c1b-954a-0c29ea867b33"
OLD_REVISION = "cf659d57c5a2d8a9bf0a950ddb148bfb492b0fa1"
OLD_SCHEMA = "0045_template_assets"
LABEL = "kp.development.upgrade"
CONTAINERS = {
    "postgres": "d971f78be5c553d8d7d3432321b9b6186375ceec49cdbefa7a3844a0f60f4f8c",
    "redis": "30467788f104f8c1bb988463b5b124bfc924efb3a9b30fa62297ada2c5843ddc",
    "mailpit": "0ff4daa33b8452b5e8bf536db2b6f00cceef497bf830e650668afda33b00a81f",
    "mock-ai": "4618872bfcbe245e1162350d4f2862877f9de3d38c9fea7b3ef8ec610f880959",
    "mock-idp": "2acaabaa04ab2f26a517d872759b48d88f2896610e839138ca8e5b9f3131d64d",
    "mock-graph": "c10b33b6a2d64ca67404cc4258ccafdb835a975dbca90d7631aa0da841298fd5",
    "otel-collector": "3bae87cdc752045281a95ec897bd75852b20ea6324c09fe8936f826fd97e011d",
}


class Blocked(RuntimeError):
    """Authored redacted error code; never include external diagnostics."""


def canonical(path: Path) -> Path:
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise Blocked("noncanonical_path")
    return path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def private_bytes(path: Path, content: bytes) -> None:
    canonical(path.parent)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def private_json(path: Path, value: Any) -> None:
    private_bytes(path, (json.dumps(value, sort_keys=True, indent=2, default=str) + "\n").encode())


def read_json(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    canonical(path)
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise Blocked("invalid_manifest")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise Blocked("invalid_manifest_shape")
    return value


def phase_receipt(path: Path) -> dict[str, Any]:
    value = read_json(path)
    if not isinstance(value, dict) or value.get("passed") is not True:
        raise Blocked("required_phase_has_not_passed")
    return value


def environment(config: dict[str, str] | None = None) -> dict[str, str]:
    return {
        "PATH": "/home/builder/.local/bin:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        **(config or {}),
        "KP_DISABLE_DOTENV": "1",
        "PYTHONUNBUFFERED": "1",
    }


def require_clean_connection_environment() -> None:
    if any(key.upper().startswith("PG") for key in os.environ):
        raise Blocked("ambient_libpq_overrides_are_unsupported")


def configuration(path: Path) -> dict[str, str]:
    require_clean_connection_environment()
    canonical(path)
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise Blocked("configuration_must_be_private_regular_file")
    parsed = dotenv_values(path, interpolate=False)
    result: dict[str, str] = {}
    for key, raw in parsed.items():
        if raw is None:
            continue
        name = key.upper()
        if name in result and ("DATABASE_URL" in name or "REDIS_URL" in name or name.startswith(("PG", "DOCKER_"))):
            raise Blocked("ambiguous_case_duplicate_connection_configuration")
        result[name] = raw
    if any(key.startswith("PG") for key in result):
        raise Blocked("copied_libpq_overrides_are_unsupported")
    required = {
        "DATABASE_URL",
        "OPERATOR_API_DATABASE_URL",
        "KP_WORKER_DATABASE_URL",
        "TRACKING_API_DATABASE_URL",
        "AUDIT_DATABASE_URL",
        "OPERATOR_API_AUDIT_DATABASE_URL",
        "KP_WORKER_AUDIT_DATABASE_URL",
    }
    if not required <= result.keys():
        raise Blocked("required_database_configuration_missing")
    for key in (key for key in result if "DATABASE_URL" in key):
        url = make_url(result[key])
        if url.get_backend_name() != "postgresql" or url.host not in {"127.0.0.1", "localhost", "::1"}:
            raise Blocked("database_target_is_not_normal_loopback")
        if (
            url.port not in {None, 5432}
            or url.database != "kingphisher"
            or not url.password
            or url.query
            or any(character in url.password for character in "\r\n\0")
        ):
            raise Blocked("database_target_is_not_normal_project")
    if make_url(result["DATABASE_URL"]).username != "kingphisher":
        raise Blocked("migration_owner_identity_mismatch")
    if not {"REDIS_URL", "OPERATOR_API_REDIS_URL", "KP_WORKER_REDIS_URL"} <= result.keys():
        raise Blocked("required_redis_configuration_missing")
    for key in (key for key in result if "REDIS_URL" in key):
        value = urlsplit(result.get(key, ""))
        if (
            value.scheme != "redis"
            or value.hostname not in {"127.0.0.1", "localhost", "::1"}
            or value.port not in {None, 6379}
            or value.path not in {"", "/0"}
            or value.query
            or value.fragment
        ):
            raise Blocked("redis_target_is_not_normal_project")
    if result.get("DOCKER_HOST", "unix:///var/run/docker.sock") != "unix:///var/run/docker.sock" or any(
        result.get(key) for key in ("DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
    ):
        raise Blocked("configuration_docker_target_conflicts_with_reviewed_socket")
    for key in ("AZURE_GRAPH_CERT_PATH", "KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR", "KP_AI_GATEWAY_PROVIDER_STATE_FILE"):
        if configured_path := result.get(key):
            target = Path(configured_path)
            target = canonical(target if target.is_absolute() else NORMAL / target)
            if not target.is_relative_to(NORMAL / "data"):
                raise Blocked("external_private_file_or_witness_layout_is_unsupported")
    if (
        any(key.startswith(("UV_", "PYTHON", "LD_")) for key in result)
        or {"PATH", "VIRTUAL_ENV", "HOME", "BASH_ENV", "ENV"} & result.keys()
    ):
        raise Blocked("configuration_overrides_code_resolution")
    return result


class Commands:
    """Capture output privately; only stable authored errors reach stdout."""

    def __init__(self, log: Path | None = None):
        self.log = log

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        input: bytes | None = None,
        timeout: int = 60,
        cwd: Path | None = None,
        output: Path | None = None,
    ) -> bytes:
        stream = None
        if output is not None:
            stream = os.fdopen(os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb")
        try:
            result = subprocess.run(  # noqa: S603 - fixed executables and validated target arguments
                args,
                input=input,
                stdout=stream or subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment() if env is None else env,
                cwd=cwd,
                timeout=timeout,
                check=False,
            )
            if self.log is not None and result.stderr:
                canonical(self.log)
                if self.log.exists() and (not self.log.is_file() or self.log.stat().st_mode & 0o077):
                    raise Blocked("command_log_is_not_private_regular_file")
                fd = os.open(self.log, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "ab") as log:
                    log.write(result.stderr)
            if result.returncode:
                raise Blocked(f"command_failed_{Path(args[0]).name}")
            return result.stdout or b""
        except subprocess.TimeoutExpired:
            raise Blocked(f"command_deadline_{Path(args[0]).name}") from None
        finally:
            if stream is not None:
                stream.close()

    def docker(self, *args: str, **kwargs: Any) -> bytes:
        return self.run(["docker", "--host", "unix:///var/run/docker.sock", *args], **kwargs)

    def unit(self) -> dict[str, str]:
        value = self.run(
            [
                "systemctl",
                "--user",
                "show",
                SERVICE,
                "--property=WorkingDirectory",
                "--property=ActiveState",
                "--property=MainPID",
                "--property=DropInPaths",
                "--property=FragmentPath",
                "--property=ControlGroup",
            ]
        )
        return dict(line.split("=", 1) for line in value.decode().splitlines() if "=" in line)

    def normal_identity(self) -> dict[str, Any]:
        if (
            platform.system() != "Linux"
            or "microsoft" not in platform.release().lower()
            or socket.gethostname() != HOST
        ):
            raise Blocked("not_reviewed_wsl_worker")
        if (
            os.environ.get("DOCKER_CONTEXT")
            or os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock") != "unix:///var/run/docker.sock"
        ):
            raise Blocked("docker_context_or_endpoint_mismatch")
        info = json.loads(
            self.docker(
                "info",
                "--format",
                '{"ID":{{json .ID}},"OSType":{{json .OSType}},"Architecture":{{json .Architecture}}}',
            )
        )
        if (
            info.get("ID") != ENGINE
            or info.get("OSType") != "linux"
            or info.get("Architecture") not in {"amd64", "x86_64"}
        ):
            raise Blocked("native_engine_identity_mismatch")
        if self.run(["git", "-C", str(NORMAL), "rev-parse", "HEAD"]).decode().strip() != OLD_REVISION:
            raise Blocked("normal_source_revision_changed")
        if self.run(["git", "-C", str(NORMAL), "status", "--porcelain", "--untracked-files=no"]).strip():
            raise Blocked("normal_tracked_source_has_user_changes")
        canonical(NORMAL)
        canonical(UNIT)
        if not canonical(NORMAL / "data").is_dir() or not canonical(NORMAL / ".venv").is_dir():
            raise Blocked("normal_data_or_environment_binding_changed")
        records = {}
        template = (
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
            '"running":{{json .State.Running}},"mounts":{{json .Mounts}}}'
        )
        for kind, identifier in CONTAINERS.items():
            record = json.loads(self.docker("inspect", identifier, "--format", template))
            if (
                record.get("id") != identifier
                or record.get("name") != f"/phishing-awareness-platform-{kind}-1"
                or record.get("running") is not True
            ):
                raise Blocked("normal_container_identity_or_state_changed")
            records[kind] = record
        return {
            "engine": ENGINE,
            "hostname": HOST,
            "containers": records,
            "normal_source": OLD_REVISION,
            "unit_sha256": digest(UNIT),
            "config_sha256": digest(NORMAL / ".env"),
        }


def source_head(source: Path) -> str:
    script = ScriptDirectory.from_config(Config(str(source / "packages/database/alembic.ini")))
    head = script.get_current_head()
    if head is None or not list(script.iterate_revisions(head, OLD_SCHEMA)):
        raise Blocked("release_has_no_reviewed_upgrade_path")
    return head


def release_manifest(source: Path, manifest: Path, expected_hash: str, commit: str) -> dict[str, str]:
    canonical(source)
    if not re.fullmatch("[0-9a-f]{40}", commit) or not re.fullmatch("[0-9a-f]{64}", expected_hash):
        raise Blocked("invalid_qualified_source_identity")
    if digest(manifest) != expected_hash:
        raise Blocked("release_manifest_hash_mismatch")
    value = read_json(manifest)
    if (
        not isinstance(value, dict)
        or value.get("commit") != commit
        or value.get("gates") != {"ci": True, "images": True, "fullstack": True}
    ):
        raise Blocked("final_source_gates_are_not_verified")
    files = value.get("files")
    if not isinstance(files, dict) or not {"pyproject.toml", "uv.lock", "scripts/supervisor.py"} <= files.keys():
        raise Blocked("incomplete_release_manifest")
    for name, expected in files.items():
        if not isinstance(name, str) or not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
            raise Blocked("invalid_release_member")
        path = Path(name)
        if (
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or path.parts[0] in {".git", ".venv", "data"}
            or path.name == ".env"
        ):
            raise Blocked("unsafe_release_member")
        member = source / path
        if not member.is_file() or member.is_symlink() or member.resolve() != member or digest(member) != expected:
            raise Blocked("release_member_identity_mismatch")
    if value.get("schema_head") != source_head(source):
        raise Blocked("qualified_schema_head_mismatch")
    return dict(files)
