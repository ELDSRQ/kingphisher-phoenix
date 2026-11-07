"""Private bounded primitives shared by the synthetic off-host recovery tool."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

SNAPSHOT_SCHEMA = "kp.offhost-recovery.snapshot.v1"
SOURCE_REQUEST_SCHEMA = "kp.offhost-recovery.source-request.v1"
TARGET_REQUEST_SCHEMA = "kp.offhost-recovery.target-request.v1"
RUNTIME_COMMIT = "3512a4129262425999e6baaaaf0cc6a0b5f866e6"
MAX_FILES = 20_000
MAX_CLEAR_BYTES = 2 * 1024**3
MAX_CIPHER_BYTES = 512 * 1024**2
MAX_MANIFEST_BYTES = 8 * 1024**2
MAX_COMMAND_BYTES = 32 * 1024**2
LOG_BYTES = 512 * 1024
SERVICES = ("postgres", "redis", "mailpit", "mock-idp", "mock-graph", "mock-ai")
APP_CHILDREN = (
    "operator-api",
    "tracking-api",
    "worker-ingestion",
    "worker-generation",
    "worker-delivery",
    "worker-retention",
    "worker-mailbox",
    "worker-reply-mailbox",
    "worker-reminder",
    "worker-alert",
    "worker-directory",
    "worker-curation",
    "worker-audit-anchor",
)


class RecoveryError(RuntimeError):
    """An authored safe error code; raw diagnostics stay in private files."""


def require(value: object, code: str) -> None:
    if not value:
        if re.fullmatch(r"[a-z0-9_.-]{1,120}", code) is None:
            code = "invalid_error_code"
        raise RecoveryError(code)


def canonical(path: Path) -> Path:
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), "noncanonical_path")
    return path


def unused(path: Path) -> Path:
    canonical(path)
    require(not os.path.lexists(path), "namespace_already_exists_preserve_assets")
    return path


def private_directory(path: Path, *, create: bool = False) -> Path:
    canonical(path)
    if create:
        unused(path).mkdir(mode=0o700)
    info = path.stat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
        "directory_not_private_owned",
    )
    return path


def private_file(path: Path, *, owner_uid: int | None = None) -> Path:
    canonical(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o077, "file_not_private_regular")
    require(info.st_uid == (os.geteuid() if owner_uid is None else owner_uid), "file_owner_mismatch")
    return path


def sha256(path: Path) -> str:
    canonical(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def private_bytes(path: Path, data: bytes, *, executable: bool = False) -> None:
    canonical(path)
    private_directory(path.parent)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if executable else 0o600), "wb"
    ) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def private_json(path: Path, value: Any) -> None:
    private_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + chr(10)).encode())


def read_json(path: Path, *, maximum: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    canonical(path)
    require(path.is_file() and path.stat().st_size <= maximum, "json_input_bound_or_kind")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, RecursionError):
        raise RecoveryError("json_input_invalid") from None
    require(isinstance(value, dict), "json_input_not_object")
    return cast(dict[str, Any], value)


def relative_name(name: str) -> str:
    require(
        isinstance(name, str) and 0 < len(name) <= 1024 and "\\" not in name and "\0" not in name,
        "archive_path_invalid",
    )
    require(
        not name.startswith("/") and all(part not in {"", ".", ".."} for part in name.split("/")),
        "archive_path_escapes",
    )
    require(not {".git", ".venv", "node_modules"}.intersection(name.split("/")), "archive_private_code_scope")
    return name


def remaining(deadline: float, *, reserve: float = 0) -> float:
    require(
        type(deadline) in {int, float}
        and type(reserve) in {int, float}
        and math.isfinite(deadline)
        and math.isfinite(reserve)
        and reserve >= 0,
        "operation_deadline_invalid",
    )
    value = deadline - time.time() - reserve
    require(value > 0, "operation_deadline_reached")
    require(value + reserve <= 2700, "operation_work_budget_exceeded")
    return value


def clean_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "AZURE_CONFIG_DIR") if key in os.environ
    }
    environment.update(
        {"LANG": "C.UTF-8", "LC_ALL": "C", "TZ": "UTC", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    )
    environment.update(extra or {})
    return environment


def purpose_fingerprints(config: Mapping[str, str | None]) -> dict[str, str]:
    """Bind protected values; path settings are covered by archived file hashes."""
    result = {}
    for raw_name, value in config.items():
        name = raw_name.upper()
        if value is None or name.endswith(("_PATH", "_FILE", "_DIR", "_URL", "_HOST", "_PORT")):
            continue
        if any(marker in name for marker in ("KEY", "SECRET", "PASSWORD", "TOKEN")) or "KEK" in name.split("_"):
            result[name] = hashlib.sha256(value.encode()).hexdigest()
    require(bool(result), "protected_configuration_missing")
    return dict(sorted(result.items()))


def command(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_data: bytes | None = None,
    output: Path | None = None,
    evidence: Path | None = None,
    record: bool = True,
) -> bytes:
    """Never record argv, env or stdin; sensitive stdout callers use record=False."""
    require(bool(argv) and all(isinstance(arg, str) and "\0" not in arg for arg in argv), "command_argv_invalid")
    require(0 < timeout <= 1800, "command_timeout_invalid")
    started = time.time()
    stream = None
    result = None
    caught: subprocess.TimeoutExpired | OSError | None = None
    if output is not None:
        canonical(output)
        private_directory(output.parent)
        stream = os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
    try:
        result = subprocess.run(  # noqa: S603 - callers assemble reviewed argument arrays; shell is never enabled
            list(argv),
            cwd=cwd,
            env=clean_environment(env),
            input=input_data,
            stdout=stream if stream is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        caught = error
    except OSError as error:
        caught = error
    finally:
        if stream is not None:
            stream.close()
        if evidence is not None and record:
            private_directory(evidence)
            name = f"command-{time.time_ns()}-{uuid.uuid4().hex[:8]}"
            stdout = (result.stdout or b"") if result is not None else getattr(caught, "stdout", b"") or b""
            stderr = (result.stderr or b"") if result is not None else getattr(caught, "stderr", b"") or b""
            metadata: dict[str, Any] = {
                "executable": Path(argv[0]).name,
                "started": started,
                "finished": time.time(),
                "returncode": None if result is None else result.returncode,
                "timed_out": isinstance(caught, subprocess.TimeoutExpired),
                "error_type": type(caught).__name__ if caught else None,
            }
            for label, content in (("stdout", stdout), ("stderr", stderr)):
                raw = content.encode() if isinstance(content, str) else content
                bounded = raw if len(raw) <= LOG_BYTES else raw[: LOG_BYTES // 2] + raw[-LOG_BYTES // 2 :]
                private_bytes(evidence / f"{name}.{label}", bounded)
                metadata[label] = {"bytes": len(raw), "retained": len(bounded), "truncated": len(raw) > LOG_BYTES}
            private_json(evidence / f"{name}.json", metadata)
    require(not isinstance(caught, subprocess.TimeoutExpired), "command_timed_out")
    require(caught is None, "command_could_not_run")
    require(result is not None and result.returncode == 0, "command_failed")
    assert result is not None
    stdout = result.stdout or b""
    require(len(stdout) <= MAX_COMMAND_BYTES, "command_stdout_bound_exceeded")
    return stdout
