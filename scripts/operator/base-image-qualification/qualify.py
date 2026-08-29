#!/usr/bin/env python3
"""Fail-closed qualification for stateful Compose base images.

The preflight reads the normalized Compose model without interpolation, checks
that every named-volume service uses an immutable digest, proves that the
digest's OCI index contains the selected platform, and starts disposable,
hardened probes. It never creates, removes, or attaches a Compose resource.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose.yml"
_DIGEST_REFERENCE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@(?P<digest>sha256:[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLATFORM = re.compile(r"linux/(?P<architecture>amd64|arm64)(?:/(?P<variant>v[0-9]+))?\Z")
_VERSION_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .()=_:+/-]{0,159}\Z")
_TIMEOUT_MIN = 5
_TIMEOUT_MAX = 600
# This is a container mount specification, never a host temporary path.
_CONTAINER_TMPFS = "/tmp:rw,noexec,nosuid,nodev"  # noqa: S108  # nosec B108


class QualificationError(RuntimeError):
    """A stable, non-secret qualification failure."""


@dataclass(frozen=True)
class ProbeSpec:
    account_name: str
    binary: str
    version_arguments: tuple[str, ...]
    version_pattern: re.Pattern[str]
    entrypoint_file: str = "/usr/local/bin/docker-entrypoint.sh"
    runtime_user: str | None = None
    writable_directory: str | None = None


@dataclass(frozen=True)
class QualifiedImage:
    service: str
    reference: str
    index_digest: str
    platform: str
    platform_digest: str
    version: str


PROBE_SPECS: dict[str, ProbeSpec] = {
    "postgres": ProbeSpec(
        account_name="postgres",
        binary="postgres",
        version_arguments=("--version",),
        version_pattern=re.compile(r"postgres \(PostgreSQL\) [0-9][A-Za-z0-9._+-]*\Z"),
    ),
    "redis": ProbeSpec(
        account_name="redis",
        binary="redis-server",
        version_arguments=("--version",),
        version_pattern=re.compile(r"Redis server v=[0-9][A-Za-z0-9._+-]*(?: .*)?\Z"),
        runtime_user="999:999",
        writable_directory="/data",
    ),
}

Runner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


def _run(command: Sequence[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - argv is internal, validated, and never passed through a shell
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        raise QualificationError("Docker CLI is not installed or is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise QualificationError("Docker did not answer within the qualification timeout") from None


def _command_result(
    runner: Runner,
    command: Sequence[str],
    *,
    timeout_seconds: int,
    operation: str,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(command, timeout_seconds)
    except QualificationError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise QualificationError(f"{operation} could not be completed") from None
    if result.returncode != 0:
        raise QualificationError(f"{operation} failed with exit status {result.returncode}")
    return result


def _normalize_platform(value: str) -> str:
    normalized = value.strip().lower()
    aliases = {
        "linux/aarch64": "linux/arm64",
        "linux/x86_64": "linux/amd64",
    }
    normalized = aliases.get(normalized, normalized)
    if _PLATFORM.fullmatch(normalized) is None:
        raise QualificationError("target platform must be linux/amd64 or linux/arm64, optionally with a vN variant")
    return normalized


def _selected_platform(
    requested: str | None,
    *,
    timeout_seconds: int,
    runner: Runner,
) -> str:
    configured = requested or os.environ.get("KP_BASE_IMAGE_PLATFORM") or os.environ.get("DOCKER_DEFAULT_PLATFORM")
    if configured:
        return _normalize_platform(configured)
    result = _command_result(
        runner,
        ("docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"),
        timeout_seconds=timeout_seconds,
        operation="Docker platform discovery",
    )
    return _normalize_platform(result.stdout)


def _compose_model(
    compose_file: Path,
    *,
    timeout_seconds: int,
    runner: Runner,
) -> dict[str, Any]:
    if not compose_file.is_file():
        raise QualificationError("Compose file does not exist")
    result = _command_result(
        runner,
        (
            "docker",
            "compose",
            "--file",
            str(compose_file),
            "config",
            "--format",
            "json",
            "--no-interpolate",
        ),
        timeout_seconds=timeout_seconds,
        operation="Compose configuration inspection",
    )
    try:
        model = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise QualificationError("Compose configuration inspection returned malformed JSON") from None
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise QualificationError("Compose configuration has no service map")
    return model


def _uses_named_volume(service: dict[str, Any]) -> bool:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise QualificationError("Compose service volume configuration is malformed")
    for volume in volumes:
        if isinstance(volume, dict) and volume.get("type") == "volume" and volume.get("source"):
            return True
    return False


def _stateful_images(model: dict[str, Any]) -> dict[str, str]:
    services = model["services"]
    images: dict[str, str] = {}
    for name, raw_service in services.items():
        if not isinstance(name, str) or not isinstance(raw_service, dict):
            raise QualificationError("Compose service configuration is malformed")
        if not _uses_named_volume(raw_service):
            continue
        image = raw_service.get("image")
        if not isinstance(image, str) or not image.strip():
            raise QualificationError(f"stateful service {name} must use a published image")
        if name not in PROBE_SPECS:
            raise QualificationError(f"stateful service {name} has no reviewed base-image probe")
        images[name] = image.strip()
    if set(images) != set(PROBE_SPECS):
        missing = ", ".join(sorted(set(PROBE_SPECS) - set(images)))
        raise QualificationError(f"required stateful services are missing from Compose: {missing}")
    return images


def _immutable_digest(reference: str, service: str) -> str:
    matched = _DIGEST_REFERENCE.fullmatch(reference)
    if matched is None:
        raise QualificationError(f"stateful service {service} image must be pinned to a lowercase sha256 digest")
    return matched.group("digest")


def _platform_digest(raw_manifest: str, *, service: str, platform: str) -> str:
    try:
        manifest = json.loads(raw_manifest)
    except (json.JSONDecodeError, TypeError):
        raise QualificationError(f"image index inspection returned malformed JSON for {service}") from None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("manifests"), list):
        raise QualificationError(f"image reference for {service} does not identify a reviewable multi-platform index")
    target = _PLATFORM.fullmatch(platform)
    if target is None:
        raise QualificationError("internal platform validation failed")
    architecture = target.group("architecture")
    variant = target.group("variant")
    matches: list[str] = []
    for descriptor in manifest["manifests"]:
        if not isinstance(descriptor, dict):
            continue
        descriptor_platform = descriptor.get("platform")
        if not isinstance(descriptor_platform, dict):
            continue
        descriptor_variant = descriptor_platform.get("variant")
        if (
            descriptor_platform.get("os") == "linux"
            and descriptor_platform.get("architecture") == architecture
            and (variant is None or descriptor_variant == variant)
        ):
            digest = descriptor.get("digest")
            if isinstance(digest, str) and _DIGEST.fullmatch(digest):
                matches.append(digest)
    if len(matches) != 1:
        raise QualificationError(f"image index for {service} does not contain exactly one {platform} manifest")
    return matches[0]


def _inspect_index(
    service: str,
    reference: str,
    platform: str,
    *,
    timeout_seconds: int,
    runner: Runner,
) -> str:
    result = _command_result(
        runner,
        ("docker", "buildx", "imagetools", "inspect", "--raw", reference),
        timeout_seconds=timeout_seconds,
        operation=f"image index inspection for {service}",
    )
    return _platform_digest(result.stdout, service=service, platform=platform)


def _inspect_local_image(
    service: str,
    reference: str,
    index_digest: str,
    platform: str,
    *,
    timeout_seconds: int,
    runner: Runner,
) -> str | None:
    """Return a content digest for an exact, already cached image.

    A valid local hit lets a preserved installation recover without registry
    access or an unnecessary pull. A non-zero inspect means only "not cached";
    malformed or identity-drifted successful output fails closed.
    """

    result = runner(("docker", "image", "inspect", reference, "--format", "{{json .}}"), timeout_seconds)
    if result.returncode != 0:
        return None
    try:
        metadata = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise QualificationError(f"local image inspection returned malformed JSON for {service}") from None
    if not isinstance(metadata, dict):
        raise QualificationError(f"local image inspection returned malformed JSON for {service}")
    target = _PLATFORM.fullmatch(platform)
    repo_digests = metadata.get("RepoDigests")
    content_digest = metadata.get("Id")
    if (
        target is None
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != target.group("architecture")
        or not isinstance(repo_digests, list)
        or not any(isinstance(value, str) and value.endswith(f"@{index_digest}") for value in repo_digests)
        or not isinstance(content_digest, str)
        or _DIGEST.fullmatch(content_digest) is None
    ):
        raise QualificationError(
            f"cached image identity or platform does not match the reviewed reference for {service}"
        )
    return content_digest


def _probe_script(spec: ProbeSpec) -> str:
    commands = [
        "set -eu",
        "test -s /etc/passwd || { printf 'kp-probe:passwd-empty\\n' >&2; exit 20; }",
        "test -s /etc/group || { printf 'kp-probe:group-empty\\n' >&2; exit 21; }",
        f"grep -q '^{spec.account_name}:' /etc/passwd || {{ printf 'kp-probe:account-missing\\n' >&2; exit 22; }}",
        f"test -s {spec.entrypoint_file} || {{ printf 'kp-probe:entrypoint-empty\\n' >&2; exit 23; }}",
        f'version="$({spec.binary} {" ".join(spec.version_arguments)})" || '
        "{ printf 'kp-probe:binary-failed\\n' >&2; exit 24; }",
        "test -n \"${version}\" || { printf 'kp-probe:version-empty\\n' >&2; exit 25; }",
    ]
    if spec.runtime_user is not None:
        commands.append(
            f'test "$(id -u):$(id -g)" = "{spec.runtime_user}" '
            "|| { printf 'kp-probe:runtime-user-mismatch\\n' >&2; exit 26; }"
        )
    if spec.writable_directory is not None:
        marker = f"{spec.writable_directory}/.kp-qualification-write"
        commands.extend(
            (
                f": > {marker} || {{ printf 'kp-probe:data-not-writable\\n' >&2; exit 27; }}",
                f"rm -f {marker}",
            )
        )
    commands.append("printf 'kp-probe:ok:%s\\n' \"${version}\"")
    return "\n".join(commands)


_PROBE_FAILURES = {
    "kp-probe:passwd-empty": "/etc/passwd is missing or empty",
    "kp-probe:group-empty": "/etc/group is missing or empty",
    "kp-probe:account-missing": "required service account is absent",
    "kp-probe:entrypoint-empty": "required entrypoint is missing or empty",
    "kp-probe:binary-failed": "service binary/version probe failed",
    "kp-probe:version-empty": "service binary returned an empty version",
    "kp-probe:runtime-user-mismatch": "configured runtime UID/GID does not match the image account",
    "kp-probe:data-not-writable": "configured runtime UID/GID cannot write the disposable data directory",
}


def _probe_failure(stderr: str) -> str | None:
    for line in stderr.splitlines():
        detail = _PROBE_FAILURES.get(line.strip())
        if detail is not None:
            return detail
    return None


def _probe_image(
    service: str,
    reference: str,
    platform: str,
    *,
    pull_policy: str,
    timeout_seconds: int,
    runner: Runner,
) -> str:
    spec = PROBE_SPECS[service]
    if pull_policy not in {"always", "never"}:
        raise QualificationError("internal image pull policy is invalid")
    command_parts = [
        "docker",
        "run",
        "--rm",
        f"--pull={pull_policy}",
        "--platform",
        platform,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        _CONTAINER_TMPFS,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--entrypoint",
        "/bin/sh",
    ]
    if spec.runtime_user is not None:
        command_parts.extend(("--user", spec.runtime_user))
    if spec.writable_directory is not None:
        command_parts.extend(
            (
                "--tmpfs",
                f"{spec.writable_directory}:rw,noexec,nosuid,nodev,mode=0700,uid=999,gid=999",
            )
        )
    command_parts.extend(
        (
            reference,
            "-ec",
            _probe_script(spec),
        )
    )
    command = tuple(command_parts)
    try:
        result = runner(command, timeout_seconds)
    except QualificationError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise QualificationError(f"ephemeral image probe for {service} could not be completed") from None
    if result.returncode != 0:
        detail = _probe_failure(result.stderr) or "container did not complete the hardened probe"
        raise QualificationError(f"ephemeral image probe for {service} failed: {detail}")
    marker = "kp-probe:ok:"
    versions = [line.removeprefix(marker) for line in result.stdout.splitlines() if line.startswith(marker)]
    if len(versions) != 1:
        raise QualificationError(f"ephemeral image probe for {service} returned no unambiguous version")
    version = versions[0].strip()
    if _VERSION_TEXT.fullmatch(version) is None or spec.version_pattern.fullmatch(version) is None:
        raise QualificationError(f"ephemeral image probe for {service} returned an unexpected version")
    return version


def qualify(
    compose_file: Path,
    *,
    requested_platform: str | None,
    timeout_seconds: int,
    runner: Runner = _run,
) -> tuple[QualifiedImage, ...]:
    if not _TIMEOUT_MIN <= timeout_seconds <= _TIMEOUT_MAX:
        raise QualificationError(f"timeout must be between {_TIMEOUT_MIN} and {_TIMEOUT_MAX} seconds")
    platform = _selected_platform(requested_platform, timeout_seconds=timeout_seconds, runner=runner)
    model = _compose_model(compose_file, timeout_seconds=timeout_seconds, runner=runner)
    images = _stateful_images(model)
    qualified: list[QualifiedImage] = []
    for service in sorted(images):
        reference = images[service]
        index_digest = _immutable_digest(reference, service)
        platform_digest = _inspect_local_image(
            service,
            reference,
            index_digest,
            platform,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )
        pull_policy = "never"
        if platform_digest is None:
            platform_digest = _inspect_index(
                service,
                reference,
                platform,
                timeout_seconds=timeout_seconds,
                runner=runner,
            )
            pull_policy = "always"
        version = _probe_image(
            service,
            reference,
            platform,
            pull_policy=pull_policy,
            timeout_seconds=timeout_seconds,
            runner=runner,
        )
        qualified.append(
            QualifiedImage(
                service=service,
                reference=reference,
                index_digest=index_digest,
                platform=platform,
                platform_digest=platform_digest,
                version=version,
            )
        )
    return tuple(qualified)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE_FILE)
    parser.add_argument("--platform", help="target OCI platform; defaults to Docker/DOCKER_DEFAULT_PLATFORM")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(os.environ.get("KP_BASE_IMAGE_TIMEOUT_SECONDS", "120")),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        results = qualify(
            args.compose_file.resolve(),
            requested_platform=args.platform,
            timeout_seconds=args.timeout_seconds,
        )
    except QualificationError as exc:
        print(f"NOT QUALIFIED: {exc}", file=sys.stderr)
        print(
            "SAFE NEXT ACTION: do not pull, create, or recreate stateful Compose services; "
            "retain existing containers and named volumes, then select a previously qualified digest or inspect "
            "upstream.",
            file=sys.stderr,
        )
        return 1
    for result in results:
        print(
            f"QUALIFIED service={result.service} index_digest={result.index_digest} "
            f"platform={result.platform} platform_digest={result.platform_digest} "
            f"passwd=non-empty group=non-empty account=present entrypoint=non-empty "
            f"version={json.dumps(result.version)}"
        )
    print(
        "SAFE NEXT ACTION: stateful image qualification passed; Compose may use only the exact reviewed references "
        "above."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
