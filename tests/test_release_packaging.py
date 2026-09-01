from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTAINER_DIR = REPOSITORY_ROOT / "infrastructure" / "containers"
RELEASE_IMAGES = ("operator-api", "tracking-api", "worker", "migration", "ai-gateway")
HARDENED_BUILDER = (
    "FROM cgr.dev/chainguard/python@sha256:aa8fd2447b8b52922db57deb3894b622c3229387aaaec5934d64b85dbff6eb17 AS builder"
)
HARDENED_RUNTIME = (
    "FROM cgr.dev/chainguard/python@sha256:ee37f5e4fb445732409626797dccb6f2a6337872def2bab48729ee61b335fa77"
)


def _dockerfile(image: str) -> str:
    return (CONTAINER_DIR / f"Dockerfile.{image}").read_text(encoding="utf-8")


def test_release_images_pin_every_external_base_and_run_as_numeric_non_root() -> None:
    for image in RELEASE_IMAGES:
        dockerfile = _dockerfile(image)
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        assert from_lines
        assert all("@sha256:" in line for line in from_lines), image
        assert dockerfile.count("USER 65532:65532") == 1, image
        assert "USER root" not in dockerfile, image
        assert "STOPSIGNAL SIGTERM" in dockerfile, image


def test_release_runtime_uses_minimal_hardened_python_without_build_tools() -> None:
    for image in RELEASE_IMAGES:
        dockerfile = _dockerfile(image)
        assert HARDENED_BUILDER in dockerfile, image
        assert dockerfile.count(HARDENED_RUNTIME) == 1, image
        assert "UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --no-editable" in dockerfile, image

        runtime = dockerfile.split(HARDENED_RUNTIME, maxsplit=1)[1]
        assert "\nRUN " not in runtime, image
        assert "pip " not in runtime, image
        assert "/uv" not in runtime, image
        assert "COPY --from=builder --chown=65532:65532 /app/.venv /app/.venv" in runtime, image


def test_service_images_use_process_liveness_and_jobs_declare_no_fake_healthcheck() -> None:
    for image, port in (("operator-api", "8000"), ("tracking-api", "8001")):
        dockerfile = _dockerfile(image)
        assert "HEALTHCHECK" in dockerfile
        assert f"http://127.0.0.1:{port}/livez" in dockerfile
        assert "/readyz" not in dockerfile

    for image in ("worker", "migration"):
        assert "HEALTHCHECK NONE" in _dockerfile(image)


def test_release_images_declare_expected_entrypoints() -> None:
    assert 'CMD ["kp-operator-api"]' in _dockerfile("operator-api")
    assert 'CMD ["kp-tracking-api"]' in _dockerfile("tracking-api")
    assert 'ENTRYPOINT ["kp-worker"]' in _dockerfile("worker")
    assert 'CMD ["python", "/app/scripts/azure_migrate.py"]' in _dockerfile("migration")
    assert 'CMD ["kp-ai-gateway"]' in _dockerfile("ai-gateway")


def test_migration_package_declares_its_alembic_runtime_imports() -> None:
    manifest = tomllib.loads((REPOSITORY_ROOT / "packages" / "database" / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = manifest["project"]["dependencies"]
    assert any(dependency.startswith("python-dotenv") for dependency in dependencies)
    assert "kp-telemetry" in dependencies


def test_image_verifier_uses_clean_context_and_exercises_every_entrypoint() -> None:
    verifier = (REPOSITORY_ROOT / "scripts" / "operator" / "release" / "verify_images.sh").read_text(encoding="utf-8")
    assert "git ls-files --cached --others --exclude-standard" in verifier
    assert '[[ -e "${tracked_path}" || -L "${tracked_path}" ]]' in verifier
    assert '"${context_dir}"' in verifier
    assert "tar --extract --preserve-permissions" in verifier
    assert 'declare -a image_records=("__kp_no_image_record__")' in verifier
    assert 'if value != "__kp_no_image_record__"' in verifier
    assert 'declare -a scan_records=("__kp_no_scan_record__")' in verifier
    assert 'if value != "__kp_no_scan_record__"' in verifier
    assert "docker_bounded build" in verifier
    assert "wait_for_healthy" in verifier
    assert "KP_DOCKER_TIMEOUT_SECONDS:-120" in verifier
    assert "KP_DOCKER_CLEANUP_TIMEOUT_SECONDS:-5" in verifier
    assert "KP_IMAGE_BUILD_MIN_FREE_GIB:-10" in verifier
    assert "KP_IMAGE_BUILD_STORAGE_PATH:-${repo_root}" in verifier
    assert "KP_IMAGE_BUILD_STORAGE_PATH must be an absolute directory" in verifier
    assert "KP_IMAGE_BUILD_STORAGE_PATH must be an existing, non-symbolic directory" in verifier
    assert 'df -Pk "${resolved_build_storage_path}"' in verifier
    context_creation = verifier.index('context_dir="$(mktemp -d')
    assert verifier.index("require_build_headroom") < context_creation
    assert verifier.index("require_timeout_configuration") < context_creation
    assert verifier.index("require_unused_image_targets") < context_creation
    assert "Refusing to move preserved verification image tag" in verifier
    assert "Use a new KP_IMAGE_PREFIX suffix; no image or evidence was changed" in verifier
    assert "^kingphisher/verify(" in verifier
    assert "Add capacity outside preserved project assets; do not prune or delete them" in verifier
    assert "subprocess.run(command, timeout=timeout_seconds" in verifier
    assert verifier.count("COPYFILE_DISABLE=1 tar") == 2
    assert "watchdog_pid" not in verifier
    assert not re.search(r"\bdocker\s+(?:build|run|inspect|image|network|exec|logs|rm)\b", verifier)
    assert "--read-only" in verifier
    assert "--cap-drop ALL" in verifier
    assert "no-new-privileges:true" in verifier
    assert "assert_container_hardening" in verifier
    assert "KP_IMAGE_EXPECTED_PLATFORM" in verifier
    assert '--platform "${expected_platform}"' in verifier
    assert '"${os_name}/${architecture}" != "${expected_platform}"' in verifier
    assert "Refusing emulated release qualification" in verifier
    assert "KP_IMAGE_EXPECTED_DOCKER_ENDPOINT" in verifier
    assert "KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR" in verifier
    assert "DOCKER_CONTEXT must be unset" in verifier

    assert "DOCKER_HOST does not match KP_IMAGE_EXPECTED_DOCKER_ENDPOINT" in verifier
    assert "{{.DockerRootDir}}" in verifier
    assert '"endpoint": {"expected": expected_docker_endpoint, "actual": docker_endpoint}' in verifier
    assert '"root_dir": {"expected": expected_docker_root_dir, "actual": docker_root_dir}' in verifier
    assert verifier.index("require_docker_target_configuration") < verifier.index("initialize_evidence_directory")
    assert "mkdir -p --" not in verifier
    assert "mkdir --" not in verifier
    assert "rm -rf --" not in verifier
    assert "from datetime import UTC" not in verifier
    assert " | None" not in verifier
    assert "datetime.now(timezone.utc)" in verifier
    assert "Optional[dict[str, object]]" in verifier
    assert verifier.count('--label "${qualification_label_key}=${run_id}"') >= 9
    assert "container ls --all --quiet" in verifier
    assert "network ls --quiet" in verifier
    assert "volume ls --quiet | LC_ALL=C sort" in verifier
    assert 'rm --force --volumes "${container_id}"' in verifier
    assert '--tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev"' in verifier
    assert '"volume_inventory_unchanged": volume_inventory_unchanged_value == "true"' in verifier
    assert "Disposable qualification containers remain" in verifier
    assert "Disposable qualification networks remain" in verifier
    assert "|| true" not in verifier
    assert "kp.release-source-manifest.v1" in verifier
    assert "kp.release-image-qualification.v1" in verifier
    assert 'output.open("x"' in verifier
    assert 'qualification.open("x"' in verifier
    assert "source-before.json" in verifier
    assert "source-after.json" in verifier
    assert "context.json" in verifier
    assert 'expected_trivy_version="0.74.0"' in verifier
    assert "KP_TRIVY_EXECUTABLE" in verifier
    assert "KP_TRIVY_EXPECTED_SHA256" in verifier
    assert "KP_TRIVY_CACHE_DIR" in verifier
    assert "KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST" in verifier
    assert "--print-source-manifest-digest" in verifier
    assert "Ambient %s is prohibited" in verifier
    assert "image --download-db-only --skip-check-update=false" in verifier
    assert "version --format json" in verifier
    assert "kp.trivy-cache-manifest.v1" in verifier
    assert "trivy-cache-before.json" in verifier
    assert "trivy-cache-after.json" in verifier
    assert "trivy-secret.yaml" in verifier
    assert '--secret-config "${evidence_dir}/trivy-secret.yaml"' in verifier
    assert "Trivy vulnerability database is stale" in verifier
    assert "release-image scan evidence contains a prohibited finding" in verifier
    assert '"scan_performed_by_verifier": scan_performed' in verifier
    assert "scan_and_record_images" in verifier
    assert "${image}-trivy.json" in verifier
    assert "${image}-trivy.sha256" in verifier
    assert "--scanners vuln,secret" in verifier
    assert "--severity HIGH,CRITICAL" in verifier
    assert "--exit-code 1" in verifier
    assert verifier.index("run_phase image_metadata") < verifier.index("run_phase image_security_scans")
    assert verifier.index("run_phase image_security_scans") < verifier.index("run_phase api_runtime")
    assert "arguments were redacted" in verifier
    assert '"$(image_tag worker)" --help' in verifier
    assert "import alembic, dotenv, kp_database, kp_telemetry, psycopg" in verifier
    assert '"$(image_tag migration)"' in verifier
    # Keep the migration smoke environment aligned with every workload that
    # azure_migrate.py marks mandatory. Missing one must fail here, before a
    # costly four-image build reaches the migration entrypoint.
    for password_name in (
        "KP_DB_PASSWORD_OPERATOR",
        "KP_DB_PASSWORD_TRACKING",
        "KP_DB_PASSWORD_INGESTION",
        "KP_DB_PASSWORD_DELIVERY",
        "KP_DB_PASSWORD_RETENTION",
        "KP_DB_PASSWORD_REMINDER",
        "KP_DB_PASSWORD_ALERT",
        "KP_DB_PASSWORD_AUDIT_ANCHOR",
    ):
        assert password_name in verifier
    for image in RELEASE_IMAGES:
        assert image in verifier
    assert '"$(image_tag mock-services)"' in verifier
    for module in ("mock_idp", "mock_graph", "mock_ai"):
        assert module in verifier
    assert '"http://127.0.0.1:${port}/users/delta"' in verifier


def test_release_context_excludes_preserved_runtime_and_recovery_payloads() -> None:
    required_exclusions = {
        "artifacts/",
        "migration-checkpoint/",
        "Kingphisher Launcher.app/",
        "Kingphisher Launcher.app.backup-*/",
    }
    for ignore_file in (".gitignore", ".dockerignore"):
        entries = {
            line.strip()
            for line in (REPOSITORY_ROOT / ignore_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        assert required_exclusions <= entries, ignore_file


def test_image_verifier_embedded_python_parses_as_python_39() -> None:
    verifier = (REPOSITORY_ROOT / "scripts" / "operator" / "release" / "verify_images.sh").read_text(encoding="utf-8")
    programs = re.findall(r"<<'PY'\n(.*?)\nPY", verifier, flags=re.DOTALL)

    assert programs
    for program in programs:
        ast.parse(program, feature_version=(3, 9))


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _source_manifest_digest(source_root: Path) -> str:
    result = subprocess.run(  # noqa: S603 - fixed repository helper in read-only source mode
        [
            "/bin/bash",
            str(REPOSITORY_ROOT / "scripts" / "operator" / "release" / "verify_images.sh"),
            "--print-source-manifest-digest",
        ],
        cwd=source_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    digest = result.stdout.strip()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    return digest


def _verifier_fake_environment(
    tmp_path: Path,
    *,
    image_collision: bool = False,
    bsd_tool_guards: bool = False,
    full_success: bool = False,
    scan_failure: bool = False,
) -> tuple[dict[str, str], Path, Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_marker = tmp_path / "docker-arguments"
    trivy_marker = tmp_path / "trivy-arguments"
    tool_marker = tmp_path / "filesystem-tool-arguments"
    docker = fake_bin / "docker"
    _write_executable(
        docker,
        """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["KP_FAKE_DOCKER_MARKER"]).open("a", encoding="utf-8") as marker:
    marker.write(" ".join(args) + "\\n")
full_success = os.environ.get("KP_FAKE_FULL_SUCCESS") == "1"


def image_name(value):
    names = ("operator-api", "tracking-api", "worker", "migration", "ai-gateway", "mock-services")
    for index, name in enumerate(names, 1):
        if value.endswith(f"-{name}:local"):
            return name, str(index) * 64
    return "unknown", "f" * 64


if args and args[0] == "info":
    if "--format" in args:
        print("linux/aarch64|/var/lib/docker")
    raise SystemExit(0)
if args[:2] == ["volume", "ls"]:
    print("preserved-project-volume")
    raise SystemExit(0)
if args[:2] in (["container", "ls"], ["network", "ls"]):
    raise SystemExit(0)
if args[:2] == ["image", "inspect"]:
    if "--format" not in args:
        raise SystemExit(0 if os.environ.get("KP_FAKE_IMAGE_COLLISION") == "1" else 1)
    format_value = args[args.index("--format") + 1]
    _name, image_id = image_name(args[2])
    if format_value == "{{.Id}}":
        print(f"sha256:{image_id}")
    elif "RepoDigests" in format_value:
        print(f"sha256:{image_id}|[]|linux|arm64|65532:65532")
    elif "Healthcheck.Test" in format_value:
        print('["CMD","true"]')
    raise SystemExit(0)
if args and args[0] == "build":
    raise SystemExit(0 if full_success else 23)
if args and args[0] == "run":
    if "--detach" in args:
        name = args[args.index("--name") + 1] if "--name" in args else "fake-container"
        print(name)
    raise SystemExit(0)
if args and args[0] == "inspect":
    format_value = args[args.index("--format") + 1]
    if "ReadonlyRootfs" in format_value:
        print("true")
    elif "CapDrop" in format_value:
        print('["ALL"]')
    elif "SecurityOpt" in format_value:
        print('["no-new-privileges:true"]')
    elif "State.Health" in format_value:
        print("healthy")
    elif "State.Running" in format_value:
        print("true")
    raise SystemExit(0)
raise SystemExit(0)
""",
    )
    _write_executable(
        fake_bin / "trivy",
        """#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["KP_FAKE_TRIVY_MARKER"]).open("a", encoding="utf-8") as marker:
    marker.write(" ".join(args) + "\\n")

if "version" in args:
    if os.environ.get("KP_FAKE_MALFORMED_TRIVY_METADATA") == "1":
        print("{")
        raise SystemExit(0)
    now = datetime.now(timezone.utc)
    if os.environ.get("KP_FAKE_STALE_TRIVY_METADATA") == "1":
        updated = now - timedelta(days=4)
        downloaded = now - timedelta(days=4)
        next_update = now - timedelta(days=3)
    else:
        updated = now - timedelta(hours=1)
        downloaded = now - timedelta(minutes=30)
        next_update = now + timedelta(hours=23)
    print(json.dumps({
        "Version": "0.74.0",
        "VulnerabilityDB": {
            "Version": 2,
            "UpdatedAt": updated.isoformat().replace("+00:00", "Z"),
            "NextUpdate": next_update.isoformat().replace("+00:00", "Z"),
            "DownloadedAt": downloaded.isoformat().replace("+00:00", "Z"),
        },
        "CheckBundle": {
            "Digest": "sha256:" + "a" * 64,
            "DownloadedAt": downloaded.isoformat().replace("+00:00", "Z"),
        },
    }))
    raise SystemExit(0)
if "--download-db-only" in args:
    raise SystemExit(0)
if "--output" not in args:
    raise SystemExit(96)
output = Path(args[args.index("--output") + 1])
image_id = args[-1]
reported_image_id = "sha256:" + "9" * 64 if os.environ.get("KP_FAKE_WRONG_SCAN_IMAGE") == "1" else image_id
results = []
if os.environ.get("KP_FAKE_SCAN_FINDING") == "1":
    results = [{"Target": "fixture", "Vulnerabilities": [{"Severity": "CRITICAL"}]}]
output.write_text(
    json.dumps(
        {
            "ArtifactName": reported_image_id,
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": reported_image_id},
            "Results": results,
        }
    ),
    encoding="utf-8",
)
if os.environ.get("KP_FAKE_CACHE_MUTATION") == "1":
    cache = Path(args[args.index("--cache-dir") + 1])
    with (cache / "db" / "trivy.db").open("a", encoding="utf-8") as database:
        database.write("changed\\n")
if os.environ.get("KP_FAKE_SCAN_FAILURE") == "1" and args[-1] == f"sha256:{'3' * 64}":
    raise SystemExit(1)
raise SystemExit(0)
""",
    )
    if bsd_tool_guards:
        for tool in ("mkdir", "rm"):
            _write_executable(
                fake_bin / tool,
                "#!/bin/sh\n"
                f'tool="{tool}"\n'
                'for argument in "$@"; do\n'
                '  printf \'%s:%s\\n\' "$tool" "$argument" >> "$KP_FAKE_TOOL_MARKER"\n'
                '  if [ "$argument" = -- ]; then exit 91; fi\n'
                "done\n"
                f'exec /bin/{tool} "$@"\n',
            )

    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "README.md").write_text("isolated verifier fixture\n", encoding="utf-8")
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "--quiet"], cwd=source_root, check=True)  # noqa: S603

    endpoint = "unix:///private/tmp/fake-kingphisher.sock"
    evidence = tmp_path / "evidence"
    trivy_cache = tmp_path / "trivy-cache"
    (trivy_cache / "db").mkdir(parents=True)
    (trivy_cache / "policy").mkdir()
    (trivy_cache / "db" / "metadata.json").write_text("{}\n", encoding="utf-8")
    (trivy_cache / "db" / "trivy.db").write_text("reviewed fixture database\n", encoding="utf-8")
    (trivy_cache / "policy" / "metadata.json").write_text("{}\n", encoding="utf-8")
    trivy_executable = fake_bin / "trivy"
    trivy_sha256 = hashlib.sha256(trivy_executable.read_bytes()).hexdigest()
    environment = os.environ.copy()
    for variable_name in tuple(environment):
        if variable_name.startswith("TRIVY_"):
            environment.pop(variable_name)
    environment.update(
        {
            "DOCKER_HOST": endpoint,
            "KP_DOCKER_CLEANUP_TIMEOUT_SECONDS": "10",
            "KP_DOCKER_TIMEOUT_SECONDS": "10",
            "KP_FAKE_DOCKER_MARKER": str(docker_marker),
            "KP_FAKE_IMAGE_COLLISION": "1" if image_collision else "0",
            "KP_FAKE_FULL_SUCCESS": "1" if full_success else "0",
            "KP_FAKE_SCAN_FAILURE": "1" if scan_failure else "0",
            "KP_FAKE_TRIVY_MARKER": str(trivy_marker),
            "KP_FAKE_TOOL_MARKER": str(tool_marker),
            "KP_IMAGE_BUILD_MIN_FREE_GIB": "1",
            "KP_IMAGE_BUILD_STORAGE_PATH": str(tmp_path),
            "KP_IMAGE_EXPECTED_DOCKER_ENDPOINT": endpoint,
            "KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR": "/var/lib/docker",
            "KP_IMAGE_EXPECTED_PLATFORM": "linux/arm64",
            "KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST": _source_manifest_digest(source_root),
            "KP_IMAGE_PREFIX": "kingphisher/verify-portability-test",
            "KP_IMAGE_QUALIFICATION_EVIDENCE_DIR": str(evidence),
            "KP_TRIVY_CACHE_DIR": str(trivy_cache),
            "KP_TRIVY_EXECUTABLE": str(trivy_executable),
            "KP_TRIVY_EXPECTED_SHA256": trivy_sha256,
            "KP_TRIVY_TIMEOUT_SECONDS": "10",
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "TMPDIR": str(tmp_path),
        }
    )
    environment.pop("DOCKER_CONTEXT", None)
    return environment, docker_marker, tool_marker, source_root


def _run_fake_verifier(source_root: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bash = Path("/bin/bash")
    assert bash.is_file()
    return subprocess.run(  # noqa: S603 - fixed verifier and isolated fake toolchain
        [str(bash), str(REPOSITORY_ROOT / "scripts" / "operator" / "release" / "verify_images.sh")],
        cwd=source_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize("unsafe_configuration", ("endpoint-mismatch", "context-override", "embedded-credential"))
def test_image_verifier_rejects_unreviewed_docker_target_before_any_docker_access(
    tmp_path: Path, unsafe_configuration: str
) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    evidence = Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"])
    if unsafe_configuration == "endpoint-mismatch":
        environment["DOCKER_HOST"] = "unix:///private/tmp/shared-desktop.sock"
    elif unsafe_configuration == "context-override":
        environment["DOCKER_CONTEXT"] = "desktop-linux"
    else:
        endpoint = "ssh://operator:do-not-disclose@worker.example/var/run/docker.sock"
        environment["DOCKER_HOST"] = endpoint
        environment["KP_IMAGE_EXPECTED_DOCKER_ENDPOINT"] = endpoint

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert not docker_marker.exists(), "Docker must not be contacted until its exact target is validated"
    assert not evidence.exists(), "target validation must precede retained evidence creation"
    assert "do-not-disclose" not in result.stdout
    assert "do-not-disclose" not in result.stderr


def test_image_verifier_preserves_an_existing_evidence_target_before_docker_access(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    evidence = Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"])
    evidence.mkdir()
    sentinel = evidence / "preserve.txt"
    sentinel.write_text("untouched\n", encoding="utf-8")

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert "Refusing to overwrite qualification evidence path" in result.stderr
    assert not docker_marker.exists()
    assert sentinel.read_text(encoding="utf-8") == "untouched\n"


def test_image_verifier_rejects_wrong_docker_root_before_image_or_container_operations(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    environment["KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR"] = "/var/lib/shared-desktop"

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    invocations = docker_marker.read_text(encoding="utf-8").splitlines()
    assert invocations
    assert all(not invocation.startswith(("image ", "build ", "run ")) for invocation in invocations)
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["docker"]["root_dir"] == {
        "actual": "/var/lib/docker",
        "expected": "/var/lib/shared-desktop",
    }


def test_image_verifier_records_exact_docker_identity_without_building_on_tag_collision(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path, image_collision=True)

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    invocations = docker_marker.read_text(encoding="utf-8").splitlines()
    assert not any(invocation.startswith(("build ", "run ")) for invocation in invocations)
    cleanup_queries = [
        invocation for invocation in invocations if invocation.startswith(("container ls ", "network ls "))
    ]
    assert cleanup_queries
    assert all("--filter label=com.kingphisher.release-qualification=" in invocation for invocation in cleanup_queries)
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["status"] == "failed"
    assert qualification["docker"] == {
        "endpoint": {
            "actual": environment["DOCKER_HOST"],
            "expected": environment["KP_IMAGE_EXPECTED_DOCKER_ENDPOINT"],
        },
        "root_dir": {"actual": "/var/lib/docker", "expected": "/var/lib/docker"},
    }
    assert qualification["cleanup"]["volume_inventory_unchanged"] is True


def test_image_verifier_uses_bsd_safe_filesystem_commands_and_removes_only_its_context(tmp_path: Path) -> None:
    environment, _, tool_marker, source_root = _verifier_fake_environment(tmp_path, bsd_tool_guards=True)

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    calls = tool_marker.read_text(encoding="utf-8").splitlines()
    assert "mkdir:--" not in calls
    assert "rm:--" not in calls
    assert any(call == "rm:-rf" for call in calls)
    assert not list(tmp_path.glob("kp-image-context.*"))
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["status"] == "failed"
    assert qualification["cleanup"]["temporary_context"] == "passed"
    assert qualification["cleanup"]["preserved_images_and_caches"] is True
    assert qualification["cleanup"]["volume_inventory_unchanged"] is True
    assert qualification["source"]["unchanged"] is True
    source_digests = {qualification["source"][name]["digest"] for name in ("before", "copied_context", "after")}
    assert len(source_digests) == 1


def test_image_verifier_rejects_symbolic_or_out_of_storage_evidence_parent_before_docker(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    real_parent = tmp_path / "real-evidence-parent"
    real_parent.mkdir()
    symbolic_parent = tmp_path / "symbolic-evidence-parent"
    symbolic_parent.symlink_to(real_parent, target_is_directory=True)
    environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"] = str(symbolic_parent / "evidence")

    symbolic_result = _run_fake_verifier(source_root, environment)

    assert symbolic_result.returncode != 0
    assert "existing, non-symbolic directory" in symbolic_result.stderr
    assert not docker_marker.exists()
    assert not (real_parent / "evidence").exists()

    build_storage = tmp_path / "build-storage"
    build_storage.mkdir()
    outside_parent = tmp_path / "outside-storage"
    outside_parent.mkdir()
    environment["KP_IMAGE_BUILD_STORAGE_PATH"] = str(build_storage)
    environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"] = str(outside_parent / "evidence")

    outside_result = _run_fake_verifier(source_root, environment)

    assert outside_result.returncode != 0
    assert "must remain beneath KP_IMAGE_BUILD_STORAGE_PATH" in outside_result.stderr
    assert not docker_marker.exists()
    assert not (outside_parent / "evidence").exists()


def test_image_verifier_binds_six_pinned_trivy_scans_into_qualification(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path, full_success=True)

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode == 0, result.stderr
    evidence = Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"])
    qualification = json.loads((evidence / "qualification.json").read_text(encoding="utf-8"))
    assert qualification["status"] == "passed"
    assert qualification["scanner"]["name"] == "trivy"
    assert qualification["scanner"]["version"] == "0.74.0"
    assert qualification["scanner"]["scan_performed_by_verifier"] is True
    assert qualification["scanner"]["executable"] == {
        "path": environment["KP_TRIVY_EXECUTABLE"],
        "expected_sha256": environment["KP_TRIVY_EXPECTED_SHA256"],
        "actual_sha256": environment["KP_TRIVY_EXPECTED_SHA256"],
    }
    assert qualification["scanner"]["configuration"]["config"]["size"] == 3
    assert qualification["scanner"]["configuration"]["ignore"]["size"] == 0
    assert qualification["scanner"]["metadata"]["vulnerability_database"]["version"] == 2
    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}",
        qualification["scanner"]["metadata"]["check_bundle"]["digest"],
    )
    assert qualification["scanner"]["cache"]["unchanged"] is True
    assert qualification["scanner"]["cache"]["before"]["digest"] == qualification["scanner"]["cache"]["after"]["digest"]
    assert qualification["source"]["expected_digest"] == environment["KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST"]
    assert qualification["source"]["before"]["digest"] == environment["KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST"]
    scans = qualification["scanner"]["artifacts"]
    assert len(scans) == 6
    images = {record["name"]: record for record in qualification["images"]}
    assert set(images) == {*RELEASE_IMAGES, "mock-services"}
    for scan in scans:
        assert (scan["tag"], scan["image_id"]) == (
            images[scan["name"]]["tag"],
            images[scan["name"]]["image_id"],
        )
        artifact = evidence / scan["artifact"]
        checksum = evidence / scan["checksum_artifact"]
        assert scan["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert checksum.read_text(encoding="utf-8") == f"{scan['sha256']}  {artifact.name}\n"
    phase_results = {record["name"]: record["result"] for record in qualification["phases"]}
    assert phase_results["image_metadata"] == "passed"
    assert phase_results["image_security_scans"] == "passed"
    assert phase_results["scanner_cache_binding"] == "passed"
    trivy_invocations = Path(environment["KP_FAKE_TRIVY_MARKER"]).read_text(encoding="utf-8").splitlines()
    assert len(trivy_invocations) == 8
    assert "image --download-db-only --skip-check-update=false" in trivy_invocations[0]
    assert "version --format json" in trivy_invocations[1]
    scan_invocations = [invocation for invocation in trivy_invocations if " --output " in invocation]
    assert len(scan_invocations) == 6
    assert all(
        "image --skip-db-update --skip-check-update --ignorefile" in invocation
        and "--ignore-unfixed=false --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1" in invocation
        for invocation in scan_invocations
    )
    assert {invocation.rsplit(" ", maxsplit=1)[-1] for invocation in scan_invocations} == {
        record["image_id"] for record in qualification["images"]
    }
    docker_invocations = docker_marker.read_text(encoding="utf-8").splitlines()
    assert sum(invocation.endswith("--format {{.Id}}") for invocation in docker_invocations) == 12


def test_image_verifier_scan_failure_cannot_produce_passing_qualification(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(
        tmp_path,
        full_success=True,
        scan_failure=True,
    )

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    evidence = Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"])
    qualification = json.loads((evidence / "qualification.json").read_text(encoding="utf-8"))
    assert qualification["status"] == "failed"
    assert qualification["scanner"]["scan_performed_by_verifier"] is False
    assert {record["name"] for record in qualification["scanner"]["artifacts"]} == {
        "operator-api",
        "tracking-api",
    }
    phases = {record["name"]: record["result"] for record in qualification["phases"]}
    assert phases["image_security_scans"] == "failed"
    assert not any("-user" in invocation for invocation in docker_marker.read_text(encoding="utf-8").splitlines())


def test_source_manifest_helper_is_deterministic_and_content_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "--quiet"], cwd=source, check=True)  # noqa: S603
    tracked = source / "candidate.txt"
    tracked.write_text("first\n", encoding="utf-8")

    first = _source_manifest_digest(source)
    second = _source_manifest_digest(source)
    tracked.write_text("second\n", encoding="utf-8")
    changed = _source_manifest_digest(source)

    assert first == second
    assert changed != first


def test_image_verifier_rejects_source_manifest_drift_before_scanner_or_docker(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    environment["KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST"] = "sha256:" + "f" * 64

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert "does not match KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST" in result.stderr
    assert not docker_marker.exists()
    assert not Path(environment["KP_FAKE_TRIVY_MARKER"]).exists()
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["status"] == "failed"
    assert qualification["source"]["expected_digest"] == "sha256:" + "f" * 64


@pytest.mark.parametrize(
    "unsafe_configuration",
    ("ambient-suppression", "binary-digest", "outside-cache", "symbolic-cache"),
)
def test_image_verifier_rejects_unreviewed_scanner_configuration_before_docker(
    tmp_path: Path,
    unsafe_configuration: str,
) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    trivy_marker = Path(environment["KP_FAKE_TRIVY_MARKER"])
    if unsafe_configuration == "ambient-suppression":
        environment["TRIVY_SKIP_DB_UPDATE"] = "true"
    elif unsafe_configuration == "binary-digest":
        environment["KP_TRIVY_EXPECTED_SHA256"] = "0" * 64
    elif unsafe_configuration == "outside-cache":
        outside = tmp_path.parent / f"{tmp_path.name}-outside-cache"
        outside.mkdir()
        environment["KP_TRIVY_CACHE_DIR"] = str(outside)
    else:
        cache = Path(environment["KP_TRIVY_CACHE_DIR"])
        symbolic = tmp_path / "symbolic-trivy-cache"
        symbolic.symlink_to(cache, target_is_directory=True)
        environment["KP_TRIVY_CACHE_DIR"] = str(symbolic)

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert not docker_marker.exists()
    assert not trivy_marker.exists()
    assert "qualification.json" in result.stdout


def test_image_verifier_rejects_stale_trivy_database_metadata_before_docker(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    environment["KP_FAKE_STALE_TRIVY_METADATA"] = "1"

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert "stale" in result.stderr
    assert not docker_marker.exists()
    invocations = Path(environment["KP_FAKE_TRIVY_MARKER"]).read_text(encoding="utf-8").splitlines()
    assert len(invocations) == 2
    assert "--download-db-only" in invocations[0]
    assert "version --format json" in invocations[1]


def test_image_verifier_retains_failed_evidence_for_malformed_trivy_metadata(tmp_path: Path) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path)
    environment["KP_FAKE_MALFORMED_TRIVY_METADATA"] = "1"

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert not docker_marker.exists()
    evidence = Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"])
    assert (evidence / "trivy-version.json").read_text(encoding="utf-8") == "{\n"
    qualification = json.loads((evidence / "qualification.json").read_text(encoding="utf-8"))
    assert qualification["status"] == "failed"
    assert qualification["scanner"]["metadata"] is None


def test_image_verifier_rejects_trivy_cache_mutation_after_exact_scans(tmp_path: Path) -> None:
    environment, _, _, source_root = _verifier_fake_environment(tmp_path, full_success=True)
    environment["KP_FAKE_CACHE_MUTATION"] = "1"

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    assert "cache changed during image scans" in result.stderr
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["status"] == "failed"
    assert qualification["scanner"]["cache"]["unchanged"] is False
    assert qualification["scanner"]["cache"]["before"]["digest"] != qualification["scanner"]["cache"]["after"]["digest"]


@pytest.mark.parametrize("failure_mode", ("wrong-image", "suppressed-finding"))
def test_image_verifier_validates_scan_json_independently_of_trivy_exit_code(
    tmp_path: Path,
    failure_mode: str,
) -> None:
    environment, docker_marker, _, source_root = _verifier_fake_environment(tmp_path, full_success=True)
    if failure_mode == "wrong-image":
        environment["KP_FAKE_WRONG_SCAN_IMAGE"] = "1"
    else:
        environment["KP_FAKE_SCAN_FINDING"] = "1"

    result = _run_fake_verifier(source_root, environment)

    assert result.returncode != 0
    qualification = json.loads(
        (Path(environment["KP_IMAGE_QUALIFICATION_EVIDENCE_DIR"]) / "qualification.json").read_text(encoding="utf-8")
    )
    assert qualification["status"] == "failed"
    assert qualification["scanner"]["scan_performed_by_verifier"] is False
    assert not any("-user" in invocation for invocation in docker_marker.read_text(encoding="utf-8").splitlines())


def test_workflow_actions_are_commit_pinned_with_readable_versions() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    action_lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("uses:")]
    assert action_lines
    for line in action_lines:
        if "uses: ./" in line:
            continue
        assert re.search(r"@[0-9a-f]{40}(?:\s+#\s+v\S+)?$", line), line
        assert " # v" in line, line

    dependency_scanner = "uv tool install pip-audit==2.10.1"
    dependency_gate = "- run: make security-scan"
    assert dependency_scanner in workflow
    assert dependency_gate in workflow
    assert workflow.index(dependency_scanner) < workflow.index(dependency_gate)


def test_workflow_cannot_bypass_release_image_gates() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    assert "make verify-images" in workflow
    assert "make security-scan-images" in workflow
    qualify_job = workflow.split("  qualify:\n", maxsplit=1)[1].split("\n  guard:\n", maxsplit=1)[0]
    assert "    needs: guard" in qualify_job
    assert "DOCKER_HOST: unix:///var/run/docker.sock" in workflow
    assert 'DOCKER_CONTEXT: ""' in workflow
    assert "KP_IMAGE_EXPECTED_DOCKER_ENDPOINT: unix:///var/run/docker.sock" in workflow
    assert "KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR: /var/lib/docker" in workflow
    assert "KP_IMAGE_EXPECTED_PLATFORM: linux/amd64" in workflow
    assert "KP_IMAGE_PREFIX: kingphisher/verify-ci-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "KP_IMAGE_QUALIFICATION_EVIDENCE_DIR: ${{ runner.temp }}/qualification-evidence/release-images" in workflow
    verify_step = workflow.split("      - name: Build and start every release image\n", maxsplit=1)[1].split(
        "      - name: Recheck the verifier-bound release images\n", maxsplit=1
    )[0]
    rescan_step = workflow.split("      - name: Recheck the verifier-bound release images\n", maxsplit=1)[1].split(
        "      - name: Upload qualification recovery evidence\n", maxsplit=1
    )[0]
    for shared_value in (
        "DOCKER_HOST: unix:///var/run/docker.sock",
        'DOCKER_CONTEXT: ""',
        "KP_IMAGE_EXPECTED_DOCKER_ENDPOINT: unix:///var/run/docker.sock",
        "KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR: /var/lib/docker",
        "KP_IMAGE_EXPECTED_PLATFORM: linux/amd64",
        "KP_IMAGE_PREFIX: kingphisher/verify-ci-${{ github.run_id }}-${{ github.run_attempt }}",
        "KP_IMAGE_BUILD_STORAGE_PATH: ${{ runner.temp }}",
        "KP_IMAGE_QUALIFICATION_EVIDENCE_DIR: ${{ runner.temp }}/qualification-evidence/release-images",
    ):
        assert shared_value in verify_step
        assert shared_value in rescan_step
    for verifier_input in (
        'KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST="$expected_source_digest"',
        'KP_TRIVY_EXECUTABLE="$trivy_executable"',
        'KP_TRIVY_EXPECTED_SHA256="$trivy_sha256"',
        'KP_TRIVY_CACHE_DIR="$trivy_cache"',
        "verify_images.sh --print-source-manifest-digest",
        'TRIVY_*) unset "$name"',
    ):
        assert verifier_input in verify_step
    assert 'trivy_sha256="d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791"' in verify_step
    assert 'trivy_sha256="$(sha256sum ' not in verify_step
    assert "path: ${{ runner.temp }}/qualification-evidence" in workflow
    assert "continue-on-error" not in workflow
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2" in workflow
    assert "anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0" in workflow
    assert workflow.count("push-to-registry: true") == 10
    assert "--bundle-from-oci" in workflow
    assert '--source-digest "$GITHUB_SHA"' in workflow
    terraform_names = {
        "operator-api": ("operator", "OPERATOR_API_DIGEST"),
        "tracking-api": ("tracking", "TRACKING_API_DIGEST"),
        "worker": ("worker", "WORKER_DIGEST"),
        "migration": ("migration", "MIGRATION_DIGEST"),
    }
    for image, (terraform_name, digest_variable) in terraform_names.items():
        output_name = image.replace("-", "_")
        assert workflow.count(f"subject-name: ${{{{ steps.images.outputs.registry }}}}/{image}") == 2
        assert workflow.count(f"subject-digest: ${{{{ steps.images.outputs.{output_name}_digest }}}}") == 2
        assert f"sbom-path: ${{{{ runner.temp }}}}/supply-chain/{image}.spdx.json" in workflow
        exact_digest_binding = re.compile(
            rf"^\s+{digest_variable}: \$\{{\{{ steps\.images\.outputs\.{output_name}_digest \}}\}}$",
            flags=re.MULTILINE,
        )
        assert len(exact_digest_binding.findall(workflow)) == 2
        digest_reference = f"{terraform_name}_image=$IMAGE_REGISTRY/{image}@${digest_variable}"
        assert workflow.count(digest_reference) == 2
    assert workflow.count("IMAGE_REGISTRY: ${{ steps.images.outputs.registry }}") == 3
    assert "postgres:16@sha256:" in workflow
    assert "redis:7-alpine@sha256:" in workflow

    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "build: verify-images" in makefile
    assert "trivy image --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1" in makefile
    image_scan = makefile.split("security-scan-images:\n", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert 'image_prefix="$${KP_IMAGE_PREFIX:-kingphisher/verify}"' in image_scan
    assert "^kingphisher/verify(" in image_scan
    assert '"$${image_prefix}-$$image:local"' in image_scan
    for image in (*RELEASE_IMAGES, "mock-services"):
        assert image in image_scan


def _image_scan_environment(tmp_path: Path, *, prefix: str) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "trivy-arguments"
    trivy = fake_bin / "trivy"
    trivy.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then\n'
        "  printf 'Version: 0.74.0\\n'\n"
        "  exit 0\n"
        "fi\n"
        'printf \'%s\\n\' "$*" >> "$KP_TRIVY_MARKER"\n',
        encoding="utf-8",
    )
    trivy.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "KP_IMAGE_PREFIX": prefix,
            "KP_TRIVY_MARKER": str(marker),
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
        }
    )
    return environment, marker


def test_image_scan_uses_the_same_unique_no_clobber_prefix_as_image_verification(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    prefix = "kingphisher/verify-arm64-20260828"
    environment, marker = _image_scan_environment(tmp_path, prefix=prefix)

    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "--no-print-directory", "security-scan-images"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    invocations = marker.read_text(encoding="utf-8").splitlines()
    assert len(invocations) == 6
    for image in (*RELEASE_IMAGES, "mock-services"):
        assert any(invocation.endswith(f"{prefix}-{image}:local") for invocation in invocations)


def test_image_scan_rejects_an_unreviewed_prefix_before_invoking_trivy(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    environment, marker = _image_scan_environment(tmp_path, prefix="production/overwrite")

    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "--no-print-directory", "security-scan-images"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "dedicated kingphisher/verify" in result.stderr
    assert not marker.exists()


def test_azure_release_builds_only_production_images_for_linux_amd64() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    build_step = workflow.split("      - name: Build immutable images in the registry\n", maxsplit=1)[1].split(
        "      - name: Authenticate supply-chain tools to ACR\n", maxsplit=1
    )[0]

    assert "for image in operator-api tracking-api worker migration ai-gateway; do" in build_step
    assert "              --platform linux/amd64 \\" in build_step
    assert sum(line.strip() == "az acr build \\" for line in build_step.splitlines()) == 1
    assert "mock-services" not in build_step


def test_azure_scans_exact_registry_digests_before_sbom_attestation_and_deploy() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    authentication = workflow.index("      - name: Authenticate supply-chain tools to ACR\n")
    scan_start = workflow.index("      - name: Scan exact immutable registry images\n")
    sbom_start = workflow.index("      - name: Generate deterministic SPDX evidence for every image\n")
    assert authentication < scan_start < sbom_start

    scan_step = workflow[scan_start:sbom_start]
    assert '"${repository}@${digest}"' in scan_step
    assert '--output "$scan_output"' in scan_step
    assert '[[ -e "$scan_output" || -L "$scan_output" ]]' in scan_step
    assert "immutable-image-trivy.sha256" in scan_step
    assert "--exit-code 1" in scan_step
    assert "${image}:${tag}" not in scan_step


def test_azure_release_never_deploys_or_attests_a_mutable_image_reference() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    build_step = workflow.split("      - name: Build immutable images in the registry\n", maxsplit=1)[1].split(
        "      - name: Authenticate supply-chain tools to ACR\n", maxsplit=1
    )[0]
    release_path = workflow.split("      - name: Authenticate supply-chain tools to ACR\n", maxsplit=1)[1].split(
        "      - name: Summarize\n", maxsplit=1
    )[0]

    assert 'tag="sha-${GITHUB_SHA}-run-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"' in build_step
    assert '--image "${image}:${tag}"' in build_step
    assert '--image "${image}@${digest}"' in build_step
    assert '[[ "$immutable_digest" != "$digest" ]]' in build_step
    assert "${{ steps.images.outputs.tag }}" not in release_path
    assert "@${digest}" in release_path
    for image, digest_output in (
        ("operator-api", "operator_api_digest"),
        ("tracking-api", "tracking_api_digest"),
        ("worker", "worker_digest"),
        ("migration", "migration_digest"),
    ):
        assert workflow.count(f"subject-name: ${{{{ steps.images.outputs.registry }}}}/{image}") == 2
        assert workflow.count(f"subject-digest: ${{{{ steps.images.outputs.{digest_output} }}}}") == 2


def test_azure_release_limits_credentials_and_protected_environment_authority() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")
    before_deploy, deploy = workflow.split("  deploy:\n", maxsplit=1)

    assert "permissions:\n  contents: read\n" in before_deploy
    assert "id-token: write" not in before_deploy
    assert "environment: ${{ inputs.environment }}" in deploy
    assert "id-token: write" in deploy
    assert workflow.count("persist-credentials: false") == 2
    assert workflow.count("timeout-minutes:") == 3
    assert "group: azure-${{ inputs.environment }}" in workflow
    assert 'chmod 700 "$docker_config"' in deploy
    assert 'chmod 600 "$docker_config/config.json"' in deploy
    assert "      - name: Remove ephemeral registry credentials\n" in deploy
    assert 'rm -f "$expected_config/config.json"' in deploy


def test_local_dependency_audit_exports_the_frozen_runtime_closure() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("security-scan-dependencies:\n", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    for flag in ("--quiet", "--frozen", "--all-packages", "--no-dev", "--no-emit-workspace", "--output-file"):
        assert flag in recipe
    assert "--format cyclonedx1.5" not in recipe
    assert "pip-audit --requirement" in recipe
    assert "--strict --require-hashes --no-deps --disable-pip" in recipe
    assert "set -eu" in recipe
    assert 'UV_CACHE_DIR="$$scan_dir/uv-cache"' in recipe
    assert '--cache-dir "$$scan_dir/audit-cache"' in recipe
    assert 'rm -rf "$$scan_dir"' in recipe
    assert (
        "security-scan: security-scan-bandit security-scan-semgrep security-scan-trivy security-scan-dependencies"
        in makefile
    )


def test_dependency_audit_cannot_pass_when_the_locked_export_fails(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv = fake_bin / "uv"
    uv.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    uv.chmod(0o755)
    marker = tmp_path / "pip-audit-ran"
    pip_audit = fake_bin / "pip-audit"
    pip_audit.write_text('#!/bin/sh\n: > "$KP_AUDIT_MARKER"\n', encoding="utf-8")
    pip_audit.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "KP_AUDIT_MARKER": str(marker),
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
            "TMPDIR": str(tmp_path),
        }
    )

    make = shutil.which("make")
    assert make is not None
    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "security-scan-dependencies"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert not marker.exists(), "pip-audit must not run against an absent or partial export"


def test_local_sbom_exports_the_complete_frozen_runtime_closure() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("sbom:\n", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    for flag in ("--preview-features sbom-export", "--frozen", "--all-packages", "--no-dev", "--no-emit-workspace"):
        assert flag in recipe
    assert "--format cyclonedx1.5" in recipe
    assert "set -eu" in recipe
    assert 'UV_CACHE_DIR="$$sbom_cache"' in recipe
    assert 'rm -rf "$$sbom_cache"' in recipe
    assert "--output-file" not in recipe
    assert "pip freeze" not in makefile
    assert "syft scan file:uv.lock" not in makefile


def test_development_commands_cannot_update_the_frozen_lock() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "PY := uv run --frozen" in makefile
    assert "UV_PYTHON_DOWNLOADS=never uv sync --frozen --all-packages" in makefile
    assert "uv run uvicorn" not in makefile


def _sign_environment(tmp_path: Path, *, image: str | None, key: str | None) -> tuple[dict[str, str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "cosign-arguments"
    cosign = fake_bin / "cosign"
    cosign.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$KP_COSIGN_MARKER"\n', encoding="utf-8")
    cosign.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "KP_COSIGN_MARKER": str(marker),
            "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
        }
    )
    if image is None:
        environment.pop("IMAGE", None)
    else:
        environment["IMAGE"] = image
    if key is None:
        environment.pop("COSIGN_KEY", None)
    else:
        environment["COSIGN_KEY"] = key
    return environment, marker


@pytest.mark.parametrize(
    ("image", "key"),
    (
        (None, "secret-key.pem"),
        ("registry.example.com/team/operator-api:latest", "secret-key.pem"),
        (f"registry.example.com/team/operator-api@sha256:{'g' * 64}", "secret-key.pem"),
        (f"operator-api@sha256:{'a' * 64}", "secret-key.pem"),
        (f"registry.example.com/team/operator-api@sha256:{'a' * 64}", None),
    ),
)
def test_local_sign_rejects_invalid_input_before_cosign(tmp_path: Path, image: str | None, key: str | None) -> None:
    make = shutil.which("make")
    assert make is not None
    environment, marker = _sign_environment(tmp_path, image=image, key=key)

    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "--no-print-directory", "sign"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert not marker.exists(), "cosign must not run until every input passes validation"
    assert "secret-key.pem" not in result.stdout
    assert "secret-key.pem" not in result.stderr


def test_local_sign_invokes_cosign_with_exact_immutable_reference_without_key_disclosure(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    image = f"registry.example.com/team/operator-api@sha256:{'a' * 64}"
    key = "local-secret-key.pem"
    environment, marker = _sign_environment(tmp_path, image=image, key=key)

    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "--no-print-directory", "sign"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text(encoding="utf-8").splitlines() == ["sign", "--yes", "--key", key, image]
    assert key not in result.stdout
    assert key not in result.stderr


def test_local_sign_requires_cosign_after_inputs_are_validated(tmp_path: Path) -> None:
    make = shutil.which("make")
    assert make is not None
    image = f"registry.example.com/team/operator-api@sha256:{'a' * 64}"
    environment = os.environ.copy()
    environment.update({"IMAGE": image, "COSIGN_KEY": "local-secret-key.pem", "PATH": str(tmp_path)})

    result = subprocess.run(  # noqa: S603 - resolved executable and fixed target
        [make, "--no-print-directory", "sign"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "cosign is required" in result.stderr
    assert "local-secret-key.pem" not in result.stdout
    assert "local-secret-key.pem" not in result.stderr


def test_native_sbom_contains_the_full_external_runtime_inventory(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv is required to validate the frozen runtime SBOM"
    output = tmp_path / "runtime.cdx.json"
    environment = os.environ.copy()
    environment.update(
        {
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
            "UV_PYTHON_DOWNLOADS": "never",
        }
    )
    result = subprocess.run(  # noqa: S603 - resolved uv executable and fixed arguments
        [
            uv,
            "export",
            "--quiet",
            "--preview-features",
            "sbom-export",
            "--frozen",
            "--all-packages",
            "--no-dev",
            "--no-emit-workspace",
            "--format",
            "cyclonedx1.5",
            "--output-file",
            str(output),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding="utf-8"))
    external = [component for component in document["components"] if component.get("purl")]
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert len(external) == 58
    assert all(component["purl"].startswith("pkg:pypi/") for component in external)
