from __future__ import annotations

import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "operator" / "base-image-qualification" / "qualify.py"
SPEC = importlib.util.spec_from_file_location("base_image_qualification", SCRIPT)
assert SPEC and SPEC.loader
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)

POSTGRES_REFERENCE = "postgres:16-alpine@sha256:" + "1" * 64
REDIS_REFERENCE = "redis:7-alpine@sha256:" + "2" * 64
ARM64_DIGEST = "sha256:" + "a" * 64


def _compose_model(*, postgres: str = POSTGRES_REFERENCE, redis: str = REDIS_REFERENCE) -> dict[str, Any]:
    return {
        "services": {
            # Normalized Compose legitimately omits ``volumes`` for stateless
            # services; this must not prevent stateful-image qualification.
            "mailpit": {"image": "mailpit:mutable"},
            "postgres": {
                "image": postgres,
                "volumes": [
                    {"type": "volume", "source": "postgres_data", "target": "/var/lib/postgresql/data"},
                    {"type": "bind", "source": "/fixtures/init", "target": "/docker-entrypoint-initdb.d"},
                ],
            },
            "redis": {
                "image": redis,
                "volumes": [{"type": "volume", "source": "redis_data", "target": "/data"}],
            },
        }
    }


def _index(*, platform: str = "linux/arm64", digest: str = ARM64_DIGEST) -> str:
    os_name, architecture, *variant = platform.split("/")
    platform_value: dict[str, str] = {"os": os_name, "architecture": architecture}
    if variant:
        platform_value["variant"] = variant[0]
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": platform_value,
                },
                {
                    "digest": "sha256:" + "b" * 64,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ],
        }
    )


class FakeRunner:
    def __init__(
        self,
        model: dict[str, Any],
        *,
        probe_failure: str | None = None,
        local_cache: bool = False,
    ) -> None:
        self.model = model
        self.probe_failure = probe_failure
        self.local_cache = local_cache
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: list[str] | tuple[str, ...], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        call = tuple(command)
        self.calls.append(call)
        assert timeout_seconds == 30
        if call[:2] == ("docker", "compose"):
            return subprocess.CompletedProcess(call, 0, stdout=json.dumps(self.model), stderr="")
        if call[:3] == ("docker", "image", "inspect"):
            if not self.local_cache:
                return subprocess.CompletedProcess(call, 1, stdout="", stderr="not found")
            reference = call[3]
            index_digest = reference.rsplit("@", maxsplit=1)[1]
            repository = reference.split(":", maxsplit=1)[0]
            return subprocess.CompletedProcess(
                call,
                0,
                stdout=json.dumps(
                    {
                        "Id": ARM64_DIGEST,
                        "Os": "linux",
                        "Architecture": "arm64",
                        "RepoDigests": [f"{repository}@{index_digest}"],
                    }
                ),
                stderr="",
            )
        if call[:4] == ("docker", "buildx", "imagetools", "inspect"):
            return subprocess.CompletedProcess(call, 0, stdout=_index(), stderr="")
        if call[:2] == ("docker", "run"):
            if self.probe_failure and POSTGRES_REFERENCE in call:
                return subprocess.CompletedProcess(call, 23, stdout="", stderr=self.probe_failure + "\n")
            version = "postgres (PostgreSQL) 16.14" if POSTGRES_REFERENCE in call else "Redis server v=7.4.6"
            return subprocess.CompletedProcess(call, 0, stdout=f"kp-probe:ok:{version}\n", stderr="")
        raise AssertionError(f"unexpected command: {call}")


def test_qualification_is_digest_platform_and_hardened_probe_bound(tmp_path: Path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    runner = FakeRunner(_compose_model())

    results = qualification.qualify(
        compose_file,
        requested_platform="linux/aarch64",
        timeout_seconds=30,
        runner=runner,
    )

    assert [result.service for result in results] == ["postgres", "redis"]
    assert all(result.platform == "linux/arm64" for result in results)
    assert all(result.platform_digest == ARM64_DIGEST for result in results)
    probe_calls = [call for call in runner.calls if call[:2] == ("docker", "run")]
    assert len(probe_calls) == 2
    for call in probe_calls:
        assert "--rm" in call
        assert "--pull=always" in call
        assert call[call.index("--platform") : call.index("--platform") + 2] == ("--platform", "linux/arm64")
        assert call[call.index("--network") : call.index("--network") + 2] == ("--network", "none")
        assert "--read-only" in call
        assert call[call.index("--cap-drop") : call.index("--cap-drop") + 2] == ("--cap-drop", "ALL")
        assert "no-new-privileges:true" in call
        assert not any(value in call for value in ("--volume", "-v", "--mount", "--name"))
    redis_probe = next(call for call in probe_calls if REDIS_REFERENCE in call)
    assert redis_probe[redis_probe.index("--user") : redis_probe.index("--user") + 2] == ("--user", "999:999")
    assert any(value.startswith("/data:rw,noexec,nosuid,nodev") for value in redis_probe)
    assert "kp-probe:runtime-user-mismatch" in redis_probe[-1]
    assert "kp-probe:data-not-writable" in redis_probe[-1]
    assert not any(value in call for call in runner.calls for value in ("up", "down", "create", "rm", "prune"))


def test_exact_cached_images_qualify_offline_without_registry_pull(tmp_path: Path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    runner = FakeRunner(_compose_model(), local_cache=True)

    results = qualification.qualify(
        compose_file,
        requested_platform="linux/arm64",
        timeout_seconds=30,
        runner=runner,
    )

    assert len(results) == 2
    assert all(result.platform_digest == ARM64_DIGEST for result in results)
    assert not any(call[:4] == ("docker", "buildx", "imagetools", "inspect") for call in runner.calls)
    probe_calls = [call for call in runner.calls if call[:2] == ("docker", "run")]
    assert len(probe_calls) == 2
    assert all("--pull=never" in call for call in probe_calls)


@pytest.mark.parametrize(
    ("sentinel", "message"),
    [
        ("kp-probe:passwd-empty", "/etc/passwd is missing or empty"),
        ("kp-probe:entrypoint-empty", "required entrypoint is missing or empty"),
    ],
)
def test_arm64_zero_byte_account_or_entrypoint_fails_closed(
    tmp_path: Path,
    sentinel: str,
    message: str,
) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    runner = FakeRunner(_compose_model(), probe_failure=sentinel)

    with pytest.raises(qualification.QualificationError, match=re.escape(message)):
        qualification.qualify(
            compose_file,
            requested_platform="linux/arm64",
            timeout_seconds=30,
            runner=runner,
        )

    assert not any(value in call for call in runner.calls for value in ("up", "down", "create", "rm", "prune"))


def test_mutable_stateful_reference_is_rejected_before_manifest_or_probe(tmp_path: Path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    runner = FakeRunner(_compose_model(postgres="postgres:16-alpine"))

    with pytest.raises(qualification.QualificationError, match="pinned to a lowercase sha256 digest"):
        qualification.qualify(
            compose_file,
            requested_platform="linux/arm64",
            timeout_seconds=30,
            runner=runner,
        )

    assert not any(call[:4] == ("docker", "buildx", "imagetools", "inspect") for call in runner.calls)
    assert not any(call[:2] == ("docker", "run") for call in runner.calls)


def test_missing_target_platform_is_rejected_before_probe() -> None:
    with pytest.raises(qualification.QualificationError, match="exactly one linux/arm64 manifest"):
        qualification._platform_digest(_index(platform="linux/amd64"), service="postgres", platform="linux/arm64")


def test_unreviewed_named_volume_service_fails_closed() -> None:
    model = _compose_model()
    model["services"]["new-database"] = {
        "image": "example/database@sha256:" + "3" * 64,
        "volumes": [{"type": "volume", "source": "new_data", "target": "/data"}],
    }

    with pytest.raises(qualification.QualificationError, match="has no reviewed base-image probe"):
        qualification._stateful_images(model)


def test_stateless_service_with_omitted_volumes_is_ignored() -> None:
    model = _compose_model()

    assert qualification._stateful_images(model) == {
        "postgres": POSTGRES_REFERENCE,
        "redis": REDIS_REFERENCE,
    }


def test_probe_failure_detail_does_not_echo_untrusted_container_output(tmp_path: Path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    runner = FakeRunner(_compose_model(), probe_failure="provider output with token=secret")

    with pytest.raises(qualification.QualificationError) as captured:
        qualification.qualify(
            compose_file,
            requested_platform="linux/arm64",
            timeout_seconds=30,
            runner=runner,
        )

    assert (
        str(captured.value)
        == "ephemeral image probe for postgres failed: container did not complete the hardened probe"
    )
    assert "secret" not in str(captured.value)


def test_wrapper_invokes_standard_library_preflight() -> None:
    wrapper_path = SCRIPT.parent / "run.sh"
    wrapper = wrapper_path.read_text(encoding="utf-8")

    assert wrapper_path.stat().st_mode & stat.S_IXUSR
    assert 'exec python3 "${script_dir}/qualify.py" "$@"' in wrapper
    assert "docker compose up" not in wrapper
    assert "docker compose down" not in wrapper


def test_success_output_records_digests_platform_probe_and_safe_action(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = qualification.QualifiedImage(
        service="postgres",
        reference=POSTGRES_REFERENCE,
        index_digest="sha256:" + "1" * 64,
        platform="linux/arm64",
        platform_digest=ARM64_DIGEST,
        version="postgres (PostgreSQL) 16.14",
    )
    monkeypatch.setattr(qualification, "qualify", lambda *args, **kwargs: (result,))

    assert qualification.main(["--platform", "linux/arm64"]) == 0

    output = capsys.readouterr()
    assert output.err == ""
    assert "QUALIFIED service=postgres" in output.out
    assert f"index_digest={result.index_digest}" in output.out
    assert f"platform_digest={result.platform_digest}" in output.out
    assert "passwd=non-empty group=non-empty account=present entrypoint=non-empty" in output.out
    assert 'version="postgres (PostgreSQL) 16.14"' in output.out
    assert "SAFE NEXT ACTION:" in output.out


def test_failure_output_is_fail_closed_and_preserves_existing_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[qualification.QualifiedImage, ...]:
        del args, kwargs
        raise qualification.QualificationError("required entrypoint is missing or empty")

    monkeypatch.setattr(qualification, "qualify", fail)

    assert qualification.main(["--platform", "linux/arm64"]) == 1

    output = capsys.readouterr()
    assert output.out == ""
    assert "NOT QUALIFIED: required entrypoint is missing or empty" in output.err
    assert "do not pull, create, or recreate" in output.err
    assert "retain existing containers and named volumes" in output.err
