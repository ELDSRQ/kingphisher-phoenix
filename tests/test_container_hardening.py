"""Static regression checks for development container security defaults."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_published_ports_are_loopback_only() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    for name, service in compose["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (
                f"{name} publishes a port beyond the local development host: {port}"
            )


def test_compose_services_disable_privilege_escalation() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    for name, service in compose["services"].items():
        assert "no-new-privileges:true" in service.get("security_opt", []), name
        assert service.get("init") is True, name
        assert service.get("pids_limit", 0) > 0, name


def test_every_external_compose_image_uses_an_immutable_manifest_digest() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    for name, service in compose["services"].items():
        image = service.get("image")
        if image is None:
            assert "build" in service, name
            continue
        repository, separator, digest = image.partition("@sha256:")
        assert separator, f"{name} uses a mutable image reference: {image}"
        assert ":" in repository, f"{name} must retain a readable version tag"
        assert len(digest) == 64 and all(character in "0123456789abcdef" for character in digest), name


def test_project_runtime_images_declare_numeric_non_root_user() -> None:
    release_dockerfiles = sorted((ROOT / "infrastructure" / "containers").glob("Dockerfile.*"))

    for dockerfile in release_dockerfiles:
        contents = dockerfile.read_text()
        assert "USER 65532:65532" in contents, dockerfile

    mock_dockerfile = ROOT / "infrastructure" / "mock-services" / "Dockerfile"
    contents = mock_dockerfile.read_text()
    from_lines = [line for line in contents.splitlines() if line.startswith("FROM ")]
    assert len(from_lines) == 3
    assert all("@sha256:" in line for line in from_lines)
    assert "USER 65532:65532" in contents
    assert "FROM cgr.dev/chainguard/python@sha256:" in contents
    assert " AS builder" in contents
    runtime = contents.rsplit("FROM cgr.dev/chainguard/python@sha256:", maxsplit=1)[1]
    assert "\nRUN " not in runtime
    assert "/uv" not in runtime
    assert "pip " not in runtime
    assert "COPY --from=builder --chown=65532:65532 /srv/.venv /srv/.venv" in runtime


def test_mock_image_installs_only_hash_verified_binary_dependencies() -> None:
    mock_directory = ROOT / "infrastructure" / "mock-services"
    dockerfile = (mock_directory / "Dockerfile").read_text()
    requirements = (mock_directory / "requirements.txt").read_text()

    assert "--require-hashes" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "make lock-mock-services" in requirements
    requirement_lines = [line for line in requirements.splitlines() if line and not line.startswith((" ", "#"))]
    assert requirement_lines
    assert all("==" in line for line in requirement_lines)
    assert requirements.count("--hash=sha256:") >= len(requirement_lines)


def test_mock_dependency_lock_has_a_reproducible_regeneration_contract() -> None:
    mock_directory = ROOT / "infrastructure" / "mock-services"
    direct_dependencies = {
        line
        for line in (mock_directory / "requirements.in").read_text().splitlines()
        if line and not line.startswith("#")
    }
    makefile = (ROOT / "Makefile").read_text()
    recipe = makefile.split("lock-mock-services:\n", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    assert direct_dependencies == {
        "cryptography==50.0.0",
        "fastapi==0.141.1",
        "PyJWT==2.13.0",
        "uvicorn==0.52.1",
    }
    for flag in ("--python-version 3.14", "--python-platform linux", "--only-binary=:all:", "--generate-hashes"):
        assert flag in recipe
