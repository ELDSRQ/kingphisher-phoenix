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


def test_project_runtime_images_declare_numeric_non_root_user() -> None:
    dockerfiles = [
        *sorted((ROOT / "infrastructure" / "containers").glob("Dockerfile.*")),
        ROOT / "infrastructure" / "mock-services" / "Dockerfile",
    ]

    for dockerfile in dockerfiles:
        contents = dockerfile.read_text()
        assert "USER 10001:10001" in contents, dockerfile
