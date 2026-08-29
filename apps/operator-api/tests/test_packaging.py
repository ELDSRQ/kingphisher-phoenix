"""Production-image dependency contract for the operator API."""

from __future__ import annotations

import tomllib
from pathlib import Path

OPERATOR_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = OPERATOR_ROOT.parents[1]


def test_operator_declares_every_imported_workspace_package() -> None:
    project = tomllib.loads((OPERATOR_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert "kp-domain-verification" in project["dependencies"]


def test_operator_container_installs_the_operator_package_scope() -> None:
    dockerfile = (REPOSITORY_ROOT / "infrastructure" / "containers" / "Dockerfile.operator-api").read_text(
        encoding="utf-8"
    )

    assert "uv sync --frozen --no-dev --no-editable --package kp-operator-api" in dockerfile


def test_operator_installed_commands_exclude_checkout_only_seed_operation() -> None:
    project = tomllib.loads((OPERATOR_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")

    assert project["scripts"] == {"kp-operator-api": "kp_operator_api.__main__:main"}
    assert not (OPERATOR_ROOT / "src" / "kp_operator_api" / "seed_cli.py").exists()
    assert (REPOSITORY_ROOT / "scripts" / "seed.py").is_file()
    assert "seed:\n\t@$(PY) python scripts/seed.py" in makefile
