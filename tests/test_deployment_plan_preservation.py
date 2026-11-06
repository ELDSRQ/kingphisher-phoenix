"""Actual plan-guard decisions preserve grants and active delivery receipts."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/operator/deployment-preflight/deployment_plan_guards.py"
SPEC = importlib.util.spec_from_file_location("deployment_plan_guards", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def _plan(address: str, actions: list[str]) -> dict:
    return {"resource_changes": [{"address": address, "change": {"actions": actions}}]}


@pytest.mark.parametrize("actions", (["delete"], ["delete", "create"], ["create", "delete"], ["forget"]))
@pytest.mark.parametrize("address", (guard.RECEIPT_ADDRESS, "azurerm_role_assignment.gateway"))
def test_workloads_refuse_any_receipt_or_role_destruction(address: str, actions: list[str]) -> None:
    with pytest.raises(guard.UnsafePlan):
        guard.validate_workloads(_plan(address, actions))


def test_workload_update_preserves_receipts_but_cannot_create_before_readiness() -> None:
    guard.validate_workloads(_plan(guard.RECEIPT_ADDRESS, ["no-op"]))
    guard.validate_workloads(_plan(guard.RECEIPT_ADDRESS, ["update"]))
    with pytest.raises(guard.UnsafePlan, match="wait for migration"):
        guard.validate_workloads(_plan(guard.RECEIPT_ADDRESS, ["create"]))


def test_first_activation_creates_only_receipts_and_existing_activation_can_be_noop() -> None:
    guard.validate_receipt_activation(_plan(guard.RECEIPT_ADDRESS, ["create"]), preserve_existing=False)
    guard.validate_receipt_activation(_plan(guard.RECEIPT_ADDRESS, ["no-op"]), preserve_existing=True)
    guard.validate_receipt_activation(_plan(guard.RECEIPT_ADDRESS, ["update"]), preserve_existing=True)
    with pytest.raises(guard.UnsafePlan):
        guard.validate_receipt_activation(_plan(guard.RECEIPT_ADDRESS, ["no-op"]), preserve_existing=False)
    with pytest.raises(guard.UnsafePlan):
        guard.validate_receipt_activation(_plan("azurerm_role_assignment.other", ["create"]), preserve_existing=True)
    with pytest.raises(guard.UnsafePlan):
        guard.validate_receipt_activation({"resource_changes": []}, preserve_existing=True)


@pytest.mark.parametrize(
    "body", (None, {"resource_changes": None}, _plan("resource.test", []), _plan("x", ["unknown"]))
)
def test_malformed_plan_fails_closed(body: object) -> None:
    with pytest.raises(guard.UnsafePlan):
        guard.validate_workloads(body)


@pytest.mark.parametrize("existing", (False, True))
def test_receipt_state_cli_preserves_environment_and_never_applies(tmp_path: Path, existing: bool) -> None:
    binary = tmp_path / "bin"
    binary.mkdir()
    marker = tmp_path / "commands"
    fake = binary / "terraform"
    fake.write_text(
        "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
        "Path(os.environ['TEST_COMMANDS']).write_text(' '.join(sys.argv[1:]))\n"
        "assert sys.argv[1:] == ['state','list']\n"
        "print(os.environ['TEST_STATE'])\n"
    )
    fake.chmod(0o755)
    environment = dict(os.environ)
    output = tmp_path / "github-env"
    output.write_text("PRESERVED=original\n")
    environment.update(
        PATH=f"{binary}{os.pathsep}{environment['PATH']}",
        TEST_COMMANDS=str(marker),
        TEST_STATE=guard.RECEIPT_ADDRESS if existing else "azurerm_resource_group.main",
        GITHUB_ENV=str(output),
    )
    result = subprocess.run(  # noqa: S603 - isolated helper and fake Terraform
        [os.sys.executable, str(SCRIPT), "receipt-state"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "state list"
    assert output.read_text() == f"PRESERVED=original\nKP_PRESERVE_ACS_RECEIPTS={'true' if existing else 'false'}\n"


def test_inspection_failure_does_not_echo_state_secrets(monkeypatch: pytest.MonkeyPatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(guard.shutil, "which", lambda _name: "/fake/terraform")
    monkeypatch.setattr(
        guard.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, stdout=json.dumps({"secret": "private-value"}), stderr="private-value"
        ),
    )
    monkeypatch.setattr(guard.os.sys, "argv", [str(SCRIPT), "receipt-state"])
    assert guard.main() == 1
    assert "private-value" not in capsys.readouterr().out
