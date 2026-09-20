"""Offline contract checks for the targeted CI-runner provisioning workflow."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "provision-ci-runner.yml"


def _step(step_name: str) -> dict:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for step in workflow["jobs"]["provision"]["steps"]:
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"no step named {step_name!r}")


def test_targeted_plan_includes_key_vault_state_move_source() -> None:
    """Terraform must resolve the singleton-to-count Key Vault state move."""

    plan = _step("Plan the runner (targeted)")["run"]
    assert "-target=azurerm_key_vault.main" in plan.split()


def test_key_vault_remains_outside_the_runner_change_allowlist() -> None:
    """The extra target provides state context, never mutation permission."""

    guard = _step("Refuse any destructive change")["run"]
    assert '"azurerm_key_vault.main[0]"' not in guard
    assert "if unexpected:" in guard
    assert "runner plan contains unrelated changes" in guard
