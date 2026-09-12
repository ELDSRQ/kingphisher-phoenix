"""Offline contract checks for the manually-dispatched Azure idle workflow.

`.github/workflows/azure-idle.yml` is the only mechanism that can apply
`environments/idle.tfvars`: `network_mode=private` puts Key Vault behind a
private endpoint, terraform refreshes ~25 `azurerm_key_vault_secret` resources
through the vault DATA plane and the idle apply DELETES the `redis-url` secret,
and the runner VM has no usable managed identity — so only a GitHub Actions job
on the self-hosted VNet runner has both the reachability and the credentials.

That makes it the most destructive workflow in the repository, and one that
cannot be rehearsed. Its contract is therefore pinned here:

* `plan` is the default mode and changes nothing at all — it does not even stop
  PostgreSQL,
* `apply` additionally requires the `confirm` dispatch input to be the exact
  string IDLE, enforced three times: before the environment review, again on the
  runner, and a third time inside `azure-idle.sh` itself,
* every plan is parsed with `terraform show -json` — never grepped as text — and
  the job FAILS if it would destroy or replace the PostgreSQL server, the WORM
  audit-anchor storage, or the CI runner VM the job is running on,
* `KP_KEEP_CI_RUNNER=1` is passed, so the CLI `-var=deploy_ci_runner=true`
  outranks `deploy_ci_runner = false` in idle.tfvars and the apply does not
  destroy its own runner mid-apply,
* the apply consumes a saved plan file, never a bare re-resolution,
* it reuses `scripts/operator/azure-idle.sh` instead of reimplementing terraform,
* it copies the auth/runner pattern of `azure-deploy.yml`, which it does not and
  must not modify,
* it ends by telling the operator to deallocate the runner, that ACR is gone and
  every image must be re-pushed, and that the resume order is PostgreSQL first.

Nothing here touches Azure, GitHub or Terraform. The workflow's shell programs
are executed directly, and the script runs against the same `az`/`gh`/`terraform`
shims the sibling module uses.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_azure_idle_contract import _run_script

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "azure-idle.yml"
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "azure-deploy.yml"
SCRIPT = REPO_ROOT / "scripts" / "operator" / "azure-idle.sh"
IDLE_TFVARS = REPO_ROOT / "infrastructure" / "terraform" / "environments" / "idle.tfvars"
RUNBOOK = REPO_ROOT / "docs" / "AZURE-IDLE.md"

# azure-deploy.yml is SHA-256 pinned across the deployment orchestration; this is
# the value the operator API refuses to dispatch without.
EXPECTED_DEPLOY_WORKFLOW_SHA256 = "5a1294cb107753de408845b2b2a95e59ac369642798c897ccec8f4e475439ebc"

RUNNER_LABELS = ("self-hosted", "linux", "azure-vnet")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(_source(WORKFLOW))


def _dispatch_inputs() -> dict:
    # PyYAML resolves the bare key `on` to the boolean True.
    triggers = _workflow()[True]
    return triggers["workflow_dispatch"]["inputs"]


def _job(name: str) -> dict:
    return _workflow()["jobs"][name]


def _step(job: str, step_name: str) -> dict:
    for step in _job(job)["steps"]:
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"no step named {step_name!r} in job {job!r}")


def _run_step(job: str, step_name: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute a step's shell program with the environment GitHub would supply."""
    step = _step(job, step_name)
    assert step.get("shell") == "bash", f"{step_name!r} must pin shell: bash"
    return subprocess.run(  # noqa: S603
        ["bash", "-c", step["run"]],  # noqa: S607
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _plan_change(kind: str, name: str, actions: list[str], index: int | None = None) -> dict[str, object]:
    address = f"{kind}.{name}" + (f"[{index}]" if index is not None else "")
    return {"address": address, "type": kind, "name": name, "change": {"actions": actions}}


def _plan_json(*changes: dict[str, object]) -> str:
    return json.dumps({"format_version": "1.2", "resource_changes": list(changes)})


# The destroy set `stop` is supposed to produce: nothing protected.
BENIGN_IDLE_PLAN = _plan_json(
    _plan_change("azurerm_container_registry", "main", ["delete"], 0),
    _plan_change("azurerm_managed_redis", "main", ["delete"], 0),
    _plan_change("azurerm_private_endpoint", "registry", ["delete"], 0),
    _plan_change("azurerm_key_vault_secret", "runtime", ["delete"]),
    _plan_change("azurerm_container_app", "operator", ["delete"], 0),
    _plan_change("azurerm_eventgrid_system_topic", "acs_delivery", ["delete"], 0),
    _plan_change("azurerm_role_definition", "acs_email_sender", ["delete"], 0),
)

# (type, name, index) of everything the guard must refuse to see removed.
PROTECTED = [
    ("azurerm_postgresql_flexible_server", "main", None),
    ("azurerm_postgresql_flexible_server_database", "main", None),
    ("azurerm_storage_account", "audit_anchor", None),
    ("azurerm_storage_container", "audit_anchor", None),
    ("azurerm_storage_container_immutability_policy", "audit_anchor", None),
    ("azurerm_linux_virtual_machine", "ci_runner", 0),
]

WORKFLOW_APPLY_ENVIRONMENT = {"GITHUB_ACTIONS": "true", "KP_IDLE_DISPATCH_CONFIRM": "IDLE"}


def _guard(tmp_path: Path, plan: str) -> subprocess.CompletedProcess[str]:
    """Run the machine-readable destroy guard over a structured plan."""
    target = tmp_path / "plan.json"
    target.write_text(plan, encoding="utf-8")
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), "guard-plan", str(target)],  # noqa: S607
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


# --------------------------------------------------------------------------
# The dispatch shape: plan is the default, apply needs a typed confirmation
# --------------------------------------------------------------------------


def test_the_workflow_parses_and_is_dispatch_only() -> None:
    triggers = _workflow()[True]
    assert list(triggers) == ["workflow_dispatch"], "an idle must never fire on a schedule or a push"


def test_plan_is_the_default_mode() -> None:
    mode = _dispatch_inputs()["mode"]
    assert mode["type"] == "choice"
    assert mode["default"] == "plan"
    assert mode["options"] == ["plan", "apply"]


def test_apply_needs_a_second_confirmation_input() -> None:
    confirm = _dispatch_inputs()["confirm"]
    # Not `required`, because mode=plan must be dispatchable without it; the
    # requirement is enforced against mode=apply in code, not by the form.
    assert confirm.get("required", False) is False
    assert confirm["default"] == ""
    assert "IDLE" in confirm["description"]


@pytest.mark.parametrize(
    ("mode", "confirm", "expected"),
    [
        ("plan", "", 0),
        ("plan", "IDLE", 0),
        ("apply", "IDLE", 0),
        ("apply", "", 1),
        ("apply", "idle", 1),
        ("apply", "IDLE ", 1),
        ("apply", "yes", 1),
        ("destroy", "IDLE", 1),
        ("", "", 1),
    ],
)
def test_the_confirmation_gate_refuses_everything_but_the_exact_string(mode: str, confirm: str, expected: int) -> None:
    result = _run_step("guard", "Refuse an apply that was not confirmed", {"IDLE_MODE": mode, "IDLE_CONFIRM": confirm})
    assert result.returncode == expected, result.stdout + result.stderr
    if expected:
        assert "::error::" in result.stdout


def test_the_confirmation_is_checked_before_the_environment_review_is_spent() -> None:
    """A malformed dispatch must not wake a reviewer or the self-hosted runner."""
    guard, idle = _job("guard"), _job("idle")
    assert "environment" not in guard, "the input check must not sit behind the approval it protects"
    assert guard["runs-on"] == "ubuntu-latest"
    assert idle["needs"] == ["guard"]
    assert idle["environment"] == "staging"


def test_the_confirmation_is_checked_again_on_the_runner() -> None:
    """Defence in depth: the approval could be given for a differently-shaped run."""
    result = _run_step(
        "idle",
        "Refuse an apply that was not confirmed",
        {"IDLE_MODE": "apply", "KP_IDLE_DISPATCH_CONFIRM": ""},
    )
    assert result.returncode == 1
    assert "confirm=IDLE" in result.stdout
    assert (
        _run_step(
            "idle",
            "Refuse an apply that was not confirmed",
            {"IDLE_MODE": "apply", "KP_IDLE_DISPATCH_CONFIRM": "IDLE"},
        ).returncode
        == 0
    )


def test_the_dispatch_inputs_reach_the_steps_as_environment_not_interpolation() -> None:
    """`${{ inputs.confirm }}` spliced into a `run:` body would be an injection."""
    source = _source(WORKFLOW)
    for step in _job("guard")["steps"] + _job("idle")["steps"]:
        assert "${{" not in step.get("run", ""), f"{step.get('name')!r} interpolates into its shell body"
    assert "IDLE_CONFIRM: ${{ inputs.confirm }}" in source
    assert "KP_IDLE_DISPATCH_CONFIRM: ${{ inputs.confirm }}" in source


# --------------------------------------------------------------------------
# The script's own gate: apply-idle is not a local bypass of the typed 'yes'
# --------------------------------------------------------------------------


def test_apply_idle_refuses_outside_github_actions(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "apply-idle", extra_env={"GITHUB_ACTIONS": ""})

    assert result.returncode == 2
    assert "workflow-only path" in result.stderr
    assert f"{SCRIPT.name} stop" in result.stderr, "it must name the interactive command instead"
    assert not calls, "it must refuse before reading anything from Azure"


def test_apply_idle_refuses_without_the_typed_dispatch_confirmation(tmp_path: Path) -> None:
    for confirm in ("", "idle", "IDLE ", "yes"):
        result, calls = _run_script(
            tmp_path,
            "apply-idle",
            extra_env={"GITHUB_ACTIONS": "true", "KP_IDLE_DISPATCH_CONFIRM": confirm},
        )
        assert result.returncode == 2, confirm
        assert "the exact string IDLE" in result.stderr
        assert not calls, confirm


def test_apply_idle_with_the_confirmation_applies_only_the_saved_plan(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "apply-idle", extra_env=WORKFLOW_APPLY_ENVIRONMENT)

    assert result.returncode == 0, result.stdout + result.stderr
    plans = [call for call in calls if call.startswith("terraform plan")]
    applies = [call for call in calls if call.startswith("terraform apply")]
    assert len(plans) == 1 and len(applies) == 1, calls
    assert "-out=.idle.tfplan" in plans[0]
    assert applies[0].endswith(".idle.tfplan"), applies
    assert "-auto-approve" not in applies[0]
    # It re-plans on the runner rather than trusting a plan from another job.
    assert calls.index(plans[0]) < calls.index(applies[0])
    assert [call for call in calls if call.startswith("az postgres flexible-server stop")]


def test_the_only_non_interactive_apply_is_the_workflow_one() -> None:
    source = _source(SCRIPT)
    assert source.count("terraform apply") == 1, "there must be exactly one apply in the script"
    assert re.search(r"^require_dispatch_confirmation\(\)\s*\{", source, re.MULTILINE)
    calls = re.findall(r"^\s*require_dispatch_confirmation .*$", source, re.MULTILINE)
    assert calls == ['  require_dispatch_confirmation "apply-idle"'], calls
    assert "read -r -p" in source, "the interactive path still types 'yes'"


# --------------------------------------------------------------------------
# plan mode changes nothing
# --------------------------------------------------------------------------


def test_plan_mode_changes_nothing_at_all(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "plan-idle")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PLAN ONLY" in result.stdout
    assert not [call for call in calls if call.startswith(("terraform apply", "terraform destroy"))], calls
    # Not even the reversible half: only apply-idle stops the database.
    assert not [call for call in calls if "flexible-server stop" in call], calls
    assert not [call for call in calls if "containerapp update" in call], calls


def test_plan_mode_needs_no_dispatch_confirmation(tmp_path: Path) -> None:
    """It is read-only, so it must not be gated on a string the operator can typo."""
    result, _ = _run_script(tmp_path, "plan-idle", extra_env={"GITHUB_ACTIONS": "", "KP_IDLE_DISPATCH_CONFIRM": ""})
    assert result.returncode == 0, result.stdout + result.stderr


def test_plan_mode_prints_the_full_plan_and_a_destroy_summary(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "plan-idle")

    plan = next(call for call in calls if call.startswith("terraform plan"))
    # No -compact-warnings/-json rendering: the full human plan is what streams.
    assert "-compact" not in plan
    assert [call for call in calls if call.startswith("terraform show -json")], calls
    assert "destroy guard" in result.stdout
    assert "resources this plan DESTROYS" in result.stdout
    assert "azurerm_container_registry.main[0]" in result.stdout


def test_the_two_modes_are_mutually_exclusive_steps() -> None:
    assert _step("idle", "Plan the idle posture")["if"] == "inputs.mode == 'plan'"
    assert _step("idle", "Apply the idle posture")["if"] == "inputs.mode == 'apply'"
    assert _step("idle", "Plan the idle posture")["run"].strip().endswith("plan-idle")
    assert _step("idle", "Apply the idle posture")["run"].strip().endswith("apply-idle")


# --------------------------------------------------------------------------
# The destroy guard, parsed from `terraform show -json`
# --------------------------------------------------------------------------


def test_the_guard_reads_the_structured_plan_not_the_human_output() -> None:
    source = _source(SCRIPT)
    assert "terraform show -json" in source
    assert "resource_changes" in source
    # The human plan is only ever grepped for the two known failure strings, and
    # never for what the plan would destroy.
    for human_grep in ("grep -q 'destroy'", "will be destroyed", "to destroy."):
        assert human_grep not in source, f"the guard must not read the rendered plan ({human_grep!r})"


@pytest.mark.parametrize(("kind", "name", "index"), PROTECTED)
@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"], ["create", "delete"]])
def test_the_guard_refuses_a_plan_that_removes_a_protected_resource(
    tmp_path: Path, kind: str, name: str, index: int | None, actions: list[str]
) -> None:
    result = _guard(tmp_path, _plan_json(_plan_change(kind, name, actions, index)))

    assert result.returncode == 3, result.stdout + result.stderr
    assert "PROTECTED" in result.stderr
    assert f"{kind}.{name}" in result.stderr


def test_the_guard_allows_the_real_idle_destroy_set(tmp_path: Path) -> None:
    result = _guard(tmp_path, BENIGN_IDLE_PLAN)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "guard OK" in result.stdout
    assert "DESTROY: 7" in result.stdout


def test_the_guard_surfaces_the_two_destroys_nobody_expects(tmp_path: Path) -> None:
    """Beyond the documented "Container Apps + ACR + Redis" summary."""
    result = _guard(tmp_path, BENIGN_IDLE_PLAN)

    assert "azurerm_eventgrid_system_topic.acs_delivery[0]" in result.stdout
    assert "azurerm_role_definition.acs_email_sender[0]" in result.stdout
    assert result.stdout.count("gated on deploy_workloads") >= 2
    assert "recreates them" in result.stdout or "recreated" in result.stdout


def test_the_guard_refuses_a_plan_it_cannot_parse(tmp_path: Path) -> None:
    for unusable in ("", "not json", "[]", '{"nope": true}'):
        result = _guard(tmp_path, unusable)
        assert result.returncode == 3, unusable
        assert "refuses" in result.stderr or "no resource_changes" in result.stderr


def test_a_protected_destroy_fails_the_apply_before_anything_changes(tmp_path: Path) -> None:
    """The guard rail must fail the JOB, not merely print a warning."""
    hostile = _plan_json(
        _plan_change("azurerm_container_registry", "main", ["delete"], 0),
        _plan_change("azurerm_postgresql_flexible_server", "main", ["delete", "create"]),
    )
    result, calls = _run_script(
        tmp_path,
        "apply-idle",
        extra_env={**WORKFLOW_APPLY_ENVIRONMENT, "KP_TEST_PLAN_JSON": hostile},
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not [call for call in calls if call.startswith("terraform apply")], calls
    # It plans and guards BEFORE stopping the database, so a refusal leaves Azure
    # exactly as it was found.
    assert not [call for call in calls if "flexible-server stop" in call], calls


def test_a_protected_destroy_also_fails_the_interactive_stop(tmp_path: Path) -> None:
    hostile = _plan_json(_plan_change("azurerm_storage_container", "audit_anchor", ["delete"]))
    result, calls = _run_script(tmp_path, "stop", stdin="yes\n", extra_env={"KP_TEST_PLAN_JSON": hostile})

    assert result.returncode == 3, result.stdout + result.stderr
    assert not [call for call in calls if call.startswith("terraform apply")], calls


def test_the_guard_runs_on_every_path_that_can_change_azure() -> None:
    """plan-idle, apply-idle, stop and start all reach terraform through run_plan."""
    source = _source(SCRIPT)
    assert source.count("guard_plan_json") == 3, "declared once, called from run_plan and from guard-plan"
    assert re.search(r"^run_plan\(\)\s*\{", source, re.MULTILINE)
    # confirm_apply (stop/start) delegates to run_plan rather than planning itself.
    confirm_body = source[source.index("confirm_apply() {") :]
    confirm_body = confirm_body[: confirm_body.index("\n}\n")]
    executable = "\n".join(line for line in confirm_body.splitlines() if not line.lstrip().startswith("#"))
    assert "terraform plan" not in executable
    assert "run_plan " in executable
    # There is exactly one `terraform plan` in the script, inside run_plan, and
    # the three commands that can change Azure all call it.
    invocations = re.findall(r"terraform plan -input=false", source)
    assert len(invocations) == 1, invocations
    assert len(re.findall(r"^\s*run_plan ", source, re.MULTILINE)) == 3  # confirm_apply, plan-idle, apply-idle


# --------------------------------------------------------------------------
# KP_KEEP_CI_RUNNER — without it the apply destroys the VM running it
# --------------------------------------------------------------------------


def test_the_workflow_passes_kp_keep_ci_runner() -> None:
    assert _job("idle")["env"]["KP_KEEP_CI_RUNNER"] == "1"


def test_idle_tfvars_would_otherwise_destroy_the_runner() -> None:
    """This is why the flag exists — the committed posture turns the runner off."""
    assert re.search(r"^deploy_ci_runner\s*=\s*false$", _source(IDLE_TFVARS), re.MULTILINE)


def test_kp_keep_ci_runner_becomes_a_cli_var_that_outranks_the_var_file(tmp_path: Path) -> None:
    _, kept = _run_script(tmp_path, "plan-idle", extra_env={"KP_KEEP_CI_RUNNER": "1"})
    plan = next(call for call in kept if call.startswith("terraform plan"))
    assert "-var=deploy_ci_runner=true" in plan
    # A CLI -var beats a -var-file; a TF_VAR_ environment variable would not.
    assert plan.index("-var=deploy_ci_runner=true") > plan.index("-var-file=environments/idle.tfvars")
    assert "TF_VAR_deploy_ci_runner" not in _source(WORKFLOW)

    _, dropped = _run_script(tmp_path, "plan-idle", extra_env={"KP_KEEP_CI_RUNNER": "0"})
    assert "-var=deploy_ci_runner=true" not in next(c for c in dropped if c.startswith("terraform plan"))


def test_the_runner_vm_is_protected_by_the_guard_as_well(tmp_path: Path) -> None:
    """Belt and braces: even a stray plan cannot take the runner out mid-apply."""
    result = _guard(tmp_path, _plan_json(_plan_change("azurerm_linux_virtual_machine", "ci_runner", ["delete"], 0)))
    assert result.returncode == 3
    assert "runner executing the job" in result.stderr


def test_the_workflow_supplies_the_registration_token_deploy_ci_runner_requires() -> None:
    """main.tf refuses deploy_ci_runner=true with an empty ci_runner_registration_token."""
    source = _source(WORKFLOW)
    assert "TF_VAR_ci_runner_registration_token: ${{ secrets.CI_RUNNER_REGISTRATION_TOKEN }}" in source
    empty = _run_step("idle", "Refuse to run without the CI runner registration token", {})
    assert empty.returncode == 1
    assert "ENVIRONMENT level" in empty.stdout
    present = _run_step(
        "idle",
        "Refuse to run without the CI runner registration token",
        {"TF_VAR_ci_runner_registration_token": "placeholder"},
    )
    assert present.returncode == 0


# --------------------------------------------------------------------------
# The auth/runner pattern, copied from azure-deploy.yml — which is untouched
# --------------------------------------------------------------------------


def test_azure_deploy_workflow_is_unmodified() -> None:
    """It is SHA-256 pinned across the deployment orchestration; editing it breaks that."""
    digest = hashlib.sha256(DEPLOY_WORKFLOW.read_bytes()).hexdigest()
    assert digest == EXPECTED_DEPLOY_WORKFLOW_SHA256


def test_it_runs_on_the_vnet_runner() -> None:
    runs_on = _job("idle")["runs-on"]
    for label in RUNNER_LABELS:
        assert label in runs_on, runs_on
        assert label in _source(DEPLOY_WORKFLOW), f"the deploy workflow no longer selects {label}"


def test_it_authenticates_with_github_oidc_and_no_stored_credential() -> None:
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    assert _job("idle")["permissions"] == {"contents": "read", "id-token": "write"}
    source = _source(WORKFLOW)
    assert 'ARM_USE_OIDC: "true"' in source
    for name in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"):
        assert f"${{{{ vars.{name} }}}}" in source, name
        assert name in _source(DEPLOY_WORKFLOW)
    # The azurerm provider needs OIDC directly; the azure/login CLI session is a
    # service principal, which it rejects for the provider config.
    assert "ARM_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}" in source


def test_the_terraform_state_location_comes_from_environment_variables() -> None:
    source = _source(WORKFLOW)
    for name in ("TF_STATE_RESOURCE_GROUP", "TF_STATE_STORAGE_ACCOUNT", "TF_STATE_CONTAINER"):
        assert f"${{{{ vars.{name} }}}}" in source, name
        assert name in _source(DEPLOY_WORKFLOW)
    # Passing them straight through means the script never needs `gh`, so no
    # GitHub token has to exist on the runner.
    assert "KP_TF_STATE_RESOURCE_GROUP" in source
    assert "GH_TOKEN" not in source


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    uses = re.findall(r"uses:\s*(\S+)", _source(WORKFLOW))
    assert uses, "the workflow must use at least the checkout action"
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.\-/]+@[0-9a-f]{40}", reference), reference
        # The same pin the deploy workflow already reviewed and uses.
        assert reference in _source(DEPLOY_WORKFLOW), f"{reference} is not the pin azure-deploy.yml uses"


def test_terraform_is_pinned_and_the_wrapper_is_off() -> None:
    """The setup-terraform wrapper merges stderr into stdout, corrupting show -json."""
    step = _step("idle", "Install Terraform")
    assert step["with"]["terraform_version"] == "1.9.8"
    assert step["with"]["terraform_wrapper"] is False


def test_an_idle_cannot_interleave_with_a_deployment() -> None:
    concurrency = _workflow()["concurrency"]
    assert concurrency["cancel-in-progress"] is False
    assert concurrency["group"] == "azure-staging"
    assert "azure-${{ inputs.environment }}" in _source(DEPLOY_WORKFLOW), "the deploy group shape changed"


def test_the_workflow_reuses_the_script_instead_of_running_terraform() -> None:
    for job in ("guard", "idle"):
        for step in _job(job)["steps"]:
            body = step.get("run", "")
            assert "terraform " not in body, f"{step.get('name')!r} invokes terraform directly"
            assert "az " not in body or "echo" in body, f"{step.get('name')!r} calls az directly"
    assert "scripts/operator/azure-idle.sh" in _source(WORKFLOW)


# --------------------------------------------------------------------------
# What the operator is told at the end
# --------------------------------------------------------------------------


def _reminder(tmp_path: Path, mode: str) -> str:
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")
    result = _run_step(
        "idle",
        "What the operator has to do next",
        {"IDLE_MODE": mode, "KP_RG": "rg-kp-staging", "GITHUB_STEP_SUMMARY": str(summary)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    written = summary.read_text(encoding="utf-8")
    assert written.strip(), "the reminder must reach the job summary, not only the log"
    return result.stdout


def test_the_reminder_runs_even_when_the_job_failed() -> None:
    assert _step("idle", "What the operator has to do next")["if"] == "always()"


def test_the_reminder_tells_the_operator_to_deallocate_the_runner(tmp_path: Path) -> None:
    """The job cannot start or stop the VM it runs on; that stays manual."""
    for mode in ("plan", "apply"):
        printed = _reminder(tmp_path, mode)
        assert "az vm deallocate -g rg-kp-staging -n vm-kp-staging-runner" in printed, mode
        assert "az vm start -g rg-kp-staging -n vm-kp-staging-runner" in printed, mode


def test_the_apply_reminder_says_acr_is_gone_and_names_the_resume_order(tmp_path: Path) -> None:
    printed = _reminder(tmp_path, "apply")

    assert "container registry is gone" in printed
    assert "re-pushed" in printed
    assert "dispatch-staging-workloads.sh" in printed
    assert "PostgreSQL FIRST, then the apps" in printed
    # And the two destroys that are not in the documented summary.
    assert "Event Grid system topic" in printed
    assert "email-sender role" in printed


def test_the_plan_reminder_says_nothing_changed(tmp_path: Path) -> None:
    printed = _reminder(tmp_path, "plan")

    assert "Nothing was changed" in printed
    assert "PostgreSQL was not stopped" in printed
    assert "confirm=IDLE" in printed
    assert "container registry is gone" not in printed


# --------------------------------------------------------------------------
# Documentation
# --------------------------------------------------------------------------


def test_the_runbook_documents_the_workflow_and_the_manual_vm_steps() -> None:
    runbook = _source(RUNBOOK)
    for required in (
        ".github/workflows/azure-idle.yml",
        "az vm start -g rg-kp-staging -n vm-kp-staging-runner",
        "az vm deallocate -g rg-kp-staging -n vm-kp-staging-runner",
        "mode=plan",
        "confirm=IDLE",
        "KP_KEEP_CI_RUNNER",
        "terraform show -json",
        "PostgreSQL first",
    ):
        assert required in runbook, f"docs/AZURE-IDLE.md must document {required}"


def test_the_workflow_says_why_it_cannot_start_its_own_runner() -> None:
    source = _source(WORKFLOW)
    assert "cannot start" in source.lower()
    assert "10.42.2.4" in source, "the evidence for the private-endpoint claim belongs next to it"


if __name__ == "__main__":  # pragma: no cover - convenience
    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))
