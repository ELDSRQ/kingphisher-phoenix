"""Tests for the Azure onboarding automation.

The scripts under `scripts/` are how a new tenant gets stood up, and they are
the part of this system a first-time administrator meets first. They are also
the part with no type checker and no compiler, so their contract is pinned here:

* they refuse bad input rather than half-provisioning a tenant,
* `--dry-run` genuinely changes nothing,
* resource names are deterministic, so re-running converges instead of
  littering the subscription with duplicates, and
* the preflight blocks (non-zero exit) rather than warning when the tenant
  cannot actually deploy.

Nothing here touches Azure. The scripts are exercised in dry-run, and the ones
that need a real subscription are asserted on their refusal behaviour.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
BOOTSTRAP = SCRIPTS / "azure_bootstrap.sh"
PREFLIGHT = SCRIPTS / "azure_preflight.sh"
MAIL_CHECK = SCRIPTS / "azure_mail_check.sh"
ENTRA_GRAPH_PREFLIGHT = SCRIPTS / "entra_graph_preflight.sh"
CLI_SHIM = REPO_ROOT / "tests" / "support" / "azure_cli_shim.py"

FAKE_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
FAKE_REPO = "example-org/example-repo"


def embedded_checkpoint_helper() -> str:
    """Extract the helper exactly as YAML removes the run-block indentation."""

    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    initializer = workflow[
        workflow.index("- name: Initialize append-only deployment checkpoint") : workflow.index(
            "- name: Check out source", workflow.index("  deploy:")
        )
    ]
    match = re.search(r"helper\.write_text\(r'''(.*?)''', encoding=\"utf-8\"\)", initializer, flags=re.DOTALL)
    assert match is not None
    # YAML strips the ten-space scalar indentation. Preserve all additional
    # indentation because it belongs to the generated Python program.
    lines = match.group(1).splitlines()
    return "\n".join([lines[0], *(line[10:] if line.startswith(" " * 10) else line for line in lines[1:])])


@pytest.fixture(autouse=True)
def isolated_command_line_tools(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Put deterministic Azure/GitHub CLI shims ahead of host tools.

    Offline tests must behave the same whether the developer has no Azure CLI,
    an authenticated CLI, or an unauthenticated CLI.  A test explicitly marked
    ``azure_live`` opts out and sees the host's real command line tools.
    """
    if request.node.get_closest_marker("azure_live") is not None:
        return
    shim_dir = tmp_path / "cli"
    shim_dir.mkdir()
    for executable in ("az", "gh"):
        launcher = shim_dir / executable
        launcher.write_text(
            f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(CLI_SHIM))} {executable} "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o700)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def run(script: Path, *args: str, expect: int | None = None) -> subprocess.CompletedProcess[str]:
    # S603/S607: the command is a fixed interpreter plus a script path from this
    # repository, and the arguments are literals defined in this file. There is
    # no external input here.
    result = subprocess.run(  # noqa: S603
        ["bash", str(script), *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=300,
        cwd=REPO_ROOT,
        env={**os.environ, "NO_COLOR": "1"},
    )
    if expect is not None:
        assert result.returncode == expect, f"exit {result.returncode}\n{result.stdout}\n{result.stderr}"
    return result


# --- every script must parse ------------------------------------------------------


@pytest.mark.parametrize(
    "script",
    [BOOTSTRAP, PREFLIGHT, MAIL_CHECK, ENTRA_GRAPH_PREFLIGHT],
    ids=lambda p: p.name,
)
def test_script_is_syntactically_valid(script: Path) -> None:
    assert script.exists(), f"{script} is missing"
    subprocess.run(["bash", "-n", str(script)], check=True, capture_output=True, timeout=60)  # noqa: S603, S607


@pytest.mark.parametrize(
    "script",
    [BOOTSTRAP, PREFLIGHT, MAIL_CHECK, ENTRA_GRAPH_PREFLIGHT],
    ids=lambda p: p.name,
)
def test_script_is_executable(script: Path) -> None:
    # Documented as `scripts/foo.sh`, so it has to actually run that way.
    assert os.access(script, os.X_OK), f"{script} is not executable"


@pytest.mark.parametrize(
    "script",
    [BOOTSTRAP, PREFLIGHT, MAIL_CHECK, ENTRA_GRAPH_PREFLIGHT],
    ids=lambda p: p.name,
)
def test_script_has_usage_help(script: Path) -> None:
    result = run(script, "--help", expect=0)
    assert "Usage" in result.stdout or "usage" in result.stdout


# --- refusing bad input -----------------------------------------------------------


def test_bootstrap_requires_a_subscription() -> None:
    result = run(BOOTSTRAP, "--repo", FAKE_REPO)
    assert result.returncode != 0
    assert "subscription" in result.stderr.lower()


def test_bootstrap_requires_a_repository() -> None:
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION)
    assert result.returncode != 0
    assert "repo" in result.stderr.lower()


def test_bootstrap_rejects_an_unknown_environment() -> None:
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--environment", "prod-ish")
    assert result.returncode != 0
    assert "staging" in result.stderr and "production" in result.stderr


def test_bootstrap_rejects_unknown_arguments() -> None:
    # A typo'd flag must stop, not be silently ignored while the script
    # provisions something the operator did not ask for.
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--yolo")
    assert result.returncode != 0
    assert "unknown argument" in result.stderr


def test_preflight_requires_a_subscription() -> None:
    result = run(PREFLIGHT)
    assert result.returncode == 2
    assert "subscription" in result.stderr.lower()


def test_mail_check_requires_a_resource_group() -> None:
    result = run(MAIL_CHECK, "--to", "someone@example.com")
    assert result.returncode == 2
    assert "resource-group" in result.stderr


def test_entra_graph_preflight_requires_separate_identity_inputs() -> None:
    result = run(ENTRA_GRAPH_PREFLIGHT)
    assert result.returncode == 2
    assert "directory-client-id" in result.stderr


@pytest.mark.parametrize("bad", ["notanemail", "missing-at.example.com", "@example.com"])
def test_mail_check_rejects_malformed_recipients(bad: str) -> None:
    # This script sends real mail. A malformed address must fail loudly before
    # anything is dispatched.
    result = run(MAIL_CHECK, "--resource-group", "rg-example", "--to", bad)
    assert result.returncode == 2
    assert "email address" in result.stderr


# --- dry-run behaviour ------------------------------------------------------------


def test_bootstrap_dry_run_changes_nothing() -> None:
    result = run(
        BOOTSTRAP,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        FAKE_REPO,
        "--environment",
        "staging",
        "--dry-run",
    )
    # It reaches the end even against a subscription it cannot see.
    assert "Bootstrap complete" in result.stdout, result.stdout + result.stderr
    # Every mutating call is announced rather than made.
    for mutating in ("az group create", "az storage account create", "gh variable set"):
        assert f"[dry-run] {mutating}" in result.stdout, f"{mutating} was not dry-run guarded"
    assert "would create application" in result.stdout


def test_bootstrap_dry_run_creates_two_distinct_applications() -> None:
    # One identity deploys, a different one is what humans sign in to. Conflating
    # them would give the deployment principal the console's identity.
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--dry-run")
    assert "phoenix-deploy-staging" in result.stdout
    assert "phoenix-console-staging" in result.stdout

    client_ids = re.findall(r"AZURE_CLIENT_ID --repo \S+ --env staging --body (\S+)", result.stdout)
    console_ids = re.findall(r"console app id (\S+)", result.stdout)
    assert client_ids and console_ids
    assert client_ids[0] != console_ids[0], "deployment and console apps must be different identities"
    assert "ENTRA_APPLICATION_CLIENT_ID" not in result.stdout
    assert "deployment_config input" in result.stdout


def test_bootstrap_wires_event_grid_secure_webhook_role_idempotently() -> None:
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--dry-run")

    assert "with 8 app roles" in result.stdout
    assert "AzureEventGridSecureWebhookSubscriber" in result.stdout
    assert "Microsoft.EventGrid" in result.stdout
    script = BOOTSTRAP.read_text(encoding="utf-8")
    assert 'EVENT_GRID_APP_ID="4962773b-9cdb-44cf-a8bf-237846a00ab7"' in script
    assert "appRoleAssignments" in script
    assert "length(value[?resourceId==" in script
    assert 'CONFIGURED_EVENT_GRID_ROLE_MEMBERS" = "Application"' in script
    assert 'CONFIGURED_EVENT_GRID_ROLE_ENABLED" = "true"' in script
    assert "deployment application" in script


def test_bootstrap_state_account_name_is_deterministic_and_valid() -> None:
    # Storage account names are globally unique and constrained to 3-24
    # lowercase alphanumerics. A non-deterministic name would create a new
    # account (and orphan the old state) on every re-run.
    outputs = [
        run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--dry-run").stdout for _ in range(2)
    ]
    names = [re.search(r"storage account: (\S+)", out).group(1) for out in outputs]  # type: ignore[union-attr]
    assert names[0] == names[1], "state account name is not stable across runs"
    assert re.fullmatch(r"[a-z0-9]{3,24}", names[0]), f"invalid storage account name: {names[0]}"


def test_bootstrap_state_account_differs_per_environment() -> None:
    def account(environment: str) -> str:
        out = run(
            BOOTSTRAP,
            "--subscription",
            FAKE_SUBSCRIPTION,
            "--repo",
            FAKE_REPO,
            "--environment",
            environment,
            "--dry-run",
        ).stdout
        return re.search(r"storage account: (\S+)", out).group(1)  # type: ignore[union-attr]

    assert account("staging") != account("production"), "staging and production would share Terraform state"


def test_mail_check_refuses_missing_resource_without_sending() -> None:
    result = run(MAIL_CHECK, "--resource-group", "rg-does-not-exist", "--to", "someone@example.com")
    # Cannot reach a real resource group, so it must fail cleanly rather than
    # attempting a send against nothing.
    assert result.returncode != 0
    assert "Sending one test message" not in result.stdout


def test_entra_graph_preflight_prints_only_reviewed_least_privilege_commands() -> None:
    result = run(
        ENTRA_GRAPH_PREFLIGHT,
        "--directory-client-id",
        "11111111-1111-4111-8111-111111111111",
        "--directory-principal-id",
        "22222222-2222-4222-8222-222222222222",
        "--mailbox-client-id",
        "33333333-3333-4333-8333-333333333333",
        "--mailbox-principal-id",
        "44444444-4444-4444-8444-444444444444",
        "--mailbox",
        "reports@example.com",
        "--group-id",
        "55555555-5555-4555-8555-555555555555",
        "--print-commands",
        expect=0,
    )
    assert "GroupMember.Read.All" in result.stdout
    assert "User.ReadBasic.All" in result.stdout
    assert "Application Mail.Read" in result.stdout
    assert "CustomResourceScope" in result.stdout
    assert "Do NOT also grant Entra/Microsoft Graph Mail.Read" in result.stdout
    assert "Commands printed only; no cloud command was executed" in result.stdout


def test_entra_graph_preflight_contract_never_claims_live_readiness() -> None:
    script = ENTRA_GRAPH_PREFLIGHT.read_text(encoding="utf-8")
    guide = (REPO_ROOT / "docs/AZURE_DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "not a live-readiness" in script
    assert "not resource-scoped enforcement" in script
    assert "Permissions are additive" in guide
    assert "Test-ServicePrincipalAuthorization" in guide


# --- preflight verdicts -----------------------------------------------------------


def test_preflight_blocks_on_an_unusable_tenant() -> None:
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION)
    # Exit 1 means "not ready" — it must not pass an unusable tenant.
    assert result.returncode == 1, result.stdout
    assert "blocking" in result.stdout


def test_preflight_json_is_machine_readable() -> None:
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION, "--json")
    payload = json.loads(result.stdout)
    assert payload["ready"] is False
    assert payload["failed"] > 0
    assert isinstance(payload["checks"], list)
    assert {"result", "check", "detail"} <= set(payload["checks"][0])


def test_preflight_checks_the_allowlist_variable_is_required() -> None:
    # An unset allowlist fails closed under OIDC: import and delivery are both
    # refused. Preflight has to treat it as blocking, not advisory.
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION, "--json")
    payload = json.loads(result.stdout)
    assert payload["ready"] is False
    assert any(check["check"] == "GUI values export" for check in payload["checks"])


def test_preflight_verifies_the_email_provider() -> None:
    # Simulated phishing must not leave from corporate mail, so the deployment
    # provisions its own sending domain. Preflight must confirm the tenant can.
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION)
    assert "Microsoft.Communication" in result.stdout
    assert "ACS live readiness" in result.stdout


def test_preflight_validates_gui_exported_acs_and_selected_provider_roles(tmp_path: Path) -> None:
    values = {
        "subscription_id": FAKE_SUBSCRIPTION,
        "entra_tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "entra_client_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        "acs_resource_mode": "provision",
        "acs_sending_domain": "simulation.example",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security awareness",
        "acs_daily_message_limit": 500,
        "acs_messages_per_minute": 25,
        "acs_ramp_batch_size": 5,
        "acs_ramp_interval_seconds": 60,
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
        "directory_group_ids": "11111111-1111-4111-8111-111111111111",
        "reported_mailbox_endpoint": "https://graph.microsoft.com/v1.0",
        "reported_mailbox_address": "reports@example.com",
        "reported_mailbox_folder": "inbox",
        "allowed_recipient_domains": "example.com",
    }
    export = tmp_path / "staging.auto.tfvars"
    export.write_text(
        "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )

    result = run(
        PREFLIGHT,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        FAKE_REPO,
        "--values-file",
        str(export),
        "--json",
    )
    assert result.returncode == 1  # The offline tenant/provider shim is intentionally unusable.
    checks = {check["check"]: check["result"] for check in json.loads(result.stdout)["checks"]}
    assert checks["GUI value contract"] == "pass"
    assert checks["customer ACS domain"] == "pass"
    assert checks["ACS pacing relationships"] == "pass"
    assert checks["directory worker role"] == "pass"
    assert checks["reported-mailbox worker role"] == "pass"


def test_preflight_existing_acs_endpoint_matches_gui_and_runtime_contract() -> None:
    script = PREFLIGHT.read_text(encoding="utf-8")
    assert r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?" in script
    assert r"\.communication\.azure\.com(?::443)?/?" in script


def test_preflight_exact_gui_export_excludes_server_internal_acs_evidence() -> None:
    script = PREFLIGHT.read_text(encoding="utf-8")
    exact_set = script[script.index("expected = {") : script.index("if set(values) == expected:")]
    for internal_field in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
        "acs_sender_username_status",
        "acs_domain_association_status",
        "acs_readiness_checked_at",
    ):
        assert internal_field not in exact_set


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    (
        ("https://name.communication.azure.com", "pass"),
        ("https://name.communication.azure.com:443/", "pass"),
        ("https://nested.name.communication.azure.com", "fail"),
        ("https://name.communication.azure.com:444", "fail"),
        ("https://-name.communication.azure.com", "fail"),
        ("https://name-.communication.azure.com", "fail"),
    ),
)
def test_preflight_enforces_exact_existing_acs_endpoint(
    tmp_path: Path,
    endpoint: str,
    expected: str,
) -> None:
    values = {
        "subscription_id": FAKE_SUBSCRIPTION,
        "entra_tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "entra_client_id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        "acs_resource_mode": "existing",
        "acs_existing_communication_service_id": (
            f"/subscriptions/{FAKE_SUBSCRIPTION}/resourceGroups/rg-acs/providers/"
            "Microsoft.Communication/CommunicationServices/acs-existing"
        ),
        "acs_existing_email_endpoint": endpoint,
        "acs_existing_email_domain_id": (
            f"/subscriptions/{FAKE_SUBSCRIPTION}/resourceGroups/rg-acs/providers/"
            "Microsoft.Communication/emailServices/email-existing/domains/simulation.example"
        ),
        "acs_sending_domain": "simulation.example",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security awareness",
        "acs_daily_message_limit": 500,
        "acs_messages_per_minute": 25,
        "acs_ramp_batch_size": 5,
        "acs_ramp_interval_seconds": 60,
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
        "directory_group_ids": "11111111-1111-4111-8111-111111111111",
        "reported_mailbox_endpoint": "https://graph.microsoft.com/v1.0",
        "reported_mailbox_address": "reports@example.com",
        "reported_mailbox_folder": "inbox",
        "allowed_recipient_domains": "example.com",
    }
    export = tmp_path / "staging.auto.tfvars"
    export.write_text(
        "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items()) + "\n",
        encoding="utf-8",
    )

    result = run(
        PREFLIGHT,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        FAKE_REPO,
        "--values-file",
        str(export),
        "--json",
    )
    checks = {check["check"]: check["result"] for check in json.loads(result.stdout)["checks"]}
    assert checks["ACS resource mode"] == expected


# --- the deployment workflow ------------------------------------------------------


def test_workflow_refuses_starter_mode_for_production() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    assert "inputs.environment == 'production' && inputs.network_mode == 'starter'" in workflow
    assert "exit 1" in workflow


def test_workflow_builds_images_without_a_docker_daemon() -> None:
    # az acr build runs inside the registry, which is what lets a hosted runner
    # deploy a tenant that has no VNet runner yet.
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    assert "az acr build" in workflow
    assert "docker build" not in workflow


def test_workflow_materializes_reviewed_send_safety_values_for_terraform() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    assert "REVIEWED_DEPLOYMENT_CONFIG: ${{ inputs.deployment_config }}" in workflow
    assert '"allowed_recipient_domains"' in workflow
    assert "reviewed deployment configuration has an invalid key contract" in workflow
    assert "reviewed deployment configuration must not contain credentials or tokens" in workflow
    assert 'target = Path(os.environ["RUNNER_TEMP"]) / "reviewed.auto.tfvars.json"' in workflow
    assert workflow.count('-var-file="$RUNNER_TEMP/reviewed.auto.tfvars.json"') == 4
    assert "DEPLOYMENT_NETWORK_MODE: ${{ inputs.network_mode }}" in workflow
    assert '-var="network_mode=$DEPLOYMENT_NETWORK_MODE"' in workflow
    assert "TF_VAR_allowed_recipient_domains" not in workflow


def test_workflow_propagates_native_graph_role_configuration_without_tokens() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    for name in (
        "enable_directory_sync",
        "enable_reported_mailbox",
        '"directory_group_ids"',
        '"reported_mailbox_address"',
        '"reported_mailbox_folder"',
        'config.pop("enable_directory_sync")',
        'config.pop("enable_reported_mailbox")',
    ):
        assert name in workflow
    assert workflow.count("https://graph.microsoft.com/v1.0") == 2
    assert "GRAPH_BEARER_TOKEN" not in workflow
    assert "REPORTED_MAILBOX_BEARER_TOKEN" not in workflow


def test_terraform_pins_enforce_policy_for_azure() -> None:
    # Azure runs under OIDC, where the operator API refuses to start with the
    # single-admin policy. Without this pin every deployment crash-loops.
    main_tf = (REPO_ROOT / "infrastructure/terraform/main.tf").read_text(encoding="utf-8")
    assert "OPERATOR_APPROVAL_POLICY" in main_tf
    assert '"enforce"' in main_tf


def test_terraform_requires_a_recipient_allowlist() -> None:
    variables = (REPO_ROOT / "infrastructure/terraform/variables.tf").read_text(encoding="utf-8")
    assert "allowed_recipient_domains" in variables
    assert "length(trimspace(var.allowed_recipient_domains)) > 0" in variables


def test_terraform_requires_customer_managed_acs_domain_readiness() -> None:
    main_tf = (REPO_ROOT / "infrastructure/terraform/main.tf").read_text(encoding="utf-8")
    assert 'domain_management                = "CustomerManaged"' in main_tf
    assert "AzureManagedDomain" not in main_tf
    assert "acs_readiness_current" in main_tf
    assert "acs_domain_verification_status" in main_tf
    assert "acs_spf_verification_status" in main_tf
    assert "acs_dkim2_verification_status" in main_tf
    assert "user_engagement_tracking_enabled = false" in main_tf


def test_workflow_requires_nonsecret_acs_readiness_inputs() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    for name in (
        '"acs_resource_mode"',
        '"acs_sending_domain"',
        '"acs_sender_local_part"',
        '"acs_domain_verification_status"',
        '"acs_readiness_checked_at"',
        '"acs_daily_message_limit"',
    ):
        assert name in workflow
    assert "ACS_CONNECTION_STRING" not in workflow


def test_workflow_three_stage_acs_plans_are_allowlisted_and_create_update_only() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")

    bootstrap_plan = workflow.index("- name: Plan ACS foundation bootstrap")
    bootstrap_guard = workflow.index("- name: Enforce ACS foundation bootstrap plan allowlist")
    bootstrap_apply = workflow.index("- name: Apply ACS foundation bootstrap")
    finalize_plan = workflow.index("- name: Plan ACS foundation finalize")
    finalize_guard = workflow.index("- name: Enforce ACS foundation finalize plan allowlist")
    finalize_apply = workflow.index("- name: Apply ACS foundation finalize")
    workload_plan = workflow.index("- name: Plan workloads")
    workload_guard = workflow.index("- name: Refuse destructive workload changes")
    workload_apply = workflow.index("- name: Apply workloads")
    assert bootstrap_plan < bootstrap_guard < bootstrap_apply < finalize_plan
    assert finalize_plan < finalize_guard < finalize_apply < workload_plan
    assert workload_plan < workload_guard < workload_apply

    bootstrap = workflow[bootstrap_plan:finalize_plan]
    assert "terraform plan -out=foundation-bootstrap.tfplan" in bootstrap
    assert '["terraform", "show", "-json", "foundation-bootstrap.tfplan"]' in bootstrap
    assert "foundation bootstrap is create/update-only and refuses deletes or replacements" in bootstrap
    assert "Bootstrap the complete non-workload foundation" in bootstrap
    assert "fresh deployment in an unrecoverable ACR-before-create blind alley" in bootstrap
    assert "-target=" not in bootstrap
    assert "foundation bootstrap must not create an ACS association or sender username" in bootstrap
    assert "terraform apply -auto-approve foundation-bootstrap.tfplan" in bootstrap
    assert '-var="acs_deployment_stage=foundation_bootstrap"' in bootstrap

    finalize = workflow[finalize_plan:workload_plan]
    assert "terraform plan -out=foundation-finalize.tfplan" in finalize
    assert '["terraform", "show", "-json", "foundation-finalize.tfplan"]' in finalize
    assert "foundation finalize is create/update-only and refuses deletes or replacements" in finalize
    assert "foundation finalize plan contains unrelated changes" in finalize
    assert "terraform apply -auto-approve foundation-finalize.tfplan" in finalize
    assert '-var="acs_deployment_stage=foundation_finalize"' in finalize

    workloads = workflow[workload_plan:]
    assert '-var="deploy_workloads=true"' in workloads
    assert '-var="deploy_workloads=false"' not in workloads
    assert '["terraform", "show", "-json", "release.tfplan"]' in workloads
    assert 'if "delete" in change.get("change", {}).get("actions", [])' in workloads
    assert "workloads phase is create/update-only and refuses deletes or replacements" in workloads
    assert "terraform apply -auto-approve release.tfplan" in workloads
    assert '-var="acs_deployment_stage=workloads"' in workloads
    assert workflow.count('-var="deploy_workloads=false"') == 2


def test_workflow_records_disk_headroom_before_qualification_and_never_auto_cleans() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    qualify = workflow[workflow.index("  qualify:") : workflow.index("  guard:")]

    disk_preflight = qualify.index("- name: Record runner disk headroom before qualification")
    checkout = qualify.index("- name: Check out source")
    dependencies = qualify.index("uv sync --frozen --all-packages")
    images = qualify.index("make verify-images")
    assert disk_preflight < checkout < dependencies < images
    assert "minimum_free_bytes = 10 * 1024**3" in qualify
    assert '"free_bytes": free_bytes' in qualify
    assert '"automatic_cleanup_allowed": False' in qualify
    assert '"mutation_performed": False' in qualify
    assert "runner disk headroom is below the required 10 GiB; no cleanup was attempted" in qualify
    assert "do not prune project images, caches, or evidence" in qualify

    artifact = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2"
    assert artifact in qualify
    upload = qualify[qualify.index("- name: Upload qualification recovery evidence") :]
    assert "if: always()" in upload
    assert "if-no-files-found: error" in upload


def test_workflow_recovery_ledger_is_correlated_append_only_and_tamper_evident() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    deploy = workflow[workflow.index("  deploy:") :]
    helper = deploy[
        deploy.index("- name: Initialize append-only deployment checkpoint") : deploy.index("- name: Check out source")
    ]

    for field in (
        '"schema": SCHEMA',
        '"sequence": len(records) + 1',
        '"deployment_request_id"',
        '"reviewed_commit_sha"',
        '"environment"',
        '"phase"',
        '"network_mode"',
        '"run_id"',
        '"run_attempt"',
        '"state_identity"',
        '"safe_next_action"',
        '"previous_record_sha256"',
        'record["record_sha256"]',
    ):
        assert field in helper
    assert 'SCHEMA = "kp.azure-deployment-checkpoint.v1"' in helper
    assert 'with path.open("a", encoding="utf-8")' in helper
    assert "checkpoint ledger integrity validation failed" in helper
    assert "checkpoint ledger correlation changed during the workflow" in helper
    assert "checkpoint ledger Terraform state identity changed during the workflow" in helper
    assert "checkpoint ledger workflow run identity changed during the workflow" in helper
    assert "checkpoint stage was already recorded for this workflow run" in helper
    assert 'evidence["last_successful_stage"]' in helper
    assert "MAX_LEDGER_BYTES = 1_048_576" in helper
    assert "MAX_RECORDS = 64" in helper
    assert "TF_STATE_RESOURCE_GROUP" in helper
    assert 'f"{environment}/kingphisher.tfstate"' in helper

    # The evidence helper can consume only normalized results and immutable
    # digests. It never reads reviewed configuration or credential material.
    assert "REVIEWED_DEPLOYMENT_CONFIG" not in helper
    assert "deployment_config" not in helper
    assert "AZURE_CLIENT_ID" not in helper
    assert "AZURE_TENANT_ID" not in helper
    assert "access_token" not in helper


def test_embedded_checkpoint_helper_compiles_and_enforces_ledger_integrity(tmp_path: Path) -> None:
    helper = tmp_path / "append-deployment-checkpoint.py"
    helper.write_text(embedded_checkpoint_helper(), encoding="utf-8")
    compile(helper.read_text(encoding="utf-8"), str(helper), "exec")
    ledger = tmp_path / "checkpoints.ndjson"
    environment = {
        **os.environ,
        "DEPLOYMENT_REQUEST_ID": f"kp-{'a' * 32}-1",
        "REVIEWED_COMMIT_SHA": "b" * 40,
        "DEPLOYMENT_ENVIRONMENT": "staging",
        "DEPLOYMENT_PHASE": "workloads",
        "DEPLOYMENT_NETWORK_MODE": "private",
        "TF_STATE_RESOURCE_GROUP": "kp-tfstate-staging",
        "TF_STATE_STORAGE_ACCOUNT": "kptfstatestaging",
        "TF_STATE_CONTAINER": "tfstate",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "KP_DEPLOYMENT_EVIDENCE_FILE": str(ledger),
    }

    def append(stage: str, *, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, str(helper), "--stage", stage, "--status", "passed"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={**environment, **(extra or {})},
        )

    assert append("reviewed_configuration").returncode == 0
    duplicate = append("reviewed_configuration")
    assert duplicate.returncode != 0
    assert "already recorded" in duplicate.stderr
    digests = {
        "KP_OPERATOR_API_DIGEST": f"sha256:{'1' * 64}",
        "KP_TRACKING_API_DIGEST": f"sha256:{'2' * 64}",
        "KP_WORKER_DIGEST": f"sha256:{'3' * 64}",
        "KP_MIGRATION_DIGEST": f"sha256:{'4' * 64}",
        "KP_AI_GATEWAY_DIGEST": f"sha256:{'5' * 64}",
    }
    assert append("immutable_images_verified", extra=digests).returncode == 0
    assert (
        append(
            "migration_health_passed",
            extra={"KP_MIGRATION_RESULT": "passed", "KP_HEALTH_RESULT": "passed"},
        ).returncode
        == 0
    )

    records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    assert [record["sequence"] for record in records] == [1, 2, 3]
    assert records[1]["previous_record_sha256"] == records[0]["record_sha256"]
    assert records[2]["evidence"]["image_digests"]["migration"] == digests["KP_MIGRATION_DIGEST"]
    assert records[2]["evidence"]["image_digests"]["ai_gateway"] == digests["KP_AI_GATEWAY_DIGEST"]
    assert records[2]["evidence"]["migration_result"] == "passed"
    assert records[2]["evidence"]["health_result"] == "passed"
    for record in records:
        supplied = record.pop("record_sha256")
        canonical = json.dumps(record, separators=(",", ":"), sort_keys=True)
        assert supplied == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        record["record_sha256"] = supplied

    records[0]["status"] = "uncertain"
    ledger.write_text(
        "\n".join(json.dumps(record, separators=(",", ":"), sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    tampered = append("cloud_operations_complete")
    assert tampered.returncode != 0
    assert "integrity validation failed" in tampered.stderr


def test_workflow_checkpoints_major_stages_and_always_uploads_uncertain_runs() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    deploy = workflow[workflow.index("  deploy:") :]

    stages = (
        "runner_preflight",
        "reviewed_configuration",
        "azure_authenticated",
        "terraform_state_initialized",
        "foundation_bootstrap_plan_safe",
        "foundation_bootstrap_applied",
        "bootstrap_integration_plan_published",
        "acs_verification_initiated",
        "foundation_finalize_plan_safe",
        "foundation_finalize_applied",
        "foundation_finalize_readback",
        "acs_stage_result_recorded",
        "immutable_images_verified",
        "workload_plan_safe",
        "workloads_applied",
        "migration_health_passed",
        "receipt_plan_safe",
        "receipts_activated",
        "cloud_operations_complete",
        "workflow_interrupted",
    )
    for stage in stages:
        assert f"--stage {stage}" in deploy

    summarize = deploy.index("- name: Summarize")
    credential_cleanup = deploy.index("- name: Remove ephemeral registry credentials")
    completed = deploy.index("- name: Record completed cloud operations")
    interrupted = deploy.index("- name: Preserve interrupted cloud operation checkpoint")
    upload = deploy.index("- name: Upload append-only deployment recovery evidence")
    assert credential_cleanup < summarize < completed < interrupted < upload
    summary = deploy[summarize:completed]
    assert "CURRENT_JOB_STATUS: ${{ job.status }}" in summary
    assert "Interrupted; reconcile the correlation checkpoint before any retry" in summary
    completion = deploy[completed:interrupted]
    assert "if: success()" in completion
    assert "--stage cloud_operations_complete --status passed" in completion
    recovery = deploy[interrupted:upload]
    assert "if: always() && job.status != 'success'" in recovery
    assert "--stage workflow_interrupted --status uncertain" in recovery
    assert "automatic retry is blocked" in recovery
    uploaded = deploy[upload:]
    assert "if: always()" in uploaded
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2" in uploaded
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in uploaded
    assert "if-no-files-found: error" in uploaded
    assert "retention-days: 90" in uploaded
    assert deploy.rstrip().endswith("retention-days: 90")


def test_workflow_checkpoint_preserves_digests_migration_health_and_safe_recovery() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    deploy = workflow[workflow.index("  deploy:") :]

    image_checkpoint = deploy[
        deploy.index("- name: Checkpoint verified immutable images") : deploy.index("- name: Plan workloads")
    ]
    for output in (
        "operator_api_digest",
        "tracking_api_digest",
        "worker_digest",
        "migration_digest",
    ):
        assert f"steps.images.outputs.{output}" in image_checkpoint
    assert 're.fullmatch(r"sha256:[0-9a-f]{64}", value)' in deploy

    migration_checkpoint = deploy[
        deploy.index("- name: Checkpoint migration and health qualification") : deploy.index(
            "- name: Plan ACS receipt subscription activation"
        )
    ]
    assert "KP_MIGRATION_RESULT: passed" in migration_checkpoint
    assert "KP_HEALTH_RESULT: passed" in migration_checkpoint
    assert 'for key in ("image_digests", "migration_result", "health_result")' in deploy
    assert "Reconcile this correlation ID with Terraform and Azure state before retrying" in deploy
    assert "do not destroy, delete, or recreate resources" in deploy
    assert "Cloud operations completed; do not automatically retry" in deploy


def test_workflow_has_no_automated_project_or_cloud_cleanup_commands() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")

    forbidden_commands = (
        r"(?m)^\s*docker\s+(?:builder\s+)?prune\b",
        r"(?m)^\s*docker\s+compose\s+down\b",
        r"(?m)^\s*terraform\s+destroy\b",
        r"(?m)^\s*az\s+\S+(?:\s+\S+)*\s+delete\b",
        r"(?m)^\s*git\s+(?:clean|reset)\b",
    )
    assert not any(re.search(pattern, workflow) for pattern in forbidden_commands)


def test_workflow_activates_acs_receipts_only_after_migration_and_readiness() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")

    workload_plan = workflow.index("- name: Plan workloads")
    qualification = workflow.index("- name: Migrate and qualify")
    activation_plan = workflow.index("- name: Plan ACS receipt subscription activation")
    activation_apply = workflow.index("- name: Activate ACS receipt subscription after readiness")
    assert workload_plan < qualification < activation_plan < activation_apply
    initial_deploy = workflow[workload_plan:qualification]
    assert "enable_acs_event_subscription=false" in initial_deploy
    assert "terraform apply -auto-approve release.tfplan" in initial_deploy
    assert "enable_acs_event_subscription=true" in workflow
    assert "azurerm_eventgrid_system_topic_event_subscription.acs_delivery[0]" in workflow
    assert "receipt activation plan contains unrelated changes" in workflow
    assert "receipt activation plan did not create the Event Grid subscription" in workflow
    assert "./scripts/azure_release.sh" in workflow[:activation_plan]


def test_qualification_workflow_has_real_release_gates() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    assert "make security-scan" in workflow
    assert "terraform init -backend=false" in workflow
    assert "terraform validate" in workflow
    assert "make test" in workflow
    assert "make test-postgres" in workflow
    assert "make test-redis" in workflow
    assert "make test-fresh-migration" in workflow
    assert "make verify-images" in workflow
    assert "make security-scan-images" in workflow
    assert "make test-contract" not in workflow
    assert "integration-gate.sh" not in workflow
    assert "postgres:" in workflow
    assert "redis:" in workflow

    qualify_environment = workflow.split("    env:\n", maxsplit=1)[1].split("    services:\n", maxsplit=1)[0]
    assert "DATABASE_URL_TEST:" in qualify_environment
    assert "AUDIT_DATABASE_URL_TEST:" in qualify_environment
    assert "REDIS_URL_POSTGRES_TEST: redis://127.0.0.1:6379/14" in qualify_environment
    assert "\n      DATABASE_URL:" not in qualify_environment
    assert "\n      REDIS_URL:" not in qualify_environment

    migration_step = workflow.split("      - name: Prepare required database roles and schema\n", maxsplit=1)[1]
    migration_step = migration_step.split("      - name: Required PostgreSQL integration gate\n", maxsplit=1)[0]
    assert "DATABASE_URL:" in migration_step
    postgres_step = workflow.split("      - name: Required PostgreSQL integration gate\n", maxsplit=1)[1]
    postgres_step = postgres_step.split("      - name: Required Redis integration gate\n", maxsplit=1)[0]
    assert "DATABASE_URL:" not in postgres_step
    redis_step = workflow.split("      - name: Required Redis integration gate\n", maxsplit=1)[1]
    redis_step = redis_step.split("      - name: Required fresh-migration gate\n", maxsplit=1)[0]
    assert "REDIS_URL_TEST: redis://127.0.0.1:6379/15" in redis_step


@pytest.mark.azure_live
def test_live_azure_cli_can_read_selected_subscription() -> None:
    """Opt-in, read-only smoke test for a real authenticated Azure session."""
    if os.getenv("KP_RUN_AZURE_LIVE") != "1":
        pytest.skip("set KP_RUN_AZURE_LIVE=1 to run the read-only Azure smoke test")
    subscription = os.getenv("AZURE_SUBSCRIPTION_ID", "").strip()
    assert subscription, "AZURE_SUBSCRIPTION_ID is required when KP_RUN_AZURE_LIVE=1"
    try:
        result = subprocess.run(  # noqa: S603
            ["az", "account", "show", "--subscription", subscription, "--output", "json"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError:
        pytest.fail("Azure CLI is required when KP_RUN_AZURE_LIVE=1")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload.get("id") == subscription
