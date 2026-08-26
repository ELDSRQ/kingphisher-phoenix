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

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
BOOTSTRAP = SCRIPTS / "azure_bootstrap.sh"
PREFLIGHT = SCRIPTS / "azure_preflight.sh"
MAIL_CHECK = SCRIPTS / "azure_mail_check.sh"

FAKE_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
FAKE_REPO = "example-org/example-repo"

requires_az = pytest.mark.skipif(shutil.which("az") is None, reason="azure cli not installed")


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


@pytest.mark.parametrize("script", [BOOTSTRAP, PREFLIGHT, MAIL_CHECK], ids=lambda p: p.name)
def test_script_is_syntactically_valid(script: Path) -> None:
    assert script.exists(), f"{script} is missing"
    subprocess.run(["bash", "-n", str(script)], check=True, capture_output=True, timeout=60)  # noqa: S603, S607


@pytest.mark.parametrize("script", [BOOTSTRAP, PREFLIGHT, MAIL_CHECK], ids=lambda p: p.name)
def test_script_is_executable(script: Path) -> None:
    # Documented as `scripts/foo.sh`, so it has to actually run that way.
    assert os.access(script, os.X_OK), f"{script} is not executable"


@pytest.mark.parametrize("script", [BOOTSTRAP, PREFLIGHT, MAIL_CHECK], ids=lambda p: p.name)
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


@pytest.mark.parametrize("bad", ["notanemail", "missing-at.example.com", "@example.com"])
def test_mail_check_rejects_malformed_recipients(bad: str) -> None:
    # This script sends real mail. A malformed address must fail loudly before
    # anything is dispatched.
    result = run(MAIL_CHECK, "--resource-group", "rg-example", "--to", bad)
    assert result.returncode == 2
    assert "email address" in result.stderr


# --- dry-run behaviour ------------------------------------------------------------


@requires_az
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


@requires_az
def test_bootstrap_dry_run_creates_two_distinct_applications() -> None:
    # One identity deploys, a different one is what humans sign in to. Conflating
    # them would give the deployment principal the console's identity.
    result = run(BOOTSTRAP, "--subscription", FAKE_SUBSCRIPTION, "--repo", FAKE_REPO, "--dry-run")
    assert "phoenix-deploy-staging" in result.stdout
    assert "phoenix-console-staging" in result.stdout

    client_ids = re.findall(r"AZURE_CLIENT_ID --repo \S+ --body (\S+)", result.stdout)
    console_ids = re.findall(r"ENTRA_APPLICATION_CLIENT_ID --repo \S+ --body (\S+)", result.stdout)
    assert client_ids and console_ids
    assert client_ids[0] != console_ids[0], "deployment and console apps must be different identities"


@requires_az
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


@requires_az
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


@requires_az
def test_mail_check_dry_run_sends_nothing() -> None:
    result = run(MAIL_CHECK, "--resource-group", "rg-does-not-exist", "--to", "someone@example.com")
    # Cannot reach a real resource group, so it must fail cleanly rather than
    # attempting a send against nothing.
    assert result.returncode != 0
    assert "Sending one test message" not in result.stdout


# --- preflight verdicts -----------------------------------------------------------


@requires_az
def test_preflight_blocks_on_an_unusable_tenant() -> None:
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION)
    # Exit 1 means "not ready" — it must not pass an unusable tenant.
    assert result.returncode == 1, result.stdout
    assert "blocking" in result.stdout


@requires_az
def test_preflight_json_is_machine_readable() -> None:
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION, "--json")
    payload = json.loads(result.stdout)
    assert payload["ready"] is False
    assert payload["failed"] > 0
    assert isinstance(payload["checks"], list)
    assert {"result", "check", "detail"} <= set(payload["checks"][0])


@requires_az
def test_preflight_checks_the_allowlist_variable_is_required() -> None:
    # An unset allowlist fails closed under OIDC: import and delivery are both
    # refused. Preflight has to treat it as blocking, not advisory.
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION, "--json")
    text = result.stdout
    assert "ALLOWED_RECIPIENT_DOMAINS" in text or "communication provider" in text


@requires_az
def test_preflight_verifies_the_email_provider() -> None:
    # Simulated phishing must not leave from corporate mail, so the deployment
    # provisions its own sending domain. Preflight must confirm the tenant can.
    result = run(PREFLIGHT, "--subscription", FAKE_SUBSCRIPTION)
    assert "Microsoft.Communication" in result.stdout
    assert "sending domain" in result.stdout or "communication provider" in result.stdout


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


def test_workflow_passes_the_required_send_safety_variables() -> None:
    workflow = (REPO_ROOT / ".github/workflows/azure-deploy.yml").read_text(encoding="utf-8")
    assert "TF_VAR_allowed_recipient_domains" in workflow
    assert "TF_VAR_network_mode" in workflow


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


def test_terraform_sends_from_its_own_managed_domain() -> None:
    # The sender must be the ACS domain, not corporate email: simulations go out
    # externally from a domain provisioned for exactly this purpose.
    main_tf = (REPO_ROOT / "infrastructure/terraform/main.tf").read_text(encoding="utf-8")
    assert 'domain_management                = "AzureManaged"' in main_tf
    assert "from_sender_domain" in main_tf
    assert "user_engagement_tracking_enabled = false" in main_tf
