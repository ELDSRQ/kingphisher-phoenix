"""Offline contracts for authenticated ACS deployment readiness evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "azure-deploy.yml"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
SUBSCRIPTION_ID = "11111111-2222-3333-4444-555555555555"
TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RESOURCE_GROUP = "rg-kingphisher-staging"
COMMUNICATION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
    "Microsoft.Communication/CommunicationServices/acs-kingphisher-staging"
)
EMAIL_SERVICE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
    "Microsoft.Communication/EmailServices/email-kingphisher-staging"
)
DOMAIN_ID = f"{EMAIL_SERVICE_ID}/domains/phish.example.com"
SENDER_ID = f"{DOMAIN_ID}/senderUsernames/awareness"


def embedded_live_readiness_program() -> str:
    """Extract Python exactly as Actions removes the run scalar indentation."""

    start = WORKFLOW.index("- name: Read ACS readiness from the authenticated Azure control plane")
    end = WORKFLOW.index("- name: Checkpoint live ACS control-plane observation", start)
    block = WORKFLOW[start:end]
    match = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", block, flags=re.DOTALL)
    assert match is not None
    lines = match.group(1).splitlines()
    return "\n".join(line[10:] if line.startswith(" " * 10) else line for line in lines)


def reviewed_config() -> dict[str, str]:
    """Return the subset consumed by the isolated live-readback program."""

    return {
        "acs_resource_mode": "existing",
        "acs_existing_communication_service_id": COMMUNICATION_ID,
        "acs_existing_email_endpoint": "https://acs-kingphisher-staging.communication.azure.com",
        "acs_existing_email_domain_id": DOMAIN_ID,
        "acs_sending_domain": "phish.example.com",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security Awareness",
        "communication_data_location": "United States",
        # These deliberately claim readiness. Offline Azure responses, not
        # these values, must determine whether the program succeeds.
        "acs_domain_verification_status": "verified",
        "acs_spf_verification_status": "verified",
        "acs_dkim_verification_status": "verified",
        "acs_dkim2_verification_status": "verified",
        "acs_sender_username_status": "verified",
        "acs_domain_association_status": "verified",
        "acs_readiness_checked_at": "2099-01-01T00:00:00Z",
    }


@pytest.fixture
def offline_live_readiness(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    program = tmp_path / "acs-live-readiness.py"
    program.write_text(embedded_live_readiness_program(), encoding="utf-8")
    compile(program.read_text(encoding="utf-8"), str(program), "exec")

    cli_dir = tmp_path / "cli"
    cli_dir.mkdir()
    fake_az = cli_dir / "az"
    fake_az.write_text(
        f"""#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
status = os.environ.get("FAKE_ACS_VERIFICATION", "Verified")
if args[:2] == ["account", "show"]:
    value = {{"subscriptionId": "{SUBSCRIPTION_ID}", "tenantId": "{TENANT_ID}"}}
elif args[:2] == ["rest", "--method"]:
    uri = args[args.index("--uri") + 1].split("?", 1)[0]
    if uri.endswith("{SENDER_ID}"):
        value = {{
            "id": "{SENDER_ID}",
            "type": "Microsoft.Communication/EmailServices/Domains/SenderUsernames",
            "username": "awareness",
            "displayName": "Security Awareness",
        }}
        sender_data_location = os.environ.get("FAKE_ACS_SENDER_DATA_LOCATION", "United States")
        if sender_data_location == "NULL":
            value["dataLocation"] = None
        elif sender_data_location != "OMIT":
            value["dataLocation"] = sender_data_location
        sender_state = os.environ.get("FAKE_ACS_SENDER_STATE", "Succeeded")
        if sender_state == "NULL":
            value["provisioningState"] = None
        elif sender_state != "OMIT":
            value["provisioningState"] = sender_state
    elif uri.endswith("{DOMAIN_ID}"):
        value = {{
            "id": "{DOMAIN_ID}",
            "type": "Microsoft.Communication/EmailServices/Domains",
            "provisioningState": "Succeeded",
            "domainManagement": "CustomerManaged",
            "fromSenderDomain": "phish.example.com",
            "Domain": status,
            "SPF": status,
            "DKIM": status,
            "DKIM2": status,
            "dataLocation": "United States",
        }}
    elif uri.endswith("{EMAIL_SERVICE_ID}"):
        value = {{
            "id": "{EMAIL_SERVICE_ID}",
            "type": "Microsoft.Communication/EmailServices",
            "provisioningState": "Succeeded",
            "dataLocation": "United States",
        }}
    elif uri.endswith("{COMMUNICATION_ID}"):
        value = {{
            "id": "{COMMUNICATION_ID}",
            "type": "Microsoft.Communication/CommunicationServices",
            "provisioningState": "Succeeded",
            "linkedDomains": ["{DOMAIN_ID}"],
            "hostName": "acs-kingphisher-staging.communication.azure.com",
            "dataLocation": "United States",
        }}
    else:
        raise SystemExit(3)
else:
    raise SystemExit(2)
print(json.dumps(value, separators=(",", ":"), sort_keys=True))
""",
        encoding="utf-8",
    )
    fake_az.chmod(0o700)

    evidence_dir = tmp_path / "deployment-evidence"
    evidence_dir.mkdir()
    (tmp_path / "reviewed.auto.tfvars.json").write_text(
        json.dumps(reviewed_config(), separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    github_environment = tmp_path / "github.env"
    github_environment.touch()
    environment = {
        **os.environ,
        "PATH": f"{cli_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_ENV": str(github_environment),
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "DEPLOYMENT_ENVIRONMENT": "staging",
        "DEPLOYMENT_PHASE": "workloads",
        "PROTECTED_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
        "PROTECTED_TENANT_ID": TENANT_ID,
        "REVIEWED_COMMIT_SHA": "b" * 40,
        "KP_REVIEWED_DEPLOYMENT_DIGEST": f"sha256:{'a' * 64}",
    }
    return program, environment


def run_program(program: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(program)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_live_readback_is_after_oidc_login_and_before_every_plan() -> None:
    deploy = WORKFLOW[WORKFLOW.index("  deploy:") :]
    login = deploy.index("uses: azure/login@")
    live_readback = deploy.index("- name: Read ACS readiness from the authenticated Azure control plane")
    first_plan = deploy.index("terraform plan")
    assert login < live_readback < first_plan
    assert (
        "if: inputs.deployment_phase == 'workloads'"
        not in deploy[
            live_readback : deploy.index("- name: Checkpoint live ACS control-plane observation", live_readback)
        ]
    )


def test_reviewed_status_strings_are_neutralized_before_terraform() -> None:
    materialize = WORKFLOW[
        WORKFLOW.index("- name: Validate and materialize reviewed deployment values") : WORKFLOW.index(
            "- name: Checkpoint reviewed configuration"
        )
    ]
    assert 'config[key] = "pending_live_readback"' in materialize
    assert 'config["acs_readiness_checked_at"] = ""' in materialize
    assert "workloads require verified ACS" not in materialize
    assert "datetime.fromisoformat" not in materialize


def test_workflow_queries_bounded_exact_resources_and_binds_evidence() -> None:
    program = embedded_live_readiness_program()
    for contract in (
        '"az", "account", "show"',
        '"az", "rest", "--method", "get"',
        "MAX_CONTROL_PLANE_BYTES = 65_536",
        '"communication_service_id"',
        '"email_service_id"',
        '"email_domain_id"',
        '"sender_username_id"',
        '"reviewed_commit_sha": reviewed_commit',
        '"reviewed_deployment_digest": reviewed_digest',
        '"subscription_id": subscription_id',
        '"tenant_id": tenant_id',
        '"inbox_placement_proven": False',
        '"event_grid_delivery_proven": False',
        '"human_mailbox_validation_proven": False',
    ):
        assert contract in program
    assert "result.stderr" not in program
    assert "print(result." not in program


def test_operator_entered_verified_values_cannot_unlock_failed_live_state(
    offline_live_readiness: tuple[Path, dict[str, str]],
) -> None:
    program, environment = offline_live_readiness
    result = run_program(program, {**environment, "FAKE_ACS_VERIFICATION": "VerificationFailed"})
    assert result.returncode != 0
    assert "finalize and workloads require live Verified Domain, SPF, DKIM, and DKIM2 states" in result.stderr
    assert not (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-live-readiness.json").exists()


def test_verified_live_state_replaces_input_and_emits_bound_digest(
    offline_live_readiness: tuple[Path, dict[str, str]],
) -> None:
    program, environment = offline_live_readiness
    before = datetime.now(UTC)
    result = run_program(program, {**environment, "FAKE_ACS_VERIFICATION": "Verified"})
    assert result.returncode == 0, result.stdout + result.stderr

    runner_temp = Path(environment["RUNNER_TEMP"])
    rewritten = json.loads((runner_temp / "reviewed.auto.tfvars.json").read_text(encoding="utf-8"))
    for key in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
        "acs_sender_username_status",
        "acs_domain_association_status",
    ):
        assert rewritten[key] == "verified"
    observed = datetime.fromisoformat(rewritten["acs_readiness_checked_at"].replace("Z", "+00:00"))
    assert before <= observed <= datetime.now(UTC)

    evidence_path = runner_temp / "deployment-evidence" / "acs-live-readiness.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["result"] == "workloads_verified"
    assert evidence["resource_ids"] == {
        "communication_service_id": COMMUNICATION_ID,
        "email_service_id": EMAIL_SERVICE_ID,
        "email_domain_id": DOMAIN_ID,
        "sender_username_id": SENDER_ID,
    }
    assert evidence["reviewed_commit_sha"] == "b" * 40
    assert evidence["reviewed_deployment_digest"] == f"sha256:{'a' * 64}"
    supplied_digest = evidence.pop("evidence_digest")
    canonical = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
    assert supplied_digest == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert f"KP_ACS_LIVE_READINESS_DIGEST={supplied_digest}" in Path(environment["GITHUB_ENV"]).read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("sender_state", ["OMIT", "NULL"])
def test_valid_sender_with_optional_unreported_provisioning_state_is_accepted(
    offline_live_readiness: tuple[Path, dict[str, str]],
    sender_state: str,
) -> None:
    program, environment = offline_live_readiness
    result = run_program(program, {**environment, "FAKE_ACS_SENDER_STATE": sender_state})
    assert result.returncode == 0, result.stdout + result.stderr


def test_explicit_failed_sender_provisioning_state_blocks_workloads(
    offline_live_readiness: tuple[Path, dict[str, str]],
) -> None:
    program, environment = offline_live_readiness
    result = run_program(program, {**environment, "FAKE_ACS_SENDER_STATE": "Failed"})
    assert result.returncode != 0
    assert "sender username is not in a ready provisioning state" in result.stderr
    assert not (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-live-readiness.json").exists()


@pytest.mark.parametrize("sender_data_location", ["OMIT", "NULL"])
def test_optional_unreported_sender_data_location_uses_validated_parent_locations(
    offline_live_readiness: tuple[Path, dict[str, str]],
    sender_data_location: str,
) -> None:
    program, environment = offline_live_readiness
    result = run_program(
        program,
        {**environment, "FAKE_ACS_SENDER_DATA_LOCATION": sender_data_location},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_explicit_mismatched_sender_data_location_blocks_workloads(
    offline_live_readiness: tuple[Path, dict[str, str]],
) -> None:
    program, environment = offline_live_readiness
    result = run_program(
        program,
        {**environment, "FAKE_ACS_SENDER_DATA_LOCATION": "Europe"},
    )
    assert result.returncode != 0
    assert "live sender data location differs from the reviewed deployment" in result.stderr
    assert not (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-live-readiness.json").exists()
