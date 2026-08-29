"""Offline contracts for foundation-only ACS verification initiation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
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


def embedded_initiation_program() -> str:
    """Extract Python exactly as Actions removes the run scalar indentation."""

    start = WORKFLOW.index("- name: Initiate pending ACS customer-domain verification")
    end = WORKFLOW.index("- name: Checkpoint ACS verification initiation", start)
    block = WORKFLOW[start:end]
    match = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", block, flags=re.DOTALL)
    assert match is not None
    lines = match.group(1).splitlines()
    return "\n".join(line[10:] if line.startswith(" " * 10) else line for line in lines)


def reviewed_config(*, mode: str = "provision") -> dict[str, str]:
    return {
        "acs_resource_mode": mode,
        "acs_sending_domain": "phish.example.com",
        "acs_existing_email_domain_id": DOMAIN_ID if mode == "existing" else "",
        # An initiation stage must neither consume nor promote these fields.
        "acs_domain_verification_status": "pending_live_readback",
        "acs_spf_verification_status": "pending_live_readback",
        "acs_dkim_verification_status": "pending_live_readback",
        "acs_dkim2_verification_status": "pending_live_readback",
    }


def readiness_output() -> dict[str, object]:
    return {
        "resource_mode": "provision",
        "sending_domain": "phish.example.com",
        "dns_status": "manual_dns_required",
        "dns_automation": False,
        "dns_records": [
            {
                "purpose": "domain",
                "name": "phish.example.com",
                "type": "TXT",
                "value": "domain-token",
                "ttl": 3600,
            },
            {
                "purpose": "spf",
                "name": "phish.example.com",
                "type": "TXT",
                "value": "v=spf1 include:spf.protection.outlook.com -all",
                "ttl": 3600,
            },
            {
                "purpose": "dkim",
                "name": "selector1-azurecomm-prod-net._domainkey.phish.example.com",
                "type": "CNAME",
                "value": "selector1.azurecomm.net",
                "ttl": 3600,
            },
            {
                "purpose": "dkim2",
                "name": "selector2-azurecomm-prod-net._domainkey.phish.example.com",
                "type": "CNAME",
                "value": "selector2.azurecomm.net",
                "ttl": 3600,
            },
        ],
    }


@pytest.fixture
def offline_initiation(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    program = tmp_path / "acs-verification-initiation.py"
    program.write_text(embedded_initiation_program(), encoding="utf-8")
    compile(program.read_text(encoding="utf-8"), str(program), "exec")

    cli_dir = tmp_path / "cli"
    cli_dir.mkdir()
    call_log = tmp_path / "calls.ndjson"
    fake_terraform = cli_dir / "terraform"
    fake_terraform.write_text(
        f"""#!/usr/bin/env python3
import json
import os
import sys

name = sys.argv[-1]
domain_id = os.environ.get("FAKE_ACS_DOMAIN_ID", "{DOMAIN_ID}")
if name == "acs_control_plane_resources":
    value = {{
        "resource_group_name": "{RESOURCE_GROUP}",
        "communication_service_id": "{COMMUNICATION_ID}",
        "email_domain_id": domain_id,
        "sender_username_id": domain_id + "/senderUsernames/awareness",
    }}
elif name == "acs_delivery_readiness":
    value = {json.dumps(readiness_output(), separators=(",", ":"), sort_keys=True)!r}
    value = json.loads(value)
    if os.environ.get("FAKE_DNS_GUIDANCE") == "INCOMPLETE":
        value["dns_records"] = value["dns_records"][:-1]
else:
    raise SystemExit(2)
print(json.dumps(value, separators=(",", ":"), sort_keys=True))
""",
        encoding="utf-8",
    )
    fake_terraform.chmod(0o700)

    fake_az = cli_dir / "az"
    fake_az.write_text(
        f"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args[:2] == ["account", "show"]:
    print(json.dumps({{"subscriptionId": "{SUBSCRIPTION_ID}", "tenantId": "{TENANT_ID}"}}))
elif args[:2] == ["rest", "--method"]:
    body = json.loads(args[args.index("--body") + 1])
    uri = args[args.index("--uri") + 1]
    with Path(os.environ["FAKE_CALL_LOG"]).open("a", encoding="utf-8") as output:
        output.write(json.dumps({{"body": body, "uri": uri}}, separators=(",", ":"), sort_keys=True) + "\\n")
    if os.environ.get("FAKE_ACS_FAIL_TYPE") == body.get("verificationType"):
        print("provider-secret-response-body")
        print("provider-secret-error-body", file=sys.stderr)
        raise SystemExit(12)
    # Simulate an accepted or idempotently already-started request. The real
    # command uses --output none; any provider output is captured and discarded.
    print("provider-secret-success-body")
else:
    raise SystemExit(3)
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
        "DEPLOYMENT_REQUEST_ID": f"kp-{'c' * 32}-1",
        "DEPLOYMENT_PHASE": "foundation_bootstrap",
        "PROTECTED_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
        "PROTECTED_TENANT_ID": TENANT_ID,
        "REVIEWED_COMMIT_SHA": "b" * 40,
        "KP_REVIEWED_DEPLOYMENT_DIGEST": f"sha256:{'a' * 64}",
        "FAKE_CALL_LOG": str(call_log),
    }
    return program, environment, call_log


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


def recorded_calls(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_initiation_is_after_saved_foundation_and_dns_plan_before_completion() -> None:
    deploy = WORKFLOW[WORKFLOW.index("  deploy:") :]
    foundation_apply = deploy.index("- name: Apply ACS foundation bootstrap")
    foundation_checkpoint = deploy.index("- name: Checkpoint ACS foundation bootstrap apply")
    publish_dns_plan = deploy.index("- name: Publish non-secret integration bootstrap plan")
    integration_checkpoint = deploy.index("- name: Checkpoint integration bootstrap plan")
    initiation = deploy.index("- name: Initiate pending ACS customer-domain verification")
    initiation_checkpoint = deploy.index("- name: Checkpoint ACS verification initiation")
    completion = deploy.index("- name: Record completed cloud operations")
    assert (
        foundation_apply
        < foundation_checkpoint
        < publish_dns_plan
        < integration_checkpoint
        < initiation
        < initiation_checkpoint
        < completion
    )
    initiation_block = deploy[initiation:initiation_checkpoint]
    assert "if: inputs.deployment_phase == 'foundation_bootstrap'" in initiation_block
    assert '"acs_verification_initiated"' in WORKFLOW
    assert '"acs_verification_initiation_digest", "KP_ACS_VERIFICATION_INITIATION_DIGEST"' in WORKFLOW
    assert "--stage acs_verification_initiated --status passed" in WORKFLOW


def test_exact_four_allowlisted_posts_emit_pending_non_secret_evidence(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    result = run_program(program, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = recorded_calls(call_log)
    assert [call["body"] for call in calls] == [
        {"verificationType": "Domain"},
        {"verificationType": "SPF"},
        {"verificationType": "DKIM"},
        {"verificationType": "DKIM2"},
    ]
    assert {call["uri"] for call in calls} == {
        f"https://management.azure.com{DOMAIN_ID}/initiateVerification?api-version=2023-04-01"
    }
    assert "provider-secret" not in result.stdout
    assert "provider-secret" not in result.stderr

    evidence_path = Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-verification-initiation.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["result"] == "accepted_pending_control_plane_verification"
    assert evidence["verification_state"] == "pending_external_dns_and_control_plane_readback"
    assert evidence["verification_types"] == ["Domain", "SPF", "DKIM", "DKIM2"]
    assert evidence["scope_limits"] == {
        "provider_response_body_recorded": False,
        "repeat_foundation_dispatch_may_be_required": True,
        "verification_marked_complete": False,
        "workloads_unlocked": False,
    }
    supplied_digest = evidence.pop("evidence_digest")
    canonical = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
    assert supplied_digest == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    github_environment = Path(environment["GITHUB_ENV"]).read_text(encoding="utf-8")
    assert f"KP_ACS_VERIFICATION_INITIATION_DIGEST={supplied_digest}" in github_environment
    assert "verified" not in github_environment.lower()


def test_wrong_subscription_resource_id_fails_before_any_post(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    wrong_id = DOMAIN_ID.replace(SUBSCRIPTION_ID, "99999999-2222-3333-4444-555555555555")
    result = run_program(program, {**environment, "FAKE_ACS_DOMAIN_ID": wrong_id})
    assert result.returncode != 0
    assert "outside the protected subscription" in result.stderr
    assert recorded_calls(call_log) == []


def test_wrong_phase_fails_before_control_plane_mutation(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    result = run_program(program, {**environment, "DEPLOYMENT_PHASE": "workloads"})
    assert result.returncode != 0
    assert "restricted to foundation_bootstrap" in result.stderr
    assert recorded_calls(call_log) == []


def test_tampered_request_body_allowlist_fails_closed(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    original = program.read_text(encoding="utf-8")
    tampered = original.replace(
        'VERIFICATION_TYPES = ("Domain", "SPF", "DKIM", "DKIM2")',
        'VERIFICATION_TYPES = ("Domain", "SPF", "DKIM", "DMARC")',
        1,
    )
    assert tampered != original
    program.write_text(tampered, encoding="utf-8")
    result = run_program(program, environment)
    assert result.returncode != 0
    assert "verification type allowlist is invalid" in result.stderr
    assert recorded_calls(call_log) == []


def test_provider_error_body_is_not_logged_and_cannot_unlock_workloads(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    result = run_program(program, {**environment, "FAKE_ACS_FAIL_TYPE": "DKIM"})
    assert result.returncode != 0
    assert "ACS DKIM verification initiation was not accepted" in result.stderr
    assert "provider-secret" not in result.stdout
    assert "provider-secret" not in result.stderr
    assert [call["body"] for call in recorded_calls(call_log)] == [
        {"verificationType": "Domain"},
        {"verificationType": "SPF"},
        {"verificationType": "DKIM"},
    ]
    runner_temp = Path(environment["RUNNER_TEMP"])
    assert not (runner_temp / "deployment-evidence" / "acs-verification-initiation.json").exists()
    config = json.loads((runner_temp / "reviewed.auto.tfvars.json").read_text(encoding="utf-8"))
    assert all(
        config[key] == "pending_live_readback"
        for key in (
            "acs_domain_verification_status",
            "acs_spf_verification_status",
            "acs_dkim_verification_status",
            "acs_dkim2_verification_status",
        )
    )


def test_incomplete_dns_guidance_blocks_all_posts(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    result = run_program(program, {**environment, "FAKE_DNS_GUIDANCE": "INCOMPLETE"})
    assert result.returncode != 0
    assert "exactly four verification records" in result.stderr
    assert recorded_calls(call_log) == []


def test_existing_resource_mode_never_receives_implicit_verification_posts(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    config_path = Path(environment["RUNNER_TEMP"]) / "reviewed.auto.tfvars.json"
    config_path.write_text(
        json.dumps(reviewed_config(mode="existing"), separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    result = run_program(program, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    assert recorded_calls(call_log) == []
    evidence = json.loads(
        (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-verification-initiation.json").read_text(
            encoding="utf-8"
        )
    )
    assert evidence["result"] == "not_applicable_existing_resource_no_mutation"
    assert evidence["verification_types"] == []


def test_prior_authenticated_verified_state_is_distinct_and_not_restarted(
    offline_initiation: tuple[Path, dict[str, str], Path],
) -> None:
    program, environment, call_log = offline_initiation
    config_path = Path(environment["RUNNER_TEMP"]) / "reviewed.auto.tfvars.json"
    config = reviewed_config()
    for key in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
    ):
        config[key] = "verified"
    config_path.write_text(json.dumps(config, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    result = run_program(program, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    assert recorded_calls(call_log) == []
    evidence = json.loads(
        (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-verification-initiation.json").read_text(
            encoding="utf-8"
        )
    )
    assert evidence["result"] == "already_verified_by_authenticated_readback_no_mutation"
    assert evidence["verification_state"] == "verified_by_prior_authenticated_control_plane_readback"
    assert evidence["verification_types"] == []
    assert evidence["scope_limits"]["workloads_unlocked"] is False


def test_workflow_never_promotes_initiation_to_verified_or_workload_ready() -> None:
    program = embedded_initiation_program()
    assert 'verification_state = "pending_external_dns_and_control_plane_readback"' in program
    assert '"verification_state": verification_state' in program
    assert '"verification_marked_complete": False' in program
    assert '"workloads_unlocked": False' in program
    assert "pending_live_readback" not in program
    for status_key in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
        "acs_sender_username_status",
        "acs_domain_association_status",
    ):
        assert re.search(rf'config\["{status_key}"\]\s*=', program) is None
    assert "terraform apply" not in program
    assert "delete" not in program.lower()
