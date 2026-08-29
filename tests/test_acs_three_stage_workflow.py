"""Behavioral contracts for the explicit ACS bootstrap/finalize/workloads workflow."""

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


def embedded_program(start_name: str, end_name: str) -> str:
    start = WORKFLOW.index(f"- name: {start_name}")
    end = WORKFLOW.index(f"- name: {end_name}", start)
    block = WORKFLOW[start:end]
    matches = re.findall(r"python3 - <<'PY'\n(.*?)\n          PY", block, flags=re.DOTALL)
    assert len(matches) == 1
    return "\n".join(line[10:] if line.startswith(" " * 10) else line for line in matches[0].splitlines())


def run_python(
    program: Path, environment: dict[str, str], *, cwd: Path = REPO_ROOT
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(program)],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def write_digest_evidence(path: Path, value: dict[str, object]) -> str:
    canonical = json.dumps(value, separators=(",", ":"), sort_keys=True)
    digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    path.write_text(
        json.dumps({**value, "evidence_digest": digest}, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return digest


@pytest.fixture
def plan_guard_runner(tmp_path: Path) -> tuple[dict[str, str], Path]:
    cli_dir = tmp_path / "cli"
    cli_dir.mkdir()
    fake_terraform = cli_dir / "terraform"
    fake_terraform.write_text(
        """#!/usr/bin/env python3
import json
import os

print(os.environ["FAKE_PLAN_JSON"])
""",
        encoding="utf-8",
    )
    fake_terraform.chmod(0o700)
    environment = {
        **os.environ,
        "PATH": f"{cli_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "FAKE_PLAN_JSON": json.dumps({"resource_changes": []}),
    }
    return environment, tmp_path


def plan(address: str, actions: list[str]) -> str:
    return json.dumps({"resource_changes": [{"address": address, "change": {"actions": actions}}]})


def test_dispatch_exposes_only_the_explicit_three_stage_contract() -> None:
    dispatch = WORKFLOW[WORKFLOW.index("deployment_phase:") : WORKFLOW.index("deployment_config:")]
    assert "default: foundation_bootstrap" in dispatch
    assert "options: [foundation_bootstrap, foundation_finalize, workloads]" in dispatch
    assert "options: [foundation, workloads]" not in dispatch


@pytest.mark.parametrize(
    ("address", "accepted"),
    [
        ("azurerm_communication_service.main[0]", True),
        ('azurerm_dns_cname_record.acs_verification["dkim2"]', True),
        ("azurerm_container_registry.main", True),
        ("azurerm_postgresql_flexible_server.main", True),
        ("azurerm_communication_service_email_domain_association.main[0]", False),
        ("azurerm_email_communication_service_domain_sender_username.main[0]", False),
    ],
)
def test_bootstrap_plan_guard_accepts_full_non_workload_foundation_but_blocks_sender_binding(
    plan_guard_runner: tuple[dict[str, str], Path],
    address: str,
    accepted: bool,
) -> None:
    environment, tmp_path = plan_guard_runner
    program = tmp_path / "bootstrap-guard.py"
    program.write_text(
        embedded_program(
            "Enforce ACS foundation bootstrap plan allowlist",
            "Checkpoint allowlisted foundation bootstrap plan",
        ),
        encoding="utf-8",
    )
    result = run_python(program, {**environment, "FAKE_PLAN_JSON": plan(address, ["create"])})
    assert (result.returncode == 0) is accepted
    if not accepted:
        assert "must not create an ACS association or sender username" in result.stderr


@pytest.mark.parametrize(
    ("address", "accepted"),
    [
        ("azurerm_communication_service_email_domain_association.main[0]", True),
        ("azurerm_email_communication_service_domain_sender_username.main[0]", True),
        ("azurerm_email_communication_service_domain.main[0]", False),
        ("azurerm_container_registry.main", False),
    ],
)
def test_finalize_plan_guard_accepts_only_association_and_sender(
    plan_guard_runner: tuple[dict[str, str], Path],
    address: str,
    accepted: bool,
) -> None:
    environment, tmp_path = plan_guard_runner
    program = tmp_path / "finalize-guard.py"
    program.write_text(
        embedded_program(
            "Enforce ACS foundation finalize plan allowlist",
            "Checkpoint allowlisted foundation finalize plan",
        ),
        encoding="utf-8",
    )
    result = run_python(program, {**environment, "FAKE_PLAN_JSON": plan(address, ["update"])})
    assert (result.returncode == 0) is accepted
    if not accepted:
        assert "unrelated changes" in result.stderr


def test_finalize_plan_guard_accepts_conclusive_noop(
    plan_guard_runner: tuple[dict[str, str], Path],
) -> None:
    environment, tmp_path = plan_guard_runner
    program = tmp_path / "finalize-noop-guard.py"
    program.write_text(
        embedded_program(
            "Enforce ACS foundation finalize plan allowlist",
            "Checkpoint allowlisted foundation finalize plan",
        ),
        encoding="utf-8",
    )
    result = run_python(program, environment)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "guard_name,next_name",
    [
        (
            "Enforce ACS foundation bootstrap plan allowlist",
            "Checkpoint allowlisted foundation bootstrap plan",
        ),
        (
            "Enforce ACS foundation finalize plan allowlist",
            "Checkpoint allowlisted foundation finalize plan",
        ),
    ],
)
def test_foundation_plan_guards_reject_replacements(
    plan_guard_runner: tuple[dict[str, str], Path],
    guard_name: str,
    next_name: str,
) -> None:
    environment, tmp_path = plan_guard_runner
    program = tmp_path / "destructive-guard.py"
    program.write_text(embedded_program(guard_name, next_name), encoding="utf-8")
    address = "azurerm_communication_service_email_domain_association.main[0]"
    result = run_python(program, {**environment, "FAKE_PLAN_JSON": plan(address, ["delete", "create"])})
    assert result.returncode != 0
    assert "refuses deletes or replacements" in result.stderr


@pytest.fixture
def finalize_readback(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    program = tmp_path / "finalize-readback.py"
    program.write_text(
        embedded_program(
            "Prove finalized ACS association and sender from Azure",
            "Checkpoint finalized ACS readback",
        ),
        encoding="utf-8",
    )
    compile(program.read_text(encoding="utf-8"), str(program), "exec")

    cli_dir = tmp_path / "cli"
    cli_dir.mkdir()
    fake_terraform = cli_dir / "terraform"
    fake_terraform.write_text(
        f"""#!/usr/bin/env python3
import json

print(json.dumps({{
    "resource_group_name": "{RESOURCE_GROUP}",
    "communication_service_id": "{COMMUNICATION_ID}",
    "email_domain_id": "{DOMAIN_ID}",
    "sender_username_id": "{SENDER_ID}",
}}))
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

args = sys.argv[1:]
if args[:2] == ["account", "show"]:
    value = {{"subscriptionId": "{SUBSCRIPTION_ID}", "tenantId": "{TENANT_ID}"}}
elif args[:2] == ["rest", "--method"]:
    uri = args[args.index("--uri") + 1].split("?", 1)[0]
    if uri.endswith("{SENDER_ID}"):
        value = {{
            "id": "{SENDER_ID}",
            "type": "Microsoft.Communication/EmailServices/Domains/SenderUsernames",
            "provisioningState": "Succeeded",
            "username": os.environ.get("FAKE_SENDER", "awareness"),
            "displayName": "Security Awareness",
            "dataLocation": "United States",
        }}
    elif uri.endswith("{DOMAIN_ID}"):
        status = os.environ.get("FAKE_DOMAIN_STATUS", "Verified")
        value = {{
            "id": "{DOMAIN_ID}",
            "type": "Microsoft.Communication/EmailServices/Domains",
            "provisioningState": "Succeeded",
            "fromSenderDomain": "phish.example.com",
            "Domain": status,
            "SPF": status,
            "DKIM": status,
            "DKIM2": status,
            "dataLocation": "United States",
        }}
    elif uri.endswith("{COMMUNICATION_ID}"):
        linked = [] if os.environ.get("FAKE_ASSOCIATION") == "MISSING" else ["{DOMAIN_ID}"]
        value = {{
            "id": "{COMMUNICATION_ID}",
            "type": "Microsoft.Communication/CommunicationServices",
            "provisioningState": "Succeeded",
            "linkedDomains": linked,
            "dataLocation": "United States",
        }}
    else:
        raise SystemExit(3)
else:
    print("provider-secret-error", file=sys.stderr)
    raise SystemExit(2)
print(json.dumps(value, separators=(",", ":"), sort_keys=True))
""",
        encoding="utf-8",
    )
    fake_az.chmod(0o700)

    (tmp_path / "deployment-evidence").mkdir()
    (tmp_path / "reviewed.auto.tfvars.json").write_text(
        json.dumps(
            {
                "acs_sending_domain": "phish.example.com",
                "acs_sender_local_part": "awareness",
                "acs_sender_display_name": "Security Awareness",
                "communication_data_location": "United States",
            }
        ),
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
        "DEPLOYMENT_PHASE": "foundation_finalize",
        "PROTECTED_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
        "PROTECTED_TENANT_ID": TENANT_ID,
        "REVIEWED_COMMIT_SHA": "b" * 40,
        "KP_REVIEWED_DEPLOYMENT_DIGEST": f"sha256:{'a' * 64}",
    }
    return program, environment


def test_finalize_post_apply_readback_emits_exact_hashed_proof(
    finalize_readback: tuple[Path, dict[str, str]],
) -> None:
    program, environment = finalize_readback
    result = run_python(program, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    evidence_path = Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-finalize-readback.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert evidence["result"] == "foundation_finalized"
    assert evidence["verification"] == {
        "domain": "verified",
        "spf": "verified",
        "dkim": "verified",
        "dkim2": "verified",
    }
    assert evidence["association"] == "verified_exact_single_match"
    assert evidence["sender"] == "verified_exact_readback"
    supplied = evidence.pop("evidence_digest")
    canonical = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
    assert supplied == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"FAKE_ASSOCIATION": "MISSING"}, "exact live ACS email-domain association"),
        ({"FAKE_SENDER": "attacker"}, "sender username does not match"),
        ({"FAKE_DOMAIN_STATUS": "VerificationFailed"}, "all four live ACS verification states"),
    ],
)
def test_finalize_post_apply_readback_fails_closed_on_incomplete_live_state(
    finalize_readback: tuple[Path, dict[str, str]],
    override: dict[str, str],
    message: str,
) -> None:
    program, environment = finalize_readback
    result = run_python(program, {**environment, **override})
    assert result.returncode != 0
    assert message in result.stderr
    assert "provider-secret" not in result.stderr
    assert not (Path(environment["RUNNER_TEMP"]) / "deployment-evidence" / "acs-finalize-readback.json").exists()


def test_stage_result_rejects_tampered_source_and_keeps_scope_limits_truthful(tmp_path: Path) -> None:
    program = tmp_path / "stage-result.py"
    program.write_text(
        embedded_program("Emit conclusive ACS stage result", "Checkpoint conclusive ACS stage result"),
        encoding="utf-8",
    )
    evidence_dir = tmp_path / "deployment-evidence"
    evidence_dir.mkdir()
    commit = "b" * 40
    reviewed_digest = f"sha256:{'a' * 64}"
    live_digest = write_digest_evidence(
        evidence_dir / "acs-live-readiness.json",
        {
            "schema": "kp.acs-live-readiness.v1",
            "phase": "foundation_bootstrap",
            "result": "foundation_bootstrap_domain_pending",
            "reviewed_commit_sha": commit,
            "reviewed_deployment_digest": reviewed_digest,
        },
    )
    initiation_digest = write_digest_evidence(
        evidence_dir / "acs-verification-initiation.json",
        {
            "schema": "kp.acs-verification-initiation.v1",
            "phase": "foundation_bootstrap",
            "result": "accepted_pending_control_plane_verification",
            "verification_types": ["Domain", "SPF", "DKIM", "DKIM2"],
            "reviewed_commit_sha": commit,
            "reviewed_deployment_digest": reviewed_digest,
        },
    )
    github_environment = tmp_path / "github.env"
    github_environment.touch()
    environment = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_ENV": str(github_environment),
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "DEPLOYMENT_REQUEST_ID": f"kp-{'c' * 32}-1",
        "DEPLOYMENT_PHASE": "foundation_bootstrap",
        "REVIEWED_COMMIT_SHA": commit,
        "KP_REVIEWED_DEPLOYMENT_DIGEST": reviewed_digest,
        "KP_ACS_LIVE_READINESS_DIGEST": live_digest,
        "KP_ACS_VERIFICATION_INITIATION_DIGEST": initiation_digest,
    }
    success = run_python(program, environment)
    assert success.returncode == 0, success.stdout + success.stderr
    result_path = evidence_dir / "acs-stage-result.json"
    stage_result = json.loads(result_path.read_text(encoding="utf-8"))
    assert stage_result["schema"] == "kp.acs-stage-result.v1"
    assert stage_result["result"] == "foundation_bootstrap_pending_dns"
    assert all(
        stage_result["claims"][key] is False
        for key in (
            "domain_verification_proven",
            "association_proven",
            "sender_proven",
            "workloads_deployed",
            "receipt_subscription_activated",
            "mail_delivery_proven",
            "inbox_placement_proven",
            "human_mailbox_validation_proven",
        )
    )

    result_path.unlink()
    live_path = evidence_dir / "acs-live-readiness.json"
    tampered = json.loads(live_path.read_text(encoding="utf-8"))
    tampered["result"] = "workloads_verified"
    live_path.write_text(json.dumps(tampered), encoding="utf-8")
    failure = run_python(program, environment)
    assert failure.returncode != 0
    assert "integrity validation failed" in failure.stderr
    assert not result_path.exists()


def test_stage_result_artifact_is_emitted_before_completion_and_always_uploaded() -> None:
    emit = WORKFLOW.index("- name: Emit conclusive ACS stage result")
    checkpoint = WORKFLOW.index("- name: Checkpoint conclusive ACS stage result")
    complete = WORKFLOW.index("- name: Record completed cloud operations")
    upload = WORKFLOW.index("- name: Upload append-only deployment recovery evidence")
    assert emit < checkpoint < complete < upload
    assert '"schema": "kp.acs-stage-result.v1"' in WORKFLOW[emit:checkpoint]
    assert "path: ${{ runner.temp }}/deployment-evidence/" in WORKFLOW[upload:]
