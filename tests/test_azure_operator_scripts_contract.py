"""Offline contract checks for the Azure bootstrap/readiness operator scripts."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "azure_bootstrap.sh"
PREFLIGHT = ROOT / "scripts" / "azure_preflight.sh"
MAIL_CHECK = ROOT / "scripts" / "azure_mail_check.sh"
RELEASE = ROOT / "scripts" / "azure_release.sh"
ENTRA_PREFLIGHT = ROOT / "scripts" / "entra_graph_preflight.sh"
FAKE_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
FAKE_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run(script: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(script), *args],  # noqa: S607
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _write_cli(shim_dir: Path, name: str, body: str) -> None:
    implementation = shim_dir / f"{name}_impl.py"
    implementation.write_text(body, encoding="utf-8")
    launcher = shim_dir / name
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(implementation))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o700)


def _expected_console_app_roles() -> list[dict[str, object]]:
    roles = [
        ("source_curator", "Source curator", "Curate threat-intelligence sources."),
        ("campaign_author", "Campaign author", "Draft awareness campaigns."),
        (
            "security_approver",
            "Security approver",
            "Give the security approval required to schedule.",
        ),
        (
            "privacy_approver",
            "Privacy approver",
            "Give the privacy approval required to schedule.",
        ),
        ("campaign_operator", "Campaign operator", "Schedule and run approved campaigns."),
        ("auditor", "Auditor", "Read audit history and reports."),
        ("administrator", "Administrator", "Full administrative access."),
    ]
    result: list[dict[str, object]] = [
        {
            "allowedMemberTypes": ["User"],
            "description": description,
            "displayName": display_name,
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"kingphisher-phoenix/role/{value}")),
            "isEnabled": True,
            "value": value,
        }
        for value, display_name, description in roles
    ]
    result.append(
        {
            "allowedMemberTypes": ["Application"],
            "description": "Allow Microsoft.EventGrid to deliver authenticated ACS receipts.",
            "displayName": "Azure Event Grid secure webhook subscriber",
            "id": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "kingphisher-phoenix/role/AzureEventGridSecureWebhookSubscriber",
                )
            ),
            "isEnabled": True,
            "value": "AzureEventGridSecureWebhookSubscriber",
        }
    )
    return result


def _install_bootstrap_precheck_shims(
    tmp_path: Path,
    *,
    console_rows: object,
    app_roles_output: str,
) -> tuple[Path, Path]:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    call_log = tmp_path / "calls"
    _write_cli(
        shim_dir,
        "az",
        f'''import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("az " + " ".join(args) + "\\n")
if args[:2] == ["account", "show"]:
    if "tenantId" in args:
        print("{FAKE_TENANT}")
    else:
        print(json.dumps({{"tenantId": "{FAKE_TENANT}"}}))
    raise SystemExit(0)
if args[:3] == ["ad", "app", "list"]:
    display_name = args[args.index("--display-name") + 1]
    if display_name == "kp-phoenix-console-staging":
        print({json.dumps(json.dumps(console_rows))})
    else:
        print("[]")
    raise SystemExit(0)
if args[:3] == ["ad", "app", "show"]:
    print({json.dumps(app_roles_output)})
    raise SystemExit(0)
if args[:2] == ["group", "create"]:
    raise SystemExit(73)
raise SystemExit(72)
''',
    )
    _write_cli(
        shim_dir,
        "gh",
        """import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("gh " + " ".join(args) + "\\n")
if args[:2] in (["auth", "status"], ["repo", "view"]):
    raise SystemExit(0)
if args[:1] == ["api"]:
    print(json.dumps({
        "name": "staging",
        "can_admins_bypass": False,
        "protection_rules": [{
            "type": "required_reviewers",
            "reviewers": [{"type": "User", "reviewer": {"login": "reviewer"}}],
        }],
    }))
    raise SystemExit(0)
raise SystemExit(71)
""",
    )
    return shim_dir, call_log


def test_bootstrap_writes_only_the_stable_protected_environment_contract() -> None:
    source = _source(BOOTSTRAP)
    required = {
        "AZURE_SUBSCRIPTION_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "TF_STATE_RESOURCE_GROUP",
        "TF_STATE_STORAGE_ACCOUNT",
        "TF_STATE_CONTAINER",
    }
    configured = set(re.findall(r"^\s*set_var ([A-Z0-9_]+) ", source, re.MULTILINE))
    assert required <= configured
    assert {
        "DEPLOYMENT_ORCHESTRATION_MODE",
        "DEPLOYMENT_GITHUB_REPOSITORY",
        "DEPLOYMENT_GITHUB_REF",
        "DEPLOYMENT_GITHUB_TOKEN_SECRET_ID",
    } <= configured
    assert (
        not {
            "ENTRA_APPLICATION_CLIENT_ID",
            "OPERATOR_FQDN",
            "TRACKING_FQDN",
            "ALLOWED_RECIPIENT_DOMAINS",
        }
        & configured
    )
    assert 'gh variable set "$key" --repo "$REPO" --env "$ENVIRONMENT"' in source
    assert "require at least one reviewer" in source
    assert "administrator bypass" in source
    assert "refusing an ambiguous bootstrap" in source
    assert "existing app role contract verified without mutation" in source
    assert 'az ad app update --id "$CONSOLE_APP_ID" --app-roles' not in source
    assert source.index('assert_unique_entra_app "$APP_NAME"') < source.index("run az group create")
    assert source.index("  validate_existing_console_app_before_mutation\nfi") < source.index("run az group create")
    assert 'if [ "$DEPLOYMENT_ORCHESTRATION_MODE_EXPLICIT" -eq 1 ]; then' in source
    assert "preserved existing deployment orchestration variables" in source


def test_existing_console_app_roles_are_verified_before_first_mutation(tmp_path: Path) -> None:
    console_app_id = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    shim_dir, call_log = _install_bootstrap_precheck_shims(
        tmp_path,
        console_rows=[
            {
                "appId": console_app_id,
                "displayName": "kp-phoenix-console-staging",
            }
        ],
        app_roles_output=json.dumps(_expected_console_app_roles()),
    )
    result = _run(
        BOOTSTRAP,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        "example-org/example-repo",
        env={
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            "KP_TEST_CALL_LOG": str(call_log),
        },
    )

    assert result.returncode == 73, result.stdout + result.stderr
    assert "existing operator app role contract verified before mutation" in result.stdout
    calls = call_log.read_text(encoding="utf-8")
    role_inspection = f"az ad app show --id {console_app_id} --query appRoles -o json"
    first_mutation = "az group create"
    assert calls.index(role_inspection) < calls.index(first_mutation)


def test_invalid_existing_console_app_roles_fail_before_first_mutation(tmp_path: Path) -> None:
    expected = _expected_console_app_roles()
    invalid_contracts = {
        "malformed": "{not-json",
        "missing": "[]",
        "ambiguous_duplicate": json.dumps([*expected, expected[0]]),
    }

    for case, roles_output in invalid_contracts.items():
        case_dir = tmp_path / case
        case_dir.mkdir()
        shim_dir, call_log = _install_bootstrap_precheck_shims(
            case_dir,
            console_rows=[
                {
                    "appId": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
                    "displayName": "kp-phoenix-console-staging",
                }
            ],
            app_roles_output=roles_output,
        )
        result = _run(
            BOOTSTRAP,
            "--subscription",
            FAKE_SUBSCRIPTION,
            "--repo",
            "example-org/example-repo",
            env={
                "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
                "KP_TEST_CALL_LOG": str(call_log),
            },
        )

        assert result.returncode == 1, f"{case}: {result.stdout}{result.stderr}"
        assert "app roles differ from the current contract" in result.stderr
        assert "az group create" not in call_log.read_text(encoding="utf-8")


def test_ambiguous_existing_console_identity_fails_before_first_mutation(tmp_path: Path) -> None:
    shim_dir, call_log = _install_bootstrap_precheck_shims(
        tmp_path,
        console_rows=[
            {
                "appId": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
                "displayName": "kp-phoenix-console-staging",
            },
            {
                "appId": "cccccccc-dddd-4eee-8fff-000000000000",
                "displayName": "kp-phoenix-console-staging",
            },
        ],
        app_roles_output=json.dumps(_expected_console_app_roles()),
    )
    result = _run(
        BOOTSTRAP,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        "example-org/example-repo",
        env={
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            "KP_TEST_CALL_LOG": str(call_log),
        },
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "multiple Entra applications" in result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert "az ad app show" not in calls
    assert "az group create" not in calls


def test_bootstrap_reference_dispatch_lists_the_exact_six_workflow_inputs() -> None:
    source = _source(BOOTSTRAP)
    inputs = set(re.findall(r"-f ([a-z_]+)=", source))
    assert inputs == {
        "environment",
        "network_mode",
        "deployment_phase",
        "deployment_config",
        "deployment_request_id",
        "reviewed_commit_sha",
    }
    assert "credential value" in source
    assert "--deployment-github-token-value" not in source
    assert "deployment_phase=foundation_bootstrap" in source
    assert re.search(r"deployment_phase=foundation(?:\s|$)", source) is None


def test_bootstrap_connector_ref_validation_matches_server_fail_closed_rules() -> None:
    source = _source(BOOTSTRAP)
    for forbidden_shape in ("*/", "*.", "*.lock", "*..*", "*//*", "(^|/)\\."):
        assert forbidden_shape in source


@pytest.mark.parametrize("unsafe_ref", ["feature//unsafe", ".hidden/main", "release.lock", "main/"])
def test_bootstrap_rejects_connector_refs_the_gui_server_would_refuse(unsafe_ref: str) -> None:
    secret_id = (
        "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-kp/"
        "providers/Microsoft.KeyVault/vaults/kp-vault/secrets/deployment-token"
    )
    result = _run(
        BOOTSTRAP,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        "example-org/example-repo",
        "--deployment-orchestration-mode",
        "github_actions",
        "--deployment-github-repository",
        "example-org/example-repo",
        "--deployment-github-ref",
        unsafe_ref,
        "--deployment-github-token-secret-id",
        secret_id,
        "--dry-run",
    )
    assert result.returncode == 1
    assert "--deployment-github-ref is invalid" in result.stderr


def test_bootstrap_dry_run_does_not_require_azure_or_github_cli() -> None:
    source = _source(BOOTSTRAP)
    dry_run_branch = source.index('if [ "$DRY_RUN" -eq 1 ]; then\n  # The preview prints command arguments')
    azure_cli_check = source.index('command -v az >/dev/null 2>&1 || die "the Azure CLI (az) is not installed"')
    github_cli_check = source.index('command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is not installed"')
    branch_end = source.index("fi\naz()", dry_run_branch)
    assert dry_run_branch < azure_cli_check < branch_end
    assert dry_run_branch < github_cli_check < branch_end


def test_preflight_checks_gui_values_selected_roles_and_protected_controls() -> None:
    source = _source(PREFLIGHT)
    for required in (
        "--values-file",
        "acs_sending_domain",
        "acs_sender_local_part",
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
        "graph_endpoint",
        "directory_group_ids",
        "reported_mailbox_endpoint",
        "reported_mailbox_address",
        "required reviewers",
        "administrator bypass",
        "DEPLOYMENT_GITHUB_TOKEN_SECRET_ID",
        '"production_ready": False',
    ):
        assert required in source
    assert "AzureManaged —" not in source
    assert "separate domain, no DNS records required" not in source


def test_mail_diagnostic_is_read_only_exact_resource_inspection() -> None:
    source = _source(MAIL_CHECK)
    for required in (
        "--communication-service",
        "--email-service",
        "--sending-domain",
        "--sender-local-part",
        "resource guessing is prohibited",
        "az resource show --ids",
        "No credential, access key, connection string, or bearer token was read",
        "one-recipient canary campaign",
    ):
        assert required in source
    for forbidden in (
        "list-key",
        "primaryConnectionString",
        "from_connection_string",
        "begin_send",
        'SENDER="DoNotReply@',
    ):
        assert forbidden not in source
    assert source.count("require_bounded_output") >= 5


def test_release_reconciles_before_start_and_bounds_health_requests() -> None:
    source = _source(RELEASE)

    assert source.index("job execution list") < source.index("job start")
    assert "an earlier migration execution is still active or uncertain" in source
    assert "inspect job executions in Azure before deciding whether a retry is safe" in source
    assert "--connect-timeout 10 --max-time 30" in source
    assert "--retry-max-time 180 --retry-all-errors" in source
    assert "KP_AZURE_RELEASE_TIMEOUT_SECONDS" in source
    assert "^kp-[0-9a-f]{32}-[1-9][0-9]{0,2}$" in source
    for forbidden in ("az group delete", "az containerapp job stop", "terraform destroy", "docker system prune"):
        assert forbidden not in source.lower()


def test_entra_preflight_requires_exact_graph_role_separation() -> None:
    source = _source(ENTRA_PREFLIGHT)
    assert "value[?resourceId=='$GRAPH_RESOURCE_ID'].appRoleId" in source
    assert "an unreviewed Microsoft Graph application role is assigned" in source
    assert "Microsoft Graph application roles would bypass the Exchange custom scope" in source
    assert "no Microsoft Graph application role bypass is present" in source


def test_all_live_operator_scripts_disable_cli_logs_and_bound_cloud_calls() -> None:
    for path in (BOOTSTRAP, PREFLIGHT, MAIL_CHECK, ENTRA_PREFLIGHT):
        source = _source(path)
        assert "export AZURE_LOGGING_ENABLE_LOG_FILE=false" in source
        assert "subprocess.run" in source
        assert "timeout=int(sys.argv[1])" in source
        assert "KP_AZURE_COMMAND_TIMEOUT_SECONDS must be between 5 and 300" in source


def test_bootstrap_dry_run_is_an_offline_preview(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    call_log = tmp_path / "calls"
    body = """import os
import sys
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("called\\n")
raise SystemExit(91)
"""
    _write_cli(shim_dir, "az", body)
    _write_cli(shim_dir, "gh", body)
    result = _run(
        BOOTSTRAP,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        "example-org/example-repo",
        "--dry-run",
        env={
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            "KP_TEST_CALL_LOG": str(call_log),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline preview" in result.stdout
    assert "no cloud command was executed" in result.stdout
    assert not call_log.exists()


def test_preflight_rejects_drift_and_credential_like_gui_values(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = ROOT / "tests" / "support" / "azure_cli_shim.py"
    for name in ("az", "gh"):
        launcher = shim_dir / name
        launcher.write_text(
            f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(shim))} {name} "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o700)
    values_file = tmp_path / "staging.auto.tfvars"
    values_file.write_text(
        "\n".join(
            (
                f'subscription_id = "{FAKE_SUBSCRIPTION}"',
                f'entra_tenant_id = "{FAKE_TENANT}"',
                'entra_client_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"',
                'password_hint = "password=correct-horse-battery-staple"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    result = _run(
        PREFLIGHT,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--repo",
        "example-org/example-repo",
        "--values-file",
        str(values_file),
        "--json",
        env={"PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"},
    )
    assert result.returncode == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    checks = {(item["check"], item["result"]) for item in payload["checks"]}
    assert ("GUI export exactness", "fail") in checks
    assert ("non-secret GUI export", "fail") in checks
    assert "correct-horse" not in result.stdout + result.stderr


def test_mail_diagnostic_does_not_misreport_cli_failure_as_absent_resource(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    _write_cli(
        shim_dir,
        "az",
        f"""import os
import sys
assert os.environ.get("AZURE_LOGGING_ENABLE_LOG_FILE") == "false"
args = sys.argv[1:]
if args[:2] == ["account", "show"]:
    print("{FAKE_SUBSCRIPTION}")
    raise SystemExit(0)
if args[:2] == ["communication", "list"]:
    raise SystemExit(88)
raise SystemExit(2)
""",
    )
    result = _run(
        MAIL_CHECK,
        "--subscription",
        FAKE_SUBSCRIPTION,
        "--resource-group",
        "rg-awareness",
        "--communication-service",
        "awareness-acs",
        "--email-service",
        "awareness-email",
        "--sending-domain",
        "mail.example.com",
        "--sender-local-part",
        "awareness",
        env={"PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"},
    )
    assert result.returncode == 2
    assert "could not inspect Communication Services" in result.stderr
    assert "was not found" not in result.stderr


def test_release_refuses_duplicate_execution_without_starting_job(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    call_log = tmp_path / "calls"
    _write_cli(
        shim_dir,
        "az",
        """import os
import sys
args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write(" ".join(args) + "\\n")
if args[:4] == ["containerapp", "job", "execution", "list"]:
    print("migration-active")
    raise SystemExit(0)
raise SystemExit(93)
""",
    )
    _write_cli(shim_dir, "curl", "raise SystemExit(94)\n")
    result = _run(
        RELEASE,
        env={
            "AZURE_RESOURCE_GROUP": "rg-awareness",
            "AZURE_MIGRATION_JOB": "awareness-migrate",
            "AZURE_OPERATOR_URL": "https://operator.example.com",
            "AZURE_TRACKING_URL": "https://tracking.example.com",
            "KP_AZURE_COMMAND_TIMEOUT_SECONDS": "5",
            "KP_AZURE_RELEASE_TIMEOUT_SECONDS": "60",
            "KP_TEST_CALL_LOG": str(call_log),
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        },
    )

    assert result.returncode == 1
    assert "still active or uncertain" in result.stderr
    calls = call_log.read_text(encoding="utf-8")
    assert "execution list" in calls
    assert "job start" not in calls


def test_unknown_credential_like_argument_is_never_reflected() -> None:
    marker = "password=do-not-reflect-this-value"
    for script in (BOOTSTRAP, PREFLIGHT, MAIL_CHECK):
        result = _run(script, f"--{marker}")
        assert result.returncode != 0
        assert marker not in result.stdout + result.stderr


def test_entra_live_preflight_fails_closed_on_wrong_tenant(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    _write_cli(
        shim_dir,
        "az",
        """import os
import sys
assert os.environ.get("AZURE_LOGGING_ENABLE_LOG_FILE") == "false"
if sys.argv[1:3] == ["account", "show"]:
    print("ffffffff-ffff-ffff-ffff-ffffffffffff")
    raise SystemExit(0)
raise SystemExit(2)
""",
    )
    result = _run(
        ENTRA_PREFLIGHT,
        "--tenant-id",
        FAKE_TENANT,
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
        env={"PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"},
    )
    assert result.returncode == 2
    assert "different Entra tenant" in result.stderr
