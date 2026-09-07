"""Offline contract checks for the nightly Azure power-down.

This is a *scheduled* job that mutates live infrastructure, so its contract is
pinned here rather than left to review:

* it performs exactly three reversible actions (stop Postgres, Container Apps to
  min-replicas 0, deallocate the CI runner VM) and nothing else,
* it never runs terraform, never deletes/destroys, and never starts anything,
* it is idempotent — already-off resources are logged skips, not errors,
* `--dry-run` issues no Azure write at all,
* the 23:00 America/New_York window is enforced in code, not assumed from the
  UTC cron, so daylight saving cannot drift it,
* a deployment in flight and an operator skip both leave Azure running.

Nothing here touches Azure. The script is exercised against an `az` shim, and
the workflow's embedded decision programs are executed directly.
"""

from __future__ import annotations

import datetime as datetime_module
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "operator" / "azure-nightly-shutdown.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "azure-nightly-shutdown.yml"
IDLE_SCRIPT = REPO_ROOT / "scripts" / "operator" / "azure-idle.sh"
RUNBOOK = REPO_ROOT / "docs" / "NIGHTLY-AZURE-SHUTDOWN.md"

OPERATOR_TIMEZONE = ZoneInfo("America/New_York")
PROJECT_TAG = "kingphisher-phoenix"

# The exact resources the nightly job is allowed to power down, and the exact
# ones it must leave alone. Changing either list is a deliberate cost/latency
# decision, so it has to change this test too.
NIGHTLY_POWER_DOWN = ("postgres flexible-server stop", "containerapp update", "vm deallocate")
NEVER_TOUCHED = ("acr", "redis", "communication", "eventgrid", "network dns", "keyvault", "storage")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _executable_lines(path: Path) -> str:
    """The file with comment-only and pure-output lines removed.

    The header comments and the run-time "left running on purpose" log
    deliberately *name* the things the job must never do (terraform, destroy,
    ACR) to explain the distinction from `azure-idle.sh stop`. Only lines that
    can actually invoke something are searched for forbidden commands.
    """

    return "\n".join(
        line for line in _source(path).splitlines() if not line.lstrip().startswith(("#", 'log "', "echo ", 'echo "'))
    ).lower()


def _embedded_program(step_name: str) -> str:
    """Extract a `python3 - <<'PY'` program exactly as YAML dedents it."""

    workflow = _source(WORKFLOW)
    start = workflow.index(f"- name: {step_name}")
    end = workflow.index("      - name: ", start + 1)
    match = re.search(r"python3 - <<'PY'\n(.*?)\n {10}PY\n", workflow[start:end], flags=re.DOTALL)
    assert match is not None, f"no embedded python program in step {step_name!r}"
    return "\n".join(line[10:] if line.startswith(" " * 10) else line for line in match.group(1).splitlines())


def _write_az_shim(shim_dir: Path, body: str) -> None:
    implementation = shim_dir / "az_impl.py"
    implementation.write_text(body, encoding="utf-8")
    launcher = shim_dir / "az"
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(implementation))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o700)


DEFAULT_INVENTORY = {
    "postgres": [
        {"name": "psql-kp-staging", "state": "Ready", "application": PROJECT_TAG, "environment": "staging"},
    ],
    "containerapp": [
        {"name": "ca-kp-staging-operator", "minReplicas": 1, "application": PROJECT_TAG, "environment": "staging"},
        {"name": "ca-kp-staging-tracking", "minReplicas": 1, "application": PROJECT_TAG, "environment": "staging"},
    ],
    "vm": [
        {
            "name": "vm-kp-staging-runner",
            "powerState": "VM running",
            "application": PROJECT_TAG,
            "environment": "staging",
        },
    ],
}

AZ_SHIM = """import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write(" ".join(args) + "\\n")
inventory = json.loads(os.environ["KP_TEST_INVENTORY"])
failing = os.environ.get("KP_TEST_FAIL_WRITES", "") == "1"
if args[:2] == ["account", "show"]:
    print("11111111-2222-3333-4444-555555555555")
    raise SystemExit(0)
if args[:2] == ["account", "set"]:
    raise SystemExit(0)
if args[:2] == ["group", "show"]:
    print("rg-kp-staging")
    raise SystemExit(0)
if args[:3] == ["postgres", "flexible-server", "list"]:
    print(json.dumps(inventory["postgres"]))
    raise SystemExit(0)
if args[:2] == ["containerapp", "list"]:
    print(json.dumps(inventory["containerapp"]))
    raise SystemExit(0)
if args[:2] == ["containerapp", "show"]:
    # the orphan probe asks which revision is current
    wanted = args[args.index("--name") + 1] if "--name" in args else ""
    print(f"{wanted}--current")
    raise SystemExit(0)
if args[:3] == ["containerapp", "revision", "list"]:
    # replicas pinned on SUPERSEDED revisions; default inventory has none
    wanted = args[args.index("--name") + 1] if "--name" in args else ""
    for row in inventory["containerapp"]:
        if row.get("name") == wanted:
            for count in row.get("orphanReplicas", []):
                print(count)
            break
    raise SystemExit(0)
if args[:2] == ["vm", "list"]:
    # The script deliberately does NOT pass --show-details (that needs
    # Microsoft.Network reads the least-privilege role does not hold), so the
    # listing carries no powerState; it is fetched per VM from the instance view.
    assert "--show-details" not in args, "vm list must not use --show-details"
    print(json.dumps([
        {k: v for k, v in row.items() if k != "powerState"} for row in inventory["vm"]
    ]))
    raise SystemExit(0)
if args[:2] == ["vm", "get-instance-view"]:
    wanted = args[args.index("--name") + 1] if "--name" in args else ""
    for row in inventory["vm"]:
        if row.get("name") == wanted:
            print(row.get("powerState", ""))
            break
    raise SystemExit(0)
if args[:4] == ["postgres", "flexible-server", "backup", "create"]:
    raise SystemExit(7 if os.environ.get("KP_TEST_FAIL_BACKUP", "") == "1" or failing else 0)
if args[:3] == ["postgres", "flexible-server", "stop"] or args[:2] in (
    ["containerapp", "update"],
    ["vm", "deallocate"],
):
    raise SystemExit(7 if failing else 0)
sys.stderr.write("unexpected az invocation: " + " ".join(args) + "\\n")
raise SystemExit(99)
"""


def _run_script(
    tmp_path: Path,
    *arguments: str,
    inventory: dict[str, list[dict[str, object]]] | None = None,
    fail_writes: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    _write_az_shim(shim_dir, AZ_SHIM)
    call_log = tmp_path / "calls"
    call_log.write_text("", encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), *arguments],  # noqa: S607
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            "KP_TEST_CALL_LOG": str(call_log),
            "KP_TEST_INVENTORY": json.dumps(inventory if inventory is not None else DEFAULT_INVENTORY),
            "KP_TEST_FAIL_WRITES": "1" if fail_writes else "0",
            **(extra_env or {}),
        },
        capture_output=True,
        text=True,
        timeout=120,
    )
    calls = [line for line in call_log.read_text(encoding="utf-8").splitlines() if line]
    return result, calls


def _writes(calls: list[str]) -> list[str]:
    return [
        call
        for call in calls
        if call.startswith(
            (
                "postgres flexible-server backup create",
                "postgres flexible-server stop",
                "containerapp update",
                "vm deallocate",
            )
        )
    ]


# --------------------------------------------------------------------------
# The script's blast radius
# --------------------------------------------------------------------------


def test_script_powers_down_exactly_the_cheap_reversible_tier(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    # The on-demand restore point is timestamped; normalise it so the expected
    # sequence stays exact. Its position matters: it must PRECEDE the stop.
    normalised = [re.sub(r"nightly-\d{8}T\d{6}Z", "nightly-<TS>", call) for call in _writes(calls)]
    assert normalised == [
        "postgres flexible-server backup create --resource-group rg-kp-staging "
        "--server-name psql-kp-staging --name nightly-<TS>",
        "postgres flexible-server stop --resource-group rg-kp-staging --name psql-kp-staging",
        "containerapp update --name ca-kp-staging-operator --resource-group rg-kp-staging --min-replicas 0",
        "containerapp update --name ca-kp-staging-tracking --resource-group rg-kp-staging --min-replicas 0",
        "vm deallocate --resource-group rg-kp-staging --name vm-kp-staging-runner",
    ]
    # ACR, Redis, ACS, DNS, Event Grid, Key Vault and storage are never even read.
    joined = " ".join(calls).lower()
    for forbidden in NEVER_TOUCHED:
        assert forbidden not in joined, f"the nightly job must not touch {forbidden}"


def test_script_never_starts_deletes_or_applies_terraform() -> None:
    source = _executable_lines(SCRIPT)
    for forbidden in (
        "terraform apply",
        "terraform plan",
        "terraform destroy",
        "group delete",
        "resource delete",
        "flexible-server start",
        "flexible-server delete",
        "vm start",
        "vm delete",
        "containerapp delete",
        "acr delete",
        "redisenterprise delete",
        "purge",
    ):
        assert forbidden not in source, f"the nightly job must never contain {forbidden!r}"


def test_script_write_allowlist_refuses_anything_else() -> None:
    source = _source(SCRIPT)
    allowlist = source[source.index("az_write() {") : source.index("PYSELECT")]
    for permitted in NIGHTLY_POWER_DOWN:
        assert permitted in allowlist
    assert "refusing an Azure write outside the nightly power-down allowlist" in allowlist


def test_dry_run_issues_no_azure_write_at_all(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "--dry-run")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _writes(calls) == []
    assert "DRY RUN" in result.stdout
    assert "would run: az postgres flexible-server stop" in result.stdout
    assert "would run: az containerapp update" in result.stdout
    assert "would run: az vm deallocate" in result.stdout


def test_already_powered_down_resources_are_a_logged_no_op(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        inventory={
            "postgres": [
                {"name": "psql-kp-staging", "state": "Stopped", "application": PROJECT_TAG, "environment": "staging"},
            ],
            "containerapp": [
                {
                    "name": "ca-kp-staging-operator",
                    "minReplicas": 0,
                    "application": PROJECT_TAG,
                    "environment": "staging",
                },
            ],
            "vm": [
                {
                    "name": "vm-kp-staging-runner",
                    "powerState": "VM deallocated",
                    "application": PROJECT_TAG,
                    "environment": "staging",
                },
            ],
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _writes(calls) == []
    assert "changed: 0" in result.stdout
    assert "already not running (state=Stopped)" in result.stdout
    assert "already at min-replicas 0" in result.stdout
    assert "already VM deallocated" in result.stdout


def test_resources_outside_the_project_tags_are_skipped_with_a_reason(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        inventory={
            "postgres": [
                {
                    "name": "psql-someone-else",
                    "state": "Ready",
                    "application": "other-product",
                    "environment": "staging",
                },
            ],
            "containerapp": [
                {
                    "name": "ca-prod-lookalike",
                    "minReplicas": 3,
                    "application": PROJECT_TAG,
                    "environment": "production",
                },
            ],
            "vm": [],
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _writes(calls) == []
    assert result.stdout.count("not tagged for this project/environment") == 2


def test_a_failed_power_down_is_reported_not_swallowed(tmp_path: Path) -> None:
    result, _ = _run_script(tmp_path, fail_writes=True)

    assert result.returncode == 2
    assert "could not be powered down" in result.stderr
    assert "failed: 4" in result.stdout


def test_json_action_log_records_every_decision(tmp_path: Path) -> None:
    result, _ = _run_script(tmp_path, "--json")

    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"action"')]
    assert {record["kind"] for record in records} == {"postgres", "containerapp", "vm"}
    assert all(record["reason"] for record in records)
    assert {record["result"] for record in records} == {
        "backed_up",
        "stopped",
        "scaled_to_zero",
        "deallocated",
    }


def test_deeper_operator_idle_is_left_alone() -> None:
    # `azure-idle.sh stop` remains the deliberate, plan-reviewed, deeper idle
    # that destroys ACR + Redis. The nightly job must never become that.
    idle = _source(IDLE_SCRIPT)
    assert "deploy_data_plane=false" in idle
    assert "terraform plan" in idle
    assert "Type 'yes' to apply this plan" in idle
    nightly = _source(SCRIPT)
    assert "azure-idle.sh" in nightly, "the nightly script must document the distinction"
    assert "deploy_data_plane" not in nightly.replace(
        "a terraform apply with deploy_workloads=false deploy_data_plane=false", ""
    )


# --------------------------------------------------------------------------
# The workflow's shape
# --------------------------------------------------------------------------


def test_workflow_schedules_both_dst_branches_and_gates_on_local_time() -> None:
    workflow = _source(WORKFLOW)
    crons = re.findall(r'- cron: "([^"]+)"', workflow)
    assert crons == ["0 3 * * *", "0 4 * * *"], "23:00 America/New_York is 03:00 UTC (EDT) and 04:00 UTC (EST)"
    program = _embedded_program("Resolve the operator switch, the skip window, and local time")
    assert 'OPERATOR_TIMEZONE = "America/New_York"' in program
    assert "WINDOW_LOCAL_HOUR = 23" in program
    assert "now_local.hour != WINDOW_LOCAL_HOUR" in program


def test_workflow_never_starts_anything_and_never_runs_terraform() -> None:
    workflow = _executable_lines(WORKFLOW)
    for forbidden in ("terraform", "vm start", "flexible-server start", "azure-idle.sh start"):
        assert forbidden not in workflow


def test_workflow_pins_every_action_to_a_full_commit_sha() -> None:
    for reference in re.findall(r"uses: (\S+)", _source(WORKFLOW)):
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference), f"{reference} is not SHA-pinned"


def test_workflow_reuses_the_existing_azure_oidc_pattern_without_new_secrets() -> None:
    workflow = _source(WORKFLOW)
    deploy = _source(REPO_ROOT / ".github" / "workflows" / "azure-deploy.yml")
    for shared in ("vars.AZURE_CLIENT_ID", "vars.AZURE_TENANT_ID", "vars.AZURE_SUBSCRIPTION_ID"):
        assert shared in workflow and shared in deploy
    assert "id-token: write" in workflow
    # No stored Azure credential, and no new repo *secret* of any kind.
    assert "secrets." not in workflow


def test_workflow_does_not_borrow_the_reviewer_gated_deploy_environment() -> None:
    workflow = _source(WORKFLOW)
    # `staging`/`production` require a human reviewer, which an unattended
    # nightly job can never satisfy; it uses its own unprotected environment.
    assert "environment: azure-nightly-shutdown" in workflow
    assert "environment: staging" not in workflow
    assert "environment: production" not in workflow
    # Nor may it queue behind a deploy on the shared concurrency group.
    assert "group: azure-nightly-shutdown" in workflow
    assert "group: azure-${{" not in workflow


def test_workflow_grants_no_write_scope_beyond_the_oidc_token() -> None:
    for permission in re.findall(r"^\s+([a-z-]+): (write|read|none)$", _source(WORKFLOW), re.MULTILINE):
        name, level = permission
        assert level != "write" or name == "id-token", f"{name}: write is not needed by a shutdown job"


def test_runbook_documents_enable_skip_and_restart() -> None:
    runbook = _source(RUNBOOK)
    for required in (
        "NIGHTLY_AZURE_SHUTDOWN",
        "NIGHTLY_AZURE_SHUTDOWN_SKIP_UNTIL",
        "gh variable set",
        "azure-nightly-shutdown",
        "--dry-run",
        "az postgres flexible-server start",
        "az vm start",
        "min-replicas",
        "azure-idle.sh",
    ):
        assert required in runbook, f"the runbook must document {required}"


# --------------------------------------------------------------------------
# The decision gates, executed exactly as the workflow ships them
# --------------------------------------------------------------------------


class _FrozenDatetime(datetime):
    _fixed = datetime(2026, 6, 1, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return cls._fixed if tz is None else cls._fixed.astimezone(tz)


def _run_window_gate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    local_now: datetime,
    mode: str = "enabled",
    skip_until: str = "",
    event: str = "schedule",
    dispatch_dry_run: str = "true",
) -> dict[str, str]:
    output = tmp_path / f"gate-output-{abs(hash((local_now, mode, skip_until, event, dispatch_dry_run)))}"
    output.write_text("", encoding="utf-8")
    frozen = type("Frozen", (_FrozenDatetime,), {"_fixed": local_now.astimezone(UTC)})
    monkeypatch.setattr(datetime_module, "datetime", frozen)
    monkeypatch.setenv("NIGHTLY_MODE", mode)
    monkeypatch.setenv("NIGHTLY_SKIP_UNTIL", skip_until)
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("DISPATCH_DRY_RUN", dispatch_dry_run)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    program = _embedded_program("Resolve the operator switch, the skip window, and local time")
    exec(compile(program, "<window-gate>", "exec"), {"__name__": "__main__"})  # noqa: S102
    return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if "=" in line)


def _at(month: int, day: int, hour: int) -> datetime:
    return datetime(2026, month, day, hour, 30, tzinfo=OPERATOR_TIMEZONE)


@pytest.mark.parametrize(
    ("month", "day"),
    [(6, 15), (1, 15)],  # EDT (UTC-4) and EST (UTC-5)
)
def test_the_local_window_fires_once_a_night_in_both_dst_regimes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, month: int, day: int
) -> None:
    fires = _run_window_gate(monkeypatch, tmp_path, local_now=_at(month, day, 23))
    assert fires["proceed"] == "true"
    assert fires["dry_run"] == "false"
    # The other DST cron branch lands on the neighbouring local hour and skips.
    for other_hour in (22, 0):
        skipped = _run_window_gate(monkeypatch, tmp_path, local_now=_at(month, day, other_hour))
        assert skipped["proceed"] == "false"
        assert "outside the 23:00 America/New_York window" in skipped["reason"]


def test_the_schedule_is_inert_until_the_operator_arms_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for mode in ("disabled", ""):
        decision = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 15, 23), mode=mode)
        assert decision["proceed"] == "false"
        assert "NIGHTLY_AZURE_SHUTDOWN is disabled" in decision["reason"]


def test_dry_run_mode_arms_the_schedule_read_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    decision = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 15, 23), mode="dry_run")
    assert decision["proceed"] == "true"
    assert decision["dry_run"] == "true"


def test_an_unreadable_switch_leaves_azure_running(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    decision = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 15, 23), mode="yes-please")
    assert decision["proceed"] == "false"
    assert "Refusing to touch Azure on an unreadable switch" in decision["reason"]


def test_operator_can_skip_a_night_and_the_skip_expires_by_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    active = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 15, 23), skip_until="2026-06-16")
    assert active["proceed"] == "false"
    assert "operator skip is active until" in active["reason"]

    expired = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 17, 23), skip_until="2026-06-16")
    assert expired["proceed"] == "true"


def test_a_malformed_skip_value_fails_safe(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    decision = _run_window_gate(monkeypatch, tmp_path, local_now=_at(6, 15, 23), skip_until="next tuesday")
    assert decision["proceed"] == "false"
    assert "Failing safe: leaving Azure running tonight" in decision["reason"]


def test_manual_dispatch_bypasses_the_window_but_defaults_to_dry_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    decision = _run_window_gate(
        monkeypatch, tmp_path, local_now=_at(6, 15, 9), mode="disabled", event="workflow_dispatch"
    )
    assert decision["proceed"] == "true"
    assert decision["dry_run"] == "true"

    live = _run_window_gate(
        monkeypatch,
        tmp_path,
        local_now=_at(6, 15, 9),
        mode="disabled",
        event="workflow_dispatch",
        dispatch_dry_run="false",
    )
    assert live["proceed"] == "true"
    assert live["dry_run"] == "false"


GH_SHIM = """import json
import os
import sys

payload = json.loads(os.environ["KP_TEST_RUNS"])
uri = sys.argv[-1]
if os.environ.get("KP_TEST_GH_BROKEN") == "1":
    sys.stderr.write("gh: server error\\n")
    raise SystemExit(1)
for workflow, runs in payload.items():
    if workflow in uri:
        print(json.dumps({"workflow_runs": runs}))
        raise SystemExit(0)
sys.stderr.write("HTTP 404: Not Found\\n")
raise SystemExit(1)
"""


def _run_deploy_gate(
    tmp_path: Path, runs: dict[str, list[dict[str, object]]], *, broken: bool = False
) -> dict[str, str]:
    shim_dir = tmp_path / "ghbin"
    shim_dir.mkdir(exist_ok=True)
    implementation = shim_dir / "gh_impl.py"
    implementation.write_text(GH_SHIM, encoding="utf-8")
    launcher = shim_dir / "gh"
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(implementation))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    output = tmp_path / "deploy-gate-output"
    output.write_text("", encoding="utf-8")
    program = tmp_path / "deploy_gate.py"
    program.write_text(_embedded_program("Refuse while an Azure deployment is in flight"), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(program)],
        env={
            **os.environ,
            "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_REPOSITORY": "example-org/example-repo",
            "GITHUB_OUTPUT": str(output),
            "KP_TEST_RUNS": json.dumps(runs),
            "KP_TEST_GH_BROKEN": "1" if broken else "0",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if "=" in line)


def test_no_deployment_in_flight_allows_the_power_down(tmp_path: Path) -> None:
    decision = _run_deploy_gate(
        tmp_path,
        {
            "azure-deploy.yml": [{"status": "completed", "run_number": 41}],
            "provision-ci-runner.yml": [],
        },
    )
    assert decision["proceed"] == "true"


@pytest.mark.parametrize("status", ["in_progress", "queued", "waiting", "requested", "pending", "action_required"])
def test_a_deployment_in_flight_leaves_azure_running(tmp_path: Path, status: str) -> None:
    decision = _run_deploy_gate(
        tmp_path,
        {
            "azure-deploy.yml": [{"status": status, "run_number": 42}],
            "provision-ci-runner.yml": [],
        },
    )
    assert decision["proceed"] == "false"
    assert "a deployment is in flight" in decision["reason"]
    assert "azure-deploy.yml run 42" in decision["reason"]


def test_a_runner_provisioning_run_also_blocks_the_power_down(tmp_path: Path) -> None:
    decision = _run_deploy_gate(
        tmp_path,
        {
            "azure-deploy.yml": [],
            "provision-ci-runner.yml": [{"status": "in_progress", "run_number": 7}],
        },
    )
    assert decision["proceed"] == "false"
    assert "provision-ci-runner.yml run 7" in decision["reason"]


def test_an_unreadable_deploy_state_fails_safe(tmp_path: Path) -> None:
    decision = _run_deploy_gate(tmp_path, {"azure-deploy.yml": []}, broken=True)
    assert decision["proceed"] == "false"
    assert "could not confirm no deploy is in flight" in decision["reason"]


def test_a_workflow_that_never_ran_is_not_treated_as_in_flight(tmp_path: Path) -> None:
    decision = _run_deploy_gate(tmp_path, {"azure-deploy.yml": [{"status": "completed", "run_number": 1}]})
    assert decision["proceed"] == "true"


def test_a_failed_pre_stop_backup_leaves_postgres_running(tmp_path: Path) -> None:
    """No backup => no stop. An unstopped server costs money; an unbacked one costs data.

    A STOPPED Azure PostgreSQL flexible server takes NO automated backups — observed
    on the live server, where dailies ran 2026-09-01..09-05 and ceased the moment it
    was stopped. With 7-day retention, stopping nightly without a fresh restore point
    would quietly age the recovery window out to nothing, so the on-demand backup is a
    PRECONDITION of the stop, not a nicety.
    """
    result, calls = _run_script(
        tmp_path,
        inventory={
            "postgres": [
                {
                    "name": "psql-kp-staging-6117w",
                    "state": "Ready",
                    "application": PROJECT_TAG,
                    "environment": "staging",
                },
            ],
            "containerapp": [],
            "vm": [],
        },
        extra_env={"KP_TEST_FAIL_BACKUP": "1"},
    )

    joined = " ".join(calls)
    assert "backup create" in joined, "it must at least attempt the pre-stop backup"
    assert "flexible-server stop" not in joined, "it must NOT stop a server it could not back up"
    assert "leaving it running" in result.stdout


def test_the_pre_stop_backup_precedes_the_stop(tmp_path: Path) -> None:
    """Ordering matters: a restore point taken after the stop would be useless."""
    _, calls = _run_script(
        tmp_path,
        inventory={
            "postgres": [
                {
                    "name": "psql-kp-staging-6117w",
                    "state": "Ready",
                    "application": PROJECT_TAG,
                    "environment": "staging",
                },
            ],
            "containerapp": [],
            "vm": [],
        },
    )

    writes = _writes(calls)
    backup = next(i for i, c in enumerate(writes) if "backup create" in c)
    stop = next(i for i, c in enumerate(writes) if "flexible-server stop" in c)
    assert backup < stop, f"backup must precede stop, got {writes}"


def test_orphaned_replicas_on_superseded_revisions_are_reported_not_silently_skipped(
    tmp_path: Path,
) -> None:
    """`min-replicas 0` at the APP level does not mean nothing is billing.

    Under revision_mode="Multiple" every past deploy leaves its revision ACTIVE,
    each holding a replica pinned at the min_replicas it was born with; scaling the
    app does not touch them. On 2026-09-07 operator+tracking reported "min-replicas
    0" while 76 such replicas billed continuously (~$889/mo) and this script logged
    "already scaled down". It must never do that again.
    """
    result, _ = _run_script(
        tmp_path,
        inventory={
            "postgres": [],
            "containerapp": [
                {
                    "name": "ca-kp-staging-operator",
                    "minReplicas": 0,
                    "application": PROJECT_TAG,
                    "environment": "staging",
                    # two superseded revisions still holding a replica each
                    "orphanReplicas": [1, 1],
                },
            ],
            "vm": [],
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "BILLING on superseded revisions" in result.stdout
    assert "already at min-replicas 0" not in result.stdout, (
        "it must not claim the app is scaled down while replicas are billing"
    )
