"""Offline contract for fail-closed managed worker health qualification."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "azure-deploy.yml").read_text(encoding="utf-8")


def _worker_gate() -> str:
    start = WORKFLOW.index("- name: Qualify every managed worker role")
    end = WORKFLOW.index("- name: Checkpoint migration and health qualification", start)
    return WORKFLOW[start:end]


def test_worker_gate_precedes_the_shared_healthy_checkpoint() -> None:
    migration = WORKFLOW.index("- name: Migrate and qualify")
    workers = WORKFLOW.index("- name: Qualify every managed worker role")
    checkpoint = WORKFLOW.index("- name: Checkpoint migration and health qualification")

    assert migration < workers < checkpoint
    assert "KP_HEALTH_RESULT: passed" in WORKFLOW[checkpoint:]


def test_worker_gate_binds_every_terraform_target_to_current_revision_telemetry() -> None:
    gate = _worker_gate()

    for required in (
        "managed_worker_health_targets",
        "log_analytics_workspace_customer_id",
        '"az", "containerapp", "revision", "list"',
        "properties.active",
        'healthState", "")).lower() != "healthy"',
        'provisioningState", "")).lower() != "provisioned"',
        "ContainerAppConsoleLogs_CL",
        'tostring(payload.event) == "worker_role_readiness"',
        "arg_max(TimeGenerated, ready, reason) by role",
        "target for target in all_targets if observed.get(target) is not True",
        "stable_passes < 2",
        "healthy_revision(app_name) != revision_name",
    ):
        assert required in gate


def test_worker_gate_is_bounded_and_does_not_echo_provider_logs() -> None:
    gate = _worker_gate()

    assert "MAX_RESPONSE_BYTES = 65_536" in gate
    assert "timeout=60" in gate
    assert "KP_WORKER_HEALTH_TIMEOUT_SECONDS: 600" in gate
    assert "len(rows) > 16" in gate
    assert "result.stderr" not in gate
    assert "Log_s" in gate
    assert "print(Log_s)" not in gate
