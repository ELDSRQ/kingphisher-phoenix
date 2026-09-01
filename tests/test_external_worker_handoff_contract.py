"""Prevent handoff guidance from drifting back to the shared Docker engine."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

HANDOFFS = (
    "README.md",
    "RESUME-HERE.md",
    "RUNBOOK.md",
    "QA_TASKS.md",
    "AGENTS.md",
    "docs/AI_HANDOFF.md",
    "docs/NEXT_SESSION_HANDOFF.md",
    "docs/WAVE-BUILD-PLAN.md",
    "docs/AZURE_DEPLOYMENT.md",
    "docs/REMEDIATION_PLAN.md",
    "docs/architecture/README.md",
    "scripts/operator/remote-docker-worker/README.md",
)

EXTERNAL_ROOT = "/Volumes/DockerExternal/KingPhisher-Phoenix"
CANONICAL_REMOTE_SOURCE = "/Users/edierks/Projects/kingphisher-phoenix"
SAFE_CONTEXT_ENDPOINT = (
    "ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock"
)
WORKFLOW_SHA256 = "32c9d13a8dee21dc0d9fe5308e6a3180b7391d7275aa91d033281bc8ddafc873"
EXTERNAL_CONTEXT_PROOF = "colima-kingphisher|aarch64|/var/lib/docker"
VALIDATED_SNAPSHOT = "20260829T013332Z-tsX1WQ"
VALIDATED_SNAPSHOT_SHA256 = "e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff"
REMOTE_MAIN_SHA = "1403d944a40214714b6cbfcf5cbabc4fa7225eb9"

CURRENT_STATE_HANDOFFS = (
    "README.md",
    "RESUME-HERE.md",
    "RUNBOOK.md",
    "QA_TASKS.md",
    "AGENTS.md",
    "docs/AI_HANDOFF.md",
    "docs/NEXT_SESSION_HANDOFF.md",
    "docs/WAVE-BUILD-PLAN.md",
    "docs/AZURE_DEPLOYMENT.md",
    "docs/REMEDIATION_PLAN.md",
    "docs/architecture/README.md",
    "scripts/operator/remote-docker-worker/README.md",
    "docs/PRODUCTION-READINESS-TASK-MATRIX.md",
)

AZURE_HANDOFFS = (
    "README.md",
    "RESUME-HERE.md",
    "RUNBOOK.md",
    "docs/AI_HANDOFF.md",
    "docs/NEXT_SESSION_HANDOFF.md",
    "docs/WAVE-BUILD-PLAN.md",
    "docs/AZURE_DEPLOYMENT.md",
    "docs/REMEDIATION_PLAN.md",
    "docs/architecture/README.md",
    "docs/PRODUCTION-READINESS-TASK-MATRIX.md",
)

TEST_ISOLATION_HANDOFFS = (
    "README.md",
    "RESUME-HERE.md",
    "RUNBOOK.md",
    "QA_TASKS.md",
    "docs/AI_HANDOFF.md",
    "docs/NEXT_SESSION_HANDOFF.md",
    "docs/WAVE-BUILD-PLAN.md",
    "docs/AZURE_DEPLOYMENT.md",
    "docs/REMEDIATION_PLAN.md",
    "docs/architecture/README.md",
    "docs/PRODUCTION-READINESS-TASK-MATRIX.md",
)


def test_every_handoff_names_the_exact_external_worker_identity() -> None:
    for relative_path in HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "192.168.1.140" in source, relative_path
        assert EXTERNAL_ROOT in source, relative_path
        assert "kingphisher" in source and "Colima" in source, relative_path


def test_every_handoff_preserves_the_shared_docker_desktop_boundary() -> None:
    for relative_path in HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "Docker Desktop" in source, relative_path
        assert "shared" in source.lower(), relative_path


def test_operational_handoffs_keep_external_selection_fail_closed() -> None:
    for relative_path in (
        "README.md",
        "RESUME-HERE.md",
        "RUNBOOK.md",
        "AGENTS.md",
        "docs/AI_HANDOFF.md",
        "docs/NEXT_SESSION_HANDOFF.md",
        "docs/WAVE-BUILD-PLAN.md",
        "docs/architecture/README.md",
        "scripts/operator/remote-docker-worker/README.md",
        "docs/PRODUCTION-READINESS-TASK-MATRIX.md",
    ):
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").lower()
        assert "fallback" in source, relative_path
        assert "desktop-linux" in source, relative_path


def test_every_handoff_records_the_proven_inactive_controller_context() -> None:
    for relative_path in HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "kp-external-mac" in source, relative_path
        assert SAFE_CONTEXT_ENDPOINT in source, relative_path
        assert EXTERNAL_CONTEXT_PROOF in source, relative_path
        assert "desktop-linux" in source, relative_path


def test_every_handoff_keeps_native_arm64_emulation_free() -> None:
    for relative_path in HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "ARM64" in source or "arm64" in source, relative_path
        assert "Rosetta" in source, relative_path
        assert "binfmt" in source, relative_path


def test_handoffs_explicitly_quarantine_legacy_remote_desktop_contexts() -> None:
    for relative_path in HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").lower()
        assert "legacy" in source, relative_path
        assert "`dockerexternal`" in source, relative_path
        assert "`kp-remote-mac`" in source, relative_path
        assert "never use" in source or "never be used" in source or "must not be used" in source, relative_path


def test_every_handoff_names_canonical_remote_source_and_read_only_target() -> None:
    for relative_path in CURRENT_STATE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert CANONICAL_REMOTE_SOURCE in source, relative_path
        assert "read-only" in source.lower(), relative_path


def test_handoffs_do_not_restore_stale_pre_cutover_claims() -> None:
    forbidden_claims = (
        "capacity now belongs to the isolated external worker",
        "capacity work has moved to the isolated external worker",
        "current execution capacity belongs to the isolated external worker",
        "the stopped internal project copy",
        "its stopped project copy",
        "cutover is still in progress",
        "cutover is not complete",
        "external profile is still provisioning",
        "no new applied/staged checkpoint",
        "external capacity remains planned",
        "external capacity is not current",
        "external build/local-live capacity remains planned",
        "external execution capacity remains planned",
        "external-worker cutover, exact-final",
        "finish the external-worker cutover",
        "finish the canonical-source external-worker cutover",
        "finish the preservation-first external-worker cutover",
        "internal seven-container project stack is still running",
        "ext-002 remains open",
    )
    for relative_path in CURRENT_STATE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").lower()
        for forbidden_claim in forbidden_claims:
            assert forbidden_claim not in source, (relative_path, forbidden_claim)


def test_operational_handoffs_preserve_current_recovery_truth() -> None:
    for relative_path in (
        "README.md",
        "RESUME-HERE.md",
        "RUNBOOK.md",
        "AGENTS.md",
        "docs/AI_HANDOFF.md",
        "docs/NEXT_SESSION_HANDOFF.md",
        "docs/WAVE-BUILD-PLAN.md",
        "docs/architecture/README.md",
        "scripts/operator/remote-docker-worker/README.md",
        "docs/PRODUCTION-READINESS-TASK-MATRIX.md",
    ):
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").lower()
        assert "seven" in source and "docker desktop" in source, relative_path
        assert "legacy" in source and "unrecoverable" in source, relative_path
        assert "ext-002" in source, relative_path


def test_operational_handoffs_record_the_proven_cutover_checkpoint() -> None:
    for relative_path in CURRENT_STATE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert VALIDATED_SNAPSHOT in source, relative_path
        assert VALIDATED_SNAPSHOT_SHA256 in source, relative_path


def test_current_handoffs_keep_install_verification_bounded_by_no_go() -> None:
    for relative_path in CURRENT_STATE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "verify_install" in source, relative_path
        assert "NO-GO" in source, relative_path


def test_recovery_runbooks_name_the_controller_checkpoint_and_stage_chain() -> None:
    for relative_path in (
        "README.md",
        "RUNBOOK.md",
        "AGENTS.md",
        "docs/AI_HANDOFF.md",
        "docs/NEXT_SESSION_HANDOFF.md",
        "docs/WAVE-BUILD-PLAN.md",
        "docs/architecture/README.md",
        "scripts/operator/remote-docker-worker/README.md",
    ):
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "checkpoint-remote.sh" in source, relative_path
        assert "stage-remote.sh" in source, relative_path
        assert "stage-checkpoint.sh" in source, relative_path
        assert "restore-state.sh" in source, relative_path
        assert "migration-checkpoint/" in source, relative_path


def test_azure_handoffs_use_exact_three_stage_frozen_workflow() -> None:
    for relative_path in AZURE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "foundation_bootstrap" in source, relative_path
        assert "foundation_finalize" in source, relative_path
        assert "workloads" in source, relative_path
        assert WORKFLOW_SHA256 in source, relative_path


def test_azure_handoffs_describe_complete_targetless_bootstrap_boundary() -> None:
    for relative_path in AZURE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        lowered = source.lower()
        assert "deploy_workloads=false" in source, relative_path
        assert "terraform targets" in lowered, relative_path
        assert "delete/replacement" in lowered or "deletion/replacement" in lowered, relative_path
        assert "sender/association" in lowered or "association/sender" in lowered, relative_path


def test_azure_handoffs_record_current_read_only_github_boundary() -> None:
    for relative_path in AZURE_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        lowered = source.lower()
        assert "ELDSRQ/kingphisher-phoenix" in source, relative_path
        assert REMOTE_MAIN_SHA in source, relative_path
        assert "zero environments" in lowered, relative_path
        assert "variables" in lowered and "secrets" in lowered, relative_path
        assert "no workflow dispatch/run" in lowered, relative_path


def test_current_handoffs_preserve_integration_redis_database_isolation() -> None:
    for relative_path in TEST_ISOLATION_HANDOFFS:
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        assert "DB14" in source, relative_path
        assert "DB15" in source, relative_path
        assert "DB0" in source, relative_path
        assert "flush only DB14" in source or "only DB14 flushed" in source or "flushes only DB14" in source, (
            relative_path
        )


def test_current_counts_are_labeled_as_pre_wave_30_history() -> None:
    for relative_path in (
        "README.md",
        "RESUME-HERE.md",
        "RUNBOOK.md",
        "docs/AI_HANDOFF.md",
        "docs/NEXT_SESSION_HANDOFF.md",
        "docs/WAVE-BUILD-PLAN.md",
        "docs/AZURE_DEPLOYMENT.md",
        "docs/REMEDIATION_PLAN.md",
        "docs/architecture/README.md",
    ):
        source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8").lower()
        if "1,994" in source:
            assert "pre-wave-30" in source, relative_path
            assert "historical" in source, relative_path
