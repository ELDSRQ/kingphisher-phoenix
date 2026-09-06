"""Adversarial static contracts for the privileged audit boundary."""

from __future__ import annotations

from pathlib import Path

from kp_database import grants

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (ROOT / "packages/database/alembic/versions/0020_transactional_audit_outbox.py").read_text()
BOOTSTRAP = (ROOT / "scripts/azure_migrate.py").read_text()


def test_dispatch_functions_are_security_definer_with_fixed_search_path() -> None:
    assert MIGRATION.count("SECURITY DEFINER") >= 6
    assert MIGRATION.count("SET search_path = pg_catalog, public") >= 6
    assert "REVOKE ALL ON FUNCTION kp_dispatch_audit_outbox" in MIGRATION
    assert "FROM PUBLIC" in MIGRATION
    assert "pg_advisory_xact_lock(1263551049)" in MIGRATION


def test_no_generic_arbitrary_body_append_or_runtime_owner_bypass() -> None:
    # Dispatch consumes a previously committed row by opaque identifier. It
    # never accepts actor/action/detail as direct function parameters.
    assert "FUNCTION kp_dispatch_audit_outbox(p_outbox_id uuid)" in MIGRATION
    assert "FUNCTION kp_append_audit" not in MIGRATION
    assert "CREATE ROLE audit_owner NOLOGIN" in BOOTSTRAP
    assert "OWNER TO audit_owner" in BOOTSTRAP
    assert "GRANT audit_owner TO" in BOOTSTRAP
    assert "GRANT audit_owner TO kp_" not in BOOTSTRAP


def test_privileged_bootstrap_does_not_rely_on_optimization_removable_asserts() -> None:
    assert "assert raw is not None" not in BOOTSTRAP
    assert "if raw is None:" in BOOTSTRAP
    assert "database driver connection is unavailable" in BOOTSTRAP


def test_runtime_roles_can_stage_only_caller_controlled_intent_columns() -> None:
    # AUD-002: the intent-column allowlist now lives in the single source of
    # truth (kp_database.grants). The adversarial guarantee is unchanged — only
    # caller-controlled columns are grantable; origin_role and status (the
    # provenance/dispatch fields) are NEVER in the INSERT allowlist.
    assert grants.OUTBOX_INSERT_COLUMNS == (
        "outbox_id",
        "kind",
        "topic",
        "payload",
        "idempotency_key",
        "available_at",
    )
    assert "origin_role" not in grants.OUTBOX_INSERT_COLUMNS
    assert "status" not in grants.OUTBOX_INSERT_COLUMNS
    # ...and the bootstrap must emit exactly that allowlist verbatim (identical
    # to the historical literal), assembled from the shared constant.
    expected = "GRANT INSERT (" + ", ".join(grants.OUTBOX_INSERT_COLUMNS) + ")"
    assert expected == "GRANT INSERT (outbox_id, kind, topic, payload, idempotency_key, available_at)"
    assert "OUTBOX_INSERT_COLUMNS" in BOOTSTRAP  # bootstrap consumes the shared allowlist
    assert "GRANT UPDATE ON TABLE audit_events" not in BOOTSTRAP
    assert "GRANT DELETE ON TABLE audit_events" not in BOOTSTRAP
    assert "GRANT TRUNCATE ON TABLE audit_events" not in BOOTSTRAP
    assert "GRANT SELECT ON TABLE audit_events, audit_chain_head TO audit_writer" in BOOTSTRAP


def test_dispatcher_rejects_self_authored_evidence_and_exposes_reconciliation() -> None:
    assert "intent.origin_role IN ('audit_writer', 'audit_owner')" in MIGRATION
    assert "kp_outbox_health" in MIGRATION
    assert "status IN ('pending', 'failed')" in MIGRATION
    assert "FOR UPDATE SKIP LOCKED" in MIGRATION


def test_health_distinguishes_future_schedules_from_overdue_backlog() -> None:
    assert "overdue_pending bigint" in MIGRATION
    assert "scheduled_or_fresh bigint" in MIGRATION
    assert "available_at <= now() - interval '1 minute'" in MIGRATION
    assert "available_at > now() - interval '1 minute'" in MIGRATION
