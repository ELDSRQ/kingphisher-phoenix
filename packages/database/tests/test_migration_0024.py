from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from kp_database.models import (
    CampaignAudience,
    CampaignAudienceManifest,
    DeliveryProviderEvent,
    DeliveryReportCorrelation,
    RecipientAssignment,
    TrackingToken,
    TrainingAssignment,
    TransactionalOutbox,
)

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0024_database_relationship_invariants.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0024", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _CleanConnection:
    def __init__(self, *, violation_at: int | None = None, count: int = 1) -> None:
        self.queries: list[str] = []
        self.violation_at = violation_at
        self.count = count

    def scalar(self, statement) -> int:  # noqa: ANN001
        self.queries.append(str(statement))
        if self.violation_at == len(self.queries):
            return self.count
        return 0


def test_upgrade_preflights_before_adding_exact_relationships(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load()
    connection = _CleanConnection()
    unique_constraints: list[tuple[str, str, tuple[str, ...]]] = []
    foreign_keys: list[tuple[str, str, str, tuple[str, ...], tuple[str, ...], str | None]] = []
    checks: list[tuple[str, str, str]] = []

    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(
        migration.op,
        "create_unique_constraint",
        lambda name, table, columns: unique_constraints.append((name, table, tuple(columns))),
    )
    monkeypatch.setattr(
        migration.op,
        "create_foreign_key",
        lambda name, source, target, local, remote, **kwargs: foreign_keys.append(
            (name, source, target, tuple(local), tuple(remote), kwargs.get("ondelete"))
        ),
    )
    monkeypatch.setattr(
        migration.op,
        "create_check_constraint",
        lambda name, table, condition: checks.append((name, table, condition)),
    )

    migration.upgrade()

    assert migration.revision == "0024_database_invariants"
    assert migration.down_revision == "0023_acs_delivery_receipts"
    assert len(connection.queries) == 7
    assert (
        "fk_tracking_tokens_assignment_campaign",
        "tracking_tokens",
        "recipient_assignments",
        ("recipient_assignment_id", "campaign_id"),
        ("recipient_assignment_id", "campaign_id"),
        "CASCADE",
    ) in foreign_keys
    assert (
        "fk_training_assignments_recipient_identity",
        "training_assignments",
        "recipient_assignments",
        ("recipient_assignment_id", "campaign_id", "recipient_id"),
        ("recipient_assignment_id", "campaign_id", "recipient_id"),
        "CASCADE",
    ) in foreign_keys
    assert (
        "fk_campaign_audience_manifest_version",
        "campaign_audience_manifest",
        "campaign_audiences",
        ("campaign_id", "audience_version"),
        ("campaign_id", "version"),
        "CASCADE",
    ) in foreign_keys
    assert (
        "fk_delivery_provider_events_attempt_binding",
        "delivery_provider_events",
        "delivery_report_correlations",
        ("recipient_assignment_id", "delivery_attempt_id"),
        ("recipient_assignment_id", "delivery_attempt_id"),
        "CASCADE",
    ) in foreign_keys
    assert (
        "uq_recipient_assignments_identity_binding",
        "recipient_assignments",
        ("recipient_assignment_id", "campaign_id", "recipient_id"),
    ) in unique_constraints
    assert {name for name, _table, _condition in checks} == {
        "ck_recipient_assignments_attempt_count_nonnegative",
        "ck_transactional_outbox_topic_matches_kind",
        "ck_transactional_outbox_attempts_nonnegative",
    }


def test_preflight_fails_without_mutating_contradictory_history(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load()
    connection = _CleanConnection(violation_at=2, count=3)
    mutations: list[str] = []
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(
        migration.op,
        "create_unique_constraint",
        lambda name, *_args, **_kwargs: mutations.append(name),
    )

    with pytest.raises(
        RuntimeError,
        match=r"training assignment recipient/campaign binding has 3 contradictory row\(s\)",
    ):
        migration.upgrade()

    assert mutations == []
    source = MIGRATION.read_text(encoding="utf-8").upper()
    assert "DELETE FROM" not in source
    assert "UPDATE " not in source


def _constraint_names(model) -> set[str]:  # noqa: ANN001
    return {str(constraint.name) for constraint in model.__table__.constraints}


def test_model_metadata_matches_migration_invariants() -> None:
    assert "uq_campaign_audiences_version_binding" in _constraint_names(CampaignAudience)
    assert "fk_campaign_audience_manifest_version" in _constraint_names(CampaignAudienceManifest)
    assert "fk_tracking_tokens_assignment_campaign" in _constraint_names(TrackingToken)
    assert "uq_recipient_assignments_campaign_binding" in _constraint_names(RecipientAssignment)
    assert "uq_recipient_assignments_identity_binding" in _constraint_names(RecipientAssignment)
    assert "ck_recipient_assignments_attempt_count_nonnegative" in _constraint_names(RecipientAssignment)
    assert "uq_delivery_report_correlations_attempt_binding" in _constraint_names(DeliveryReportCorrelation)
    assert "fk_delivery_provider_events_attempt_binding" in _constraint_names(DeliveryProviderEvent)
    assert "fk_training_assignments_recipient_identity" in _constraint_names(TrainingAssignment)
    assert "ck_transactional_outbox_topic_matches_kind" in _constraint_names(TransactionalOutbox)
    assert "ck_transactional_outbox_attempts_nonnegative" in _constraint_names(TransactionalOutbox)


def test_constraints_use_portable_sql_expressions() -> None:
    outbox_checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in TransactionalOutbox.__table__.constraints
        if hasattr(constraint, "sqltext")
    }
    assignment_checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in RecipientAssignment.__table__.constraints
        if hasattr(constraint, "sqltext")
    }

    assert "length(trim(topic)) > 0" in outbox_checks["ck_transactional_outbox_topic_matches_kind"]
    assert outbox_checks["ck_transactional_outbox_attempts_nonnegative"] == "attempts >= 0"
    assert assignment_checks["ck_recipient_assignments_attempt_count_nonnegative"] == "delivery_attempt_count >= 0"
