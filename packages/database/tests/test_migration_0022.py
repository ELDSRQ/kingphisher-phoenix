from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from kp_database.models import (
    DeliveryReportCorrelation,
    Microsoft365IntegrationState,
    ReportedMailReceipt,
)

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0022_microsoft365_integration_state.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0022", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_chains_after_frozen_audiences_and_adds_fk_integrity(monkeypatch) -> None:  # noqa: ANN001
    migration = _load()
    tables: list[str] = []
    foreign_keys: list[str] = []
    unique_constraints: list[str] = []
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "add_column", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(migration.op, "alter_column", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(migration.op, "create_index", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        migration.op,
        "create_unique_constraint",
        lambda name, *_args, **_kwargs: unique_constraints.append(name),
    )
    monkeypatch.setattr(migration.op, "create_table", lambda name, *_args, **_kwargs: tables.append(name))
    monkeypatch.setattr(migration.op, "create_foreign_key", lambda name, *_args, **_kwargs: foreign_keys.append(name))
    monkeypatch.setattr(migration.op, "execute", lambda statement: statements.append(str(statement)))

    migration.upgrade()

    assert migration.down_revision == "0021_frozen_campaign_audiences"
    assert migration.revision == "0022_m365_integration"
    assert tables == [
        "microsoft365_integration_states",
        "delivery_report_correlations",
        "reported_mail_receipts",
    ]
    assert foreign_keys == ["fk_events_recipient_assignment"]
    assert "uq_recipient_assignments_attempt_binding" in unique_constraints
    assert "directory_group_ref = NULL" in "\n".join(statements)
    source = MIGRATION.read_text()
    assert source.count('ondelete="SET NULL"') >= 3
    assert 'ondelete="CASCADE"' in source
    assert "fk_delivery_report_correlation_attempt" in source
    assert "ck_m365_integration_pending_preview" in source
    assert "ck_m365_integration_mailbox_lease" in source


def test_sensitive_persistence_columns_use_ciphertext_mapping() -> None:
    assert Microsoft365IntegrationState.__table__.c.cursor.type.__class__.__name__ == "CipherText"
    assert Microsoft365IntegrationState.__table__.c.pending_payload.type.__class__.__name__ == "CipherText"
    assert DeliveryReportCorrelation.__table__.c.report_verifier.type.__class__.__name__ == "CipherText"
    assert ReportedMailReceipt.__table__.c.external_id.type.__class__.__name__ == "CipherText"
