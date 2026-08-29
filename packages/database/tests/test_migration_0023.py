from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from kp_database.models import DeliveryProviderEvent, RecipientDeliverySuppression

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0023_acs_delivery_receipts.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0023", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_adds_receipt_suppression_and_pacing_state(monkeypatch) -> None:  # noqa: ANN001
    migration = _load()
    tables: list[str] = []
    indexes: list[tuple[str, bool]] = []
    monkeypatch.setattr(migration.op, "create_table", lambda name, *_args, **_kwargs: tables.append(name))
    monkeypatch.setattr(
        migration.op,
        "create_index",
        lambda name, *_args, **kwargs: indexes.append((name, bool(kwargs.get("unique")))),
    )

    migration.upgrade()

    assert migration.down_revision == "0022_m365_integration"
    assert tables == [
        "delivery_provider_events",
        "recipient_delivery_suppressions",
        "delivery_pacing_states",
    ]
    assert ("uq_delivery_report_correlations_provider_id", True) in indexes


def test_receipt_schema_contains_no_mailbox_or_raw_diagnostic_column() -> None:
    receipt_columns = set(DeliveryProviderEvent.__table__.c.keys())
    suppression_columns = set(RecipientDeliverySuppression.__table__.c.keys())

    assert "recipient_assignment_id" in receipt_columns
    assert "status_detail_hash" in receipt_columns
    assert not {"mailbox", "recipient", "sender", "status_detail"} & receipt_columns
    assert not {"mailbox", "recipient", "sender"} & suppression_columns
