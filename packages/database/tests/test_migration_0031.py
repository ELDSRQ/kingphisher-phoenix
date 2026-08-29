from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.models import AwarenessLedgerEntry, TrackingEvent

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0031_awareness_ledger.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0031", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_is_linear_additive_pii_free_and_retention_bounded() -> None:
    migration = _load_migration()
    assert migration.revision == "0031_awareness_ledger"
    assert migration.down_revision == "0030_default_privacy_notice"

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)  # type: ignore[attr-defined]
    migration.upgrade()
    sql = output.getvalue()

    assert "awareness_ledger_entries" in sql
    assert "uq_events_human_interaction_dedup" in sql
    assert "HUMAN_INTERACTION_CONFIRMED" in sql
    assert "retain_until = campaign_date + 1826" in sql
    assert "no_activity_at_close" in sql
    assert "REVOKE ALL ON awareness_ledger_entries FROM PUBLIC" in sql
    assert "operator" not in sql
    assert "mailbox" not in sql
    assert "display_name" not in sql
    assert "department" not in sql
    assert "recipient_id" not in sql
    assert "DELETE FROM" not in sql
    assert "UPDATE events" not in sql


def test_models_keep_confirmed_interaction_distinct_and_ledger_unlinked_from_pii() -> None:
    event_index = next(
        item
        for item in TrackingEvent.__table__.indexes  # type: ignore[attr-defined]
        if item.name == "uq_events_human_interaction_dedup"
    )
    assert event_index.unique is True
    assert str(event_index.dialect_options["postgresql"]["where"]) == ("event_type = 'HUMAN_INTERACTION_CONFIRMED'")

    table = AwarenessLedgerEntry.__table__  # type: ignore[attr-defined]
    column_names = set(table.c.keys())
    assert not ({"recipient_id", "recipient_assignment_id", "mailbox", "display_name", "department"} & column_names)
    assert not table.foreign_keys
    assert {
        "assignment_exposure_pseudonym",
        "targeted",
        "accepted",
        "delivered",
        "observed_click",
        "reported",
        "confirmed_interaction",
    } <= column_names
    assert {
        "training_assigned",
        "training_completed",
        "training_passed",
        "no_activity_at_close",
        "retain_until",
    } <= column_names
