from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.models import RetentionPolicy

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0032_source_explicit_curation.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0032", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sql(action: str) -> str:
    migration = _load_migration()
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)  # type: ignore[attr-defined]
    getattr(migration, action)()
    return output.getvalue()


def test_upgrade_is_linear_additive_and_quarantines_only_preexisting_active_items() -> None:
    migration = _load_migration()
    assert migration.revision == "0032_source_explicit_curation"
    assert migration.down_revision == "0031_awareness_ledger"

    sql = _sql("upgrade")
    assert "UPDATE source_items" in sql
    assert "quarantine_state = 'QUARANTINED'" in sql
    assert "WHERE quarantine_state = 'ACTIVE'" in sql
    assert "upgrade_review_required_v1" in sql
    assert "DELETE" not in sql
    assert "campaign_patterns" not in sql
    assert "retention_days BETWEEN 1 AND 365" in sql
    assert "CREATE UNIQUE INDEX uq_retention_policies_single_default" in sql
    assert "WHERE is_default IS TRUE" in sql


def test_downgrade_restores_only_untouched_migration_tagged_rows() -> None:
    sql = _sql("downgrade")

    assert "quarantine_state = 'ACTIVE'" in sql
    assert "quarantine_state = 'QUARANTINED'" in sql
    assert "quarantine_reason = 'upgrade_review_required_v1'" in sql
    assert "duplicate_of IS NULL" in sql
    assert "DELETE" not in sql
    assert "DROP INDEX uq_retention_policies_single_default" in sql
    assert "DROP CONSTRAINT days_bounded" in sql


def test_model_metadata_mirrors_migration_retention_constraints() -> None:
    """ORM metadata must reflect migration 0032's landed database contract."""

    table = RetentionPolicy.__table__  # type: ignore[attr-defined]
    constraint_names = {str(constraint.name) for constraint in table.constraints}
    assert "ck_retention_policies_days_bounded" in constraint_names
    check = next(
        constraint for constraint in table.constraints if str(constraint.name) == "ck_retention_policies_days_bounded"
    )
    assert " ".join(str(check.sqltext).split()) == "retention_days BETWEEN 1 AND 365"

    index = next(
        item
        for item in table.indexes  # type: ignore[attr-defined]
        if item.name == "uq_retention_policies_single_default"
    )
    assert index.unique is True
    assert [column.name for column in index.columns] == ["is_default"]
    assert str(index.dialect_options["postgresql"]["where"]) == "is_default IS TRUE"
