from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.models import AggregationCandidate

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0039_aggregation_candidates.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0039", MIGRATION)
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


def test_migration_is_linked_into_the_chain() -> None:
    migration = _load_migration()
    assert migration.revision == "0039_aggregation_candidates"
    assert migration.down_revision == "0038_unique_constraint_naming"


def test_upgrade_creates_table_enum_indexes_and_least_privilege_grant() -> None:
    sql = _sql("upgrade")
    assert "CREATE TABLE aggregation_candidates" in sql
    assert "CREATE TYPE aggregation_review_state AS ENUM ('pending', 'promoted', 'dismissed')" in sql
    assert "ck_aggregation_candidates_rank_positive" in sql
    assert "ck_aggregation_candidates_score_unit" in sql
    assert "ix_aggregation_candidates_run" in sql
    assert "ix_aggregation_candidates_review" in sql
    # Least-privilege: only the operator role, granted conditionally, and no
    # broad PUBLIC access.
    assert "REVOKE ALL ON aggregation_candidates FROM PUBLIC" in sql
    assert "GRANT SELECT, INSERT, UPDATE ON aggregation_candidates TO kp_operator" in sql
    assert "TO PUBLIC" not in sql
    # Additive only.
    assert "DROP TABLE" not in sql
    assert "campaign_patterns" not in sql


def test_downgrade_is_a_clean_reversal() -> None:
    sql = _sql("downgrade")
    assert "DROP TABLE aggregation_candidates" in sql
    assert "DROP TYPE aggregation_review_state" in sql
    assert "DROP INDEX ix_aggregation_candidates_run" in sql
    assert "DROP INDEX ix_aggregation_candidates_review" in sql


def test_model_metadata_mirrors_the_migrated_table() -> None:
    """ORM metadata must reflect the landed database contract."""

    table = AggregationCandidate.__table__  # type: ignore[attr-defined]
    assert table.name == "aggregation_candidates"
    constraint_names = {str(c.name) for c in table.constraints}
    assert "ck_aggregation_candidates_rank_positive" in constraint_names
    assert "ck_aggregation_candidates_score_unit" in constraint_names
    index_names = {i.name for i in table.indexes}
    assert index_names == {"ix_aggregation_candidates_run", "ix_aggregation_candidates_review"}
    columns = set(table.columns.keys())
    assert {
        "aggregation_candidate_id",
        "run_id",
        "rank",
        "score",
        "title",
        "model_id",
        "record",
        "source_item_ids",
        "created_at",
        "review_state",
        "reviewed_at",
        "reviewed_by",
        "promoted_pattern_id",
    } <= columns
