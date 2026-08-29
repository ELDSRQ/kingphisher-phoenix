from __future__ import annotations

import importlib.util
import re
from io import StringIO
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.models import Campaign, TrainingResource

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0026_training_resource_library.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0026", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_training_library_migration_is_linear_and_preserves_legacy_assignments() -> None:
    migration = _load()
    assert migration.revision == "0026_training_resource_library"
    assert migration.down_revision == "0025_campaign_programs"
    source = MIGRATION.read_text(encoding="utf-8")
    assert "SELECT DISTINCT ON (campaign_id)" in source
    assert "ORDER BY campaign_id, assigned_at, training_assignment_id" in source
    assert "DELETE FROM training_assignments" not in source
    assert "UPDATE training_assignments" not in source
    assert 'ondelete="RESTRICT"' in source


def test_training_library_model_metadata_matches_migration_contract() -> None:
    assert Campaign.__table__.c.training_resource_id.nullable
    foreign_key = next(iter(Campaign.__table__.c.training_resource_id.foreign_keys))
    assert foreign_key.target_fullname == "training_resources.training_resource_id"
    assert foreign_key.ondelete == "RESTRICT"
    assert {
        "ck_training_resources_title_bounded",
        "ck_training_resources_content_bounded",
        "ck_training_resources_source_ref_bounded",
        "ck_training_resources_version_positive",
    } <= {str(constraint.name) for constraint in TrainingResource.__table__.constraints}
    assert {"created_by", "created_at", "submitted_at", "reviewed_by", "reviewed_at", "review_rationale"} <= {
        column.name for column in TrainingResource.__table__.columns
    }


def test_training_library_schema_identifiers_fit_postgres_limit() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    names = re.findall(r'"((?:ck|fk)_[a-z0-9_]+)"', source)
    assert names
    assert all(len(name) <= 63 for name in names)


def test_training_bounds_compile_not_valid_and_preserve_legacy_rows() -> None:
    migration = _load()
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)

    migration.upgrade()

    sql = output.getvalue()
    for constraint in (
        "ck_training_resources_title_bounded",
        "ck_training_resources_content_bounded",
        "ck_training_resources_source_ref_bounded",
        "ck_training_resources_version_positive",
    ):
        statement = next(line for line in sql.splitlines() if f"ADD CONSTRAINT {constraint}" in line)
        assert " CHECK " in statement
        assert statement.rstrip().endswith("NOT VALID;")
    assert sql.count("NOT VALID") == 4
    assert "VALIDATE CONSTRAINT" not in sql
    assert "UPDATE training_resources" not in sql
    assert "DELETE FROM training_resources" not in sql
