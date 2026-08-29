from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0030_default_privacy_notice.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0030", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_is_linear_preserves_notices_and_publishes_a_default() -> None:
    migration = _load_migration()
    assert migration.revision == "0030_default_privacy_notice"
    assert migration.down_revision == "0029_campaign_canary_gate"

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)  # type: ignore[attr-defined]
    migration.upgrade()
    sql = output.getvalue()

    assert "row_number() OVER" in sql
    assert "uq_privacy_notices_single_current" in sql
    assert "WHERE NOT EXISTS" in sql
    assert migration._DEFAULT_NOTICE_ID == "00000000-0000-4000-8000-000000000030"
    assert "365 days" in migration._DEFAULT_NOTICE
    assert "DROP TABLE" not in sql
    assert "DELETE FROM" not in sql


def test_model_enforces_at_most_one_current_privacy_notice() -> None:
    from kp_database.models import PrivacyNotice

    index = next(
        item
        for item in PrivacyNotice.__table__.indexes  # type: ignore[attr-defined]
        if item.name == "uq_privacy_notices_single_current"
    )
    assert index.unique is True
    assert str(index.dialect_options["postgresql"]["where"]) == "is_current IS TRUE"
