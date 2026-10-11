from __future__ import annotations

import importlib.util
from io import StringIO
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.base import metadata


def test_direct_migration_backfills_legacy_policy_and_retains_canary_evidence_constraints() -> None:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0043_reviewed_direct_campaigns.py"
    spec = importlib.util.spec_from_file_location("migration_0043", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={
            "as_sql": True,
            "output_buffer": output,
            "target_metadata": metadata,
        },
    )
    module.op = Operations(context)
    module.upgrade()
    sql = output.getvalue()
    assert module.down_revision == "0042_campaign_created_at"
    assert "DEFAULT 'canary' NOT NULL" in sql
    assert "direct_published" in sql and "canary_succeeded_at IS NULL" in sql
    assert "DROP TABLE" not in sql and "DELETE" not in sql and "UPDATE" not in sql
    assert "DROP CONSTRAINT ck_campaign_launch_gates_ck_campaign_launch_success_evidence" not in sql
