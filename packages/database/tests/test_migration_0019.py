"""Training remediation migration contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0019_training_remediation_loop.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0019", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_backfills_progress_and_adds_dedup_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    columns: list[str] = []
    constraints: list[str] = []
    indexes: list[str] = []
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "add_column", lambda _table, column: columns.append(column.name))
    monkeypatch.setattr(migration.op, "alter_column", lambda *args, **kwargs: None)
    monkeypatch.setattr(migration.op, "create_foreign_key", lambda *args, **kwargs: constraints.append(args[0]))
    monkeypatch.setattr(migration.op, "create_unique_constraint", lambda name, *args: constraints.append(name))
    monkeypatch.setattr(migration.op, "create_check_constraint", lambda name, *args: constraints.append(name))
    monkeypatch.setattr(migration.op, "create_index", lambda name, *args, **kwargs: indexes.append(name))
    monkeypatch.setattr(migration.op, "execute", lambda statement: statements.append(str(statement)))

    migration.upgrade()

    assert {
        "recipient_assignment_id",
        "opened_at",
        "due_at",
        "access_expires_at",
        "training_token_hash",
        "training_completion_token_hash",
    } <= set(columns)
    assert "uq_training_assignment_recipient_assignment" in constraints
    assert "uq_events_training_dedup" in indexes
    sql = " ".join(statements).upper()
    assert "72 HOURS" in sql
    assert "90 DAYS" in sql
    assert "STATUS = 'STARTED'" in sql
    assert "'REMINDED', 'EXPIRED'" not in sql
    assert "ROW_NUMBER() OVER" in sql
    assert "REPLAY_RANK > 1" in sql
    assert "BUILTIN:TRAINING-REMEDIATION-V1" in sql
    assert "ON CONFLICT (TRAINING_RESOURCE_ID) DO NOTHING" in sql
