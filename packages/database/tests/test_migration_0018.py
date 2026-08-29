"""Persistent emergency-stop migration contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0018_persistent_emergency_stop.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0018", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_creates_singleton_and_preserves_legacy_global_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    created: list[tuple[object, ...]] = []
    statements: list[object] = []
    monkeypatch.setattr(migration.op, "create_table", lambda *args: created.append(args))
    monkeypatch.setattr(migration.op, "execute", statements.append)

    migration.upgrade()

    assert created and created[0][0] == "system_safety_state"
    ddl_names = {getattr(item, "name", None) for item in created[0][1:]}
    assert {"singleton_id", "emergency_stop_engaged", "generation"} <= ddl_names
    sql = " ".join(str(statement) for statement in statements).upper()
    assert "INSERT INTO SYSTEM_SAFETY_STATE" in sql
    assert "FROM AUDIT_EVENTS" in sql
    assert "ACTION = 'KILL-SWITCH.ENGAGE'" in sql
    assert "OBJECT_TYPE = 'SYSTEM'" in sql
    assert "OBJECT_ID = 'DELIVERY'" in sql
    assert "LATEST_LEGACY_STOP.OCCURRED_AT IS NOT NULL" in sql
