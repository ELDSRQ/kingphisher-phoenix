"""RoE v2 migration invalidates incomplete legacy authorization artifacts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0017_roe_signature_v2.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0017", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_marks_legacy_artifacts_version_one_and_revokes_them(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    added: list[tuple[str, object]] = []
    statements: list[str] = []
    altered: list[tuple[object, ...]] = []
    monkeypatch.setattr(migration.op, "add_column", lambda table, column: added.append((table, column)))
    monkeypatch.setattr(migration.op, "execute", statements.append)
    monkeypatch.setattr(migration.op, "alter_column", lambda *args, **kwargs: altered.append((*args, kwargs)))

    migration.upgrade()

    assert added[0][0] == "rules_of_engagement"
    assert added[0][1].name == "signature_version"  # type: ignore[attr-defined]
    assert str(added[0][1].server_default.arg) == "1"  # type: ignore[attr-defined]
    sql = " ".join(statements).upper()
    assert "UPDATE RULES_OF_ENGAGEMENT" in sql
    assert "REVOKED_AT = COALESCE(REVOKED_AT, NOW())" in sql
    assert "WHERE SIGNATURE_VERSION = 1" in sql
    assert altered
