"""Legacy tracking bearers are revoked during the HMAC verifier migration."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0016_tracking_token_hmac.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0016", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_revokes_all_active_legacy_tracking_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    migration = _load_migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)

    migration.upgrade()

    sql = " ".join(statements).upper()
    assert "UPDATE TRACKING_TOKENS" in sql
    assert "STATUS = 'REVOKED'" in sql
    assert "WHERE STATUS = 'ACTIVE'" in sql
    assert "REVOKED_AT = NOW()" in sql
