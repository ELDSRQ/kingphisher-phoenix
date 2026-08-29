"""Frozen campaign audience migration contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0021_frozen_campaign_audiences.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0021", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_chains_after_transactional_audit_outbox() -> None:
    migration = _load_migration()

    assert migration.revision == "0021_frozen_campaign_audiences"
    assert migration.down_revision == "0020_transactional_audit_outbox"


def test_upgrade_backfills_legacy_campaigns_fail_closed_and_protects_manifest(
    monkeypatch,
) -> None:
    migration = _load_migration()
    tables: list[str] = []
    statements: list[str] = []
    indexes: list[str] = []
    monkeypatch.setattr(migration.op, "create_table", lambda name, *_args, **_kwargs: tables.append(name))
    monkeypatch.setattr(migration.op, "create_index", lambda name, *_args, **_kwargs: indexes.append(name))
    monkeypatch.setattr(migration.op, "execute", lambda statement: statements.append(str(statement)))

    migration.upgrade()

    assert tables == [
        "audience_groups",
        "audience_group_members",
        "campaign_audiences",
        "campaign_audience_manifest",
    ]
    sql = "\n".join(statements)
    assert "legacy_requires_configuration" in sql
    assert "legacy-unconfigured:" in sql
    assert "campaign_audience_manifest_immutable" in sql
    assert "BEFORE INSERT OR UPDATE OR DELETE ON campaign_audience_manifest" in sql
    assert "current_frozen_at IS NOT NULL" in sql
    assert "NEW.audience_version <> current_version" in sql
    assert "ix_campaign_audience_manifest_recipient" in indexes


def test_downgrade_removes_manifest_before_audience_definition(monkeypatch) -> None:
    migration = _load_migration()
    dropped: list[str] = []
    monkeypatch.setattr(migration.op, "execute", lambda _statement: None)
    monkeypatch.setattr(migration.op, "drop_index", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(migration.op, "drop_table", dropped.append)

    migration.downgrade()

    assert dropped.index("campaign_audience_manifest") < dropped.index("campaign_audiences")
    assert dropped[-1] == "audience_groups"
