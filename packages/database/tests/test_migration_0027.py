from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from kp_database.models import CipherText, RecipientExclusion

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0027_recipient_exclusion_lifecycle.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0027", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exclusion_lifecycle_migration_is_linear_additive_and_nondestructive() -> None:
    migration = _load()
    source = MIGRATION.read_text(encoding="utf-8")

    assert migration.revision == "0027_recipient_exclusions"
    assert migration.down_revision == "0026_training_resource_library"
    assert len(migration.revision) <= 32
    assert 'sa.Column("created_at"' in source
    assert 'server_default=sa.text("now()")' in source
    assert 'sa.Column("revoked_at"' in source
    assert 'sa.Column("revoked_by"' in source
    assert 'sa.Column("revoke_reason"' in source
    assert "create_foreign_key" not in source
    upgrade = source.split("def upgrade()", 1)[1].split("def downgrade()", 1)[0].upper()
    assert "DELETE " not in upgrade
    assert "UPDATE " not in upgrade


def test_exclusion_model_matches_lifecycle_and_ciphertext_contract() -> None:
    columns = RecipientExclusion.__table__.c

    assert not columns.created_at.nullable
    assert columns.created_at.server_default is not None
    assert columns.revoked_at.nullable
    assert columns.revoked_by.nullable
    assert columns.revoke_reason.nullable
    assert isinstance(columns.reason.type, CipherText)
    assert isinstance(columns.revoke_reason.type, CipherText)
    assert not columns.campaign_id.foreign_keys
    assert {
        "ix_recipient_exclusions_recipient_created",
        "ix_recipient_exclusions_active_scope",
    } <= {index.name for index in RecipientExclusion.__table__.indexes}
