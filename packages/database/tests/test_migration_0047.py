"""Governed current-threat library migration (W3-02, revision 0047).

Checks the migration chains onto the W3-01 head, is additive only (no destructive
DDL/DML in ``upgrade``), and creates the three new tables and enum types the ORM
declares. The full apply-to-Postgres path is covered by the postgres-gated
fresh-install / autogenerate-drift suites.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path


def _load() -> object:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0047_threat_library.py"
    spec = importlib.util.spec_from_file_location("migration_0047", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_chains_onto_the_w3_01_head() -> None:
    module = _load()
    assert module.revision == "0047_threat_library"
    assert module.down_revision == "0046_cue_manifest"


def test_upgrade_is_additive_only() -> None:
    module = _load()
    upgrade_src = inspect.getsource(module.upgrade)
    module_src = inspect.getsource(module)
    assert "DROP TABLE" not in upgrade_src
    assert "DELETE " not in upgrade_src.upper()
    assert "ALTER TABLE" not in upgrade_src.upper()
    assert "op.drop_" not in upgrade_src
    # Least-privilege grants are emitted (via the _grant helper).
    assert "op.execute" in module_src and "GRANT SELECT, INSERT, UPDATE" in module_src


def test_upgrade_creates_the_three_tables_and_enums() -> None:
    module = _load()
    upgrade_src = inspect.getsource(module.upgrade)
    for table in ("source_policies", "threat_artifacts", "threat_bundle_imports"):
        assert f'create_table(\n        "{table}"' in upgrade_src or f'"{table}"' in upgrade_src
    # New enum types created; the pre-existing quarantine_state is reused.
    assert "_SOURCE_TRUST.create" in upgrade_src
    assert "_ARTIFACT_ORIGIN.create" in upgrade_src
    assert "_ARTIFACT_REVIEW_STATE.create" in upgrade_src
    assert "_QUARANTINE_STATE.create" not in upgrade_src  # reused, never recreated
    # The quarantine invariant is mirrored at the schema.
    assert "quarantine_state = 'QUARANTINED'" in upgrade_src


def test_downgrade_drops_what_upgrade_added() -> None:
    module = _load()
    downgrade_src = inspect.getsource(module.downgrade)
    for table in ("source_policies", "threat_artifacts", "threat_bundle_imports"):
        assert table in downgrade_src
    assert "drop_table" in downgrade_src
