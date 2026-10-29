"""Training cue-coverage migration (W4-01, KP-AUD-015, revision 0050).

Checks the migration chains onto the W1-07 head, is additive only (no destructive
DDL/DML in ``upgrade``), creates the two new tables, and adds the single launch-gate
coverage-fingerprint column with its NULL-tolerant CHECK. The full apply-to-Postgres
path is covered by the postgres-gated fresh-install / autogenerate-drift suites.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path


def _load() -> object:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0050_training_cue_coverage.py"
    spec = importlib.util.spec_from_file_location("migration_0050", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision_chains_onto_the_w1_07_head() -> None:
    module = _load()
    assert module.revision == "0050_training_cue_coverage"
    assert module.down_revision == "0049_session_epoch_rotation"
    # Both ids must fit alembic_version.version_num (varchar(32)).
    assert len(module.revision) <= 32
    assert len(module.down_revision) <= 32


def test_upgrade_is_additive_only() -> None:
    module = _load()
    upgrade_src = inspect.getsource(module.upgrade)
    assert "DROP TABLE" not in upgrade_src.upper()
    assert "DELETE " not in upgrade_src.upper()
    assert "op.drop_" not in upgrade_src
    # The only ALTER is the additive add_column for the coverage fingerprint.
    assert "op.add_column" in upgrade_src
    assert "drop_column" not in upgrade_src


def test_upgrade_creates_the_two_tables_and_the_gate_column() -> None:
    module = _load()
    upgrade_src = inspect.getsource(module.upgrade)
    for table in ("training_cue_coverage", "campaign_cue_coverage_exceptions"):
        assert f'"{table}"' in upgrade_src
    # The reviewed-coverage all-or-nothing invariant is mirrored at the schema.
    assert "ck_training_cue_coverage_review_all_or_nothing" in upgrade_src
    # The launch-gate fingerprint column and its NULL-tolerant CHECK are added.
    assert "cue_coverage_hash" in upgrade_src
    assert "ck_campaign_launch_cue_coverage_hash" in upgrade_src
    assert "cue_coverage_hash IS NULL OR length(cue_coverage_hash) = 64" in upgrade_src


def test_downgrade_drops_what_upgrade_added() -> None:
    module = _load()
    downgrade_src = inspect.getsource(module.downgrade)
    for table in ("training_cue_coverage", "campaign_cue_coverage_exceptions"):
        assert table in downgrade_src
    assert "drop_table" in downgrade_src
    assert "drop_column" in downgrade_src
    assert "ck_campaign_launch_cue_coverage_hash" in downgrade_src
