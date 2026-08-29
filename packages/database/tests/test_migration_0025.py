from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

from kp_database.models import CampaignProgram, CampaignProgramOccurrence

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0025_campaign_programs.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0025", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _constraint_names(model) -> set[str]:
    return {str(constraint.name) for constraint in model.__table__.constraints}


def test_program_migration_is_a_single_linear_revision() -> None:
    migration = _load()
    assert migration.revision == "0025_campaign_programs"
    assert migration.down_revision == "0024_database_invariants"
    source = MIGRATION.read_text(encoding="utf-8")
    assert "campaign_programs" in source
    assert "campaign_program_occurrences" in source
    assert 'postgresql.ENUM("ACTIVE", "PAUSED"' in source
    assert "CREATE TRIGGER" not in source.upper()


def test_program_model_metadata_matches_database_invariants() -> None:
    program_constraints = _constraint_names(CampaignProgram)
    assert {
        "ck_campaign_programs_version_positive",
        "ck_campaign_programs_cadence_allowlist",
        "ck_campaign_programs_occurrence_count_bounded",
        "ck_campaign_programs_configuration_hash_hex",
        "uq_campaign_programs_source_campaign_id",
    } <= program_constraints
    occurrence_constraints = _constraint_names(CampaignProgramOccurrence)
    assert {
        "ck_campaign_program_occurrences_occurrence_number_positive",
        "ck_campaign_program_occurrences_window_ordered",
        "uq_campaign_program_occurrence_number",
        "uq_campaign_program_occurrences_campaign_id",
    } <= occurrence_constraints


def test_program_schema_identifiers_fit_postgres_limit() -> None:
    for model in (CampaignProgram, CampaignProgramOccurrence):
        assert len(model.__table__.name) <= 63
        for constraint in model.__table__.constraints:
            assert constraint.name is not None
            assert len(str(constraint.name)) <= 63, constraint.name
    migration_source = MIGRATION.read_text(encoding="utf-8")
    explicit_names = re.findall(r'name="([a-z0-9_]+)"', migration_source)
    assert explicit_names
    assert all(len(name) <= 63 for name in explicit_names)
