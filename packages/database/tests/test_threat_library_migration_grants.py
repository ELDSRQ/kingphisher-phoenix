"""Historical threat-library grants accept only their three literal targets."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def migration(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0047_threat_library.py"
    spec = importlib.util.spec_from_file_location("threat_library_grants_migration", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    statements = []
    monkeypatch.setattr(module.op, "execute", statements.append)
    return module, statements


@pytest.mark.parametrize(
    "table,revoke,grant",
    [
        (
            "source_policies",
            "REVOKE ALL ON source_policies FROM PUBLIC",
            "DO $grant$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN "
            "GRANT SELECT, INSERT, UPDATE ON source_policies TO kp_operator; END IF; END $grant$;",
        ),
        (
            "threat_artifacts",
            "REVOKE ALL ON threat_artifacts FROM PUBLIC",
            "DO $grant$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN "
            "GRANT SELECT, INSERT, UPDATE ON threat_artifacts TO kp_operator; END IF; END $grant$;",
        ),
        (
            "threat_bundle_imports",
            "REVOKE ALL ON threat_bundle_imports FROM PUBLIC",
            "DO $grant$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN "
            "GRANT SELECT, INSERT, UPDATE ON threat_bundle_imports TO kp_operator; END IF; END $grant$;",
        ),
    ],
)
def test_allowed_table_emits_exact_public_revoke_then_conditional_operator_grant(migration, table, revoke, grant):
    module, statements = migration
    module._grant(table)
    assert [" ".join(statement.split()) for statement in statements] == [revoke, grant]
    assert module.revision == "0047_threat_library"
    assert module.down_revision == "0046_cue_manifest"


@pytest.mark.parametrize(
    "table",
    [
        "",
        "recipients",
        "public.source_policies",
        " source_policies",
        "source_policies ",
        "SOURCE_POLICIES",
        "source_policies; DROP TABLE recipients; --",
        "threat_artifacts/* comment */",
        '"threat_bundle_imports"',
    ],
)
def test_unknown_or_injection_like_identifier_is_rejected_before_any_sql(migration, table):
    module, statements = migration
    with pytest.raises(ValueError, match="unsupported threat-library grant table"):
        module._grant(table)
    assert statements == []
