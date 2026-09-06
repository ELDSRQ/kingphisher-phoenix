"""Single-source-of-truth contract for the AUD-002 grant matrix (static).

These are fast, DB-free checks that the grant matrix lives in exactly one place
(``kp_database.grants``), that ``scripts/azure_migrate.py`` consumes THAT object
rather than a copy, that the runtime-probe oracle is internally consistent, and
that the audit-ownership fix (point 4) is present in the migration chain and the
local bootstrap. They complement the effect-level ``postgres`` tests.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from kp_database import grants

_REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = _REPO_ROOT / "scripts" / "azure_migrate.py"
MIGRATION_0034 = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0034_audit_owner_separation.py"
POSTGRES_INIT_PATH = _REPO_ROOT / "infrastructure" / "containers" / "postgres-init" / "001-roles.sh"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_azure_migrate_source", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_azure_migrate_consumes_the_shared_matrix_object_not_a_copy() -> None:
    script = _load_script()
    # Identity, not equality: azure_migrate must reference the very same objects
    # so the matrix can never fork into two sources of truth again.
    assert script.TABLE_GRANTS is grants.TABLE_GRANTS
    assert script.WORKLOAD_COLUMN_GRANTS is grants.WORKLOAD_COLUMN_GRANTS
    assert script.AUDIT_ANCHOR_COLUMN_GRANTS is grants.AUDIT_ANCHOR_COLUMN_GRANTS
    assert script.RUNTIME_ROLES is grants.RUNTIME_ROLES
    assert script.REQUIRED_WORKLOADS is grants.REQUIRED_WORKLOADS
    # The literal matrix must no longer be defined in the script source.
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert '"SELECT, INSERT, UPDATE, DELETE": (' not in source, "matrix literal leaked back into azure_migrate.py"


def test_probe_oracle_is_consistent_with_the_declared_grants() -> None:
    for workload in grants.RUNTIME_ROLES:
        table_privs = grants.table_privileges(workload)
        for table, verbs in table_privs.items():
            for verb in verbs:
                assert grants.expected_table_privilege(workload, table, verb), (workload, table, verb)
        # denied set never overlaps what the workload is actually granted.
        allowed = grants.granted_tables(workload) | grants.column_granted_tables(workload)
        assert grants.denied_tables(workload).isdisjoint(allowed), workload


def test_enqueue_and_audit_anchor_partitions_are_coherent() -> None:
    assert "audit-anchor" not in grants.enqueue_workloads()
    assert grants.enqueue_workloads() == frozenset(grants.RUNTIME_ROLES) - {"audit-anchor"}
    # Every enqueue role reads the arbiter column but never the payload.
    for workload in grants.enqueue_workloads():
        assert grants.expected_column_privilege(workload, "transactional_outbox", "idempotency_key", "SELECT")
        assert not grants.expected_column_privilege(workload, "transactional_outbox", "payload", "SELECT")
    # audit-anchor reads only its declared audit columns, no table-level grant.
    assert grants.TABLE_GRANTS["audit-anchor"] == {}
    for table, columns in grants.AUDIT_ANCHOR_COLUMN_GRANTS.items():
        for column in columns:
            assert grants.expected_column_privilege("audit-anchor", table, column, "SELECT")
        # ...but NOT destructive verbs on the evidence tables.
        for verb in ("INSERT", "UPDATE", "DELETE"):
            assert not grants.expected_table_privilege("audit-anchor", table, verb), (table, verb)


def test_sensitive_tables_are_denied_to_every_workload() -> None:
    # No workload may reach the integrity secret; only audit-anchor reads the
    # two evidence tables, and only via column SELECT.
    for workload in grants.RUNTIME_ROLES:
        for verb in grants.TABLE_VERBS:
            assert not grants.expected_table_privilege(workload, "audit_integrity_secret", verb), (workload, verb)


def test_point4_audit_owner_migration_is_in_the_chain() -> None:
    assert MIGRATION_0034.exists(), "0034_audit_owner_separation migration is missing"
    source = MIGRATION_0034.read_text(encoding="utf-8")
    assert 'down_revision = "0033_training_knowledge_check"' in source
    assert "OWNER TO audit_owner" in source
    assert "NOLOGIN" in source
    # Scoped to the two evidence tables only (see migration design note): the
    # ownership-transfer FOREACH must target ONLY the two evidence tables and
    # must NOT reassign transactional_outbox (app-owned on local installs).
    assert "ARRAY['audit_events', 'audit_chain_head']" in source
    assert "'transactional_outbox'" not in source  # single-quoted = a SQL array element


def test_local_bootstrap_converges_to_audit_owner_not_audit_writer() -> None:
    init = POSTGRES_INIT_PATH.read_text(encoding="utf-8")
    assert "OWNER TO audit_owner" in init
    assert "CREATE ROLE audit_owner NOLOGIN" in init
    # The old behaviour (leaving the LOGIN audit_writer as final owner of the
    # evidence tables) must be gone.
    assert "ALTER TABLE public.%I OWNER TO audit_writer" not in init
