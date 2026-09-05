"""Contract tests for the Azure migration bootstrap grants."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "azure_migrate.py"
POSTGRES_INIT_PATH = (
    Path(__file__).resolve().parents[3] / "infrastructure" / "containers" / "postgres-init" / "001-roles.sh"
)


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_azure_migrate", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _table_privileges(script: ModuleType, workload: str, table: str) -> set[str]:
    """Return the effective table verbs encoded in the reviewed grant map."""

    return {
        privilege.strip()
        for privileges, tables in script.TABLE_GRANTS[workload].items()
        if table in tables
        for privilege in privileges.split(",")
    }


def _column_privileges(script: ModuleType, workload: str, table: str, column: str) -> set[str]:
    """Return only explicit column-scoped verbs from the reviewed grant map."""

    return {
        privilege
        for privilege, table_columns in script.WORKLOAD_COLUMN_GRANTS.get(workload, {}).items()
        if column in table_columns.get(table, ())
    }


class _Context:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def __enter__(self) -> _Connection:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        return None


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar(self) -> object:
        return self._value


class _Transaction:
    def rollback(self) -> None:
        return None

    def commit(self) -> None:
        return None


class _Connection:
    def __init__(
        self,
        *,
        existing_roles: set[str] | None = None,
        installed_audit_root: str | None = None,
    ) -> None:
        self.statements: list[str] = []
        self.raw_statements: list[object] = []
        self.existing_roles = existing_roles or set()
        self.installed_audit_root = installed_audit_root
        self.connection = SimpleNamespace(driver_connection=SimpleNamespace(execute=self.raw_statements.append))

    # Model whether a fresh runtime session can enqueue. Default True is the
    # healthy path; a test sets it False so the post-commit KP-008 probe fails
    # (proving the migration fails the deploy closed instead of shipping a 503).
    probe_enqueue_ok: bool = True

    def scalar(self, statement: object, parameters: dict[str, object] | None = None) -> int | str | bool | None:
        if "current_user" in str(statement):
            return "kpadmin"
        if "to_regclass" in str(statement):
            return "audit_integrity_secret" if self.installed_audit_root is not None else None
        if "SELECT key_hex" in str(statement):
            return self.installed_audit_root
        if parameters and parameters.get("role_name") in self.existing_roles:
            return 1
        return None

    def execute(self, statement: object, _parameters: dict[str, object] | None = None) -> None:
        self.statements.append(str(statement))

    # --- Post-commit probe surface (fresh-session runtime checks) ---
    def exec_driver_sql(self, statement: object, parameters: dict[str, object] | None = None) -> _Result:
        text_sql = str(statement)
        self.statements.append(text_sql)
        if "current_user" in text_sql:
            return _Result("kp_operator")
        if "INSERT INTO transactional_outbox" in text_sql and not self.probe_enqueue_ok:
            raise RuntimeError("permission denied for table transactional_outbox")
        return _Result(None)

    def begin(self) -> _Transaction:
        return _Transaction()

    def rollback(self) -> None:
        return None


class _Engine:
    def __init__(
        self,
        *,
        existing_roles: set[str] | None = None,
        installed_audit_root: str | None = None,
    ) -> None:
        self.connection = _Connection(
            existing_roles=existing_roles,
            installed_audit_root=installed_audit_root,
        )

    def begin(self) -> _Context:
        return _Context(self.connection)

    def connect(self) -> _Context:
        return _Context(self.connection)

    def dispose(self) -> None:
        return None


def test_bootstrap_grants_only_the_real_audit_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _load_script()
    engine = _Engine()
    upgrades: list[tuple[Any, str]] = []
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda config, target: upgrades.append((config, target)))

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert "audit_chain_head" in statements
    assert "audit_chain_heads" not in statements
    assert "ALTER DEFAULT PRIVILEGES" not in statements
    assert "REVOKE CREATE ON SCHEMA public FROM audit_writer" in statements
    assert "ALTER TABLE public.audit_events OWNER TO audit_owner" in statements
    assert "ALTER TABLE public.audit_chain_head OWNER TO audit_owner" in statements
    assert "audit_integrity_secret" in statements
    assert "transactional_outbox" in statements
    assert "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox" in statements
    assert "GRANT INSERT (outbox_id, kind, topic, payload, idempotency_key, available_at)" in statements
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC" in statements
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC" in statements
    assert "REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC" in statements
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM kp_operator" in statements
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM kp_tracking" in statements
    assert "GRANT USAGE ON SCHEMA public TO kp_worker_delivery" in statements
    assert "GRANT SELECT, INSERT ON TABLE events TO kp_tracking" in statements
    assert "GRANT SELECT ON TABLE tracking_tokens, training_resources, campaigns TO kp_tracking" in statements
    assert "GRANT SELECT, UPDATE ON TABLE recipient_assignments TO kp_tracking" in statements
    assert "GRANT UPDATE (training_resource_id) ON TABLE campaigns TO kp_tracking" not in statements
    assert "GRANT SELECT, UPDATE ON TABLE campaigns, recipient_assignments TO kp_tracking" not in statements
    assert "GRANT SELECT ON TABLE" in statements and "system_safety_state" in statements
    assert (
        "GRANT SELECT, UPDATE ON TABLE campaigns, recipient_assignments, system_safety_state, campaign_launch_gates "
        "TO kp_worker_delivery" in statements
    )
    assert "audit_events TO kp_operator" not in statements
    assert "GRANT CREATE ON SCHEMA public TO kp_" not in statements
    assert engine.connection.raw_statements
    assert upgrades and upgrades[0][1] == "head"


def test_bootstrap_fails_closed_without_a_required_runtime_password(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _load_script()
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS - {"tracking"}:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.delenv(script._password_env("tracking"), raising=False)

    with pytest.raises(RuntimeError, match="KP_DB_PASSWORD_TRACKING"):
        script.main()


def test_runtime_grant_map_excludes_audit_tables_and_schema_ownership() -> None:
    script = _load_script()

    assert {
        "operator",
        "tracking",
        "ingestion",
        "delivery",
        "retention",
        "reminder",
        "alert",
        "audit-anchor",
    } == script.REQUIRED_WORKLOADS
    for workload, grants in script.TABLE_GRANTS.items():
        granted_tables = {table for tables in grants.values() for table in tables}
        assert "audit_events" not in granted_tables, workload
        assert "audit_chain_head" not in granted_tables, workload
        assert all("ALL" not in privileges for privileges in grants), workload


def test_awareness_ledger_grants_are_retention_only_and_survive_privilege_reset() -> None:
    script = _load_script()

    assert _table_privileges(script, "retention", "awareness_ledger_entries") == {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
    }
    for workload in script.TABLE_GRANTS.keys() - {"retention"}:
        assert _table_privileges(script, workload, "awareness_ledger_entries") == set(), workload

    local_init = POSTGRES_INIT_PATH.read_text(encoding="utf-8")
    assert "REVOKE ALL ON TABLE public.awareness_ledger_entries FROM PUBLIC" in local_init
    assert (
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.awareness_ledger_entries "
        "TO kp_worker_retention" in local_init
    )
    for role in ("worker", "kp_operator", "kp_tracking", "kp_worker_delivery"):
        assert f"'{role}'" in local_init


def test_managed_migration_revokes_legacy_monolithic_ledger_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _load_script()
    engine = _Engine(existing_roles={"worker"})
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda *_args, **_kwargs: None)

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert "REVOKE ALL ON TABLE awareness_ledger_entries FROM worker" in statements
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE awareness_ledger_entries TO kp_worker_retention" in statements


def test_audit_anchor_primary_role_has_no_business_or_outbox_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _load_script()
    engine = _Engine()
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda *_args, **_kwargs: None)

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert script.TABLE_GRANTS["audit-anchor"] == {}
    assert set(script.AUDIT_ANCHOR_COLUMN_GRANTS) == {"audit_events", "audit_chain_head"}
    assert "GRANT USAGE ON SCHEMA public TO kp_worker_audit_anchor" in statements
    assert "ON TABLE transactional_outbox TO kp_worker_audit_anchor" not in statements
    audit_event_columns = ", ".join(script.AUDIT_ANCHOR_COLUMN_GRANTS["audit_events"])
    head_columns = ", ".join(script.AUDIT_ANCHOR_COLUMN_GRANTS["audit_chain_head"])
    assert f"GRANT SELECT ({audit_event_columns}) ON TABLE audit_events TO kp_worker_audit_anchor" in statements
    assert f"GRANT SELECT ({head_columns}) ON TABLE audit_chain_head TO kp_worker_audit_anchor" in statements
    assert "GRANT SELECT ON TABLE audit_events TO kp_worker_audit_anchor" not in statements
    assert "GRANT SELECT ON TABLE audit_chain_head TO kp_worker_audit_anchor" not in statements
    assert (
        "GRANT EXECUTE ON FUNCTION kp_outbox_health(), kp_verify_audit_head() TO kp_worker_audit_anchor" in statements
    )
    assert "kp_dispatch_audit_outbox(uuid) TO kp_worker_audit_anchor" not in statements
    assert "kp_dispatch_pending_audit(integer) TO kp_worker_audit_anchor" not in statements
    assert "kp_claim_queue_outbox(integer) TO kp_worker_audit_anchor" not in statements
    assert "kp_complete_outbox(uuid) TO kp_worker_audit_anchor" not in statements
    assert "kp_fail_outbox(uuid,text) TO kp_worker_audit_anchor" not in statements
    assert "ON TABLE audit_integrity_secret TO kp_worker_audit_anchor" not in statements


def test_campaign_and_microsoft365_roles_have_only_their_runtime_permissions() -> None:
    script = _load_script()

    audience_tables = {
        "audience_groups",
        "audience_group_members",
        "campaign_audiences",
        "campaign_audience_manifest",
    }
    for table in audience_tables:
        assert _table_privileges(script, "operator", table) == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    assert _table_privileges(script, "operator", "campaign_programs") == {"SELECT", "INSERT", "UPDATE"}
    assert _table_privileges(script, "operator", "campaign_program_occurrences") == {"SELECT", "INSERT"}
    for table in {"campaign_programs", "campaign_program_occurrences"}:
        for workload in script.TABLE_GRANTS.keys() - {"operator"}:
            assert _table_privileges(script, workload, table) == set()
    assert _table_privileges(script, "operator", "microsoft365_integration_states") == {"SELECT"}
    assert _table_privileges(script, "operator", "delivery_report_correlations") == {"SELECT"}
    assert _table_privileges(script, "tracking", "campaigns") == {"SELECT"}
    assert script.WORKLOAD_COLUMN_GRANTS == {}
    assert _column_privileges(script, "tracking", "campaigns", "training_resource_id") == set()
    for column in ("title", "state", "schedule_start", "schedule_end", "max_recipients"):
        assert _column_privileges(script, "tracking", "campaigns", column) == set()
    assert _table_privileges(script, "tracking", "recipient_assignments") == {"SELECT", "UPDATE"}

    assert _table_privileges(script, "directory", "microsoft365_integration_states") == {
        "SELECT",
        "INSERT",
        "UPDATE",
    }
    assert _table_privileges(script, "directory", "recipients") == {"SELECT", "INSERT", "UPDATE"}
    assert _table_privileges(script, "directory", "audience_groups") == {"SELECT"}
    assert _table_privileges(script, "directory", "audience_group_members") == {
        "SELECT",
        "INSERT",
        "DELETE",
    }
    assert _table_privileges(script, "directory", "campaigns") == {"SELECT", "UPDATE"}
    assert _table_privileges(script, "directory", "campaign_audiences") == {"SELECT", "UPDATE"}
    assert _table_privileges(script, "directory", "campaign_approvals") == {"DELETE"}
    assert _table_privileges(script, "directory", "campaign_audience_manifest") == {"DELETE"}

    assert _table_privileges(script, "delivery", "delivery_report_correlations") == {
        "SELECT",
        "INSERT",
        "UPDATE",
    }
    assert _table_privileges(script, "delivery", "recipient_assignments") == {"SELECT", "UPDATE"}

    assert _table_privileges(script, "mailbox", "microsoft365_integration_states") == {
        "SELECT",
        "INSERT",
        "UPDATE",
    }
    assert _table_privileges(script, "mailbox", "reported_mail_receipts") == {"SELECT", "INSERT"}
    assert _table_privileges(script, "mailbox", "events") == {"SELECT", "INSERT"}
    assert _table_privileges(script, "mailbox", "delivery_report_correlations") == {"SELECT"}
    assert _table_privileges(script, "mailbox", "recipient_assignments") == {"SELECT"}
    assert _table_privileges(script, "mailbox", "tracking_tokens") == {"SELECT"}


def test_acs_receipt_and_pacing_grants_are_delivery_only_and_non_destructive() -> None:
    script = _load_script()

    assert _table_privileges(script, "delivery", "delivery_provider_events") == {"SELECT", "INSERT"}
    for table in ("recipient_delivery_suppressions", "delivery_pacing_states"):
        assert _table_privileges(script, "delivery", table) == {"SELECT", "INSERT", "UPDATE"}

    for workload in script.TABLE_GRANTS.keys() - {"delivery"}:
        for table in (
            "delivery_provider_events",
            "recipient_delivery_suppressions",
            "delivery_pacing_states",
        ):
            assert _table_privileges(script, workload, table) == set(), (workload, table)


def test_microsoft365_worker_roles_deny_cross_workload_mutations() -> None:
    script = _load_script()

    forbidden = {
        "operator": {
            "microsoft365_integration_states": {"INSERT", "UPDATE", "DELETE"},
            "delivery_report_correlations": {"INSERT", "UPDATE", "DELETE"},
            "reported_mail_receipts": {"SELECT", "INSERT", "UPDATE", "DELETE"},
        },
        "directory": {
            "campaign_audience_manifest": {"SELECT", "INSERT", "UPDATE"},
            "delivery_report_correlations": {"SELECT", "INSERT", "UPDATE", "DELETE"},
            "reported_mail_receipts": {"SELECT", "INSERT", "UPDATE", "DELETE"},
            "recipients": {"DELETE"},
        },
        "delivery": {
            "microsoft365_integration_states": {"SELECT", "INSERT", "UPDATE", "DELETE"},
            "reported_mail_receipts": {"SELECT", "INSERT", "UPDATE", "DELETE"},
            "events": {"SELECT", "INSERT", "UPDATE", "DELETE"},
        },
        "mailbox": {
            "delivery_report_correlations": {"INSERT", "UPDATE", "DELETE"},
            "recipient_assignments": {"INSERT", "UPDATE", "DELETE"},
            "reported_mail_receipts": {"UPDATE", "DELETE"},
            "events": {"UPDATE", "DELETE"},
            "recipients": {"SELECT", "INSERT", "UPDATE", "DELETE"},
        },
    }
    for workload, table_denials in forbidden.items():
        for table, denied_verbs in table_denials.items():
            assert _table_privileges(script, workload, table).isdisjoint(denied_verbs), (workload, table)


def test_enabled_microsoft365_roles_emit_scoped_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _load_script()
    engine = _Engine()
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS | {"directory", "mailbox"}:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda *_args, **_kwargs: None)

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert (
        "GRANT SELECT, INSERT, UPDATE ON TABLE microsoft365_integration_states, recipients "
        "TO kp_worker_directory" in statements
    )
    assert "GRANT DELETE ON TABLE campaign_approvals, campaign_audience_manifest TO kp_worker_directory" in statements
    assert "GRANT SELECT, INSERT ON TABLE events, reported_mail_receipts TO kp_worker_mailbox" in statements
    assert "GRANT SELECT, INSERT, UPDATE ON TABLE microsoft365_integration_states TO kp_worker_mailbox" in statements
    for role in ("kp_worker_directory", "kp_worker_mailbox"):
        assert (
            "GRANT INSERT (outbox_id, kind, topic, payload, idempotency_key, available_at) "
            f"ON TABLE public.transactional_outbox TO {role}" in statements
        )


def test_delivery_role_emits_scoped_acs_receipt_and_pacing_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _load_script()
    engine = _Engine()
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda *_args, **_kwargs: None)

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert "GRANT SELECT, INSERT ON TABLE delivery_provider_events TO kp_worker_delivery" in statements
    assert (
        "GRANT SELECT, INSERT, UPDATE ON TABLE delivery_report_correlations, "
        "recipient_delivery_suppressions, delivery_pacing_states TO kp_worker_delivery" in statements
    )
    assert "GRANT DELETE ON TABLE delivery_provider_events" not in statements


def test_unconfigured_optional_worker_role_is_preserved_without_implicit_retirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _load_script()
    engine = _Engine(existing_roles={"kp_worker_generation"})
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.delenv(script._password_env("generation"), raising=False)
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda *_args, **_kwargs: None)

    script.main()

    raw = "\n".join(str(statement) for statement in engine.connection.raw_statements)
    statements = "\n".join(engine.connection.statements)
    assert "kp_worker_generation" not in raw
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM kp_worker_generation" not in statements
    assert "REVOKE ALL PRIVILEGES ON SCHEMA public FROM kp_worker_generation" not in statements
    assert "GRANT USAGE ON SCHEMA public TO kp_worker_generation" not in statements


def test_existing_audit_root_mismatch_fails_before_any_role_or_migration_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _load_script()
    engine = _Engine(installed_audit_root="02" * 32)
    upgrades: list[tuple[object, str]] = []
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda config, target: upgrades.append((config, target)))

    with pytest.raises(RuntimeError, match="automatic rotation is refused"):
        script.main()

    assert engine.connection.raw_statements == []
    assert engine.connection.statements == []
    assert upgrades == []


def _run_bootstrap(script: ModuleType, engine: _Engine, monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, str]]:
    upgrades: list[tuple[Any, str]] = []
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://example.invalid/platform")
    monkeypatch.setenv("AUDIT_WRITER_PASSWORD", "test-only")
    monkeypatch.setenv("AUDIT_ROOT_KEY", "01" * 32)
    for workload in script.REQUIRED_WORKLOADS:
        monkeypatch.setenv(script._password_env(workload), f"test-only-{workload}")
    monkeypatch.setattr(script, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(script.command, "upgrade", lambda config, target: upgrades.append((config, target)))
    return upgrades


def test_outbox_insert_granted_to_enqueue_roles_and_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    # The outbox column-INSERT is granted to every enqueueing role as the owner,
    # and the migration then runs a post-commit fresh-session probe that actually
    # attempts the enqueue INSERT (as the real runtime role) and an audit_writer
    # dispatch EXECUTE -- the authoritative KP-008 gate.
    script = _load_script()
    engine = _Engine()
    _run_bootstrap(script, engine, monkeypatch)

    script.main()

    statements = "\n".join(engine.connection.statements)
    assert (
        "GRANT INSERT (outbox_id, kind, topic, payload, idempotency_key, available_at) "
        "ON TABLE public.transactional_outbox TO kp_operator" in statements
    )
    assert (
        "GRANT EXECUTE ON FUNCTION kp_outbox_health(), kp_verify_audit_head() TO kp_worker_audit_anchor" in statements
    )
    # The post-commit probe exercised the real runtime operations from fresh
    # least-privilege logins.
    assert "INSERT INTO transactional_outbox" in statements
    assert "SELECT kp_outbox_health()" in statements


def test_migration_fails_closed_when_runtime_enqueue_probe_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    # If a fresh kp_operator session cannot actually enqueue (the KP-008 failure
    # mode), the migration must fail the deploy with the exact denial rather than
    # ship a build that 503s on the first console write.
    script = _load_script()
    engine = _Engine()
    engine.connection.probe_enqueue_ok = False
    _run_bootstrap(script, engine, monkeypatch)

    with pytest.raises(RuntimeError, match="KP-008 runtime privilege probe FAILED"):
        script.main()
