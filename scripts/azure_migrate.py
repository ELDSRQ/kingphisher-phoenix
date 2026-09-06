"""Provision least-privilege runtime roles, then run Alembic as the owner."""

from __future__ import annotations

import hmac
import os
import sys
import uuid

from alembic import command
from alembic.config import Config

# AUD-002: the least-privilege grant matrix is the single source of truth in
# kp_database.grants. This script imports and consumes it rather than carrying
# its own literal copy. The names are re-exported at module scope so existing
# contract tests that read `azure_migrate.TABLE_GRANTS` etc. keep working.
from kp_database import grants
from kp_database.grants import (
    AUDIT_ANCHOR_COLUMN_GRANTS,
    AUDIT_ANCHOR_FUNCTIONS,
    OUTBOX_CONFLICT_SELECT_COLUMNS,
    OUTBOX_INSERT_COLUMNS,
    REQUIRED_WORKLOADS,
    RUNTIME_ROLES,
    TABLE_GRANTS,
    WORKLOAD_COLUMN_GRANTS,
)
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

# The Alembic config path is overridable so the effect-level test can drive
# main() against the repo's alembic.ini instead of the container's /app path.
DEFAULT_ALEMBIC_INI = "/app/packages/database/alembic.ini"


def _runtime_url(database_url: str, role_name: str, password: str) -> str:
    """Derive a runtime role DSN from the migration DSN (same host/db/params)."""
    return make_url(database_url).set(username=role_name, password=password).render_as_string(hide_password=False)


def _probe_has_table_privilege(probe: object, table: str, verb: str) -> bool:
    return bool(
        probe.exec_driver_sql(  # type: ignore[attr-defined]
            "SELECT has_table_privilege(%(t)s, %(v)s)", {"t": f"public.{table}", "v": verb}
        ).scalar()
    )


def _probe_has_column_privilege(probe: object, table: str, column: str, verb: str) -> bool:
    return bool(
        probe.exec_driver_sql(  # type: ignore[attr-defined]
            "SELECT has_column_privilege(%(t)s, %(c)s, %(v)s)",
            {"t": f"public.{table}", "c": column, "v": verb},
        ).scalar()
    )


def _probe_workload_privileges(database_url: str, workload: str, password: str) -> list[str]:
    """Fresh-login effect check for one workload role, both directions.

    Positive: every (table, verb) in the workload's matrix slice is TRUE.
    Negative: every (table, verb) OUTSIDE the slice (across the whole known
    matrix universe) is FALSE — a workload cannot touch another's tables, the
    audit evidence, or the integrity secret. The oracle is kp_database.grants,
    so this compares live PostgreSQL against the single source of truth.
    """
    failures: list[str] = []
    role = RUNTIME_ROLES[workload]
    engine = create_engine(_runtime_url(database_url, role, password))
    try:
        with engine.connect() as probe:
            current = probe.exec_driver_sql("SELECT current_user").scalar()
            # Table-level oracle across the full matrix universe (positive AND
            # negative): has_table_privilege must equal what grants declares.
            for table in sorted(grants.all_matrix_tables()):
                for verb in grants.TABLE_VERBS:
                    expected = grants.expected_table_privilege(workload, table, verb)
                    actual = _probe_has_table_privilege(probe, table, verb)
                    if actual != expected:
                        direction = "missing" if expected else "unexpectedly granted"
                        failures.append(f"{role}: {verb} on {table} {direction}")
            # Column-scoped precision: the outbox arbiter column is readable but
            # the bearer payload is not; audit-anchor reads only its columns.
            if workload in grants.enqueue_workloads():
                if not _probe_has_column_privilege(probe, "transactional_outbox", "idempotency_key", "SELECT"):
                    failures.append(f"{role}: SELECT (idempotency_key) on transactional_outbox missing (KP-008)")
                if _probe_has_column_privilege(probe, "transactional_outbox", "payload", "SELECT"):
                    failures.append(f"{role}: SELECT (payload) on transactional_outbox unexpectedly granted")
            if workload == "audit-anchor":
                for table, columns in AUDIT_ANCHOR_COLUMN_GRANTS.items():
                    for column in columns:
                        if not _probe_has_column_privilege(probe, table, column, "SELECT"):
                            failures.append(f"{role}: SELECT ({column}) on {table} missing")
            # Keep the real INSERT ... ON CONFLICT DML probe as the special case:
            # kp_operator actually enqueues, proving the arbiter SELECT is enough.
            if workload == "operator":
                probe_id = str(uuid.uuid4())
                try:
                    probe.exec_driver_sql(
                        "INSERT INTO transactional_outbox "
                        "(outbox_id, kind, payload, idempotency_key, available_at) "
                        "VALUES (%(id)s, 'audit', '{}'::jsonb, %(key)s, now()) "
                        "ON CONFLICT (idempotency_key) DO NOTHING",
                        {"id": probe_id, "key": f"kp008-probe:{probe_id}"},
                    )
                    print(
                        f"KP-008 probe OK: {current} can INSERT into transactional_outbox",
                        file=sys.stderr,
                        flush=True,
                    )
                except Exception as exc:  # noqa: BLE001 - report the exact runtime denial
                    failures.append(f"kp_operator enqueue DML: {type(exc).__name__}: {str(exc)[:200]}")
                finally:
                    probe.rollback()
            else:
                probe.rollback()
    finally:
        engine.dispose()
    return failures


def _probe_runtime_privileges(database_url: str, runtime_passwords: dict[str, str], audit_password: str) -> None:
    """Authoritative post-commit KP-008 gate, matrix-driven across every role.

    The in-transaction grant checks run as the migration admin and can read true
    while a fresh least-privilege session is still denied at runtime (the KP-008
    contradiction). So verify from ACTUAL role logins, over the same DSN the
    services use, and fail closed with the exact denial rather than shipping a
    deploy that 503s on the first console write. Every configured workload is
    probed in BOTH directions; audit_writer's dispatch EXECUTE is checked too.
    """
    failures: list[str] = []
    for workload, password in runtime_passwords.items():
        failures.extend(_probe_workload_privileges(database_url, workload, password))
    if audit_password:
        audit_engine = create_engine(_runtime_url(database_url, "audit_writer", audit_password))
        try:
            with audit_engine.connect() as probe:
                current = probe.exec_driver_sql("SELECT current_user").scalar()
                try:
                    probe.exec_driver_sql("SELECT kp_outbox_health()")
                    print(f"KP-008 probe OK: {current} can EXECUTE kp_outbox_health()", file=sys.stderr, flush=True)
                except Exception as exc:  # noqa: BLE001 - report the exact runtime denial
                    failures.append(f"audit_writer dispatch EXECUTE: {type(exc).__name__}: {str(exc)[:200]}")
                finally:
                    probe.rollback()
        finally:
            audit_engine.dispose()
    if failures:
        raise RuntimeError(
            "KP-008 runtime privilege probe FAILED (fresh least-privilege sessions): " + " | ".join(failures)
        )


def _password_env(workload: str) -> str:
    return f"KP_DB_PASSWORD_{workload.upper().replace('-', '_')}"


def _ensure_login_role(raw: object, role_name: str, password: str, *, exists: bool) -> None:
    action = sql.SQL("ALTER") if exists else sql.SQL("CREATE")
    statement = sql.SQL(
        "{} ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    ).format(
        action,
        sql.Identifier(role_name),
        sql.Literal(password),
    )
    raw.execute(statement)  # type: ignore[attr-defined]


def _reset_privileges(connection: object, role_name: str) -> None:
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role_name}"))  # type: ignore[attr-defined]
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role_name}"))  # type: ignore[attr-defined]
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {role_name}"))  # type: ignore[attr-defined]


def _grant_workload(connection: object, workload: str, role_name: str) -> None:
    connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role_name}"))  # type: ignore[attr-defined]
    if workload == "audit-anchor":
        for table, columns in AUDIT_ANCHOR_COLUMN_GRANTS.items():
            connection.execute(  # type: ignore[attr-defined]
                text(f"GRANT SELECT ({', '.join(columns)}) ON TABLE {table} TO {role_name}")
            )
        return
    for privileges, tables in TABLE_GRANTS[workload].items():
        connection.execute(  # type: ignore[attr-defined]
            text(f"GRANT {privileges} ON TABLE {', '.join(tables)} TO {role_name}")
        )
    for privilege, table_columns in WORKLOAD_COLUMN_GRANTS.get(workload, {}).items():
        for table, columns in table_columns.items():
            connection.execute(  # type: ignore[attr-defined]
                text(f"GRANT {privilege} ({', '.join(columns)}) ON TABLE {table} TO {role_name}")
            )


def main() -> None:
    database_url = os.environ.get("DATABASE_URL", "")
    audit_password = os.environ.get("AUDIT_WRITER_PASSWORD", "")
    audit_root_key = os.environ.get("AUDIT_ROOT_KEY", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if not audit_password:
        raise RuntimeError("AUDIT_WRITER_PASSWORD is required")
    if len(audit_root_key) != 64 or any(ch not in "0123456789abcdef" for ch in audit_root_key):
        raise RuntimeError("AUDIT_ROOT_KEY must be 64 lowercase hexadecimal characters")
    runtime_passwords: dict[str, str] = {}
    for workload in RUNTIME_ROLES:
        password = os.environ.get(_password_env(workload))
        if workload in REQUIRED_WORKLOADS and not password:
            raise RuntimeError(f"missing required database password: {_password_env(workload)}")
        if password:
            runtime_passwords[workload] = password

    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.begin() as connection:
        raw = connection.connection.driver_connection
        if raw is None:
            raise RuntimeError("database driver connection is unavailable")
        # Validate the immutable audit root before changing roles or applying
        # migrations on an existing installation. Key rotation requires a
        # separately reviewed recovery procedure with evidence continuity.
        if connection.scalar(text("SELECT to_regclass('public.audit_integrity_secret')")):
            installed_audit_root = connection.scalar(
                text("SELECT key_hex FROM public.audit_integrity_secret WHERE singleton_id = 1")
            )
            if installed_audit_root is not None and not hmac.compare_digest(str(installed_audit_root), audit_root_key):
                raise RuntimeError(
                    "AUDIT_ROOT_KEY differs from the installed audit root; automatic rotation is refused"
                )
        audit_exists = bool(connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer'")))
        _ensure_login_role(raw, "audit_writer", audit_password, exists=audit_exists)
        audit_owner_exists = bool(connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner'")))
        if not audit_owner_exists:
            raw.execute(
                "CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOREPLICATION NOBYPASSRLS"
            )
        migration_role = str(connection.scalar(text("SELECT current_user")))
        raw.execute(sql.SQL("GRANT audit_owner TO {}").format(sql.Identifier(migration_role)))
        for workload, role_name in RUNTIME_ROLES.items():
            exists = bool(
                connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"), {"role_name": role_name})
            )
            password = runtime_passwords.get(workload)
            if password:
                _ensure_login_role(raw, role_name, password, exists=exists)
            # Missing optional-worker configuration is not authorization to
            # disable a preserved login or revoke its privileges. Explicit
            # role retirement belongs to a separately reviewed operation.

        # audit_writer needs CREATE only while legacy migrations transfer the
        # two audit tables. Ownership returns to the migration principal below.
        connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_writer"))

    config = Config(os.environ.get("KP_ALEMBIC_INI", DEFAULT_ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    with engine.begin() as connection:
        # The NOLOGIN owner is reachable only by the explicit migration
        # principal. No workload or dispatcher login can exploit owner bypass.
        # PostgreSQL requires the *incoming* owner to hold CREATE on the object's
        # schema before ALTER ... OWNER succeeds. A superuser migration principal
        # bypasses this check (local dev), but Azure Database for PostgreSQL's
        # admin is not a superuser, so grant CREATE to audit_owner transiently and
        # revoke it below, leaving the NOLOGIN owner no standing schema-create right.
        connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_owner"))
        for table_name in (
            "audit_events",
            "audit_chain_head",
            "audit_integrity_secret",
            "transactional_outbox",
        ):
            connection.execute(text(f"ALTER TABLE public.{table_name} OWNER TO audit_owner"))
        for signature in (
            "kp_dispatch_audit_outbox(uuid)",
            "kp_dispatch_pending_audit(integer)",
            "kp_claim_queue_outbox(integer)",
            "kp_complete_outbox(uuid)",
            "kp_fail_outbox(uuid,text)",
            "kp_outbox_health()",
            "kp_verify_audit_head()",
        ):
            connection.execute(text(f"ALTER FUNCTION public.{signature} OWNER TO audit_owner"))
        connection.execute(text("REVOKE CREATE ON SCHEMA public FROM audit_owner"))
        # Azure's admin is not a superuser: the SECURITY DEFINER audit functions
        # execute as audit_owner and must be able to call pgcrypto's digest/hmac
        # (used to hash the audit chain). Grant those explicitly so correctness
        # does not depend on PUBLIC's default execute; ignore absence defensively.
        connection.execute(
            text(
                "DO $$ BEGIN "
                "GRANT EXECUTE ON FUNCTION public.digest(bytea, text) TO audit_owner; "
                "GRANT EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) TO audit_owner; "
                "EXCEPTION WHEN undefined_function OR undefined_object THEN NULL; END $$"
            )
        )
        installed_audit_root = connection.scalar(
            text("SELECT key_hex FROM public.audit_integrity_secret WHERE singleton_id = 1")
        )
        if installed_audit_root is None:
            connection.execute(
                text("INSERT INTO public.audit_integrity_secret (singleton_id, key_hex) VALUES (1, :key)"),
                {"key": audit_root_key},
            )
        elif not hmac.compare_digest(str(installed_audit_root), audit_root_key):
            raise RuntimeError("AUDIT_ROOT_KEY differs from the installed audit root; automatic rotation is refused")
        # Remove PostgreSQL's ambient PUBLIC path before granting named roles.
        # Otherwise a role-specific REVOKE could be bypassed through PUBLIC.
        connection.execute(text("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC"))
        connection.execute(text("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC"))
        connection.execute(text("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC"))
        legacy_worker_exists = bool(
            connection.scalar(
                text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"),
                {"role_name": "worker"},
            )
        )
        if legacy_worker_exists:
            # Migration 0031 supports older monolithic deployments, but a
            # managed deployment must retain ledger authority only on the
            # dedicated retention login after its privilege reset.
            connection.execute(text("REVOKE ALL ON TABLE awareness_ledger_entries FROM worker"))
        # audit_events, audit_chain_head, audit_integrity_secret,
        # transactional_outbox and the audit/outbox functions are owned by
        # audit_owner. Under Azure Database for PostgreSQL the migration
        # principal is not a superuser, and a GRANT/REVOKE it issues on another
        # role's objects does not take effect, so these privileges must be
        # (re)issued AS the owning role. Do so explicitly.
        connection.execute(text("SET ROLE audit_owner"))
        try:
            connection.execute(
                text(
                    "REVOKE ALL PRIVILEGES ON TABLE audit_events, audit_chain_head, "
                    "audit_integrity_secret, transactional_outbox FROM audit_writer"
                )
            )
            connection.execute(text("GRANT SELECT ON TABLE audit_events, audit_chain_head TO audit_writer"))
            connection.execute(
                text(
                    "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox(uuid), kp_dispatch_pending_audit(integer), "
                    "kp_claim_queue_outbox(integer), kp_complete_outbox(uuid), kp_fail_outbox(uuid,text), "
                    "kp_outbox_health(), kp_verify_audit_head() TO audit_writer"
                )
            )
        finally:
            connection.execute(text("RESET ROLE"))
        connection.execute(text("REVOKE CREATE ON SCHEMA public FROM audit_writer"))
        connection.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer"))
        for workload, role_name in RUNTIME_ROLES.items():
            if workload in runtime_passwords:
                _reset_privileges(connection, role_name)
                _grant_workload(connection, workload, role_name)
                # Workloads may create intent but cannot select another
                # workload's bearer payload or alter dispatch/evidence state.
                # transactional_outbox and the two read-only audit functions are
                # owned by the NOLOGIN audit_owner, so these privileges are issued
                # AS the owner. The column list intentionally excludes origin_role
                # (defaults to session_user) and status so a workload cannot forge
                # provenance or mark its own intent dispatched. The authoritative
                # KP-008 check is the post-commit fresh-session probe below, not
                # this in-transaction grant -- an in-transaction privilege check
                # can read true while a fresh runtime session is still denied.
                connection.execute(text("SET ROLE audit_owner"))
                try:
                    if workload != "audit-anchor":
                        outbox_insert_columns = ", ".join(OUTBOX_INSERT_COLUMNS)
                        connection.execute(
                            text(
                                f"GRANT INSERT ({outbox_insert_columns}) "
                                f"ON TABLE public.transactional_outbox TO {role_name}"
                            )
                        )
                        # enqueue uses INSERT ... ON CONFLICT (idempotency_key)
                        # DO NOTHING; the conflict arbiter needs SELECT on the
                        # arbiter column, or the INSERT is denied "for table"
                        # (KP-008). Column-scoped SELECT on idempotency_key alone
                        # satisfies it without exposing payload or origin_role.
                        outbox_conflict_columns = ", ".join(OUTBOX_CONFLICT_SELECT_COLUMNS)
                        connection.execute(
                            text(
                                f"GRANT SELECT ({outbox_conflict_columns}) "
                                f"ON TABLE public.transactional_outbox TO {role_name}"
                            )
                        )
                    else:
                        anchor_functions = ", ".join(AUDIT_ANCHOR_FUNCTIONS)
                        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {anchor_functions} TO {role_name}"))
                finally:
                    connection.execute(text("RESET ROLE"))

    # Block 2 has committed. Verify from fresh runtime logins that the audit
    # write path actually works, and fail the deploy with the exact denial if
    # not (KP-008). This is the authoritative gate; do not trust the
    # in-transaction admin-session checks above.
    if runtime_passwords and audit_password:
        _probe_runtime_privileges(database_url, runtime_passwords, audit_password)


if __name__ == "__main__":
    main()
