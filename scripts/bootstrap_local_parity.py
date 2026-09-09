#!/usr/bin/env python3
"""Close the local/production audit parity gap.

Runs AFTER Alembic migrations (tables exist) and BEFORE bootstrap_local_audit.py
(audit chain verification).  Imports kp_database.grants as the single source of
truth and applies the same ownership/grant/probe logic as azure_migrate.py,
adapted for the local superuser context.

Env vars:
    DATABASE_URL            Required.  Must target localhost kingphisher database.
    KP_DEV_RUNTIME_PASSWORD Shared dev password for all runtime LOGIN roles.
                            Defaults to "dev-runtime-password" if unset.
    KP_LOCAL_PARITY_VERIFY  If "1", run the KP-008 runtime privilege probe after grants.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from dotenv import load_dotenv
from kp_database.grants import (
    AUDIT_ANCHOR_COLUMN_GRANTS,
    AUDIT_ANCHOR_FUNCTIONS,
    OUTBOX_CONFLICT_SELECT_COLUMNS,
    OUTBOX_INSERT_COLUMNS,
    RUNTIME_ROLES,
    SENSITIVE_TABLES,
    TABLE_GRANTS,
    WORKLOAD_COLUMN_GRANTS,
    all_matrix_tables,
)
from kp_database.session import create_db_engine
from sqlalchemy import text
from sqlalchemy.engine import Engine

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get("KP_DISABLE_DOTENV") != "1":
    load_dotenv(ROOT / ".env", override=False)

_DEFAULT_PASSWORD = "dev-runtime-password"  # noqa: S105 - dev-only bootstrap default
_OWNED_TABLES = ("audit_events", "audit_chain_head", "audit_integrity_secret", "transactional_outbox")
_OWNED_FUNCTIONS = (
    "kp_dispatch_audit_outbox(uuid)",
    "kp_dispatch_pending_audit(integer)",
    "kp_claim_queue_outbox(integer)",
    "kp_complete_outbox(uuid)",
    "kp_fail_outbox(uuid,text)",
    "kp_outbox_health()",
    "kp_verify_audit_head()",
)


def _require_local_database(database_url: str) -> None:
    url = create_db_engine(database_url).url
    host = (url.host or "").lower()
    database = unquote(url.database or "")
    if host not in {"localhost", "127.0.0.1", "::1"} or database != "kingphisher":
        raise RuntimeError("local parity bootstrap is restricted to the loopback kingphisher development database")


def _create_or_alter_role(connection: Any, role_name: str, password: str) -> None:
    exists = bool(
        connection.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role_name"),
            {"role_name": role_name},
        ).scalar()
    )
    if exists:
        connection.execute(text(f"ALTER ROLE {role_name} LOGIN PASSWORD '{password}'"))
    else:
        connection.execute(
            text(
                f"CREATE ROLE {role_name} LOGIN PASSWORD '{password}' "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
            )
        )


def _reset_privileges(connection: Any, role_name: str) -> None:
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role_name}"))
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role_name}"))
    connection.execute(text(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {role_name}"))


def _grant_workload(connection: Any, workload: str, role_name: str) -> None:
    connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role_name}"))
    if workload == "audit-anchor":
        for table, columns in AUDIT_ANCHOR_COLUMN_GRANTS.items():
            connection.execute(text(f"GRANT SELECT ({', '.join(columns)}) ON TABLE {table} TO {role_name}"))
        return
    for privileges, tables in TABLE_GRANTS[workload].items():
        connection.execute(text(f"GRANT {privileges} ON TABLE {', '.join(tables)} TO {role_name}"))
    for privilege, table_columns in WORKLOAD_COLUMN_GRANTS.get(workload, {}).items():
        for table, columns in table_columns.items():
            connection.execute(text(f"GRANT {privilege} ({', '.join(columns)}) ON TABLE {table} TO {role_name}"))


def _grant_outbox_as_audit_owner(connection: Any, workload: str, role_name: str) -> None:
    """Grant outbox column-scoped INSERT/SELECT as audit_owner (owner of outbox)."""
    connection.execute(text("SET ROLE audit_owner"))
    try:
        if workload != "audit-anchor":
            outbox_insert_columns = ", ".join(OUTBOX_INSERT_COLUMNS)
            connection.execute(
                text(f"GRANT INSERT ({outbox_insert_columns}) ON TABLE public.transactional_outbox TO {role_name}")
            )
            outbox_conflict_columns = ", ".join(OUTBOX_CONFLICT_SELECT_COLUMNS)
            connection.execute(
                text(f"GRANT SELECT ({outbox_conflict_columns}) ON TABLE public.transactional_outbox TO {role_name}")
            )
        else:
            anchor_functions = ", ".join(AUDIT_ANCHOR_FUNCTIONS)
            connection.execute(text(f"GRANT EXECUTE ON FUNCTION {anchor_functions} TO {role_name}"))
    finally:
        connection.execute(text("RESET ROLE"))


def main() -> int:
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    _require_local_database(database_url)

    password = os.environ.get("KP_DEV_RUNTIME_PASSWORD", _DEFAULT_PASSWORD)
    verify = os.environ.get("KP_LOCAL_PARITY_VERIFY", "0") == "1"

    engine: Engine = create_db_engine(database_url)
    try:
        with engine.begin() as connection:
            # --- audit_owner: NOLOGIN role that owns audit tables/functions ---
            if not connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner'")).scalar():
                connection.execute(
                    text(
                        "CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                        "NOINHERIT NOREPLICATION NOBYPASSRLS"
                    )
                )

            # --- Ownership transfer ---
            connection.execute(text("GRANT USAGE, CREATE ON SCHEMA public TO audit_owner"))
            for table_name in _OWNED_TABLES:
                connection.execute(text(f"ALTER TABLE public.{table_name} OWNER TO audit_owner"))
            for signature in _OWNED_FUNCTIONS:
                connection.execute(text(f"ALTER FUNCTION public.{signature} OWNER TO audit_owner"))
            connection.execute(text("REVOKE CREATE ON SCHEMA public FROM audit_owner"))

            # pgcrypto functions (defensive; ignore absence)
            connection.execute(
                text(
                    "DO $$ BEGIN "
                    "GRANT EXECUTE ON FUNCTION public.digest(bytea, text) TO audit_owner; "
                    "GRANT EXECUTE ON FUNCTION public.hmac(bytea, bytea, text) TO audit_owner; "
                    "EXCEPTION WHEN undefined_function OR undefined_object THEN NULL; END $$"
                )
            )

            # --- Revoke PUBLIC (ambient path bypass) ---
            connection.execute(text("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC"))
            connection.execute(text("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC"))
            connection.execute(text("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC"))

            # --- Legacy worker role access ---
            if connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'worker'")).scalar():
                connection.execute(text("REVOKE ALL ON TABLE awareness_ledger_entries FROM worker"))

            # --- audit_writer grants (as audit_owner) ---
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
            connection.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer"))

            # --- Runtime LOGIN roles + full grant matrix ---
            for workload, role_name in RUNTIME_ROLES.items():
                _create_or_alter_role(connection, role_name, password)
                _reset_privileges(connection, role_name)
                _grant_workload(connection, workload, role_name)
                _grant_outbox_as_audit_owner(connection, workload, role_name)

            # --- audit_writer outbox column-scoped grants ---
            connection.execute(text("SET ROLE audit_owner"))
            try:
                outbox_insert_columns = ", ".join(OUTBOX_INSERT_COLUMNS)
                connection.execute(
                    text(f"GRANT INSERT ({outbox_insert_columns}) ON TABLE public.transactional_outbox TO audit_writer")
                )
                outbox_conflict_columns = ", ".join(OUTBOX_CONFLICT_SELECT_COLUMNS)
                connection.execute(
                    text(
                        f"GRANT SELECT ({outbox_conflict_columns}) ON TABLE public.transactional_outbox TO audit_writer"
                    )
                )
            finally:
                connection.execute(text("RESET ROLE"))

        print("local audit parity bootstrap complete")
    finally:
        engine.dispose()

    if verify:
        _probe_runtime_privileges(database_url, password)

    return 0


def _probe_runtime_privileges(database_url: str, password: str) -> None:
    """Fresh-login effect check for every workload role (KP-008, both directions)."""
    from kp_database.grants import TABLE_VERBS, expected_table_privilege

    failures: list[str] = []
    all_tables = all_matrix_tables() | SENSITIVE_TABLES

    for workload, role_name in RUNTIME_ROLES.items():
        probe_url = database_url.replace("//kingphisher:", f"//{role_name}:{password}@")
        engine = create_db_engine(probe_url)
        try:
            with engine.connect() as probe:
                for table in sorted(all_tables):
                    for verb in TABLE_VERBS:
                        expected = expected_table_privilege(workload, table, verb)
                        actual = bool(
                            probe.execute(
                                text("SELECT has_table_privilege(:t, :v)"),
                                {"t": f"public.{table}", "v": verb},
                            ).scalar()
                        )
                        if actual != expected:
                            direction = "missing" if expected else "unexpectedly granted"
                            failures.append(f"{role_name}: {verb} on {table} {direction}")
                probe.rollback()
        finally:
            engine.dispose()

    if failures:
        raise RuntimeError("KP-008 runtime privilege probe FAILED: " + " | ".join(failures))
    print("KP-008 runtime privilege probe passed")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        raise SystemExit(f"local parity bootstrap failed: {exc}") from None
