"""Provision least-privilege runtime roles, then run Alembic as the owner."""

from __future__ import annotations

import hmac
import os
import sys
import uuid

from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

RUNTIME_ROLES = {
    "operator": "kp_operator",
    "tracking": "kp_tracking",
    "ingestion": "kp_worker_ingestion",
    "delivery": "kp_worker_delivery",
    "retention": "kp_worker_retention",
    "reminder": "kp_worker_reminder",
    "alert": "kp_worker_alert",
    "audit-anchor": "kp_worker_audit_anchor",
    "generation": "kp_worker_generation",
    "directory": "kp_worker_directory",
    "mailbox": "kp_worker_mailbox",
}
REQUIRED_WORKLOADS = frozenset(
    {"operator", "tracking", "ingestion", "delivery", "retention", "reminder", "alert", "audit-anchor"}
)

# Grants describe current code paths, not broad service categories. A new
# table is intentionally unavailable until this map is reviewed and updated.
TABLE_GRANTS: dict[str, dict[str, tuple[str, ...]]] = {
    "operator": {
        "SELECT, INSERT, UPDATE, DELETE": (
            "sources",
            "source_terms",
            "source_items",
            "campaign_patterns",
            "template_versions",
            "campaigns",
            "campaign_approvals",
            "recipients",
            "recipient_exclusions",
            "tracking_tokens",
            "recipient_assignments",
            "events",
            "training_resources",
            "training_assignments",
            "privacy_requests",
            "privacy_notices",
            "retention_policies",
            "system_safety_state",
            "retention_actions",
            "alert_subscriptions",
            "verified_domains",
            "rules_of_engagement",
            "audience_groups",
            "audience_group_members",
            "campaign_audiences",
            "campaign_audience_manifest",
            "campaign_launch_gates",
        ),
        "SELECT, INSERT, UPDATE": ("campaign_programs",),
        "SELECT, INSERT": ("campaign_program_occurrences",),
        # The console binds the durable launch review (create/re-create) and
        # reads canary membership; re-review deletes and re-inserts these rows.
        "SELECT, INSERT, DELETE": ("campaign_canary_recipients",),
        # The console exposes integration health and campaign reportability,
        # but it never owns provider cursors, receipts or report verifiers.
        "SELECT": (
            "microsoft365_integration_states",
            "delivery_report_correlations",
        ),
    },
    "tracking": {
        "SELECT": ("tracking_tokens", "training_resources", "campaigns"),
        # The first training assignment locks the campaign row and persists
        # its immutable resource binding. The separate column grant below is
        # the only campaign field tracking may change.
        "SELECT, UPDATE": ("recipient_assignments",),
        "SELECT, INSERT": ("events",),
        "SELECT, INSERT, UPDATE": ("training_assignments",),
    },
    "ingestion": {
        "SELECT, UPDATE": ("sources",),
        "SELECT, INSERT": ("source_items", "campaign_patterns"),
        # process_ingestion reads current licence terms (session.get(SourceTerms))
        # to gate fetching; read-only.
        "SELECT": ("source_terms",),
    },
    "delivery": {
        "SELECT": (
            "campaign_approvals",
            "campaign_patterns",
            "recipients",
            "rules_of_engagement",
            "template_versions",
            "tracking_tokens",
            "campaign_audiences",
            "training_resources",
            "campaign_canary_recipients",
        ),
        # system_safety_state is taken with a FOR SHARE lock (with_for_update
        # read=True) which requires UPDATE; campaign_launch_gates is locked and
        # its gate state is mutated during the launch/canary checks.
        "SELECT, UPDATE": ("campaigns", "recipient_assignments", "system_safety_state", "campaign_launch_gates"),
        # One retry-stable row is created before the provider call and updated
        # only with the provider's non-secret acceptance metadata. Delivery
        # receipts may activate a suppression and reserve durable ACS pacing;
        # no delivery path deletes provider evidence or suppressions.
        "SELECT, INSERT": ("delivery_provider_events",),
        "SELECT, INSERT, UPDATE": (
            "delivery_report_correlations",
            "recipient_delivery_suppressions",
            "delivery_pacing_states",
        ),
    },
    "retention": {
        "SELECT": ("retention_policies",),
        # microsoft365_integration_states is locked (FOR UPDATE SKIP LOCKED) and
        # its status/cursor fields updated during reported-mail retention.
        "SELECT, UPDATE": ("campaigns", "microsoft365_integration_states"),
        "SELECT, UPDATE, DELETE": ("recipient_assignments", "tracking_tokens"),
        "SELECT, DELETE": ("events", "training_assignments", "reported_mail_receipts"),
        "SELECT, INSERT": ("retention_actions",),
        "SELECT, INSERT, UPDATE, DELETE": ("awareness_ledger_entries",),
    },
    "reminder": {
        # process_reminder re-reads the assignment row (plain read, no lock).
        "SELECT": ("recipients", "tracking_tokens", "recipient_assignments"),
        "SELECT, UPDATE": ("training_assignments",),
    },
    "alert": {"SELECT, UPDATE": ("alert_subscriptions",)},
    # Direct evidence reads plus SECURITY DEFINER verification functions are
    # the entire anchor database surface. It cannot read the signing secret or
    # outbox payloads, append/dispatch evidence, or access business tables.
    "audit-anchor": {},
    "generation": {
        # process_generation takes FOR UPDATE row locks on the source and pattern
        # rows it advances (with_for_update=True), so it needs UPDATE, not just
        # SELECT, on each — FOR UPDATE requires the UPDATE privilege.
        "SELECT, UPDATE": ("sources", "source_terms", "source_items", "campaign_patterns"),
        "SELECT, INSERT": ("template_versions",),
    },
    "directory": {
        "SELECT": ("audience_groups",),
        "SELECT, INSERT, UPDATE": (
            "microsoft365_integration_states",
            "recipients",
        ),
        "SELECT, INSERT, DELETE": ("audience_group_members",),
        "SELECT, UPDATE": ("campaigns", "campaign_audiences"),
        # A directory membership change invalidates an approved frozen
        # audience. It cannot create or expand a campaign manifest.
        "DELETE": ("campaign_approvals", "campaign_audience_manifest"),
    },
    "mailbox": {
        "SELECT": (
            "tracking_tokens",
            "recipient_assignments",
            "delivery_report_correlations",
        ),
        "SELECT, INSERT": ("events", "reported_mail_receipts"),
        "SELECT, INSERT, UPDATE": ("microsoft365_integration_states",),
    },
}

WORKLOAD_COLUMN_GRANTS: dict[str, dict[str, dict[str, tuple[str, ...]]]] = {}

AUDIT_ANCHOR_COLUMN_GRANTS = {
    "audit_events": (
        "actor",
        "action",
        "object_type",
        "object_id",
        "occurred_at",
        "detail",
        "prev_hash",
        "event_hash",
        "nonce",
        "canonical_payload",
        "chain_version",
    ),
    "audit_chain_head": ("id", "event_hash", "signature", "signed_at"),
}


def _runtime_url(database_url: str, role_name: str, password: str) -> str:
    """Derive a runtime role DSN from the migration DSN (same host/db/params)."""
    return make_url(database_url).set(username=role_name, password=password).render_as_string(hide_password=False)


def _probe_runtime_privileges(database_url: str, operator_password: str, audit_password: str) -> None:
    """Authoritative post-commit KP-008 gate.

    The in-transaction grant checks run as the migration admin and can read true
    while a fresh least-privilege session is still denied at runtime (the KP-008
    contradiction). So verify from ACTUAL role logins, over the same DSN the
    services use, and fail closed with the exact denial rather than shipping a
    deploy that 503s on the first console write. Covers the two synchronous steps
    of an audit write: kp_operator enqueues intent, then audit_writer dispatches.
    """
    failures: list[str] = []
    op_engine = create_engine(_runtime_url(database_url, "kp_operator", operator_password))
    try:
        with op_engine.connect() as probe:
            # exec_driver_sql autobegins a transaction; never commit it, and roll
            # it back in finally so nothing is persisted and any aborted state
            # from a denied INSERT is cleared. Do NOT call probe.begin() here --
            # that conflicts with the already-open autobegun transaction.
            current = probe.exec_driver_sql("SELECT current_user").scalar()
            probe_id = str(uuid.uuid4())
            try:
                probe.exec_driver_sql(
                    "INSERT INTO transactional_outbox "
                    "(outbox_id, kind, payload, idempotency_key, available_at) "
                    "VALUES (%(id)s, 'audit', '{}'::jsonb, %(key)s, now()) "
                    "ON CONFLICT (idempotency_key) DO NOTHING",
                    {"id": probe_id, "key": f"kp008-probe:{probe_id}"},
                )
                print(f"KP-008 probe OK: {current} can INSERT into transactional_outbox", file=sys.stderr, flush=True)
            except Exception as exc:  # noqa: BLE001 - report the exact runtime denial
                failures.append(f"kp_operator enqueue: {type(exc).__name__}: {str(exc)[:200]}")
            finally:
                probe.rollback()
    finally:
        op_engine.dispose()
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

    config = Config("/app/packages/database/alembic.ini")
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
                        connection.execute(
                            text(
                                f"GRANT INSERT (outbox_id, kind, topic, payload, idempotency_key, available_at) "
                                f"ON TABLE public.transactional_outbox TO {role_name}"
                            )
                        )
                    else:
                        connection.execute(
                            text(f"GRANT EXECUTE ON FUNCTION kp_outbox_health(), kp_verify_audit_head() TO {role_name}")
                        )
                finally:
                    connection.execute(text("RESET ROLE"))

    # Block 2 has committed. Verify from fresh runtime logins that the audit
    # write path actually works, and fail the deploy with the exact denial if
    # not (KP-008). This is the authoritative gate; do not trust the
    # in-transaction admin-session checks above.
    operator_password = runtime_passwords.get("operator")
    if operator_password and audit_password:
        _probe_runtime_privileges(database_url, operator_password, audit_password)


if __name__ == "__main__":
    main()
