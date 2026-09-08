"""Authoritative role -> (table, privileges) grant matrix (single source of truth).

DRAFT (AUD-002). This module is the *one* place the least-privilege runtime
grant matrix is declared. ``scripts/azure_migrate.py`` imports and consumes it
instead of carrying its own literal copy, and the runtime KP-008 privilege probe
and the effect-level tests iterate the same structures. Nothing here executes
SQL; it is pure data plus small pure helpers so it can be imported from a
migration, a script, or a test without a database connection.

Why this exists (KP-008 structural root): the grant matrix was previously a
literal embedded in ``scripts/azure_migrate.py``. Legacy, scattered
``DO``/``IF EXISTS`` grant blocks in the Alembic revisions (see MODULE NOTE at
the bottom) granted overlapping/older role names. With two+ sources of truth,
the runtime privileges a workload actually received depended on which path ran,
which is exactly how a role ended up able (or unable) to enqueue. Centralizing
the matrix here makes the authoritative set reviewable in one diff and lets the
runtime probe assert the *effect* (has_table_privilege) rather than SQL strings.

The privilege strings (dict keys) are kept byte-identical to the historical
``TABLE_GRANTS`` literal so the emitted ``GRANT ... TO`` statements are
unchanged and existing string-level contract tests keep passing.
"""

from __future__ import annotations

from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Role model
# ---------------------------------------------------------------------------

#: workload key -> PostgreSQL LOGIN role name
RUNTIME_ROLES: dict[str, str] = {
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

#: workloads whose passwords are mandatory for a managed bootstrap
REQUIRED_WORKLOADS = frozenset(
    {"operator", "tracking", "ingestion", "delivery", "retention", "reminder", "alert", "audit-anchor"}
)

# The four table verbs the negative-direction probe asserts are DENIED on every
# table outside a workload's slice.
TABLE_VERBS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")

# ---------------------------------------------------------------------------
# The authoritative matrix
# ---------------------------------------------------------------------------
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
        # The operator reads suppression state and can deactivate (toggle
        # active). INSERT and DELETE remain delivery-worker-only; provider
        # evidence is never created or removed by the console.
        "SELECT, UPDATE": ("recipient_delivery_suppressions",),
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

#: privilege -> {table -> columns}. Currently empty (all column-scoping is
#: expressed through the audit-anchor and outbox grants below), but kept so a
#: future column-scoped workload grant has a home in the single source of truth.
WORKLOAD_COLUMN_GRANTS: dict[str, dict[str, dict[str, tuple[str, ...]]]] = {}

#: audit-anchor is a read-only evidence reader: column-scoped SELECT only.
AUDIT_ANCHOR_COLUMN_GRANTS: dict[str, tuple[str, ...]] = {
    "audit_events": (
        "actor",
        "action",
        "object_type",
        "object_id",
        "occurred_at",
        "detail",
        # origin_role is a chain-v2 CANONICAL field. AuditStore.verify() rebuilds
        # the canonical payload from the row's own columns and compares, so a
        # column it cannot read is a column it cannot bind — and this role's whole
        # job is tamper detection. Without this grant an origin_role-only rewrite
        # was invisible to the anchor's verification (verify() falls back to the
        # recorded canonical text for readers lacking the column, which is exactly
        # the value an attacker editing columns would leave untouched).
        # It is read-only and strictly less sensitive than actor/action/detail,
        # which this role already reads. See
        # docs/design/AUDIT-CHAIN-INTEGRITY-2026-09.md.
        "origin_role",
        "prev_hash",
        "event_hash",
        "nonce",
        "canonical_payload",
        "chain_version",
    ),
    "audit_chain_head": ("id", "event_hash", "signature", "signed_at"),
}

# ---------------------------------------------------------------------------
# Outbox / audit runtime grants (also part of the single source of truth)
# ---------------------------------------------------------------------------
# These are owned by the NOLOGIN ``audit_owner`` and issued AS that owner in the
# bootstrap. They are declared here as data so the emitter and the probe agree.

#: every enqueueing workload may INSERT intent into the outbox with these
#: columns only (origin_role/status intentionally excluded — a workload cannot
#: forge provenance or mark its own intent dispatched).
OUTBOX_INSERT_COLUMNS: tuple[str, ...] = (
    "outbox_id",
    "kind",
    "topic",
    "payload",
    "idempotency_key",
    "available_at",
)
#: ON CONFLICT (idempotency_key) DO NOTHING needs SELECT on the arbiter column,
#: or the INSERT is denied "for table" (KP-008 root cause). Column-scoped so
#: payload/origin_role stay unreadable.
OUTBOX_CONFLICT_SELECT_COLUMNS: tuple[str, ...] = ("idempotency_key",)

#: audit-anchor gets EXECUTE on the two read-only verification functions only.
AUDIT_ANCHOR_FUNCTIONS: tuple[str, ...] = ("kp_outbox_health()", "kp_verify_audit_head()")

#: high-value tables the negative-direction probe always includes in the denied
#: universe so a workload is proven to have NO access to audit evidence / the
#: integrity secret even though they never appear in TABLE_GRANTS.
SENSITIVE_TABLES: frozenset[str] = frozenset(
    {"audit_events", "audit_chain_head", "audit_integrity_secret", "transactional_outbox"}
)


# ---------------------------------------------------------------------------
# Pure helpers (no database access)
# ---------------------------------------------------------------------------
def enqueue_workloads() -> frozenset[str]:
    """Workloads that enqueue into the transactional outbox (all but audit-anchor)."""
    return frozenset(RUNTIME_ROLES) - {"audit-anchor"}


def iter_table_grants(workload: str) -> Iterator[tuple[str, tuple[str, ...]]]:
    """Yield ``(privilege_string, tables)`` pairs for a workload, matrix order."""
    yield from TABLE_GRANTS[workload].items()


def table_privileges(workload: str) -> dict[str, set[str]]:
    """Return ``{table: {verb, ...}}`` — the effective table-level verbs."""
    result: dict[str, set[str]] = {}
    for privileges, tables in TABLE_GRANTS.get(workload, {}).items():
        verbs = {verb.strip() for verb in privileges.split(",")}
        for table in tables:
            result.setdefault(table, set()).update(verbs)
    return result


def granted_tables(workload: str) -> set[str]:
    """Tables the workload holds ANY table-level privilege on."""
    return set(table_privileges(workload))


def column_granted_tables(workload: str) -> set[str]:
    """Tables the workload touches only through a column-scoped grant.

    ``has_table_privilege`` reads TRUE when a role holds the verb on ANY column,
    so these tables must be excluded from the blanket negative probe and checked
    with ``has_column_privilege`` instead.
    """
    tables: set[str] = set()
    for table_columns in WORKLOAD_COLUMN_GRANTS.get(workload, {}).values():
        tables.update(table_columns)
    if workload == "audit-anchor":
        tables.update(AUDIT_ANCHOR_COLUMN_GRANTS)
    return tables


def all_matrix_tables() -> set[str]:
    """Union of every table named anywhere in the matrix (table + column + audit)."""
    tables: set[str] = set()
    for workload in TABLE_GRANTS:
        tables |= granted_tables(workload)
        tables |= column_granted_tables(workload)
    tables |= set(AUDIT_ANCHOR_COLUMN_GRANTS)
    tables |= set(SENSITIVE_TABLES)
    return tables


def workload_for_role(role_name: str) -> str:
    """Reverse RUNTIME_ROLES: PostgreSQL role name -> workload key."""
    for workload, name in RUNTIME_ROLES.items():
        if name == role_name:
            return workload
    raise KeyError(role_name)


def _split_privileges(privilege_string: str) -> set[str]:
    return {verb.strip() for verb in privilege_string.split(",")}


def expected_column_verbs(workload: str, table: str) -> set[str]:
    """Verbs a workload holds on SOME column of ``table``.

    This is the oracle for ``has_any_column_privilege()``, NOT for
    ``has_table_privilege()`` — the latter is false for a column-only grant, so
    this set must never feed the table-level oracle (see
    ``expected_table_privilege``).
    """
    verbs: set[str] = set()
    for privilege, table_columns in WORKLOAD_COLUMN_GRANTS.get(workload, {}).items():
        if table in table_columns:
            verbs |= _split_privileges(privilege)
    if workload == "audit-anchor" and table in AUDIT_ANCHOR_COLUMN_GRANTS:
        verbs.add("SELECT")
    if table == "transactional_outbox" and workload in enqueue_workloads():
        verbs.add("INSERT")
        verbs.add("SELECT")
    return verbs


def expected_table_privilege(workload: str, table: str, verb: str) -> bool:
    """Oracle for ``has_table_privilege(role, table, verb)`` from the matrix.

    TABLE-LEVEL ONLY. PostgreSQL's ``has_table_privilege()`` is FALSE for a
    column-only grant — ``has_any_column_privilege()`` is the function that folds
    column grants in. Reporting column-scoped access as a table privilege here
    made the runtime probe demand a table-level grant that KP-008 deliberately
    withholds (the enqueue roles get ``INSERT (cols)`` +
    ``SELECT (idempotency_key)`` precisely so the bearer payload stays
    unreadable), so every enqueue role failed the probe as "SELECT on
    transactional_outbox missing". Column expectations belong in
    ``expected_column_privilege``, which the probe checks separately.

    The single source of truth the runtime probe compares live PostgreSQL
    against, and the same oracle the fast unit-test harness models — so the two
    can never silently disagree.
    """
    return verb in table_privileges(workload).get(table, set())


def expected_column_privilege(workload: str, table: str, column: str, verb: str) -> bool:
    """Oracle for ``has_column_privilege(role, table, column, verb)``."""
    if table == "transactional_outbox" and workload in enqueue_workloads():
        if verb == "INSERT" and column in OUTBOX_INSERT_COLUMNS:
            return True
        if verb == "SELECT" and column in OUTBOX_CONFLICT_SELECT_COLUMNS:
            return True
        # a whole-table verb also covers every column
        return verb in table_privileges(workload).get(table, set())
    if workload == "audit-anchor" and verb == "SELECT" and column in AUDIT_ANCHOR_COLUMN_GRANTS.get(table, ()):
        return True
    for privilege, table_columns in WORKLOAD_COLUMN_GRANTS.get(workload, {}).items():
        if column in table_columns.get(table, ()) and verb in _split_privileges(privilege):
            return True
    # fall back to the whole-table grant
    return verb in table_privileges(workload).get(table, set())


def denied_tables(workload: str) -> set[str]:
    """Tables the workload must have NO table-level access to.

    The negative direction of the KP-008 probe: everything in the known matrix
    universe minus this workload's own slice, minus tables it reaches through a
    column-scoped grant, minus the outbox for enqueueing roles (they hold a
    column-scoped INSERT/SELECT there).
    """
    universe = all_matrix_tables()
    allowed = granted_tables(workload) | column_granted_tables(workload)
    if workload in enqueue_workloads():
        allowed.add("transactional_outbox")
    return universe - allowed


# ---------------------------------------------------------------------------
# MODULE NOTE — legacy scattered grant blocks (FLAGGED FOR REVIEWER, NOT deleted)
# ---------------------------------------------------------------------------
# The following Alembic revisions still carry their own inline GRANT/REVOKE/
# OWNER blocks. They target OLDER role names (``operator_api``, ``worker``,
# ``PUBLIC``) that predate the per-workload roles above, and they run guarded
# (``IF EXISTS`` / ``DO $$``) so they no-op on managed installs where those
# legacy roles do not exist. They are intentionally LEFT IN PLACE for now
# (fresh-install fidelity + monolithic-deployment back-compat) but represent the
# second source of truth this task is consolidating. A reviewer should decide
# whether each is superseded by this matrix + the azure bootstrap:
#
#   - alembic/versions/0001_initial.py:391-392
#       REVOKE UPDATE,DELETE,TRUNCATE ON audit_events FROM PUBLIC;
#       GRANT SELECT,INSERT ON audit_events TO audit_writer
#   - alembic/versions/0002_audit_chain_head.py:37-38
#       REVOKE ... ON audit_chain_head FROM PUBLIC;
#       GRANT SELECT,INSERT,UPDATE ON audit_chain_head TO audit_writer
#   - alembic/versions/0020_transactional_audit_outbox.py:262-266
#       REVOKE ALL ON audit tables + outbox functions FROM PUBLIC
#   - alembic/versions/0021_frozen_campaign_audiences.py:145-146
#       GRANT ... ON audience_groups,... TO operator_api  (legacy role)
#   - alembic/versions/0029_campaign_canary_launch_gate.py:125-131
#       GRANT ... TO operator_api / worker  (legacy roles)
#   - alembic/versions/0031_awareness_ledger.py:119-128
#       REVOKE ALL ... FROM PUBLIC; GRANT ... TO worker / kp_worker_retention
#   - alembic/versions/0010_audit_ownership_separation.py:55-106
#       ownership -> audit_writer (LOGIN); see AUD-002 point 4 — superseded by
#       0034 audit_owner separation (audit_writer must NOT own the audit tables).
#   - infrastructure/containers/postgres-init/001-roles.sh:36-47
#       local-dev ALTER TABLE ... OWNER TO audit_writer — likewise superseded.
