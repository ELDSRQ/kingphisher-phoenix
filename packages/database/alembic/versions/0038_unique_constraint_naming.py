"""Rename five unique constraints to the declared naming convention.

`Base.metadata` sets ``NAMING_CONVENTION`` (``kp_database.base``) with
``"uq": "uq_%(table_name)s_%(column_0_name)s"``, and the ORM declares these five
columns with ``unique=True``, so SQLAlchemy names their constraints by that
convention. The migrations that created them used hand-abbreviated names
instead, e.g. ``uq_training_assignment_token_hash`` where the convention yields
``uq_training_assignments_training_token_hash``.

Autogenerate matches constraints by NAME, so every one of the five looked like a
missing constraint and the drift gate reported five spurious ``add_constraint``
entries — see ``docs/design/SCHEMA-DRIFT-2026-09-07.md``. The constraints were
present the whole time; only the names disagreed. That noise is worth removing
rather than suppressing: a drift gate that always reports five false positives
is a gate nobody reads, and it would hide a genuinely missing unique constraint
on the training bearer hashes or on ``external_event_id_hash`` (provider-receipt
idempotency).

``ALTER TABLE ... RENAME CONSTRAINT`` is a catalog-only change: no table rewrite,
no index rebuild, no data movement.

Deliberately untouched:
  * ``uq_delivery_report_correlations_attempt_binding`` — composite
    (delivery_attempt_id, recipient_assignment_id), declared explicitly.
  * ``uq_delivery_report_correlations_message_id`` — already matches.
  * ``uq_training_assignment_recipient_assignment`` — declared explicitly.

Revision ID: 0038_unique_constraint_naming
Revises: 0037_knowledge_options_jsonb
Create Date: 2026-09-07
"""

from __future__ import annotations

from alembic import op

revision = "0038_unique_constraint_naming"
down_revision = "0037_knowledge_options_jsonb"
branch_labels = None
depends_on = None

#: (table, current name, convention name)
_RENAMES: tuple[tuple[str, str, str], ...] = (
    (
        "delivery_provider_events",
        "uq_delivery_provider_events_external_hash",
        "uq_delivery_provider_events_external_event_id_hash",
    ),
    (
        "delivery_report_correlations",
        "uq_delivery_report_correlations_assignment",
        "uq_delivery_report_correlations_recipient_assignment_id",
    ),
    (
        "delivery_report_correlations",
        "uq_delivery_report_correlations_verifier",
        "uq_delivery_report_correlations_verifier_hash",
    ),
    (
        "training_assignments",
        "uq_training_assignment_token_hash",
        "uq_training_assignments_training_token_hash",
    ),
    (
        "training_assignments",
        "uq_training_assignment_completion_token_hash",
        "uq_training_assignments_training_completion_token_hash",
    ),
)


def _rename(table: str, old: str, new: str) -> None:
    """Rename only if ``old`` is present and ``new`` is not — idempotent.

    The SQL is built by interpolation because PostgreSQL cannot bind an
    *identifier* as a parameter. Every value comes from the ``_RENAMES`` literal
    above — module constants, never input — so there is no injection path.
    """
    op.execute(
        f"""
        DO $rename$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint con
                  JOIN pg_class rel ON rel.oid = con.conrelid
                 WHERE rel.relname = '{table}' AND con.conname = '{old}'
            ) AND NOT EXISTS (
                SELECT 1 FROM pg_constraint con
                  JOIN pg_class rel ON rel.oid = con.conrelid
                 WHERE rel.relname = '{table}' AND con.conname = '{new}'
            ) THEN
                ALTER TABLE public.{table} RENAME CONSTRAINT {old} TO {new};
            END IF;
        END
        $rename$;
        """
    )


def upgrade() -> None:
    for table, old, new in _RENAMES:
        _rename(table, old, new)


def downgrade() -> None:
    for table, old, new in _RENAMES:
        _rename(table, new, old)
