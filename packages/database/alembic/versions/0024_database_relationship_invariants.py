"""Enforce existing assignment, audience, receipt, and outbox invariants.

Revision ID: 0024_database_invariants
Revises: 0023_acs_delivery_receipts
Create Date: 2026-08-27

This revision intentionally does not repair or delete contradictory history.
It reports the offending relationship and row count before adding constraints
so an operator can investigate rather than silently changing evidence.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine import Connection

revision = "0024_database_invariants"
down_revision = "0023_acs_delivery_receipts"
branch_labels = None
depends_on = None


def _require_clean(connection: Connection, *, invariant: str, query: str) -> None:
    violating_rows = int(connection.scalar(sa.text(query)) or 0)
    if violating_rows:
        raise RuntimeError(
            "0024_database_invariants preflight failed: "
            f"{invariant} has {violating_rows} contradictory row(s); "
            "investigate and reconcile them before retrying the migration"
        )


def _preflight(connection: Connection) -> None:
    _require_clean(
        connection,
        invariant="tracking token assignment/campaign binding",
        query="""
            SELECT count(*)
              FROM tracking_tokens token
              LEFT JOIN recipient_assignments assignment
                ON assignment.recipient_assignment_id = token.recipient_assignment_id
               AND assignment.campaign_id = token.campaign_id
             WHERE assignment.recipient_assignment_id IS NULL
        """,
    )
    _require_clean(
        connection,
        invariant="training assignment recipient/campaign binding",
        query="""
            SELECT count(*)
              FROM training_assignments training
              LEFT JOIN recipient_assignments assignment
                ON assignment.recipient_assignment_id = training.recipient_assignment_id
               AND assignment.campaign_id = training.campaign_id
               AND assignment.recipient_id = training.recipient_id
             WHERE training.recipient_assignment_id IS NOT NULL
               AND assignment.recipient_assignment_id IS NULL
        """,
    )
    _require_clean(
        connection,
        invariant="frozen manifest audience-version binding",
        query="""
            SELECT count(*)
              FROM campaign_audience_manifest manifest
              LEFT JOIN campaign_audiences audience
                ON audience.campaign_id = manifest.campaign_id
               AND audience.version = manifest.audience_version
             WHERE audience.campaign_id IS NULL
        """,
    )
    _require_clean(
        connection,
        invariant="provider event delivery-attempt binding",
        query="""
            SELECT count(*)
              FROM delivery_provider_events event
              LEFT JOIN delivery_report_correlations correlation
                ON correlation.delivery_attempt_id = event.delivery_attempt_id
               AND correlation.recipient_assignment_id = event.recipient_assignment_id
             WHERE correlation.delivery_attempt_id IS NULL
        """,
    )
    _require_clean(
        connection,
        invariant="recipient assignment delivery-attempt count",
        query="""
            SELECT count(*)
              FROM recipient_assignments
             WHERE delivery_attempt_count < 0
        """,
    )
    _require_clean(
        connection,
        invariant="transactional outbox kind/topic shape",
        query="""
            SELECT count(*)
              FROM transactional_outbox
             WHERE (kind = 'audit' AND topic IS NOT NULL)
                OR (kind = 'queue' AND (topic IS NULL OR length(trim(topic)) = 0))
        """,
    )
    _require_clean(
        connection,
        invariant="transactional outbox attempt count",
        query="""
            SELECT count(*)
              FROM transactional_outbox
             WHERE attempts < 0
        """,
    )


def upgrade() -> None:
    _preflight(op.get_bind())

    op.create_unique_constraint(
        "uq_campaign_audiences_version_binding",
        "campaign_audiences",
        ["campaign_id", "version"],
    )
    op.create_unique_constraint(
        "uq_recipient_assignments_campaign_binding",
        "recipient_assignments",
        ["recipient_assignment_id", "campaign_id"],
    )
    op.create_unique_constraint(
        "uq_recipient_assignments_identity_binding",
        "recipient_assignments",
        ["recipient_assignment_id", "campaign_id", "recipient_id"],
    )
    op.create_unique_constraint(
        "uq_delivery_report_correlations_attempt_binding",
        "delivery_report_correlations",
        ["recipient_assignment_id", "delivery_attempt_id"],
    )

    op.create_foreign_key(
        "fk_campaign_audience_manifest_version",
        "campaign_audience_manifest",
        "campaign_audiences",
        ["campaign_id", "audience_version"],
        ["campaign_id", "version"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_tracking_tokens_assignment_campaign",
        "tracking_tokens",
        "recipient_assignments",
        ["recipient_assignment_id", "campaign_id"],
        ["recipient_assignment_id", "campaign_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_training_assignments_recipient_identity",
        "training_assignments",
        "recipient_assignments",
        ["recipient_assignment_id", "campaign_id", "recipient_id"],
        ["recipient_assignment_id", "campaign_id", "recipient_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_delivery_provider_events_attempt_binding",
        "delivery_provider_events",
        "delivery_report_correlations",
        ["recipient_assignment_id", "delivery_attempt_id"],
        ["recipient_assignment_id", "delivery_attempt_id"],
        ondelete="CASCADE",
    )

    op.create_check_constraint(
        "ck_recipient_assignments_attempt_count_nonnegative",
        "recipient_assignments",
        "delivery_attempt_count >= 0",
    )
    op.create_check_constraint(
        "ck_transactional_outbox_topic_matches_kind",
        "transactional_outbox",
        "(kind = 'audit' AND topic IS NULL) OR (kind = 'queue' AND topic IS NOT NULL AND length(trim(topic)) > 0)",
    )
    op.create_check_constraint(
        "ck_transactional_outbox_attempts_nonnegative",
        "transactional_outbox",
        "attempts >= 0",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_transactional_outbox_attempts_nonnegative",
        "transactional_outbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_transactional_outbox_topic_matches_kind",
        "transactional_outbox",
        type_="check",
    )
    op.drop_constraint(
        "ck_recipient_assignments_attempt_count_nonnegative",
        "recipient_assignments",
        type_="check",
    )

    op.drop_constraint(
        "fk_delivery_provider_events_attempt_binding",
        "delivery_provider_events",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_training_assignments_recipient_identity",
        "training_assignments",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_tracking_tokens_assignment_campaign",
        "tracking_tokens",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_campaign_audience_manifest_version",
        "campaign_audience_manifest",
        type_="foreignkey",
    )

    op.drop_constraint(
        "uq_delivery_report_correlations_attempt_binding",
        "delivery_report_correlations",
        type_="unique",
    )
    op.drop_constraint(
        "uq_recipient_assignments_identity_binding",
        "recipient_assignments",
        type_="unique",
    )
    op.drop_constraint(
        "uq_recipient_assignments_campaign_binding",
        "recipient_assignments",
        type_="unique",
    )
    op.drop_constraint(
        "uq_campaign_audiences_version_binding",
        "campaign_audiences",
        type_="unique",
    )
