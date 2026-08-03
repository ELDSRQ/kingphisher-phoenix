"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-02

"""
from __future__ import annotations

import contextlib

from alembic import op
from kp_database import models  # noqa: F401
from kp_database.base import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline schema is derived from the model definitions so the migration
    # cannot drift from the ORM.
    Base.metadata.create_all(bind=op.get_bind())

    # Defense-in-depth: if run as a superuser (local/dev bootstrap), harden the
    # audit table against UPDATE/DELETE even for the app role. Production
    # grants are owned by infrastructure/terraform.
    bind = op.get_bind()
    with contextlib.suppress(Exception):  # noqa: BLE001 - dev DB may not permit REVOKE
        bind.exec_driver_sql(
            "REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC"
        )
        # Local bootstrap: let the INSERT-only audit role append rows and read
        # the persisted chain head so multiple processes chain together.
        bind.exec_driver_sql(
            "GRANT SELECT, INSERT ON audit_events TO audit_writer"
        )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS retention_actions")
    op.execute("DROP TABLE IF EXISTS audit_events")
    op.execute("DROP TABLE IF EXISTS training_assignments")
    op.execute("DROP TABLE IF EXISTS training_resources")
    op.execute("DROP TABLE IF EXISTS events")
    op.execute("DROP TABLE IF EXISTS recipient_assignments")
    op.execute("DROP TABLE IF EXISTS tracking_tokens")
    op.execute("DROP TABLE IF EXISTS recipient_exclusions")
    op.execute("DROP TABLE IF EXISTS recipients")
    op.execute("DROP TABLE IF EXISTS campaign_approvals")
    op.execute("DROP TABLE IF EXISTS campaigns")
    op.execute("DROP TABLE IF EXISTS template_versions")
    op.execute("DROP TABLE IF EXISTS campaign_patterns")
    op.execute("DROP TABLE IF EXISTS source_items")
    op.execute("DROP TABLE IF EXISTS source_terms")
    op.execute("DROP TABLE IF EXISTS sources")
    op.execute("DROP TABLE IF EXISTS privacy_requests")
