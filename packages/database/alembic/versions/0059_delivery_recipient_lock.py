"""Permit delivery's recipient shared lock without mailbox/status writes.

Revision ID: 0059_delivery_recipient_lock
Revises: 0058_delivery_exclusion_grants

PostgreSQL requires UPDATE on at least one column for SELECT FOR SHARE. The
identity column is the narrow lock capability, as for mailbox assignment locks.
No table-wide UPDATE, new role, credential rotation or data mutation occurs.
"""

from alembic import op

revision = "0059_delivery_recipient_lock"
down_revision = "0058_delivery_exclusion_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            GRANT UPDATE (recipient_id) ON public.recipients TO kp_worker_delivery;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            REVOKE UPDATE (recipient_id) ON public.recipients FROM kp_worker_delivery;
        END IF;
    END $$""")
