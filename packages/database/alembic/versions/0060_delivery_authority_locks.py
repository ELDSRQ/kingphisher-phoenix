"""Narrow row-lock privileges for live delivery authorization and training.

Revision ID: 0060_delivery_authority_locks
Revises: 0059_delivery_recipient_lock

PostgreSQL requires UPDATE on at least one column for SELECT FOR SHARE/UPDATE.
Identity-only grants support the exact runtime locks without authority to
revoke authorization, change reviewed content, or alter campaign business data.
Only existing roles receive additive grants; no data or login changes occur.
"""

from alembic import op

revision = "0060_delivery_authority_locks"
down_revision = "0059_delivery_recipient_lock"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            GRANT UPDATE (roe_id) ON public.rules_of_engagement TO kp_worker_delivery;
            GRANT UPDATE (training_resource_id) ON public.training_resources TO kp_worker_delivery;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_tracking') THEN
            GRANT UPDATE (campaign_id) ON public.campaigns TO kp_tracking;
            GRANT UPDATE (training_resource_id) ON public.training_resources TO kp_tracking;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            REVOKE UPDATE (roe_id) ON public.rules_of_engagement FROM kp_worker_delivery;
            REVOKE UPDATE (training_resource_id) ON public.training_resources FROM kp_worker_delivery;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_tracking') THEN
            REVOKE UPDATE (campaign_id) ON public.campaigns FROM kp_tracking;
            REVOKE UPDATE (training_resource_id) ON public.training_resources FROM kp_tracking;
        END IF;
    END $$""")
