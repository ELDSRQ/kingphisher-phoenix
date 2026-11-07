"""Permit delivery's live exclusion check without reading private reasons.

Revision ID: 0058_delivery_exclusion_grants
Revises: 0057_runtime_feature_grants

Additive column grants only, for an already existing role. No login changes,
exclusion mutations or access to encrypted reasons/operator identities.
"""

from alembic import op

revision = "0058_delivery_exclusion_grants"
down_revision = "0057_runtime_feature_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            GRANT SELECT (recipient_id, revoked_at, expires_at, campaign_id)
                ON public.recipient_exclusions TO kp_worker_delivery;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            REVOKE SELECT (recipient_id, revoked_at, expires_at, campaign_id)
                ON public.recipient_exclusions FROM kp_worker_delivery;
        END IF;
    END $$""")
