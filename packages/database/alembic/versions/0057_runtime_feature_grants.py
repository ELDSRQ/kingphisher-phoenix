"""Add runtime permissions for existing operator, retention and delivery paths.

Revision ID: 0057_runtime_feature_grants
Revises: 0056_adaptive_draft_boundary

Pure additive object grants for roles that already exist. This migration never
creates roles, changes credentials, rewrites data or grants worker cue authority.
The literal grants are frozen; the canonical current bootstrap matrix must agree.
"""

from alembic import op

revision = "0057_runtime_feature_grants"
down_revision = "0056_adaptive_draft_boundary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_operator') THEN
            GRANT SELECT, INSERT, UPDATE ON public.ai_generation_providers,
                public.provider_config_generation, public.console_session_epoch,
                public.credential_rotations, public.training_cue_coverage TO kp_operator;
            GRANT SELECT, INSERT ON public.campaign_cue_coverage_exceptions TO kp_operator;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_retention') THEN
            GRANT SELECT (reply_mail_receipt_id, received_at) ON public.reply_mail_receipts TO kp_worker_retention;
            GRANT DELETE ON public.reply_mail_receipts TO kp_worker_retention;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            GRANT SELECT (campaign_id, recipient_id, audience_version)
                ON public.campaign_audience_manifest TO kp_worker_delivery;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_operator') THEN
            REVOKE SELECT, INSERT, UPDATE ON public.ai_generation_providers,
                public.provider_config_generation, public.console_session_epoch,
                public.credential_rotations, public.training_cue_coverage FROM kp_operator;
            REVOKE SELECT, INSERT ON public.campaign_cue_coverage_exceptions FROM kp_operator;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_retention') THEN
            REVOKE SELECT (reply_mail_receipt_id, received_at) ON public.reply_mail_receipts FROM kp_worker_retention;
            REVOKE DELETE ON public.reply_mail_receipts FROM kp_worker_retention;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_delivery') THEN
            REVOKE SELECT (campaign_id, recipient_id, audience_version)
                ON public.campaign_audience_manifest FROM kp_worker_delivery;
        END IF;
    END $$""")
