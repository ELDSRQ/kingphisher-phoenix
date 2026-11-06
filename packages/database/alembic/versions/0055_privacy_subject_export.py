"""Governed, bounded privacy-subject projection without broad outcome reads.

Revision ID: 0055_privacy_subject_export
Revises: 0054_queue_reconcile_roles

The application authorizes HANDLE_PRIVACY, matches the decrypted request's
mailbox hash to its recipients and derives their governed pseudonyms. PostgreSQL
cannot derive that identity from application-encrypted fields. It additionally
authenticates the operator login, verified request, subject existence and exact
tenant/key/pseudonym bounds. The definer returns only the minimized projection.
"""

from alembic import op

revision = "0055_privacy_subject_export"
down_revision = "0054_queue_reconcile_roles"
branch_labels = None
depends_on = None

SIGNATURE = "public.kp_privacy_subject_ledger(uuid,uuid,text,text,text,integer)"


def upgrade() -> None:
    op.execute("""CREATE FUNCTION public.kp_privacy_subject_ledger(
        p_request_id uuid, p_recipient_id uuid, p_tenant_scope text,
        p_pseudonym text, p_key_version text, p_limit integer)
        RETURNS TABLE(campaign_id uuid, campaign_date date, campaign_date_basis text,
            delivered boolean, observed_open boolean, observed_click boolean,
            confirmed_interaction boolean, reported boolean, training_started boolean,
            training_completed boolean, no_activity_at_close boolean)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        BEGIN
            IF session_user <> 'kp_operator' THEN
                RAISE EXCEPTION 'privacy subject export is not authorized' USING ERRCODE = '42501';
            END IF;
            IF p_tenant_scope IS DISTINCT FROM 'single_tenant_database'
                OR p_pseudonym IS NULL OR p_pseudonym !~ '^[0-9a-f]{64}$'
                OR p_key_version IS NULL OR p_key_version !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$'
                OR p_limit IS NULL OR p_limit < 1 OR p_limit > 501 THEN
                RAISE EXCEPTION 'privacy subject export bounds are invalid' USING ERRCODE = '22023';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM public.privacy_requests r
                WHERE r.privacy_request_id = p_request_id AND r.status IN ('verified', 'in_progress')
                    AND r.verified_at IS NOT NULL)
                OR NOT EXISTS (SELECT 1 FROM public.recipients r WHERE r.recipient_id = p_recipient_id) THEN
                RAISE EXCEPTION 'privacy request or subject is not authorized' USING ERRCODE = '42501';
            END IF;
            RETURN QUERY SELECT l.campaign_id, l.campaign_date, l.campaign_date_basis::text,
                l.delivered, l.observed_open, l.observed_click, l.confirmed_interaction, l.reported,
                l.training_started, l.training_completed, l.no_activity_at_close
                FROM public.awareness_ledger_entries l
                WHERE l.tenant_scope = p_tenant_scope AND l.recipient_pseudonym = p_pseudonym
                    AND l.pseudonym_key_version = p_key_version
                ORDER BY l.campaign_date, l.campaign_id, l.awareness_ledger_entry_id LIMIT p_limit;
        END $$""")
    op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC")
    # A NOINHERIT migrator can already encounter audit_owner-owned tables.
    # Skip redundant grants there; otherwise grant just this function's reads
    # from the migration-owned business tables before transferring the function.
    op.execute("""DO $$ BEGIN
        IF (SELECT pg_get_userbyid(relowner) FROM pg_class
            WHERE oid='public.awareness_ledger_entries'::regclass) <> 'audit_owner' THEN
            GRANT SELECT (tenant_scope, recipient_pseudonym, pseudonym_key_version, campaign_id,
                campaign_date, campaign_date_basis, delivered, observed_open, observed_click,
                confirmed_interaction, reported, training_started, training_completed,
                no_activity_at_close, awareness_ledger_entry_id) ON public.awareness_ledger_entries TO audit_owner;
        END IF;
        IF (SELECT pg_get_userbyid(relowner) FROM pg_class
            WHERE oid='public.privacy_requests'::regclass) <> 'audit_owner' THEN
            GRANT SELECT (privacy_request_id, status, verified_at) ON public.privacy_requests TO audit_owner;
        END IF;
        IF (SELECT pg_get_userbyid(relowner) FROM pg_class
            WHERE oid='public.recipients'::regclass) <> 'audit_owner' THEN
            GRANT SELECT (recipient_id) ON public.recipients TO audit_owner;
        END IF;
        GRANT USAGE, CREATE ON SCHEMA public TO audit_owner;
        ALTER FUNCTION public.kp_privacy_subject_ledger(uuid,uuid,text,text,text,integer) OWNER TO audit_owner;
        REVOKE CREATE ON SCHEMA public FROM audit_owner;
    END $$""")
    op.execute("SET LOCAL ROLE audit_owner")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_operator') THEN
            GRANT EXECUTE ON FUNCTION public.kp_privacy_subject_ledger(uuid,uuid,text,text,text,integer) TO kp_operator;
        END IF;
    END $$""")
    op.execute("RESET ROLE")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_operator') THEN
            GRANT SELECT (disposition, received_at) ON public.reported_mail_receipts,
                public.reply_mail_receipts TO kp_operator;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("SET LOCAL ROLE audit_owner")
    op.execute(f"DROP FUNCTION {SIGNATURE}")
    op.execute("RESET ROLE")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_operator') THEN
            REVOKE SELECT (disposition, received_at) ON public.reported_mail_receipts,
                public.reply_mail_receipts FROM kp_operator;
        END IF;
    END $$""")
