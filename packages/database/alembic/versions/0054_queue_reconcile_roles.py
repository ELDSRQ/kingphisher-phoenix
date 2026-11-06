"""Constrain restored-queue inspection to each authenticated worker's topic.

Revision ID: 0054_queue_reconcile_roles
Revises: 0053_retention_holds

The SQL limits and role/topic mapping are frozen migration contracts. Tests
compare them with the current Python contract; changing either requires a new
migration, never editing a deployed revision.

Optional timestamp/UUID cursors allow bounded recovery sweeps. Three-argument
callers start at the newest page; each worker can request only its own topic.
"""

from alembic import op

revision = "0054_queue_reconcile_roles"
down_revision = "0053_retention_holds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE FUNCTION public.kp_reconcile_queue_outbox(
        p_topic text, p_window_seconds integer, p_limit integer,
        p_before_dispatched_at timestamptz DEFAULT NULL, p_before_outbox_id uuid DEFAULT NULL)
        RETURNS TABLE(outbox_id uuid, topic text, payload jsonb,
            idempotency_key text, available_at timestamptz, dispatched_at timestamptz)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        DECLARE allowed_topic text;
        BEGIN
            -- session_user remains the authenticated login under definer rights.
            -- current_user would authenticate the owner instead of the worker.
            allowed_topic := CASE session_user
                WHEN 'kp_worker_ingestion' THEN 'ingest'
                WHEN 'kp_worker_generation' THEN 'generate'
                WHEN 'kp_worker_delivery' THEN 'deliver'
                WHEN 'kp_worker_retention' THEN 'retention'
                WHEN 'kp_worker_mailbox' THEN 'mailbox'
                WHEN 'kp_worker_reply_mailbox' THEN 'reply-mailbox'
                WHEN 'kp_worker_reminder' THEN 'remind'
                WHEN 'kp_worker_alert' THEN 'alert'
                WHEN 'kp_worker_directory' THEN 'directory'
                WHEN 'kp_worker_curation' THEN 'curate'
                ELSE NULL END;
            IF allowed_topic IS NULL OR p_topic IS DISTINCT FROM allowed_topic THEN
                RAISE EXCEPTION 'queue reconciliation topic is not authorized' USING ERRCODE = '42501';
            END IF;
            IF p_window_seconds IS NULL OR p_window_seconds < 1 OR p_window_seconds > 7689600
                OR p_limit IS NULL OR p_limit < 1 OR p_limit > 5000 THEN
                RAISE EXCEPTION 'queue reconciliation bounds are invalid' USING ERRCODE = '22023';
            END IF;
            IF (p_before_dispatched_at IS NULL) <> (p_before_outbox_id IS NULL) THEN
                RAISE EXCEPTION 'queue reconciliation cursor is invalid' USING ERRCODE = '22023';
            END IF;
            RETURN QUERY SELECT q.outbox_id, q.topic::text, q.payload,
                q.idempotency_key::text, q.available_at, q.dispatched_at
                FROM public.transactional_outbox AS q
                WHERE q.kind = 'queue' AND q.status = 'dispatched' AND q.topic = p_topic
                    AND q.dispatched_at IS NOT NULL
                    AND q.dispatched_at >= now() - make_interval(secs => p_window_seconds)
                    AND (p_before_dispatched_at IS NULL OR
                        (q.dispatched_at,q.outbox_id) < (p_before_dispatched_at,p_before_outbox_id))
                ORDER BY q.dispatched_at DESC, q.outbox_id DESC LIMIT p_limit;
        END $$""")
    op.execute(
        "REVOKE ALL ON FUNCTION public.kp_reconcile_queue_outbox(text,integer,integer,timestamptz,uuid) FROM PUBLIC"
    )
    # Local installs retain an app-owned outbox, while managed installs transfer
    # it to audit_owner. Grant only the read required in the former case.
    op.execute("""DO $$ BEGIN
        IF (SELECT pg_get_userbyid(relowner) FROM pg_class
            WHERE oid = 'public.transactional_outbox'::regclass) <> 'audit_owner' THEN
            GRANT SELECT ON public.transactional_outbox TO audit_owner;
        END IF;
        GRANT USAGE, CREATE ON SCHEMA public TO audit_owner;
        ALTER FUNCTION public.kp_reconcile_queue_outbox(text,integer,integer,timestamptz,uuid) OWNER TO audit_owner;
        REVOKE CREATE ON SCHEMA public FROM audit_owner;
    END $$""")
    # Managed migrators may be NOINHERIT members of audit_owner. Issue function
    # grants explicitly as the new owner, then restore migration authority for
    # the separately owned business tables below.
    op.execute("SET LOCAL ROLE audit_owner")
    op.execute("""DO $$ DECLARE target text; BEGIN
        FOREACH target IN ARRAY ARRAY['kp_worker_ingestion', 'kp_worker_generation',
            'kp_worker_delivery', 'kp_worker_retention', 'kp_worker_mailbox',
            'kp_worker_reply_mailbox', 'kp_worker_reminder', 'kp_worker_alert',
            'kp_worker_directory', 'kp_worker_curation'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target) THEN
                EXECUTE format('GRANT EXECUTE ON FUNCTION '
                    'public.kp_reconcile_queue_outbox(text,integer,integer,timestamptz,uuid) TO %I', target);
            END IF;
        END LOOP;
    END $$""")
    op.execute("RESET ROLE")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_worker_mailbox') THEN
            GRANT UPDATE (recipient_assignment_id) ON public.recipient_assignments TO kp_worker_mailbox;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
            GRANT SELECT (tenant_scope, recipient_pseudonym, pseudonym_key_version)
                ON public.awareness_ledger_entries TO kp_operator;
            GRANT SELECT (recipient_assignment_id) ON public.reported_mail_receipts,
                public.reply_mail_receipts TO kp_operator;
            GRANT DELETE ON public.reported_mail_receipts, public.reply_mail_receipts TO kp_operator;
            GRANT UPDATE (pending_preview_id, pending_preview_hash, pending_payload, pending_created_at,
                pending_expires_at, status, last_error, updated_at)
                ON public.microsoft365_integration_states TO kp_operator;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("SET LOCAL ROLE audit_owner")
    op.execute("DROP FUNCTION public.kp_reconcile_queue_outbox(text,integer,integer,timestamptz,uuid)")
    op.execute("RESET ROLE")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_worker_mailbox') THEN
            REVOKE UPDATE (recipient_assignment_id) ON public.recipient_assignments FROM kp_worker_mailbox;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kp_operator') THEN
            REVOKE SELECT (tenant_scope, recipient_pseudonym, pseudonym_key_version)
                ON public.awareness_ledger_entries FROM kp_operator;
            REVOKE SELECT (recipient_assignment_id) ON public.reported_mail_receipts,
                public.reply_mail_receipts FROM kp_operator;
            REVOKE DELETE ON public.reported_mail_receipts, public.reply_mail_receipts FROM kp_operator;
            REVOKE UPDATE (pending_preview_id, pending_preview_hash, pending_payload, pending_created_at,
                pending_expires_at, status, last_error, updated_at)
                ON public.microsoft365_integration_states FROM kp_operator;
        END IF;
    END $$""")
