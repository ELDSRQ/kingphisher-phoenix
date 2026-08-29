"""Database-enforced append-only audit and transactional outbox.

Revision ID: 0020_transactional_audit_outbox
Revises: 0019_training_remediation_loop
Create Date: 2026-08-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0020_transactional_audit_outbox"
down_revision = "0019_training_remediation_loop"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.add_column("audit_events", sa.Column("outbox_id", sa.UUID(), nullable=True))
    op.add_column("audit_events", sa.Column("origin_role", sa.String(length=128), nullable=True))
    op.add_column("audit_events", sa.Column("canonical_payload", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("chain_version", sa.Integer(), server_default="1", nullable=False))
    op.create_unique_constraint("uq_audit_events_outbox_id", "audit_events", ["outbox_id"])

    op.create_table(
        "transactional_outbox",
        sa.Column("outbox_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("topic", sa.String(length=64), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        # session_user cannot be forged through an omitted ORM field. Azure
        # grants INSERT only on the caller-controlled columns below.
        sa.Column("origin_role", sa.String(length=128), server_default=sa.text("session_user"), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('audit', 'queue')", name="ck_transactional_outbox_kind"),
        sa.CheckConstraint(
            "status IN ('pending', 'dispatching', 'dispatched', 'failed')",
            name="ck_transactional_outbox_status",
        ),
        sa.PrimaryKeyConstraint("outbox_id", name="pk_transactional_outbox"),
        sa.UniqueConstraint("idempotency_key", name="uq_transactional_outbox_idempotency_key"),
    )
    op.create_index(
        "ix_transactional_outbox_dispatch",
        "transactional_outbox",
        ["kind", "status", "available_at"],
        unique=False,
    )

    # The signing root is database-resident but readable only by the NOLOGIN
    # audit owner/migration authority. It is populated by azure_migrate.py.
    op.execute(
        """
        CREATE TABLE audit_integrity_secret (
            singleton_id integer PRIMARY KEY CHECK (singleton_id = 1),
            key_hex varchar(64) NOT NULL CHECK (key_hex ~ '^[0-9a-f]{64}$'),
            installed_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )

    op.execute(
        r"""
        CREATE OR REPLACE FUNCTION kp_dispatch_audit_outbox(p_outbox_id uuid)
        RETURNS uuid
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            intent transactional_outbox%ROWTYPE;
            previous_hash text;
            nonce_value text;
            canonical_value text;
            event_hash_value text;
            signature_value text;
            event_id uuid;
            root_key text;
            occurred timestamptz;
        BEGIN
            PERFORM pg_advisory_xact_lock(1263551049);
            SELECT * INTO intent
              FROM public.transactional_outbox
             WHERE outbox_id = p_outbox_id
             FOR UPDATE;
            IF NOT FOUND OR intent.kind <> 'audit' THEN
                RAISE EXCEPTION 'unknown audit outbox intent';
            END IF;
            IF intent.status = 'dispatched' THEN
                SELECT audit_event_id INTO event_id FROM public.audit_events WHERE outbox_id = p_outbox_id;
                RETURN event_id;
            END IF;
            IF intent.origin_role IN ('audit_writer', 'audit_owner')
               OR coalesce(intent.payload->>'actor', '') = ''
               OR coalesce(intent.payload->>'action', '') = '' THEN
                RAISE EXCEPTION 'invalid or self-authored audit intent';
            END IF;

            SELECT key_hex INTO root_key FROM public.audit_integrity_secret WHERE singleton_id = 1;
            IF root_key IS NULL THEN
                RAISE EXCEPTION 'audit integrity root is not configured';
            END IF;
            SELECT event_hash INTO previous_hash FROM public.audit_chain_head WHERE id = 1 FOR UPDATE;
            previous_hash := coalesce(previous_hash, repeat('0', 64));
            occurred := coalesce((intent.payload->>'occurred_at')::timestamptz, intent.created_at);
            nonce_value := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
            canonical_value := jsonb_build_object(
                'action', intent.payload->>'action',
                'actor', intent.payload->>'actor',
                'detail', coalesce(intent.payload->'detail', '{}'::jsonb),
                'object_id', intent.payload->>'object_id',
                'object_type', intent.payload->>'object_type',
                'occurred_at', to_char(occurred AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'),
                'origin_role', intent.origin_role,
                'version', 2
            )::text;
            event_hash_value := encode(
                digest(convert_to(previous_hash || canonical_value || nonce_value, 'UTF8'), 'sha256'),
                'hex'
            );
            signature_value := encode(
                hmac(convert_to(event_hash_value, 'UTF8'), decode(root_key, 'hex'), 'sha256'),
                'hex'
            );
            event_id := gen_random_uuid();

            INSERT INTO public.audit_events (
                audit_event_id, actor, action, object_type, object_id, outcome,
                occurred_at, detail, prev_hash, event_hash, nonce, outbox_id,
                origin_role, canonical_payload, chain_version
            ) VALUES (
                event_id, intent.payload->>'actor', intent.payload->>'action',
                intent.payload->>'object_type', intent.payload->>'object_id', 'success',
                occurred, coalesce(intent.payload->'detail', '{}'::jsonb), previous_hash,
                event_hash_value, nonce_value, intent.outbox_id, intent.origin_role,
                canonical_value, 2
            ) ON CONFLICT (outbox_id) DO NOTHING;

            INSERT INTO public.audit_chain_head (id, event_hash, signature, signed_at)
            VALUES (1, event_hash_value, signature_value, now())
            ON CONFLICT (id) DO UPDATE SET event_hash = excluded.event_hash,
                signature = excluded.signature, signed_at = excluded.signed_at;
            UPDATE public.transactional_outbox
               SET status = 'dispatched', dispatched_at = now(), lease_until = NULL,
                   last_error = NULL, attempts = attempts + 1
             WHERE outbox_id = p_outbox_id;
            RETURN event_id;
        END
        $function$;

        CREATE OR REPLACE FUNCTION kp_dispatch_pending_audit(p_limit integer DEFAULT 100)
        RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE item record; dispatched integer := 0;
        BEGIN
            FOR item IN
                SELECT outbox_id FROM public.transactional_outbox
                 WHERE kind = 'audit' AND status IN ('pending', 'failed') AND available_at <= now()
                 ORDER BY created_at, outbox_id FOR UPDATE SKIP LOCKED LIMIT greatest(1, least(p_limit, 1000))
            LOOP
                PERFORM public.kp_dispatch_audit_outbox(item.outbox_id);
                dispatched := dispatched + 1;
            END LOOP;
            RETURN dispatched;
        END
        $function$;

        CREATE OR REPLACE FUNCTION kp_claim_queue_outbox(p_limit integer DEFAULT 1)
        RETURNS TABLE(outbox_id uuid, topic text, payload jsonb, idempotency_key text, available_at timestamptz)
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $function$
            WITH claim AS (
                SELECT o.outbox_id FROM public.transactional_outbox o
                 WHERE o.kind = 'queue' AND o.available_at <= now()
                   AND (o.status IN ('pending', 'failed') OR (o.status = 'dispatching' AND o.lease_until < now()))
                 ORDER BY o.created_at, o.outbox_id FOR UPDATE SKIP LOCKED LIMIT greatest(1, least(p_limit, 100))
            ), updated AS (
                UPDATE public.transactional_outbox o SET status = 'dispatching',
                    lease_until = now() + interval '60 seconds', attempts = attempts + 1, last_error = NULL
                  FROM claim WHERE o.outbox_id = claim.outbox_id
                  RETURNING o.outbox_id, o.topic::text, o.payload, o.idempotency_key::text, o.available_at
            ) SELECT * FROM updated
        $function$;

        CREATE OR REPLACE FUNCTION kp_complete_outbox(p_outbox_id uuid)
        RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
        AS $function$
            UPDATE public.transactional_outbox SET status = 'dispatched', dispatched_at = now(), lease_until = NULL
             WHERE outbox_id = p_outbox_id AND kind = 'queue' AND status = 'dispatching'
        $function$;

        CREATE OR REPLACE FUNCTION kp_fail_outbox(p_outbox_id uuid, p_error text)
        RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
        AS $function$
            UPDATE public.transactional_outbox SET status = 'failed', lease_until = NULL,
                available_at = now() + interval '30 seconds',
                last_error = left(coalesce(p_error, 'unknown dispatch error'), 1000)
             WHERE outbox_id = p_outbox_id AND kind = 'queue' AND status = 'dispatching'
        $function$;

        CREATE OR REPLACE FUNCTION kp_outbox_health()
        RETURNS TABLE(
            pending bigint,
            overdue_pending bigint,
            scheduled_or_fresh bigint,
            failed bigint,
            dispatching_stale bigint
        )
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
        AS $function$
            SELECT count(*) FILTER (WHERE status = 'pending'),
                   count(*) FILTER (
                       WHERE status = 'pending' AND available_at <= now() - interval '1 minute'
                   ),
                   count(*) FILTER (
                       WHERE status = 'pending' AND available_at > now() - interval '1 minute'
                   ),
                   count(*) FILTER (WHERE status = 'failed'),
                   count(*) FILTER (WHERE status = 'dispatching' AND lease_until < now())
              FROM public.transactional_outbox
             WHERE status <> 'dispatched'
        $function$;

        CREATE OR REPLACE FUNCTION kp_verify_audit_head()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $function$
            SELECT CASE
                WHEN s.key_hex IS NULL THEN false
                WHEN h.event_hash IS NULL AND NOT EXISTS (SELECT 1 FROM public.audit_events) THEN true
                WHEN h.event_hash IS NULL OR h.signature IS NULL THEN false
                ELSE h.signature = encode(
                    hmac(convert_to(h.event_hash, 'UTF8'), decode(s.key_hex, 'hex'), 'sha256'),
                    'hex'
                )
            END
              FROM (VALUES (1)) singleton(id)
              LEFT JOIN public.audit_chain_head h ON h.id = singleton.id
              LEFT JOIN public.audit_integrity_secret s ON s.singleton_id = singleton.id
        $function$;
        """
    )
    op.execute(
        "REVOKE ALL ON TABLE audit_events, audit_chain_head, audit_integrity_secret, transactional_outbox FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION kp_dispatch_audit_outbox(uuid), kp_dispatch_pending_audit(integer), "
        "kp_claim_queue_outbox(integer), kp_complete_outbox(uuid), kp_fail_outbox(uuid,text), "
        "kp_outbox_health(), kp_verify_audit_head() FROM PUBLIC"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS kp_verify_audit_head()")
    op.execute("DROP FUNCTION IF EXISTS kp_outbox_health()")
    op.execute("DROP FUNCTION IF EXISTS kp_fail_outbox(uuid,text)")
    op.execute("DROP FUNCTION IF EXISTS kp_complete_outbox(uuid)")
    op.execute("DROP FUNCTION IF EXISTS kp_claim_queue_outbox(integer)")
    op.execute("DROP FUNCTION IF EXISTS kp_dispatch_pending_audit(integer)")
    op.execute("DROP FUNCTION IF EXISTS kp_dispatch_audit_outbox(uuid)")
    op.drop_index("ix_transactional_outbox_dispatch", table_name="transactional_outbox")
    op.drop_table("audit_integrity_secret")
    op.drop_table("transactional_outbox")
    op.drop_constraint("uq_audit_events_outbox_id", "audit_events", type_="unique")
    op.drop_column("audit_events", "chain_version")
    op.drop_column("audit_events", "canonical_payload")
    op.drop_column("audit_events", "origin_role")
    op.drop_column("audit_events", "outbox_id")
