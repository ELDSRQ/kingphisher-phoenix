"""Constrained automatic adaptive drafts, without campaign INSERT authority.

Revision ID: 0056_adaptive_draft_boundary
Revises: 0055_privacy_subject_export

The function remains owned by the migration principal, never a runtime login.
It creates all four linked records atomically; no caller-supplied campaign,
author, content, authorization, launch state or schedule fields are accepted.
Retention's pre-existing lifecycle campaign UPDATE is unchanged by this repair.
"""

from alembic import op

revision = "0056_adaptive_draft_boundary"
down_revision = "0055_privacy_subject_export"
branch_labels = None
depends_on = None

SIGNATURE = "public.kp_create_adaptive_program_draft(uuid,integer,uuid,uuid,uuid,jsonb)"


def upgrade() -> None:
    op.execute("""CREATE FUNCTION public.kp_create_adaptive_program_draft(
        p_program uuid, p_iteration integer, p_campaign uuid, p_occurrence uuid,
        p_adaptation uuid, p_metadata jsonb) RETURNS uuid
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        DECLARE
            program public.campaign_programs%ROWTYPE;
            source public.campaigns%ROWTYPE;
            prior public.campaign_program_occurrences%ROWTYPE;
            start_at timestamptz;
            end_at timestamptz;
            source_ids jsonb;
            exclusions jsonb;
            suffix text;
            author uuid;
            item jsonb;
        BEGIN
            IF session_user <> 'kp_worker_retention' THEN
                RAISE EXCEPTION 'adaptive draft creation is not authorized' USING ERRCODE='42501';
            END IF;
            IF p_program IS NULL OR p_campaign IS NULL OR p_occurrence IS NULL OR p_adaptation IS NULL
                OR p_iteration IS NULL OR p_iteration NOT BETWEEN 2 AND 12
                OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
                OR octet_length(p_metadata::text) > 1048576
                OR NOT p_metadata ?& ARRAY['difficulty','signals','changes','enrollment',
                    'excluded_ids','configuration_hash','manifest_hash']
                OR p_metadata - ARRAY['difficulty','signals','changes','enrollment',
                    'excluded_ids','configuration_hash','manifest_hash'] <> '{}'::jsonb
                OR jsonb_typeof(p_metadata->'difficulty') <> 'object'
                OR jsonb_typeof(p_metadata->'signals') <> 'object'
                OR jsonb_typeof(p_metadata->'changes') <> 'object'
                OR jsonb_typeof(p_metadata->'enrollment') <> 'object'
                OR jsonb_typeof(p_metadata->'excluded_ids') <> 'array'
                OR jsonb_typeof(p_metadata->'configuration_hash') IS DISTINCT FROM 'string'
                OR jsonb_typeof(p_metadata->'manifest_hash') IS DISTINCT FROM 'string'
                OR (p_metadata->>'configuration_hash') !~ '^[0-9a-f]{64}$'
                OR (p_metadata->>'manifest_hash') !~ '^[0-9a-f]{64}$'
                OR (p_metadata->'changes'->>'content_changed') IS DISTINCT FROM 'false'
                OR (p_metadata->'changes'->>'scope') IS DISTINCT FROM 'enrollment_and_difficulty_metadata'
                OR (p_metadata->'difficulty'->>'adaptive_level') IS NULL
                OR (p_metadata->'difficulty'->>'adaptive_level') !~ '^[1-5]$' THEN
                RAISE EXCEPTION 'adaptive draft metadata bounds are invalid' USING ERRCODE='22023';
            END IF;
            FOR item IN SELECT value FROM jsonb_each(p_metadata->'signals') LOOP
                IF jsonb_typeof(item) <> 'number' OR item::text !~ '^[0-9]{1,9}$' THEN
                    RAISE EXCEPTION 'adaptive signals must be bounded counts' USING ERRCODE='22023';
                END IF;
            END LOOP;
            SELECT * INTO STRICT program FROM public.campaign_programs
                WHERE campaign_program_id=p_program FOR UPDATE;
            IF program.generation_mode <> 'adaptive' OR program.state <> 'ACTIVE'
                OR p_iteration > program.occurrence_count THEN
                RAISE EXCEPTION 'adaptive program is not eligible' USING ERRCODE='22023';
            END IF;
            -- Replay returns the existing binding, but never accepts a stale
            -- iteration number as permission to create a different campaign.
            SELECT * INTO prior FROM public.campaign_program_occurrences
                WHERE campaign_program_id=p_program AND occurrence_number=p_iteration;
            IF FOUND THEN
                RETURN prior.campaign_id;
            END IF;
            SELECT * INTO STRICT prior FROM public.campaign_program_occurrences
                WHERE campaign_program_id=p_program ORDER BY occurrence_number DESC LIMIT 1;
            IF prior.occurrence_number <> p_iteration-1
                OR NOT EXISTS (SELECT 1 FROM public.campaigns
                    WHERE campaign_id=prior.campaign_id AND state='COMPLETED') THEN
                RAISE EXCEPTION 'adaptive prior iteration is not complete' USING ERRCODE='22023';
            END IF;
            SELECT * INTO STRICT source FROM public.campaigns
                WHERE campaign_id=program.source_campaign_id FOR SHARE;
            IF (p_metadata->'difficulty') - ARRAY['adaptive_level','program_adaptation']
                IS DISTINCT FROM
                    coalesce(source.difficulty,'{}'::jsonb) - ARRAY['adaptive_level','program_adaptation'] THEN
                RAISE EXCEPTION 'adaptive draft cannot change source content metadata' USING ERRCODE='22023';
            END IF;
            author := coalesce(program.created_by, source.created_by);
            start_at := source.schedule_start + make_interval(days => program.cadence_days*(p_iteration-1));
            end_at := source.schedule_end + make_interval(days => program.cadence_days*(p_iteration-1));
            IF author IS NULL OR source.roe_id IS NULL OR start_at IS NULL OR start_at <= clock_timestamp()
                OR end_at IS NULL OR end_at <= start_at
                OR NOT EXISTS (SELECT 1 FROM public.campaign_audiences a
                    WHERE a.campaign_id=source.campaign_id AND a.frozen_at IS NOT NULL
                        AND a.manifest_hash IS NOT NULL AND NOT a.legacy_requires_configuration)
                OR NOT EXISTS (SELECT 1 FROM public.campaign_patterns p
                    WHERE p.campaign_pattern_id=source.pattern_id AND p.approval_state='APPROVED')
                OR NOT EXISTS (SELECT 1 FROM public.template_versions t
                    WHERE t.template_version_id=source.current_template_id AND t.approval_state='APPROVED')
                OR NOT EXISTS (SELECT 1 FROM public.training_resources t
                    WHERE t.training_resource_id=source.training_resource_id AND t.approval_state='APPROVED'
                        AND t.requires_completion AND t.version=source.training_resource_version)
                OR source.training_resource_digest IS NULL THEN
                RAISE EXCEPTION 'adaptive source requires current review' USING ERRCODE='22023';
            END IF;
            SELECT jsonb_agg(recipient_id::text ORDER BY recipient_id::text) INTO source_ids
                FROM public.campaign_audience_manifest WHERE campaign_id=source.campaign_id;
            IF source_ids IS NULL OR jsonb_array_length(source_ids) > 100000
                OR jsonb_array_length(p_metadata->'excluded_ids') > jsonb_array_length(source_ids)
                OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_metadata->'excluded_ids') e
                    WHERE jsonb_typeof(e) <> 'string' OR NOT source_ids @> jsonb_build_array(e)) THEN
                RAISE EXCEPTION 'adaptive enrollment exceeds reviewed source' USING ERRCODE='22023';
            END IF;
            SELECT coalesce(jsonb_agg(value ORDER BY value::text),'[]'::jsonb) INTO exclusions
                FROM (SELECT DISTINCT value FROM jsonb_array_elements(p_metadata->'excluded_ids')) e;
            suffix := ' · Run ' || p_iteration || ' of ' || program.occurrence_count;
            INSERT INTO public.campaigns(campaign_id,delivery_mode,pattern_id,current_template_id,title,
                state,sender_mailbox,sender_display_name,roe_id,training_domain,schedule_start,schedule_end,
                timezone,max_recipients,retention_policy_id,training_resource_id,training_resource_version,
                training_resource_digest,difficulty,manifest_hash,manifest_signed_at,recall_of,created_by,expires_at)
            VALUES(p_campaign,'reviewed_direct',source.pattern_id,source.current_template_id,
                rtrim(left(source.title,255-length(suffix))) || suffix,'DRAFT',source.sender_mailbox,
                source.sender_display_name,NULL,source.training_domain,start_at,end_at,source.timezone,
                source.max_recipients,source.retention_policy_id,source.training_resource_id,
                source.training_resource_version,source.training_resource_digest,p_metadata->'difficulty',
                p_metadata->>'manifest_hash',NULL,NULL,author,end_at);
            INSERT INTO public.campaign_audiences(campaign_id,version,group_ids,departments,statuses,
                include_recipient_ids,exclude_recipient_ids,configuration_hash,preview_hash,manifest_hash,
                frozen_at,legacy_requires_configuration)
            VALUES(p_campaign,1,'[]','[]','[]',source_ids,exclusions,
                p_metadata->>'configuration_hash',NULL,NULL,NULL,false);
            INSERT INTO public.campaign_program_occurrences(campaign_program_occurrence_id,campaign_program_id,
                occurrence_number,campaign_id,schedule_start,schedule_end)
            VALUES(p_occurrence,p_program,p_iteration,p_campaign,start_at,end_at);
            INSERT INTO public.campaign_program_adaptations(campaign_program_adaptation_id,campaign_program_id,
                iteration_number,iteration_campaign_id,basis_campaign_id,signals,changes,enrollment)
            VALUES(p_adaptation,p_program,p_iteration,p_campaign,prior.campaign_id,
                p_metadata->'signals',p_metadata->'changes',p_metadata->'enrollment');
            UPDATE public.campaign_programs SET updated_at=clock_timestamp() WHERE campaign_program_id=p_program;
            RETURN p_campaign;
        END $$""")
    op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kp_worker_retention') THEN
            GRANT EXECUTE ON FUNCTION public.kp_create_adaptive_program_draft(uuid,integer,uuid,uuid,uuid,jsonb)
                TO kp_worker_retention;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {SIGNATURE}")
