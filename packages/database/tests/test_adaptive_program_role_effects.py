"""Actual managed retention/operator login effects for adaptive DRAFT creation.

Uses a uniquely named, preserved synthetic database. Runtime role provisioning
must run serially with other managed-role qualification modules.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import Response
from kp_database import grants
from kp_database.audit_store import AuditStore
from kp_database.models import Campaign, CampaignAudience, CampaignProgram, CampaignProgramOccurrence, CipherText
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.program_routes import ProgramIterationCreate, create_program_iteration, get_program_adaptations
from kp_workers.program_jobs import maybe_materialize_due_program_iterations
from psycopg import sql
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from test_adaptive_program_iterations import _adaptive_source, _recipient
from test_queue_reconcile_postgres import managed_database as _managed_database

pytestmark = pytest.mark.postgres
SIGNATURE = "public." + grants.PROGRAM_DRAFT_FUNCTION


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    url, admin, _, audit_password = managed_database
    previous = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(b"p" * 32)
    factory = make_session_factory(admin)
    with factory() as session:
        program_id = _adaptive_source(session, [_recipient(f"synthetic-{uuid4().hex}@example.test")])
        program = session.get(CampaignProgram, program_id)
        source = session.get(Campaign, program.source_campaign_id)
        source.state = dm.CampaignState.COMPLETED
        author, source_id = program.created_by, source.campaign_id
        session.commit()
    retention = create_engine(url.set(username="kp_worker_retention", password="effect-retention"))
    operator = create_engine(url.set(username="kp_operator", password="effect-operator"))
    audit = create_engine(url.set(username="audit_writer", password=audit_password))
    yield program_id, author, source_id, factory, retention, operator, audit
    for engine in (retention, operator, audit):
        engine.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous


def test_actual_retention_tick_creates_only_attributed_unreviewed_draft_and_durable_audit(subject):
    program_id, author, source_id, factory, retention, _, audit = subject
    store = AuditStore(audit, intent_engine=retention)
    with retention.connect() as connection:
        assert connection.scalar(text("SELECT session_user")) == "kp_worker_retention"
        assert not connection.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
    ctx = SimpleNamespace(session_factory=make_session_factory(retention), audit_store=store)
    outcome = maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))
    assert outcome["created"] >= 1 and outcome["errored"] == 0
    with factory() as session:
        occurrence = session.scalars(
            select(CampaignProgramOccurrence).where(
                CampaignProgramOccurrence.campaign_program_id == program_id,
                CampaignProgramOccurrence.occurrence_number == 2,
            )
        ).one()
        campaign = session.get(Campaign, occurrence.campaign_id)
        source = session.get(Campaign, source_id)
        audience = session.get(CampaignAudience, campaign.campaign_id)
        assert campaign.created_by == author
        assert campaign.pattern_id == source.pattern_id and campaign.current_template_id == source.current_template_id
        assert campaign.training_resource_digest == source.training_resource_digest
        assert campaign.state == dm.CampaignState.DRAFT and campaign.delivery_mode == "reviewed_direct"
        assert campaign.roe_id is None and campaign.manifest_signed_at is None
        assert audience.frozen_at is None and audience.manifest_hash is None and audience.preview_hash is None
        assert (
            session.scalar(
                text("SELECT count(*) FROM campaign_approvals WHERE campaign_id=:id"), {"id": campaign.campaign_id}
            )
            == 0
        )
        assert (
            session.scalar(
                text("SELECT count(*) FROM campaign_launch_gates WHERE campaign_id=:id"), {"id": campaign.campaign_id}
            )
            == 0
        )
        assert (
            session.scalar(
                text(
                    "SELECT count(*) FROM audit_events WHERE object_id=:id "
                    "AND action='campaign_program.iteration.materialize'"
                ),
                {"id": str(program_id)},
            )
            == 1
        )
    assert maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))["created"] == 0
    with retention.begin() as connection:
        replay = connection.scalar(
            text("SELECT public.kp_create_adaptive_program_draft(:program,2,:id,:id,:id,CAST(:metadata AS jsonb))"),
            {"program": program_id, "id": uuid4(), "metadata": json.dumps(_metadata())},
        )
        assert replay == occurrence.campaign_id


def test_actual_operator_route_creates_and_reads_aggregate_adaptation(subject):
    program_id, author, _, _, _, operator, audit = subject
    requester = uuid4()
    with make_session_factory(operator)() as session:
        response = Response()
        payload = create_program_iteration(
            program_id,
            ProgramIterationCreate(expected_iteration=2),
            response,
            session=session,
            audit=AuditStore(audit, intent_engine=operator),
            principal=SimpleNamespace(principal_id=str(requester)),
        )
        assert response.status_code == 201 and payload["created"]
        campaign = session.get(Campaign, payload["iteration_campaign_id"])
        assert campaign.created_by == author and campaign.created_by != requester
        adaptations = get_program_adaptations(
            program_id,
            Response(),
            limit=100,
            offset=0,
            session=session,
            principal=SimpleNamespace(principal_id=str(requester)),
        )
        assert len(adaptations) == 1 and adaptations[0]["content_changed"] is False
        assert "excluded_opt_out_ids" not in str(adaptations)


def _metadata(**overrides):
    return {
        "difficulty": {"adaptive_level": 3},
        "signals": {"accepted": 0},
        "changes": {"content_changed": False, "scope": "enrollment_and_difficulty_metadata"},
        "enrollment": {},
        "excluded_ids": [],
        "configuration_hash": "a" * 64,
        "manifest_hash": "b" * 64,
        **overrides,
    }


@pytest.mark.parametrize(
    "override",
    [
        {"state": "approved"},
        {"difficulty": {"adaptive_level": 6}},
        {"excluded_ids": [str(uuid4())]},
        {"manifest_hash": None},
        {"changes": {"content_changed": True, "scope": "enrollment_and_difficulty_metadata"}},
    ],
)
def test_definer_rejects_unbounded_or_expanding_payload_without_creating_campaign(subject, override):
    program_id, _, _, factory, retention, _, _ = subject
    new_id = uuid4()
    with retention.connect() as connection:
        with pytest.raises(DBAPIError) as denied:
            connection.execute(
                text(
                    "SELECT public.kp_create_adaptive_program_draft("
                    ":program,2,:campaign,:occurrence,:adaptation,CAST(:metadata AS jsonb))"
                ),
                {
                    "program": program_id,
                    "campaign": new_id,
                    "occurrence": uuid4(),
                    "adaptation": uuid4(),
                    "metadata": json.dumps(_metadata(**override)),
                },
            )
        assert denied.value.orig.sqlstate == "22023"
    with factory() as session:
        assert session.get(Campaign, new_id) is None


def test_retention_has_no_new_direct_insert_or_approval_gate_send_authority(subject, managed_database):
    _, _, _, _, retention, _, _ = subject
    with retention.connect() as connection:
        for table in (
            "campaigns",
            "campaign_audiences",
            "campaign_program_occurrences",
            "campaign_program_adaptations",
            "campaign_approvals",
            "campaign_launch_gates",
            "transactional_outbox",
        ):
            assert not connection.scalar(text("SELECT has_table_privilege(:table,'INSERT')"), {"table": table})
        # Existing retention lifecycle UPDATE on campaigns is deliberately
        # reported, never misrepresented as an overall inability to set state.
        assert connection.scalar(text("SELECT has_table_privilege('campaigns','UPDATE')"))
    url, admin, _, _ = managed_database
    for workload in ("operator", "delivery", "tracking"):
        engine = create_engine(url.set(username=grants.RUNTIME_ROLES[workload], password=f"effect-{workload}"))
        with engine.connect() as connection:
            with pytest.raises(DBAPIError) as denied:
                connection.execute(
                    text("SELECT public.kp_create_adaptive_program_draft(:id,2,:id,:id,:id,'{}')"), {"id": uuid4()}
                )
            assert denied.value.orig.sqlstate == "42501"
        engine.dispose()
    with admin.connect() as connection:
        info = (
            connection.execute(
                text(
                    "SELECT prosecdef,proconfig,pg_get_userbyid(proowner) AS owner "
                    "FROM pg_proc WHERE oid=CAST(:signature AS regprocedure)"
                ),
                {"signature": SIGNATURE},
            )
            .mappings()
            .one()
        )
        assert info["prosecdef"] and info["proconfig"] == ["search_path=pg_catalog"]
        assert info["owner"] not in grants.RUNTIME_ROLES.values()
        assert not connection.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM pg_proc p,aclexplode(p.proacl) a "
                "WHERE p.oid=CAST(:signature AS regprocedure) AND a.grantee=0 AND a.privilege_type='EXECUTE')"
            ),
            {"signature": SIGNATURE},
        )


def test_draft_boundary_migration_runs_as_noinherit_nonsuperuser_owner(managed_database, subject):
    url, admin, _, _ = managed_database
    role = "kp_adaptive_migrator_" + uuid4().hex
    with admin.begin() as connection:
        connection.connection.driver_connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOINHERIT NOSUPERUSER NOCREATEROLE NOCREATEDB").format(
                sql.Identifier(role), sql.Literal("synthetic-migration-only")
            )
        )
        connection.connection.driver_connection.execute(
            sql.SQL("GRANT USAGE,CREATE ON SCHEMA public TO {}").format(sql.Identifier(role))
        )
        connection.connection.driver_connection.execute(
            sql.SQL(
                "GRANT SELECT,INSERT,UPDATE ON campaigns,campaign_programs,campaign_program_occurrences,"
                "campaign_program_adaptations,campaign_audiences,campaign_audience_manifest,"
                "campaign_patterns,template_versions,training_resources TO {}"
            ).format(sql.Identifier(role))
        )
        connection.execute(text(f"DROP FUNCTION {SIGNATURE}"))
    engine = create_engine(url.set(username=role, password="synthetic-migration-only"))
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0056_adaptive_draft_boundary.py"
    spec = importlib.util.spec_from_file_location("adaptive_draft_migration_effect", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with engine.begin() as connection:
        assert not connection.scalar(text("SELECT rolsuper OR rolinherit FROM pg_roles WHERE rolname=session_user"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert (
            connection.scalar(
                text("SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE oid=CAST(:signature AS regprocedure)"),
                {"signature": SIGNATURE},
            )
            == role
        )
    with engine.connect() as connection:
        # Even the owning login cannot exercise the runtime function by virtue
        # of ownership: authorization binds the actual retention session_user.
        with pytest.raises(DBAPIError) as denied:
            connection.execute(
                text("SELECT public.kp_create_adaptive_program_draft(:id,2,:id,:id,:id,'{}')"),
                {"id": uuid4()},
            )
        assert denied.value.orig.sqlstate == "42501"
    engine.dispose()
    _, _, _, _, retention, _, audit = subject
    outcome = maybe_materialize_due_program_iterations(
        SimpleNamespace(
            session_factory=make_session_factory(retention), audit_store=AuditStore(audit, intent_engine=retention)
        ),
        datetime.now(UTC),
    )
    assert outcome["created"] >= 1 and outcome["errored"] == 0
