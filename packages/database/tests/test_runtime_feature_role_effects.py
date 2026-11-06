"""Actual managed role effects for operator features, retention and delivery.

Uses one fresh preserved synthetic database and real NOINHERIT role logins.
No provider calls, configuration-file writes or real credential rotations occur.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_authorization import Principal, Role
from kp_database.audit_store import AuditStore
from kp_database.models import (
    AiGenerationProvider,
    Campaign,
    CampaignAudienceManifest,
    CampaignProgram,
    CipherText,
    ProviderConfigGeneration,
    RecipientAssignment,
    ReplyMailReceipt,
    TemplateVersion,
)
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.console import (
    _begin_credential_rotation,
    _bump_session_epoch_row,
    _mark_credential_rotation_applied,
)
from kp_operator_api.console.ai_providers import _bump_generation, _mark_generation_applied, _rows_by_provider
from kp_operator_api.routes.campaigns import (
    CueCoverageCreate,
    CueCoverageDecision,
    CueCoverageExceptionRequest,
    create_campaign_cue_coverage,
    decide_campaign_cue_coverage,
    list_campaign_cue_coverage,
    record_cue_coverage_exception,
)
from kp_workers.retention_jobs import _purge_aged_receipts
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from test_adaptive_program_iterations import _adaptive_source, _recipient
from test_queue_reconcile_postgres import managed_database as _managed_database

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    url, admin, _, audit_password = managed_database
    previous = CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys
    CipherText.configure_key(b"q" * 32)
    factory = make_session_factory(admin)
    with factory() as session:
        recipient = _recipient(f"feature-{uuid4().hex}@example.test")
        program_id = _adaptive_source(session, [recipient])
        campaign = session.get(Campaign, session.get(CampaignProgram, program_id).source_campaign_id)
        campaign.state = dm.CampaignState.DRAFT
        template = session.get(TemplateVersion, campaign.current_template_id)
        template.cue_manifest = {"cues": [{"cue_type": "urgency"}]}
        bystander = _recipient(f"excluded-{uuid4().hex}@example.test")
        session.add(bystander)
        session.flush()
        assignments = []
        for row in (recipient, bystander):
            assignment = RecipientAssignment(
                recipient_assignment_id=uuid4(),
                campaign_id=campaign.campaign_id,
                recipient_id=row.recipient_id,
                send_state=dm.SendState.QUEUED,
                idempotency_key=f"feature:{uuid4()}",
            )
            session.add(assignment)
            assignments.append(assignment.recipient_assignment_id)
        session.commit()
        campaign_id = campaign.campaign_id
    engines = {
        role: create_engine(
            url.set(username=f"kp_worker_{role}" if role != "operator" else "kp_operator", password=f"effect-{role}")
        )
        for role in ("operator", "delivery", "retention", "tracking", "generation")
        if role != "tracking"
    }
    engines["tracking"] = create_engine(url.set(username="kp_tracking", password="effect-tracking"))
    audit_engine = create_engine(url.set(username="audit_writer", password=audit_password))
    store = AuditStore(audit_engine, intent_engine=engines["operator"])
    yield campaign_id, assignments, factory, engines, store
    for engine in [*engines.values(), audit_engine]:
        engine.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous


def _deny(engine, statement, parameters=None):
    with engine.connect() as connection:
        with pytest.raises(DBAPIError) as denied:
            connection.execute(text(statement), parameters or {})
        assert denied.value.orig.sqlstate == "42501"


def test_operator_provider_generation_epoch_and_rotation_helpers_use_only_metadata(subject):
    _, _, _, engines, _ = subject
    provider = f"qualification-{uuid4().hex[:12]}"
    with make_session_factory(engines["operator"])() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_operator"
        assert not session.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
        session.add(
            AiGenerationProvider(
                provider=provider, api_key="synthetic-qualification-key", model_id="synthetic-model", is_active=False
            )
        )
        session.flush()
        assert _rows_by_provider(session)[provider].api_key == "synthetic-qualification-key"
        generation = _bump_generation(session, "local")
        _mark_generation_applied(session, generation)
        assert _bump_session_epoch_row(session) > 0
        credential = f"qualification-{uuid4().hex[:12]}"
        rotation = _begin_credential_rotation(session, credential)
        _mark_credential_rotation_applied(session, credential, rotation)
        session.commit()
        assert session.get(ProviderConfigGeneration, 1).applied_generation == generation
    for table in (
        "ai_generation_providers",
        "provider_config_generation",
        "console_session_epoch",
        "credential_rotations",
    ):
        _deny(engines["operator"], f"DELETE FROM public.{table} WHERE false")  # noqa: S608 - fixed table tuple


def test_operator_can_create_review_read_and_document_cue_coverage_with_real_audit(subject):
    campaign_id, _, _, engines, store = subject
    author = Principal(str(uuid4()), {Role.ADMINISTRATOR})
    reviewer = Principal(str(uuid4()), {Role.ADMINISTRATOR})
    factory = make_session_factory(engines["operator"])
    with factory() as session:
        created = create_campaign_cue_coverage(
            campaign_id,
            CueCoverageCreate(
                cue_id="urgency",
                lesson_section="Verify independently",
                quiz_item="Pause before acting",
            ),
            session=session,
            audit=store,
            principal=author,
        )
        coverage_id = UUID(created["coverage_id"])
    with factory() as session:
        decide_campaign_cue_coverage(
            campaign_id,
            coverage_id,
            CueCoverageDecision(decision="reviewed"),
            session=session,
            audit=store,
            principal=reviewer,
        )
    with factory() as session:
        listed = list_campaign_cue_coverage(campaign_id, session=session, principal=reviewer)
        assert listed["satisfied"] and listed["coverage"][0]["reviewed"]
        documented = record_cue_coverage_exception(
            campaign_id,
            CueCoverageExceptionRequest(
                cue_id="urgency",
                rationale="Synthetic documented policy exception",
            ),
            session=session,
            audit=store,
            principal=reviewer,
        )
        assert documented["cue_id"] == "urgency"
    _deny(engines["operator"], "DELETE FROM public.training_cue_coverage WHERE false")
    _deny(engines["operator"], "UPDATE public.campaign_cue_coverage_exceptions SET rationale=rationale WHERE false")


def test_retention_purges_only_bounded_old_reply_receipts_without_reading_private_evidence(subject):
    _, _, factory, engines, _ = subject
    now = datetime.now(UTC)
    old, recent = [uuid4() for _ in range(3)], uuid4()
    with factory() as session:
        for identity in [*old, recent]:
            session.add(
                ReplyMailReceipt(
                    reply_mail_receipt_id=identity,
                    provider="qualification",
                    scope_hash=uuid4().hex * 2,
                    external_id="synthetic-private-identifier",
                    external_id_hash=uuid4().hex * 2,
                    disposition="qualification",
                    evidence={"synthetic": True},
                    received_at=now - timedelta(days=40 if identity in old else 1),
                )
            )
        session.commit()
    with make_session_factory(engines["retention"])() as session:
        assert _purge_aged_receipts(session, ReplyMailReceipt, now - timedelta(days=30), 2) == 2
        session.commit()
        assert _purge_aged_receipts(session, ReplyMailReceipt, now - timedelta(days=30), 2) == 1
        session.commit()
        assert _purge_aged_receipts(session, ReplyMailReceipt, now - timedelta(days=30), 2) == 0
    with factory() as session:
        assert session.get(ReplyMailReceipt, recent) is not None
        assert all(session.get(ReplyMailReceipt, identity) is None for identity in old)
    for column in ("external_id", "external_id_hash", "evidence", "provider", "recipient_assignment_id"):
        _deny(engines["retention"], f"SELECT {column} FROM public.reply_mail_receipts")  # noqa: S608 - fixed columns


def test_delivery_exact_manifest_join_includes_only_reviewed_recipient_and_cannot_mutate_manifest(subject):
    campaign_id, assignments, _, engines, _ = subject
    with make_session_factory(engines["delivery"])() as session:
        selected = list(
            session.scalars(
                select(RecipientAssignment)
                .join(
                    CampaignAudienceManifest,
                    (CampaignAudienceManifest.campaign_id == RecipientAssignment.campaign_id)
                    & (CampaignAudienceManifest.recipient_id == RecipientAssignment.recipient_id),
                )
                .where(
                    RecipientAssignment.recipient_assignment_id.in_(assignments),
                    RecipientAssignment.campaign_id == campaign_id,
                    CampaignAudienceManifest.audience_version == 1,
                )
            )
        )
        assert [row.recipient_assignment_id for row in selected] == assignments[:1]
        assert not session.scalar(text("SELECT has_table_privilege('public.campaign_audience_manifest','SELECT')"))
    _deny(engines["delivery"], "SELECT recipient_hash FROM public.campaign_audience_manifest")
    _deny(engines["delivery"], "UPDATE public.campaign_audience_manifest SET ordinal=ordinal WHERE false")
    _deny(engines["delivery"], "DELETE FROM public.campaign_audience_manifest WHERE false")


def test_other_runtime_logins_do_not_acquire_operator_feature_or_worker_cue_access(subject):
    _, _, _, engines, _ = subject
    for role in ("delivery", "retention", "tracking", "generation"):
        for table in (
            "ai_generation_providers",
            "provider_config_generation",
            "console_session_epoch",
            "credential_rotations",
            "training_cue_coverage",
            "campaign_cue_coverage_exceptions",
        ):
            _deny(engines[role], f"SELECT * FROM public.{table}")  # noqa: S608 - fixed table tuple


def test_additive_migration_restores_existing_role_grants_without_login_changes(managed_database):
    url, admin, _, _ = managed_database
    migration_path = Path(__file__).resolve().parents[1] / "alembic/versions/0057_runtime_feature_grants.py"
    spec = importlib.util.spec_from_file_location("runtime_feature_migration_effect", migration_path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with admin.begin() as connection:
        role_query = text(
            "SELECT rolname,rolcanlogin,rolinherit,rolsuper FROM pg_roles WHERE rolname IN "
            "('kp_operator','kp_worker_retention','kp_worker_delivery') ORDER BY rolname"
        )
        before = connection.execute(role_query).all()
        connection.execute(
            text(
                "REVOKE SELECT(reply_mail_receipt_id,received_at),DELETE "
                "ON public.reply_mail_receipts FROM kp_worker_retention"
            )
        )
        connection.execute(
            text(
                "REVOKE SELECT(campaign_id,recipient_id,audience_version) "
                "ON public.campaign_audience_manifest FROM kp_worker_delivery"
            )
        )
        connection.execute(text("REVOKE SELECT,INSERT,UPDATE ON public.ai_generation_providers FROM kp_operator"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert connection.execute(role_query).all() == before
    for role, password, query in (
        ("kp_operator", "effect-operator", "SELECT * FROM public.ai_generation_providers"),
        (
            "kp_worker_retention",
            "effect-retention",
            "SELECT reply_mail_receipt_id,received_at FROM public.reply_mail_receipts",
        ),
        (
            "kp_worker_delivery",
            "effect-delivery",
            "SELECT campaign_id,recipient_id,audience_version FROM public.campaign_audience_manifest",
        ),
    ):
        engine = create_engine(url.set(username=role, password=password))
        with engine.connect() as connection:
            connection.execute(text(query)).all()
        engine.dispose()
