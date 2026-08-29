"""Regression coverage for the immutable Alembic baseline and fresh installs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from kp_database.models import (
    AudienceGroup,
    AudienceGroupMember,
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignPattern,
    CipherText,
    DeliveryReportCorrelation,
    Microsoft365IntegrationState,
    PrivacyNotice,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    ReportedMailReceipt,
    TrackingEvent,
    TrackingToken,
    TrainingResource,
    TransactionalOutbox,
)
from kp_database.outbox import enqueue_audit
from kp_database.privacy import hash_mailbox
from kp_domain_models import models as dm
from kp_workers.directory_jobs import _group_hash, _object_hash, _scope, apply_directory, preview_directory
from kp_workers.providers.graph import DirectorySyncResult
from kp_workers.providers.microsoft365 import ReportedMailboxPollResult
from kp_workers.reported_mail_jobs import _consume, process_mailbox
from psycopg import sql
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from test_audit_store import TEST_URL, requires_db

DATABASE_ROOT = Path(__file__).resolve().parents[1]
INITIAL_MIGRATION = DATABASE_ROOT / "alembic" / "versions" / "0001_initial.py"


def _load_initial_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kp_migration_0001", INITIAL_MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_initial_revision_is_a_frozen_schema_snapshot() -> None:
    source = INITIAL_MIGRATION.read_text(encoding="utf-8")
    migration = _load_initial_migration()

    assert "kp_database" not in source
    assert "Base.metadata" not in source
    assert "verified_domains" not in migration._METADATA.tables
    assert "rules_of_engagement" not in migration._METADATA.tables
    assert "retention_policies" not in migration._METADATA.tables
    assert "sender_display_name" not in migration._METADATA.tables["campaigns"].c
    assert "fetch_path" not in migration._METADATA.tables["sources"].c


@contextmanager
def _isolated_database(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Config, URL]]:
    source_url = make_url(TEST_URL)
    admin_url = source_url.set(database="postgres")
    database_name = f"kp_migration_{uuid.uuid4().hex}"
    database_url = source_url.set(database=database_name)
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT", pool_pre_ping=True)
    created = False
    try:
        try:
            with admin_engine.connect() as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
            created = True
        except Exception as exc:
            pytest.skip(f"Postgres test role cannot create an isolated migration database: {exc}")

        monkeypatch.setenv("DATABASE_URL", database_url.render_as_string(hide_password=False))
        config = Config(str(DATABASE_ROOT / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", database_url.render_as_string(hide_password=False))
        yield config, database_url
    finally:
        if created:
            with admin_engine.connect() as connection:
                raw = connection.connection.driver_connection
                raw.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name)))
        admin_engine.dispose()


@pytest.mark.postgres
@requires_db
def test_fresh_postgres_database_upgrades_from_base_to_head(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the actual revision chain in an isolated database.

    A dedicated database is required because audit ownership migrations refer
    explicitly to the public schema. Environments without CREATEDB support
    skip with an actionable reason rather than mutating a shared test schema.
    """

    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "head")

        migrated_engine = create_engine(database_url, pool_pre_ping=True)
        try:
            schema = inspect(migrated_engine)
            table_names = set(schema.get_table_names())
            assert "verified_domains" in table_names
            assert "rules_of_engagement" in schema.get_table_names()
            assert {"campaign_programs", "campaign_program_occurrences"} <= table_names
            program_checks = {item["name"] for item in schema.get_check_constraints("campaign_programs")}
            assert {
                "ck_campaign_programs_version_positive",
                "ck_campaign_programs_cadence_allowlist",
                "ck_campaign_programs_occurrence_count_bounded",
                "ck_campaign_programs_configuration_hash_hex",
            } <= program_checks
            occurrence_uniques = {
                item["name"] for item in schema.get_unique_constraints("campaign_program_occurrences")
            }
            assert {
                "uq_campaign_program_occurrences_campaign_id",
                "uq_campaign_program_occurrence_number",
            } <= occurrence_uniques
            assert "sender_display_name" in {column["name"] for column in schema.get_columns("campaigns")}
            recipient_indexes = {index["name"]: index for index in schema.get_indexes("recipients")}
            assert recipient_indexes["uq_recipients_mailbox_sha256_active"]["unique"] is True
            assert recipient_indexes["ix_recipients_mailbox_sha256"]["unique"] is False
            training_columns = {column["name"] for column in schema.get_columns("training_assignments")}
            assert {
                "recipient_assignment_id",
                "opened_at",
                "due_at",
                "access_expires_at",
                "training_token_hash",
                "training_completion_token_hash",
            } <= training_columns
            assert "training_resource_id" in {column["name"] for column in schema.get_columns("campaigns")}
            assert {"created_at", "revoked_at", "revoked_by", "revoke_reason"} <= {
                column["name"] for column in schema.get_columns("recipient_exclusions")
            }
            exclusion_indexes = {index["name"] for index in schema.get_indexes("recipient_exclusions")}
            assert {
                "ix_recipient_exclusions_recipient_created",
                "ix_recipient_exclusions_active_scope",
            } <= exclusion_indexes
            assert {
                "created_by",
                "created_at",
                "submitted_at",
                "reviewed_by",
                "reviewed_at",
                "review_rationale",
            } <= {column["name"] for column in schema.get_columns("training_resources")}
            campaign_foreign_keys = {item["name"]: item for item in schema.get_foreign_keys("campaigns")}
            resource_foreign_key = campaign_foreign_keys["fk_campaigns_training_resource_id_training_resources"]
            assert resource_foreign_key["referred_table"] == "training_resources"
            assert resource_foreign_key["options"].get("ondelete") == "RESTRICT"
            CipherText.configure_key(b"z" * 32)
            assert isinstance(RecipientExclusion.__table__.c.revoke_reason.type, CipherText)
            cursor_secret = "https://graph.microsoft.com/opaque-cursor-secret"
            external_secret = "opaque-external-message-id"
            report_verifier = "rpt1_" + "C" * 43
            with Session(migrated_engine) as session:
                current_notice = session.scalar(
                    select(PrivacyNotice).where(PrivacyNotice.is_current.is_(True)).limit(1)
                )
                assert current_notice is not None
                assert current_notice.notice_id == uuid.UUID("00000000-0000-4000-8000-000000000030")
                assert "365 days" in current_notice.notice_text
                builtin_training = session.get(
                    TrainingResource,
                    uuid.UUID("00000000-0000-4000-8000-000000000019"),
                )
                assert builtin_training is not None
                assert builtin_training.approval_state == dm.TemplateApprovalState.APPROVED
                assert builtin_training.source_ref == "builtin:training-remediation-v1"
                session.add(
                    Microsoft365IntegrationState(
                        integration_state_id=uuid.uuid4(),
                        kind="directory",
                        provider="microsoft365",
                        scope_hash="1" * 64,
                        config_fingerprint="2" * 64,
                        cursor=cursor_secret,
                        pending_payload='{"private":"preview"}',
                        pending_preview_id=uuid.uuid4(),
                        pending_preview_hash="f" * 64,
                        pending_created_at=datetime.now(UTC),
                        pending_expires_at=datetime.now(UTC) + timedelta(minutes=15),
                        status="preview_ready",
                        generation=1,
                        last_counts={},
                    )
                )
                session.add(
                    ReportedMailReceipt(
                        reported_mail_receipt_id=uuid.uuid4(),
                        provider="microsoft365",
                        scope_hash="1" * 64,
                        external_id=external_secret,
                        external_id_hash="3" * 64,
                        disposition="unknown",
                        evidence={"sources": ["attached_original"]},
                        received_at=datetime.now(UTC),
                    )
                )
                pattern_id = uuid.uuid4()
                campaign_id = uuid.uuid4()
                recipient_id = uuid.uuid4()
                assignment_id = uuid.uuid4()
                attempt_id = uuid.uuid4()
                token_id = uuid.uuid4()
                session.add(
                    CampaignPattern(
                        campaign_pattern_id=pattern_id,
                        lure_category=dm.LureCategory.OTHER,
                        confidence=dm.Confidence.HIGH,
                    )
                )
                session.flush()
                session.add(
                    Campaign(
                        campaign_id=campaign_id,
                        pattern_id=pattern_id,
                        title="M365 report round trip",
                        state=dm.CampaignState.ACTIVE,
                        sender_mailbox="security@example.com",
                        training_domain="example.com",
                        max_recipients=1,
                        expires_at=datetime.now(UTC) + timedelta(days=1),
                    )
                )
                session.flush()
                session.add(
                    Recipient(
                        recipient_id=recipient_id,
                        employee_key="learner",
                        mailbox="learner@example.com",
                        mailbox_sha256="4" * 64,
                        status=dm.RecipientStatus.ACTIVE,
                    )
                )
                session.flush()
                session.add(
                    RecipientAssignment(
                        recipient_assignment_id=assignment_id,
                        campaign_id=campaign_id,
                        recipient_id=recipient_id,
                        send_state=dm.SendState.ACCEPTED,
                        delivery_attempt_id=attempt_id,
                        delivery_attempt_count=1,
                        idempotency_key="m365-round-trip",
                    )
                )
                session.flush()
                session.add(
                    TrackingToken(
                        token_id=token_id,
                        token_hash="5" * 64,
                        token_prefix="555555",
                        campaign_id=campaign_id,
                        recipient_assignment_id=assignment_id,
                        status=dm.TokenStatus.ACTIVE,
                        expires_at=datetime.now(UTC) + timedelta(days=1),
                    )
                )
                session.flush()
                session.add(
                    DeliveryReportCorrelation(
                        delivery_attempt_id=attempt_id,
                        recipient_assignment_id=assignment_id,
                        report_verifier=report_verifier,
                        verifier_hash=hashlib.sha256(report_verifier.encode("ascii")).hexdigest(),
                        message_id="<m365-round-trip@example.com>",
                    )
                )
                session.commit()
                assert (
                    _consume(
                        session,
                        provider="microsoft365",
                        scope_hash="1" * 64,
                        external_id="round-trip-report",
                        received_at=datetime.now(UTC),
                        candidate=report_verifier,
                        disposition="candidate",
                        evidence={"sources": ["attached_original"], "parts_seen": 2},
                    )
                    == "reported"
                )
                session.commit()
                assert (
                    _consume(
                        session,
                        provider="microsoft365",
                        scope_hash="1" * 64,
                        external_id="round-trip-report",
                        received_at=datetime.now(UTC),
                        candidate=report_verifier,
                        disposition="candidate",
                        evidence={"sources": ["attached_original"]},
                    )
                    == "replay"
                )
                assert len(list(session.scalars(select(TrackingEvent)))) == 1
            with migrated_engine.connect() as connection:
                assert (
                    connection.scalar(text("SELECT version_num FROM alembic_version"))
                    == ScriptDirectory.from_config(config).get_current_head()
                )
                assert (
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM training_resources "
                            "WHERE source_ref = 'builtin:training-remediation-v1' AND approval_state = 'APPROVED'"
                        )
                    )
                    == 1
                )
                raw_cursor = connection.scalar(text("SELECT cursor FROM microsoft365_integration_states"))
                raw_external = connection.scalar(text("SELECT external_id FROM reported_mail_receipts"))
                raw_verifier = connection.scalar(text("SELECT report_verifier FROM delivery_report_correlations"))
                raw_evidence = connection.scalar(
                    text("SELECT evidence::text FROM reported_mail_receipts WHERE external_id_hash <> :legacy"),
                    {"legacy": "3" * 64},
                )
                assert cursor_secret not in raw_cursor
                assert external_secret not in raw_external
                assert report_verifier not in raw_verifier
                assert report_verifier not in raw_evidence
        finally:
            migrated_engine.dispose()


@pytest.mark.postgres
@requires_db
def test_directory_apply_rename_removal_and_collision_are_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "head")
        engine = create_engine(database_url, pool_pre_ping=True)
        CipherText.configure_key(b"y" * 32)
        salt = b"s" * 32

        class _Audit:
            @staticmethod
            def record(**kwargs) -> None:
                session = kwargs.pop("session")
                enqueue_audit(session, **kwargs)

        settings = SimpleNamespace(
            graph_group_id_set=lambda: (),
            microsoft_tenant_id="11111111-1111-1111-1111-111111111111",
            effective_graph_base_url="https://graph.microsoft.com/v1.0",
            recipient_domain_allowlist=lambda: frozenset({"example.com"}),
            require_recipient_hash_salt=lambda: salt,
        )
        context = SimpleNamespace(
            settings=settings,
            session_factory=sessionmaker(engine, expire_on_commit=False),
            audit_store=_Audit(),
        )
        scope_hash, fingerprint, source, _ = _scope(context)
        stable_id = "stable-entra-object"
        removed_id = "removed-entra-object"
        preview_id = uuid.uuid4()
        payload = {
            "mode": "full",
            "source": source,
            "users": [
                {
                    "entra_id": stable_id,
                    "mailbox": "renamed@example.com",
                    "display_name": "Renamed Learner",
                    "department": "Security",
                }
            ],
            "removals": [],
            "group_members": {"stable-directory-group": [stable_id]},
            "cursor": "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=next",
            "cursor_kind": "delta",
            "config_fingerprint": fingerprint,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with Session(engine) as session:
            stable_recipient_id = uuid.uuid4()
            removed_recipient_id = uuid.uuid4()
            group_id = uuid.uuid4()
            campaign_id = uuid.uuid4()
            stable_recipient = Recipient(
                recipient_id=stable_recipient_id,
                employee_key="entra:stable",
                mailbox="old@example.com",
                mailbox_sha256=hash_mailbox("old@example.com", salt),
                status=dm.RecipientStatus.ACTIVE,
                directory_source=source,
                directory_object_id_hash=_object_hash(stable_id, salt, source),
                directory_generation=1,
                directory_owned=True,
            )
            removed_recipient = Recipient(
                recipient_id=removed_recipient_id,
                employee_key="entra:removed",
                mailbox="removed@example.com",
                mailbox_sha256=hash_mailbox("removed@example.com", salt),
                status=dm.RecipientStatus.ACTIVE,
                directory_source=source,
                directory_object_id_hash=_object_hash(removed_id, salt, source),
                directory_generation=1,
                directory_owned=True,
            )
            group = AudienceGroup(
                audience_group_id=group_id,
                name="Reviewed directory group",
                directory_group_ref="stable-directory-group",
                directory_group_ref_hash=_group_hash("stable-directory-group", salt),
            )
            pattern = CampaignPattern(
                campaign_pattern_id=uuid.uuid4(),
                lure_category=dm.LureCategory.OTHER,
                confidence=dm.Confidence.HIGH,
            )
            campaign = Campaign(
                campaign_id=campaign_id,
                pattern_id=pattern.campaign_pattern_id,
                title="Frozen group campaign",
                state=dm.CampaignState.DRAFT,
                sender_mailbox="sender@example.com",
                training_domain="training.example.com",
                max_recipients=10,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
            audience = CampaignAudience(
                campaign_id=campaign.campaign_id,
                group_ids=[str(group.audience_group_id)],
                departments=[],
                statuses=[dm.RecipientStatus.ACTIVE.value],
                include_recipient_ids=[],
                exclude_recipient_ids=[],
                configuration_hash="c" * 64,
            )
            session.add_all(
                [
                    stable_recipient,
                    removed_recipient,
                    group,
                    pattern,
                    Microsoft365IntegrationState(
                        integration_state_id=uuid.uuid4(),
                        kind="directory",
                        provider="microsoft365",
                        scope_hash=scope_hash,
                        config_fingerprint=fingerprint,
                        status="preview_ready",
                        generation=1,
                        pending_preview_id=preview_id,
                        pending_preview_hash=hashlib.sha256(encoded.encode()).hexdigest(),
                        pending_payload=encoded,
                        pending_created_at=datetime.now(UTC),
                        pending_expires_at=datetime.now(UTC) + timedelta(minutes=15),
                        last_counts={"accepted": 1},
                    ),
                ]
            )
            # These tables expose FK-only mappings rather than ORM
            # relationships, so establish their referenced rows explicitly.
            session.flush()
            session.add(campaign)
            session.flush()
            session.add(audience)
            session.flush()
            session.add_all(
                [
                    AudienceGroupMember(
                        audience_group_member_id=uuid.uuid4(),
                        audience_group_id=group.audience_group_id,
                        recipient_id=removed_recipient.recipient_id,
                    ),
                    CampaignAudienceManifest(
                        campaign_id=campaign.campaign_id,
                        recipient_id=removed_recipient.recipient_id,
                        audience_version=1,
                        ordinal=0,
                        recipient_hash="r" * 64,
                    ),
                ]
            )
            session.flush()
            audience.preview_hash = "p" * 64
            audience.manifest_hash = "m" * 64
            audience.frozen_at = datetime.now(UTC)
            campaign.manifest_hash = audience.manifest_hash
            campaign.state = dm.CampaignState.APPROVED
            session.commit()

        result = apply_directory(
            context,
            preview_id=str(preview_id),
            requested_by="operator",
            job_id="apply-1",
        )

        assert result == {
            "created": 0,
            "updated": 1,
            "deactivated": 1,
            "groups_updated": 1,
            "campaigns_invalidated": 1,
        }
        with Session(engine) as session:
            renamed = session.scalar(
                select(Recipient).where(Recipient.mailbox_sha256 == hash_mailbox("renamed@example.com", salt))
            )
            removed = session.scalar(
                select(Recipient).where(Recipient.directory_object_id_hash == _object_hash(removed_id, salt, source))
            )
            state = session.scalar(select(Microsoft365IntegrationState))
            assert renamed is not None and renamed.status == dm.RecipientStatus.ACTIVE
            assert removed is not None and removed.status == dm.RecipientStatus.DEPARTED
            assert state is not None and state.status == "healthy" and state.generation == 2
            assert len(list(session.scalars(select(TransactionalOutbox)))) == 1
            assert session.scalar(select(CampaignAudienceManifest)) is None
            assert session.get(Campaign, campaign_id).state == dm.CampaignState.DRAFT
            assert set(
                session.scalars(
                    select(AudienceGroupMember.recipient_id).where(AudienceGroupMember.audience_group_id == group_id)
                )
            ) == {stable_recipient_id}

            manual = Recipient(
                recipient_id=uuid.uuid4(),
                employee_key="manual",
                mailbox="collision@example.com",
                mailbox_sha256=hash_mailbox("collision@example.com", salt),
                status=dm.RecipientStatus.ACTIVE,
                directory_owned=False,
            )
            session.add(manual)
            collision_preview = uuid.uuid4()
            collision_payload = {
                **payload,
                "users": [
                    {
                        "entra_id": "new-entra-object",
                        "mailbox": "collision@example.com",
                        "display_name": "Collision",
                        "department": "Security",
                    }
                ],
            }
            collision_encoded = json.dumps(collision_payload, sort_keys=True, separators=(",", ":"))
            state.status = "preview_ready"
            state.pending_preview_id = collision_preview
            state.pending_preview_hash = hashlib.sha256(collision_encoded.encode()).hexdigest()
            state.pending_payload = collision_encoded
            state.pending_created_at = datetime.now(UTC)
            state.pending_expires_at = datetime.now(UTC) + timedelta(minutes=15)
            session.commit()

        with pytest.raises(RuntimeError, match="collides"):
            apply_directory(
                context,
                preview_id=str(collision_preview),
                requested_by="operator",
                job_id="apply-collision",
            )
        with Session(engine) as session:
            state = session.scalar(select(Microsoft365IntegrationState))
            assert state is not None and state.status == "preview_ready"
            assert (
                session.scalar(
                    select(Recipient).where(Recipient.mailbox_sha256 == hash_mailbox("collision@example.com", salt))
                )
                is not None
            )
            state.pending_created_at = datetime.now(UTC) - timedelta(minutes=20)
            state.pending_expires_at = datetime.now(UTC) - timedelta(minutes=5)
            session.commit()
        with pytest.raises(RuntimeError, match="expired"):
            apply_directory(
                context,
                preview_id=str(collision_preview),
                requested_by="operator",
                job_id="apply-expired",
            )
        with Session(engine) as session:
            state = session.scalar(select(Microsoft365IntegrationState))
            assert state is not None and state.status == "expired"
            assert state.pending_preview_id is None and state.pending_payload is None

        settings.graph_group_id_set = lambda: ("stable-directory-group",)
        monkeypatch.setattr(
            "kp_workers.directory_jobs._fetch",
            lambda _ctx, _state, _groups: (
                DirectorySyncResult((), (), None, None, True, False, 1, 1),
                {},
            ),
        )
        rejected = preview_directory(context, requested_by="operator", job_id="rejected-full")
        assert rejected["status"] == "rejected"
        with Session(engine) as session:
            state = session.scalar(select(Microsoft365IntegrationState))
            assert state is not None and state.pending_preview_id is None
            active = session.get(Recipient, stable_recipient_id)
            assert active is not None and active.status == dm.RecipientStatus.ACTIVE
        engine.dispose()


@pytest.mark.postgres
@requires_db
def test_mailbox_job_replay_and_stale_poll_cannot_regress_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "head")
        engine = create_engine(database_url, pool_pre_ping=True)
        CipherText.configure_key(b"q" * 32)

        class _Audit:
            @staticmethod
            def record(**kwargs) -> None:
                session = kwargs.pop("session")
                enqueue_audit(session, **kwargs)

        settings = SimpleNamespace(
            reported_mailbox_provider="microsoft365",
            microsoft_tenant_id="11111111-1111-1111-1111-111111111111",
            reported_mailbox_id="reports@example.com",
            reported_mailbox_folder_id="inbox",
            effective_reported_mailbox_url="https://graph.microsoft.com/v1.0",
            reported_mailbox_bearer_token=None,
            reported_mailbox_client_id=None,
            reported_mailbox_basic_username=None,
            reported_mailbox_basic_password=None,
            provider_timeout_seconds=2.0,
            mailbox_poll_limit=10,
        )
        context = SimpleNamespace(
            settings=settings,
            session_factory=sessionmaker(engine, expire_on_commit=False),
            audit_store=_Audit(),
            queue=SimpleNamespace(),
        )
        calls = 0

        class _Provider:
            def poll(self, _cursor: str | None) -> ReportedMailboxPollResult:
                nonlocal calls
                calls += 1
                return ReportedMailboxPollResult("complete", (), "cursor-one", "delta", 1, 0, 0, 0)

        monkeypatch.setattr("kp_workers.reported_mail_jobs._m365_provider", lambda _ctx: _Provider())
        message = {"id": "job-1", "idempotency_key": "mailbox-job-1", "payload": {}}
        process_mailbox(context, message)
        process_mailbox(context, message)
        assert calls == 1

        class _StaleProvider:
            def poll(self, _cursor: str | None) -> ReportedMailboxPollResult:
                with Session(engine) as session:
                    state = session.scalar(
                        select(Microsoft365IntegrationState).where(Microsoft365IntegrationState.kind == "mailbox")
                    )
                    assert state is not None
                    state.cursor = "cursor-from-newer-worker"
                    state.generation += 1
                    state.active_job_key = "newer-job"
                    state.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
                    session.commit()
                item = SimpleNamespace(external_id="stale-receipt", received_at=datetime.now(UTC))
                return ReportedMailboxPollResult("complete", (item,), "stale-cursor", "delta", 1, 0, 0, 0)

        monkeypatch.setattr("kp_workers.reported_mail_jobs._m365_provider", lambda _ctx: _StaleProvider())
        monkeypatch.setattr(
            "kp_workers.reported_mail_jobs._m365_candidate",
            lambda _item: (None, "unknown", {"source": "bounded-test"}),
        )
        process_mailbox(
            context,
            {"id": "job-2", "idempotency_key": "mailbox-job-2", "payload": {}},
        )
        with Session(engine) as session:
            state = session.scalar(
                select(Microsoft365IntegrationState).where(Microsoft365IntegrationState.kind == "mailbox")
            )
            assert state is not None and state.cursor == "cursor-from-newer-worker"
            assert session.scalar(select(ReportedMailReceipt)) is None
        engine.dispose()


@pytest.mark.postgres
@requires_db
def test_existing_legacy_training_rows_upgrade_to_immutable_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "0018_persistent_emergency_stop")
        legacy_id = uuid.uuid4()
        resource_id = uuid.uuid4()
        recipient_id = uuid.uuid4()
        assigned_at = "2026-08-01T12:00:00+00:00"
        legacy_title = "L" * 200
        legacy_content = "C" * 20_001
        legacy_source_ref = "R" * 501
        engine = create_engine(database_url, pool_pre_ping=True)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO training_resources "
                        "(training_resource_id, title, kind, content, version, requires_completion, source_ref, "
                        "approval_state) VALUES "
                        "(:resource_id, :title, 'article', :content, 0, true, :source_ref, 'APPROVED')"
                    ),
                    {
                        "resource_id": resource_id,
                        "title": legacy_title,
                        "content": legacy_content,
                        "source_ref": legacy_source_ref,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO training_assignments "
                        "(training_assignment_id, recipient_id, resource_id, assigned_at, status) VALUES "
                        "(:assignment_id, :recipient_id, :resource_id, :assigned_at, 'ASSIGNED')"
                    ),
                    {
                        "assignment_id": legacy_id,
                        "recipient_id": recipient_id,
                        "resource_id": resource_id,
                        "assigned_at": assigned_at,
                    },
                )

            command.upgrade(config, "head")
            with engine.connect() as connection:
                row = connection.execute(
                    text(
                        "SELECT assigned_at, opened_at, due_at, access_expires_at, recipient_assignment_id "
                        "FROM training_assignments WHERE training_assignment_id = :assignment_id"
                    ),
                    {"assignment_id": legacy_id},
                ).one()
                legacy_resource = connection.execute(
                    text(
                        "SELECT title, content, version, source_ref FROM training_resources "
                        "WHERE training_resource_id = :resource_id"
                    ),
                    {"resource_id": resource_id},
                ).one()
                validation = {
                    constraint.conname: constraint.convalidated
                    for constraint in connection.execute(
                        text(
                            "SELECT conname, convalidated FROM pg_constraint "
                            "WHERE conname LIKE 'ck_training_resources_%_bounded' "
                            "OR conname LIKE 'ck_training_resources_%_version_positive'"
                        )
                    )
                }
            assert row.opened_at is None
            assert row.recipient_assignment_id is None
            assert row.due_at - row.assigned_at == timedelta(hours=72)
            assert row.access_expires_at - row.assigned_at == timedelta(days=90)
            assert legacy_resource == (legacy_title, legacy_content, 0, legacy_source_ref)
            assert len(validation) == 4
            assert all(validated is False for validated in validation.values())
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO training_resources "
                        "(training_resource_id, title, kind, content, version, requires_completion, source_ref, "
                        "approval_state) VALUES "
                        "(:resource_id, :title, 'article', 'Safe text', 1, true, 'new:test', 'DRAFT')"
                    ),
                    {"resource_id": uuid.uuid4(), "title": "N" * 200},
                )
        finally:
            engine.dispose()


@pytest.mark.postgres
@requires_db
def test_retention_policy_constraints_reject_invalid_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Migrated head enforces bounded retention days and one single default."""

    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "head")
        engine = create_engine(database_url, pool_pre_ping=True)
        try:
            insert = text(
                "INSERT INTO retention_policies "
                "(retention_policy_id, name, data_category, retention_days, is_default, description) "
                "VALUES (:policy_id, :name, :category, :days, :is_default, NULL)"
            )
            with engine.begin() as connection:
                connection.execute(
                    insert,
                    {
                        "policy_id": uuid.uuid4(),
                        "name": "default-raw",
                        "category": "raw_evidence",
                        "days": 365,
                        "is_default": True,
                    },
                )
                connection.execute(
                    insert,
                    {
                        "policy_id": uuid.uuid4(),
                        "name": "short-raw",
                        "category": "raw_evidence",
                        "days": 30,
                        "is_default": False,
                    },
                )
                db_objects = connection.execute(
                    text(
                        "SELECT conname FROM pg_constraint WHERE conrelid = "
                        "'retention_policies'::regclass AND conname = 'ck_retention_policies_days_bounded'"
                    )
                ).scalar()
                index_names = {
                    row[0]
                    for row in connection.execute(
                        text("SELECT indexname FROM pg_indexes WHERE tablename = 'retention_policies'")
                    )
                }
            assert db_objects == "ck_retention_policies_days_bounded"
            assert "uq_retention_policies_single_default" in index_names

            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    insert,
                    {
                        "policy_id": uuid.uuid4(),
                        "name": "second-default",
                        "category": "raw_evidence",
                        "days": 90,
                        "is_default": True,
                    },
                )
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    insert,
                    {
                        "policy_id": uuid.uuid4(),
                        "name": "zero-days",
                        "category": "raw_evidence",
                        "days": 0,
                        "is_default": False,
                    },
                )
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    insert,
                    {
                        "policy_id": uuid.uuid4(),
                        "name": "too-long",
                        "category": "raw_evidence",
                        "days": 366,
                        "is_default": False,
                    },
                )
        finally:
            engine.dispose()


@pytest.mark.postgres
@requires_db
def test_existing_recipient_exclusion_upgrades_from_0026_to_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve an active exclusion while adding the 0027 lifecycle fields."""

    with _isolated_database(monkeypatch) as (config, database_url):
        command.upgrade(config, "0026_training_resource_library")
        recipient_id = uuid.uuid4()
        exclusion_id = uuid.uuid4()
        revoker_id = uuid.uuid4()
        legacy_reason = "legacy approved accommodation"
        engine = create_engine(database_url, pool_pre_ping=True)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO recipients "
                        "(recipient_id, employee_key, mailbox, mailbox_sha256, is_test_account, status) VALUES "
                        "(:recipient_id, 'legacy-employee', 'legacy@example.com', :mailbox_hash, false, 'ACTIVE')"
                    ),
                    {"recipient_id": recipient_id, "mailbox_hash": "7" * 64},
                )
                connection.execute(
                    text(
                        "INSERT INTO recipient_exclusions "
                        "(recipient_exclusion_id, recipient_id, exclusion_type, reason) VALUES "
                        "(:exclusion_id, :recipient_id, 'ACCOMMODATION', :reason)"
                    ),
                    {
                        "exclusion_id": exclusion_id,
                        "recipient_id": recipient_id,
                        "reason": legacy_reason,
                    },
                )

            command.upgrade(config, "head")
            with engine.begin() as connection:
                migrated = connection.execute(
                    text(
                        "SELECT reason, created_at, revoked_at, revoked_by, revoke_reason "
                        "FROM recipient_exclusions WHERE recipient_exclusion_id = :exclusion_id"
                    ),
                    {"exclusion_id": exclusion_id},
                ).one()
                assert migrated.reason == legacy_reason
                assert migrated.created_at is not None
                assert migrated.revoked_at is None
                assert migrated.revoked_by is None
                assert migrated.revoke_reason is None

                indexes = {item["name"]: item for item in inspect(connection).get_indexes("recipient_exclusions")}
                assert indexes["ix_recipient_exclusions_recipient_created"]["unique"] is False
                assert indexes["ix_recipient_exclusions_active_scope"]["unique"] is False

                revoked_at = datetime.now(UTC)
                connection.execute(
                    text(
                        "UPDATE recipient_exclusions "
                        "SET revoked_at = :revoked_at, revoked_by = :revoker_id, revoke_reason = :revoke_reason "
                        "WHERE recipient_exclusion_id = :exclusion_id"
                    ),
                    {
                        "revoked_at": revoked_at,
                        "revoker_id": revoker_id,
                        "revoke_reason": "reviewed withdrawal",
                        "exclusion_id": exclusion_id,
                    },
                )
                lifecycle = connection.execute(
                    text(
                        "SELECT revoked_at, revoked_by, revoke_reason FROM recipient_exclusions "
                        "WHERE recipient_exclusion_id = :exclusion_id"
                    ),
                    {"exclusion_id": exclusion_id},
                ).one()
                assert lifecycle.revoked_at == revoked_at
                assert lifecycle.revoked_by == revoker_id
                assert lifecycle.revoke_reason == "reviewed withdrawal"
        finally:
            engine.dispose()
