from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.campaign_service import AudienceDefinition, audience_definition_hash, bind_campaign_training_resource
from kp_database.models import (
    AuditEvent,
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignPattern,
    CampaignProgram,
    CampaignProgramOccurrence,
    RulesOfEngagement,
    TemplateVersion,
    TrainingResource,
)
from kp_database.session import create_db_engine
from kp_domain_models import models as dm
from kp_operator_api import program_routes
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from kp_telemetry.errors import AuditFailureError
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
TEST_SCHEMA = f"operator_program_{uuid4().hex}"
ISOLATED_URL = (
    make_url(TEST_URL)
    .update_query_dict({"options": f"-csearch_path={TEST_SCHEMA}"})
    .render_as_string(hide_password=False)
)
ADMIN_ID = UUID("10000000-0000-0000-0000-000000000002")


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    engine = create_db_engine(TEST_URL)
    try:
        with engine.connect():
            return True
    except Exception:
        return False
    finally:
        engine.dispose()


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _token(roles: list[str]) -> str:
    settings = OperatorApiSettings()
    return jwt.encode(
        {
            "sub": str(ADMIN_ID),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": roles},
        },
        CONSOLE_JWT.encode(),
        algorithm="HS256",
    )


ADMIN_HEADERS = {"Authorization": f"Bearer {_token(['administrator'])}"}
AUDITOR_HEADERS = {"Authorization": f"Bearer {_token(['auditor'])}"}


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    admin_engine = create_db_engine(TEST_URL)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{TEST_SCHEMA}"')
    engine = create_db_engine(ISOLATED_URL)
    try:
        Base.metadata.create_all(bind=engine)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE audit_chain_head ("
                    "id INTEGER PRIMARY KEY CHECK (id = 1), "
                    "event_hash VARCHAR(64) NOT NULL, signature VARCHAR(64), "
                    "signed_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
            )
        settings = OperatorApiSettings(
            audit_hmac_key=HMAC,
            ciphertext_kek=KEK,
            console_jwt_secret=CONSOLE_JWT,
            database_url=ISOLATED_URL,
            audit_database_url=ISOLATED_URL,
            tracking_base_url="https://training.example.com",
            training_base_url="https://training.example.com/awareness",
            training_domains="training.example.com",
        )
        app = create_app(settings)
        with TestClient(app, raise_server_exceptions=False) as test_client:
            app.state.audit_verifier.status = "ok"
            app.state.audit_health_check = lambda: True
            yield test_client
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{TEST_SCHEMA}" CASCADE')
        admin_engine.dispose()


def _seed_source(client: TestClient) -> UUID:
    now = datetime.now(UTC)
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        pattern_version=1,
        lure_category=dm.LureCategory.CONFERENCE,
        confidence=dm.Confidence.HIGH,
        approval_state=dm.PatternApprovalState.APPROVED,
    )
    template = TemplateVersion(
        template_version_id=uuid4(),
        version=1,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="i" * 64,
        subject="Program source",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    roe = RulesOfEngagement(
        roe_id=uuid4(),
        signer="Security",
        authorizing_party="RSA Conference",
        terms_text="Authorized awareness simulation",
        terms_hash="t" * 64,
        signature="s" * 64,
        signature_version=2,
        signed_at=now,
        window_start=now,
        window_end=now + timedelta(days=366),
        target_domains=["example.com"],
    )
    start = now + timedelta(days=2)
    end = start + timedelta(hours=4)
    source = Campaign(
        campaign_id=uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        current_template_id=template.template_version_id,
        title="RSA Conference finite program",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="awareness@example.com",
        roe_id=roe.roe_id,
        training_domain="training.example.com",
        schedule_start=start,
        schedule_end=end,
        timezone="UTC",
        max_recipients=50,
        manifest_hash="m" * 64,
        created_by=ADMIN_ID,
        expires_at=end,
    )
    resource = TrainingResource(
        training_resource_id=uuid4(),
        title="Program lesson",
        kind="article",
        content="Pause and independently verify the request.",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    bind_campaign_training_resource(source, resource)
    definition = AudienceDefinition(
        departments=("security",),
        statuses=(dm.RecipientStatus.ACTIVE,),
        sample_size=25,
        sample_seed="program-api-test",
    )
    audience = CampaignAudience(
        campaign_id=source.campaign_id,
        version=1,
        group_ids=[],
        departments=list(definition.departments),
        statuses=[item.value for item in definition.statuses],
        include_recipient_ids=[],
        exclude_recipient_ids=[],
        sample_size=definition.sample_size,
        sample_seed=definition.sample_seed,
        configuration_hash=audience_definition_hash(definition),
        preview_hash="p" * 64,
        manifest_hash="a" * 64,
        frozen_at=now,
        legacy_requires_configuration=False,
    )
    with client.app.state.session_factory() as session:
        session.add_all([pattern, template, roe, resource])
        session.flush()
        session.add_all([source, audience])
        session.commit()
    return source.campaign_id


def _create_program(client: TestClient, source_id: UUID) -> dict[str, object]:
    response = client.post(
        "/api/v1/programs",
        headers=ADMIN_HEADERS,
        json={"source_campaign_id": str(source_id), "cadence_days": 28, "occurrence_count": 3},
    )
    assert response.status_code == 201, response.text
    return response.json()


@requires_db
def test_program_create_list_and_detail_are_bounded_and_pii_free(client: TestClient) -> None:
    source_id = _seed_source(client)
    created = _create_program(client, source_id)

    assert created["created"] is True
    assert created["source_campaign_id"] == str(source_id)
    assert created["state"] == "active"
    assert created["version"] == 1
    assert created["complete"] is False
    occurrences = created["occurrences"]
    assert [item["occurrence_number"] for item in occurrences] == [1, 2, 3]
    assert [item["state"] for item in occurrences] == ["scheduled", "draft", "draft"]
    assert all(item["schedule_start"].endswith("Z") and item["schedule_end"].endswith("Z") for item in occurrences)
    assert not {"title", "sender_mailbox", "recipient_id", "mailbox"} & set(occurrences[0])

    program_id = created["campaign_program_id"]
    listing = client.get("/api/v1/programs", headers=ADMIN_HEADERS)
    assert listing.status_code == 200, listing.text
    assert listing.json()[0]["campaign_program_id"] == program_id
    assert "occurrences" not in listing.json()[0]
    detail = client.get(f"/api/v1/programs/{program_id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200, detail.text
    assert detail.json()["occurrences"] == occurrences

    replay = client.post(
        "/api/v1/programs",
        headers=ADMIN_HEADERS,
        json={"source_campaign_id": str(source_id), "cadence_days": 28, "occurrence_count": 3},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["created"] is False
    assert replay.json()["campaign_program_id"] == program_id

    future_campaign_ids = [UUID(item["campaign_id"]) for item in occurrences[1:]]
    with client.app.state.session_factory() as session:
        for campaign_id in future_campaign_ids:
            campaign = session.get(Campaign, campaign_id)
            audience = session.get(CampaignAudience, campaign_id)
            assert campaign is not None and campaign.state is dm.CampaignState.DRAFT
            assert campaign.roe_id is None
            assert campaign.manifest_signed_at is None
            assert audience is not None and audience.frozen_at is None
            assert audience.preview_hash is None and audience.manifest_hash is None
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(CampaignApproval)
                    .where(CampaignApproval.campaign_id == campaign_id)
                )
                == 0
            )


@requires_db
def test_pause_is_versioned_blocks_future_schedule_and_does_not_recall_source(client: TestClient) -> None:
    source_id = _seed_source(client)
    created = _create_program(client, source_id)
    program_id = created["campaign_program_id"]
    future_id = created["occurrences"][1]["campaign_id"]

    paused = client.post(
        f"/api/v1/programs/{program_id}/pause",
        headers=ADMIN_HEADERS,
        json={"expected_version": 1, "rationale": "Pause while the next exercise is reviewed"},
    )
    assert paused.status_code == 200, paused.text
    assert paused.json()["state"] == "paused"
    assert paused.json()["version"] == 2
    blocked = client.post(f"/api/v1/campaigns/{future_id}/schedule", headers=ADMIN_HEADERS)
    assert blocked.status_code == 409
    assert blocked.json()["detail"] == "KP-005: campaign program is paused; resume it before scheduling this occurrence"

    stale = client.post(
        f"/api/v1/programs/{program_id}/resume",
        headers=ADMIN_HEADERS,
        json={"expected_version": 1, "rationale": "Stale browser state"},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == "KP-005: campaign program changed; reload it before retrying"
    resumed = client.post(
        f"/api/v1/programs/{program_id}/resume",
        headers=ADMIN_HEADERS,
        json={"expected_version": 2, "rationale": "Review is complete"},
    )
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["state"] == "active"
    assert resumed.json()["version"] == 3

    with client.app.state.session_factory() as session:
        source = session.get(Campaign, source_id)
        assert source is not None and source.state is dm.CampaignState.SCHEDULED
        program_actions = list(
            session.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.object_id == str(program_id))
                .order_by(AuditEvent.occurred_at, AuditEvent.audit_event_id)
            )
        )
        assert program_actions == [
            "campaign_program.create",
            "campaign_program.paused",
            "campaign_program.active",
        ]
        blocked_audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == str(future_id),
                AuditEvent.action == "campaign.schedule.blocked",
            )
        )
        assert blocked_audit is not None
        assert blocked_audit.detail == {"reason": "campaign_program_paused"}


@requires_db
def test_program_completion_is_derived_from_occurrence_campaign_states(client: TestClient) -> None:
    source_id = _seed_source(client)
    created = _create_program(client, source_id)
    with client.app.state.session_factory() as session:
        occurrences = session.scalars(
            select(CampaignProgramOccurrence).where(
                CampaignProgramOccurrence.campaign_program_id == UUID(created["campaign_program_id"])
            )
        )
        for occurrence in occurrences:
            campaign = session.get(Campaign, occurrence.campaign_id)
            assert campaign is not None
            campaign.state = dm.CampaignState.COMPLETED
        session.commit()
    detail = client.get(f"/api/v1/programs/{created['campaign_program_id']}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    assert detail.json()["complete"] is True


@requires_db
def test_program_routes_enforce_auth_and_bounded_inputs(client: TestClient) -> None:
    source_id = _seed_source(client)
    assert client.get("/api/v1/programs").status_code == 401
    assert client.get("/api/v1/programs?limit=201", headers=ADMIN_HEADERS).status_code == 422
    assert client.get("/api/v1/programs?offset=10001", headers=ADMIN_HEADERS).status_code == 422
    denied = client.post(
        "/api/v1/programs",
        headers=AUDITOR_HEADERS,
        json={"source_campaign_id": str(source_id), "cadence_days": 28, "occurrence_count": 3},
    )
    assert denied.status_code == 403
    invalid = client.post(
        "/api/v1/programs",
        headers=ADMIN_HEADERS,
        json={"source_campaign_id": str(source_id), "cadence_days": 30, "occurrence_count": 13},
    )
    assert invalid.status_code == 422
    assert client.get("/api/v1/programs/not-a-uuid", headers=ADMIN_HEADERS).status_code == 422

    created = _create_program(client, source_id)
    blank = client.post(
        f"/api/v1/programs/{created['campaign_program_id']}/pause",
        headers=ADMIN_HEADERS,
        json={"expected_version": 1, "rationale": "   "},
    )
    assert blank.status_code == 422


@requires_db
def test_program_creation_rolls_back_when_audit_intent_fails(client: TestClient) -> None:
    source_id = _seed_source(client)
    original_audit_store = client.app.state.audit_store

    class FailingAuditStore:
        def record(self, **kwargs: object) -> None:
            del kwargs
            raise AuditFailureError()

    client.app.state.audit_store = FailingAuditStore()
    try:
        response = client.post(
            "/api/v1/programs",
            headers=ADMIN_HEADERS,
            json={"source_campaign_id": str(source_id), "cadence_days": 28, "occurrence_count": 3},
        )
    finally:
        client.app.state.audit_store = original_audit_store

    assert response.status_code == 503
    assert response.json()["code"] == "KP-008"
    with client.app.state.session_factory() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(CampaignProgram).where(CampaignProgram.source_campaign_id == source_id)
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(CampaignProgramOccurrence)
                .join(
                    CampaignProgram,
                    CampaignProgram.campaign_program_id == CampaignProgramOccurrence.campaign_program_id,
                )
                .where(CampaignProgram.source_campaign_id == source_id)
            )
            == 0
        )


@requires_db
def test_unexpected_program_failure_logs_only_bounded_metadata(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = _seed_source(client)

    class DatabasePasswordLeak(RuntimeError):
        pass

    def fail_materialization(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise DatabasePasswordLeak("password=must-not-reach-log-or-response")

    monkeypatch.setattr(program_routes, "materialize_campaign_program", fail_materialization)
    response = client.post(
        "/api/v1/programs",
        headers=ADMIN_HEADERS,
        json={"source_campaign_id": str(source_id), "cadence_days": 28, "occurrence_count": 3},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error"}
    captured = capsys.readouterr().out
    assert "unexpected_request_error" in captured
    assert "DatabasePasswordLeak" in captured
    assert '"route_template":"/api/v1/programs"' in captured
    assert "password=must-not-reach-log-or-response" not in captured
