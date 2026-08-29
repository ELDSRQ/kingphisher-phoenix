from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import CampaignPattern, TemplateVersion
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
AUTHOR_ID = UUID("10000000-0000-0000-0000-000000000001")
ADMIN_ID = UUID("10000000-0000-0000-0000-000000000002")


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(TEST_URL)
        with engine.connect():
            pass
        engine.dispose()
        return True
    except Exception:
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")
_TEST_ENGINE = create_db_engine(TEST_URL)
_TEST_SESSIONS = make_session_factory(_TEST_ENGINE)


def _token(subject: UUID, roles: list[str]) -> str:
    settings = OperatorApiSettings()
    return jwt.encode(
        {
            "sub": str(subject),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": roles},
        },
        CONSOLE_JWT.encode(),
        algorithm="HS256",
    )


AUTHOR_HEADERS = {"Authorization": f"Bearer {_token(AUTHOR_ID, ['campaign_author'])}"}
ADMIN_HEADERS = {"Authorization": f"Bearer {_token(ADMIN_ID, ['administrator'])}"}
CURATOR_HEADERS = {"Authorization": f"Bearer {_token(ADMIN_ID, ['source_curator'])}"}


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    Base.metadata.drop_all(bind=_TEST_ENGINE)
    Base.metadata.create_all(bind=_TEST_ENGINE)
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        database_url=TEST_URL,
        audit_database_url=TEST_URL,
        tracking_base_url="https://training.example.com",
        training_base_url="https://training.example.com/awareness",
        training_domains="training.example.com",
    )
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    test_client = TestClient(app)
    yield test_client
    test_client.close()
    app.state.audit_engine.dispose()
    app.state.session_factory.kw["bind"].dispose()
    _TEST_ENGINE.dispose()


def _seed_library() -> tuple[UUID, UUID, UUID]:
    approved_pattern_id = uuid4()
    draft_pattern_id = uuid4()
    template_id = uuid4()
    with _TEST_SESSIONS() as session:
        session.add_all(
            [
                CampaignPattern(
                    campaign_pattern_id=approved_pattern_id,
                    pattern_version=3,
                    lure_category=dm.LureCategory.CONFERENCE,
                    impersonation_category="Conference organizer",
                    target_role_category="Speakers",
                    emotional_triggers=["urgency"],
                    requested_action="Review the updated session schedule",
                    delivery_method="email",
                    warning_cues=["Unexpected schedule change"],
                    actor_type="Event impersonator",
                    sector_targeting="Conferences",
                    attack_mapping={"difficulty": {"score": 3}, "attack_techniques": ["social engineering"]},
                    confidence=dm.Confidence.HIGH,
                    supporting_evidence=[{"private_source_reference": "must-not-leak"}],
                    prohibited_content_indicators=[],
                    approval_state=dm.PatternApprovalState.APPROVED,
                    approved_by=ADMIN_ID,
                ),
                CampaignPattern(
                    campaign_pattern_id=draft_pattern_id,
                    lure_category=dm.LureCategory.INVOICE,
                    impersonation_category="Vendor",
                    target_role_category="Finance",
                    requested_action="Review an invoice notice",
                    attack_mapping={"difficulty": {"score": 1}},
                    confidence=dm.Confidence.MEDIUM,
                    approval_state=dm.PatternApprovalState.DRAFT,
                ),
                TemplateVersion(
                    template_version_id=template_id,
                    campaign_id=uuid4(),
                    version=7,
                    idempotency_key=f"approved-library-source-{template_id}",
                    generator_version="generator-v1",
                    prompt_template_version="prompt-v2",
                    model_id="model-safe",
                    input_hash="a" * 64,
                    raw_proposal={
                        "subject": "Conference schedule update",
                        "plain_text": "Review the warning cues, {{ recipient.first_name }}.",
                        "safe_html": "<p>Review the warning cues.</p>",
                        "requested_by": str(ADMIN_ID),
                        "private_prompt": "must-not-leak",
                    },
                    subject="Conference schedule update",
                    plain_text="Review the warning cues, {{ recipient.first_name }}.",
                    safe_html="<p>Review the warning cues.</p>",
                    synthetic_sender_display="Conference Team",
                    learning_objectives=["Check unexpected schedule changes"],
                    warning_cues=["Unexpected urgency"],
                    training_explanation="Pause and verify through a trusted channel.",
                    approval_hash="b" * 64,
                    approval_state=dm.TemplateApprovalState.APPROVED,
                    unicode_validation={"passed": True},
                ),
            ]
        )
        session.commit()
    return approved_pattern_id, draft_pattern_id, template_id


@requires_db
def test_library_search_filters_are_bounded_and_do_not_leak_raw_content(client: TestClient) -> None:
    approved_pattern_id, _, template_id = _seed_library()

    patterns = client.get(
        "/api/v1/patterns?q=Conference&approval_state=approved&lure_category=conference&difficulty_score=3",
        headers=AUTHOR_HEADERS,
    )
    assert patterns.status_code == 200, patterns.text
    assert patterns.json() == [
        {
            "campaign_pattern_id": str(approved_pattern_id),
            "lure_category": "conference",
            "approval_state": "approved",
            "difficulty_score": 3,
            "reusable": True,
            "can_clone": True,
            "can_approve": False,
        }
    ]

    templates = client.get("/api/v1/templates?q=model-safe&approval_state=approved", headers=AUTHOR_HEADERS)
    assert templates.status_code == 200, templates.text
    assert templates.json() == [
        {
            "template_version_id": str(template_id),
            "version": 7,
            "subject": "Conference schedule update",
            "model_id": "model-safe",
            "approval_state": "approved",
            "reusable": True,
            "campaign_bound": True,
        }
    ]
    assert "private_prompt" not in templates.text
    assert client.get("/api/v1/templates?limit=201", headers=AUTHOR_HEADERS).status_code == 422
    assert client.get("/api/v1/patterns?difficulty_score=6", headers=AUTHOR_HEADERS).status_code == 422


@requires_db
def test_previews_are_non_executing_and_privacy_minimized(client: TestClient) -> None:
    pattern_id, _, template_id = _seed_library()

    template = client.get(f"/api/v1/templates/{template_id}/preview", headers=AUTHOR_HEADERS)
    assert template.status_code == 200, template.text
    payload = template.json()
    assert payload["subject"] == "Conference schedule update"
    assert "Sample" in payload["plain_text"]
    assert payload["safe_html_present"] is True
    assert payload["html_execution"] is False
    assert "safe_html" not in payload
    assert "private_prompt" not in template.text

    pattern = client.get(f"/api/v1/patterns/{pattern_id}/preview", headers=AUTHOR_HEADERS)
    assert pattern.status_code == 200, pattern.text
    assert pattern.json()["difficulty"] == {"score": 3}
    assert pattern.json()["can_clone"] is True
    assert pattern.json()["can_approve"] is False
    assert "supporting_evidence" not in pattern.json()
    assert "must-not-leak" not in pattern.text


@requires_db
def test_template_clone_resets_approval_binding_and_blocks_self_approval(client: TestClient) -> None:
    _, _, template_id = _seed_library()
    response = client.post(
        f"/api/v1/templates/{template_id}/clone",
        json={"reason": "Adapt for a different educational scenario"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 201, response.text
    clone_id = UUID(response.json()["template_version_id"])
    assert response.json()["requires_human_review"] is True
    with _TEST_SESSIONS() as session:
        clone = session.get(TemplateVersion, clone_id)
        assert clone is not None
        assert clone.approval_state == dm.TemplateApprovalState.DRAFT
        assert clone.campaign_id is None
        assert clone.approval_hash is None
        assert clone.idempotency_key is None
        assert clone.edited_content is None
        assert clone.version == 1
        assert clone.unicode_validation == {}
        assert clone.raw_proposal["requested_by"] == str(ADMIN_ID)
        assert "private_prompt" not in clone.raw_proposal

    decision = client.post(
        f"/api/v1/templates/{clone_id}/decision",
        json={"decision": "approved", "rationale": "Looks safe"},
        headers=ADMIN_HEADERS,
    )
    assert decision.status_code == 403, decision.text


@requires_db
def test_pattern_clone_resets_evidence_and_blocks_self_approval(client: TestClient) -> None:
    pattern_id, _, _ = _seed_library()
    response = client.post(
        f"/api/v1/patterns/{pattern_id}/clone",
        json={"reason": "Adapt the learning scenario"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 201, response.text
    clone_id = UUID(response.json()["campaign_pattern_id"])
    with _TEST_SESSIONS() as session:
        clone = session.get(CampaignPattern, clone_id)
        assert clone is not None
        assert clone.approval_state == dm.PatternApprovalState.DRAFT
        assert clone.approved_by is None
        assert clone.approved_at is None
        assert clone.created_by == ADMIN_ID
        assert clone.pattern_version == 1
        assert clone.supporting_evidence == []
        assert clone.prohibited_content_indicators == []

    approval = client.post(f"/api/v1/patterns/{clone_id}/approve", headers=ADMIN_HEADERS)
    assert approval.status_code == 403, approval.text


@requires_db
def test_pattern_approval_is_single_decision_and_state_bounded(client: TestClient) -> None:
    _, draft_id, _ = _seed_library()
    first = client.post(f"/api/v1/patterns/{draft_id}/approve", headers=ADMIN_HEADERS)
    assert first.status_code == 200, first.text
    assert first.json()["generation_request_recorded"] is True
    assert "generation_queued" not in first.json()
    replay = client.post(f"/api/v1/patterns/{draft_id}/approve", headers=ADMIN_HEADERS)
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"].endswith("pattern is not awaiting approval")

    blocked_id = uuid4()
    with _TEST_SESSIONS() as session:
        session.add(
            CampaignPattern(
                campaign_pattern_id=blocked_id,
                pattern_version=1,
                lure_category=dm.LureCategory.OTHER,
                confidence=dm.Confidence.UNVERIFIED,
                supporting_evidence=[],
                prohibited_content_indicators=["prohibited scenario"],
                approval_state=dm.PatternApprovalState.DRAFT,
                created_by=AUTHOR_ID,
            )
        )
        session.commit()
    blocked = client.post(f"/api/v1/patterns/{blocked_id}/approve", headers=ADMIN_HEADERS)
    assert blocked.status_code == 422, blocked.text
    assert blocked.json()["detail"].startswith("KP-007:")
    preview = client.get(f"/api/v1/patterns/{blocked_id}/preview", headers=ADMIN_HEADERS)
    assert preview.status_code == 200, preview.text
    assert preview.json()["can_approve"] is False
    assert preview.json()["can_clone"] is False


@requires_db
def test_clone_requires_authoring_permission_and_revalidates_content(client: TestClient) -> None:
    pattern_id, _, template_id = _seed_library()
    assert client.post(f"/api/v1/templates/{template_id}/clone", json={"reason": "x"}).status_code == 401
    assert (
        client.post(f"/api/v1/patterns/{pattern_id}/clone", json={"reason": "x"}, headers=CURATOR_HEADERS).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/templates/{template_id}/clone", json={"reason": "   "}, headers=AUTHOR_HEADERS
        ).status_code
        == 422
    )

    with _TEST_SESSIONS() as session:
        unsafe_id = uuid4()
        session.add(
            TemplateVersion(
                template_version_id=unsafe_id,
                version=1,
                generator_version="old",
                prompt_template_version="old",
                model_id="old",
                input_hash="c" * 64,
                raw_proposal={},
                subject="Password verification",
                plain_text="Send us your password.",
                safe_html="",
                approval_state=dm.TemplateApprovalState.APPROVED,
            )
        )
        session.commit()
    rejected = client.post(
        f"/api/v1/templates/{unsafe_id}/clone",
        json={"reason": "Try to reuse legacy content"},
        headers=AUTHOR_HEADERS,
    )
    assert rejected.status_code == 422, rejected.text
