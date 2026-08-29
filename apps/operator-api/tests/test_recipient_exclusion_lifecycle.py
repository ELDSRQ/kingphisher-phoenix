from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import Campaign, CampaignPattern, Recipient, RecipientExclusion, TransactionalOutbox
from kp_database.privacy import hash_mailbox
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from sqlalchemy import func, select

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(TEST_URL)
        with engine.connect():
            pass
        engine.dispose()
        return True
    except Exception:  # noqa: BLE001 - environment capability gate
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")
_TEST_ENGINE = create_db_engine(TEST_URL)
_TEST_SESSIONS = make_session_factory(_TEST_ENGINE)


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    Base.metadata.drop_all(bind=_TEST_ENGINE)
    Base.metadata.create_all(bind=_TEST_ENGINE)
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        recipient_hash_salt=SALT_HEX,
        tracking_token_hmac_key="34" * 32,
        roe_signing_key="11" * 32,
        domain_verification_key="22" * 32,
        allowed_recipient_domains="example.com",
        database_url=TEST_URL,
        audit_database_url=TEST_URL,
    )
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    test_client = TestClient(app)
    yield test_client
    test_client.close()
    app.state.audit_engine.dispose()
    app.state.session_factory.kw["bind"].dispose()
    _TEST_ENGINE.dispose()


def _headers(role: str, *, subject: UUID | None = None) -> dict[str, str]:
    settings = OperatorApiSettings()
    token = jwt.encode(
        {
            "sub": str(subject or uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": [role]},
        },
        CONSOLE_JWT,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_recipient(*, status: dm.RecipientStatus = dm.RecipientStatus.ACTIVE) -> UUID:
    recipient_id = uuid4()
    mailbox = f"learner-{recipient_id}@example.com"
    with _TEST_SESSIONS() as session:
        session.add(
            Recipient(
                recipient_id=recipient_id,
                employee_key=mailbox,
                mailbox=mailbox,
                mailbox_sha256=hash_mailbox(mailbox, bytes.fromhex(SALT_HEX)),
                display_name="Conference Learner",
                department="Security",
                status=status,
                is_test_account=False,
            )
        )
        session.commit()
    return recipient_id


def _seed_campaign() -> UUID:
    campaign_id = uuid4()
    with _TEST_SESSIONS() as session:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.CONFERENCE,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        session.add(
            Campaign(
                campaign_id=campaign_id,
                pattern_id=pattern.campaign_pattern_id,
                title="Exclusion lifecycle",
                state=dm.CampaignState.DRAFT,
                sender_mailbox="security@example.com",
                training_domain="training.example.com",
                max_recipients=10,
                expires_at=datetime.now(UTC) + timedelta(days=2),
            )
        )
        session.commit()
    return campaign_id


@requires_db
def test_active_duplicate_is_idempotent_and_list_is_minimized(client: TestClient) -> None:
    recipient_id = _seed_recipient()
    creator = uuid4()
    path = f"/api/v1/recipients/{recipient_id}/exclusions"
    body = {"exclusion_type": "global", "reason": "documented accommodation"}

    first = client.post(path, json=body, headers=_headers("privacy_approver", subject=creator))
    duplicate = client.post(path, json=body, headers=_headers("privacy_approver", subject=creator))
    listing = client.get(path, headers=_headers("privacy_approver"))

    assert first.status_code == 201, first.text
    assert first.json()["created"] is True
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json() == {
        "recipient_exclusion_id": first.json()["recipient_exclusion_id"],
        "created": False,
    }
    assert listing.status_code == 200, listing.text
    assert len(listing.json()) == 1
    assert listing.json()[0]["active"] is True
    assert listing.json()[0]["created_by"] == str(creator)
    serialized = listing.text.lower()
    assert "mailbox" not in serialized
    assert "employee_key" not in serialized
    with _TEST_SESSIONS() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(RecipientExclusion)
                .where(RecipientExclusion.recipient_id == recipient_id)
            )
            == 1
        )


@requires_db
def test_campaign_scope_expiry_and_recipient_state_are_validated(client: TestClient) -> None:
    recipient_id = _seed_recipient()
    departed_id = _seed_recipient(status=dm.RecipientStatus.DEPARTED)
    campaign_id = _seed_campaign()
    headers = _headers("privacy_approver")
    path = f"/api/v1/recipients/{recipient_id}/exclusions"

    valid = client.post(
        path,
        headers=headers,
        json={
            "exclusion_type": "campaign_specific",
            "campaign_id": str(campaign_id),
            "reason": "campaign conflict",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert valid.status_code == 201, valid.text

    invalid_bodies = [
        {"exclusion_type": "campaign_specific", "reason": "missing campaign"},
        {
            "exclusion_type": "global",
            "campaign_id": str(campaign_id),
            "reason": "scope mismatch",
        },
        {
            "exclusion_type": "campaign_specific",
            "campaign_id": str(uuid4()),
            "reason": "unknown campaign",
        },
        {
            "exclusion_type": "global",
            "reason": "past expiry",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
        {
            "exclusion_type": "global",
            "reason": "naive expiry",
            "expires_at": (datetime.now() + timedelta(days=1)).isoformat(),
        },
    ]
    assert [client.post(path, headers=headers, json=body).status_code for body in invalid_bodies] == [
        422,
        422,
        404,
        422,
        422,
    ]
    departed = client.post(
        f"/api/v1/recipients/{departed_id}/exclusions",
        headers=headers,
        json={"exclusion_type": "global", "reason": "not active"},
    )
    assert departed.status_code == 404


@requires_db
def test_revoke_is_confirmed_idempotent_audited_and_preserves_history(client: TestClient) -> None:
    recipient_id = _seed_recipient()
    creator, revoker, later_actor = uuid4(), uuid4(), uuid4()
    path = f"/api/v1/recipients/{recipient_id}/exclusions"
    created = client.post(
        path,
        headers=_headers("privacy_approver", subject=creator),
        json={"exclusion_type": "accommodation", "reason": "accessibility request"},
    ).json()
    revoke_path = f"{path}/{created['recipient_exclusion_id']}/revoke"

    refused = client.post(
        revoke_path,
        headers=_headers("privacy_approver", subject=revoker),
        json={"confirm": False, "rationale": "reviewed withdrawal"},
    )
    first = client.post(
        revoke_path,
        headers=_headers("privacy_approver", subject=revoker),
        json={"confirm": True, "rationale": "reviewed withdrawal"},
    )
    repeated = client.post(
        revoke_path,
        headers=_headers("privacy_approver", subject=later_actor),
        json={"confirm": True, "rationale": "must not overwrite history"},
    )

    assert refused.status_code == 422
    assert first.status_code == 200 and first.json()["changed"] is True
    assert repeated.status_code == 200 and repeated.json()["changed"] is False
    assert client.get(path, headers=_headers("privacy_approver")).json() == []
    history = client.get(f"{path}?include_inactive=true&limit=10", headers=_headers("privacy_approver"))
    assert history.status_code == 200
    assert history.json()[0]["active"] is False
    assert history.json()[0]["revoked_by"] == str(revoker)
    assert history.json()[0]["revoke_reason"] == "reviewed withdrawal"
    with _TEST_SESSIONS() as session:
        exclusion = session.get(RecipientExclusion, UUID(created["recipient_exclusion_id"]))
        assert exclusion is not None
        assert exclusion.revoked_by == revoker
        assert exclusion.revoke_reason == "reviewed withdrawal"
        audits = list(
            session.scalars(
                select(TransactionalOutbox.payload)
                .where(TransactionalOutbox.kind == "audit")
                .order_by(TransactionalOutbox.created_at.desc())
                .limit(3)
            )
        )
    assert {item["detail"].get("changed") for item in audits} >= {False, True}
    assert "reviewed withdrawal" not in str(audits)


@requires_db
def test_exclusion_routes_require_manage_capability_and_match_recipient(client: TestClient) -> None:
    recipient_id = _seed_recipient()
    other_recipient_id = _seed_recipient()
    path = f"/api/v1/recipients/{recipient_id}/exclusions"
    body = {"exclusion_type": "global", "reason": "security review"}

    assert client.post(path, json=body).status_code == 401
    assert client.post(path, json=body, headers=_headers("auditor")).status_code == 403
    assert client.get(path, headers=_headers("auditor")).status_code == 403
    created = client.post(path, json=body, headers=_headers("privacy_approver")).json()
    wrong_recipient = client.post(
        f"/api/v1/recipients/{other_recipient_id}/exclusions/{created['recipient_exclusion_id']}/revoke",
        headers=_headers("privacy_approver"),
        json={"confirm": True, "rationale": "wrong recipient"},
    )
    assert wrong_recipient.status_code == 404
