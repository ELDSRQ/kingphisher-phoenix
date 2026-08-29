from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignPattern,
    Recipient,
    RecipientAssignment,
    TransactionalOutbox,
)
from kp_database.privacy import hash_mailbox
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from sqlalchemy import select

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"
TRUSTED_ORIGIN = "https://operator.example"
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
        oidc_redirect_uri=f"{TRUSTED_ORIGIN}/api/v1/console/oidc/callback",
    )
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    test_client = TestClient(app)
    yield test_client
    test_client.close()
    app.state.audit_engine.dispose()
    app.state.session_factory.kw["bind"].dispose()
    _TEST_ENGINE.dispose()


def _token(roles: list[str]) -> str:
    settings = OperatorApiSettings()
    return jwt.encode(
        {
            "sub": str(uuid4()),
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


def _seed_recipient(mailbox: str, *, is_test_account: bool = False) -> UUID:
    recipient_id = uuid4()
    with _TEST_SESSIONS() as session:
        session.add(
            Recipient(
                recipient_id=recipient_id,
                employee_key=mailbox,
                mailbox=mailbox,
                mailbox_sha256=hash_mailbox(mailbox, bytes.fromhex(SALT_HEX)),
                display_name="Canary Candidate",
                department="Security",
                is_test_account=is_test_account,
                status=dm.RecipientStatus.ACTIVE,
            )
        )
        session.commit()
    return recipient_id


def _seed_protected_campaign(recipient_id: UUID, *, frozen: bool, assigned: bool) -> UUID:
    pattern_id = uuid4()
    campaign_id = uuid4()
    now = datetime.now(UTC)
    with _TEST_SESSIONS() as session:
        session.add(
            CampaignPattern(
                campaign_pattern_id=pattern_id,
                lure_category=dm.LureCategory.CONFERENCE,
                confidence=dm.Confidence.HIGH,
            )
        )
        session.flush()
        session.add(
            Campaign(
                campaign_id=campaign_id,
                pattern_id=pattern_id,
                title="Canary boundary",
                state=dm.CampaignState.DRAFT,
                sender_mailbox="security@example.com",
                training_domain="training.example.com",
                max_recipients=1,
                expires_at=now + timedelta(days=1),
            )
        )
        session.flush()
        if frozen:
            session.add(
                CampaignAudience(
                    campaign_id=campaign_id,
                    version=1,
                    group_ids=[],
                    departments=[],
                    statuses=[],
                    include_recipient_ids=[str(recipient_id)],
                    exclude_recipient_ids=[],
                    configuration_hash="1" * 64,
                    preview_hash="2" * 64,
                    manifest_hash="3" * 64,
                    frozen_at=now,
                )
            )
            session.flush()
            session.add(
                CampaignAudienceManifest(
                    campaign_id=campaign_id,
                    recipient_id=recipient_id,
                    audience_version=1,
                    ordinal=0,
                    recipient_hash="4" * 64,
                )
            )
        if assigned:
            session.add(
                RecipientAssignment(
                    recipient_assignment_id=uuid4(),
                    campaign_id=campaign_id,
                    recipient_id=recipient_id,
                    send_state=dm.SendState.QUEUED,
                    idempotency_key=f"canary:{campaign_id}:{recipient_id}",
                )
            )
        session.commit()
    return campaign_id


def _recipient_is_test_account(recipient_id: UUID) -> bool:
    with _TEST_SESSIONS() as session:
        recipient = session.get(Recipient, recipient_id)
        assert recipient is not None
        return bool(recipient.is_test_account)


@requires_db
def test_import_defaults_false_and_authorized_list_exposes_designation(client: TestClient) -> None:
    mailbox = "conference+test@example.com"
    response = client.post(
        "/api/v1/recipients/import",
        json={"csv_text": f"{mailbox},Conference Canary,Security"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 201, response.text
    with _TEST_SESSIONS() as session:
        recipient = session.scalar(
            select(Recipient).where(Recipient.mailbox_sha256 == hash_mailbox(mailbox, bytes.fromhex(SALT_HEX)))
        )
        assert recipient is not None
        assert recipient.is_test_account is False
        recipient_id = str(recipient.recipient_id)
    listing = client.get("/api/v1/recipients", headers=ADMIN_HEADERS)
    listed = {item["recipient_id"]: item for item in listing.json()["items"]}
    assert listed[recipient_id]["is_test_account"] is False


@requires_db
def test_explicit_designation_is_audited_and_same_value_is_idempotent(client: TestClient) -> None:
    recipient_id = _seed_recipient(f"canary-{uuid4()}@example.com")
    body = {"is_test_account": True, "confirm": True, "reason": "approved internal canary mailbox"}

    first = client.put(f"/api/v1/recipients/{recipient_id}/test-account", json=body, headers=ADMIN_HEADERS)
    second = client.put(f"/api/v1/recipients/{recipient_id}/test-account", json=body, headers=ADMIN_HEADERS)

    assert first.status_code == 200, first.text
    assert first.json() == {"recipient_id": str(recipient_id), "is_test_account": True, "changed": True}
    assert second.status_code == 200, second.text
    assert second.json()["changed"] is False
    assert _recipient_is_test_account(recipient_id) is True
    with _TEST_SESSIONS() as session:
        payloads = list(
            session.scalars(
                select(TransactionalOutbox.payload)
                .where(TransactionalOutbox.kind == "audit")
                .order_by(TransactionalOutbox.created_at.desc())
                .limit(2)
            )
        )
    assert {payload["detail"]["changed"] for payload in payloads} == {False, True}
    assert all(payload["detail"]["old_is_test_account"] in {False, True} for payload in payloads)
    assert all("@" not in str(payload["detail"]) for payload in payloads)


@requires_db
@pytest.mark.parametrize(("frozen", "assigned"), [(True, False), (False, True)])
def test_designation_change_is_blocked_by_nonterminal_campaign_eligibility(
    client: TestClient,
    frozen: bool,
    assigned: bool,
) -> None:
    recipient_id = _seed_recipient(f"protected-{uuid4()}@example.com")
    _seed_protected_campaign(recipient_id, frozen=frozen, assigned=assigned)

    response = client.put(
        f"/api/v1/recipients/{recipient_id}/test-account",
        json={"is_test_account": True, "confirm": True, "reason": "attempted change"},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409
    assert "frozen or assigned nonterminal campaign" in response.json()["detail"]
    assert _recipient_is_test_account(recipient_id) is False


@requires_db
@pytest.mark.parametrize(
    ("recipient_id", "body", "expected"),
    [
        ("not-a-uuid", {"is_test_account": True, "confirm": True, "reason": "valid"}, 422),
        (str(uuid4()), {"is_test_account": True, "confirm": True, "reason": "valid"}, 404),
        (str(uuid4()), {"is_test_account": True, "confirm": False, "reason": "valid"}, 422),
        (str(uuid4()), {"is_test_account": True, "confirm": True, "reason": " "}, 422),
        (str(uuid4()), {"is_test_account": "true", "confirm": True, "reason": "valid"}, 422),
        (str(uuid4()), {"is_test_account": True, "confirm": True, "reason": "x" * 501}, 422),
    ],
)
def test_designation_validation_and_missing_recipient_are_bounded(
    client: TestClient,
    recipient_id: str,
    body: dict[str, object],
    expected: int,
) -> None:
    response = client.put(
        f"/api/v1/recipients/{recipient_id}/test-account",
        json=body,
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == expected
    assert len(response.content) < 4096


@requires_db
def test_designation_uses_existing_auth_csrf_and_audit_health_boundaries(client: TestClient) -> None:
    recipient_id = _seed_recipient(f"guarded-{uuid4()}@example.com")
    path = f"/api/v1/recipients/{recipient_id}/test-account"
    body = {"is_test_account": True, "confirm": True, "reason": "guard test"}

    assert client.put(path, json=body).status_code == 401
    assert client.put(path, json=body, headers=AUDITOR_HEADERS).status_code == 403

    cookie_token = _token(["administrator"])
    client.cookies.set("kp_oidc_session", cookie_token)
    try:
        csrf = client.put(
            path,
            json=body,
            headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
        )
        assert csrf.status_code == 403
        assert csrf.json()["code"] == "csrf_rejected"
    finally:
        client.cookies.clear()

    application = cast(Any, client.app)
    application.state.audit_verifier.status = "failed"
    try:
        unhealthy = client.put(path, json=body, headers=ADMIN_HEADERS)
        assert unhealthy.status_code == 503
    finally:
        application.state.audit_verifier.status = "ok"
    assert _recipient_is_test_account(recipient_id) is False
