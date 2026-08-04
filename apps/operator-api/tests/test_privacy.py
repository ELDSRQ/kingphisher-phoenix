"""WS-6 CCPA privacy endpoints against a disposable Postgres.

Require the local dev stack (`docker compose up -d postgres`) and the
`kingphisher_test` database (created by `make db-init`); skipped otherwise.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import (
    CipherText,
    PrivacyNotice,
    Recipient,
    RetentionPolicy,
)
from kp_database.privacy import hash_mailbox
from kp_database.session import create_db_engine, make_session_factory
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="dev Postgres not reachable")


@pytest.fixture(scope="module")
def client() -> TestClient:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    CipherText.configure_key(bytes.fromhex(KEK))

    _seed_default_retention_policy()

    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        recipient_hash_salt=SALT_HEX,
        database_url=TEST_URL,
        audit_database_url=TEST_URL,
        tracking_base_url="http://track.local:8001",
        training_base_url="http://train.local:3000/training/awareness",
        training_domains="example.com,training.local",
    )
    return TestClient(create_app(settings))


def _token(roles: list[str]) -> str:
    import jwt

    settings = OperatorApiSettings()
    claims = {
        "sub": str(uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": roles},
    }
    return jwt.encode(claims, CONSOLE_JWT.encode(), algorithm="HS256")


PRIVACY_HEADERS = {"Authorization": f"Bearer {_token(['privacy_approver'])}"}
ADMIN_HEADERS = {"Authorization": f"Bearer {_token(['administrator'])}"}


def _seed_recipient(mailbox: str) -> str:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        recipient = Recipient(
            recipient_id=uuid4(),
            employee_key=mailbox.lower(),
            mailbox=mailbox,
            mailbox_sha256=hash_mailbox(mailbox, bytes.fromhex(SALT_HEX)),
            display_name="Data Subject",
            department="Engineering",
            is_test_account=False,
        )
        session.add(recipient)
        session.commit()
        return str(recipient.recipient_id)
    finally:
        session.close()


def _seed_default_retention_policy() -> None:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        session.add(
            RetentionPolicy(
                retention_policy_id=uuid4(),
                name="Default",
                data_category="recipient_assignments",
                retention_days=365,
                is_default=True,
                description="Assignments, tokens, and events purged 365 days after delivery.",
            )
        )
        session.commit()
    finally:
        session.close()


def _seed_notice() -> None:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        session.add(
            PrivacyNotice(
                notice_id=uuid4(),
                version=1,
                notice_text="Simulated lures are training. Data retained <= 365 days.",
                effective_at=datetime.now(UTC),
                is_current=True,
            )
        )
        session.commit()
    finally:
        session.close()


@requires_db
def test_privacy_notice_404_when_unpublished(client: TestClient) -> None:
    resp = client.get("/api/v1/privacy/notice", headers=PRIVACY_HEADERS)
    assert resp.status_code == 404


@requires_db
def test_privacy_notice_published(client: TestClient) -> None:
    _seed_notice()
    resp = client.get("/api/v1/privacy/notice", headers=PRIVACY_HEADERS)
    assert resp.status_code == 200
    assert "365" in resp.json()["notice_text"]


@requires_db
def test_privacy_request_lifecycle_and_deletion(client: TestClient) -> None:
    mailbox = "privacy.dsr@example.com"
    recipient_id = _seed_recipient(mailbox)

    submit = client.post(
        "/api/v1/privacy/requests",
        headers=PRIVACY_HEADERS,
        json={"request_type": "deletion", "requester_mailbox": mailbox},
    )
    assert submit.status_code == 201, submit.text
    body = submit.json()
    request_id = body["privacy_request_id"]
    assert body["status"] == "opened"
    assert "sla_deadline" in body

    listing = client.get("/api/v1/privacy/requests", headers=PRIVACY_HEADERS)
    assert listing.status_code == 200
    assert any(r["privacy_request_id"] == request_id and r["requester_mailbox"] == mailbox for r in listing.json())

    verify = client.post(f"/api/v1/privacy/requests/{request_id}/verify", headers=PRIVACY_HEADERS)
    assert verify.status_code == 200, verify.text
    assert verify.json()["status"] == "in_progress"

    export = client.get(f"/api/v1/privacy/requests/{request_id}/export", headers=PRIVACY_HEADERS)
    assert export.status_code == 200, export.text
    assert export.json()["records"][0]["recipient_id"] == recipient_id

    fulfill = client.post(f"/api/v1/privacy/requests/{request_id}/fulfill", headers=PRIVACY_HEADERS, json={})
    assert fulfill.status_code == 200, fulfill.text
    assert fulfill.json()["deleted"] == 1

    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        recipient = session.get(Recipient, __import__("uuid").UUID(recipient_id))
        assert recipient is not None and recipient.deleted_at is not None
    finally:
        session.close()


@requires_db
def test_recipient_delete_endpoint(client: TestClient) -> None:
    mailbox = "privacy.delete@example.com"
    recipient_id = _seed_recipient(mailbox)
    auditor_headers = {"Authorization": f"Bearer {_token(['source_curator'])}"}

    no_perm = client.delete(f"/api/v1/recipients/{recipient_id}", headers=auditor_headers)
    assert no_perm.status_code in (401, 403)

    ok = client.delete(f"/api/v1/recipients/{recipient_id}", headers=ADMIN_HEADERS)
    assert ok.status_code == 200, ok.text

    again = client.delete(f"/api/v1/recipients/{recipient_id}", headers=ADMIN_HEADERS)
    assert again.status_code == 404


@requires_db
def test_default_retention_policy_seeded(client: TestClient) -> None:
    session = make_session_factory(create_db_engine(TEST_URL))()
    try:
        policy = session.scalar(
            __import__("sqlalchemy").select(RetentionPolicy).where(RetentionPolicy.is_default.is_(True)).limit(1)
        )
        assert policy is not None
        assert policy.retention_days == 365
    finally:
        session.close()
