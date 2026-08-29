"""WS-6 CCPA privacy endpoints against a disposable Postgres.

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from kp_database.base import Base
from kp_database.models import (
    CipherText,
    Microsoft365IntegrationState,
    PrivacyNotice,
    Recipient,
    RetentionPolicy,
)
from kp_database.privacy import hash_mailbox
from kp_database.session import create_db_engine, make_session_factory
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.postgres


KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
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


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
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
    application = create_app(settings)
    application.state.audit_verifier.status = "ok"
    test_client = TestClient(application)
    yield test_client
    test_client.close()
    application.state.audit_engine.dispose()
    application.state.session_factory.kw["bind"].dispose()


def _session():
    engine = create_engine(
        TEST_URL,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )
    return make_session_factory(engine)()


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


def _seed_recipient(mailbox: str, *, directory_owned: bool = False) -> str:
    session = _session()
    try:
        recipient = Recipient(
            recipient_id=uuid4(),
            employee_key=mailbox.lower(),
            mailbox=mailbox,
            mailbox_sha256=hash_mailbox(mailbox, bytes.fromhex(SALT_HEX)),
            display_name="Data Subject",
            department="Engineering",
            is_test_account=False,
            directory_source="m365:privacy-test" if directory_owned else None,
            directory_object_id_hash=("a" * 64) if directory_owned else None,
            directory_generation=7 if directory_owned else None,
            directory_owned=directory_owned,
        )
        session.add(recipient)
        if directory_owned:
            now = datetime.now(UTC)
            session.add(
                Microsoft365IntegrationState(
                    integration_state_id=uuid4(),
                    kind="directory",
                    provider="microsoft365",
                    scope_hash="1" * 64,
                    config_fingerprint="2" * 64,
                    status="preview_ready",
                    pending_preview_id=uuid4(),
                    pending_preview_hash="3" * 64,
                    pending_payload=f'{{"mailbox":"{mailbox}","entra_id":"privacy-object"}}',
                    pending_created_at=now,
                    pending_expires_at=now + timedelta(minutes=15),
                    last_counts={},
                )
            )
        session.commit()
        return str(recipient.recipient_id)
    finally:
        session.close()


def _seed_default_retention_policy() -> None:
    session = _session()
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
    session = _session()
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
def test_privacy_request_listing_is_bounded_and_pageable(client: TestClient) -> None:
    for index in range(3):
        response = client.post(
            "/api/v1/privacy/requests",
            headers=PRIVACY_HEADERS,
            json={"request_type": "access_export", "requester_mailbox": f"page-{index}@example.com"},
        )
        assert response.status_code == 201, response.text

    first = client.get("/api/v1/privacy/requests?limit=1&offset=0", headers=PRIVACY_HEADERS)
    second = client.get("/api/v1/privacy/requests?limit=1&offset=1", headers=PRIVACY_HEADERS)
    assert first.status_code == second.status_code == 200
    for response in (first, second):
        assert response.headers["cache-control"] == "private, no-store, max-age=0"
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["expires"] == "0"
    assert len(first.json()) == len(second.json()) == 1
    assert first.json()[0]["privacy_request_id"] != second.json()[0]["privacy_request_id"]
    assert client.get("/api/v1/privacy/requests?limit=501", headers=PRIVACY_HEADERS).status_code == 422
    assert client.get("/api/v1/privacy/requests?offset=-1", headers=PRIVACY_HEADERS).status_code == 422


@requires_db
def test_privacy_request_lifecycle_and_deletion(client: TestClient) -> None:
    mailbox = "privacy.dsr@example.com"
    recipient_id = _seed_recipient(mailbox, directory_owned=True)

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

    verify = client.post(
        f"/api/v1/privacy/requests/{request_id}/verify",
        headers=PRIVACY_HEADERS,
        json={"method": "authenticated_hr_record", "evidence_ref": "case-123"},
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["status"] == "verified"

    old_export = client.get(f"/api/v1/privacy/requests/{request_id}/export", headers=PRIVACY_HEADERS)
    assert old_export.status_code == 405
    export = client.post(f"/api/v1/privacy/requests/{request_id}/export", headers=PRIVACY_HEADERS)
    assert export.status_code == 200, export.text
    assert export.headers["cache-control"] == "private, no-store, max-age=0"
    assert export.headers["pragma"] == "no-cache"
    assert export.headers["expires"] == "0"
    assert export.json()["records"][0]["recipient_id"] == recipient_id

    fulfill = client.post(f"/api/v1/privacy/requests/{request_id}/fulfill", headers=PRIVACY_HEADERS, json={})
    assert fulfill.status_code == 200, fulfill.text
    assert fulfill.json()["deleted"] == 1

    session = _session()
    try:
        recipient = session.get(Recipient, __import__("uuid").UUID(recipient_id))
        assert recipient is not None and recipient.deleted_at is not None
        assert recipient.display_name is None
        assert recipient.department is None
        assert recipient.mailbox.startswith("erased-")
        assert recipient.directory_source is None
        assert recipient.directory_object_id_hash is None
        assert recipient.directory_generation is None
        assert recipient.directory_owned is False

        raw = session.execute(
            __import__("sqlalchemy").text(
                "SELECT employee_key, mailbox, display_name, department, directory_source, "
                "directory_object_id_hash, directory_generation, directory_owned "
                "FROM recipients WHERE recipient_id = :recipient_id"
            ),
            {"recipient_id": recipient_id},
        ).one()
        raw_values = "|".join("" if value is None else str(value) for value in raw)
        assert mailbox not in raw_values
        assert "privacy-test" not in raw_values
        assert "a" * 64 not in raw_values
        assert raw[4:] == (None, None, None, False)
        integration = session.scalar(
            __import__("sqlalchemy")
            .select(Microsoft365IntegrationState)
            .where(Microsoft365IntegrationState.kind == "directory")
        )
        assert integration is not None
        assert integration.status == "discarded"
        assert integration.pending_payload is None
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
    session = _session()
    try:
        policy = session.scalar(
            __import__("sqlalchemy").select(RetentionPolicy).where(RetentionPolicy.is_default.is_(True)).limit(1)
        )
        assert policy is not None
        assert policy.retention_days == 365
    finally:
        session.close()


@requires_db
def test_unverified_request_cannot_export_or_fulfill(client: TestClient) -> None:
    mailbox = "privacy.unverified@example.com"
    _seed_recipient(mailbox)
    submitted = client.post(
        "/api/v1/privacy/requests",
        headers=PRIVACY_HEADERS,
        json={"request_type": "access_export", "requester_mailbox": mailbox},
    )
    request_id = submitted.json()["privacy_request_id"]

    export = client.post(f"/api/v1/privacy/requests/{request_id}/export", headers=PRIVACY_HEADERS)
    fulfill = client.post(f"/api/v1/privacy/requests/{request_id}/fulfill", headers=PRIVACY_HEADERS, json={})
    assert export.status_code == 409
    assert fulfill.status_code == 409


@requires_db
def test_correction_updates_supported_fields(client: TestClient) -> None:
    mailbox = "privacy.correct@example.com"
    recipient_id = _seed_recipient(mailbox)
    submitted = client.post(
        "/api/v1/privacy/requests",
        headers=PRIVACY_HEADERS,
        json={"request_type": "correction", "requester_mailbox": mailbox},
    )
    request_id = submitted.json()["privacy_request_id"]
    verified = client.post(
        f"/api/v1/privacy/requests/{request_id}/verify",
        headers=PRIVACY_HEADERS,
        json={"method": "authenticated_hr_record", "evidence_ref": "case-456"},
    )
    assert verified.status_code == 200
    fulfilled = client.post(
        f"/api/v1/privacy/requests/{request_id}/fulfill",
        headers=PRIVACY_HEADERS,
        json={"corrections": {"display_name": "Correct Name", "department": "Legal"}},
    )
    assert fulfilled.status_code == 200, fulfilled.text
    assert fulfilled.json()["corrected"] == 1

    session = _session()
    try:
        recipient = session.get(Recipient, __import__("uuid").UUID(recipient_id))
        assert recipient is not None
        assert recipient.display_name == "Correct Name"
        assert recipient.department == "Legal"
    finally:
        session.close()
