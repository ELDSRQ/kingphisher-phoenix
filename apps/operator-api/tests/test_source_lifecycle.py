from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.models import Source, SourceTerms
from kp_database.outbox import enqueue_audit
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.main import create_app
from kp_telemetry.errors import AuditFailureError
from sqlalchemy import Engine, Table, create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SOURCE_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
TERMS_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


class _Audit:
    def __init__(self) -> None:
        self.fail = False
        self.calls: list[dict[str, Any]] = []
        self.queue_dispatches = 0

    def record(self, *, session: Session, **kwargs: Any) -> None:
        if self.fail:
            raise AuditFailureError()
        self.calls.append(dict(kwargs))
        enqueue_audit(
            session,
            actor=str(kwargs["actor"]),
            action=str(kwargs["action"]),
            object_type=str(kwargs["object_type"]),
            object_id=str(kwargs["object_id"]),
            detail=kwargs.get("detail"),
        )

    def dispatch_pending_queue(self, _queue: object) -> int:
        self.queue_dispatches += 1
        return 0

    def outbox_health(self) -> dict[str, int]:
        return {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
    )


def _headers(settings: OperatorApiSettings, role: str = "source_curator") -> dict[str, str]:
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": [role]},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _create_database() -> Engine:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, Source.__table__).create(engine)
    cast(Table, SourceTerms.__table__).create(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE transactional_outbox ("
            "outbox_id VARCHAR(36) PRIMARY KEY, kind VARCHAR(16) NOT NULL, topic VARCHAR(64), "
            "payload JSON NOT NULL, idempotency_key VARCHAR(128) NOT NULL UNIQUE, "
            "available_at DATETIME NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'pending')"
        )
    return engine


@pytest.fixture
def lifecycle() -> Iterator[tuple[TestClient, OperatorApiSettings, Engine, _Audit]]:
    settings = _settings()
    engine = _create_database()
    audit = _Audit()
    with Session(engine) as session:
        source = Source(
            source_id=SOURCE_ID,
            source_key="source-1",
            name="Threat feed",
            source_type=dm.SourceType.RSS,
            base_domain="feed.example.com",
            fetch_path="/rss.xml",
            enabled=False,
        )
        session.add(source)
        session.flush()
        session.add(
            SourceTerms(
                source_terms_id=TERMS_ID,
                source_id=SOURCE_ID,
                terms_reference="https://feed.example.com/terms",
                terms_hash="a" * 64,
                commercial_use_ok=True,
                automation_ok=True,
                redistribution_ok=True,
                retention_ok=True,
                terms_reviewed_at=datetime.now(UTC) - timedelta(days=1),
                next_review_at=datetime.now(UTC) + timedelta(days=30),
                enabled=True,
            )
        )
        session.flush()
        source.license_state_id = TERMS_ID
        session.commit()

    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    app.state.audit_store = audit

    def session_override() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_audit_store] = lambda: audit
    client = TestClient(app)
    try:
        yield client, settings, engine, audit
    finally:
        client.close()
        engine.dispose()


def _outbox(engine: Engine, kind: str) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text(
                    "SELECT kind, topic, idempotency_key, status FROM transactional_outbox "
                    "WHERE kind = :kind ORDER BY rowid"
                ),
                {"kind": kind},
            ).mappings()
        ]


def _source_enabled(engine: Engine) -> bool:
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        assert source is not None
        return source.enabled


def _source_terms(engine: Engine) -> tuple[Source, SourceTerms]:
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        terms = session.get(SourceTerms, TERMS_ID)
        assert source is not None and terms is not None
        session.expunge(source)
        session.expunge(terms)
        return source, terms


def test_enable_is_idempotent_and_disable_reenable_queues_a_fresh_job(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, audit = lifecycle
    headers = _headers(settings)

    first = client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=headers)
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["changed"] is True
    assert first_body["ingestion_queued"] is True
    first_job = uuid.UUID(first_body["job_id"])

    repeated = client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=headers)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json() == {
        "source_id": str(SOURCE_ID),
        "enabled": True,
        "changed": False,
        "ingestion_queued": False,
        "job_id": None,
    }
    assert [row["idempotency_key"] for row in _outbox(engine, "queue")] == [f"ingest:{SOURCE_ID}:{first_job}"]

    disabled = client.post(f"/api/v1/sources/{SOURCE_ID}/disable", headers=headers)
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["changed"] is True
    repeated_disable = client.post(f"/api/v1/sources/{SOURCE_ID}/disable", headers=headers)
    assert repeated_disable.status_code == 200, repeated_disable.text
    assert repeated_disable.json()["changed"] is False

    reenabled = client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=headers)
    assert reenabled.status_code == 200, reenabled.text
    second_job = uuid.UUID(reenabled.json()["job_id"])
    assert second_job != first_job
    queue_rows = _outbox(engine, "queue")
    assert len(queue_rows) == 2
    assert {row["idempotency_key"] for row in queue_rows} == {
        f"ingest:{SOURCE_ID}:{first_job}",
        f"ingest:{SOURCE_ID}:{second_job}",
    }
    assert all(len(str(row["idempotency_key"])) <= 128 for row in queue_rows)
    assert _source_enabled(engine) is True
    assert audit.queue_dispatches == 2


def test_manual_ingest_can_repeat_and_disabled_source_is_rejected(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, _audit = lifecycle
    headers = _headers(settings)

    disabled = client.post(f"/api/v1/sources/{SOURCE_ID}/ingest", headers=headers)
    assert disabled.status_code == 409
    assert len(disabled.content) < 4096
    assert _outbox(engine, "queue") == []

    assert client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=headers).status_code == 200
    first = client.post(f"/api/v1/sources/{SOURCE_ID}/ingest", headers=headers)
    second = client.post(f"/api/v1/sources/{SOURCE_ID}/ingest", headers=headers)
    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    first_job = uuid.UUID(first.json()["job_id"])
    second_job = uuid.UUID(second.json()["job_id"])
    assert first_job != second_job
    queue_rows = _outbox(engine, "queue")
    assert len(queue_rows) == 3
    assert len({row["idempotency_key"] for row in queue_rows}) == 3
    assert f"ingest:{SOURCE_ID}:{first_job}" in {row["idempotency_key"] for row in queue_rows}
    assert f"ingest:{SOURCE_ID}:{second_job}" in {row["idempotency_key"] for row in queue_rows}


def test_audit_failure_rolls_back_enable_and_queue_intent(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, audit = lifecycle
    audit.fail = True

    response = client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=_headers(settings))

    assert response.status_code == 503
    assert response.json()["code"] == "KP-008"
    assert _source_enabled(engine) is False
    assert _outbox(engine, "queue") == []
    assert _outbox(engine, "audit") == []
    assert audit.queue_dispatches == 0


def test_source_terms_can_be_acknowledged_inspected_and_revoked_without_losing_provenance(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, audit = lifecycle
    headers = _headers(settings)
    future = datetime.now(UTC) + timedelta(days=90)

    recorded = client.post(
        f"/api/v1/sources/{SOURCE_ID}/terms",
        headers=headers,
        json={
            "terms_reference": "  https://feed.example.com/terms/v2  ",
            "terms_hash": "B" * 64,
            "commercial_use_ok": True,
            "automation_ok": True,
            "redistribution_ok": True,
            "retention_ok": True,
            "next_review_at": future.isoformat(),
        },
    )
    assert recorded.status_code == 201, recorded.text
    recorded_body = recorded.json()
    new_terms_id = uuid.UUID(recorded_body["license_state_id"])
    assert new_terms_id != TERMS_ID
    assert recorded_body["governance_ready"] is True
    assert recorded_body["acknowledgement"]["terms_reference"] == "https://feed.example.com/terms/v2"
    assert recorded_body["acknowledgement"]["terms_hash"] == "b" * 64

    inspected = client.get(f"/api/v1/sources/{SOURCE_ID}/terms/current", headers=headers)
    assert inspected.status_code == 200
    assert inspected.json() == recorded_body
    with Session(engine) as session:
        prior = session.get(SourceTerms, TERMS_ID)
        current = session.get(SourceTerms, new_terms_id)
        source = session.get(Source, SOURCE_ID)
        assert prior is not None and prior.enabled is False
        assert current is not None and current.enabled is True
        assert source is not None and source.license_state_id == new_terms_id

    assert client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=headers).status_code == 200
    revoked = client.post(f"/api/v1/sources/{SOURCE_ID}/terms/revoke", headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["governance_ready"] is False
    assert revoked.json()["license_state_id"] == str(new_terms_id)
    assert revoked.json()["acknowledgement"]["enabled"] is False
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        current = session.get(SourceTerms, new_terms_id)
        assert source is not None and source.enabled is False
        assert source.license_state_id == new_terms_id
        assert current is not None and current.enabled is False

    revoke_audit = audit.calls[-1]
    assert revoke_audit["action"] == "source.terms.revoke"
    assert revoke_audit["detail"] == {"terms_changed": True, "source_disabled": True}
    assert "terms_reference" not in str(revoke_audit["detail"])


@pytest.mark.parametrize(
    "override",
    [
        {"terms_reference": "x" * 2049},
        {"terms_reference": "https://feed.example.com/terms\nsecret"},
        {"terms_hash": "not-a-sha256"},
        {"commercial_use_ok": False},
        {"automation_ok": False},
        {"redistribution_ok": False},
        {"retention_ok": False},
        {"next_review_at": datetime.now().isoformat()},
        {"next_review_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
    ],
)
def test_source_terms_acknowledgement_rejects_unusable_attestations(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit], override: dict[str, object]
) -> None:
    client, settings, engine, _audit = lifecycle
    body: dict[str, object] = {
        "terms_reference": "https://feed.example.com/terms/v2",
        "terms_hash": "b" * 64,
        "commercial_use_ok": True,
        "automation_ok": True,
        "redistribution_ok": True,
        "retention_ok": True,
        "next_review_at": (datetime.now(UTC) + timedelta(days=90)).isoformat(),
    }
    body.update(override)

    response = client.post(f"/api/v1/sources/{SOURCE_ID}/terms", headers=_headers(settings), json=body)

    assert response.status_code == 422
    source, terms = _source_terms(engine)
    assert source.license_state_id == TERMS_ID
    assert terms.enabled is True


@pytest.mark.parametrize("failure", ["missing", "wrong_source", "disabled", "expired", "insufficient"])
def test_enable_fails_closed_without_current_complete_source_terms(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit], failure: str
) -> None:
    client, settings, engine, audit = lifecycle
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        terms = session.get(SourceTerms, TERMS_ID)
        assert source is not None and terms is not None
        if failure == "missing":
            source.license_state_id = None
        elif failure == "wrong_source":
            terms.source_id = uuid.uuid4()
        elif failure == "disabled":
            terms.enabled = False
        elif failure == "expired":
            terms.next_review_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            terms.retention_ok = False
        session.commit()

    response = client.post(f"/api/v1/sources/{SOURCE_ID}/enable", headers=_headers(settings))

    assert response.status_code == 409
    assert response.json()["code"] == "KP-005"
    assert response.json()["detail"] == "KP-005: current source terms acknowledgement is required"
    assert _source_enabled(engine) is False
    assert _outbox(engine, "queue") == []
    assert audit.calls[-1]["action"] == "source.governance.blocked"
    assert audit.calls[-1]["detail"] == {"reason": "source_terms_not_current", "source_disabled": False}
    if failure in {"missing", "wrong_source"}:
        inspected = client.get(f"/api/v1/sources/{SOURCE_ID}/terms/current", headers=_headers(settings))
        assert inspected.status_code == 200
        assert inspected.json()["governance_ready"] is False
        assert inspected.json()["acknowledgement"] is None


def test_manual_ingest_disables_an_enabled_source_after_terms_expire(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, audit = lifecycle
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        terms = session.get(SourceTerms, TERMS_ID)
        assert source is not None and terms is not None
        source.enabled = True
        terms.next_review_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    response = client.post(f"/api/v1/sources/{SOURCE_ID}/ingest", headers=_headers(settings))

    assert response.status_code == 409
    assert _source_enabled(engine) is False
    assert _outbox(engine, "queue") == []
    assert audit.calls[-1]["detail"] == {"reason": "source_terms_not_current", "source_disabled": True}


@pytest.mark.parametrize("action", ["enable", "disable", "ingest"])
def test_source_lifecycle_boundaries_and_authorization_are_bounded(
    lifecycle: tuple[TestClient, OperatorApiSettings, Engine, _Audit], action: str
) -> None:
    client, settings, _engine, _audit = lifecycle
    malformed = client.post(f"/api/v1/sources/not-a-uuid/{action}", headers=_headers(settings))
    assert malformed.status_code == 422
    assert len(malformed.content) < 4096

    unauthorized = client.post(f"/api/v1/sources/{SOURCE_ID}/{action}", headers=_headers(settings, "auditor"))
    assert unauthorized.status_code == 403
    assert len(unauthorized.content) < 4096

    missing = client.post(f"/api/v1/sources/{uuid.uuid4()}/{action}", headers=_headers(settings))
    assert missing.status_code == 404
    assert len(missing.content) < 4096
