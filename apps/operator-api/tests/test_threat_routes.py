from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_database.models import CampaignPattern, Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.main import create_app
from sqlalchemy import Engine, Table, create_engine, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SOURCE_ID = uuid.UUID("11111111-1111-4111-8111-11111111111f")
TERMS_ID = uuid.UUID("22222222-2222-4222-8222-22222222222e")
ACTIVE_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
QUARANTINED_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
REJECTED_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    return "JSON"


class _Audit:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def record(self, *, session: Session, **kwargs: Any) -> None:
        del session
        self.calls.append(dict(kwargs))

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


def _database() -> Engine:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, Source.__table__).create(engine)
    cast(Table, SourceTerms.__table__).create(engine)
    cast(Table, SourceItem.__table__).create(engine)
    cast(Table, CampaignPattern.__table__).create(engine)
    return engine


def _seed(engine: Engine) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session:
        source = Source(
            source_id=SOURCE_ID,
            source_key="threat-route-test",
            name="Threat Intelligence Feed",
            source_type=dm.SourceType.STIX,
            base_domain="feed.example.com",
            fetch_path="/bundle.json",
            license_state_id=TERMS_ID,
            enabled=True,
            last_success_at=now - timedelta(hours=1),
            last_attempt_at=now - timedelta(hours=1),
            consecutive_failures=0,
        )
        terms = SourceTerms(
            source_terms_id=TERMS_ID,
            source_id=SOURCE_ID,
            terms_reference="https://feed.example.com/terms",
            terms_hash="a" * 64,
            commercial_use_ok=True,
            automation_ok=True,
            redistribution_ok=True,
            retention_ok=True,
            terms_reviewed_at=now - timedelta(days=1),
            next_review_at=now + timedelta(days=30),
            enabled=True,
        )
        indicators = {f"indicator-{index:02d}": "x" * 1_000 for index in range(30)}
        indicators["ttp"] = "T1566.002"
        session.add_all(
            [
                source,
                terms,
                SourceItem(
                    source_item_id=ACTIVE_ID,
                    source_id=SOURCE_ID,
                    publisher="Example Intelligence",
                    title="A" * 1_000,
                    published_at=now - timedelta(days=1),
                    retrieved_at=now - timedelta(minutes=5),
                    sanitized_text="untrusted source excerpt " * 100,
                    content_hash="1" * 64,
                    source_reference="https://feed.example.com/advisories/active",
                    license_state_id=TERMS_ID,
                    confidence=dm.Confidence.HIGH,
                    claimed_actor="Example Threat Group",
                    claimed_target_sector="Energy",
                    extracted_indicators=indicators,
                    quarantine_state=dm.QuarantineState.ACTIVE,
                ),
                SourceItem(
                    source_item_id=QUARANTINED_ID,
                    source_id=SOURCE_ID,
                    publisher="Example Intelligence",
                    title="Aging item",
                    published_at=now - timedelta(days=30),
                    retrieved_at=now - timedelta(minutes=10),
                    sanitized_text="Aging source excerpt",
                    content_hash="2" * 64,
                    source_reference="stix--aging",
                    license_state_id=TERMS_ID,
                    confidence=dm.Confidence.MEDIUM,
                    extracted_indicators={"stix_type": "indicator"},
                    quarantine_state=dm.QuarantineState.QUARANTINED,
                    quarantine_reason="insufficient corroboration",
                ),
                SourceItem(
                    source_item_id=REJECTED_ID,
                    source_id=SOURCE_ID,
                    publisher="Example Intelligence",
                    title="Stale item",
                    published_at=now - timedelta(days=120),
                    retrieved_at=now - timedelta(minutes=15),
                    sanitized_text="Stale source excerpt",
                    content_hash="3" * 64,
                    source_reference="stix--stale",
                    license_state_id=TERMS_ID,
                    confidence=dm.Confidence.LOW,
                    extracted_indicators={},
                    quarantine_state=dm.QuarantineState.REJECTED,
                    quarantine_reason="not relevant",
                ),
            ]
        )
        session.commit()


@pytest.fixture
def threats() -> Iterator[tuple[TestClient, OperatorApiSettings, Engine, _Audit]]:
    settings = _settings()
    engine = _database()
    _seed(engine)
    audit = _Audit()
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


def test_threat_queue_requires_source_management_authority_and_bounds_pagination(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, _engine, _audit = threats

    assert client.get("/api/v1/threats").status_code == 401
    assert client.get("/api/v1/threats", headers=_headers(settings, "campaign_author")).status_code == 403
    assert client.get("/api/v1/threats?limit=101", headers=_headers(settings)).status_code == 422
    assert client.get("/api/v1/threats?offset=10001", headers=_headers(settings)).status_code == 422

    first = client.get("/api/v1/threats?limit=1", headers=_headers(settings))
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 3
    assert first.json()["limit"] == 1
    assert first.json()["offset"] == 0
    assert first.json()["truncated"] is True
    assert first.json()["items"][0]["source_item_id"] == str(ACTIVE_ID)

    second = client.get("/api/v1/threats?limit=1&offset=1", headers=_headers(settings))
    assert second.status_code == 200, second.text
    assert second.json()["items"][0]["source_item_id"] == str(QUARANTINED_ID)


def test_threat_queue_emits_only_bounded_untrusted_evidence_and_source_health(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, _engine, _audit = threats

    response = client.get("/api/v1/threats?review_state=active", headers=_headers(settings))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert len(item["title"]) == 255
    assert len(item["excerpt"]) == 500
    assert item["excerpt_is_untrusted"] is True
    assert item["citation"] == "https://feed.example.com/advisories/active"
    assert item["claimed_actor"] == "Example Threat Group"
    assert item["claimed_target_sector"] == "Energy"
    assert item["confidence"] == "high"
    assert item["freshness"]["bucket"] == "fresh"
    assert len(item["ttp_indicator_summary"]) == 20
    assert item["ttp_indicator_summary"][0] == {"name": "ttp", "value": "T1566.002"}
    assert all(len(entry["value"]) <= 256 for entry in item["ttp_indicator_summary"])
    assert item["source_health"] == {
        "source_id": str(SOURCE_ID),
        "name": "Threat Intelligence Feed",
        "enabled": True,
        "governance_ready": True,
        "state": "healthy",
        "last_success_at": item["source_health"]["last_success_at"],
        "last_attempt_at": item["source_health"]["last_attempt_at"],
        "consecutive_failures": 0,
    }
    assert "sanitized_text" not in item
    assert "extracted_indicators" not in item


@pytest.mark.parametrize(
    ("query", "expected_id"),
    [
        ("review_state=quarantined", QUARANTINED_ID),
        ("quarantine_state=rejected", REJECTED_ID),
        ("confidence=medium", QUARANTINED_ID),
        ("freshness=aging", QUARANTINED_ID),
        ("freshness=stale", REJECTED_ID),
        (f"source_id={SOURCE_ID}&confidence=low", REJECTED_ID),
    ],
)
def test_threat_queue_filters_are_composable_and_deterministic(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
    query: str,
    expected_id: uuid.UUID,
) -> None:
    client, settings, _engine, _audit = threats

    response = client.get(f"/api/v1/threats?{query}", headers=_headers(settings))

    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["source_item_id"] == str(expected_id)


def test_activate_reject_and_merge_duplicate_are_audited_and_idempotent(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, audit = threats
    headers = _headers(settings)

    rejected = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/reject",
        headers=headers,
        json={"rationale": "insufficient evidence for this program"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["review_state"] == "rejected"
    assert rejected.json()["changed"] is True
    repeated = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/reject",
        headers=headers,
        json={"rationale": "insufficient evidence for this program"},
    )
    assert repeated.status_code == 200
    assert repeated.json()["changed"] is False

    activated = client.post(f"/api/v1/threats/{ACTIVE_ID}/activate", headers=headers)
    assert activated.status_code == 200, activated.text
    assert activated.json()["review_state"] == "active"
    repeated_activation = client.post(f"/api/v1/threats/{ACTIVE_ID}/activate", headers=headers)
    assert repeated_activation.status_code == 200
    assert repeated_activation.json()["changed"] is False

    merged = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(QUARANTINED_ID)},
    )
    assert merged.status_code == 200, merged.text
    assert merged.json()["review_state"] == "duplicate"
    assert merged.json()["duplicate_of"] == str(QUARANTINED_ID)
    assert audit.calls[-1]["detail"] == {"changed": True, "duplicate_of": str(QUARANTINED_ID)}

    with Session(engine) as session:
        item = session.get(SourceItem, ACTIVE_ID)
        assert item is not None
        assert item.quarantine_state == dm.QuarantineState.REJECTED
        assert item.quarantine_reason == "duplicate"
        assert item.duplicate_of == QUARANTINED_ID
        patterns = list(session.scalars(select(CampaignPattern)))
        assert len(patterns) == 1
        assert patterns[0].attack_mapping["source_item_id"] == str(ACTIVE_ID)
        assert patterns[0].approval_state == dm.PatternApprovalState.REJECTED
    assert [call["action"] for call in audit.calls] == [
        "threat.reject",
        "threat.reject.noop",
        "threat.activate",
        "threat.activate.noop",
        "threat.merge_duplicate",
    ]


def test_actions_reject_pii_missing_targets_self_merge_and_duplicate_cycles(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, _engine, audit = threats
    headers = _headers(settings)

    pii = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/reject",
        headers=headers,
        json={"rationale": "reported by person@example.com"},
    )
    assert pii.status_code == 422
    assert "person@example.com" not in pii.text
    assert audit.calls == []

    missing = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(uuid.uuid4())},
    )
    assert missing.status_code == 404
    self_merge = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(ACTIVE_ID)},
    )
    assert self_merge.status_code == 409
    first = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(QUARANTINED_ID)},
    )
    assert first.status_code == 200
    cycle = client.post(
        f"/api/v1/threats/{QUARANTINED_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(ACTIVE_ID)},
    )
    assert cycle.status_code == 409
    assert cycle.json()["detail"] == "KP-005: duplicate relationship would create a cycle"


def test_activate_reject_and_merge_cover_legacy_random_id_linked_patterns(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, engine, _audit = threats
    legacy_pattern_id = uuid.uuid4()
    with Session(engine) as session:
        session.add(
            CampaignPattern(
                campaign_pattern_id=legacy_pattern_id,
                lure_category=dm.LureCategory.CREDENTIAL_REFERENCE,
                confidence=dm.Confidence.MEDIUM,
                attack_mapping={"source_item_id": str(QUARANTINED_ID)},
                supporting_evidence=[{"source_item_id": str(QUARANTINED_ID)}],
                approval_state=dm.PatternApprovalState.DRAFT,
            )
        )
        session.commit()

    headers = _headers(settings)
    activated = client.post(f"/api/v1/threats/{QUARANTINED_ID}/activate", headers=headers)
    assert activated.status_code == 200, activated.text
    rejected = client.post(
        f"/api/v1/threats/{QUARANTINED_ID}/reject",
        headers=headers,
        json={"rationale": "not suitable for this program"},
    )
    assert rejected.status_code == 200, rejected.text
    reactivated = client.post(f"/api/v1/threats/{QUARANTINED_ID}/activate", headers=headers)
    assert reactivated.status_code == 200, reactivated.text
    with Session(engine) as session:
        preserved = session.get(CampaignPattern, legacy_pattern_id)
        assert preserved is not None
        assert preserved.approval_state == dm.PatternApprovalState.REJECTED
    merged = client.post(
        f"/api/v1/threats/{QUARANTINED_ID}/merge-duplicate",
        headers=headers,
        json={"duplicate_of": str(ACTIVE_ID)},
    )
    assert merged.status_code == 200, merged.text

    with Session(engine) as session:
        patterns = list(session.scalars(select(CampaignPattern)))
        assert [pattern.campaign_pattern_id for pattern in patterns] == [legacy_pattern_id]
        assert patterns[0].approval_state == dm.PatternApprovalState.REJECTED


@pytest.mark.parametrize("governance_failure", ["disabled", "revoked", "expired"])
def test_activation_requires_current_locked_source_governance(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
    governance_failure: str,
) -> None:
    client, settings, engine, audit = threats
    with Session(engine) as session:
        source = session.get(Source, SOURCE_ID)
        terms = session.get(SourceTerms, TERMS_ID)
        assert source is not None and terms is not None
        if governance_failure == "disabled":
            source.enabled = False
        elif governance_failure == "revoked":
            terms.enabled = False
        else:
            terms.next_review_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    response = client.post(
        f"/api/v1/threats/{QUARANTINED_ID}/activate",
        headers=_headers(settings),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "KP-005: threat source governance is not current"
    assert audit.calls == []
    with Session(engine) as session:
        item = session.get(SourceItem, QUARANTINED_ID)
        assert item is not None
        assert item.quarantine_state == dm.QuarantineState.QUARANTINED
        assert session.scalar(select(func.count()).select_from(CampaignPattern)) == 0


def test_unknown_threat_action_and_extra_body_fields_fail_closed(
    threats: tuple[TestClient, OperatorApiSettings, Engine, _Audit],
) -> None:
    client, settings, _engine, _audit = threats
    headers = _headers(settings)

    assert client.post(f"/api/v1/threats/{uuid.uuid4()}/activate", headers=headers).status_code == 404
    extra = client.post(
        f"/api/v1/threats/{ACTIVE_ID}/reject",
        headers=headers,
        json={"rationale": "not relevant", "approval_state": "approved"},
    )
    assert extra.status_code == 422

    # Curation never creates, approves, or launches campaign material.
    with Session(_engine) as session:
        assert session.scalar(select(func.count()).select_from(SourceItem)) == 3
