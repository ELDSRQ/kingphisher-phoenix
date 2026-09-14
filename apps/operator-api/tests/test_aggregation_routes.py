"""M3 operator-console aggregation: runs + candidate review/promote/dismiss."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import jwt
import kp_operator_api.console.aggregation_routes as aggregation_module
import pytest
from fastapi.testclient import TestClient
from kp_contracts.aggregation import AggregatedCampaign, AggregateResponse
from kp_contracts.generation import CampaignRecord
from kp_database.aggregation_candidates import get_candidate, insert_candidates, set_review_state
from kp_database.models import AggregationCandidate, CampaignPattern, Source, SourceItem, SourceTerms
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
REJECTED_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")

DISABLED_SOURCE_ID = uuid.UUID("33333333-3333-4333-8333-33333333333d")
DISABLED_TERMS_ID = uuid.UUID("44444444-4444-4444-8444-44444444444c")
DISABLED_ITEM_ID = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


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


def _settings(**overrides: Any) -> OperatorApiSettings:
    base: dict[str, Any] = {
        "audit_hmac_key": HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "database_url": "postgresql+psycopg://unused:unused@localhost:1/unused",
        "audit_database_url": "postgresql+psycopg://unused:unused@localhost:1/unused",
        "oidc_mode": "dev",
    }
    base.update(overrides)
    return OperatorApiSettings(**base)


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
    cast(Table, AggregationCandidate.__table__).create(engine)
    return engine


def _seed_governed(engine: Engine, *, with_rejected: bool = False, with_disabled: bool = False) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session:
        session.add(
            Source(
                source_id=SOURCE_ID,
                source_key="agg-route-test",
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
        )
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
                terms_reviewed_at=now - timedelta(days=1),
                next_review_at=now + timedelta(days=30),
                enabled=True,
            )
        )
        session.add(
            SourceItem(
                source_item_id=ACTIVE_ID,
                source_id=SOURCE_ID,
                publisher="Example Intelligence",
                title="Active campaign advisory",
                published_at=now - timedelta(days=1),
                retrieved_at=now - timedelta(minutes=5),
                sanitized_text="neutralized excerpt for the current campaign",
                content_hash="1" * 64,
                source_reference="https://feed.example.com/advisories/active",
                license_state_id=TERMS_ID,
                confidence=dm.Confidence.HIGH,
                claimed_actor="Example Threat Group",
                claimed_target_sector="Finance",
                extracted_indicators={"ttp": "T1566.002"},
                quarantine_state=dm.QuarantineState.ACTIVE,
            )
        )
        if with_rejected:
            session.add(
                SourceItem(
                    source_item_id=REJECTED_ID,
                    source_id=SOURCE_ID,
                    publisher="Example Intelligence",
                    title="Rejected item",
                    published_at=now - timedelta(days=2),
                    retrieved_at=now - timedelta(minutes=6),
                    sanitized_text="rejected excerpt",
                    content_hash="3" * 64,
                    source_reference="stix--rejected",
                    license_state_id=TERMS_ID,
                    confidence=dm.Confidence.LOW,
                    extracted_indicators={},
                    quarantine_state=dm.QuarantineState.REJECTED,
                    quarantine_reason="not relevant",
                )
            )
        if with_disabled:
            session.add(
                Source(
                    source_id=DISABLED_SOURCE_ID,
                    source_key="agg-route-disabled",
                    name="Disabled Feed",
                    source_type=dm.SourceType.STIX,
                    base_domain="off.example.com",
                    fetch_path="/bundle.json",
                    license_state_id=DISABLED_TERMS_ID,
                    enabled=False,
                    consecutive_failures=0,
                )
            )
            session.add(
                SourceTerms(
                    source_terms_id=DISABLED_TERMS_ID,
                    source_id=DISABLED_SOURCE_ID,
                    terms_reference="https://off.example.com/terms",
                    terms_hash="b" * 64,
                    commercial_use_ok=True,
                    automation_ok=True,
                    redistribution_ok=True,
                    retention_ok=True,
                    terms_reviewed_at=now - timedelta(days=1),
                    next_review_at=now + timedelta(days=30),
                    enabled=True,
                )
            )
            session.add(
                SourceItem(
                    source_item_id=DISABLED_ITEM_ID,
                    source_id=DISABLED_SOURCE_ID,
                    publisher="Disabled Intelligence",
                    title="Item from a disabled source",
                    published_at=now - timedelta(hours=1),
                    retrieved_at=now - timedelta(minutes=1),
                    sanitized_text="excerpt from a disabled source",
                    content_hash="4" * 64,
                    source_reference="stix--disabled",
                    license_state_id=DISABLED_TERMS_ID,
                    confidence=dm.Confidence.HIGH,
                    extracted_indicators={},
                    quarantine_state=dm.QuarantineState.ACTIVE,
                )
            )
        session.commit()


def _app(settings: OperatorApiSettings, engine: Engine, audit: _Audit) -> TestClient:
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    app.state.audit_store = audit
    # The background aggregation task opens its OWN session off app state.
    app.state.session_factory = lambda: Session(engine)

    def session_override() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_audit_store] = lambda: audit
    return TestClient(app)


def _gateway_body(source_item_id: uuid.UUID) -> dict[str, Any]:
    record = CampaignRecord(
        campaign_name="Invoice lure wave",
        claimed_brand="Acme",
        target_sector="Finance",
        target_region="EU",
        lure_theme="unpaid invoice",
        reported_subjects=["Overdue invoice"],
        sender_characteristics="spoofed vendor domain",
        body_characteristics="urgent tone, payment demand",
        call_to_action="open the attached invoice",
        delivery_method="email",
        evidence_excerpt="neutralized excerpt for the current campaign",
        confidence=0.8,
        model_id="onprem/analyst",
    )
    campaign = AggregatedCampaign(
        rank=1,
        score=0.92,
        title="Invoice lure wave",
        as_of=datetime.now(UTC).isoformat(),
        source_item_ids=[str(source_item_id)],
        rationale="recent and finance-targeting",
        record=record,
    )
    return AggregateResponse(model_id="onprem/analyst", candidates=[campaign]).model_dump(mode="json")


class _FakeClient:
    """Sync httpx.Client stand-in returning one valid AggregateResponse body."""

    body: dict[str, Any] = {}
    captured: dict[str, Any] = {}

    def __init__(self, *, timeout: float) -> None:
        assert timeout == 1800.0
        _FakeClient.captured["timeout"] = timeout

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def post(self, url: str, *, json: Any, headers: dict[str, str]) -> httpx.Response:
        _FakeClient.captured["url"] = url
        _FakeClient.captured["json"] = json
        _FakeClient.captured["headers"] = headers
        return httpx.Response(200, request=httpx.Request("POST", url), json=_FakeClient.body)


def test_run_reports_503_when_gateway_url_unset() -> None:
    settings = _settings()
    engine = _database()
    _seed_governed(engine)
    audit = _Audit()
    client = _app(settings, engine, audit)
    response = client.post("/api/v1/console/aggregate/runs", json={}, headers=_headers(settings))
    assert response.status_code == 503, response.text
    engine.dispose()


def test_run_reports_409_when_no_eligible_items() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()  # no items seeded
    audit = _Audit()
    client = _app(settings, engine, audit)
    response = client.post("/api/v1/console/aggregate/runs", json={}, headers=_headers(settings))
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "no eligible ingested items to aggregate"
    engine.dispose()


def test_run_happy_path_persists_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example", ai_gateway_api_key="shared-key")
    engine = _database()
    _seed_governed(engine, with_rejected=True)
    audit = _Audit()
    client = _app(settings, engine, audit)

    _FakeClient.body = _gateway_body(ACTIVE_ID)
    _FakeClient.captured = {}
    monkeypatch.setattr(aggregation_module.httpx, "Client", _FakeClient)

    response = client.post(
        "/api/v1/console/aggregate/runs",
        json={"max_items": 50, "max_candidates": 5},
        headers=_headers(settings),
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "started"
    # The rejected item is excluded by the governed read; only the active item counts.
    assert body["items_considered"] == 1

    # The gateway was reached with the SHARED bearer, not the caller's token.
    assert _FakeClient.captured["url"] == "https://gw.internal.example/aggregate"
    assert _FakeClient.captured["headers"]["Authorization"] == "Bearer shared-key"

    # TestClient runs background tasks before returning, so the candidate is stored.
    listed = client.get("/api/v1/console/aggregate/candidates", headers=_headers(settings))
    assert listed.status_code == 200, listed.text
    candidates = listed.json()["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["title"] == "Invoice lure wave"
    assert candidates[0]["review_state"] == "pending"
    assert candidates[0]["source_item_ids"] == [str(ACTIVE_ID)]
    engine.dispose()


def test_governed_read_excludes_rejected_and_disabled_source_items() -> None:
    engine = _database()
    _seed_governed(engine, with_rejected=True, with_disabled=True)
    with Session(engine) as session:
        items = aggregation_module._load_governed_items(session, as_of=datetime.now(UTC))
    assert [item.item_id for item in items] == [str(ACTIVE_ID)]
    engine.dispose()


def _insert_pending(engine: Engine, source_item_ids: list[str]) -> uuid.UUID:
    with Session(engine) as session:
        (row,) = insert_candidates(
            session,
            run_id=uuid.uuid4(),
            created_at=datetime.now(UTC),
            candidates=[
                {
                    "rank": 1,
                    "score": 0.9,
                    "title": "Invoice lure wave",
                    "as_of": datetime.now(UTC).isoformat(),
                    "rationale": "recent",
                    "model_id": "onprem/analyst",
                    "record": {"campaign_name": "Invoice lure wave"},
                    "source_item_ids": source_item_ids,
                }
            ],
        )
        session.commit()
        return row.aggregation_candidate_id


def test_promote_activates_pattern_and_records_verdict() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()
    _seed_governed(engine)
    candidate_id = _insert_pending(engine, [str(ACTIVE_ID)])
    audit = _Audit()
    client = _app(settings, engine, audit)

    response = client.post(
        f"/api/v1/console/aggregate/candidates/{candidate_id}/promote",
        headers=_headers(settings),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["candidate"]["review_state"] == "promoted"
    assert body["campaign_pattern_id"] == body["candidate"]["promoted_pattern_id"]

    with Session(engine) as session:
        stored = get_candidate(session, candidate_id)
        assert stored is not None
        assert stored.review_state == dm.AggregationReviewState.PROMOTED
        assert session.scalar(select(func.count()).select_from(CampaignPattern)) == 1
        activated = session.get(SourceItem, ACTIVE_ID)
        assert activated is not None
        assert activated.quarantine_state == dm.QuarantineState.ACTIVE
    assert audit.calls[-1]["action"] == "aggregation.candidate.promote"
    engine.dispose()


def test_promote_with_no_resolvable_item_returns_422() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()
    _seed_governed(engine)
    # A syntactically-valid but absent id and an unparseable id both fail to resolve.
    candidate_id = _insert_pending(engine, ["not-a-uuid", str(uuid.uuid4())])
    audit = _Audit()
    client = _app(settings, engine, audit)

    response = client.post(
        f"/api/v1/console/aggregate/candidates/{candidate_id}/promote",
        headers=_headers(settings),
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "candidate has no resolvable supporting source item"
    engine.dispose()


def test_promote_or_dismiss_already_decided_returns_409() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()
    _seed_governed(engine)
    candidate_id = _insert_pending(engine, [str(ACTIVE_ID)])
    with Session(engine) as session:
        set_review_state(
            session,
            candidate_id,
            dm.AggregationReviewState.DISMISSED,
            reviewed_at=datetime.now(UTC),
            reviewed_by="op",
        )
        session.commit()
    audit = _Audit()
    client = _app(settings, engine, audit)

    promote = client.post(
        f"/api/v1/console/aggregate/candidates/{candidate_id}/promote",
        headers=_headers(settings),
    )
    assert promote.status_code == 409, promote.text
    dismiss = client.post(
        f"/api/v1/console/aggregate/candidates/{candidate_id}/dismiss",
        headers=_headers(settings),
    )
    assert dismiss.status_code == 409, dismiss.text
    # A missing candidate is a 404.
    missing = client.post(
        f"/api/v1/console/aggregate/candidates/{uuid.uuid4()}/dismiss",
        headers=_headers(settings),
    )
    assert missing.status_code == 404, missing.text
    engine.dispose()


def test_dismiss_marks_candidate_dismissed() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()
    _seed_governed(engine)
    candidate_id = _insert_pending(engine, [str(ACTIVE_ID)])
    audit = _Audit()
    client = _app(settings, engine, audit)

    response = client.post(
        f"/api/v1/console/aggregate/candidates/{candidate_id}/dismiss",
        headers=_headers(settings),
    )
    assert response.status_code == 200, response.text
    assert response.json()["candidate"]["review_state"] == "dismissed"
    with Session(engine) as session:
        stored = get_candidate(session, candidate_id)
        assert stored is not None
        assert stored.review_state == dm.AggregationReviewState.DISMISSED
    assert audit.calls[-1]["action"] == "aggregation.candidate.dismiss"
    engine.dispose()


def test_all_endpoints_require_manage_sources() -> None:
    settings = _settings(ai_gateway_url="https://gw.internal.example")
    engine = _database()
    _seed_governed(engine)
    candidate_id = _insert_pending(engine, [str(ACTIVE_ID)])
    audit = _Audit()
    client = _app(settings, engine, audit)
    weak = _headers(settings, "campaign_author")

    assert client.post("/api/v1/console/aggregate/runs", json={}, headers=weak).status_code == 403
    assert client.get("/api/v1/console/aggregate/candidates", headers=weak).status_code == 403
    assert client.post(f"/api/v1/console/aggregate/candidates/{candidate_id}/promote", headers=weak).status_code == 403
    assert client.post(f"/api/v1/console/aggregate/candidates/{candidate_id}/dismiss", headers=weak).status_code == 403
    # And unauthenticated is rejected before any capability check.
    assert client.get("/api/v1/console/aggregate/candidates").status_code == 401
    engine.dispose()
