"""Governed current-threat library + reviewer workbench routes (W3-02)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from kp_curation.threat_bundle import sign_bundle
from kp_database.models import SourcePolicy, ThreatArtifact, ThreatBundleImport
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.main import create_app
from sqlalchemy import Engine, Table, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
POLICY_ID = uuid.UUID("11111111-1111-4111-8111-1111111111aa")
DISABLED_POLICY_ID = uuid.UUID("11111111-1111-4111-8111-1111111111bb")
ARTIFACT_ID = uuid.UUID("22222222-2222-4222-8222-2222222222aa")

_BUNDLE_SEED = bytes(range(1, 33))


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    return "JSON"


def _verify_key_hex() -> str:
    public = Ed25519PrivateKey.from_private_bytes(_BUNDLE_SEED).public_key()
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


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
        threat_bundle_verify_key=_verify_key_hex(),
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
    cast(Table, SourcePolicy.__table__).create(engine)
    cast(Table, ThreatArtifact.__table__).create(engine)
    cast(Table, ThreatBundleImport.__table__).create(engine)
    return engine


def _seed(engine: Engine) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session:
        session.add_all(
            [
                SourcePolicy(
                    source_policy_id=POLICY_ID,
                    source_key="curated-offline",
                    owner="threat-intel-team",
                    license="CC-BY-4.0",
                    parser="curated/1",
                    trust=dm.SourceTrust.CURATED,
                    freshness=30,
                    enabled=True,
                    last_success_at=now - timedelta(hours=1),
                    consecutive_failures=0,
                ),
                SourcePolicy(
                    source_policy_id=DISABLED_POLICY_ID,
                    source_key="disabled-feed",
                    owner="threat-intel-team",
                    license="proprietary",
                    parser="rss/1",
                    trust=dm.SourceTrust.UNTRUSTED,
                    freshness=7,
                    enabled=False,
                    last_success_at=now - timedelta(days=100),
                    consecutive_failures=5,
                ),
                ThreatArtifact(
                    threat_artifact_id=ARTIFACT_ID,
                    source_policy_id=POLICY_ID,
                    content_hash="a" * 64,
                    title="URGENT: verify your Microsoft 365 account",
                    origin=dm.ArtifactOrigin.MAILBOX,
                    quarantine_state=dm.QuarantineState.QUARANTINED,
                    original_sha256="b" * 64,
                    original_bytes=512,
                    safe_preview_html="<p>Dear user, verify your account.</p>",
                    safe_preview_text="Dear user, verify your account.",
                    cue_manifest={
                        "ontology_version": "cue-ontology/1",
                        "cues": [{"cue_type": "urgency"}, {"cue_type": "credential_request"}],
                        "transformations": [],
                    },
                    provenance={
                        "hash": "a" * 64,
                        "observed_at": now.isoformat(),
                        "source": "curated-offline",
                        "parser_version": "threat-safe-preview/1",
                        "reviewer": None,
                    },
                    review_state=dm.ArtifactReviewState.PENDING,
                    first_seen_at=now - timedelta(minutes=5),
                ),
            ]
        )
        session.commit()


@pytest.fixture
def library() -> Iterator[tuple[TestClient, OperatorApiSettings, Engine, _Audit]]:
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


def _signed_bundle(bundle_id: str = "bundle-xyz") -> dict[str, Any]:
    return sign_bundle(
        bundle_id=bundle_id,
        artifacts=[
            {
                "title": "Payroll update required",
                "origin": "bundle",
                "raw_html": '<p>Update your <a href="https://evil.example/go">bank details</a> now.</p>',
                "parser": "curated/1",
                "parser_version": "curated/1",
                "source": "curated-offline",
                "observed_at": "2026-10-20T00:00:00+00:00",
            }
        ],
        signing_key=_BUNDLE_SEED,
        created_at="2026-10-20T00:00:00+00:00",
    )


def test_list_returns_safe_summary_and_cue_labels(library: Any) -> None:
    client, settings, _engine, _audit = library
    response = client.get("/api/v1/threat-library/artifacts", headers=_headers(settings))
    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 1
    item = page["items"][0]
    assert item["quarantine_state"] == "quarantined"
    assert item["approvable"] is False and item["deliverable"] is False
    assert set(item["cue_labels"]) == {"urgency", "credential_request"}
    # The list view never leaks the safe preview body or any original.
    assert "safe_preview_html" not in item


def test_detail_returns_safe_preview_and_manifest_never_original(library: Any) -> None:
    client, settings, _engine, _audit = library
    response = client.get(f"/api/v1/threat-library/artifacts/{ARTIFACT_ID}", headers=_headers(settings))
    assert response.status_code == 200
    body = response.json()
    assert body["safe_preview_html"].startswith("<p>")
    assert body["cue_manifest"]["ontology_version"] == "cue-ontology/1"
    # Only the digest/size of the original are present — no raw field.
    assert body["original_sha256"] == "b" * 64 and body["original_bytes"] == 512
    assert "original_html" not in body and "raw_html" not in body
    assert body["approvable"] is False and body["deliverable"] is False


def test_review_records_reviewer_and_keeps_quarantine(library: Any) -> None:
    client, settings, engine, audit = library
    response = client.post(
        f"/api/v1/threat-library/artifacts/{ARTIFACT_ID}/review",
        headers=_headers(settings),
        json={"decision": "safe_reviewed", "reviewer": "alice"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["review_state"] == "safe_reviewed"
    assert body["reviewer"] == "alice"
    # The verdict governs the preview only; the original stays quarantined.
    assert body["quarantine_state"] == "quarantined"
    assert body["provenance"]["reviewer"] == "alice"
    with Session(engine) as session:
        stored = session.get(ThreatArtifact, ARTIFACT_ID)
        assert stored is not None and stored.quarantine_state == dm.QuarantineState.QUARANTINED
    assert any(call["action"] == "threat_library.review" for call in audit.calls)


def test_bundle_import_verifies_quarantines_and_replay_protects(library: Any) -> None:
    client, settings, engine, _audit = library
    bundle = _signed_bundle()
    response = client.post(
        "/api/v1/threat-library/bundles/import",
        headers=_headers(settings),
        json={"source_key": "curated-offline", "bundle": bundle},
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["imported"] == 1 and result["artifact_count"] == 1
    with Session(engine) as session:
        rows = list(session.scalars(select(ThreatArtifact).where(ThreatArtifact.origin == dm.ArtifactOrigin.BUNDLE)))
        assert len(rows) == 1
        assert "evil.example" not in rows[0].safe_preview_html
        assert rows[0].quarantine_state == dm.QuarantineState.QUARANTINED
    # Replaying the same bundle id is refused.
    replay = client.post(
        "/api/v1/threat-library/bundles/import",
        headers=_headers(settings),
        json={"source_key": "curated-offline", "bundle": bundle},
    )
    assert replay.status_code == 409


def test_bundle_import_tampered_signature_rejected(library: Any) -> None:
    client, settings, _engine, _audit = library
    bundle = _signed_bundle("bundle-tamper")
    bundle["artifacts"] = [{**bundle["artifacts"][0], "title": "attacker inserted"}]  # type: ignore[index]
    response = client.post(
        "/api/v1/threat-library/bundles/import",
        headers=_headers(settings),
        json={"source_key": "curated-offline", "bundle": bundle},
    )
    assert response.status_code in (400, 422)
    assert "verification failed" in response.text.lower() or "checksum" in response.text.lower()


def test_bundle_import_under_disabled_policy_fails_closed(library: Any) -> None:
    client, settings, _engine, _audit = library
    response = client.post(
        "/api/v1/threat-library/bundles/import",
        headers=_headers(settings),
        json={"source_key": "disabled-feed", "bundle": _signed_bundle("bundle-disabled")},
    )
    assert response.status_code == 409


def test_source_health_system_view_flags_stale_and_failed(library: Any) -> None:
    client, settings, _engine, _audit = library
    response = client.get("/api/v1/threat-library/sources/health?stale_or_failed_only=true", headers=_headers(settings))
    assert response.status_code == 200
    rows = response.json()
    by_key = {row["source_key"]: row for row in rows}
    assert "disabled-feed" in by_key
    disabled = by_key["disabled-feed"]
    assert disabled["enabled"] is False
    assert disabled["admits_ingestion"] is False
    # The healthy curated source is not in the stale/failed-only view.
    assert "curated-offline" not in by_key
