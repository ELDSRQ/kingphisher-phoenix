"""Sending-domain onboarding wizard + signed Rules-of-Engagement endpoints.

Covers the authorization boundary from the operator side: challenge minting,
fail-closed DNS verification, lookalike candidate generation, RoE signing
(only over verified target domains), listing, and revocation. Requires the
local dev Postgres; skipped otherwise.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from kp_domain_models.roe import roe_signature_hex
from kp_domain_verification.verification import challenge_record_value
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT_HEX = "0f0e0d0c0b0a09080706050403020100"
ROE_KEY = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
VERIFY_KEY = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    global _available
    if _available is None:
        try:
            from kp_database.session import create_db_engine

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
    from kp_database.base import Base
    from kp_database.session import create_db_engine

    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    engine.dispose()

    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        recipient_hash_salt=SALT_HEX,
        roe_signing_key=ROE_KEY.hex(),
        domain_verification_key=VERIFY_KEY.hex(),
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


OPERATOR_HEADERS = {"Authorization": f"Bearer {_token(['campaign_operator'])}"}
AUDITOR_HEADERS = {"Authorization": f"Bearer {_token(['auditor'])}"}


@requires_db
def test_challenge_mints_deterministic_txt_and_dns_records(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/sending-domains/challenge",
        json={"domain": "corp-benefits.example", "relay": "ses"},
        headers=OPERATOR_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["domain"] == "corp-benefits.example"
    assert body["status"] == "awaiting_dns"
    expected = challenge_record_value("corp-benefits.example", signing_key=VERIFY_KEY)
    records = body["dns_records"]
    assert any(r["value"] == expected for r in records)
    assert any("include:amazonses.com" in r["value"] for r in records)
    assert any(r["name"] == "_dmarc.corp-benefits.example" for r in records)
    assert len(records) == 4
    # Deterministic: a second challenge returns the identical TXT value.
    again = client.post(
        "/api/v1/sending-domains/challenge", json={"domain": "corp-benefits.example"}, headers=OPERATOR_HEADERS
    ).json()
    assert any(r["value"] == expected for r in again["dns_records"])


@requires_db
def test_verify_records_verified_domain(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    records = [challenge_record_value("corp-training.example", signing_key=VERIFY_KEY)]
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda _domain, *, resolver_timeout: (records, None),
    )
    resp = client.post(
        "/api/v1/sending-domains/verify", json={"domain": "corp-training.example"}, headers=OPERATOR_HEADERS
    )
    assert resp.status_code == 200
    assert resp.json()["verified"] is True

    listing = client.get("/api/v1/sending-domains", headers=OPERATOR_HEADERS).json()
    assert "corp-training.example" in {d["domain"] for d in listing["domains"]}


@requires_db
@pytest.mark.parametrize(
    ("dns_records", "dns_error"),
    [
        (["v=spf1 -all"], None),
        ([], None),
        ([], "timed out"),
    ],
)
def test_verify_fails_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, dns_records: list[str], dns_error: str | None
) -> None:
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda _domain, *, resolver_timeout: (dns_records, dns_error),
    )
    resp = client.post("/api/v1/sending-domains/verify", json={"domain": "unowned.example"}, headers=OPERATOR_HEADERS)
    assert resp.status_code == 422
    listing = client.get("/api/v1/sending-domains", headers=OPERATOR_HEADERS).json()
    assert "unowned.example" not in {d["domain"] for d in listing["domains"]}


@requires_db
def test_verify_rejects_malformed_domain(client: TestClient) -> None:
    resp = client.post("/api/v1/sending-domains/verify", json={"domain": "not a domain"}, headers=OPERATOR_HEADERS)
    assert resp.status_code == 422


@requires_db
def test_lookalike_generator_returns_candidates_with_records(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/sending-domains/generate",
        params={"brand": "Okta", "base_domain": "corp-training.example", "limit": 3},
        headers=OPERATOR_HEADERS,
    )
    assert resp.status_code == 200
    candidates = resp.json()["candidates"]
    assert len(candidates) == 3
    for candidate in candidates:
        assert candidate["domain"].endswith(".corp-training.example")
        assert len(candidate["dns_records"]) == 4
        assert any(r["value"].startswith("kp-phoenix-verification=") for r in candidate["dns_records"])


@requires_db
def test_lookalike_generator_rejects_bad_base(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/sending-domains/generate",
        params={"brand": "Okta", "base_domain": "not a domain"},
        headers=OPERATOR_HEADERS,
    )
    assert resp.status_code == 422


@requires_db
def test_roe_requires_verified_target_domains(client: TestClient) -> None:
    window_start = datetime.now(UTC) + timedelta(days=1)
    body = {
        "authorizing_party": "Example Corp",
        "terms": "Engagement authorized for example.com only.",
        "window_start": window_start.isoformat(),
        "window_end": (window_start + timedelta(days=30)).isoformat(),
        "target_domains": ["not-verified.example"],
    }
    resp = client.post("/api/v1/roe", json=body, headers=OPERATOR_HEADERS)
    assert resp.status_code == 422
    assert "not DNS-verified" in resp.json()["detail"]


@requires_db
def test_roe_signs_over_verified_target_domains(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    records = [challenge_record_value("example.com", signing_key=VERIFY_KEY)]
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda _domain, *, resolver_timeout: (records, None),
    )
    assert (
        client.post(
            "/api/v1/sending-domains/verify", json={"domain": "example.com"}, headers=OPERATOR_HEADERS
        ).status_code
        == 200
    )

    window_start = datetime.now(UTC) + timedelta(days=1)
    terms = "Engagement authorized for the verified example.com domain."
    body = {
        "authorizing_party": "Example Corp",
        "terms": terms,
        "window_start": window_start.isoformat(),
        "window_end": (window_start + timedelta(days=30)).isoformat(),
        "target_domains": ["example.com"],
    }
    resp = client.post("/api/v1/roe", json=body, headers=OPERATOR_HEADERS)
    assert resp.status_code == 201
    created = resp.json()
    import hashlib

    assert created["terms_hash"] == hashlib.sha256(terms.encode()).hexdigest()
    signed_at = datetime.fromisoformat(created["signed_at"])
    expected_sig = roe_signature_hex(created["terms_hash"], created["signer"], signed_at, signing_key=ROE_KEY)
    assert created["signature"] == expected_sig

    roes = client.get("/api/v1/roe", headers=OPERATOR_HEADERS).json()["roes"]
    assert any(r["roe_id"] == created["roe_id"] and r["target_domains"] == ["example.com"] for r in roes)


@requires_db
def test_roe_rejects_inverted_window(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    records = [challenge_record_value("example.com", signing_key=VERIFY_KEY)]
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda _domain, *, resolver_timeout: (records, None),
    )
    client.post("/api/v1/sending-domains/verify", json={"domain": "example.com"}, headers=OPERATOR_HEADERS)
    start = datetime.now(UTC) + timedelta(days=1)
    body = {
        "authorizing_party": "Example Corp",
        "terms": "inverted",
        "window_start": start.isoformat(),
        "window_end": (start - timedelta(days=1)).isoformat(),
        "target_domains": ["example.com"],
    }
    resp = client.post("/api/v1/roe", json=body, headers=OPERATOR_HEADERS)
    assert resp.status_code == 422


@requires_db
def test_roe_revoke_then_double_revoke_conflicts(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    records = [challenge_record_value("example.com", signing_key=VERIFY_KEY)]
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda _domain, *, resolver_timeout: (records, None),
    )
    start = datetime.now(UTC) + timedelta(days=1)
    created = client.post(
        "/api/v1/roe",
        json={
            "authorizing_party": "Example Corp",
            "terms": "revocable engagement",
            "window_start": start.isoformat(),
            "window_end": (start + timedelta(days=7)).isoformat(),
            "target_domains": ["example.com"],
        },
        headers=OPERATOR_HEADERS,
    ).json()
    revoked = client.post(
        f"/api/v1/roe/{created['roe_id']}/revoke", json={"reason": "engagement complete"}, headers=OPERATOR_HEADERS
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None
    again = client.post(f"/api/v1/roe/{created['roe_id']}/revoke", json={"reason": "again"}, headers=OPERATOR_HEADERS)
    assert again.status_code == 409


@requires_db
def test_wizard_endpoints_require_verification_capability(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/sending-domains/challenge", json={"domain": "corp-benefits.example"}, headers=AUDITOR_HEADERS
    )
    assert resp.status_code == 403
    resp = client.post(
        "/api/v1/roe",
        json={
            "authorizing_party": "Example Corp",
            "terms": "t",
            "window_start": datetime.now(UTC).isoformat(),
            "window_end": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "target_domains": ["example.com"],
        },
        headers=AUDITOR_HEADERS,
    )
    assert resp.status_code == 403
