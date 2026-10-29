"""Operator health + capability dashboard (KP-AUD-002/004/016/024).

Covers the read-only aggregation endpoint ``GET /api/v1/console/health``: its
RBAC gate, the full set of translated capability items, mode-awareness
(local vs Azure-managed), stale-data labelling, and the no-secret/no-raw-error
invariant.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import kp_operator_api.health_dashboard as hd
import pytest
from fastapi.testclient import TestClient
from kp_authorization.rbac import Principal, Role
from kp_operator_api.auth import OidcIdP
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CONSOLE_PASSWORD = "correct horse battery staple"

_ALL_WORKER_IDS = {f"worker.{role}" for role in hd.LOCAL_WORKER_ROLES}
_NON_WORKER_IDS = {
    "migration",
    "database",
    "redis",
    "ai_provider",
    "authorization_roe",
    "audit_witness",
    "tls_cert",
    "backup",
}
_VALID_STATES = {"available", "configured_unverified", "unavailable", "production_blocked"}


@pytest.fixture()
def env_file(tmp_path) -> str:
    path = tmp_path / ".env"
    path.write_text(f"KP_CONSOLE_PASSWORD={CONSOLE_PASSWORD}{os.linesep}", encoding="utf-8")
    return str(path)


def _settings(env_file: str, **overrides: object) -> OperatorApiSettings:
    base = dict(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=env_file,
        oidc_issuer="http://localhost:8443/realms/kingphisher",
        oidc_audience="kp-operator-api",
        console_static_dir="/nonexistent-console-dir",
    )
    base.update(overrides)
    return OperatorApiSettings(**base)


def _app(env_file: str, **overrides: object):
    app = create_app(_settings(env_file, **overrides))
    app.state.audit_verifier.status = "ok"
    return app


def _login(client: TestClient) -> str:
    resp = client.post("/api/v1/console/session", json={"password": CONSOLE_PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _role_token(settings: OperatorApiSettings, *roles: str) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": list(roles)},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def test_health_dashboard_requires_authentication(env_file: str) -> None:
    client = TestClient(_app(env_file))
    assert client.get("/api/v1/console/health").status_code == 401


def test_health_dashboard_rejects_a_principal_without_view_aggregate(env_file: str) -> None:
    settings = _settings(env_file)
    app = _app(env_file)
    # A principal with no roles holds no capabilities, so the view-aggregate gate
    # must deny it exactly as it does for the peer /console/status route.
    token = _role_token(settings)
    resp = TestClient(app).get("/api/v1/console/health", headers=_auth(token))
    assert resp.status_code == 403


def test_health_dashboard_aggregates_every_capability(env_file: str) -> None:
    app = _app(env_file)
    client = TestClient(app)
    token = _login(client)

    resp = client.get("/api/v1/console/health", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["runtime_control"] == "local_supervisor"
    assert body["overall_state"] in _VALID_STATES
    assert isinstance(body["generated_at"], str) and body["generated_at"].endswith("+00:00")

    ids = {item["id"] for item in body["items"]}
    assert ids == _ALL_WORKER_IDS | _NON_WORKER_IDS

    for item in body["items"]:
        assert item["state"] in _VALID_STATES
        assert item["severity"] in {"ok", "info", "warning", "critical"}
        assert item["capability"] and item["reason"] and item["safe_action"]
        assert item["evidence_timestamp"].endswith("+00:00")
        assert isinstance(item["stale"], bool)


def test_health_dashboard_is_mode_aware_for_managed_azure(env_file: str, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(env_file, config_store="managed", oidc_mode="oidc", receipts_provider="none")
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    principal = Principal(subject_id=str(uuid.uuid4()), roles={Role.ADMINISTRATOR})
    monkeypatch.setattr(OidcIdP, "verify", lambda _self, _token: principal)

    client = TestClient(app)
    client.cookies.clear()
    resp = client.get("/api/v1/console/health", headers=_auth("managed-token"))
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["runtime_control"] == "azure_control_plane"
    by_id = {item["id"]: item for item in body["items"]}
    # Local probes are not authoritative in a managed deployment: they must read
    # as configured-but-unverified and point at the Azure control plane, never
    # claim a false "down".
    for item_id in ("database", "redis", "backup", "tls_cert", *(f"worker.{r}" for r in hd.LOCAL_WORKER_ROLES)):
        assert by_id[item_id]["state"] == "configured_unverified", item_id
        assert by_id[item_id]["workflow"] == "#azure-deployment"


def test_health_dashboard_labels_a_stale_audit_anchor(env_file: str) -> None:
    app = _app(env_file)
    stale_at = datetime.now(UTC) - timedelta(hours=6)
    app.state.last_successful_anchor_at = lambda: stale_at
    app.state.audit_anchor_gate_interval_seconds = 60.0

    client = TestClient(app)
    token = _login(client)
    body = client.get("/api/v1/console/health", headers=_auth(token)).json()
    witness = next(item for item in body["items"] if item["id"] == "audit_witness")

    assert witness["stale"] is True
    assert witness["state"] == "production_blocked"
    assert witness["evidence_timestamp"] == stale_at.isoformat()


def test_health_dashboard_never_leaks_the_provider_api_key(
    env_file: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "sk-TOPSECRET-should-never-appear"
    run_dir = tmp_path / "data" / "run"
    run_dir.mkdir(parents=True)
    (run_dir / hd._STATE_FILENAME).write_text(
        '{"provider":"openai","model_id":"gpt","base_url":"https://x","api_key":"' + secret + '"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(hd, "_run_dir", lambda _settings: run_dir)
    monkeypatch.setattr(hd, "_desired_provider", lambda _session: "openai")

    app = _app(env_file)
    client = TestClient(app)
    token = _login(client)
    resp = client.get("/api/v1/console/health", headers=_auth(token))

    assert resp.status_code == 200
    assert secret not in resp.text
    provider_item = next(item for item in resp.json()["items"] if item["id"] == "ai_provider")
    # Desired (openai) matches the runtime state file's provider -> available.
    assert provider_item["state"] == "available"


def test_health_dashboard_reports_db_backed_items_safely_without_a_database(env_file: str) -> None:
    # No database is reachable in the unit harness: the schema-version and RoE
    # items must degrade to a safe state with a plain reason, never a raw error.
    app = _app(env_file)
    client = TestClient(app)
    token = _login(client)
    body = client.get("/api/v1/console/health", headers=_auth(token)).json()
    by_id = {item["id"]: item for item in body["items"]}

    assert by_id["authorization_roe"]["state"] in {"production_blocked", "unavailable"}
    assert by_id["migration"]["state"] in {"unavailable", "configured_unverified"}
    for item in body["items"]:
        assert "Traceback" not in item["reason"]
        assert "psycopg" not in item["reason"].lower()
