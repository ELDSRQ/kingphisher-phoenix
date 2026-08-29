"""Liveness and readiness contract tests for the operator API."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from types import SimpleNamespace

import kp_operator_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import (
    _AUDIT_GATE_EXEMPT_ROUTES,
    _audit_mutation_state_is_healthy,
    _requires_healthy_audit,
    create_app,
)

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
    )


@pytest.fixture
def app() -> Iterator[object]:
    application = create_app(_settings())
    application.state.audit_verifier.status = "ok"
    yield application


def test_livez_is_process_only(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(main_module, "_queue_is_ready", lambda queue: (_ for _ in ()).throw(AssertionError()))

    class _UnexpectedLimiter:
        def allow(self, key: str) -> bool:
            raise AssertionError("liveness must not consult rate-limiter state")

    app.state.ip_limiter = _UnexpectedLimiter()  # type: ignore[attr-defined]

    response = TestClient(app).get("/livez")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


@pytest.mark.parametrize(
    ("database_states", "queue_ready", "audit_status"),
    [
        ([False], True, "ok"),
        ([True, False], True, "ok"),
        ([True, True], False, "ok"),
        ([True, True], True, "pending"),
        ([True, True], True, "failing"),
        ([True, True], True, "error"),
    ],
)
def test_readyz_fails_closed_without_sensitive_detail(
    app: object,
    monkeypatch: pytest.MonkeyPatch,
    database_states: list[bool],
    queue_ready: bool,
    audit_status: str,
) -> None:
    states = iter(database_states)
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: next(states))
    monkeypatch.setattr(main_module, "_queue_is_ready", lambda queue: queue_ready)
    app.state.audit_verifier.status = audit_status  # type: ignore[attr-defined]

    response = TestClient(app).get("/readyz")  # type: ignore[arg-type]

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


def test_readyz_succeeds_only_when_all_dependencies_are_ready(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: True)
    monkeypatch.setattr(main_module, "_queue_is_ready", lambda queue: True)

    response = TestClient(app).get("/readyz")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_healthz_compatibility_is_preserved(app: object) -> None:
    response = TestClient(app).get("/healthz")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_operational_metrics_are_not_exposed_over_the_operator_http_surface(
    app: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: True)
    monkeypatch.setattr(main_module, "_queue_is_ready", lambda queue: True)
    app.state.audit_store = SimpleNamespace(  # type: ignore[attr-defined]
        outbox_health=lambda: {"overdue_pending": 2, "failed": 1, "dispatching_stale": 0}
    )
    client = TestClient(app)  # type: ignore[arg-type]

    assert client.get("/readyz").status_code == 200
    response = client.get("/metrics")

    assert response.status_code == 404
    assert "kp_operator_" not in response.text


def test_operator_api_has_no_write_only_metrics_registry() -> None:
    assert not hasattr(main_module, "metrics")
    assert importlib.util.find_spec("kp_operator_api.observability") is None


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"])
def test_developer_documentation_surface_is_disabled(app: object, path: str) -> None:
    response = TestClient(app).get(path)  # type: ignore[arg-type]

    assert response.status_code == 404
    assert "openapi" not in response.text.lower()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/campaigns"),
        ("POST", "/api/v1/campaigns/c1/schedule"),
        ("POST", "/api/v1/campaigns/c1/approvals/security"),
        ("POST", "/api/v1/sources/source-1/enable"),
        ("DELETE", "/api/v1/alerts/subscriptions/sub-1"),
        ("POST", "/api/v1/kill-switch/reset"),
        ("POST", "/api/v1/privacy/requests/request-1/fulfill"),
        ("POST", "/api/v1/sending-domains/example.test/revoke"),
        ("POST", "/api/v1/roe/roe-1/revoke"),
    ],
)
def test_audited_business_mutation_route_policy(method: str, path: str) -> None:
    assert _requires_healthy_audit(method, path)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/console/session"),
        ("POST", "/api/v1/console/logout"),
        ("POST", "/api/v1/console/azure-deployment/validate"),
        ("POST", "/api/v1/console/onboarding/assist"),
        ("PUT", "/api/v1/console/config"),
        ("POST", "/api/v1/templates/preview"),
        ("POST", "/api/v1/audit/verify"),
        ("POST", "/api/v1/kill-switch"),
        ("GET", "/api/v1/campaigns"),
    ],
)
def test_recovery_and_non_mutating_routes_bypass_audit_gate(method: str, path: str) -> None:
    assert not _requires_healthy_audit(method, path)


def test_unknown_future_unsafe_api_route_is_gated_by_default() -> None:
    assert _requires_healthy_audit("POST", "/api/v1/future-campaign-feature")
    assert _requires_healthy_audit("PATCH", "/api/v1/future-campaign-feature/item-1")


def test_audit_gate_exemptions_are_exact_and_intentional() -> None:
    assert {
        ("POST", "/api/v1/audit/verify"),
        ("POST", "/api/v1/console/azure-deployment/validate"),
        ("PUT", "/api/v1/console/config"),
        ("POST", "/api/v1/console/logout"),
        ("PUT", "/api/v1/console/onboarding"),
        ("POST", "/api/v1/console/onboarding/assist"),
        ("POST", "/api/v1/console/onboarding/test"),
        ("POST", "/api/v1/console/restart"),
        ("POST", "/api/v1/console/session"),
        ("POST", "/api/v1/kill-switch"),
        ("POST", "/api/v1/templates/preview"),
    } == _AUDIT_GATE_EXEMPT_ROUTES


def test_audit_health_is_fail_closed_for_unknown_and_unhealthy_state() -> None:
    assert not _audit_mutation_state_is_healthy(None, object())
    assert not _audit_mutation_state_is_healthy(SimpleNamespace(status="pending"), object())
    assert not _audit_mutation_state_is_healthy(
        SimpleNamespace(status="ok"),
        SimpleNamespace(outbox_health=lambda: {"failed": 0}),
    )


def test_future_scheduled_outbox_work_is_healthy() -> None:
    store = SimpleNamespace(
        outbox_health=lambda: {
            "pending": 2,
            "overdue_pending": 0,
            "scheduled_or_fresh": 2,
            "failed": 0,
            "dispatching_stale": 0,
        }
    )

    assert _audit_mutation_state_is_healthy(SimpleNamespace(status="ok"), store)


def test_protected_mutation_uses_injected_fail_closed_health_seam() -> None:
    application = create_app(_settings())
    application.state.audit_health_check = lambda: False

    response = TestClient(application).post("/api/v1/campaigns", json={})

    assert response.status_code == 503
    assert response.json()["code"] == "audit_integrity_unhealthy"


def test_protected_mutation_fails_closed_when_health_check_raises() -> None:
    application = create_app(_settings())

    def unknown_health() -> bool:
        raise RuntimeError("audit database unavailable")

    application.state.audit_health_check = unknown_health

    response = TestClient(application).post("/api/v1/campaigns", json={})

    assert response.status_code == 503
    assert response.json()["code"] == "audit_integrity_unhealthy"


def test_preview_does_not_consult_audit_health_seam() -> None:
    application = create_app(_settings())

    def unexpected_health_check() -> bool:
        raise AssertionError("preview must not consult audit integrity")

    application.state.audit_health_check = unexpected_health_check

    response = TestClient(application).post("/api/v1/templates/preview", json={})

    assert response.status_code != 503
