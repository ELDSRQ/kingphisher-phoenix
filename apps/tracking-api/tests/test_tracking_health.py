"""Liveness and readiness contract tests for the tracking API."""

from __future__ import annotations

import importlib.util
import re

import kp_tracking_api.main as main_module
import pytest
from fastapi.testclient import TestClient
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app


@pytest.fixture
def app() -> object:
    return create_app(TrackingApiSettings())


def test_livez_is_process_only(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: (_ for _ in ()).throw(AssertionError()))

    response = TestClient(app).get("/livez")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_readyz_reports_database_availability_without_detail(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: False)

    response = TestClient(app).get("/readyz")  # type: ignore[arg-type]

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


def test_readyz_succeeds_when_database_is_ready(app: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: True)

    response = TestClient(app).get("/readyz")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_healthz_compatibility_is_preserved(app: object) -> None:
    response = TestClient(app).get("/healthz")  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_are_not_public_and_trace_context_is_w3c_compatible(
    app: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "_database_is_ready", lambda engine: True)
    client = TestClient(app)  # type: ignore[arg-type]
    incoming = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"

    ready = client.get("/readyz", headers={"traceparent": incoming})
    response = client.get("/metrics")

    assert ready.headers["traceparent"].startswith("00-1234567890abcdef1234567890abcdef-")
    assert response.status_code == 404
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", response.headers["traceparent"])
    assert "kp_tracking_" not in response.text


def test_tracking_api_has_no_write_only_metrics_registry() -> None:
    assert not hasattr(main_module, "metrics")
    assert importlib.util.find_spec("kp_tracking_api.observability") is None


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"])
def test_developer_documentation_surface_is_disabled(app: object, path: str) -> None:
    response = TestClient(app).get(path)  # type: ignore[arg-type]

    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store"
    assert "openapi" not in response.text.lower()


def test_invalid_traceparent_is_not_reflected(app: object) -> None:
    response = TestClient(app).get("/livez", headers={"traceparent": "recipient@example.com"})  # type: ignore[arg-type]

    assert "recipient" not in response.headers["traceparent"]
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", response.headers["traceparent"])
