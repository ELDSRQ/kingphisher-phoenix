"""Contract tests for deterministic local setup assistance."""

from __future__ import annotations

import mock_ai
import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize("component", ["oidc", "graph", "smtp", "mailbox", "ai", "training", "webhook"])
def test_setup_assist_covers_supported_components_without_echoing_context(component: str) -> None:
    marker = "private-customer-host.example"
    with TestClient(mock_ai.app) as client:
        response = client.post(
            "/setup-assist",
            json={
                "component": component,
                "question": "What should I configure next?",
                "values": {"hostname": marker, "port": "443"},
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["answer"], str) and body["answer"]
    assert isinstance(body["suggestions"], dict) and body["suggestions"]
    assert marker not in response.text


def test_setup_assist_returns_safe_generic_guidance_for_unknown_component() -> None:
    with TestClient(mock_ai.app) as client:
        response = client.post(
            "/setup-assist",
            json={"component": "future-provider", "question": "How do I begin?", "values": {}},
        )

    assert response.status_code == 200
    assert response.json()["suggestions"]["verification"] == "test connection"


@pytest.mark.parametrize(
    "payload",
    [
        {"component": "smtp", "question": "Help", "values": {"api_key": "redacted"}},
        {"component": "smtp", "question": "Help", "values": {"note": "Bearer abcdefghijklmnop"}},
        {"component": "smtp", "question": "password=do-not-send", "values": {}},
        {
            "component": "smtp",
            "question": "Help",
            "values": {"endpoint": "https://operator:credential@example.test"},
        },
    ],
)
def test_setup_assist_rejects_secret_looking_input(payload: dict[str, object]) -> None:
    with TestClient(mock_ai.app) as client:
        response = client.post("/setup-assist", json=payload)
    assert response.status_code == 422
    assert "do-not-send" not in response.text
    assert "credential@example" not in response.text


def test_setup_assist_forbids_extra_fields_and_caps_context() -> None:
    with TestClient(mock_ai.app) as client:
        extra = client.post(
            "/setup-assist",
            json={"component": "oidc", "question": "Help", "values": {}, "debug": True},
        )
        too_many = client.post(
            "/setup-assist",
            json={
                "component": "oidc",
                "question": "Help",
                "values": {f"field_{index}": "safe" for index in range(13)},
            },
        )
        oversized = client.post(
            "/setup-assist",
            json={"component": "oidc", "question": "x" * 501, "values": {}},
        )

    assert extra.status_code == 422
    assert too_many.status_code == 422
    assert oversized.status_code == 422
