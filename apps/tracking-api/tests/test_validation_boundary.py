"""Public tracking request-validation response boundary."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from pydantic import BaseModel, ConfigDict

_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-robots-tag": "noindex, nofollow, noarchive",
}


def _settings(*, max_body_bytes: int = 65_536) -> TrackingApiSettings:
    return TrackingApiSettings(
        tracking_token_hmac_key=(b"k" * 32).hex(),
        training_token_hmac_key=(b"t" * 32).hex(),
        max_body_bytes=max_body_bytes,
    )


def _assert_security_headers(response: Response) -> None:
    for name, value in _SECURITY_HEADERS.items():
        assert response.headers[name] == value


class _SecretPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret: str


class _ManyInvalidFields(BaseModel):
    field_01: int
    field_02: int
    field_03: int
    field_04: int
    field_05: int
    field_06: int
    field_07: int
    field_08: int
    field_09: int
    field_10: int
    field_11: int
    field_12: int
    field_13: int
    field_14: int
    field_15: int
    field_16: int
    field_17: int


class _DeepPayload(BaseModel):
    value: list[list[list[list[list[list[list[list[int]]]]]]]]


def _validation_app() -> FastAPI:
    app = create_app(_settings())

    @app.post("/test/secret")
    def secret_validation(_payload: _SecretPayload) -> dict[str, bool]:
        return {"accepted": True}

    @app.post("/test/many")
    def many_validation(_payload: _ManyInvalidFields) -> dict[str, bool]:
        return {"accepted": True}

    return app


def test_invalid_near_limit_body_is_bounded_redacted_and_hardened() -> None:
    app = _validation_app()
    marker = "SECRET-MARKER-" + "x" * 64_000

    with TestClient(app) as client:
        response = client.post("/test/secret", json={"secret": {"submitted": marker}})

    assert response.status_code == 422
    assert len(response.content) < 4_096
    assert marker not in response.text
    assert "submitted" not in response.text
    assert "input" not in response.text
    assert "context" not in response.text
    assert "url" not in response.text
    assert response.json() == {
        "code": "request_validation_failed",
        "detail": [{"type": "string_type", "loc": ["body", "field"], "msg": "Value is invalid"}],
        "truncated": False,
    }
    _assert_security_headers(response)


def test_validation_error_count_is_capped_and_reported_as_truncated() -> None:
    app = _validation_app()
    marker = "SECRET-MULTI-ERROR"
    payload = {f"field_{number:02d}": marker for number in range(1, 18)}

    with TestClient(app) as client:
        response = client.post("/test/many", json=payload)

    assert response.status_code == 422
    assert response.json()["truncated"] is True
    assert len(response.json()["detail"]) == 16
    assert marker not in response.text
    assert all(
        error == {"type": "int_parsing", "loc": ["body", "field"], "msg": "Value is invalid"}
        for error in response.json()["detail"]
    )
    _assert_security_headers(response)


def test_malformed_json_uses_only_stable_generic_metadata() -> None:
    app = _validation_app()
    marker = "SECRET-JSON-EXCEPTION"

    with TestClient(app) as client:
        response = client.post(
            "/test/secret",
            content=f'{{"secret":"{marker}",'.encode(),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 422
    assert marker not in response.text
    assert response.json()["code"] == "request_validation_failed"
    assert response.json()["detail"] == [
        {
            "type": "json_invalid",
            "loc": ["body", len(marker) + 13],
            "msg": "Request body must be valid JSON",
        }
    ]
    assert response.json()["truncated"] is False
    _assert_security_headers(response)


def test_validation_location_depth_is_capped() -> None:
    app = create_app(_settings())

    @app.post("/test/deep")
    def deep_validation(_payload: _DeepPayload) -> dict[str, bool]:
        return {"accepted": True}

    marker = "SECRET-DEEP-ERROR"
    with TestClient(app) as client:
        response = client.post("/test/deep", json={"value": [[[[[[[[marker]]]]]]]]})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert len(detail) == 1
    assert len(detail[0]["loc"]) == 8
    assert detail[0]["loc"] == ["body", "field", 0, 0, 0, 0, 0, 0]
    assert marker not in response.text
    _assert_security_headers(response)
