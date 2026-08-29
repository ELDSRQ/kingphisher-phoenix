import uuid

import jwt
import kp_operator_api.content_library as content_library_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _make_settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        tracking_base_url="http://track.local:8001",
        training_base_url="http://train.local:3000/training/awareness",
        training_domains="example.com,training.local",
    )


def _token(settings: OperatorApiSettings, role: str = "campaign_author") -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": [role]},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def test_preview_template_renders() -> None:
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={
                "subject": "Hi {{ recipient.first_name }}",
                "plain_text": "Open {{ tracking.click_url }}",
                "safe_html": "",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == "Hi Sample"
    assert "click/preview-" in body["plain_text"]
    assert body["safe_html"] == ""
    assert body["safe_html_present"] is False
    assert body["html_execution"] is False


def test_preview_template_rejects_unauthorized_var() -> None:
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "{{ recipient.employee_key }}", "plain_text": "", "safe_html": ""},
        )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "template contains unsupported or malformed rendering syntax"


def test_preview_render_failure_never_reflects_exception_or_template_content(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "password=must-not-log"

    def fail_render(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError(f"{secret} https://internal-renderer/private template=private-value")

    monkeypatch.setattr(content_library_module._renderer, "render", fail_render)
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "private-value", "plain_text": "normal preview", "safe_html": ""},
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "template contains unsupported or malformed rendering syntax"}
    rendered = response.text + capsys.readouterr().out
    assert secret not in rendered
    assert "internal-renderer" not in rendered
    assert "private-value" not in rendered
    assert "Traceback" not in rendered


def test_preview_safety_feedback_uses_stable_reason_codes_without_reflection() -> None:
    settings = _make_settings()
    app = create_app(settings)
    secret_host = "private-data-must-not-log.private.example"
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "Review", "plain_text": f"Open https://{secret_host}/private", "safe_html": ""},
        )

    assert response.status_code == 422
    assert response.json() == {
        "code": "KP-007",
        "detail": "KP-007: template content failed deterministic safety validation: disallowed_link",
    }
    assert secret_host not in response.text


def test_preview_requires_auth() -> None:
    app = create_app(_make_settings())
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            json={"subject": "x", "plain_text": "", "safe_html": ""},
        )
    assert resp.status_code == 401


def test_template_approver_can_render_preview_but_cannot_clone() -> None:
    settings = _make_settings()
    app = create_app(settings)
    app.state.audit_health_check = lambda: True
    headers = {"Authorization": f"Bearer {_token(settings, 'security_approver')}"}
    template_id = uuid.uuid4()

    with TestClient(app) as client:
        preview = client.post(
            "/api/v1/templates/preview",
            headers=headers,
            json={"subject": "Review", "plain_text": "Inspect {{ tracking.click_url }}", "safe_html": ""},
        )
        # Keep this authorization assertion independent of a running database.
        # FastAPI resolves route resources before the principal because of the
        # endpoint's parameter order, but neither resource may make a reviewer
        # authorized to invoke the author-only clone operation.
        app.dependency_overrides[get_session] = lambda: object()
        app.dependency_overrides[get_audit_store] = lambda: object()
        clone = client.post(
            f"/api/v1/templates/{template_id}/clone",
            headers=headers,
            json={"reason": "reviewers must not author new content"},
        )

    assert preview.status_code == 200, preview.text
    assert preview.json()["plain_text"].startswith("Inspect http://track.local:8001/")
    assert "click/preview-" in preview.json()["plain_text"]
    assert clone.status_code == 403, clone.text
    assert clone.json() == {"code": "KP-003", "detail": "KP-003: required capability is not assigned"}
