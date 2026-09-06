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


def test_preview_returns_bounded_html_structure_summary() -> None:
    settings = _make_settings()
    app = create_app(settings)
    safe_html = (
        "<h1>Security Notice</h1>"
        '<p>Hello <a href="https://training.local/review">Review your account</a></p>'
        "<h2>What to do</h2>"
    )
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "Review", "plain_text": "See {{ tracking.click_url }}", "safe_html": safe_html},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    summary = body["html_summary"]
    # Counts.
    assert summary["link_count"] == 1
    assert summary["image_count"] == 0
    assert summary["form_count"] == 0
    # Heading text extracted as plain strings (client escapes them).
    assert summary["headings"] == ["Security Notice", "What to do"]
    # Link text + href, both plain strings.
    assert len(summary["links"]) == 1
    assert summary["links"][0]["text"] == "Review your account"
    assert summary["links"][0]["href"] == "https://training.local/review"
    # Top-level structure of the fragment.
    assert summary["top_level_tags"] == ["h1", "p", "h2"]


def test_preview_without_safe_html_has_no_summary() -> None:
    settings = _make_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/templates/preview",
            headers={"Authorization": f"Bearer {_token(settings)}"},
            json={"subject": "Review", "plain_text": "See {{ tracking.click_url }}", "safe_html": ""},
        )
    assert resp.status_code == 200, resp.text
    assert "html_summary" not in resp.json()


def test_html_summary_extracts_structure_and_counts() -> None:
    summary = content_library_module._summarize_safe_html(
        "<div><h1>Title</h1><p>Body <a href='https://train.local/a'>Click</a> and "
        "<a href='https://train.local/b'>Again</a></p><img src='x'><form></form></div>"
    )
    assert summary["link_count"] == 2
    assert summary["image_count"] == 1
    assert summary["form_count"] == 1
    assert summary["headings"] == ["Title"]
    assert summary["links"] == [
        {"text": "Click", "href": "https://train.local/a"},
        {"text": "Again", "href": "https://train.local/b"},
    ]
    # A single top-level <div> wraps the fragment.
    assert summary["top_level_tags"] == ["div"]


def test_html_summary_caps_text_and_href_length() -> None:
    long_text = "T" * 500
    long_href = "https://train.local/" + ("q" * 500)
    summary = content_library_module._summarize_safe_html(
        f'<a href="{long_href}">{long_text}</a><h1>{long_text}</h1>'
    )
    assert len(summary["links"][0]["text"]) == content_library_module._HTML_SUMMARY_MAX_TEXT
    assert len(summary["links"][0]["href"]) == content_library_module._HTML_SUMMARY_MAX_HREF
    assert len(summary["headings"][0]) == content_library_module._HTML_SUMMARY_MAX_TEXT


def test_html_summary_caps_list_lengths_and_counts() -> None:
    link_total = content_library_module._HTML_SUMMARY_MAX_LINKS + 40
    image_total = content_library_module._HTML_SUMMARY_MAX_COUNT + 25
    tag_total = content_library_module._HTML_SUMMARY_MAX_TOP_TAGS + 30
    many_links = "".join(f'<a href="https://train.local/{i}">L{i}</a>' for i in range(link_total))
    many_images = "<img src='x'>" * image_total
    many_divs = "<div></div>" * tag_total
    summary = content_library_module._summarize_safe_html(many_links + many_images + many_divs)
    # Returned lists are truncated to their caps regardless of input size...
    assert len(summary["links"]) == content_library_module._HTML_SUMMARY_MAX_LINKS
    assert len(summary["top_level_tags"]) == content_library_module._HTML_SUMMARY_MAX_TOP_TAGS
    # ...the link count reflects the (bounded) true total when under the ceiling...
    assert summary["link_count"] == link_total
    # ...and a count is capped so a hostile-but-sanitized template cannot inflate it.
    assert summary["image_count"] == content_library_module._HTML_SUMMARY_MAX_COUNT
    assert image_total > content_library_module._HTML_SUMMARY_MAX_COUNT


def test_html_summary_returns_plain_strings_never_markup() -> None:
    summary = content_library_module._summarize_safe_html(
        '<h1>A &amp; B</h1><a href="https://train.local/x">go &lt;here&gt;</a>'
    )
    # Char refs are decoded to plain text; the client escapes on display. No raw
    # tags/markup are re-emitted by the summary.
    assert summary["headings"] == ["A & B"]
    assert summary["links"][0]["text"] == "go <here>"
    assert "<" not in "".join(summary["top_level_tags"])


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
