"""Route-level tests for operator logo attach/remove on a DRAFT template.

Calls ``set_template_logo`` directly with a fake session (hermetic, no DB),
mirroring test_template_approval_gate. Proves: a logo lands in ``safe_html``
(so the approval hash covers it) with the training link preserved, an empty
logo removes it, only DRAFT templates can be branded, and an unsupported logo
is rejected before any mutation.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from kp_authorization import Principal, Role
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import TemplateVersion
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.routes.patterns import TemplateLogoRequest, set_template_logo
from kp_telemetry.errors import ConflictError, ValidationError_

_KEK = "01" * 32
_HMAC = "02" * 32
_CONSOLE_JWT = "03" * 32
_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)
_BODY = (
    f'<table><tr><td><p style="color:#005a9c">Security notice</p>'
    f'<a href="{TRAINING_URL_PLACEHOLDER}">Verify</a></td></tr></table>'
)


class _Session:
    def __init__(self, template: TemplateVersion) -> None:
        self.template = template
        self.commits = 0

    def get(self, _model: object, identifier: uuid.UUID) -> TemplateVersion | None:
        return self.template if identifier == self.template.template_version_id else None

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **event: Any) -> None:
        self.events.append(event)


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=_HMAC,
        ciphertext_kek=_KEK,
        console_jwt_secret=_CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
    )


def _template(
    *,
    safe_html: str | None = _BODY,
    state: dm.TemplateApprovalState = dm.TemplateApprovalState.DRAFT,
    edited: Any = None,
) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        version=1,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="a" * 64,
        raw_proposal={},
        subject="Security notice",
        plain_text=f"Review {TRAINING_URL_PLACEHOLDER}",
        safe_html=safe_html,
        edited_content=edited,
        approval_state=state,
    )


def _call(template: TemplateVersion, logo: str) -> tuple[dict[str, Any], _Session, _Audit]:
    session = _Session(template)
    audit = _Audit()
    result = set_template_logo(
        template.template_version_id,
        TemplateLogoRequest(logo=logo),
        settings=_settings(),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=Principal(str(uuid.uuid4()), {Role.SECURITY_APPROVER}),
    )
    return result, session, audit


def test_https_logo_is_injected_into_safe_html_and_link_preserved() -> None:
    template = _template()
    result, session, audit = _call(template, "https://cdn.acme.example/logo.png")
    assert result["logo_applied"] is True
    assert "cdn.acme.example/logo.png" in template.safe_html
    assert TRAINING_URL_PLACEHOLDER in template.safe_html
    assert template.edited_content == {"operator_logo_src": "https://cdn.acme.example/logo.png"}
    assert session.commits == 1
    assert audit.events[0]["action"] == "template.logo" and audit.events[0]["detail"]["logo_applied"] is True


def test_data_image_logo_is_injected() -> None:
    template = _template()
    result, _session, _audit = _call(template, _PNG)
    assert result["logo_applied"] is True
    assert "data:image/png;base64" in template.safe_html


def test_empty_logo_removes_previous_and_keeps_branding() -> None:
    template = _template()
    _call(template, "https://cdn.acme.example/logo.png")
    result, session, _audit = _call(template, "")
    assert result["logo_applied"] is False
    assert "cdn.acme.example" not in template.safe_html
    assert "Security notice" in template.safe_html and TRAINING_URL_PLACEHOLDER in template.safe_html
    assert template.edited_content in (None, {})


def test_only_draft_templates_can_be_branded() -> None:
    template = _template(state=dm.TemplateApprovalState.APPROVED)
    with pytest.raises(ConflictError):
        _call(template, _PNG)
    assert template.safe_html == _BODY  # unchanged


def test_unsupported_logo_is_rejected_before_mutation() -> None:
    template = _template()
    with pytest.raises(ValidationError_):
        _call(template, "http://cdn.acme.example/logo.png")
    assert template.safe_html == _BODY


def test_template_without_html_body_is_rejected() -> None:
    template = _template(safe_html="   ")
    with pytest.raises(ValidationError_):
        _call(template, _PNG)
