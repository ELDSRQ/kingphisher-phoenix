"""Fail-closed canonical content gate for template approval."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_authorization import Principal, Role
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER, GenerationResponse
from kp_database.models import TemplateVersion
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.main import create_app
from kp_operator_api.routers import TemplateDecision, decide_template
from kp_telemetry.errors import PermissionDeniedError, ValidationError_

_KEK = "01" * 32
_HMAC = "02" * 32
_CONSOLE_JWT = "03" * 32
_REVIEWER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")
_REQUESTER_ID = uuid.UUID("20000000-0000-4000-8000-000000000002")
_ERROR = "template content is incomplete or not recipient-bound"


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

    def outbox_health(self) -> dict[str, int]:
        return {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}


def _principal() -> Principal:
    return Principal(str(_REVIEWER_ID), {Role.SECURITY_APPROVER})


def _template(
    *,
    subject: str | None = "Conference security exercise",
    plain_text: str | None = f"Review this simulation: {TRAINING_URL_PLACEHOLDER}",
    safe_html: str | None = None,
    raw_proposal: dict[str, object] | None = None,
) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        version=1,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="a" * 64,
        raw_proposal=raw_proposal or {"requested_by": str(_REQUESTER_ID)},
        subject=subject,
        plain_text=plain_text,
        safe_html=safe_html,
        approval_state=dm.TemplateApprovalState.DRAFT,
    )


def _decide(template: TemplateVersion, decision: dm.ApprovalDecision) -> tuple[dict[str, Any], _Session, _Audit]:
    session = _Session(template)
    audit = _Audit()
    result = decide_template(
        template.template_version_id,
        TemplateDecision(decision=decision, rationale="Human review complete"),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=_principal(),
    )
    return result, session, audit


@pytest.mark.parametrize(
    "template",
    [
        _template(subject="   "),
        _template(plain_text="   "),
        _template(plain_text="A simulation with no recipient training route"),
        _template(
            subject=None,
            plain_text=None,
            safe_html=None,
            raw_proposal={
                "subject": "Legacy raw-only draft",
                "plain_text": f"Review {TRAINING_URL_PLACEHOLDER}",
                "safe_html": f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
                "requested_by": str(_REQUESTER_ID),
            },
        ),
        _template(
            safe_html='<a href="{{ tracking.click_url }}">SECRET-LEGACY-MISMATCH</a>',
        ),
    ],
)
def test_direct_approval_rejects_incomplete_canonical_content_before_mutation(template: TemplateVersion) -> None:
    session = _Session(template)
    audit = _Audit()

    with pytest.raises(ValidationError_) as captured:
        decide_template(
            template.template_version_id,
            TemplateDecision(decision=dm.ApprovalDecision.APPROVED, rationale="Reviewed"),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            principal=_principal(),
        )

    assert captured.value.message == _ERROR
    assert "SECRET" not in str(captured.value)
    assert template.approval_state == dm.TemplateApprovalState.DRAFT
    assert session.commits == 0
    assert audit.events == []


@pytest.mark.parametrize(
    "safe_html",
    [
        None,
        "   ",
        f'<p>Simulation</p><a href="{TRAINING_URL_PLACEHOLDER}">Open training</a>',
    ],
)
def test_text_only_and_html_canonical_templates_can_be_approved(safe_html: str | None) -> None:
    template = _template(safe_html=safe_html)

    result, session, audit = _decide(template, dm.ApprovalDecision.APPROVED)

    assert result["approval_state"] == "approved"
    assert template.approval_state == dm.TemplateApprovalState.APPROVED
    assert session.commits == 1
    assert [event["action"] for event in audit.events] == ["template.approve"]


def test_malformed_template_can_still_be_rejected() -> None:
    template = _template(subject=None, plain_text=None, safe_html="unsafe legacy body")

    result, session, audit = _decide(template, dm.ApprovalDecision.REJECTED)

    assert result["approval_state"] == "rejected"
    assert template.approval_state == dm.TemplateApprovalState.REJECTED
    assert session.commits == 1
    assert [event["action"] for event in audit.events] == ["template.reject"]


def test_requester_still_cannot_approve_valid_generated_content() -> None:
    template = _template()
    session = _Session(template)
    audit = _Audit()
    requester = Principal(str(_REQUESTER_ID), {Role.SECURITY_APPROVER})

    with pytest.raises(PermissionDeniedError, match="requested this generation"):
        decide_template(
            template.template_version_id,
            TemplateDecision(decision=dm.ApprovalDecision.APPROVED, rationale="Self review"),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            principal=requester,
        )

    assert template.approval_state == dm.TemplateApprovalState.DRAFT
    assert session.commits == 0
    assert audit.events == []


def test_seed_and_generated_canonical_shapes_satisfy_approval_gate() -> None:
    seed = _template(
        subject="Invoice requires immediate review",
        plain_text=f"This is a training simulation — learn more at {TRAINING_URL_PLACEHOLDER}.",
        safe_html=f'<p>This is a training simulation.</p><a href="{TRAINING_URL_PLACEHOLDER}">Learn more</a>',
    )
    generated = GenerationResponse(
        subject="AI-reviewed security exercise",
        plain_text=f"Review this simulation: {TRAINING_URL_PLACEHOLDER}",
        safe_html=f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
        model_id="reviewed-model",
    )
    generated_template = _template(
        subject=generated.subject,
        plain_text=generated.plain_text,
        safe_html=generated.safe_html,
    )

    for template in (seed, generated_template):
        result, _session, _audit = _decide(template, dm.ApprovalDecision.APPROVED)
        assert result["approval_state"] == "approved"


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=_HMAC,
        ciphertext_kek=_KEK,
        console_jwt_secret=_CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
    )


def _headers(settings: OperatorApiSettings) -> dict[str, str]:
    token = jwt.encode(
        {
            "sub": str(_REVIEWER_ID),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["security_approver"]},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def test_api_failed_approval_is_stable_and_has_no_side_effects() -> None:
    settings = _settings()
    template = _template(
        plain_text="SECRET-INCOMPLETE-CANONICAL-CONTENT",
        raw_proposal={
            "subject": "Raw proposal looks complete",
            "plain_text": f"Review {TRAINING_URL_PLACEHOLDER}",
            "requested_by": str(_REQUESTER_ID),
        },
    )
    session = _Session(template)
    audit = _Audit()
    app = create_app(settings)
    app.state.audit_health_check = lambda: True

    def session_override() -> Iterator[_Session]:
        yield session

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_audit_store] = lambda: audit
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/templates/{template.template_version_id}/decision",
            json={"decision": "approved", "rationale": "Reviewed"},
            headers=_headers(settings),
        )

    assert response.status_code == 422
    assert response.json() == {"code": "KP-001", "detail": f"KP-001: {_ERROR}"}
    assert "SECRET" not in response.text
    assert template.approval_state == dm.TemplateApprovalState.DRAFT
    assert session.commits == 0
    assert audit.events == []
