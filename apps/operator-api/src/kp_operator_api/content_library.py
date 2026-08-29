"""Bounded template and campaign-pattern library endpoints."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import CampaignPattern, TemplateVersion
from kp_domain_models import models as dm
from kp_safety_validation.validator import SafetyValidator
from kp_telemetry.errors import NotFoundError, SafetyRejectionError, ValidationError_
from kp_templating.render import MessageRenderer
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.deps import get_audit_store, get_session

_renderer = MessageRenderer()
_COLLECTION_MAX_OFFSET = 10_000

_SAFETY_REASON_CODES: tuple[tuple[str, str], ...] = (
    ("obfuscation:", "obfuscated_content"),
    ("active HTML element", "active_html"),
    ("HTML event handler", "active_html"),
    ("URL shortener:", "disallowed_link"),
    ("external IP link", "disallowed_link"),
    ("external link", "disallowed_link"),
    ("credential/MFA request", "credential_request"),
    ("attachment/executable", "unsafe_attachment"),
    ("command-execution", "command_execution"),
    ("software-installation", "software_installation"),
    ("financial-transfer", "financial_transfer"),
    ("sensitive employee scenario", "sensitive_employee_scenario"),
    ("javascript:", "active_content"),
    ("data:/file:/vbscript:", "active_content"),
    ("macro content", "active_content"),
    ("QR code content", "qr_code"),
    ("disallowed attachment:", "unsafe_attachment"),
)


class TemplatePreview(BaseModel):
    subject: str = Field(default="", max_length=998)
    plain_text: str = Field(default="", max_length=200_000)
    safe_html: str = Field(default="", max_length=200_000)


class ContentClone(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _template_content(template: TemplateVersion) -> TemplatePreview:
    proposal = template.raw_proposal or {}

    def value(column: str | None, key: str) -> str:
        candidate = column if column is not None else proposal.get(key, "")
        if not isinstance(candidate, str):
            raise ValidationError_(f"template {key} is malformed")
        return candidate

    try:
        return TemplatePreview(
            subject=value(template.subject, "subject"),
            plain_text=value(template.plain_text, "plain_text"),
            safe_html=value(template.safe_html, "safe_html"),
        )
    except ValueError as exc:
        raise ValidationError_("template content exceeds the supported preview boundary") from exc


def _principal_uuid(principal: Principal) -> uuid.UUID:
    """Return the canonical caller UUID used by author/reviewer boundaries."""

    try:
        return uuid.UUID(principal.principal_id)
    except ValueError as exc:
        # Authentication rejects this before a route runs. Keep direct calls
        # fail-closed as well and do not reflect the opaque identifier.
        raise ValidationError_("authenticated principal identifier is invalid") from exc


def _pattern_action_flags(pattern: CampaignPattern, principal: Principal) -> dict[str, bool]:
    """Derive pattern actions without exposing creator or reviewer identity."""

    is_creator = pattern.created_by == _principal_uuid(principal)
    return {
        "can_clone": bool(principal.can(Capability.CREATE_CAMPAIGN) and not pattern.prohibited_content_indicators),
        "can_approve": bool(
            principal.can(Capability.APPROVE_PATTERN)
            and not is_creator
            and not pattern.prohibited_content_indicators
            and pattern.approval_state in {dm.PatternApprovalState.DRAFT, dm.PatternApprovalState.PENDING}
        ),
    }


def _validate_template_content(session: Session, content: TemplatePreview) -> None:
    validator = session.info.get("safety_validator")
    if not isinstance(validator, SafetyValidator):
        raise HTTPException(status_code=503, detail="template safety validator is unavailable")
    verdict = validator.validate(content.subject, content.plain_text, content.safe_html)
    if not verdict.allowed:
        reason_codes = {
            code for reason in verdict.reasons for prefix, code in _SAFETY_REASON_CODES if reason.startswith(prefix)
        }
        if not reason_codes:
            reason_codes = {"unsafe_content"}
        raise SafetyRejectionError(
            "template content failed deterministic safety validation: " + ", ".join(sorted(reason_codes))
        )


def _render_template_preview(body: TemplatePreview, request: Request) -> dict[str, Any]:
    """Render with fixed synthetic contexts and return HTML only as inert JSON text.

    The authoring API preserves the rendered ``safe_html`` string for its public
    response contract. It never emits an HTML response; clients must not inject
    the value into an executable document.
    """
    from kp_templating.render import CampaignContext, RecipientContext, TrackingContext

    tracking_base = request.app.state.settings.tracking_base_url.rstrip("/")
    sample_hash = "preview-" + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    recipient = RecipientContext(
        first_name="Sample", last_name="Employee", department="Engineering", email="sample@example.com"
    )
    campaign_ctx = CampaignContext(
        title="Preview campaign", sender_display="IT Security", training_domain="training.local"
    )
    tracking = TrackingContext(
        open_url=f"{tracking_base}/v1/track/open/{sample_hash}",
        click_url=f"{tracking_base}/v1/track/click/{sample_hash}",
        training_url=request.app.state.settings.training_base_url,
    )
    try:
        subject = _renderer.render(
            body.subject,
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
        plain_text = _renderer.render(
            body.plain_text,
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
        # Render to prove the sanitized alternative has no invalid template
        # variables. It is deliberately withheld so the console cannot execute it.
        rendered_html = _renderer.render(
            body.safe_html,
            recipient=recipient,
            campaign=campaign_ctx,
            tracking=tracking,
            sender_email="sender@example.com",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="template contains unsupported or malformed rendering syntax",
        ) from exc
    return {
        "subject": subject,
        "plain_text": plain_text,
        "safe_html": rendered_html,
        "safe_html_present": bool(rendered_html),
        "html_execution": False,
    }


def preview_template(
    body: TemplatePreview,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_TEMPLATE)),
) -> dict[str, Any]:
    del principal
    _validate_template_content(session, body)
    return _render_template_preview(body, request)


def list_templates(
    q: str | None = Query(default=None, min_length=1, max_length=100),
    approval_state: dm.TemplateApprovalState | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_TEMPLATE)),
) -> list[dict[str, Any]]:
    del principal
    statement = select(TemplateVersion)
    if approval_state is not None:
        statement = statement.where(TemplateVersion.approval_state == approval_state)
    if q is not None:
        term = q.strip()
        if not term:
            raise ValidationError_("template search cannot be blank")
        match = f"%{term.replace('%', r'\%').replace('_', r'\_')}%"
        statement = statement.where(
            or_(
                TemplateVersion.subject.ilike(match, escape="\\"),
                TemplateVersion.plain_text.ilike(match, escape="\\"),
                TemplateVersion.model_id.ilike(match, escape="\\"),
                TemplateVersion.raw_proposal["subject"].as_string().ilike(match, escape="\\"),
                TemplateVersion.raw_proposal["plain_text"].as_string().ilike(match, escape="\\"),
            )
        )
    rows = list(
        session.scalars(statement.order_by(TemplateVersion.template_version_id.desc()).offset(offset).limit(limit))
    )
    return [
        {
            "template_version_id": str(t.template_version_id),
            "version": t.version,
            "subject": _template_content(t).subject,
            "model_id": t.model_id,
            "approval_state": t.approval_state.value,
            "reusable": t.approval_state == dm.TemplateApprovalState.APPROVED,
            "campaign_bound": t.campaign_id is not None,
        }
        for t in rows
    ]


def list_patterns(
    q: str | None = Query(default=None, min_length=1, max_length=100),
    approval_state: dm.PatternApprovalState | None = Query(default=None),
    lure_category: dm.LureCategory | None = Query(default=None),
    difficulty_score: int | None = Query(default=None, ge=1, le=5),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_PATTERN)),
) -> list[dict[str, Any]]:
    statement = select(CampaignPattern)
    if approval_state is not None:
        statement = statement.where(CampaignPattern.approval_state == approval_state)
    if lure_category is not None:
        statement = statement.where(CampaignPattern.lure_category == lure_category)
    if difficulty_score is not None:
        statement = statement.where(
            CampaignPattern.attack_mapping["difficulty"]["score"].as_integer() == difficulty_score
        )
    if q is not None:
        term = q.strip()
        if not term:
            raise ValidationError_("pattern search cannot be blank")
        match = f"%{term.replace('%', r'\%').replace('_', r'\_')}%"
        statement = statement.where(
            or_(
                CampaignPattern.impersonation_category.ilike(match, escape="\\"),
                CampaignPattern.target_role_category.ilike(match, escape="\\"),
                CampaignPattern.requested_action.ilike(match, escape="\\"),
                CampaignPattern.actor_type.ilike(match, escape="\\"),
                CampaignPattern.sector_targeting.ilike(match, escape="\\"),
            )
        )
    rows = list(
        session.scalars(statement.order_by(CampaignPattern.campaign_pattern_id.desc()).offset(offset).limit(limit))
    )
    return [
        {
            "campaign_pattern_id": str(p.campaign_pattern_id),
            "lure_category": p.lure_category.value,
            "approval_state": p.approval_state.value,
            "difficulty_score": (p.attack_mapping or {}).get("difficulty", {}).get("score"),
            "reusable": p.approval_state == dm.PatternApprovalState.APPROVED,
            **_pattern_action_flags(p, principal),
        }
        for p in rows
    ]


def _json_clone(value: Any, *, label: str) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValidationError_(f"{label} exceeds the supported clone boundary")
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValidationError_(f"{label} is malformed") from exc


def _pattern_preview(pattern: CampaignPattern) -> dict[str, Any]:
    mapping = pattern.attack_mapping or {}
    difficulty = mapping.get("difficulty", {}) if isinstance(mapping, dict) else {}
    techniques = mapping.get("attack_techniques", []) if isinstance(mapping, dict) else []
    return {
        "campaign_pattern_id": str(pattern.campaign_pattern_id),
        "pattern_version": pattern.pattern_version,
        "lure_category": pattern.lure_category.value,
        "approval_state": pattern.approval_state.value,
        "impersonation_category": pattern.impersonation_category,
        "target_role_category": pattern.target_role_category,
        "emotional_triggers": _json_clone(pattern.emotional_triggers or [], label="emotional triggers"),
        "requested_action": pattern.requested_action,
        "delivery_method": pattern.delivery_method,
        "warning_cues": _json_clone(pattern.warning_cues or [], label="warning cues"),
        "actor_type": pattern.actor_type,
        "sector_targeting": pattern.sector_targeting,
        "difficulty": _json_clone(difficulty, label="difficulty"),
        "attack_techniques": _json_clone(techniques, label="attack techniques"),
        "confidence": pattern.confidence.value,
    }


def preview_library_pattern(
    pattern_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_PATTERN)),
) -> dict[str, Any]:
    pattern = session.get(CampaignPattern, pattern_id)
    if pattern is None:
        raise NotFoundError("pattern not found")
    return {**_pattern_preview(pattern), **_pattern_action_flags(pattern, principal)}


def clone_pattern(
    pattern_id: uuid.UUID,
    body: ContentClone,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    source = session.get(CampaignPattern, pattern_id)
    if source is None:
        raise NotFoundError("pattern not found")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("clone reason is required")
    if source.prohibited_content_indicators:
        raise SafetyRejectionError("pattern contains prohibited-content indicators and cannot be cloned")
    preview = _pattern_preview(source)
    clone = CampaignPattern(
        campaign_pattern_id=uuid.uuid4(),
        pattern_version=1,
        lure_category=source.lure_category,
        impersonation_category=source.impersonation_category,
        target_role_category=source.target_role_category,
        emotional_triggers=preview["emotional_triggers"],
        requested_action=source.requested_action,
        delivery_method=source.delivery_method,
        warning_cues=preview["warning_cues"],
        actor_type=source.actor_type,
        sector_targeting=source.sector_targeting,
        attack_mapping={
            "difficulty": preview["difficulty"],
            "attack_techniques": preview["attack_techniques"],
        },
        confidence=source.confidence,
        supporting_evidence=[],
        prohibited_content_indicators=[],
        approval_state=dm.PatternApprovalState.DRAFT,
        approved_by=None,
        approved_at=None,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    session.add(clone)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="pattern.clone",
        object_type="campaign_pattern",
        object_id=str(clone.campaign_pattern_id),
        detail={"source_pattern_id": str(source.campaign_pattern_id), "reason": reason, "approval_reset": True},
    )
    session.commit()
    return {
        "campaign_pattern_id": str(clone.campaign_pattern_id),
        "approval_state": clone.approval_state.value,
        "requires_human_review": True,
    }


def preview_library_template(
    template_version_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_TEMPLATE)),
) -> dict[str, Any]:
    del principal
    template = session.get(TemplateVersion, template_version_id)
    if template is None:
        raise NotFoundError("template not found")
    content = _template_content(template)
    _validate_template_content(session, content)
    rendered = _render_template_preview(content, request)
    rendered.pop("safe_html", None)
    return {
        "template_version_id": str(template.template_version_id),
        "approval_state": template.approval_state.value,
        **rendered,
    }


def clone_template(
    template_version_id: uuid.UUID,
    body: ContentClone,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    source = session.get(TemplateVersion, template_version_id)
    if source is None:
        raise NotFoundError("template not found")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("clone reason is required")
    content = _template_content(source)
    _validate_template_content(session, content)
    sender_display = source.synthetic_sender_display
    if sender_display and (len(sender_display) > 255 or "\r" in sender_display or "\n" in sender_display):
        raise SafetyRejectionError("template sender display is unsafe")
    clone_id = uuid.uuid4()
    clone = TemplateVersion(
        template_version_id=clone_id,
        campaign_id=None,
        version=1,
        idempotency_key=None,
        generator_version=source.generator_version,
        prompt_template_version=source.prompt_template_version,
        model_id=source.model_id,
        input_hash=hashlib.sha256(
            json.dumps(content.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        raw_proposal={
            "subject": content.subject,
            "plain_text": content.plain_text,
            "safe_html": content.safe_html,
            "requested_by": principal.principal_id,
        },
        edited_content=None,
        safe_html=content.safe_html,
        plain_text=content.plain_text,
        subject=content.subject,
        synthetic_sender_display=sender_display,
        learning_objectives=_json_clone(source.learning_objectives or [], label="learning objectives"),
        warning_cues=_json_clone(source.warning_cues or [], label="template warning cues"),
        training_explanation=source.training_explanation,
        approval_hash=None,
        approval_state=dm.TemplateApprovalState.DRAFT,
        unicode_validation={},
    )
    session.add(clone)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="template.clone",
        object_type="template",
        object_id=str(clone_id),
        detail={"source_template_id": str(source.template_version_id), "reason": reason, "approval_reset": True},
    )
    session.commit()
    return {
        "template_version_id": str(clone.template_version_id),
        "approval_state": clone.approval_state.value,
        "campaign_bound": False,
        "requires_human_review": True,
    }


def register_routes(parent: APIRouter) -> None:
    """Register a flat route set on the existing versioned aggregate router.

    FastAPI 0.135 keeps nested routers as ``_IncludedRouter`` entries. The
    operator router's route-introspection contracts require concrete
    ``APIRoute`` objects, so use the public registration API here.
    """
    parent.add_api_route(
        "/templates/preview",
        preview_template,
        methods=["POST"],
        status_code=status.HTTP_200_OK,
    )
    parent.add_api_route("/templates", list_templates, methods=["GET"])
    parent.add_api_route("/patterns", list_patterns, methods=["GET"])
    parent.add_api_route(
        "/patterns/{pattern_id}/preview",
        preview_library_pattern,
        methods=["GET"],
        status_code=status.HTTP_200_OK,
    )
    parent.add_api_route(
        "/patterns/{pattern_id}/clone",
        clone_pattern,
        methods=["POST"],
        status_code=status.HTTP_201_CREATED,
    )
    parent.add_api_route(
        "/templates/{template_version_id}/preview",
        preview_library_template,
        methods=["GET"],
        status_code=status.HTTP_200_OK,
    )
    parent.add_api_route(
        "/templates/{template_version_id}/clone",
        clone_template,
        methods=["POST"],
        status_code=status.HTTP_201_CREATED,
    )
