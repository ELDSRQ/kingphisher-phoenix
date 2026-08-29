"""Bounded recurring campaign program materialization.

Programs deliberately do not introduce a scheduler or copy authorization
evidence.  Creating a program materializes a small, finite set of campaign
drafts in the caller's transaction.  Every future occurrence must pass the
existing audience freeze, approval, Rules-of-Engagement, and schedule gates.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError, ValidationError_
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kp_database.campaign_service import (
    audience_definition,
    audience_definition_hash,
    campaign_content_manifest_hash,
    require_bound_training_resource,
)
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignPattern,
    CampaignProgram,
    CampaignProgramOccurrence,
    TemplateVersion,
)

ALLOWED_PROGRAM_CADENCE_DAYS = frozenset({7, 14, 28, 84})
MIN_PROGRAM_OCCURRENCES = 2
MAX_PROGRAM_OCCURRENCES = 12
MAX_PROGRAM_HORIZON_DAYS = 366

_TERMINAL_CAMPAIGN_STATES = frozenset(
    {
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.RECALLED,
        dm.CampaignState.REJECTED,
        dm.CampaignState.STOPPED,
    }
)


@dataclass(frozen=True)
class CampaignProgramMaterialization:
    program: CampaignProgram
    occurrences: tuple[CampaignProgramOccurrence, ...]
    created: bool


def _require_aware(value: datetime | None, *, label: str) -> datetime:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError_(f"source campaign {label} must include a timezone offset")
    return value.astimezone(UTC)


def _validate_program_shape(cadence_days: int, occurrence_count: int) -> None:
    if type(cadence_days) is not int or cadence_days not in ALLOWED_PROGRAM_CADENCE_DAYS:
        allowed = ", ".join(str(item) for item in sorted(ALLOWED_PROGRAM_CADENCE_DAYS))
        raise ValidationError_(f"cadence_days must be one of: {allowed}")
    if type(occurrence_count) is not int or not MIN_PROGRAM_OCCURRENCES <= occurrence_count <= MAX_PROGRAM_OCCURRENCES:
        raise ValidationError_(
            f"occurrence_count must be between {MIN_PROGRAM_OCCURRENCES} and {MAX_PROGRAM_OCCURRENCES}"
        )


def _configuration_hash(
    source: Campaign,
    audience: CampaignAudience,
    pattern: CampaignPattern,
    template: TemplateVersion,
    *,
    cadence_days: int,
    occurrence_count: int,
) -> str:
    payload = {
        "audience_configuration_hash": audience.configuration_hash,
        "cadence_days": cadence_days,
        "current_template_id": str(source.current_template_id) if source.current_template_id else None,
        "difficulty": source.difficulty or {},
        "max_recipients": source.max_recipients,
        "occurrence_count": occurrence_count,
        "pattern": {
            "approval_state": pattern.approval_state.value,
            "attack_mapping": pattern.attack_mapping or {},
            "campaign_pattern_id": str(pattern.campaign_pattern_id),
            "delivery_method": pattern.delivery_method,
            "emotional_triggers": pattern.emotional_triggers or [],
            "impersonation_category": pattern.impersonation_category,
            "lure_category": pattern.lure_category.value,
            "pattern_version": pattern.pattern_version,
            "prohibited_content_indicators": pattern.prohibited_content_indicators or [],
            "requested_action": pattern.requested_action,
            "warning_cues": pattern.warning_cues or [],
        },
        "retention_policy_id": str(source.retention_policy_id) if source.retention_policy_id else None,
        "schedule_end": _require_aware(source.schedule_end, label="schedule end").isoformat(),
        "schedule_start": _require_aware(source.schedule_start, label="schedule start").isoformat(),
        "sender_display_name": source.sender_display_name,
        "sender_mailbox": source.sender_mailbox,
        "source_campaign_id": str(source.campaign_id),
        "source_manifest_hash": source.manifest_hash,
        "template": {
            "approval_hash": template.approval_hash,
            "approval_state": template.approval_state.value,
            "edited_content": template.edited_content,
            "input_hash": template.input_hash,
            "learning_objectives": template.learning_objectives or [],
            "plain_text": template.plain_text,
            "safe_html": template.safe_html,
            "subject": template.subject,
            "synthetic_sender_display": template.synthetic_sender_display,
            "template_version_id": str(template.template_version_id),
            "training_explanation": template.training_explanation,
            "unicode_validation": template.unicode_validation or {},
            "version": template.version,
            "warning_cues": template.warning_cues or [],
        },
        "timezone": source.timezone,
        "training_domain": source.training_domain,
        "training_resource": {
            "content_digest": source.training_resource_digest,
            "training_resource_id": (
                str(source.training_resource_id) if source.training_resource_id is not None else None
            ),
            "version": source.training_resource_version,
        },
    }
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reviewed_source_audience(session: Session, source: Campaign) -> CampaignAudience:
    source_audience = session.get(CampaignAudience, source.campaign_id)
    if (
        source_audience is None
        or source_audience.legacy_requires_configuration
        or source_audience.frozen_at is None
        or source_audience.manifest_hash is None
    ):
        raise ConflictError("a program requires a frozen source campaign audience")
    calculated_hash = audience_definition_hash(audience_definition(source_audience))
    if source_audience.configuration_hash != calculated_hash:
        raise ConflictError("source campaign audience configuration hash is inconsistent")
    return source_audience


def _approved_source_content(session: Session, source: Campaign) -> tuple[CampaignPattern, TemplateVersion]:
    pattern = session.get(CampaignPattern, source.pattern_id)
    if pattern is None or pattern.approval_state is not dm.PatternApprovalState.APPROVED:
        raise ConflictError("a program requires an approved source campaign pattern")
    if source.current_template_id is None:
        raise ConflictError("a program requires an approved source campaign template")
    template = session.get(TemplateVersion, source.current_template_id)
    if template is None or template.approval_state is not dm.TemplateApprovalState.APPROVED:
        raise ConflictError("a program requires an approved source campaign template")
    return pattern, template


def _occurrence_title(source_title: str, occurrence_number: int, occurrence_count: int) -> str:
    suffix = f" · Run {occurrence_number} of {occurrence_count}"
    return f"{source_title[: 255 - len(suffix)].rstrip()}{suffix}"


def _copy_unfrozen_audience(source: CampaignAudience, campaign_id: uuid.UUID) -> CampaignAudience:
    definition = audience_definition(source)
    return CampaignAudience(
        campaign_id=campaign_id,
        version=1,
        group_ids=[str(item) for item in definition.group_ids],
        departments=list(definition.departments),
        statuses=[item.value for item in definition.statuses],
        include_recipient_ids=[str(item) for item in definition.include_recipient_ids],
        exclude_recipient_ids=[str(item) for item in definition.exclude_recipient_ids],
        sample_size=definition.sample_size,
        sample_seed=definition.sample_seed,
        configuration_hash=audience_definition_hash(definition),
        preview_hash=None,
        manifest_hash=None,
        frozen_at=None,
        legacy_requires_configuration=False,
    )


def _program_occurrences(session: Session, program_id: uuid.UUID) -> tuple[CampaignProgramOccurrence, ...]:
    return tuple(
        session.scalars(
            select(CampaignProgramOccurrence)
            .where(CampaignProgramOccurrence.campaign_program_id == program_id)
            .order_by(CampaignProgramOccurrence.occurrence_number)
        )
    )


def materialize_campaign_program(
    session: Session,
    *,
    source_campaign_id: uuid.UUID,
    cadence_days: int,
    occurrence_count: int,
    created_by: uuid.UUID | None,
    now: datetime | None = None,
) -> CampaignProgramMaterialization:
    """Create every occurrence in one caller-owned transaction.

    Locking the unique source campaign serializes concurrent creation on
    PostgreSQL.  A replay with the same source and shape returns the existing
    program; a replay that changes cadence or count fails closed.
    """

    _validate_program_shape(cadence_days, occurrence_count)
    current_time = _require_aware(now or datetime.now(UTC), label="materialization time")
    source = session.scalar(select(Campaign).where(Campaign.campaign_id == source_campaign_id).with_for_update())
    if source is None:
        raise NotFoundError("source campaign not found")

    existing = session.scalar(select(CampaignProgram).where(CampaignProgram.source_campaign_id == source_campaign_id))
    if existing is not None:
        if existing.cadence_days != cadence_days or existing.occurrence_count != occurrence_count:
            raise ConflictError("source campaign already belongs to a different program configuration")
        source_audience = _reviewed_source_audience(session, source)
        pattern, template = _approved_source_content(session, source)
        require_bound_training_resource(session, source)
        current_hash = _configuration_hash(
            source,
            source_audience,
            pattern,
            template,
            cadence_days=cadence_days,
            occurrence_count=occurrence_count,
        )
        if existing.configuration_hash != current_hash:
            raise ConflictError("source campaign configuration changed after the program was created")
        return CampaignProgramMaterialization(
            existing,
            _program_occurrences(session, existing.campaign_program_id),
            False,
        )

    if source.state is not dm.CampaignState.SCHEDULED:
        raise ConflictError("a program requires a scheduled source campaign")
    if source.roe_id is None:
        raise ConflictError("a program requires a Rules-of-Engagement-bound source campaign")
    pattern, template = _approved_source_content(session, source)
    require_bound_training_resource(session, source)
    schedule_start = _require_aware(source.schedule_start, label="schedule start")
    schedule_end = _require_aware(source.schedule_end, label="schedule end")
    if schedule_end <= schedule_start:
        raise ValidationError_("source campaign schedule end must be after its start")
    if schedule_start <= current_time:
        raise ConflictError("a program requires a source campaign that has not started")
    final_end = schedule_end + timedelta(days=cadence_days * (occurrence_count - 1))
    if final_end > schedule_start + timedelta(days=MAX_PROGRAM_HORIZON_DAYS):
        raise ValidationError_(f"program must end within {MAX_PROGRAM_HORIZON_DAYS} days of its first start")

    source_audience = _reviewed_source_audience(session, source)

    program_id = uuid.uuid4()
    program = CampaignProgram(
        campaign_program_id=program_id,
        source_campaign_id=source_campaign_id,
        state=dm.CampaignProgramState.ACTIVE,
        version=1,
        cadence_days=cadence_days,
        occurrence_count=occurrence_count,
        configuration_hash=_configuration_hash(
            source,
            source_audience,
            pattern,
            template,
            cadence_days=cadence_days,
            occurrence_count=occurrence_count,
        ),
        created_by=created_by,
    )
    session.add(program)

    occurrences: list[CampaignProgramOccurrence] = []
    for occurrence_number in range(1, occurrence_count + 1):
        offset = timedelta(days=cadence_days * (occurrence_number - 1))
        occurrence_start = schedule_start + offset
        occurrence_end = schedule_end + offset
        if occurrence_number == 1:
            campaign_id = source_campaign_id
        else:
            campaign_id = uuid.uuid4()
            campaign = Campaign(
                campaign_id=campaign_id,
                pattern_id=source.pattern_id,
                current_template_id=source.current_template_id,
                title=_occurrence_title(source.title, occurrence_number, occurrence_count),
                state=dm.CampaignState.DRAFT,
                sender_mailbox=source.sender_mailbox,
                sender_display_name=source.sender_display_name,
                training_domain=source.training_domain,
                schedule_start=occurrence_start,
                schedule_end=occurrence_end,
                timezone=source.timezone,
                max_recipients=source.max_recipients,
                retention_policy_id=source.retention_policy_id,
                training_resource_id=source.training_resource_id,
                training_resource_version=source.training_resource_version,
                training_resource_digest=source.training_resource_digest,
                difficulty=copy.deepcopy(source.difficulty or {}),
                manifest_hash=None,
                created_by=created_by,
                expires_at=occurrence_end,
            )
            campaign.manifest_hash = campaign_content_manifest_hash(campaign)
            session.add_all([campaign, _copy_unfrozen_audience(source_audience, campaign_id)])
        occurrence = CampaignProgramOccurrence(
            campaign_program_occurrence_id=uuid.uuid4(),
            campaign_program_id=program_id,
            occurrence_number=occurrence_number,
            campaign_id=campaign_id,
            schedule_start=occurrence_start,
            schedule_end=occurrence_end,
        )
        session.add(occurrence)
        occurrences.append(occurrence)

    session.flush()
    return CampaignProgramMaterialization(program, tuple(occurrences), True)


def get_campaign_program(
    session: Session,
    program_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> CampaignProgram:
    statement = select(CampaignProgram).where(CampaignProgram.campaign_program_id == program_id)
    if for_update:
        statement = statement.with_for_update()
    program = session.scalar(statement)
    if program is None:
        raise NotFoundError("campaign program not found")
    return program


def list_campaign_program_occurrences(session: Session, program_id: uuid.UUID) -> tuple[CampaignProgramOccurrence, ...]:
    get_campaign_program(session, program_id)
    return _program_occurrences(session, program_id)


def campaign_program_is_complete(session: Session, program_id: uuid.UUID) -> bool:
    get_campaign_program(session, program_id)
    nonterminal = session.scalar(
        select(func.count())
        .select_from(CampaignProgramOccurrence)
        .join(Campaign, Campaign.campaign_id == CampaignProgramOccurrence.campaign_id)
        .where(
            CampaignProgramOccurrence.campaign_program_id == program_id,
            Campaign.state.not_in(_TERMINAL_CAMPAIGN_STATES),
        )
    )
    return int(nonterminal or 0) == 0


def set_campaign_program_state(
    session: Session,
    *,
    program_id: uuid.UUID,
    state: dm.CampaignProgramState,
    expected_version: int,
    now: datetime | None = None,
) -> tuple[CampaignProgram, bool]:
    if type(expected_version) is not int or expected_version < 1:
        raise ValidationError_("expected_version must be a positive integer")
    if not isinstance(state, dm.CampaignProgramState):
        raise ValidationError_("campaign program state must be active or paused")
    current_time = _require_aware(now or datetime.now(UTC), label="state transition time")
    program = get_campaign_program(session, program_id, for_update=True)
    if program.version != expected_version:
        raise ConflictError("campaign program changed; reload it before retrying")
    if campaign_program_is_complete(session, program_id):
        raise ConflictError("a completed campaign program cannot be paused or resumed")
    if program.state is state:
        return program, False
    program.state = state
    program.version += 1
    program.updated_at = current_time
    session.flush()
    return program, True


def require_program_active_for_schedule(session: Session, campaign_id: uuid.UUID) -> CampaignProgram | None:
    """Fail closed when an occurrence belongs to a paused program.

    This is a forward scheduling gate. It intentionally does not claim to
    recall delivery work that was already scheduled before the pause.
    """

    program = session.scalar(
        select(CampaignProgram)
        .join(
            CampaignProgramOccurrence,
            CampaignProgramOccurrence.campaign_program_id == CampaignProgram.campaign_program_id,
        )
        .where(CampaignProgramOccurrence.campaign_id == campaign_id)
        .with_for_update(read=True)
    )
    if program is not None and program.state is dm.CampaignProgramState.PAUSED:
        raise ConflictError("campaign program is paused; resume it before scheduling this occurrence")
    return program
