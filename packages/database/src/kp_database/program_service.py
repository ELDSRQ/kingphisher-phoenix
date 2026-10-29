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
from typing import Any

from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError, ValidationError_
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kp_database.campaign_service import (
    AudienceDefinition,
    _excluded_recipient_ids,
    audience_definition,
    audience_definition_hash,
    campaign_content_manifest_hash,
    require_bound_training_resource,
)
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignPattern,
    CampaignProgram,
    CampaignProgramAdaptation,
    CampaignProgramOccurrence,
    RecipientAssignment,
    TemplateVersion,
    TrackingEvent,
    TrackingToken,
)
from kp_database.reporting import (
    SINGLE_TENANT_DATABASE_SCOPE,
    campaign_funnel,
    payload_automation_suspected,
)

#: W4-03 generation modes. ``fixed_schedule`` is the original eager behavior;
#: ``adaptive`` defers every iteration past the source to worker-driven,
#: cue-adaptive DRAFT generation.
GENERATION_MODE_FIXED = "fixed_schedule"
GENERATION_MODE_ADAPTIVE = "adaptive"
ALLOWED_PROGRAM_GENERATION_MODES = frozenset({GENERATION_MODE_FIXED, GENERATION_MODE_ADAPTIVE})

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
    generation_mode: str = GENERATION_MODE_FIXED,
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
    if generation_mode != GENERATION_MODE_FIXED:
        # Backward compatible: fixed-schedule programs keep their original
        # fingerprint, so pre-W4-03 rows still replay idempotently.
        payload["generation_mode"] = generation_mode
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


def _build_iteration_campaign(
    source: Campaign,
    *,
    campaign_id: uuid.UUID,
    occurrence_number: int,
    occurrence_count: int,
    occurrence_start: datetime,
    occurrence_end: datetime,
    created_by: uuid.UUID | None,
    difficulty: dict[str, Any],
) -> Campaign:
    """Build one DRAFT iteration campaign copied from the reviewed source.

    State is always DRAFT: an iteration carries no approval, launch gate, or
    RoE binding of its own and must earn them through the normal path before it
    can ever be scheduled or sent.
    """

    campaign = Campaign(
        campaign_id=campaign_id,
        pattern_id=source.pattern_id,
        delivery_mode=getattr(source, "delivery_mode", None) or "canary",
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
        difficulty=difficulty,
        manifest_hash=None,
        created_by=created_by,
        expires_at=occurrence_end,
    )
    campaign.manifest_hash = campaign_content_manifest_hash(campaign)
    return campaign


def _program_occurrences(session: Session, program_id: uuid.UUID) -> tuple[CampaignProgramOccurrence, ...]:
    return tuple(
        session.scalars(
            select(CampaignProgramOccurrence)
            .where(CampaignProgramOccurrence.campaign_program_id == program_id)
            .order_by(CampaignProgramOccurrence.occurrence_number)
        )
    )


def _validate_generation_mode(generation_mode: str) -> None:
    if generation_mode not in ALLOWED_PROGRAM_GENERATION_MODES:
        allowed = ", ".join(sorted(ALLOWED_PROGRAM_GENERATION_MODES))
        raise ValidationError_(f"generation_mode must be one of: {allowed}")


def materialize_campaign_program(
    session: Session,
    *,
    source_campaign_id: uuid.UUID,
    cadence_days: int,
    occurrence_count: int,
    created_by: uuid.UUID | None,
    generation_mode: str = GENERATION_MODE_FIXED,
    now: datetime | None = None,
) -> CampaignProgramMaterialization:
    """Create the program's occurrences in one caller-owned transaction.

    Locking the unique source campaign serializes concurrent creation on
    PostgreSQL.  A replay with the same source and shape returns the existing
    program; a replay that changes cadence, count, or mode fails closed.

    ``fixed_schedule`` (the default) eagerly materializes the whole reviewed
    timeline as independent DRAFT occurrences.  ``adaptive`` materializes only
    the source occurrence here; later iterations are generated over time by
    :func:`materialize_next_program_iteration` as each prior iteration
    completes.  Neither mode ever sends or approves: every later iteration is a
    DRAFT that must clear the normal approval + RoE + schedule gates.
    """

    _validate_program_shape(cadence_days, occurrence_count)
    _validate_generation_mode(generation_mode)
    current_time = _require_aware(now or datetime.now(UTC), label="materialization time")
    source = session.scalar(select(Campaign).where(Campaign.campaign_id == source_campaign_id).with_for_update())
    if source is None:
        raise NotFoundError("source campaign not found")

    existing = session.scalar(select(CampaignProgram).where(CampaignProgram.source_campaign_id == source_campaign_id))
    if existing is not None:
        if (
            existing.cadence_days != cadence_days
            or existing.occurrence_count != occurrence_count
            or existing.generation_mode != generation_mode
        ):
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
            generation_mode=generation_mode,
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
        generation_mode=generation_mode,
        configuration_hash=_configuration_hash(
            source,
            source_audience,
            pattern,
            template,
            cadence_days=cadence_days,
            occurrence_count=occurrence_count,
            generation_mode=generation_mode,
        ),
        created_by=created_by,
    )
    session.add(program)

    # Adaptive programs materialize only the human-made source occurrence here;
    # every later DRAFT iteration is generated over time, after the prior one
    # completes, by ``materialize_next_program_iteration``.
    materialized_count = occurrence_count if generation_mode == GENERATION_MODE_FIXED else 1

    occurrences: list[CampaignProgramOccurrence] = []
    for occurrence_number in range(1, materialized_count + 1):
        offset = timedelta(days=cadence_days * (occurrence_number - 1))
        occurrence_start = schedule_start + offset
        occurrence_end = schedule_end + offset
        if occurrence_number == 1:
            campaign_id = source_campaign_id
        else:
            campaign_id = uuid.uuid4()
            campaign = _build_iteration_campaign(
                source,
                campaign_id=campaign_id,
                occurrence_number=occurrence_number,
                occurrence_count=occurrence_count,
                occurrence_start=occurrence_start,
                occurrence_end=occurrence_end,
                created_by=created_by,
                difficulty=copy.deepcopy(source.difficulty or {}),
            )
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
    program = get_campaign_program(session, program_id)
    materialized = int(
        session.scalar(
            select(func.count())
            .select_from(CampaignProgramOccurrence)
            .where(CampaignProgramOccurrence.campaign_program_id == program_id)
        )
        or 0
    )
    # An adaptive program whose later iterations have not been generated yet is
    # not complete, even if every materialized occurrence is terminal. For a
    # fixed program every occurrence is materialized up front, so this is a
    # no-op there.
    if materialized < program.occurrence_count:
        return False
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


# ---------------------------------------------------------------------------
# W4-03: adaptive iteration generation.
#
# An adaptive program's later iterations are materialized over time, one at a
# time, after each prior iteration completes. Generation is deterministic (AI is
# never required), explainable (every change records the prior signal that drove
# it), and strictly DRAFT-only: this code never approves, schedules, or sends,
# and nothing here can advance a campaign past DRAFT. Idempotency rests on the
# unique ``(campaign_program_id, occurrence_number)`` /
# ``(campaign_program_id, iteration_number)`` keys plus a row lock on the
# program, so a worker restart or duplicate delivery cannot double-generate.
# ---------------------------------------------------------------------------

#: An adaptive iteration is generated only once its immediately-prior iteration
#: has reached this terminal, results-bearing state. Nothing is autonomous: the
#: prior iteration only reaches COMPLETED through the normal human-run lifecycle.
_ADAPTATION_READY_PRIOR_STATES = frozenset({dm.CampaignState.COMPLETED})

MIN_ADAPTIVE_LEVEL = 1
MAX_ADAPTIVE_LEVEL = 5
#: Human-click rate (of accepted deliveries) at or above which the prior
#: iteration is treated as "too susceptible", so the next iteration eases off to
#: reinforce fundamentals rather than escalate.
_HIGH_SUSCEPTIBILITY_CLICK_RATE = 0.30


@dataclass(frozen=True)
class PriorIterationSignals:
    """Bounded, human-interaction signals read from a completed iteration."""

    accepted: int
    human_clicked: int
    automation_suspected_clicked: int
    reported: int

    @property
    def human_click_rate(self) -> float:
        return self.human_clicked / self.accepted if self.accepted > 0 else 0.0


@dataclass(frozen=True)
class AdaptationPlan:
    """A deterministic, explainable difficulty decision for one iteration."""

    prior_level: int
    next_level: int
    difficulty_delta: int
    rationale: str
    drivers: tuple[dict[str, Any], ...]


def _clamp_level(level: int) -> int:
    return max(MIN_ADAPTIVE_LEVEL, min(MAX_ADAPTIVE_LEVEL, level))


def plan_iteration_adaptation(prior_level: int, signals: PriorIterationSignals) -> AdaptationPlan:
    """Decide the next iteration's difficulty from the prior iteration's signals.

    Pure and deterministic: the same inputs always yield the same plan, and no
    model call is involved. Every change records the signal that drove it so the
    adaptation is explainable.
    """

    level = _clamp_level(prior_level)
    rate = signals.human_click_rate
    drivers: list[dict[str, Any]] = []
    delta = 0
    if signals.accepted > 0 and rate >= _HIGH_SUSCEPTIBILITY_CLICK_RATE:
        delta = -1
        drivers.append(
            {
                "signal": "human_click_rate",
                "value": round(rate, 4),
                "threshold": _HIGH_SUSCEPTIBILITY_CLICK_RATE,
                "change": "difficulty_delta",
                "delta": -1,
                "why": "prior human-click rate met/exceeded the susceptibility threshold; "
                "ease difficulty to reinforce fundamentals",
            }
        )
    elif signals.accepted > 0 and signals.human_clicked == 0 and signals.reported > 0:
        delta = 1
        drivers.append(
            {
                "signal": "reported_without_clicks",
                "reported": signals.reported,
                "human_clicked": 0,
                "change": "difficulty_delta",
                "delta": 1,
                "why": "prior iteration drew reports and zero human clicks; "
                "escalate difficulty to keep the population challenged",
            }
        )
    else:
        drivers.append(
            {
                "signal": "steady",
                "human_click_rate": round(rate, 4),
                "reported": signals.reported,
                "change": "difficulty_delta",
                "delta": 0,
                "why": "prior signals fell between thresholds; hold difficulty steady",
            }
        )
    if signals.automation_suspected_clicked > 0:
        # Record, but never let suspected automation move difficulty: it is an
        # exclusion signal (see enrollment), not a human-behavior signal.
        drivers.append(
            {
                "signal": "automation_suspected_clicked",
                "value": signals.automation_suspected_clicked,
                "change": "none",
                "delta": 0,
                "why": "suspected-automation clicks are excluded from behavior adaptation and from enrollment",
            }
        )
    next_level = _clamp_level(level + delta)
    effective_delta = next_level - level
    rationale = (
        f"adaptive_level {level} -> {next_level} (delta {effective_delta:+d}); "
        f"prior accepted={signals.accepted}, human_clicked={signals.human_clicked}, "
        f"reported={signals.reported}, automation_suspected_clicked={signals.automation_suspected_clicked}"
    )
    return AdaptationPlan(
        prior_level=level,
        next_level=next_level,
        difficulty_delta=effective_delta,
        rationale=rationale,
        drivers=tuple(drivers),
    )


@dataclass(frozen=True)
class IterationEnrollment:
    """The deterministic enrollment decision for one adaptive iteration."""

    enrolled: tuple[uuid.UUID, ...]
    excluded_opt_out: tuple[uuid.UUID, ...]
    excluded_scanner_only: tuple[uuid.UUID, ...]


def resolve_iteration_enrollment(
    base_recipient_ids: set[uuid.UUID] | frozenset[uuid.UUID],
    *,
    opt_out_ids: set[uuid.UUID] | frozenset[uuid.UUID],
    scanner_only_ids: set[uuid.UUID] | frozenset[uuid.UUID],
) -> IterationEnrollment:
    """Narrow the reviewed base population to the enrollable set.

    Honors opt-out/suppression and never enrolls a scanner-only recipient (one
    whose only prior signal is suspected automation). The scanner-only reason
    wins when a recipient is flagged both ways, so the no-scanner invariant is
    reported as such. Pure set logic; stable, sorted output.
    """

    base = set(base_recipient_ids)
    scanner = base & set(scanner_only_ids)
    opt_out = (base & set(opt_out_ids)) - scanner
    enrolled = base - scanner - opt_out

    def _sorted(ids: set[uuid.UUID]) -> tuple[uuid.UUID, ...]:
        return tuple(sorted(ids, key=str))

    return IterationEnrollment(
        enrolled=_sorted(enrolled),
        excluded_opt_out=_sorted(opt_out),
        excluded_scanner_only=_sorted(scanner),
    )


def _source_reviewed_recipient_ids(session: Session, source_campaign_id: uuid.UUID) -> set[uuid.UUID]:
    """The exact reviewed recipient population frozen on the source iteration."""

    rows = session.scalars(
        select(CampaignAudienceManifest.recipient_id).where(CampaignAudienceManifest.campaign_id == source_campaign_id)
    )
    return set(rows)


def _scanner_only_recipient_ids(session: Session, campaign_id: uuid.UUID) -> set[uuid.UUID]:
    """Recipients whose only prior click signal is suspected automation.

    Mirrors the reporting funnel's classification (W1-06/KP-AUD-014) at recipient
    granularity: a human click wins, so a recipient with any genuine click is
    never scanner-only. These recipients must never be enrolled or targeted as
    if human.
    """

    assignment_for_event = func.coalesce(
        TrackingEvent.recipient_assignment_id,
        TrackingToken.recipient_assignment_id,
    )
    rows = session.execute(
        select(RecipientAssignment.recipient_id, TrackingEvent.payload)
        .select_from(TrackingEvent)
        .outerjoin(TrackingToken, TrackingToken.token_id == TrackingEvent.token_id)
        .join(RecipientAssignment, RecipientAssignment.recipient_assignment_id == assignment_for_event)
        .where(
            RecipientAssignment.campaign_id == campaign_id,
            RecipientAssignment.provider_accepted_at.is_not(None),
            TrackingEvent.event_type == dm.EventType.CLICKED,
        )
    )
    human: set[uuid.UUID] = set()
    automation: set[uuid.UUID] = set()
    for recipient_id, payload in rows:
        if recipient_id is None:
            continue
        if payload_automation_suspected(payload):
            automation.add(recipient_id)
        else:
            human.add(recipient_id)
    return automation - human


def _prior_iteration_signals(session: Session, campaign_id: uuid.UUID) -> PriorIterationSignals:
    funnel = campaign_funnel(session, campaign_id, scope=SINGLE_TENANT_DATABASE_SCOPE)
    return PriorIterationSignals(
        accepted=funnel.accepted,
        human_clicked=funnel.clicked,
        automation_suspected_clicked=funnel.clicked_automation_suspected,
        reported=funnel.reported,
    )


def _adaptive_iteration_audience(
    campaign_id: uuid.UUID,
    *,
    include_ids: set[uuid.UUID] | frozenset[uuid.UUID],
    exclude_ids: set[uuid.UUID] | frozenset[uuid.UUID],
) -> CampaignAudience:
    """An unfrozen, recipient-pinned audience for an adaptive iteration.

    The iteration is pinned to the reviewed source population (no groups or
    filters that could re-expand it to new or automated recipients) with the
    adaptive exclusions recorded explicitly. It is deliberately left unfrozen so
    the operator still previews, freezes, and approves it through the normal
    path, which independently re-applies opt-out/suppression.
    """

    include = tuple(sorted(set(include_ids), key=str))
    exclude = tuple(sorted(set(exclude_ids), key=str))
    definition = AudienceDefinition(
        group_ids=(),
        departments=(),
        statuses=(),
        include_recipient_ids=include,
        exclude_recipient_ids=exclude,
        sample_size=None,
        sample_seed=None,
    )
    return CampaignAudience(
        campaign_id=campaign_id,
        version=1,
        group_ids=[],
        departments=[],
        statuses=[],
        include_recipient_ids=[str(item) for item in include],
        exclude_recipient_ids=[str(item) for item in exclude],
        sample_size=None,
        sample_seed=None,
        configuration_hash=audience_definition_hash(definition),
        preview_hash=None,
        manifest_hash=None,
        frozen_at=None,
        legacy_requires_configuration=False,
    )


@dataclass(frozen=True)
class ProgramIterationResult:
    """Outcome of a single adaptive-iteration generation attempt."""

    program: CampaignProgram
    occurrence: CampaignProgramOccurrence | None
    adaptation: CampaignProgramAdaptation | None
    created: bool
    reason: str


def _prior_adaptive_level(campaign: Campaign) -> int:
    try:
        return _clamp_level(int((campaign.difficulty or {}).get("adaptive_level", MIN_ADAPTIVE_LEVEL)))
    except (TypeError, ValueError):
        return MIN_ADAPTIVE_LEVEL


def materialize_next_program_iteration(
    session: Session,
    *,
    program_id: uuid.UUID,
    created_by: uuid.UUID | None = None,
    now: datetime | None = None,
) -> ProgramIterationResult:
    """Generate the next DRAFT iteration of an adaptive program, if one is due.

    Safe to call repeatedly: it locks the program row, generates at most one
    iteration, and relies on the occurrence/adaptation unique keys as a final
    backstop, so a worker restart or duplicate delivery never double-generates.
    It NEVER approves, schedules, or sends; the new iteration is a DRAFT that
    must clear the normal approval + RoE + schedule gates like any hand-made
    campaign.
    """

    current_time = _require_aware(now or datetime.now(UTC), label="iteration time")
    program = get_campaign_program(session, program_id, for_update=True)
    if program.generation_mode != GENERATION_MODE_ADAPTIVE:
        return ProgramIterationResult(program, None, None, False, "not_adaptive")
    if program.state is not dm.CampaignProgramState.ACTIVE:
        return ProgramIterationResult(program, None, None, False, "paused")

    occurrences = _program_occurrences(session, program_id)
    if not occurrences:  # pragma: no cover - creation always seeds occurrence 1
        raise ConflictError("adaptive program is missing its source occurrence")
    latest = occurrences[-1]
    if latest.occurrence_number >= program.occurrence_count:
        return ProgramIterationResult(program, None, None, False, "complete")

    prior_campaign = session.get(Campaign, latest.campaign_id)
    if prior_campaign is None:
        raise ConflictError("adaptive program occurrence is missing its campaign")
    if prior_campaign.state not in _ADAPTATION_READY_PRIOR_STATES:
        return ProgramIterationResult(program, None, None, False, "prior_not_complete")

    next_number = latest.occurrence_number + 1
    source = session.get(Campaign, program.source_campaign_id)
    if source is None:  # pragma: no cover - FK RESTRICT protects this
        raise ConflictError("adaptive program source campaign is missing")
    # Revalidate the source blueprint is still a frozen, approved, RoE-bound
    # campaign before generating a new iteration from it; these raise on drift.
    _reviewed_source_audience(session, source)
    _approved_source_content(session, source)
    require_bound_training_resource(session, source)

    schedule_start = _require_aware(source.schedule_start, label="schedule start")
    schedule_end = _require_aware(source.schedule_end, label="schedule end")
    offset = timedelta(days=program.cadence_days * (next_number - 1))
    occurrence_start = schedule_start + offset
    occurrence_end = schedule_end + offset

    base_ids = _source_reviewed_recipient_ids(session, program.source_campaign_id)
    if not base_ids:
        raise ConflictError("adaptive program source has no reviewed recipient population")

    signals = _prior_iteration_signals(session, latest.campaign_id)
    plan = plan_iteration_adaptation(_prior_adaptive_level(prior_campaign), signals)

    scanner_only = _scanner_only_recipient_ids(session, latest.campaign_id)

    campaign_id = uuid.uuid4()
    # Opt-out/suppression is scoped per campaign or global; a brand-new campaign
    # id resolves the global suppressions that must be honored at enrollment.
    opt_out_ids = _excluded_recipient_ids(session, campaign_id)
    enrollment = resolve_iteration_enrollment(base_ids, opt_out_ids=opt_out_ids, scanner_only_ids=scanner_only)

    difficulty = copy.deepcopy(source.difficulty or {})
    difficulty["adaptive_level"] = plan.next_level
    difficulty["program_adaptation"] = {
        "iteration_number": next_number,
        "basis_campaign_id": str(latest.campaign_id),
        "prior_level": plan.prior_level,
        "next_level": plan.next_level,
        "difficulty_delta": plan.difficulty_delta,
        "rationale": plan.rationale,
        "drivers": [dict(driver) for driver in plan.drivers],
    }

    campaign = _build_iteration_campaign(
        source,
        campaign_id=campaign_id,
        occurrence_number=next_number,
        occurrence_count=program.occurrence_count,
        occurrence_start=occurrence_start,
        occurrence_end=occurrence_end,
        created_by=created_by,
        difficulty=difficulty,
    )
    excluded_union = set(enrollment.excluded_opt_out) | set(enrollment.excluded_scanner_only)
    audience = _adaptive_iteration_audience(campaign_id, include_ids=base_ids, exclude_ids=excluded_union)

    occurrence = CampaignProgramOccurrence(
        campaign_program_occurrence_id=uuid.uuid4(),
        campaign_program_id=program_id,
        occurrence_number=next_number,
        campaign_id=campaign_id,
        schedule_start=occurrence_start,
        schedule_end=occurrence_end,
    )
    adaptation = CampaignProgramAdaptation(
        campaign_program_adaptation_id=uuid.uuid4(),
        campaign_program_id=program_id,
        iteration_number=next_number,
        iteration_campaign_id=campaign_id,
        basis_campaign_id=latest.campaign_id,
        signals={
            "accepted": signals.accepted,
            "human_clicked": signals.human_clicked,
            "automation_suspected_clicked": signals.automation_suspected_clicked,
            "reported": signals.reported,
        },
        changes={
            "prior_level": plan.prior_level,
            "next_level": plan.next_level,
            "difficulty_delta": plan.difficulty_delta,
            "rationale": plan.rationale,
            "drivers": [dict(driver) for driver in plan.drivers],
        },
        enrollment={
            "base_population": len(base_ids),
            "enrolled": len(enrollment.enrolled),
            "excluded_opt_out": len(enrollment.excluded_opt_out),
            "excluded_scanner_only": len(enrollment.excluded_scanner_only),
            "excluded_opt_out_ids": [str(item) for item in enrollment.excluded_opt_out],
            "excluded_scanner_only_ids": [str(item) for item in enrollment.excluded_scanner_only],
        },
    )
    session.add_all([campaign, audience, occurrence, adaptation])
    program.updated_at = current_time
    session.flush()
    return ProgramIterationResult(program, occurrence, adaptation, True, "created")


def list_program_adaptations(session: Session, program_id: uuid.UUID) -> tuple[CampaignProgramAdaptation, ...]:
    get_campaign_program(session, program_id)
    return tuple(
        session.scalars(
            select(CampaignProgramAdaptation)
            .where(CampaignProgramAdaptation.campaign_program_id == program_id)
            .order_by(CampaignProgramAdaptation.iteration_number)
        )
    )


def active_adaptive_program_ids(session: Session, *, limit: int = 500) -> tuple[uuid.UUID, ...]:
    """Program ids a generation worker should consider, oldest first.

    Returns only ACTIVE adaptive programs; whether any one is actually due is
    decided (under a row lock) by :func:`materialize_next_program_iteration`.
    """

    rows = session.scalars(
        select(CampaignProgram.campaign_program_id)
        .where(
            CampaignProgram.generation_mode == GENERATION_MODE_ADAPTIVE,
            CampaignProgram.state == dm.CampaignProgramState.ACTIVE,
        )
        .order_by(CampaignProgram.created_at, CampaignProgram.campaign_program_id)
        .limit(limit)
    )
    return tuple(rows)
