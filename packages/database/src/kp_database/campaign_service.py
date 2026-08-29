"""Campaign launch preparation.

Creates the recipient assignments and tracking tokens for a scheduled
campaign and returns per-recipient tracking URLs. Ports the launch/tracking
mechanics of the original King Phisher (`mailer.py` uid generation, `uid`
template variable, `tracking_dot` image) into Phoenix's safe model:

- the raw bearer exists only in the returned delivery data; the database
  stores a keyed HMAC verifier that a database reader cannot replay
- every assignment carries a deterministic idempotency key so re-launching a
  campaign (even after a queue retry) never duplicates sends
- tokens expire at campaign end and are revocable via the kill switch
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from kp_domain_models import models as dm
from kp_domain_models.policy import is_recipient_allowed
from kp_telemetry.errors import ConflictError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from kp_database.models import (
    AudienceGroup,
    AudienceGroupMember,
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignCanaryRecipient,
    CampaignLaunchGate,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    TemplateVersion,
    TrackingToken,
    TrainingResource,
)

TOKEN_EXPIRY_BUFFER_SECONDS = 7 * 24 * 60 * 60
MAX_AUDIENCE_RECIPIENTS = 10_000

_LAUNCHABLE_STATES = {
    dm.CampaignState.APPROVED,
    dm.CampaignState.SCHEDULED,
    dm.CampaignState.SENDING,
    dm.CampaignState.ACTIVE,
}

# Test sends may target test accounts from any non-terminal state (e.g. a DRAFT
# being iterated on), but never from a state that ended the campaign.
_TERMINAL_STATES = {
    dm.CampaignState.RECALLED,
    dm.CampaignState.RECALL_IN_PROGRESS,
    dm.CampaignState.EXPIRED,
    dm.CampaignState.CANCELLED,
    dm.CampaignState.COMPLETED,
    dm.CampaignState.STOPPED,
    dm.CampaignState.REJECTED,
}


class PreparedRecipient(NamedTuple):
    assignment_id: str
    bearer_token: str
    token_verifier: str
    bearer_checksum: str
    token_prefix: str
    open_url: str
    click_url: str

    @property
    def token_hash(self) -> str:
        """Compatibility alias for callers that display the verifier prefix."""

        return self.token_verifier


@dataclass(frozen=True)
class AudienceDefinition:
    group_ids: tuple[uuid.UUID, ...] = ()
    departments: tuple[str, ...] = ()
    statuses: tuple[dm.RecipientStatus, ...] = ()
    include_recipient_ids: tuple[uuid.UUID, ...] = ()
    exclude_recipient_ids: tuple[uuid.UUID, ...] = ()
    sample_size: int | None = None
    sample_seed: str | None = None


@dataclass(frozen=True)
class AudiencePreviewRecipient:
    recipient_id: uuid.UUID
    recipient_hash: str
    masked_mailbox: str
    department: str | None
    status: dm.RecipientStatus


@dataclass(frozen=True)
class AudiencePreview:
    campaign_id: uuid.UUID
    audience_version: int
    configuration_hash: str
    preview_hash: str
    selected_count: int
    included: tuple[AudiencePreviewRecipient, ...]
    excluded_counts: dict[str, int]
    sample_size: int | None
    sample_seed: str | None
    roe_id: uuid.UUID | None
    added_count: int
    removed_count: int
    unchanged_count: int
    over_limit: bool


def training_resource_content_digest(resource: TrainingResource) -> str:
    """Fingerprint the exact lesson text presented to campaign recipients.

    Resources without a knowledge check keep the legacy content-only digest so
    already-bound campaigns remain valid. When a knowledge check is present,
    the digest additionally pins the question, the option set, and the correct
    answer index: a post-review edit to any of them invalidates the binding.
    """

    if getattr(resource, "knowledge_question", None) is None:
        return hashlib.sha256(resource.content.encode("utf-8")).hexdigest()
    return _canonical_hash(
        {
            "content": resource.content,
            "knowledge_question": resource.knowledge_question,
            "knowledge_options": resource.knowledge_options,
            "knowledge_answer_index": resource.knowledge_answer_index,
        }
    )


def training_binding_error(campaign: Campaign, resource: TrainingResource | None) -> str | None:
    """Explain why a campaign's reviewed lesson binding is not launchable."""

    if (
        campaign.training_resource_id is None
        or campaign.training_resource_version is None
        or campaign.training_resource_digest is None
    ):
        return (
            "campaign has no exact reviewed training lesson binding; choose an approved lesson "
            "and review the campaign again"
        )
    if resource is None or resource.training_resource_id != campaign.training_resource_id:
        return (
            "campaign's selected training lesson is unavailable; choose another approved lesson "
            "and review the campaign again"
        )
    if resource.approval_state is not dm.TemplateApprovalState.APPROVED:
        return (
            f"campaign's selected training lesson is {resource.approval_state.value}; "
            "choose an approved lesson and review the campaign again"
        )
    if not resource.requires_completion:
        return (
            "campaign's selected training lesson does not require completion; choose an approved "
            "completion lesson and review the campaign again"
        )
    if resource.version != campaign.training_resource_version:
        return (
            "campaign's selected training lesson version changed after review; choose the current "
            "approved lesson and review the campaign again"
        )
    calculated = training_resource_content_digest(resource)
    if not hmac.compare_digest(calculated, campaign.training_resource_digest):
        return (
            "campaign's selected training lesson content changed after review; choose the current "
            "approved lesson and review the campaign again"
        )
    expected_manifest = campaign_content_manifest_hash(campaign)
    if campaign.manifest_hash is None or not hmac.compare_digest(expected_manifest, campaign.manifest_hash):
        return "campaign review manifest is inconsistent; choose the approved lesson and review the campaign again"
    return None


def require_bound_training_resource(
    session: Session,
    campaign: Campaign,
    *,
    lock: bool = True,
) -> TrainingResource:
    """Return the exact approved campaign lesson or fail closed."""

    resource = None
    if campaign.training_resource_id is not None:
        resource = session.get(
            TrainingResource,
            campaign.training_resource_id,
            with_for_update=lock,
        )
    error = training_binding_error(campaign, resource)
    if error is not None:
        raise ConflictError(error)
    if resource is None:
        # Keep the invariant explicit in optimized Python builds too.  This is
        # intentionally the same non-secret remediation presented for a
        # missing reviewed binding above.
        raise ConflictError(
            "campaign's selected training lesson is unavailable; choose another approved lesson "
            "and review the campaign again"
        )
    return resource


def campaign_content_manifest_hash(campaign: Campaign) -> str:
    """Hash every immutable content choice presented during campaign review."""

    return _canonical_hash(
        {
            "campaign_id": str(campaign.campaign_id),
            "pattern_id": str(campaign.pattern_id),
            "template_version_id": str(campaign.current_template_id) if campaign.current_template_id else None,
            "training_resource_digest": campaign.training_resource_digest,
            "training_resource_id": (
                str(campaign.training_resource_id) if campaign.training_resource_id is not None else None
            ),
            "training_resource_version": campaign.training_resource_version,
        }
    )


def campaign_canary_manifest_hash(rows: Sequence[tuple[uuid.UUID, str]]) -> str:
    """Fingerprint the ordered, explicitly reviewed canary cohort."""

    return _canonical_hash(
        {
            "version": 1,
            "recipients": [(str(recipient_id), recipient_hash) for recipient_id, recipient_hash in rows],
        }
    )


def template_content_approval_hash(template: TemplateVersion) -> str:
    """Fingerprint only the canonical recipient-visible reviewed content."""

    return _canonical_hash(
        {
            "version": 1,
            "template_version_id": str(template.template_version_id),
            "template_version": template.version,
            "subject": template.subject,
            "plain_text": template.plain_text,
            "safe_html": template.safe_html,
            "synthetic_sender_display": template.synthetic_sender_display,
            "learning_objectives": template.learning_objectives or [],
            "warning_cues": template.warning_cues or [],
            "training_explanation": template.training_explanation,
        }
    )


def campaign_launch_review_manifest_hash(
    campaign: Campaign,
    audience: CampaignAudience,
    *,
    template_approval_hash: str,
    canary_manifest_hash: str,
) -> str:
    """Bind every mutable launch choice reviewed by a human."""

    return _canonical_hash(
        {
            "version": 1,
            "campaign_id": str(campaign.campaign_id),
            "title": campaign.title,
            "sender_mailbox": campaign.sender_mailbox,
            "sender_display_name": campaign.sender_display_name,
            "training_domain": campaign.training_domain,
            "schedule_start": campaign.schedule_start.isoformat() if campaign.schedule_start else None,
            "schedule_end": campaign.schedule_end.isoformat() if campaign.schedule_end else None,
            "timezone": campaign.timezone,
            "max_recipients": campaign.max_recipients,
            "roe_id": str(campaign.roe_id) if campaign.roe_id else None,
            "content_manifest_hash": campaign.manifest_hash,
            "template_approval_hash": template_approval_hash,
            "audience_version": audience.version,
            "audience_configuration_hash": audience.configuration_hash,
            "audience_manifest_hash": audience.manifest_hash,
            "canary_manifest_hash": canary_manifest_hash,
        }
    )


def bind_campaign_launch_review(
    session: Session,
    campaign: Campaign,
    template: TemplateVersion,
) -> CampaignLaunchGate:
    """Lock a campaign's full review manifest and explicit canary cohort."""

    audience = session.get(CampaignAudience, campaign.campaign_id, with_for_update=True)
    if (
        audience is None
        or audience.legacy_requires_configuration
        or audience.frozen_at is None
        or audience.manifest_hash is None
        or campaign.roe_id is None
    ):
        raise ConflictError("campaign requires a frozen audience and reviewed Rules-of-Engagement")
    if template.approval_state is not dm.TemplateApprovalState.APPROVED:
        raise ConflictError("campaign requires an exactly approved template before review")
    template_hash = template_content_approval_hash(template)

    canary_rows = list(
        session.execute(
            select(
                CampaignAudienceManifest.recipient_id,
                CampaignAudienceManifest.recipient_hash,
            )
            .join(Recipient, Recipient.recipient_id == CampaignAudienceManifest.recipient_id)
            .where(
                CampaignAudienceManifest.campaign_id == campaign.campaign_id,
                CampaignAudienceManifest.audience_version == audience.version,
                Recipient.is_test_account.is_(True),
                Recipient.status == dm.RecipientStatus.ACTIVE,
                Recipient.deleted_at.is_(None),
            )
            .order_by(CampaignAudienceManifest.ordinal)
            .limit(MAX_AUDIENCE_RECIPIENTS + 1)
        )
    )
    if not canary_rows:
        raise ConflictError(
            "campaign requires at least one server-marked test account in its frozen audience before review"
        )
    if len(canary_rows) > MAX_AUDIENCE_RECIPIENTS:
        raise ConflictError("campaign canary cohort exceeds the supported 10,000-recipient boundary")
    canary = [(recipient_id, recipient_hash) for recipient_id, recipient_hash in canary_rows]
    canary_hash = campaign_canary_manifest_hash(canary)
    review_hash = campaign_launch_review_manifest_hash(
        campaign,
        audience,
        template_approval_hash=template_hash,
        canary_manifest_hash=canary_hash,
    )

    existing = session.get(CampaignLaunchGate, campaign.campaign_id, with_for_update=True)
    if existing is not None and existing.review_manifest_hash == review_hash and existing.state == "reviewed":
        return existing
    if existing is not None:
        session.execute(
            delete(CampaignCanaryRecipient).where(CampaignCanaryRecipient.campaign_id == campaign.campaign_id)
        )
        session.delete(existing)
        session.flush()
    gate = CampaignLaunchGate(
        campaign_id=campaign.campaign_id,
        review_manifest_hash=review_hash,
        content_manifest_hash=campaign.manifest_hash,
        template_approval_hash=template_hash,
        audience_manifest_hash=audience.manifest_hash,
        canary_manifest_hash=canary_hash,
        roe_id=campaign.roe_id,
        state="reviewed",
    )
    session.add(gate)
    session.flush()
    for ordinal, (recipient_id, recipient_hash) in enumerate(canary):
        session.add(
            CampaignCanaryRecipient(
                campaign_id=campaign.campaign_id,
                recipient_id=recipient_id,
                ordinal=ordinal,
                recipient_hash=recipient_hash,
            )
        )
    session.flush()
    return gate


def campaign_launch_gate_error(
    campaign: Campaign,
    audience: CampaignAudience | None,
    template: TemplateVersion | None,
    gate: CampaignLaunchGate | None,
) -> str | None:
    """Return a bounded reason when reviewed launch evidence has drifted."""

    if gate is None:
        return "campaign has no durable launch review; review it again"
    if audience is None or audience.legacy_requires_configuration or audience.frozen_at is None:
        return "campaign audience is not frozen; review it again"
    if audience.manifest_hash is None or not hmac.compare_digest(audience.manifest_hash, gate.audience_manifest_hash):
        return "campaign audience changed after review; review it again"
    if campaign.roe_id is None or campaign.roe_id != gate.roe_id:
        return "campaign Rules-of-Engagement changed after review; review it again"
    if campaign.manifest_hash is None or not hmac.compare_digest(campaign.manifest_hash, gate.content_manifest_hash):
        return "campaign content or training changed after review; review it again"
    if (
        template is None
        or template.approval_state is not dm.TemplateApprovalState.APPROVED
        or not hmac.compare_digest(template_content_approval_hash(template), gate.template_approval_hash)
    ):
        return "campaign template changed after review; review it again"
    expected = campaign_launch_review_manifest_hash(
        campaign,
        audience,
        template_approval_hash=template_content_approval_hash(template),
        canary_manifest_hash=gate.canary_manifest_hash,
    )
    if not hmac.compare_digest(expected, gate.review_manifest_hash):
        return "campaign configuration changed after review; review it again"
    return None


def invalidate_campaign_launch_review(session: Session, campaign_id: uuid.UUID) -> None:
    """Discard superseded gate state; immutable audit records retain history."""

    session.execute(delete(CampaignLaunchGate).where(CampaignLaunchGate.campaign_id == campaign_id))


def bind_campaign_training_resource(campaign: Campaign, resource: TrainingResource) -> None:
    """Persist the operator's explicit, currently approved lesson choice."""

    if resource.approval_state is not dm.TemplateApprovalState.APPROVED:
        raise ConflictError("campaign requires an approved training lesson")
    if not resource.requires_completion:
        raise ConflictError("campaign requires an approved training lesson that requires completion")
    campaign.training_resource_id = resource.training_resource_id
    campaign.training_resource_version = resource.version
    campaign.training_resource_digest = training_resource_content_digest(resource)
    campaign.manifest_hash = campaign_content_manifest_hash(campaign)


def _canonical_hash(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def normalize_audience_definition(definition: AudienceDefinition) -> AudienceDefinition:
    group_ids = tuple(sorted(set(definition.group_ids), key=str))
    include_ids = tuple(sorted(set(definition.include_recipient_ids), key=str))
    exclude_ids = tuple(sorted(set(definition.exclude_recipient_ids), key=str))
    departments = tuple(sorted({item.strip().casefold() for item in definition.departments if item.strip()}))
    statuses = tuple(sorted(set(definition.statuses), key=lambda item: item.value))
    if len(group_ids) + len(include_ids) + len(exclude_ids) > MAX_AUDIENCE_RECIPIENTS:
        raise ValueError("audience selectors exceed the 10,000-recipient configuration limit")
    if definition.sample_size is not None and not 1 <= definition.sample_size <= MAX_AUDIENCE_RECIPIENTS:
        raise ValueError("sample_size must be between 1 and 10,000")
    sample_seed = definition.sample_seed.strip() if definition.sample_seed else None
    if definition.sample_size is not None and not sample_seed:
        raise ValueError("sample_seed is required when sample_size is set")
    if sample_seed is not None and len(sample_seed) > 128:
        raise ValueError("sample_seed must be at most 128 characters")
    return AudienceDefinition(
        group_ids=group_ids,
        departments=departments,
        statuses=statuses,
        include_recipient_ids=include_ids,
        exclude_recipient_ids=exclude_ids,
        sample_size=definition.sample_size,
        sample_seed=sample_seed,
    )


def audience_definition_hash(definition: AudienceDefinition) -> str:
    normalized = normalize_audience_definition(definition)
    return _canonical_hash(
        {
            "departments": list(normalized.departments),
            "exclude_recipient_ids": [str(item) for item in normalized.exclude_recipient_ids],
            "group_ids": [str(item) for item in normalized.group_ids],
            "include_recipient_ids": [str(item) for item in normalized.include_recipient_ids],
            "sample_seed": normalized.sample_seed,
            "sample_size": normalized.sample_size,
            "statuses": [item.value for item in normalized.statuses],
        }
    )


def empty_audience(campaign_id: uuid.UUID) -> CampaignAudience:
    definition = AudienceDefinition()
    return CampaignAudience(
        campaign_id=campaign_id,
        version=1,
        group_ids=[],
        departments=[],
        statuses=[],
        include_recipient_ids=[],
        exclude_recipient_ids=[],
        configuration_hash=audience_definition_hash(definition),
        legacy_requires_configuration=False,
    )


def audience_definition(row: CampaignAudience) -> AudienceDefinition:
    try:
        return normalize_audience_definition(
            AudienceDefinition(
                group_ids=tuple(uuid.UUID(str(item)) for item in row.group_ids or []),
                departments=tuple(str(item) for item in row.departments or []),
                statuses=tuple(dm.RecipientStatus(str(item)) for item in row.statuses or []),
                include_recipient_ids=tuple(uuid.UUID(str(item)) for item in row.include_recipient_ids or []),
                exclude_recipient_ids=tuple(uuid.UUID(str(item)) for item in row.exclude_recipient_ids or []),
                sample_size=row.sample_size,
                sample_seed=row.sample_seed,
            )
        )
    except (TypeError, ValueError):
        raise ConflictError("campaign audience configuration is malformed") from None


def invalidate_campaign_audience(session: Session, campaign: Campaign, audience: CampaignAudience) -> None:
    invalidate_campaign_launch_review(session, campaign.campaign_id)
    audience.preview_hash = None
    audience.manifest_hash = None
    audience.frozen_at = None
    campaign.roe_id = None
    if campaign.state not in _TERMINAL_STATES:
        campaign.state = dm.CampaignState.DRAFT
    # Migration 0021 allows manifest deletion only after the frozen marker is
    # cleared. Flushing this state first makes invalidation explicit and keeps
    # direct INSERT/UPDATE/DELETE attempts against a frozen manifest blocked.
    session.flush()
    session.execute(
        delete(CampaignAudienceManifest).where(CampaignAudienceManifest.campaign_id == campaign.campaign_id)
    )
    session.execute(delete(CampaignApproval).where(CampaignApproval.campaign_id == campaign.campaign_id))


def configure_campaign_audience(
    session: Session,
    campaign: Campaign,
    definition: AudienceDefinition,
) -> tuple[CampaignAudience, bool]:
    if campaign.state in _TERMINAL_STATES or campaign.state in {
        dm.CampaignState.SCHEDULED,
        dm.CampaignState.SENDING,
        dm.CampaignState.ACTIVE,
    }:
        raise ConflictError("a running or terminal campaign audience cannot be changed")
    locked = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign.campaign_id).with_for_update())
    if locked is None:
        raise ConflictError("campaign no longer exists")
    campaign = locked
    normalized = normalize_audience_definition(definition)
    digest = audience_definition_hash(normalized)
    audience = session.get(CampaignAudience, campaign.campaign_id, with_for_update=True)
    if audience is None:
        audience = empty_audience(campaign.campaign_id)
        session.add(audience)
        session.flush()
    changed = audience.configuration_hash != digest or audience.legacy_requires_configuration
    if not changed:
        return audience, False
    invalidate_campaign_audience(session, campaign, audience)
    audience.version += 1
    audience.group_ids = [str(item) for item in normalized.group_ids]
    audience.departments = list(normalized.departments)
    audience.statuses = [item.value for item in normalized.statuses]
    audience.include_recipient_ids = [str(item) for item in normalized.include_recipient_ids]
    audience.exclude_recipient_ids = [str(item) for item in normalized.exclude_recipient_ids]
    audience.sample_size = normalized.sample_size
    audience.sample_seed = normalized.sample_seed
    audience.configuration_hash = digest
    audience.legacy_requires_configuration = False
    audience.updated_at = datetime.now(UTC)
    session.flush()
    return audience, True


def _recipient_snapshot_hash(campaign_id: uuid.UUID, recipient: Recipient) -> str:
    return hashlib.sha256(
        f"campaign-audience-v1:{campaign_id}:{recipient.recipient_id}:{recipient.mailbox_sha256}".encode("ascii")
    ).hexdigest()


def _masked_mailbox(mailbox: str) -> str:
    local, _, domain = mailbox.rpartition("@")
    return f"{local[:1]}***@{domain}" if local and domain else "***"


def _bounded_ids(rows: Sequence[uuid.UUID], *, label: str) -> set[uuid.UUID]:
    if len(rows) > MAX_AUDIENCE_RECIPIENTS:
        raise ConflictError(f"{label} exceeds the supported 10,000-recipient boundary")
    return set(rows)


def preview_campaign_audience(
    session: Session,
    campaign: Campaign,
    *,
    allowed_domains: frozenset[str] | None,
    roe_options: Sequence[tuple[uuid.UUID, frozenset[str]]],
) -> AudiencePreview:
    audience = session.get(CampaignAudience, campaign.campaign_id)
    if audience is None or audience.legacy_requires_configuration:
        raise ConflictError("campaign audience must be configured before preview")
    definition = audience_definition(audience)
    sample_seed = definition.sample_seed
    if definition.sample_size is not None and sample_seed is None:
        raise ConflictError("campaign audience configuration is malformed")

    group_member_ids: set[uuid.UUID] = set()
    if definition.group_ids:
        known_groups = _bounded_ids(
            list(
                session.scalars(
                    select(AudienceGroup.audience_group_id)
                    .where(AudienceGroup.audience_group_id.in_(definition.group_ids))
                    .limit(MAX_AUDIENCE_RECIPIENTS + 1)
                )
            ),
            label="audience group selection",
        )
        if known_groups != set(definition.group_ids):
            raise ConflictError("campaign audience references an unknown static group")
        group_member_ids = _bounded_ids(
            list(
                session.scalars(
                    select(AudienceGroupMember.recipient_id)
                    .distinct()
                    .where(AudienceGroupMember.audience_group_id.in_(definition.group_ids))
                    .limit(MAX_AUDIENCE_RECIPIENTS + 1)
                )
            ),
            label="audience group membership",
        )

    explicit_ids = set(definition.include_recipient_ids)
    base_ids = explicit_ids | group_member_ids
    filter_only = not base_ids and bool(definition.departments or definition.statuses)
    if not base_ids and not filter_only:
        recipients: list[Recipient] = []
    else:
        query = select(Recipient).order_by(Recipient.recipient_id).limit(MAX_AUDIENCE_RECIPIENTS + 1)
        if base_ids:
            query = query.where(Recipient.recipient_id.in_(base_ids))
        else:
            if definition.departments:
                query = query.where(func.lower(func.trim(Recipient.department)).in_(definition.departments))
            if definition.statuses:
                query = query.where(Recipient.status.in_(definition.statuses))
        recipients = list(session.scalars(query))
        if len(recipients) > MAX_AUDIENCE_RECIPIENTS:
            raise ConflictError("audience candidate query exceeds the supported 10,000-recipient boundary")

    missing_count = len(base_ids - {item.recipient_id for item in recipients})
    exclusion_ids = set()
    if recipients:
        exclusion_ids = _bounded_ids(
            list(
                session.scalars(
                    select(RecipientExclusion.recipient_id)
                    .distinct()
                    .where(
                        RecipientExclusion.recipient_id.in_([item.recipient_id for item in recipients]),
                        RecipientExclusion.revoked_at.is_(None),
                        RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > datetime.now(UTC)),
                        (RecipientExclusion.campaign_id == campaign.campaign_id)
                        | (RecipientExclusion.campaign_id.is_(None)),
                    )
                    .limit(MAX_AUDIENCE_RECIPIENTS + 1)
                )
            ),
            label="active recipient exclusions",
        )

    excluded_counts: dict[str, int] = {}

    def exclude(reason: str) -> None:
        excluded_counts[reason] = excluded_counts.get(reason, 0) + 1

    if missing_count:
        excluded_counts["missing_recipient"] = missing_count
    department_filters = {item.casefold() for item in definition.departments}
    status_filters = set(definition.statuses)
    explicitly_excluded = set(definition.exclude_recipient_ids)
    policy_eligible: list[Recipient] = []
    for recipient in recipients:
        if recipient.recipient_id in explicitly_excluded:
            exclude("explicit_exclusion")
        elif recipient.deleted_at is not None:
            exclude("deleted")
        elif status_filters and recipient.status not in status_filters:
            exclude("status_filter")
        elif recipient.status is not dm.RecipientStatus.ACTIVE:
            exclude("inactive")
        elif department_filters and (recipient.department or "").strip().casefold() not in department_filters:
            exclude("department_filter")
        elif recipient.recipient_id in exclusion_ids:
            exclude("recipient_exclusion")
        elif allowed_domains is not None and not is_recipient_allowed(recipient.mailbox, allowed_domains):
            exclude("domain_not_allowed")
        else:
            policy_eligible.append(recipient)

    coverage: list[tuple[int, str, uuid.UUID, frozenset[str], list[Recipient]]] = []
    for roe_id, domains in roe_options:
        covered = [item for item in policy_eligible if is_recipient_allowed(item.mailbox, domains)]
        coverage.append((len(covered), str(roe_id), roe_id, domains, covered))
    chosen_roe: uuid.UUID | None = None
    covered_recipients: list[Recipient] = []
    if coverage:
        _, _, chosen_roe, _, covered_recipients = sorted(coverage, key=lambda item: (-item[0], item[1]))[0]
    covered_ids = {item.recipient_id for item in covered_recipients}
    for recipient in policy_eligible:
        if recipient.recipient_id not in covered_ids:
            exclude("roe_not_covered")

    sampled = covered_recipients
    if definition.sample_size is not None and len(sampled) > definition.sample_size:
        sampled = sorted(
            sampled,
            key=lambda item: hashlib.sha256(
                f"audience-sample-v1:{sample_seed}:{item.recipient_id}".encode()
            ).hexdigest(),
        )[: definition.sample_size]
        exclude_count = len(covered_recipients) - len(sampled)
        excluded_counts["sampled_out"] = excluded_counts.get("sampled_out", 0) + exclude_count
    sampled.sort(key=lambda item: str(item.recipient_id))
    over_limit = len(sampled) > min(campaign.max_recipients, MAX_AUDIENCE_RECIPIENTS)
    included = tuple(
        AudiencePreviewRecipient(
            recipient_id=item.recipient_id,
            recipient_hash=_recipient_snapshot_hash(campaign.campaign_id, item),
            masked_mailbox=_masked_mailbox(item.mailbox),
            department=item.department,
            status=item.status,
        )
        for item in sampled
    )
    manifest_rows = [(str(item.recipient_id), item.recipient_hash) for item in included]
    preview_hash = _canonical_hash(
        {
            "audience_version": audience.version,
            "configuration_hash": audience.configuration_hash,
            "excluded_counts": dict(sorted(excluded_counts.items())),
            "recipients": manifest_rows,
            "roe_id": str(chosen_roe) if chosen_roe else None,
        }
    )
    previous_ids = set(
        session.scalars(
            select(CampaignAudienceManifest.recipient_id).where(
                CampaignAudienceManifest.campaign_id == campaign.campaign_id
            )
        )
    )
    current_ids = {item.recipient_id for item in included}
    return AudiencePreview(
        campaign_id=campaign.campaign_id,
        audience_version=audience.version,
        configuration_hash=audience.configuration_hash,
        preview_hash=preview_hash,
        selected_count=len(recipients) + missing_count,
        included=included,
        excluded_counts=dict(sorted(excluded_counts.items())),
        sample_size=definition.sample_size,
        sample_seed=definition.sample_seed,
        roe_id=chosen_roe,
        added_count=len(current_ids - previous_ids),
        removed_count=len(previous_ids - current_ids),
        unchanged_count=len(current_ids & previous_ids),
        over_limit=over_limit,
    )


def freeze_campaign_audience(
    session: Session,
    campaign: Campaign,
    preview: AudiencePreview,
    *,
    expected_preview_hash: str,
) -> CampaignAudience:
    locked_campaign = session.scalar(
        select(Campaign).where(Campaign.campaign_id == campaign.campaign_id).with_for_update()
    )
    if locked_campaign is None:
        raise ConflictError("campaign no longer exists")
    campaign = locked_campaign
    audience = session.get(CampaignAudience, campaign.campaign_id, with_for_update=True)
    if audience is None or audience.legacy_requires_configuration:
        raise ConflictError("campaign audience must be configured before freezing")
    if campaign.state != dm.CampaignState.DRAFT:
        raise ConflictError("campaign audience can only be frozen while the campaign is a draft")
    if preview.preview_hash != expected_preview_hash:
        raise ConflictError("audience preview changed; review the latest preview before freezing")
    if preview.configuration_hash != audience.configuration_hash or preview.audience_version != audience.version:
        raise ConflictError("audience configuration changed; preview it again")
    if preview.roe_id is None:
        raise ConflictError("no signed Rules-of-Engagement covers the selected audience")
    if not preview.included:
        raise ConflictError("campaign audience contains no eligible recipients")
    if preview.over_limit:
        raise ConflictError("campaign audience exceeds max_recipients")
    manifest_hash = _canonical_hash(
        {
            "audience_version": audience.version,
            "recipients": [(str(item.recipient_id), item.recipient_hash) for item in preview.included],
            "roe_id": str(preview.roe_id),
        }
    )
    if audience.manifest_hash == manifest_hash and audience.preview_hash == preview.preview_hash:
        return audience
    session.execute(
        delete(CampaignAudienceManifest).where(CampaignAudienceManifest.campaign_id == campaign.campaign_id)
    )
    for ordinal, item in enumerate(preview.included):
        session.add(
            CampaignAudienceManifest(
                campaign_id=campaign.campaign_id,
                recipient_id=item.recipient_id,
                audience_version=audience.version,
                ordinal=ordinal,
                recipient_hash=item.recipient_hash,
            )
        )
    # Persist exact rows while the audience is explicitly unfrozen. The DB
    # trigger then prevents any row-level mutation after frozen_at is set.
    session.flush()
    audience.preview_hash = preview.preview_hash
    audience.manifest_hash = manifest_hash
    audience.frozen_at = datetime.now(UTC)
    campaign.roe_id = preview.roe_id
    session.flush()
    return audience


def audience_matches_preview(session: Session, campaign: Campaign, preview: AudiencePreview) -> bool:
    audience = session.get(CampaignAudience, campaign.campaign_id)
    if (
        audience is None
        or audience.legacy_requires_configuration
        or audience.frozen_at is None
        or audience.preview_hash != preview.preview_hash
        or audience.version != preview.audience_version
        or campaign.roe_id != preview.roe_id
    ):
        return False
    rows = list(
        session.execute(
            select(
                CampaignAudienceManifest.recipient_id,
                CampaignAudienceManifest.recipient_hash,
                CampaignAudienceManifest.ordinal,
            )
            .where(CampaignAudienceManifest.campaign_id == campaign.campaign_id)
            .order_by(CampaignAudienceManifest.ordinal)
            .limit(MAX_AUDIENCE_RECIPIENTS + 1)
        )
    )
    if len(rows) > MAX_AUDIENCE_RECIPIENTS:
        return False
    expected = [(item.recipient_id, item.recipient_hash, ordinal) for ordinal, item in enumerate(preview.included)]
    actual = [(recipient_id, recipient_hash, ordinal) for recipient_id, recipient_hash, ordinal in rows]
    return actual == expected


def tracking_token_verifier(raw_token: str, signing_key: bytes) -> str:
    """Return the non-replayable database verifier for an opaque bearer."""

    if len(signing_key) != 32:
        raise ValueError("tracking token HMAC key must be exactly 32 bytes")
    return hmac.new(signing_key, raw_token.encode("ascii"), hashlib.sha256).hexdigest()


def _tracking_token_key(explicit: bytes | None) -> bytes:
    if explicit is not None:
        return explicit
    configured = os.environ.get("TRACKING_TOKEN_HMAC_KEY", "")
    try:
        key = bytes.fromhex(configured)
    except ValueError as exc:
        raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key") from exc
    if len(key) != 32:
        raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key")
    return key


def _excluded_recipient_ids(session: Session, campaign_id: uuid.UUID) -> set[uuid.UUID]:
    rows = (
        session.execute(
            select(RecipientExclusion.recipient_id).where(
                RecipientExclusion.recipient_id.is_not(None),
                RecipientExclusion.revoked_at.is_(None),
                RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > datetime.now(UTC)),
                (RecipientExclusion.campaign_id == campaign_id) | (RecipientExclusion.campaign_id.is_(None)),
            )
        )
        .scalars()
        .all()
    )
    return set(rows)


def prepare_campaign(
    session: Session,
    campaign: Campaign,
    *,
    tracking_base_url: str,
    include_test_accounts: bool = False,
    test_only: bool = False,
    recipient_scope: frozenset[uuid.UUID] | None = None,
    omit_recipient_ids: frozenset[uuid.UUID] = frozenset(),
    token_hmac_key: bytes | None = None,
) -> list[PreparedRecipient]:
    """Create assignments + tokens for eligible recipients of `campaign`.

    Returns tracking URLs and transient bearers so the caller can stage the
    delivery outbox job. The caller exclusively owns commit/rollback so
    campaign state, assignments, token rotation, audit, and queue intent can
    be one transaction. Safe to retry: assignment IDs remain stable and a still-
    queued assignment receives a fresh bearer, invalidating older queue data.
    """
    if campaign.state in _TERMINAL_STATES:
        raise ConflictError(f"campaign is in a terminal state ({campaign.state.value})")
    if not test_only and campaign.state not in _LAUNCHABLE_STATES:
        raise ConflictError(f"campaign is not launchable (state={campaign.state.value})")
    locked_campaign = session.scalar(
        select(Campaign).where(Campaign.campaign_id == campaign.campaign_id).with_for_update()
    )
    if locked_campaign is None:
        raise ConflictError("campaign no longer exists")
    campaign = locked_campaign
    if campaign.max_recipients > MAX_AUDIENCE_RECIPIENTS:
        raise ConflictError("campaign max_recipients exceeds the supported 10,000-recipient boundary")
    require_bound_training_resource(session, campaign)

    verifier_key = _tracking_token_key(token_hmac_key)
    excluded = _excluded_recipient_ids(session, campaign.campaign_id)
    audience = session.get(CampaignAudience, campaign.campaign_id)
    if (
        audience is None
        or audience.legacy_requires_configuration
        or audience.frozen_at is None
        or audience.manifest_hash is None
    ):
        raise ConflictError("campaign requires a frozen audience manifest")
    manifest_rows = list(
        session.execute(
            select(CampaignAudienceManifest, Recipient)
            .join(Recipient, Recipient.recipient_id == CampaignAudienceManifest.recipient_id)
            .where(CampaignAudienceManifest.campaign_id == campaign.campaign_id)
            .order_by(CampaignAudienceManifest.ordinal)
            .limit(MAX_AUDIENCE_RECIPIENTS + 1)
        )
    )
    if not manifest_rows:
        raise ConflictError("campaign frozen audience manifest is empty")
    if len(manifest_rows) > MAX_AUDIENCE_RECIPIENTS:
        raise ConflictError("campaign audience exceeds the supported 10,000-recipient boundary")
    eligible: list[Recipient] = []
    for manifest, recipient in manifest_rows:
        if manifest.audience_version != audience.version:
            raise ConflictError("campaign audience manifest version is stale")
        if manifest.recipient_hash != _recipient_snapshot_hash(campaign.campaign_id, recipient):
            raise ConflictError("campaign audience manifest changed after approval")
        if recipient.status is not dm.RecipientStatus.ACTIVE or recipient.deleted_at is not None:
            raise ConflictError("campaign audience contains an inactive recipient and must be reviewed again")
        if recipient.recipient_id in excluded:
            raise ConflictError("campaign audience contains an excluded recipient and must be reviewed again")
        if recipient_scope is not None and recipient.recipient_id not in recipient_scope:
            continue
        if recipient.recipient_id in omit_recipient_ids:
            continue
        if test_only and not recipient.is_test_account:
            continue
        eligible.append(recipient)
    # The flag is retained for call compatibility. A normal launch now uses
    # the exact manifest, including an explicitly selected test account.
    del include_test_accounts
    if len(eligible) > campaign.max_recipients:
        raise ConflictError(
            f"campaign exceeds max_recipients ({len(eligible)} eligible > {campaign.max_recipients} allowed)"
        )

    now = datetime.now(UTC)
    expires_at = campaign.expires_at
    if expires_at is None:
        expires_at = campaign.schedule_end
    if expires_at is None:
        expires_at = now
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    expires_at = expires_at + timedelta(seconds=TOKEN_EXPIRY_BUFFER_SECONDS)

    tracking_base_url = tracking_base_url.rstrip("/")
    prepared: list[PreparedRecipient] = []

    recipient_ids = [recipient.recipient_id for recipient in eligible]
    assignments = list(
        session.scalars(
            select(RecipientAssignment).where(
                RecipientAssignment.campaign_id == campaign.campaign_id,
                RecipientAssignment.recipient_id.in_(recipient_ids),
            )
        )
    )
    assignment_by_recipient = {item.recipient_id: item for item in assignments}
    assignment_ids = [item.recipient_assignment_id for item in assignments]
    token_by_assignment = {
        item.recipient_assignment_id: item
        for item in (
            session.scalars(select(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids)))
            if assignment_ids
            else []
        )
    }

    for recipient in eligible:
        assignment = assignment_by_recipient.get(recipient.recipient_id)
        if assignment is not None:
            # A publish retry cannot recover a raw bearer from its HMAC. Rotate
            # only while the assignment remains QUEUED. Any previously queued
            # delivery carries the old verifier and will fail the worker's
            # database binding check rather than sending a dead link.
            if assignment.send_state != dm.SendState.QUEUED:
                continue
            token = token_by_assignment.get(assignment.recipient_assignment_id)
            prepared.append(
                _rotate_or_create_token(
                    session,
                    tracking_base_url,
                    campaign,
                    assignment,
                    token,
                    expires_at=expires_at,
                    verifier_key=verifier_key,
                )
            )
            continue

        assignment = RecipientAssignment(
            recipient_assignment_id=uuid.uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            snapshot_version=1,
            send_state=dm.SendState.QUEUED,
            idempotency_key=f"{campaign.campaign_id}:{recipient.recipient_id}:1",
        )
        session.add(assignment)
        session.flush()

        prepared.append(
            _rotate_or_create_token(
                session,
                tracking_base_url,
                campaign,
                assignment,
                None,
                expires_at=expires_at,
                verifier_key=verifier_key,
            )
        )

    session.flush()
    return prepared


def _rotate_or_create_token(
    session: Session,
    tracking_base_url: str,
    campaign: Campaign,
    assignment: RecipientAssignment,
    token: TrackingToken | None,
    *,
    expires_at: datetime,
    verifier_key: bytes,
) -> PreparedRecipient:
    raw_token = secrets.token_urlsafe(32)
    verifier = tracking_token_verifier(raw_token, verifier_key)
    if token is None:
        token = TrackingToken(
            token_id=uuid.uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_assignment_id=assignment.recipient_assignment_id,
        )
        session.add(token)
    token.token_hash = verifier
    # Prefix derives from the HMAC, never from the bearer.
    token.token_prefix = verifier[:6]
    token.pepper_version = 2
    token.status = dm.TokenStatus.ACTIVE
    token.expires_at = expires_at
    token.revoked_at = None
    token.revoked_reason = None
    session.flush()
    assignment.token_id = token.token_id
    assignment.failure_reason = None
    return PreparedRecipient(
        assignment_id=str(assignment.recipient_assignment_id),
        bearer_token=raw_token,
        token_verifier=verifier,
        bearer_checksum=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
        token_prefix=token.token_prefix,
        open_url=f"{tracking_base_url}/v1/track/open/{raw_token}",
        click_url=f"{tracking_base_url}/v1/track/click/{raw_token}",
    )
