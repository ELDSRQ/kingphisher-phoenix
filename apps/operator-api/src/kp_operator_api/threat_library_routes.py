"""Governed current-threat library + reviewer workbench API (W3-02, Report-04).

Operators browse the governed current-threat library, review the SAFE preview of
each quarantined artifact (never the hostile original), import signed offline
curated bundles, and see stale/failed source health in the System view.

Hard invariants enforced here, not just documented:

* A :class:`ThreatArtifact` is always ``QUARANTINED``; no route ever flips it to
  active/approved or returns it as deliverable content. The review endpoint
  records a verdict on the *safe preview* only.
* The response bodies carry the safe preview + the deterministic W3-01 cue
  manifest + minimized provenance. The raw original is not stored and cannot be
  served.
* A signed offline bundle is checksum- and signature-verified before any import,
  and a ``bundle_id`` already imported is refused (replay protection).
* Importing under a disabled source policy fails closed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.cue_ontology import manifest_cue_labels
from kp_curation.threat_bundle import BundleError, verify_bundle
from kp_curation.threat_library import ingest_threat_artifact, source_policy_health
from kp_database.audit_store import AuditStore
from kp_database.models import SourcePolicy, ThreatArtifact, ThreatBundleImport
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError, ValidationError_
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings

router = APIRouter(prefix="/api/v1/threat-library", tags=["threat-library"])

_MAX_LIMIT = 100
_MAX_OFFSET = 10_000
_MAX_PREVIEW_CHARS = 200_000
_MAX_TITLE_CHARS = 998


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class ArtifactProvenanceView(_StrictModel):
    hash: str
    observed_at: str | None = None
    source: str | None = None
    parser_version: str | None = None
    reviewer: str | None = None


class SourcePolicyHealthView(_StrictModel):
    source_policy_id: uuid.UUID | None = None
    source_key: str | None = None
    owner: str | None = None
    license: str | None = None
    parser: str | None = None
    trust: dm.SourceTrust | None = None
    enabled: bool
    freshness: int
    bucket: str
    is_stale: bool
    is_failed: bool
    admits_ingestion: bool
    age_days: float | None = None
    consecutive_failures: int = Field(ge=0)
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None


class ThreatArtifactSummary(_StrictModel):
    threat_artifact_id: uuid.UUID
    title: str = Field(max_length=_MAX_TITLE_CHARS)
    origin: dm.ArtifactOrigin
    quarantine_state: dm.QuarantineState
    review_state: dm.ArtifactReviewState
    # The original is isolated: these are its only retained trace.
    original_sha256: str
    original_bytes: int = Field(ge=0)
    content_hash: str
    cue_labels: list[str]
    provenance: ArtifactProvenanceView
    first_seen_at: datetime
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    # A governed threat artifact is never approvable or deliverable.
    approvable: bool = False
    deliverable: bool = False


class ThreatArtifactDetail(ThreatArtifactSummary):
    safe_preview_html: str = Field(max_length=_MAX_PREVIEW_CHARS)
    safe_preview_text: str = Field(max_length=_MAX_PREVIEW_CHARS)
    cue_manifest: dict[str, Any]


class ThreatArtifactPage(_StrictModel):
    items: list[ThreatArtifactSummary] = Field(max_length=_MAX_LIMIT)
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=_MAX_LIMIT)
    offset: int = Field(ge=0, le=_MAX_OFFSET)
    truncated: bool
    as_of: datetime


class ThreatReviewDecision(_StrictModel):
    decision: dm.ArtifactReviewState
    reviewer: str | None = Field(default=None, max_length=255)


class BundleImportRequest(_StrictModel):
    source_key: str = Field(min_length=1, max_length=64)
    bundle: dict[str, Any]


class BundleImportResult(_StrictModel):
    bundle_id: str
    imported: int = Field(ge=0)
    deduplicated: int = Field(ge=0)
    blocked: int = Field(ge=0)
    artifact_count: int = Field(ge=0)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _provenance_view(raw: Any) -> ArtifactProvenanceView:
    data = raw if isinstance(raw, dict) else {}
    return ArtifactProvenanceView(
        hash=str(data.get("hash") or ""),
        observed_at=str(data["observed_at"]) if data.get("observed_at") is not None else None,
        source=str(data["source"]) if data.get("source") is not None else None,
        parser_version=str(data["parser_version"]) if data.get("parser_version") is not None else None,
        reviewer=str(data["reviewer"]) if data.get("reviewer") is not None else None,
    )


def _summary(artifact: ThreatArtifact) -> ThreatArtifactSummary:
    manifest = artifact.cue_manifest if isinstance(artifact.cue_manifest, dict) else {}
    return ThreatArtifactSummary(
        threat_artifact_id=artifact.threat_artifact_id,
        title=str(artifact.title or "")[:_MAX_TITLE_CHARS],
        origin=artifact.origin,
        quarantine_state=artifact.quarantine_state,
        review_state=artifact.review_state,
        original_sha256=artifact.original_sha256,
        original_bytes=max(0, int(artifact.original_bytes or 0)),
        content_hash=artifact.content_hash,
        cue_labels=manifest_cue_labels(manifest),
        provenance=_provenance_view(artifact.provenance),
        first_seen_at=_as_utc(artifact.first_seen_at) or _utcnow(),
        reviewer=artifact.reviewer,
        reviewed_at=_as_utc(artifact.reviewed_at),
    )


def _detail(artifact: ThreatArtifact) -> ThreatArtifactDetail:
    base = _summary(artifact).model_dump()
    manifest = artifact.cue_manifest if isinstance(artifact.cue_manifest, dict) else {}
    return ThreatArtifactDetail(
        **base,
        safe_preview_html=str(artifact.safe_preview_html or "")[:_MAX_PREVIEW_CHARS],
        safe_preview_text=str(artifact.safe_preview_text or "")[:_MAX_PREVIEW_CHARS],
        cue_manifest=manifest,
    )


def _policy_health_view(policy: SourcePolicy, *, as_of: datetime) -> SourcePolicyHealthView:
    health = source_policy_health(policy, as_of=as_of)
    return SourcePolicyHealthView(
        source_policy_id=policy.source_policy_id,
        source_key=policy.source_key,
        owner=policy.owner,
        license=policy.license,
        parser=policy.parser,
        trust=policy.trust,
        enabled=policy.enabled,
        freshness=int(policy.freshness),
        bucket=health.bucket,
        is_stale=health.is_stale,
        is_failed=health.is_failed,
        admits_ingestion=health.admits_ingestion,
        age_days=health.age_days,
        consecutive_failures=health.consecutive_failures,
        last_success_at=_as_utc(policy.last_success_at),
        last_failure_at=_as_utc(policy.last_failure_at),
    )


@router.get("/artifacts", response_model=ThreatArtifactPage)
def list_threat_artifacts(
    review_state: dm.ArtifactReviewState | None = Query(default=None),
    origin: dm.ArtifactOrigin | None = Query(default=None),
    source_policy_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_MAX_OFFSET),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatArtifactPage:
    as_of = _utcnow()
    conditions: list[Any] = []
    if review_state is not None:
        conditions.append(ThreatArtifact.review_state == review_state)
    if origin is not None:
        conditions.append(ThreatArtifact.origin == origin)
    if source_policy_id is not None:
        conditions.append(ThreatArtifact.source_policy_id == source_policy_id)

    total = int(session.scalar(select(func.count()).select_from(ThreatArtifact).where(*conditions)) or 0)
    rows = list(
        session.scalars(
            select(ThreatArtifact)
            .where(*conditions)
            .order_by(ThreatArtifact.first_seen_at.desc(), ThreatArtifact.threat_artifact_id)
            .offset(offset)
            .limit(limit)
        )
    )
    items = [_summary(row) for row in rows]
    return ThreatArtifactPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        truncated=offset + len(items) < total,
        as_of=as_of,
    )


@router.get("/artifacts/{threat_artifact_id}", response_model=ThreatArtifactDetail)
def get_threat_artifact(
    threat_artifact_id: uuid.UUID,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatArtifactDetail:
    artifact = session.get(ThreatArtifact, threat_artifact_id)
    if artifact is None:
        raise NotFoundError("threat artifact not found")
    return _detail(artifact)


@router.post("/artifacts/{threat_artifact_id}/review", response_model=ThreatArtifactDetail)
def review_threat_artifact(
    threat_artifact_id: uuid.UUID,
    body: ThreatReviewDecision,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> ThreatArtifactDetail:
    if body.decision not in (dm.ArtifactReviewState.SAFE_REVIEWED, dm.ArtifactReviewState.REJECTED):
        raise ValidationError_("a review decision must be safe_reviewed or rejected")
    artifact = session.get(ThreatArtifact, threat_artifact_id, with_for_update=True)
    if artifact is None:
        raise NotFoundError("threat artifact not found")

    reviewer = (body.reviewer or principal.principal_id)[:255]
    now = _utcnow()
    artifact.review_state = body.decision
    artifact.reviewer = reviewer
    artifact.reviewed_at = now
    # The verdict governs the safe preview only; the original stays quarantined.
    artifact.quarantine_state = dm.QuarantineState.QUARANTINED
    provenance = dict(artifact.provenance) if isinstance(artifact.provenance, dict) else {}
    provenance["reviewer"] = reviewer
    artifact.provenance = provenance

    audit.record(
        session=session,
        actor=principal.principal_id,
        action="threat_library.review",
        object_type="threat_artifact",
        object_id=str(threat_artifact_id),
        detail={"decision": body.decision.value, "reviewer": reviewer},
    )
    session.commit()
    session.refresh(artifact)
    return _detail(artifact)


@router.post("/bundles/import", response_model=BundleImportResult, status_code=status.HTTP_201_CREATED)
def import_threat_bundle(
    body: BundleImportRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> BundleImportResult:
    verify_key = settings.require_threat_bundle_verify_key()
    import json as _json

    try:
        verified = verify_bundle(_json.dumps(body.bundle).encode("utf-8"), verify_key=verify_key)
    except BundleError as error:
        raise ValidationError_(f"bundle verification failed: {error}") from None

    # Replay protection: a bundle id already imported is refused, never reapplied.
    if session.scalar(
        select(ThreatBundleImport.threat_bundle_import_id)
        .where(ThreatBundleImport.bundle_id == verified.bundle_id)
        .limit(1)
    ):
        raise ConflictError("threat bundle has already been imported")

    policy = session.scalar(select(SourcePolicy).where(SourcePolicy.source_key == body.source_key).with_for_update())
    if policy is None:
        raise NotFoundError("source policy not found")
    if not policy.enabled:
        raise ConflictError("source policy is disabled; bundle import fails closed")

    imported = deduplicated = blocked = 0
    now = _utcnow()
    for artifact in verified.artifacts:
        result = ingest_threat_artifact(
            session,
            policy=policy,
            title=artifact.title,
            raw_html=artifact.raw_html,
            plain_text=artifact.plain_text,
            origin=dm.ArtifactOrigin.BUNDLE,
            allowed_image_hosts=settings.image_host_set(),
            parser_version=artifact.parser_version or "bundle",
            observed_at=now,
            source=artifact.source or body.source_key,
        )
        if result.created:
            imported += 1
        elif result.deduplicated:
            deduplicated += 1
        elif result.blocked:
            blocked += 1

    # A verified import is a successful source event: keep the policy fresh.
    policy.last_success_at = now
    policy.consecutive_failures = 0
    session.add(
        ThreatBundleImport(
            threat_bundle_import_id=uuid.uuid4(),
            bundle_id=verified.bundle_id,
            checksum=verified.checksum,
            imported_at=now,
            imported_by=principal.principal_id,
            artifact_count=len(verified.artifacts),
        )
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="threat_library.bundle.import",
        object_type="threat_bundle",
        object_id=verified.bundle_id,
        detail={
            "source_key": body.source_key,
            "checksum": verified.checksum,
            "imported": imported,
            "deduplicated": deduplicated,
            "blocked": blocked,
            "artifact_count": len(verified.artifacts),
        },
    )
    session.commit()
    return BundleImportResult(
        bundle_id=verified.bundle_id,
        imported=imported,
        deduplicated=deduplicated,
        blocked=blocked,
        artifact_count=len(verified.artifacts),
    )


@router.get("/sources/health", response_model=list[SourcePolicyHealthView])
def list_source_policy_health(
    stale_or_failed_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=_MAX_OFFSET),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> list[SourcePolicyHealthView]:
    as_of = _utcnow()
    rows = list(
        session.scalars(
            select(SourcePolicy)
            .order_by(SourcePolicy.source_key, SourcePolicy.source_policy_id)
            .offset(offset)
            .limit(limit)
        )
    )
    views = [_policy_health_view(policy, as_of=as_of) for policy in rows]
    if stale_or_failed_only:
        views = [view for view in views if view.is_stale or view.is_failed or not view.enabled]
    return views
