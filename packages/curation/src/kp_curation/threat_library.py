"""Governed current-threat library: quarantined originals, safe previews (W3-02).

This is the service layer behind the operator's current-threat library and
reviewer workbench (Report-04). It turns a HOSTILE threat artifact — a real lure
from a feed, a reported mailbox, or a signed offline bundle — into a governed,
reviewable record, under four hard invariants:

* **The original is isolated.** Its exact bytes are never persisted; only a
  SHA-256 and a byte length are kept (like W3-01's hashed-offset evidence), so a
  licensed or PII-bearing original is minimized, not stored.
* **The original is quarantined and inert.** A :class:`ThreatArtifact` is always
  ``QUARANTINED`` and is never approvable or deliverable. What an operator
  reviews and reuses is the SAFE preview.
* **The safe preview reuses the shared pipeline.** It is produced by
  :func:`kp_curation.clone_real_message` — the same allow-list sanitizer and
  payload-neutralization used for operator clones — and carries the deterministic
  W3-01 cue manifest. No network is ever contacted: embedded URLs are neutralized
  to the inert training placeholder, never fetched.
* **Disabled or stale sources fail closed.** A policy that is disabled, stale
  past its freshness SLA, or failing does not admit ingestion.

Imports are idempotent: the same artifact (by content hash) collapses to a
single record, so a bundle re-presented or a lure reported by many users does
not duplicate.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from kp_domain_models import models as dm
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_curation.clone_service import CloneError, clone_real_message

#: parser id stamped when a safe preview is produced by the shared clone pipeline.
PARSER_VERSION = "threat-safe-preview/1"
_MAX_BODY = 400_000

#: Consecutive ingestion failures at or above which a source fails closed.
FAILURE_THRESHOLD = 3

HealthBucket = Literal["disabled", "failed", "stale", "awaiting_first_success", "healthy"]


class _GovernedPolicy(Protocol):
    enabled: bool
    freshness: int
    last_success_at: datetime | None
    consecutive_failures: int


@dataclass(frozen=True)
class SafeArtifact:
    """The safe, reviewable product of neutralizing one hostile original.

    Carries no raw original content — only its hash/size and the sanitized
    preview with the deterministic cue manifest.
    """

    content_hash: str
    title: str
    safe_preview_html: str
    safe_preview_text: str
    cue_manifest: dict[str, Any]
    original_sha256: str
    original_bytes: int


@dataclass(frozen=True)
class SourcePolicyHealth:
    """Freshness/failure health of a source policy for the operator System view."""

    bucket: HealthBucket
    is_stale: bool
    is_failed: bool
    admits_ingestion: bool
    age_days: float | None
    consecutive_failures: int


@dataclass(frozen=True)
class IngestResult:
    created: bool
    deduplicated: bool
    blocked: bool
    threat_artifact_id: str | None
    reason: str | None = None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def artifact_hash(title: str, raw_html: str, plain_text: str | None) -> str:
    """Deduplication fingerprint: the same campaign collapses to one artifact.

    Whitespace- and case-normalized over title + body so trivially re-forwarded
    or re-bundled copies of one lure share a hash. Distinct from
    ``original_sha256`` (the exact digest of the hostile original).
    """

    normalized = re.sub(r"\s+", " ", f"{title}\0{raw_html}\0{plain_text or ''}").strip().lower()
    return _sha256(normalized.encode("utf-8"))


def _original_digest(title: str, raw_html: str, plain_text: str | None) -> tuple[str, int]:
    """SHA-256 and byte length of the exact original — the only trace we keep."""

    raw = f"{title}\0{raw_html}\0{plain_text or ''}".encode()
    return _sha256(raw), len(raw)


def build_safe_artifact(
    *,
    title: str,
    raw_html: str,
    plain_text: str | None = None,
    allowed_image_hosts: Any = (),
) -> SafeArtifact:
    """Neutralize one hostile original into a safe, cue-tagged preview.

    Reuses :func:`clone_real_message`, so the preview goes through the same
    allow-list sanitizer (scripts/forms/iframes/media/trackers dropped, every
    link neutralized to the inert training placeholder — never fetched) and
    carries the deterministic W3-01 cue manifest. Raises :class:`CloneError` for
    empty/unclonable input. The raw original is hashed and sized here and then
    discarded; it is never returned or stored.
    """

    original_sha256, original_bytes = _original_digest(title, raw_html, plain_text)
    cloned = clone_real_message(
        subject=title,
        raw_html=raw_html,
        plain_text=plain_text,
        allowed_image_hosts=allowed_image_hosts,
    )
    return SafeArtifact(
        content_hash=artifact_hash(title, raw_html, plain_text),
        title=cloned.subject[:_MAX_BODY],
        safe_preview_html=cloned.safe_html[:_MAX_BODY],
        safe_preview_text=cloned.plain_text[:_MAX_BODY],
        cue_manifest=cloned.cue_manifest,
        original_sha256=original_sha256,
        original_bytes=original_bytes,
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def source_policy_health(policy: _GovernedPolicy, *, as_of: datetime) -> SourcePolicyHealth:
    """Classify a source policy's freshness/failure health (fail-closed).

    ``disabled`` and ``failed`` and ``stale`` do not admit ingestion;
    ``awaiting_first_success`` (enabled, never yet succeeded) and ``healthy`` do.
    A source is ``stale`` when its most recent success is older than its
    freshness SLA. These are the states the operator System view surfaces.
    """

    now = _as_utc(as_of) or datetime.now(UTC)
    failures = max(0, int(policy.consecutive_failures))
    last_success = _as_utc(policy.last_success_at)
    age_days = (now - last_success).total_seconds() / 86_400.0 if last_success is not None else None

    is_failed = failures >= FAILURE_THRESHOLD
    is_stale = age_days is not None and age_days > float(policy.freshness)

    if not policy.enabled:
        bucket: HealthBucket = "disabled"
    elif is_failed:
        bucket = "failed"
    elif is_stale:
        bucket = "stale"
    elif last_success is None:
        bucket = "awaiting_first_success"
    else:
        bucket = "healthy"

    admits = bucket in ("awaiting_first_success", "healthy")
    return SourcePolicyHealth(
        bucket=bucket,
        is_stale=is_stale,
        is_failed=is_failed,
        admits_ingestion=admits,
        age_days=round(age_days, 6) if age_days is not None else None,
        consecutive_failures=failures,
    )


def policy_admits_ingestion(policy: _GovernedPolicy, *, as_of: datetime) -> bool:
    """Fail-closed gate: may an artifact be ingested against this policy now?"""

    return source_policy_health(policy, as_of=as_of).admits_ingestion


def ingest_threat_artifact(
    session: Session,
    *,
    policy: dm.SourcePolicy | Any,
    title: str,
    raw_html: str,
    plain_text: str | None = None,
    origin: dm.ArtifactOrigin,
    allowed_image_hosts: Any = (),
    parser_version: str = PARSER_VERSION,
    observed_at: datetime | None = None,
    source: str | None = None,
) -> IngestResult:
    """Ingest one hostile artifact into the governed library, or report why not.

    Fails closed when ``policy`` does not admit ingestion (disabled/stale/failed).
    Deduplicates by content hash (idempotent: a repeat import returns the existing
    artifact). On success the original is quarantined (hash/size only) and a safe
    preview with the W3-01 cue manifest is stored. Returns without raising for the
    ordinary non-success paths so a batch poller can continue.
    """

    from kp_database.models import ThreatArtifact as ThreatArtifactRow

    as_of = _as_utc(observed_at) or datetime.now(UTC)
    title = (title or "").strip()[:998]
    if not title or not (raw_html or "").strip() and not (plain_text or "").strip():
        return IngestResult(False, False, False, None, reason="empty title or content")

    if not policy_admits_ingestion(policy, as_of=as_of):
        health = source_policy_health(policy, as_of=as_of)
        return IngestResult(False, False, True, None, reason=f"source fails closed: {health.bucket}")

    try:
        safe = build_safe_artifact(
            title=title,
            raw_html=raw_html,
            plain_text=plain_text,
            allowed_image_hosts=allowed_image_hosts,
        )
    except CloneError as error:
        return IngestResult(False, False, False, None, reason=f"neutralization failed: {error}")

    existing = session.scalar(
        select(ThreatArtifactRow.threat_artifact_id).where(ThreatArtifactRow.content_hash == safe.content_hash).limit(1)
    )
    if existing is not None:
        return IngestResult(False, True, False, str(existing), reason="duplicate artifact")

    provenance = dm.ArtifactProvenance(
        hash=safe.content_hash,
        observed_at=as_of,
        source=(source or getattr(policy, "source_key", None) or "unknown")[:255],
        parser_version=parser_version[:255],
        reviewer=None,
    )
    artifact = ThreatArtifactRow(
        source_policy_id=getattr(policy, "source_policy_id", None),
        content_hash=safe.content_hash,
        title=safe.title,
        origin=origin,
        quarantine_state=dm.QuarantineState.QUARANTINED,
        original_sha256=safe.original_sha256,
        original_bytes=safe.original_bytes,
        safe_preview_html=safe.safe_preview_html,
        safe_preview_text=safe.safe_preview_text,
        cue_manifest=safe.cue_manifest,
        provenance=provenance.model_dump(mode="json"),
        review_state=dm.ArtifactReviewState.PENDING,
        reviewer=None,
        reviewed_at=None,
        first_seen_at=as_of,
    )
    session.add(artifact)
    session.flush()
    return IngestResult(True, False, False, str(artifact.threat_artifact_id))
