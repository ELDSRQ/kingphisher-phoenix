"""Governed current-threat library service invariants (W3-02).

Pins: originals are quarantined + minimized (hash/size only, never raw bytes),
safe previews reuse the sanitizer + the W3-01 cue manifest, no embedded URL is
ever contacted, disabled/stale/failed sources fail closed, and duplicate imports
are idempotent.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from kp_curation.threat_library import (
    FAILURE_THRESHOLD,
    artifact_hash,
    build_safe_artifact,
    ingest_threat_artifact,
    policy_admits_ingestion,
    source_policy_health,
)
from kp_database.models import SourcePolicy, ThreatArtifact
from kp_domain_models import models as dm
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

_LURE_HTML = (
    "<p>Dear user, your Microsoft 365 account is locked. "
    '<a href="https://evil.example/login">Verify your account now</a></p>'
    "<script>steal()</script>"
)


def _policy(engine: Engine, **overrides: object) -> SourcePolicy:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "source_key": "threat-feed-1",
        "owner": "threat-intel-team",
        "license": "CC-BY-4.0",
        "parser": "rss/1",
        "trust": dm.SourceTrust.PARTNER,
        "freshness": 7,
        "enabled": True,
        "last_success_at": now - timedelta(hours=1),
        "consecutive_failures": 0,
    }
    defaults.update(overrides)
    policy = SourcePolicy(**defaults)
    with Session(engine) as session:
        session.add(policy)
        session.commit()
        session.refresh(policy)
        session.expunge(policy)
    return policy


# --- Safe preview: sanitizer + W3-01 cue manifest, original minimized ---


def test_safe_preview_neutralizes_lure_and_carries_cue_manifest() -> None:
    safe = build_safe_artifact(title="URGENT: verify your account", raw_html=_LURE_HTML)
    # The hostile destination and active content never reach the safe preview.
    assert "evil.example" not in safe.safe_preview_html
    assert "<script" not in safe.safe_preview_html.lower()
    # The deterministic W3-01 cue manifest rides along with the preview.
    assert safe.cue_manifest["ontology_version"] == "cue-ontology/1"
    cue_types = {cue["cue_type"] for cue in safe.cue_manifest["cues"]}
    assert {"urgency", "credential_request", "brand_impersonation"} <= cue_types
    # A transformation receipt records the neutralized link, by hash not raw URL.
    assert any(rec["component"] == "anchor_href" for rec in safe.cue_manifest["transformations"])
    assert "evil.example" not in json.dumps(safe.cue_manifest)


def test_original_is_minimized_hash_and_size_only() -> None:
    safe = build_safe_artifact(title="Account locked", raw_html=_LURE_HTML)
    assert len(safe.original_sha256) == 64
    assert safe.original_bytes > 0
    # The SafeArtifact exposes no raw-original field at all.
    assert not hasattr(safe, "raw_html")
    assert "evil.example" not in json.dumps(
        {"html": safe.safe_preview_html, "text": safe.safe_preview_text, "manifest": safe.cue_manifest}
    )


def test_content_hash_is_stable_and_normalized() -> None:
    # Case-insensitive and tolerant of surrounding/collapsible whitespace.
    a = artifact_hash("Subject", "<p>Body</p>", None)
    b = artifact_hash("  SUBJECT", "<p>Body</p>", "")
    assert a == b
    # A genuinely different body yields a different fingerprint.
    assert a != artifact_hash("Subject", "<p>Other</p>", None)


# --- Fail-closed source health ---


def test_disabled_source_fails_closed(engine: Engine) -> None:
    policy = _policy(engine, enabled=False)
    health = source_policy_health(policy, as_of=datetime.now(UTC))
    assert health.bucket == "disabled" and not health.admits_ingestion
    result = ingest_threat_artifact(
        _session(engine), policy=policy, title="x", raw_html=_LURE_HTML, origin=dm.ArtifactOrigin.FEED
    )
    assert result.blocked and not result.created


def test_stale_source_fails_closed(engine: Engine) -> None:
    policy = _policy(engine, freshness=7, last_success_at=datetime.now(UTC) - timedelta(days=30))
    health = source_policy_health(policy, as_of=datetime.now(UTC))
    assert health.is_stale and health.bucket == "stale" and not health.admits_ingestion
    assert not policy_admits_ingestion(policy, as_of=datetime.now(UTC))


def test_failed_source_fails_closed(engine: Engine) -> None:
    policy = _policy(engine, consecutive_failures=FAILURE_THRESHOLD)
    health = source_policy_health(policy, as_of=datetime.now(UTC))
    assert health.is_failed and health.bucket == "failed" and not health.admits_ingestion


def test_first_ingest_allowed_before_any_success(engine: Engine) -> None:
    policy = _policy(engine, last_success_at=None)
    health = source_policy_health(policy, as_of=datetime.now(UTC))
    assert health.bucket == "awaiting_first_success" and health.admits_ingestion


# --- Ingestion: quarantine + dedupe ---


def _session(engine: Engine) -> Session:
    return Session(engine)


def test_ingest_quarantines_original_and_stores_safe_preview(engine: Engine) -> None:
    policy = _policy(engine)
    with Session(engine) as session:
        result = ingest_threat_artifact(
            session,
            policy=policy,
            title="URGENT: verify your Microsoft 365 account",
            raw_html=_LURE_HTML,
            origin=dm.ArtifactOrigin.MAILBOX,
        )
        session.commit()
        assert result.created and not result.blocked
        assert result.threat_artifact_id is not None
        artifact = session.get(ThreatArtifact, uuid.UUID(result.threat_artifact_id))
        assert artifact is not None
        # Invariant: the original is quarantined; nothing marks it deliverable.
        assert artifact.quarantine_state == dm.QuarantineState.QUARANTINED
        assert artifact.review_state == dm.ArtifactReviewState.PENDING
        # Only the digest/size of the original is kept.
        assert len(artifact.original_sha256) == 64 and artifact.original_bytes > 0
        assert "evil.example" not in artifact.safe_preview_html
        assert artifact.cue_manifest["ontology_version"] == "cue-ontology/1"
        # Minimized provenance recorded.
        assert artifact.provenance["hash"] == artifact.content_hash
        assert artifact.provenance["source"] == "threat-feed-1"
        assert artifact.provenance["reviewer"] is None


def test_duplicate_import_is_idempotent(engine: Engine) -> None:
    policy = _policy(engine)
    with Session(engine) as session:
        first = ingest_threat_artifact(
            session, policy=policy, title="Verify your account", raw_html=_LURE_HTML, origin=dm.ArtifactOrigin.FEED
        )
        session.commit()
        second = ingest_threat_artifact(
            session, policy=policy, title="Verify your account", raw_html=_LURE_HTML, origin=dm.ArtifactOrigin.FEED
        )
        session.commit()
        assert first.created and second.deduplicated
        assert second.threat_artifact_id == first.threat_artifact_id
        count = len(list(session.scalars(select(ThreatArtifact))))
        assert count == 1  # the repeat import collapsed onto the first artifact
