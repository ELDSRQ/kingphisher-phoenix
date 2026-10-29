"""Auto-curation of forwarded phish into dated, deduped DRAFT clones (hermetic)."""

from __future__ import annotations

import uuid
from typing import Any

from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_curation.curation_service import CURATED_MODEL_ID, curate_forwarded_message
from kp_domain_models import models as dm

_HTML = '<p>Dear user, your Microsoft 365 password expires. <a href="https://evil.example/x">Verify now</a>.</p>'


class _Session:
    def __init__(self, dedup_return: uuid.UUID | None = None) -> None:
        self.added: list[Any] = []
        self.dedup_return = dedup_return
        self.flushed = 0

    def scalar(self, _stmt: object) -> uuid.UUID | None:
        return self.dedup_return

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flushed += 1


def _curate(session: _Session, subject: str = "MS365: verify your account", html: str = _HTML) -> Any:
    return curate_forwarded_message(
        session,  # type: ignore[arg-type]
        subject=subject,
        raw_html=html,
        plain_text=None,
        source="forwarded-mailbox",
        allowed_image_hosts=set(),
        requested_by="curator-1",
    )


def test_curate_creates_dated_neutralized_draft() -> None:
    s = _Session()
    r = _curate(s)
    assert r.created and not r.deduplicated
    t = s.added[0]
    assert t.model_id == CURATED_MODEL_ID
    assert t.approval_state == dm.TemplateApprovalState.DRAFT
    assert t.edited_content["auto_curated"] is True
    assert t.edited_content["source"] == "forwarded-mailbox"
    assert t.edited_content["first_seen"]
    # payload neutralized: the real link is gone, only the training placeholder remains
    assert TRAINING_URL_PLACEHOLDER in t.safe_html and "evil.example" not in t.safe_html


def test_curate_dedups_the_same_campaign() -> None:
    s = _Session(dedup_return=uuid.uuid4())
    r = _curate(s)
    assert r.deduplicated and not r.created
    assert s.added == []


def test_curate_rejects_empty_input() -> None:
    s = _Session()
    r = curate_forwarded_message(
        s,  # type: ignore[arg-type]
        subject="   ",
        raw_html="",
        plain_text=None,
        source="x",
        allowed_image_hosts=set(),
        requested_by="u",
    )
    assert not r.created and not r.deduplicated and r.reason and "empty" in r.reason


def test_curate_populates_cue_manifest_and_label_projection() -> None:
    s = _Session()
    r = _curate(s)
    assert r.created
    t = s.added[0]
    # Structured manifest stored in its own column, isolated from safe_html.
    assert t.cue_manifest["ontology_version"] == "cue-ontology/1"
    assert t.cue_manifest["source"] == "reconstruction"
    cue_types = {cue["cue_type"] for cue in t.cue_manifest["cues"]}
    assert {"brand_impersonation", "credential_request"} <= cue_types
    # warning_cues is the deterministic string-label projection of the manifest.
    assert t.warning_cues == sorted(cue_types)
    # A transformation receipt records the neutralized real link.
    assert any(rec["component"] == "anchor_href" for rec in t.cue_manifest["transformations"])
    # The raw malicious destination never reaches the manifest.
    import json as _json

    assert "evil.example" not in _json.dumps(t.cue_manifest)
