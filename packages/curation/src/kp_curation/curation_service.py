"""Auto-curate a forwarded real phishing email into a dated, deduped DRAFT clone.

Users forward suspicious emails to a designated mailbox; each genuine external
phish is cloned (payload neutralized, exactly like an operator clone) into a
DRAFT template the operator can review and approve. Over time this builds a
constantly-refreshed library of replicas drawn from what is actually targeting
the organization.

Deduplicated by a content hash, so the same campaign forwarded by many users
yields a single template. Everything lands as DRAFT — never auto-approved and
never auto-sent; a human still reviews and approves before any campaign uses it,
and a campaign only sends to a domain named in a signed Rules-of-Engagement.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from kp_database.models import TemplateVersion
from kp_domain_models import models as dm
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_curation.clone_service import CloneError, clone_real_message

#: model_id stamped on auto-curated clones, distinct from operator clones.
CURATED_MODEL_ID = "auto-curated/1"
_MAX_BODY = 400_000


@dataclass(slots=True)
class CurationResult:
    created: bool
    deduplicated: bool
    template_version_id: str | None
    reason: str | None = None


def curation_hash(subject: str, raw_html: str) -> str:
    """Content fingerprint used to dedupe the same campaign forwarded repeatedly."""
    normalized = re.sub(r"\s+", " ", f"{subject}\0{raw_html}").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def curate_forwarded_message(
    session: Session,
    *,
    subject: str,
    raw_html: str,
    plain_text: str | None,
    source: str,
    allowed_image_hosts: Iterable[str],
    requested_by: str,
) -> CurationResult:
    """Clone one forwarded phish into a DRAFT template, or report a duplicate.

    Returns without raising for the ordinary non-success paths (empty input,
    duplicate campaign, unclonable content) so a scheduled poller can keep going
    across a batch; genuinely unexpected errors still propagate.
    """
    subject = (subject or "").strip()[:998]
    if not subject or not (raw_html or "").strip():
        return CurationResult(False, False, None, reason="empty subject or body")

    chash = curation_hash(subject, raw_html)
    existing = session.scalar(
        select(TemplateVersion.template_version_id)
        .where(TemplateVersion.input_hash == chash, TemplateVersion.model_id == CURATED_MODEL_ID)
        .limit(1)
    )
    if existing is not None:
        return CurationResult(False, True, str(existing), reason="duplicate campaign")

    try:
        cloned = clone_real_message(
            subject=subject, raw_html=raw_html, plain_text=plain_text, allowed_image_hosts=allowed_image_hosts
        )
    except CloneError as error:
        return CurationResult(False, False, None, reason=f"clone failed: {error}")

    first_seen = datetime.now(UTC).isoformat()
    template = TemplateVersion(
        template_version_id=uuid.uuid4(),
        campaign_id=None,
        version=1,
        generator_version="auto-curate-0.1.0",
        prompt_template_version="auto-curate-0.1.0",
        model_id=CURATED_MODEL_ID,
        input_hash=chash,
        raw_proposal={
            "requested_by": requested_by,
            "subject": cloned.subject,
            "plain_text": cloned.plain_text,
            "safe_html": cloned.safe_html,
            "source": source,
            **cloned.provenance,
        },
        # Curation provenance the console surfaces (dated, deduplicated, source).
        edited_content={
            "auto_curated": True,
            "curation_hash": chash,
            "source": source,
            "first_seen": first_seen,
        },
        subject=cloned.subject[:_MAX_BODY],
        plain_text=cloned.plain_text[:_MAX_BODY],
        safe_html=cloned.safe_html[:_MAX_BODY],
        approval_state=dm.TemplateApprovalState.DRAFT,
    )
    session.add(template)
    session.flush()
    return CurationResult(True, False, str(template.template_version_id))
