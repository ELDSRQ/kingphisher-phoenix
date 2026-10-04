"""Scheduled forward-a-phish curation (B2).

Periodically reads forwarded suspicious emails from the curation mailbox, pulls
the subject + body with the hardened :mod:`curation_mime` extractor, and
auto-clones each into a dated, deduplicated DRAFT template (the B1 pipeline).

Security posture (ingesting attacker-controlled content):
* parsing is bounded and non-rendering (``curation_mime``); attachments are
  never read;
* cloning is **model-free and deterministic** — no AI sees the attacker content
  on this path, so there is no prompt-injection surface here;
* the clone is forced to drop **all external images** (empty image allow-list),
  so a curated replica can never pull a remote resource / tracking beacon from
  the attacker; only self-contained raster ``data:image`` logos survive, and the
  allow-list sanitizer strips every script/form/iframe/handler and neutralizes
  every link to the training placeholder;
* everything lands as DRAFT for human review — never auto-approved or sent.
"""

from __future__ import annotations

import logging
from datetime import datetime
from html import escape
from typing import Any

import httpx
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_operator_api.curation_service import curate_forwarded_message

from kp_workers.jobs import WorkerContext
from kp_workers.providers.curation_mime import MAX_RAW_BYTES, extract_forwarded_phish

logger = logging.getLogger(__name__)

_CURATION_SOURCE = "forwarded-mailbox"
_HTTP_TIMEOUT = 10.0
#: Attacker content must never pull a remote resource into the replica.
_NO_EXTERNAL_IMAGES: set[str] = set()


def maybe_publish_curate(ctx: WorkerContext, now: datetime) -> None:
    """Enqueue one curation run per interval bucket (idempotent)."""
    interval = max(60, ctx.settings.curation_interval_seconds)
    bucket = int(now.timestamp()) // interval
    with ctx.session_factory() as session:
        enqueue_queue(
            session,
            topic="curate",
            payload={"scheduled_at": now.isoformat()},
            idempotency_key=f"curate-{bucket}",
        )
        dispatch_after_commit(session, lambda: ctx.audit_store.dispatch_pending_queue(ctx.queue))
        session.commit()


def _fetch_mailpit_forwards(settings: Any, address: str) -> list[bytes]:
    """Return raw bytes of recent messages addressed to the curation mailbox."""
    base = settings.mailpit_api_url.rstrip("/")
    limit = settings.curation_poll_limit
    raws: list[bytes] = []
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            summary = client.get(f"{base}/api/v1/search", params={"query": f"to:{address}", "limit": limit})
            if summary.status_code != 200:
                return []
            messages = summary.json().get("messages") or []
            for item in messages[:limit]:
                message_id = item.get("ID")
                if not message_id:
                    continue
                raw = client.get(f"{base}/api/v1/message/{message_id}/raw")
                if raw.status_code == 200 and 0 < len(raw.content) <= MAX_RAW_BYTES:
                    raws.append(raw.content)
    except (httpx.HTTPError, ValueError, KeyError):
        return []
    return raws


def process_curate(ctx: WorkerContext, message: dict[str, Any]) -> None:
    """One scheduled curation run over the forward-a-phish mailbox."""
    settings = ctx.settings
    address = (settings.curation_mailbox_address or "").strip().lower()
    if not address:
        return  # curation disabled: no mailbox configured
    if settings.reported_mailbox_provider != "mailpit":
        # Microsoft Graph body-fetch is a managed-path follow-up; fail closed.
        logger.info("curation: only the mailpit source is implemented; skipping run")
        return

    raws = _fetch_mailpit_forwards(settings, address)
    if not raws:
        return

    created = deduped = skipped = 0
    with ctx.session_factory() as session:
        for raw in raws:
            extracted = extract_forwarded_phish(raw)
            if extracted is None:
                skipped += 1
                continue
            html = extracted.html
            if not html:
                # Plain-text-only forward: wrap escaped text so the clone has a body.
                html = "<p>" + escape(extracted.text or "").replace("\n", "<br/>") + "</p>"
            result = curate_forwarded_message(
                session,
                subject=extracted.subject,
                raw_html=html,
                plain_text=extracted.text,
                source=_CURATION_SOURCE,
                allowed_image_hosts=_NO_EXTERNAL_IMAGES,
                requested_by="curation-worker",
            )
            if result.created:
                created += 1
            elif result.deduplicated:
                deduped += 1
            else:
                skipped += 1
        session.commit()
    logger.info("curation run complete: created=%d deduplicated=%d skipped=%d", created, deduped, skipped)
