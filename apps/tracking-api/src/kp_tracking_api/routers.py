"""Tracking endpoints.

Stateless and token-based: no sessions, no cookies. The only identifier in
requests is a SHA-256 hash of the tracking token (`token_hash`); the raw token
is never stored or echoed. Events are recorded with a minimized client IP
prefix + truncated user agent (HIGH-17 / WS-9) and a confidence, then the
mailbox-reader/correction pipeline can downweight low-confidence events
(e.g. automated scanners).

Security posture (HIGH-04 / WS-9):
- clicks are deduplicated like opens, so URL-scanning bots cannot inflate them
- open/click dedup is storage-enforced via the partial unique index
  `uq_events_open_click_dedup` (metric-integrity): INSERT ... ON CONFLICT
  DO NOTHING closes the SELECT-then-INSERT race for concurrent
  double-clicks/prefetches; the first event wins and duplicates are no-ops
- `X-Forwarded-For` is only honored when the direct peer is a configured
  reverse proxy, so a spoofed header cannot change attribution
- `/v1/corrections` is gated by a shared-secret bearer token and IP rate limit
- every endpoint is rate-limited (per token for track, per IP for corrections)
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from kp_database.models import (
    RecipientAssignment,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
    TrainingResource,
)
from kp_database.privacy import CLIENT_IP_MAX, minimize_ip, minimize_user_agent
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

router = APIRouter(prefix="/v1")

GIF_BYTES = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"  # noqa: E501
TOKEN_HASH_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


@router.get("/training/awareness", response_class=HTMLResponse)
def training_awareness() -> HTMLResponse:
    """Local, dependency-free landing page for development simulations."""
    return HTMLResponse(
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security awareness training</title>
<style>
body{font:18px/1.5 system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1.5rem;color:#172033}
main{border:1px solid #ccd4e0;border-radius:12px;padding:2rem}
h1{line-height:1.2;color:#174a7e}li{margin:.7rem 0}
</style>
</head><body><main><h1>This was a security awareness simulation</h1>
<p>No credentials were collected. The link click was recorded for the campaign report.</p>
<h2>Warning signs to remember</h2><ul>
<li>Unexpected urgency or pressure</li>
<li>An unfamiliar sender or destination</li>
<li>Requests to open a link before independently verifying the message</li>
</ul>
<p>When in doubt, report the message to your IT or security contact.</p></main></body></html>""",
        headers={"Cache-Control": "no-store"},
    )


def _session(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    with factory() as session:
        yield session


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%")[0])
        return True
    except ValueError:
        return False


def _peer_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _client_ip(request: Request) -> str | None:
    """Client IP for attribution/rate-limit keys.

    `X-Forwarded-For` is only trusted when the direct peer is a configured
    reverse proxy (nginx/caddy). Without that, the first entry is attacker
    controlled and ignored in favor of the peer address.
    """
    peer = _peer_ip(request)
    if peer is None:
        return None
    trusted = {p.strip() for p in request.app.state.settings.trusted_proxies.split(",") if p.strip()}
    if peer in trusted:
        fwd = request.headers.get("X-Forwarded-For")
        if fwd:
            first = fwd.split(",")[0].strip()
            if _is_valid_ip(first):
                return first[:CLIENT_IP_MAX]
    return peer[:CLIENT_IP_MAX]


def _token_rate_limited(request: Request, token_hash: str) -> None:
    """Per-token limit on unauthenticated track endpoints.

    `token_hash` is a path parameter, so FastAPI injects it into this
    dependency; the key lives in memory only and is never logged.
    """
    # Reject attacker-controlled high-cardinality strings before allocating a
    # limiter bucket or querying storage. Token hashes are SHA-256 hex values.
    if TOKEN_HASH_RE.fullmatch(token_hash) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if not request.app.state.token_limiter.allow(token_hash.lower()):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _ip_rate_limited(request: Request) -> None:
    if not request.app.state.ip_limiter.allow(_client_ip(request) or "unknown"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _global_rate_limited(request: Request) -> None:
    if not request.app.state.global_limiter.allow("tracking"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _require_corrections_secret(request: Request) -> None:
    expected = request.app.state.settings.corrections_secret
    if not expected:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="corrections not configured")
    header = request.headers.get("Authorization", "")
    supplied = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


def _resolve_active_token(token_hash: str, session: Session) -> TrackingToken | None:
    token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == token_hash))
    if token is None or token.status != dm.TokenStatus.ACTIVE:
        return None
    if token.expires_at and token.expires_at < datetime.now(UTC):
        return None
    return token


def _record_first_event(
    request: Request,
    session: Session,
    token: TrackingToken,
    event_type: dm.EventType,
) -> None:
    """Insert the token's first OPENED/CLICKED event; duplicates are no-ops.

    metric-integrity: dedup relies on the partial unique index
    ``uq_events_open_click_dedup`` instead of a SELECT-then-INSERT check, so
    concurrent requests cannot create duplicate rows — the first INSERT wins
    and ON CONFLICT DO NOTHING discards the losers.
    """
    session.execute(
        pg_insert(TrackingEvent)
        .values(
            event_id=uuid.uuid4(),
            event_type=event_type,
            token_id=token.token_id,
            campaign_id=token.campaign_id,
            confidence=dm.Confidence.MEDIUM,
            occurred_at=datetime.now(UTC),
            client_ip=minimize_ip(_client_ip(request)),
            user_agent=minimize_user_agent(request.headers.get("user-agent")),
            payload={},
        )
        .on_conflict_do_nothing()
    )
    session.commit()


@router.get(
    "/track/open/{token_hash}",
    dependencies=[Depends(_token_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
def record_open(
    token_hash: str,
    request: Request,
    session: Session = Depends(_session),
) -> Response:
    token = _resolve_active_token(token_hash, session)
    if token is None:
        return Response(status_code=404)

    _record_first_event(request, session, token, dm.EventType.OPENED)
    return Response(content=GIF_BYTES, media_type="image/gif", headers={"Cache-Control": "no-store"})


@router.get(
    "/track/click/{token_hash}",
    dependencies=[Depends(_token_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
def record_click(
    token_hash: str,
    request: Request,
    session: Session = Depends(_session),
) -> Response:
    token = _resolve_active_token(token_hash, session)
    if token is None:
        return Response(status_code=404)

    _record_first_event(request, session, token, dm.EventType.CLICKED)
    return Response(
        status_code=302, headers={"Location": request.app.state.settings.training_base_url, "Cache-Control": "no-store"}
    )


class CorrectionBody(BaseModel):
    token_hash: str
    # 2000 matches the storage-side truncation limit in submit_correction.
    correction: str = Field(max_length=2000)
    rationale: str = Field(max_length=2000)


@router.post(
    "/training/{token_hash}/complete",
    dependencies=[Depends(_token_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
def complete_training(
    token_hash: str,
    session: Session = Depends(_session),
) -> dict[str, str]:
    """Complete training using the campaign's expiring recipient token.

    The endpoint stores no cookie or recipient identifier. Replays are
    idempotent while the token remains active, and revoked/expired tokens fail
    closed through ``_resolve_active_token``.
    """
    token = _resolve_active_token(token_hash, session)
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    # Serialize completion attempts for this recipient/campaign so concurrent
    # token replays cannot create duplicate training assignments or events.
    recipient_assignment = session.get(RecipientAssignment, token.recipient_assignment_id, with_for_update=True)
    if recipient_assignment is None or recipient_assignment.campaign_id != token.campaign_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    training = session.scalar(
        select(TrainingAssignment).where(
            TrainingAssignment.recipient_id == recipient_assignment.recipient_id,
            TrainingAssignment.campaign_id == token.campaign_id,
        )
    )
    now = datetime.now(UTC)
    if training is None:
        resource = session.scalar(
            select(TrainingResource)
            .where(
                TrainingResource.approval_state == dm.TemplateApprovalState.APPROVED,
                TrainingResource.requires_completion.is_(True),
            )
            .order_by(TrainingResource.training_resource_id)
            .limit(1)
        )
        if resource is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="approved training resource unavailable",
            )
        training = TrainingAssignment(
            training_assignment_id=uuid.uuid4(),
            recipient_id=recipient_assignment.recipient_id,
            resource_id=resource.training_resource_id,
            campaign_id=token.campaign_id,
            assigned_at=now,
            completed_at=now,
            status=dm.TrainingAssignmentStatus.COMPLETED,
        )
        session.add(training)
    elif training.completed_at is None:
        training.completed_at = now
        training.status = dm.TrainingAssignmentStatus.COMPLETED
    existing_event = session.scalar(
        select(TrackingEvent).where(
            TrackingEvent.token_id == token.token_id,
            TrackingEvent.event_type == dm.EventType.TRAINING_COMPLETED,
        )
    )
    if existing_event is None:
        session.add(
            TrackingEvent(
                event_id=uuid.uuid4(),
                event_type=dm.EventType.TRAINING_COMPLETED,
                token_id=token.token_id,
                recipient_id=recipient_assignment.recipient_id,
                campaign_id=token.campaign_id,
                confidence=dm.Confidence.HIGH,
                occurred_at=training.completed_at or now,
                payload={},
            )
        )
    session.commit()
    return {
        "training_assignment_id": str(training.training_assignment_id),
        "status": dm.TrainingAssignmentStatus.COMPLETED.value,
    }


@router.post(
    "/corrections",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_corrections_secret), Depends(_ip_rate_limited)],
)
def submit_correction(body: CorrectionBody, session: Session = Depends(_session)) -> dict[str, str]:
    token = _resolve_active_token(body.token_hash, session)
    if token is None:
        raise NotFoundError("token not found")
    now = datetime.now(UTC)
    dup = session.scalar(
        select(TrackingEvent).where(
            TrackingEvent.token_id == token.token_id,
            TrackingEvent.event_type == dm.EventType.EVENT_CORRECTED,
        )
    )
    if dup is not None:
        raise ConflictError("correction already exists for this token")
    event = TrackingEvent(
        event_id=uuid.uuid4(),
        event_type=dm.EventType.EVENT_CORRECTED,
        token_id=token.token_id,
        campaign_id=token.campaign_id,
        confidence=dm.Confidence.HIGH,
        occurred_at=now,
        payload={"correction": body.correction[:2000], "rationale": body.rationale[:2000]},
    )
    session.add(event)
    session.commit()
    return {"event_id": str(event.event_id)}
