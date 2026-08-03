"""Tracking endpoints.

Stateless and token-based: no sessions, no cookies. The only identifier in
requests is a SHA-256 hash of the tracking token (`token_hash`); the raw token
is never stored or echoed. Events are recorded with client IP + user agent and
a confidence, then the mailbox-reader/correction pipeline can downweight
low-confidence events (e.g. automated scanners).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response, status
from kp_database.models import TrackingEvent, TrackingToken
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

router = APIRouter(prefix="/v1")

GIF_BYTES = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"  # noqa: E501


def _session(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    with factory() as session:
        yield session


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()[:45]
    return request.client.host[:45] if request.client else None


@router.get("/track/open/{token_hash}")
def record_open(token_hash: str, request: Request, session: Session = Depends(_session)) -> Response:
    token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == token_hash))
    if token is None or token.status != dm.TokenStatus.ACTIVE:
        return Response(status_code=404)
    if token.expires_at and token.expires_at < datetime.now(UTC):
        return Response(status_code=404)

    existing = session.scalar(
        select(TrackingEvent).where(
            TrackingEvent.token_id == token.token_id,
            TrackingEvent.event_type == dm.EventType.OPENED,
        )
    )
    if existing is None:
        session.add(TrackingEvent(
            event_id=uuid.uuid4(),
            event_type=dm.EventType.OPENED,
            token_id=token.token_id,
            campaign_id=token.campaign_id,
            confidence=dm.Confidence.MEDIUM,
            occurred_at=datetime.now(UTC),
            client_ip=_client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:1000],
            payload={},
        ))
        session.commit()
    return Response(content=GIF_BYTES, media_type="image/gif", headers={"Cache-Control": "no-store"})


@router.get("/track/click/{token_hash}")
def record_click(token_hash: str, request: Request, session: Session = Depends(_session)) -> Response:
    token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == token_hash))
    if token is None or token.status != dm.TokenStatus.ACTIVE:
        return Response(status_code=404)
    if token.expires_at and token.expires_at < datetime.now(UTC):
        return Response(status_code=404)
    session.add(TrackingEvent(
        event_id=uuid.uuid4(),
        event_type=dm.EventType.CLICKED,
        token_id=token.token_id,
        campaign_id=token.campaign_id,
        confidence=dm.Confidence.MEDIUM,
        occurred_at=datetime.now(UTC),
        client_ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:1000],
        payload={},
    ))
    session.commit()
    return Response(status_code=302,
                    headers={"Location": request.app.state.settings.training_base_url,
                             "Cache-Control": "no-store"})


class CorrectionBody(BaseModel):
    token_hash: str
    correction: str
    rationale: str


@router.post("/corrections", status_code=status.HTTP_201_CREATED)
def submit_correction(body: CorrectionBody, session: Session = Depends(_session)) -> dict[str, str]:
    token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == body.token_hash))
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
        payload={"correction": body.correction, "rationale": body.rationale[:2000]},
    )
    session.add(event)
    session.commit()
    return {"event_id": str(event.event_id)}
