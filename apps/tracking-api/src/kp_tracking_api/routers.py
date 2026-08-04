"""Tracking endpoints.

Stateless and token-based: no sessions, no cookies. The only identifier in
requests is a SHA-256 hash of the tracking token (`token_hash`); the raw token
is never stored or echoed. Events are recorded with a minimized client IP
prefix + truncated user agent (HIGH-17 / WS-9) and a confidence, then the
mailbox-reader/correction pipeline can downweight low-confidence events
(e.g. automated scanners).

Security posture (HIGH-04 / WS-9):
- clicks are deduplicated like opens, so URL-scanning bots cannot inflate them
- `X-Forwarded-For` is only honored when the direct peer is a configured
  reverse proxy, so a spoofed header cannot change attribution
- `/v1/corrections` is gated by a shared-secret bearer token and IP rate limit
- every endpoint is rate-limited (per token for track, per IP for corrections)
"""

from __future__ import annotations

import ipaddress
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from kp_database.models import TrackingEvent, TrackingToken
from kp_database.privacy import CLIENT_IP_MAX, minimize_ip, minimize_user_agent
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
    if not request.app.state.token_limiter.allow(token_hash):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _ip_rate_limited(request: Request) -> None:
    if not request.app.state.ip_limiter.allow(_client_ip(request) or "unknown"):
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


@router.get("/track/open/{token_hash}", dependencies=[Depends(_token_rate_limited)])
def record_open(
    token_hash: str,
    request: Request,
    session: Session = Depends(_session),
) -> Response:
    token = _resolve_active_token(token_hash, session)
    if token is None:
        return Response(status_code=404)

    existing = session.scalar(
        select(TrackingEvent).where(
            TrackingEvent.token_id == token.token_id,
            TrackingEvent.event_type == dm.EventType.OPENED,
        )
    )
    if existing is None:
        session.add(
            TrackingEvent(
                event_id=uuid.uuid4(),
                event_type=dm.EventType.OPENED,
                token_id=token.token_id,
                campaign_id=token.campaign_id,
                confidence=dm.Confidence.MEDIUM,
                occurred_at=datetime.now(UTC),
                client_ip=minimize_ip(_client_ip(request)),
                user_agent=minimize_user_agent(request.headers.get("user-agent")),
                payload={},
            )
        )
        session.commit()
    return Response(content=GIF_BYTES, media_type="image/gif", headers={"Cache-Control": "no-store"})


@router.get("/track/click/{token_hash}", dependencies=[Depends(_token_rate_limited)])
def record_click(
    token_hash: str,
    request: Request,
    session: Session = Depends(_session),
) -> Response:
    token = _resolve_active_token(token_hash, session)
    if token is None:
        return Response(status_code=404)

    existing = session.scalar(
        select(TrackingEvent).where(
            TrackingEvent.token_id == token.token_id,
            TrackingEvent.event_type == dm.EventType.CLICKED,
        )
    )
    if existing is None:
        session.add(
            TrackingEvent(
                event_id=uuid.uuid4(),
                event_type=dm.EventType.CLICKED,
                token_id=token.token_id,
                campaign_id=token.campaign_id,
                confidence=dm.Confidence.MEDIUM,
                occurred_at=datetime.now(UTC),
                client_ip=minimize_ip(_client_ip(request)),
                user_agent=minimize_user_agent(request.headers.get("user-agent")),
                payload={},
            )
        )
        session.commit()
    return Response(
        status_code=302, headers={"Location": request.app.state.settings.training_base_url, "Cache-Control": "no-store"}
    )


class CorrectionBody(BaseModel):
    token_hash: str
    correction: str
    rationale: str


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
