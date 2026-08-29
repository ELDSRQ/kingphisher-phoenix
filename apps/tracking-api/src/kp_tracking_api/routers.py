"""Tracking endpoints.

Stateless and token-based: no sessions, no cookies. Requests carry an opaque
bearer; the database stores only a keyed HMAC verifier and cannot replay that
credential. Events are recorded with a minimized client IP prefix + truncated
user agent (HIGH-17 / WS-9) and a confidence. The tracking service never
changes or downweights recorded analytics evidence.

Security posture (HIGH-04 / WS-9):
- clicks are deduplicated like opens, so URL-scanning bots cannot inflate them
- open/click dedup is storage-enforced via the partial unique index
  `uq_events_open_click_dedup` (metric-integrity): INSERT ... ON CONFLICT
  DO NOTHING closes the SELECT-then-INSERT race for concurrent
  double-clicks/prefetches; the first event wins and duplicates are no-ops
- `X-Forwarded-For` is only honored when the direct peer is a configured
  reverse proxy, so a spoofed header cannot change attribution
- the legacy `/v1/corrections` path is a stable no-write HTTP 410; future
  corrections require a normalized, operator-reviewed workflow
- active tracking endpoints are rate-limited per token
"""

from __future__ import annotations

import hmac
import html
import ipaddress
import re
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from kp_database.campaign_service import (
    require_bound_training_resource,
    tracking_token_verifier,
    training_resource_content_digest,
)
from kp_database.models import (
    Campaign,
    RecipientAssignment,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
    TrainingResource,
)
from kp_database.privacy import CLIENT_IP_MAX, minimize_ip, minimize_user_agent
from kp_database.training import (
    TrainingBearerPurpose,
    training_bearer_verifier,
    verify_training_bearer,
)
from kp_database.training import (
    training_bearer as make_training_bearer,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

router = APIRouter(prefix="/v1")

GIF_BYTES = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"  # noqa: E501
TOKEN_BEARER_RE = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")
TRAINING_DUE_AFTER = timedelta(hours=72)
TRAINING_ACCESS_FOR = timedelta(days=90)
_TRAINING_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
}
_QUIZ_ANSWER = "verify_independently"
_QUIZ_OPTIONS = frozenset({"act_immediately", _QUIZ_ANSWER, "reply_with_credentials"})
_MAX_QUIZ_BODY_BYTES = 1024


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
<p>No credentials are collected on this page. If you arrived after selecting a simulated message link,
that interaction may have been recorded for the campaign report.</p>
<h2>Warning signs to remember</h2><ul>
<li>Unexpected urgency or pressure</li>
<li>An unfamiliar sender or destination</li>
<li>Requests to open a link before independently verifying the message</li>
</ul>
<p>When in doubt, report the message to your IT or security contact.</p></main></body></html>""",
        headers=_TRAINING_HEADERS,
    )


def _session(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    with factory() as session:
        yield session


def _canonical_ip(value: str) -> str | None:
    try:
        # A scope identifier is meaningful only on the direct local link and
        # must not become attacker-controlled rate-limit key material.
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def _peer_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _client_ip(request: Request) -> str | None:
    """Client IP for attribution/rate-limit keys.

    `X-Forwarded-For` is only trusted when the direct peer is in a configured
    ingress network. The chain is walked from the direct-proxy side so a
    client-supplied leftmost entry cannot replace the actual upstream client.
    """
    peer = _peer_ip(request)
    if peer is None:
        return None
    if request.app.state.settings.is_trusted_proxy(peer):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded and len(forwarded) <= 1024:
            parts = [part.strip() for part in forwarded.split(",")]
            if 1 <= len(parts) <= 16 and all(parts):
                chain = [_canonical_ip(part) for part in parts]
                if all(address is not None for address in chain):
                    canonical_chain = [address for address in chain if address is not None]
                    for address in reversed(canonical_chain):
                        if not request.app.state.settings.is_trusted_proxy(address):
                            return address[:CLIENT_IP_MAX]
                    return canonical_chain[0][:CLIENT_IP_MAX]
    return peer[:CLIENT_IP_MAX]


def _token_rate_limited(request: Request, token_hash: str) -> None:
    """Per-token limit on unauthenticated track endpoints.

    `token_hash` is a path parameter, so FastAPI injects it into this
    dependency; the key lives in memory only and is never logged.
    """
    # Reject attacker-controlled high-cardinality strings before allocating a
    # limiter bucket or querying storage. Issued bearers are URL-safe opaque
    # strings with at least 240 bits of entropy.
    if TOKEN_BEARER_RE.fullmatch(token_hash) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    # Base64url bearers are case-sensitive; normalizing case would let one
    # distinct token exhaust another token's bucket.
    if not request.app.state.token_limiter.allow(token_hash):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _training_rate_limited(request: Request, training_bearer: str) -> None:
    if TOKEN_BEARER_RE.fullmatch(training_bearer) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if not request.app.state.token_limiter.allow(f"training:{training_bearer}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _ip_rate_limited(request: Request) -> None:
    if not request.app.state.ip_limiter.allow(_client_ip(request) or "unknown"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _global_rate_limited(request: Request) -> None:
    if not request.app.state.global_limiter.allow("tracking"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")


def _resolve_active_token(raw_bearer: str, session: Session, verifier_key: bytes) -> TrackingToken | None:
    verifier = tracking_token_verifier(raw_bearer, verifier_key)
    token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == verifier))
    if token is None or token.status != dm.TokenStatus.ACTIVE:
        return None
    if token.expires_at and token.expires_at < datetime.now(UTC):
        return None
    return token


def _tracking_verifier_key(request: Request) -> bytes:
    try:
        return cast(bytes, request.app.state.settings.require_tracking_token_hmac_key())
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="tracking token verification unavailable"
        ) from exc


def _training_verifier_key(request: Request) -> bytes:
    try:
        return cast(bytes, request.app.state.settings.require_training_token_hmac_key())
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="training token verification unavailable",
        ) from exc


def _campaign_training_resource(session: Session, campaign_id: uuid.UUID) -> TrainingResource:
    """Return only the exact lesson selected and reviewed with the campaign."""

    campaign = session.get(Campaign, campaign_id, with_for_update=True)
    if campaign is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        return require_bound_training_resource(session, campaign)
    except ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=exc.message,
        ) from exc


def _assigned_training_resource(session: Session, training: TrainingAssignment) -> TrainingResource:
    """Revalidate the immutable lesson evidence before rendering or completion.

    Superseding a lesson must not strand an assignment that was already
    launched. Its exact ID, version, and content digest must nevertheless
    continue to match the reviewed campaign binding.
    """

    campaign = session.get(Campaign, training.campaign_id)
    resource = session.get(TrainingResource, training.resource_id)
    if (
        campaign is None
        or resource is None
        or campaign.training_resource_id != training.resource_id
        or campaign.training_resource_version != resource.version
        or campaign.training_resource_digest is None
        or not hmac.compare_digest(
            campaign.training_resource_digest,
            training_resource_content_digest(resource),
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="training resource unavailable",
        )
    return resource


def _token_matches_assignment(token: TrackingToken, recipient_assignment: RecipientAssignment) -> bool:
    """Fail closed if redundant token/assignment bindings ever drift."""

    return bool(
        token.recipient_assignment_id == recipient_assignment.recipient_assignment_id
        and token.campaign_id == recipient_assignment.campaign_id
        and recipient_assignment.token_id == token.token_id
    )


def _lock_tracking_assignment(session: Session, token: TrackingToken) -> RecipientAssignment | None:
    """Acquire the assignment lock shared with project-before-purge retention."""

    recipient_assignment = session.get(
        RecipientAssignment,
        token.recipient_assignment_id,
        with_for_update=True,
        populate_existing=True,
    )
    if recipient_assignment is None or not _token_matches_assignment(token, recipient_assignment):
        return None
    return recipient_assignment


def _ensure_training_assignment(
    session: Session,
    token: TrackingToken,
    key: bytes,
    *,
    now: datetime,
    recipient_assignment: RecipientAssignment | None = None,
) -> tuple[TrainingAssignment, str]:
    recipient_assignment = recipient_assignment or _lock_tracking_assignment(session, token)
    if recipient_assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    training = session.scalar(
        select(TrainingAssignment).where(
            TrainingAssignment.recipient_assignment_id == recipient_assignment.recipient_assignment_id
        )
    )
    if training is None:
        training = TrainingAssignment(
            training_assignment_id=uuid.uuid4(),
            recipient_assignment_id=recipient_assignment.recipient_assignment_id,
            recipient_id=recipient_assignment.recipient_id,
            resource_id=_campaign_training_resource(session, token.campaign_id).training_resource_id,
            campaign_id=token.campaign_id,
            assigned_at=now,
            opened_at=None,
            due_at=now + TRAINING_DUE_AFTER,
            access_expires_at=now + TRAINING_ACCESS_FOR,
            completed_at=None,
            status=dm.TrainingAssignmentStatus.ASSIGNED,
        )
        session.add(training)
    raw_bearer = make_training_bearer(
        training.training_assignment_id,
        training.access_expires_at,
        key,
        purpose=TrainingBearerPurpose.OPEN,
    )
    completion_bearer = make_training_bearer(
        training.training_assignment_id,
        training.access_expires_at,
        key,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    verifier = training_bearer_verifier(raw_bearer, key, purpose=TrainingBearerPurpose.OPEN)
    completion_verifier = training_bearer_verifier(
        completion_bearer,
        key,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    if training.training_token_hash is None and training.training_completion_token_hash is None:
        training.training_token_hash = verifier
        training.training_completion_token_hash = completion_verifier
    elif (
        training.training_token_hash is None
        or training.training_completion_token_hash is None
        or not secrets.compare_digest(training.training_token_hash, verifier)
        or not secrets.compare_digest(training.training_completion_token_hash, completion_verifier)
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="training assignment verifier mismatch")
    return training, raw_bearer


def _resolve_training_assignment(
    raw_bearer: str,
    session: Session,
    key: bytes,
    *,
    purpose: TrainingBearerPurpose,
    for_update: bool = False,
) -> tuple[TrainingAssignment, RecipientAssignment, TrackingToken] | None:
    verifier = training_bearer_verifier(raw_bearer, key, purpose=purpose)
    verifier_column = (
        TrainingAssignment.training_token_hash
        if purpose is TrainingBearerPurpose.OPEN
        else TrainingAssignment.training_completion_token_hash
    )
    statement = (
        select(TrainingAssignment)
        .join(
            RecipientAssignment,
            RecipientAssignment.recipient_assignment_id == TrainingAssignment.recipient_assignment_id,
        )
        .where(verifier_column == verifier)
    )
    if for_update:
        # Lock the assignment, not the child row, so retention, click, page
        # open, and quiz completion all serialize on one stable boundary.
        statement = statement.with_for_update(of=RecipientAssignment)
    training = session.scalar(statement)
    if (
        training is None
        or training.recipient_assignment_id is None
        or not verify_training_bearer(
            raw_bearer,
            assignment_id=training.training_assignment_id,
            expires_at=training.access_expires_at,
            key=key,
            purpose=purpose,
        )
    ):
        return None
    recipient_assignment = session.get(RecipientAssignment, training.recipient_assignment_id)
    if recipient_assignment is None or recipient_assignment.token_id is None:
        return None
    token = session.get(TrackingToken, recipient_assignment.token_id)
    if (
        token is None
        or token.status != dm.TokenStatus.ACTIVE
        or not _token_matches_assignment(token, recipient_assignment)
    ):
        return None
    return training, recipient_assignment, token


def _training_page(
    resource: TrainingResource,
    completion_bearer: str,
    *,
    retry: bool = False,
) -> HTMLResponse:
    title = html.escape(resource.title)
    content = html.escape(resource.content).replace("\n", "<br>")
    action = f"/v1/training/{completion_bearer}/complete"
    feedback = (
        '<p role="alert"><strong>Not quite.</strong> Review the warning signs and try again.</p>' if retry else ""
    )
    # A lesson with a knowledge check renders its own bounded question and
    # options (never the correct-answer index — the tracking service compares
    # the submitted option server-side). A lesson without one keeps the
    # generic quiz, so existing bindings are unaffected by the new feature.
    if resource.knowledge_question is not None and resource.knowledge_options:
        quiz_question = html.escape(resource.knowledge_question)
        quiz_radios = "\n".join(
            f'<label><input required type="radio" name="answer" value="{html.escape(str(option), quote=True)}">'
            f"{html.escape(str(option))}</label>"
            for option in resource.knowledge_options
        )
    else:
        quiz_question = "What is the safest response to an unexpected urgent message?"
        quiz_radios = (
            '<label><input required type="radio" name="answer" value="act_immediately">'
            "Act immediately so the request does not expire</label>\n"
            '<label><input required type="radio" name="answer" value="verify_independently">'
            "Verify the request through a trusted, independent channel</label>\n"
            '<label><input required type="radio" name="answer" value="reply_with_credentials">'
            "Reply with credentials to prove your identity</label>"
        )
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{font:18px/1.5 system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1.5rem;color:#172033}}
main{{border:1px solid #ccd4e0;border-radius:12px;padding:2rem}}h1{{line-height:1.2;color:#174a7e}}
fieldset{{margin:1.5rem 0;padding:1rem}}label{{display:block;margin:.7rem 0}}
button{{font:inherit;padding:.7rem 1rem;background:#174a7e;color:white;border:0;border-radius:6px}}
</style></head><body><main><p><strong>Security awareness training</strong></p><h1>{title}</h1>
<p>{content}</p><ul><li>Pause before acting on urgency.</li><li>Inspect the sender and destination.</li>
<li>Report suspicious messages through your approved channel.</li></ul>
{feedback}<form method="post" action="{action}"><fieldset><legend><strong>Knowledge check</strong></legend>
<p>{quiz_question}</p>
{quiz_radios}
</fieldset><button type="submit">Submit answer</button></form>
</main></body></html>""",
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT if retry else status.HTTP_200_OK,
        headers=_TRAINING_HEADERS,
    )


def _completion_page() -> HTMLResponse:
    return HTMLResponse(
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Training complete</title></head>
<body><main><h1>Training complete</h1>
<p>Your completion has been recorded. You may close this window.</p></main></body></html>""",
        headers=_TRAINING_HEADERS,
    )


async def _submitted_quiz_answer(request: Request) -> str | None:
    """Parse one bounded form answer without adding a multipart dependency."""

    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        return None
    body = await request.body()
    if not body or len(body) > _MAX_QUIZ_BODY_BYTES:
        return None
    try:
        fields = parse_qsl(
            body.decode("ascii"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
        )
    except (UnicodeDecodeError, ValueError):
        return None
    if len(fields) != 1 or fields[0][0] != "answer":
        return None
    return fields[0][1]


def _record_first_event(
    request: Request,
    session: Session,
    token: TrackingToken,
    recipient_assignment: RecipientAssignment,
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
            recipient_assignment_id=recipient_assignment.recipient_assignment_id,
            recipient_id=recipient_assignment.recipient_id,
            campaign_id=token.campaign_id,
            confidence=dm.Confidence.MEDIUM,
            occurred_at=datetime.now(UTC),
            client_ip=minimize_ip(_client_ip(request)),
            user_agent=minimize_user_agent(request.headers.get("user-agent")),
            payload={},
        )
        .on_conflict_do_nothing()
    )


@router.get(
    "/track/open/{token_hash}",
    dependencies=[Depends(_token_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
def record_open(
    token_hash: str,
    request: Request,
    session: Session = Depends(_session),
) -> Response:
    token = _resolve_active_token(token_hash, session, _tracking_verifier_key(request))
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    recipient_assignment = _lock_tracking_assignment(session, token)
    if recipient_assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    _record_first_event(request, session, token, recipient_assignment, dm.EventType.OPENED)
    session.commit()
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
    token = _resolve_active_token(token_hash, session, _tracking_verifier_key(request))
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    recipient_assignment = _lock_tracking_assignment(session, token)
    if recipient_assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    _record_first_event(request, session, token, recipient_assignment, dm.EventType.CLICKED)
    _, raw_training_bearer = _ensure_training_assignment(
        session,
        token,
        _training_verifier_key(request),
        now=datetime.now(UTC),
        recipient_assignment=recipient_assignment,
    )
    # Click evidence and its training assignment become visible together while
    # the assignment row remains locked against project-before-purge retention.
    session.commit()
    return RedirectResponse(
        url=f"/v1/training/{raw_training_bearer}",
        status_code=status.HTTP_302_FOUND,
        headers={"Cache-Control": "no-store"},
    )


@router.get(
    "/training/{training_bearer}",
    response_class=HTMLResponse,
    dependencies=[Depends(_training_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
def open_training(
    training_bearer: str,
    request: Request,
    session: Session = Depends(_session),
) -> HTMLResponse:
    training_key = _training_verifier_key(request)
    resolved = _resolve_training_assignment(
        training_bearer,
        session,
        training_key,
        purpose=TrainingBearerPurpose.OPEN,
        for_update=True,
    )
    if resolved is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    training, recipient_assignment, token = resolved
    resource = _assigned_training_resource(session, training)
    if training.opened_at is None:
        training.opened_at = datetime.now(UTC)
        if training.status == dm.TrainingAssignmentStatus.ASSIGNED:
            training.status = dm.TrainingAssignmentStatus.STARTED
        session.execute(
            pg_insert(TrackingEvent)
            .values(
                event_id=uuid.uuid4(),
                event_type=dm.EventType.TRAINING_STARTED,
                token_id=token.token_id,
                recipient_assignment_id=recipient_assignment.recipient_assignment_id,
                recipient_id=recipient_assignment.recipient_id,
                campaign_id=token.campaign_id,
                confidence=dm.Confidence.HIGH,
                occurred_at=training.opened_at,
                payload={},
            )
            .on_conflict_do_nothing()
        )
        session.commit()
    completion_bearer = make_training_bearer(
        training.training_assignment_id,
        training.access_expires_at,
        training_key,
        purpose=TrainingBearerPurpose.COMPLETE,
    )
    return _training_page(resource, completion_bearer)


@router.post(
    "/training/{training_bearer}/complete",
    response_class=HTMLResponse,
    dependencies=[Depends(_training_rate_limited), Depends(_ip_rate_limited), Depends(_global_rate_limited)],
)
async def complete_training(
    training_bearer: str,
    request: Request,
    session: Session = Depends(_session),
) -> HTMLResponse:
    """Complete one assignment with a purpose-scoped expiring bearer.

    The endpoint stores no raw bearer, cookie, or recipient identifier.
    Replays and concurrent submissions are storage-idempotent.
    """
    resolved = _resolve_training_assignment(
        training_bearer,
        session,
        _training_verifier_key(request),
        purpose=TrainingBearerPurpose.COMPLETE,
        for_update=True,
    )
    if resolved is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    training, recipient_assignment, token = resolved
    # A successful submission is immutable. Replaying the same purpose-bound
    # completion request returns the same terminal page without changing its
    # timestamp or requiring a second answer.
    if training.completed_at is not None:
        return _completion_page()
    resource = _assigned_training_resource(session, training)
    answer = await _submitted_quiz_answer(request)
    if resource.knowledge_question is not None and resource.knowledge_options:
        valid_options: frozenset[str] | set[str] = set(resource.knowledge_options)
        correct_answer: str | None = (
            resource.knowledge_options[resource.knowledge_answer_index]
            if resource.knowledge_answer_index is not None
            and 0 <= resource.knowledge_answer_index < len(resource.knowledge_options)
            else None
        )
    else:
        valid_options = _QUIZ_OPTIONS
        correct_answer = _QUIZ_ANSWER
    if answer not in valid_options:
        return _training_page(resource, training_bearer, retry=True)
    assert answer is not None  # membership above implies a non-None string
    now = datetime.now(UTC)
    # A purpose-bound quiz answer is a deliberate training-page action. Keep
    # that high-confidence fact separate from scanner-triggerable CLICKED and
    # OPENED observations, including when the learner answers incorrectly.
    # The partial unique index makes retries and concurrent submissions no-ops.
    session.execute(
        pg_insert(TrackingEvent)
        .values(
            event_id=uuid.uuid4(),
            event_type=dm.EventType.HUMAN_INTERACTION_CONFIRMED,
            token_id=token.token_id,
            recipient_assignment_id=recipient_assignment.recipient_assignment_id,
            recipient_id=recipient_assignment.recipient_id,
            campaign_id=token.campaign_id,
            confidence=dm.Confidence.HIGH,
            occurred_at=now,
            payload={},
        )
        .on_conflict_do_nothing()
    )
    if correct_answer is None:
        session.commit()
        return _training_page(resource, training_bearer, retry=True)
    if not secrets.compare_digest(answer, correct_answer):
        session.commit()
        return _training_page(resource, training_bearer, retry=True)
    if training.opened_at is None:
        training.opened_at = now
    if training.completed_at is None:
        training.completed_at = now
        training.status = dm.TrainingAssignmentStatus.COMPLETED
    session.execute(
        pg_insert(TrackingEvent)
        .values(
            event_id=uuid.uuid4(),
            event_type=dm.EventType.TRAINING_COMPLETED,
            token_id=token.token_id,
            recipient_assignment_id=recipient_assignment.recipient_assignment_id,
            recipient_id=recipient_assignment.recipient_id,
            campaign_id=token.campaign_id,
            confidence=dm.Confidence.HIGH,
            occurred_at=training.completed_at,
            payload={},
        )
        .on_conflict_do_nothing()
    )
    session.commit()
    return _completion_page()


LEGACY_CORRECTIONS_RETIRED = {
    "code": "legacy_corrections_retired",
    "detail": "legacy correction ingestion is retired; no correction was recorded",
}


@router.post("/corrections", status_code=status.HTTP_410_GONE, response_model=None)
def legacy_corrections_retired() -> JSONResponse:
    """Reject the former shared-secret mutation before auth or database use."""

    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content=LEGACY_CORRECTIONS_RETIRED,
        headers={"Cache-Control": "no-store"},
    )
