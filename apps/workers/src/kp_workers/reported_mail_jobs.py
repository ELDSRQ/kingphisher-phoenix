"""Durable reported-mail polling and correlation validation."""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from kp_database.models import (
    DeliveryReportCorrelation,
    Microsoft365IntegrationState,
    RecipientAssignment,
    ReportedMailReceipt,
    TrackingEvent,
    TrackingToken,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_domain_models import models as dm
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_workers.observability import provider_call
from kp_workers.providers.mailpit import MailpitReportedMessageProvider
from kp_workers.providers.microsoft365 import Microsoft365ReportedMailboxProvider, ReportedMailboxMessage


class ReportedMailContext(Protocol):
    settings: Any
    session_factory: Any
    audit_store: Any
    queue: Any


MAILBOX_LEASE_TTL = timedelta(minutes=5)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scope(ctx: ReportedMailContext) -> tuple[str, str, str]:
    provider = ctx.settings.reported_mailbox_provider
    scope_hash = _digest(
        json.dumps(
            {
                "purpose": "kp-reported-mail-scope-v1",
                "provider": provider,
                "tenant": ctx.settings.microsoft_tenant_id or "local",
                "mailbox": ctx.settings.reported_mailbox_id or "local-mailpit",
                "folder": ctx.settings.reported_mailbox_folder_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    fingerprint = _digest(
        json.dumps(
            {
                "purpose": "kp-reported-mail-config-v1",
                "provider": provider,
                "tenant": ctx.settings.microsoft_tenant_id or "local",
                "url": ctx.settings.effective_reported_mailbox_url.rstrip("/"),
                "scope": scope_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return provider, scope_hash, fingerprint


def _state(
    session: Session,
    *,
    provider: str,
    scope_hash: str,
    fingerprint: str,
) -> Microsoft365IntegrationState:
    state = session.scalar(
        select(Microsoft365IntegrationState)
        .where(
            Microsoft365IntegrationState.kind == "mailbox",
            Microsoft365IntegrationState.scope_hash == scope_hash,
        )
        .with_for_update()
    )
    if state is None:
        state = Microsoft365IntegrationState(
            integration_state_id=uuid.uuid4(),
            kind="mailbox",
            provider=provider,
            scope_hash=scope_hash,
            config_fingerprint=fingerprint,
            status="never",
            generation=0,
            last_counts={},
        )
        session.add(state)
        session.flush()
    elif state.config_fingerprint != fingerprint:
        state.config_fingerprint = fingerprint
        state.cursor = None
        state.cursor_kind = None
        state.active_job_key = None
        state.lease_expires_at = None
        state.last_job_key = None
        state.status = "configuration_changed"
    return state


def _m365_provider(ctx: ReportedMailContext) -> Microsoft365ReportedMailboxProvider:
    mailbox_id = ctx.settings.reported_mailbox_id
    if not mailbox_id:
        raise RuntimeError("Microsoft 365 reported mailbox ID is required")
    return Microsoft365ReportedMailboxProvider(
        ctx.settings.effective_reported_mailbox_url,
        mailbox_id=mailbox_id,
        folder_id=ctx.settings.reported_mailbox_folder_id,
        bearer_token=ctx.settings.reported_mailbox_bearer_token,
        managed_identity_client_id=ctx.settings.reported_mailbox_client_id,
        timeout=ctx.settings.provider_timeout_seconds,
        page_size=ctx.settings.mailbox_poll_limit,
        max_messages=max(ctx.settings.mailbox_poll_limit, 1),
    )


def ensure_reported_mail_state(ctx: ReportedMailContext) -> None:
    """Publish non-secret readiness before the operator can queue actions."""
    provider, scope_hash, fingerprint = _scope(ctx)
    with ctx.session_factory() as session:
        _state(session, provider=provider, scope_hash=scope_hash, fingerprint=fingerprint)
        session.commit()


def _receipt_exists(session: Session, provider: str, scope_hash: str, external_hash: str) -> bool:
    return (
        session.scalar(
            select(ReportedMailReceipt.reported_mail_receipt_id).where(
                ReportedMailReceipt.provider == provider,
                ReportedMailReceipt.scope_hash == scope_hash,
                ReportedMailReceipt.external_id_hash == external_hash,
            )
        )
        is not None
    )


def _m365_candidate(message: ReportedMailboxMessage) -> tuple[str | None, str, dict[str, Any]]:
    mime = message.mime
    evidence = {
        "disposition": mime.disposition,
        "parts_seen": mime.parts_seen,
        "attachments_seen": mime.attachments_seen,
        "invalid_candidates": mime.invalid_candidate_count,
        "sources": sorted({item.source for item in mime.evidence}),
    }
    if mime.disposition != "single" or mime.candidate is None:
        return None, "ambiguous" if mime.disposition == "ambiguous" else "unknown", evidence
    if not any(item.source == "attached_original" for item in mime.evidence):
        return None, "untrusted_source", evidence
    return mime.candidate, "candidate", evidence


def _record_validated_candidate(
    session: Session,
    *,
    candidate: str,
    provider: str,
) -> tuple[RecipientAssignment | None, TrackingToken | None]:
    if provider == "mailpit":
        token = session.scalar(select(TrackingToken).where(TrackingToken.token_hash == candidate.lower()))
        if token is None or not secrets.compare_digest(token.token_hash.lower(), candidate.lower()):
            return None, None
        assignment = session.get(
            RecipientAssignment,
            token.recipient_assignment_id,
            with_for_update=True,
            populate_existing=True,
        )
        return assignment, token
    verifier_hash = _digest(candidate)
    correlation = session.scalar(
        select(DeliveryReportCorrelation).where(DeliveryReportCorrelation.verifier_hash == verifier_hash)
    )
    if correlation is None or not secrets.compare_digest(correlation.report_verifier, candidate):
        return None, None
    assignment = session.get(
        RecipientAssignment,
        correlation.recipient_assignment_id,
        with_for_update=True,
        populate_existing=True,
    )
    if assignment is None or assignment.delivery_attempt_id != correlation.delivery_attempt_id:
        return None, None
    token = session.scalar(
        select(TrackingToken).where(TrackingToken.recipient_assignment_id == assignment.recipient_assignment_id)
    )
    return assignment, token


def _consume(
    session: Session,
    *,
    provider: str,
    scope_hash: str,
    external_id: str,
    received_at: datetime,
    candidate: str | None,
    disposition: str,
    evidence: dict[str, Any],
) -> str:
    external_hash = _digest(f"{provider}\0{scope_hash}\0{external_id}")
    if _receipt_exists(session, provider, scope_hash, external_hash):
        return "replay"
    assignment: RecipientAssignment | None = None
    token: TrackingToken | None = None
    if candidate is not None:
        assignment, token = _record_validated_candidate(session, candidate=candidate, provider=provider)
        if assignment is None:
            disposition = "unknown"
    event_id: uuid.UUID | None = None
    if assignment is not None:
        existing = session.scalar(
            select(TrackingEvent).where(
                TrackingEvent.recipient_assignment_id == assignment.recipient_assignment_id,
                TrackingEvent.event_type == dm.EventType.MESSAGE_REPORTED,
            )
        )
        if existing is None:
            event_id = uuid.uuid4()
            session.add(
                TrackingEvent(
                    event_id=event_id,
                    event_type=dm.EventType.MESSAGE_REPORTED,
                    token_id=token.token_id if token is not None else None,
                    recipient_assignment_id=assignment.recipient_assignment_id,
                    recipient_id=assignment.recipient_id,
                    campaign_id=assignment.campaign_id,
                    confidence=dm.Confidence.HIGH,
                    occurred_at=received_at,
                    payload={"provider": provider, "receipt_hash": external_hash},
                )
            )
            # The receipt carries an FK to this event but the models do not
            # expose an ORM relationship; flush explicitly to guarantee FK
            # ordering in the same transaction.
            session.flush()
            disposition = "reported"
        else:
            event_id = existing.event_id
            disposition = "duplicate_assignment"
    session.add(
        ReportedMailReceipt(
            reported_mail_receipt_id=uuid.uuid4(),
            provider=provider,
            scope_hash=scope_hash,
            external_id=external_id,
            external_id_hash=external_hash,
            recipient_assignment_id=assignment.recipient_assignment_id if assignment is not None else None,
            event_id=event_id,
            disposition=disposition,
            evidence=evidence,
            received_at=received_at,
        )
    )
    return disposition


def _mailbox_job_key(message: dict[str, Any]) -> str:
    value = message.get("idempotency_key") or message.get("id")
    if not isinstance(value, str) or not value or len(value) > 255:
        raise RuntimeError("mailbox job requires a bounded idempotency key")
    return value


def process_mailbox(ctx: ReportedMailContext, message: dict[str, Any]) -> None:
    provider_name, scope_hash, fingerprint = _scope(ctx)
    job_key = _mailbox_job_key(message)
    with ctx.session_factory() as session:
        state = _state(session, provider=provider_name, scope_hash=scope_hash, fingerprint=fingerprint)
        now = datetime.now(UTC)
        if state.last_job_key == job_key:
            return
        lease_active = (
            state.active_job_key is not None and state.lease_expires_at is not None and state.lease_expires_at > now
        )
        if lease_active:
            raise RuntimeError("reported mailbox poll is already leased")
        state.active_job_key = job_key
        state.lease_expires_at = now + MAILBOX_LEASE_TTL
        state.last_attempt_at = now
        state.updated_at = now
        starting_cursor = state.cursor
        starting_generation = state.generation
        session.commit()

    next_cursor_kind: str | None
    if provider_name == "microsoft365":
        with provider_call("graph", "poll"):
            result = _m365_provider(ctx).poll(starting_cursor)
        if result.status == "error":
            with ctx.session_factory() as session:
                state = _state(session, provider=provider_name, scope_hash=scope_hash, fingerprint=fingerprint)
                if (
                    state.active_job_key != job_key
                    or state.generation != starting_generation
                    or state.cursor != starting_cursor
                ):
                    return
                state.status = "error"
                state.last_error = (result.error_code or "provider_error")[:128]
                state.last_counts = {"recorded": 0, "rejected": result.rejected_count}
                state.active_job_key = None
                state.lease_expires_at = None
                state.last_job_key = job_key
                state.updated_at = datetime.now(UTC)
                ctx.audit_store.record(
                    session=session,
                    actor="worker:mailbox",
                    action="mailbox.poll.failed",
                    object_type="system",
                    object_id=scope_hash[:16],
                    detail={"provider": provider_name, "error_code": state.last_error},
                )
                session.commit()
            return
        incoming = [(item.external_id, item.received_at, *_m365_candidate(item)) for item in result.messages]
        next_cursor = result.cursor
        next_cursor_kind = result.cursor_kind
        status = result.status
        provider_counts = {
            "provider_rejected": result.rejected_count,
            "provider_duplicates": result.duplicate_count,
            "provider_removed": result.removed_count,
            "pages": result.pages,
        }
    elif provider_name == "mailpit":
        provider = MailpitReportedMessageProvider(
            ctx.settings.effective_reported_mailbox_url,
            timeout=ctx.settings.provider_timeout_seconds,
            limit=ctx.settings.mailbox_poll_limit,
            bearer_token=ctx.settings.reported_mailbox_bearer_token,
            basic_username=ctx.settings.reported_mailbox_basic_username,
            basic_password=ctx.settings.reported_mailbox_basic_password,
            cursor=starting_cursor,
        )
        with provider_call("mailpit", "poll"):
            reports = provider.poll()
        incoming = [
            (item.external_id, item.reported_at, item.token_hash, "candidate", {"source": "mailpit_header"})
            for item in reports
        ]
        next_cursor = provider.cursor
        next_cursor_kind = "watermark" if provider.cursor else None
        status = "complete"
        provider_counts = {}
    else:
        raise RuntimeError("unsupported reported mailbox provider")

    counts: dict[str, int] = {"polled": len(incoming), **provider_counts}
    with ctx.session_factory() as session:
        state = _state(session, provider=provider_name, scope_hash=scope_hash, fingerprint=fingerprint)
        if (
            state.active_job_key != job_key
            or state.generation != starting_generation
            or state.cursor != starting_cursor
        ):
            # Another lease holder advanced or reconfigured this scope while
            # the provider request was in flight. Discard this stale result;
            # it must write neither receipts nor cursor.
            if state.active_job_key == job_key:
                state.active_job_key = None
                state.lease_expires_at = None
                session.commit()
            return
        for external_id, received_at, candidate, disposition, evidence in incoming:
            outcome = _consume(
                session,
                provider=provider_name,
                scope_hash=scope_hash,
                external_id=external_id,
                received_at=received_at,
                candidate=candidate,
                disposition=disposition,
                evidence=evidence,
            )
            counts[outcome] = counts.get(outcome, 0) + 1
        # Cursor, receipts, events, the completed job key and audit intent
        # share this commit. Commit-before-ack replay exits before polling.
        state.cursor = next_cursor
        state.cursor_kind = next_cursor_kind
        state.status = "healthy" if status == "complete" else "truncated"
        state.last_error = None if status == "complete" else "bounded_segment"
        state.last_success_at = datetime.now(UTC)
        state.updated_at = state.last_success_at
        state.generation += 1
        state.last_counts = counts
        state.active_job_key = None
        state.lease_expires_at = None
        state.last_job_key = job_key
        ctx.audit_store.record(
            session=session,
            actor="worker:mailbox",
            action="mailbox.poll",
            object_type="system",
            object_id=scope_hash[:16],
            detail={"provider": provider_name, **counts},
        )
        session.commit()


def maybe_publish_mailbox(ctx: ReportedMailContext, now: datetime) -> None:
    """Publish at most one bounded mailbox poll per UTC minute."""

    bucket = int(now.timestamp()) // 60
    key = f"mailbox-self-{bucket}"
    with ctx.session_factory() as session:
        enqueue_queue(
            session,
            topic="mailbox",
            payload={"scheduled_at": now.isoformat()},
            idempotency_key=key,
        )
        dispatch_after_commit(session, lambda: ctx.audit_store.dispatch_pending_queue(ctx.queue))
        session.commit()
