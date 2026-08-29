"""Durable preview/apply orchestration for bounded Microsoft 365 directory sync."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from kp_database.campaign_service import invalidate_campaign_audience
from kp_database.models import (
    AudienceGroup,
    AudienceGroupMember,
    Campaign,
    CampaignAudience,
    Microsoft365IntegrationState,
    Recipient,
)
from kp_database.privacy import hash_mailbox
from kp_domain_models import models as dm
from kp_domain_models.policy import is_recipient_allowed
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kp_workers.observability import provider_call
from kp_workers.providers.graph import (
    DirectorySyncResult,
    DirectoryUser,
    GraphDirectoryProvider,
    GraphRequestError,
    GraphRetryLimitError,
)

MAX_SYNC_USERS = 10_000
PREVIEW_TTL = timedelta(minutes=15)


class _DirectoryDataConflictError(RuntimeError):
    """A provider response contradicted another row in the same snapshot."""


def _directory_error_code(exc: Exception) -> str:
    """Return a fixed diagnostic suitable for durable state and audit data."""
    if isinstance(exc, _DirectoryDataConflictError):
        return "provider_data_conflict"
    if isinstance(exc, GraphRetryLimitError):
        return "provider_retry_exhausted"
    if isinstance(exc, GraphRequestError):
        return "provider_request_failed"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "provider_response_invalid"
    if isinstance(exc, TimeoutError):
        return "provider_timeout"
    if isinstance(exc, (ConnectionError, OSError)):
        return "provider_connection_failed"
    return "provider_fetch_failed"


def _queue_uuid(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"directory job {field} must be a UUID")
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise RuntimeError(f"directory job {field} must be a UUID") from None


class DirectoryJobContext(Protocol):
    settings: Any
    session_factory: Any
    audit_store: Any


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scope(ctx: DirectoryJobContext) -> tuple[str, str, str, tuple[str, ...]]:
    groups = ctx.settings.graph_group_id_set()
    tenant = ctx.settings.microsoft_tenant_id or "local"
    scope_hash = _digest(
        json.dumps(
            {
                "purpose": "kp-m365-directory-scope-v1",
                "provider": "microsoft365",
                "tenant": tenant,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    fingerprint = _digest(
        json.dumps(
            {
                "purpose": "kp-m365-directory-config-v1",
                "provider": "microsoft365",
                "tenant": tenant,
                "base_url": ctx.settings.effective_graph_base_url.rstrip("/"),
                "groups": groups,
                "allowed_domains": sorted(ctx.settings.recipient_domain_allowlist()),
                "policy": "enabled-member-mail-v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    # Directory ownership follows the tenant/provider identity, not the
    # selected-group configuration. Otherwise changing selected groups would
    # strand old recipients under a different source and make their existing
    # mailboxes collide with the next reviewed sync.
    source_hash = _digest(
        json.dumps(
            {"purpose": "kp-m365-directory-source-v1", "provider": "microsoft365", "tenant": tenant},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return scope_hash, fingerprint, f"m365:{source_hash[:16]}", groups


def _state(
    session: Session,
    *,
    scope_hash: str,
    fingerprint: str,
    lock: bool = True,
    reconcile_config: bool = True,
) -> Microsoft365IntegrationState:
    statement = select(Microsoft365IntegrationState).where(
        Microsoft365IntegrationState.kind == "directory",
        Microsoft365IntegrationState.scope_hash == scope_hash,
    )
    if lock:
        statement = statement.with_for_update()
    state = session.scalar(statement)
    if state is None:
        state = Microsoft365IntegrationState(
            integration_state_id=uuid.uuid4(),
            kind="directory",
            provider="microsoft365",
            scope_hash=scope_hash,
            config_fingerprint=fingerprint,
            status="never",
            generation=0,
            last_counts={},
        )
        session.add(state)
        session.flush()
    elif reconcile_config and state.config_fingerprint != fingerprint:
        state.config_fingerprint = fingerprint
        state.cursor = None
        state.cursor_kind = None
        state.pending_preview_id = None
        state.pending_preview_hash = None
        state.pending_payload = None
        state.pending_created_at = None
        state.pending_expires_at = None
        state.status = "configuration_changed"
    return state


def _clear_preview(state: Microsoft365IntegrationState) -> None:
    state.pending_preview_id = None
    state.pending_preview_hash = None
    state.pending_payload = None
    state.pending_created_at = None
    state.pending_expires_at = None


def _provider(ctx: DirectoryJobContext, groups: tuple[str, ...]) -> GraphDirectoryProvider:
    return GraphDirectoryProvider(
        ctx.settings.effective_graph_base_url,
        bearer_token=ctx.settings.graph_bearer_token,
        api_key=ctx.settings.graph_api_key,
        managed_identity_client_id=ctx.settings.graph_client_id,
        timeout=ctx.settings.provider_timeout_seconds,
        max_users=ctx.settings.graph_max_users,
        max_pages=ctx.settings.graph_max_pages,
        group_ids=groups,
    )


def ensure_directory_state(ctx: DirectoryJobContext) -> None:
    """Publish non-secret readiness before the operator can queue actions."""
    scope_hash, fingerprint, _, _ = _scope(ctx)
    with ctx.session_factory() as session:
        _state(session, scope_hash=scope_hash, fingerprint=fingerprint)
        session.commit()


def _accepted_user(user: DirectoryUser, allowed_domains: frozenset[str]) -> str | None:
    if user.mail is None:
        return "mail_null"
    if user.account_enabled is not True:
        return "disabled" if user.account_enabled is False else "service_or_unknown"
    if (user.user_type or "").casefold() != "member":
        return "guest" if (user.user_type or "").casefold() == "guest" else "service_or_unknown"
    if not allowed_domains or not is_recipient_allowed(user.mailbox, allowed_domains):
        return "domain_not_allowed"
    return None


def _fetch(
    ctx: DirectoryJobContext, cursor: str | None, groups: tuple[str, ...]
) -> tuple[DirectorySyncResult, dict[str, list[str]]]:
    provider = _provider(ctx, groups)
    if not groups:
        with provider_call("graph", "fetch"):
            return provider.fetch_changes(cursor), {}
    users: dict[str, DirectoryUser] = {}
    mapping: dict[str, list[str]] = {}
    rejected = 0
    pages = 0
    for group_id in groups:
        with provider_call("graph", "fetch"):
            result = provider.fetch_group_members((group_id,))
        if not result.complete or result.truncated:
            return result, {}
        pages += result.pages
        rejected += result.rejected_count
        member_ids: list[str] = []
        for user in result.users:
            previous = users.get(user.entra_id)
            if previous is not None and previous.mailbox.casefold() != user.mailbox.casefold():
                raise _DirectoryDataConflictError("directory returned conflicting records for one Entra object")
            users[user.entra_id] = user
            member_ids.append(user.entra_id)
        mapping[group_id] = sorted(set(member_ids))
    return (
        DirectorySyncResult(
            users=tuple(users[key] for key in sorted(users)),
            removals=(),
            cursor=None,
            cursor_kind=None,
            complete=True,
            truncated=False,
            rejected_count=rejected,
            pages=pages,
        ),
        mapping,
    )


def preview_directory(ctx: DirectoryJobContext, *, requested_by: str, job_id: str) -> dict[str, Any]:
    scope_hash, fingerprint, source, groups = _scope(ctx)
    with ctx.session_factory() as session:
        state = _state(session, scope_hash=scope_hash, fingerprint=fingerprint)
        now = datetime.now(UTC)
        state.last_attempt_at = now
        state.updated_at = now
        # A durable latest-request token lets the post-network transaction
        # discard an older fetch after a newer preview has started.  The
        # directory row does not use mailbox leases, so last_job_key is the
        # simple, constraint-compatible field for this fence.
        state.last_job_key = job_id
        cursor = state.cursor
        session.commit()
    try:
        result, group_members = _fetch(ctx, cursor, groups)
    except Exception as exc:
        with ctx.session_factory() as session:
            state = _state(
                session,
                scope_hash=scope_hash,
                fingerprint=fingerprint,
                reconcile_config=False,
            )
            if state.last_job_key != job_id or state.config_fingerprint != fingerprint:
                # A newer preview/configuration owns the row.  Treat this
                # obsolete attempt as consumed so the queue does not retry it.
                return {"status": "superseded", "counts": {}}
            state.status = "error"
            state.last_error = _directory_error_code(exc)
            state.last_counts = {"accepted": 0, "rejected": 0}
            _clear_preview(state)
            state.updated_at = datetime.now(UTC)
            ctx.audit_store.record(
                session=session,
                actor="worker:directory",
                action="directory.preview.failed",
                object_type="system",
                object_id=job_id,
                detail={"error_code": state.last_error},
            )
            session.commit()
        raise

    counts: dict[str, int] = {"provider_rejected": result.rejected_count}
    accepted: list[dict[str, Any]] = []
    allowed_domains = ctx.settings.recipient_domain_allowlist()
    for user in result.users:
        rejection = _accepted_user(user, allowed_domains)
        if rejection is not None:
            counts[rejection] = counts.get(rejection, 0) + 1
            continue
        accepted.append(
            {
                "entra_id": user.entra_id,
                "mailbox": user.mailbox,
                "display_name": user.display_name,
                "department": user.department,
            }
        )
    counts["accepted"] = len(accepted)
    counts["removed"] = len(result.removals)
    counts["pages"] = result.pages
    if len(accepted) > MAX_SYNC_USERS:
        result = DirectorySyncResult((), (), None, None, False, True, result.rejected_count, result.pages)
    with ctx.session_factory() as session:
        state = _state(
            session,
            scope_hash=scope_hash,
            fingerprint=fingerprint,
            reconcile_config=False,
        )
        if state.last_job_key != job_id or state.config_fingerprint != fingerprint:
            return {"status": "superseded", "counts": {}}
        policy_rejected = sum(
            count for name, count in counts.items() if name not in {"accepted", "removed", "pages", "provider_rejected"}
        )
        rejected_full_snapshot = bool(groups and (result.rejected_count or policy_rejected))
        if not result.complete or result.truncated or rejected_full_snapshot:
            state.status = "rejected" if rejected_full_snapshot else "truncated"
            state.last_error = (
                "full_snapshot_contains_rejected_rows" if rejected_full_snapshot else "provider_result_incomplete"
            )
            state.last_counts = counts
            _clear_preview(state)
            state.updated_at = datetime.now(UTC)
            ctx.audit_store.record(
                session=session,
                actor="worker:directory",
                action="directory.preview.rejected",
                object_type="system",
                object_id=job_id,
                detail={"reason": state.last_error, **counts},
            )
            session.commit()
            return {"status": state.status, "counts": counts}
        payload = {
            "mode": "full" if groups else "delta",
            "source": source,
            "users": accepted,
            "removals": [item.entra_id for item in result.removals],
            "group_members": group_members,
            "cursor": result.cursor,
            "cursor_kind": result.cursor_kind,
            "config_fingerprint": fingerprint,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        preview_id = uuid.uuid4()
        preview_hash = _digest(encoded)
        state.status = "preview_ready"
        state.last_error = None
        state.last_counts = counts
        state.pending_preview_id = preview_id
        state.pending_preview_hash = preview_hash
        state.pending_payload = encoded
        state.pending_created_at = datetime.now(UTC)
        state.pending_expires_at = state.pending_created_at + PREVIEW_TTL
        state.last_success_at = state.pending_created_at
        state.updated_at = state.last_success_at
        ctx.audit_store.record(
            session=session,
            actor="worker:directory",
            action="directory.preview",
            object_type="system",
            object_id=str(preview_id),
            detail={"requested_by": requested_by, "mode": payload["mode"], **counts},
        )
        session.commit()
        return {"status": "preview_ready", "preview_id": str(preview_id), "counts": counts}


def _object_hash(entra_id: str, salt: bytes, source: str) -> str:
    return hmac.new(
        salt,
        b"kp-directory-object-v1\0" + source.encode("ascii") + b"\0" + entra_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _group_hash(group_id: str, salt: bytes) -> str:
    return hmac.new(
        salt,
        b"kp-directory-group-v1\0microsoft365\0" + group_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _invalidate_group_campaigns(session: Session, group_id: uuid.UUID) -> int:
    impacted = list(
        session.scalars(select(CampaignAudience).where(CampaignAudience.group_ids.contains([str(group_id)])))
    )
    invalidated = 0
    for audience in impacted:
        campaign = session.get(Campaign, audience.campaign_id, with_for_update=True)
        if campaign is not None and audience.frozen_at is not None:
            invalidate_campaign_audience(session, campaign, audience)
            invalidated += 1
    return invalidated


def apply_directory(ctx: DirectoryJobContext, *, preview_id: str, requested_by: str, job_id: str) -> dict[str, int]:
    scope_hash, fingerprint, source, _ = _scope(ctx)
    salt = ctx.settings.require_recipient_hash_salt()
    with ctx.session_factory() as session:
        state = _state(session, scope_hash=scope_hash, fingerprint=fingerprint)
        try:
            expected_preview_id = uuid.UUID(preview_id)
        except ValueError:
            raise RuntimeError("directory preview ID is malformed") from None
        if (
            state.status != "preview_ready"
            or state.pending_preview_id != expected_preview_id
            or not state.pending_payload
            or _digest(state.pending_payload) != state.pending_preview_hash
        ):
            raise RuntimeError("directory preview is missing, stale or already applied")
        now = datetime.now(UTC)
        if state.pending_expires_at is None or state.pending_expires_at <= now:
            _clear_preview(state)
            state.status = "expired"
            state.last_error = "preview_expired"
            state.updated_at = now
            session.commit()
            raise RuntimeError("directory preview expired and must be regenerated")
        payload = json.loads(state.pending_payload)
        if payload.get("config_fingerprint") != fingerprint or payload.get("source") != source:
            raise RuntimeError("directory configuration changed after preview")
        next_generation = state.generation + 1
        object_to_recipient: dict[str, uuid.UUID] = {}
        created = updated = deactivated = 0
        incoming_hashes: set[str] = set()
        for raw in payload["users"]:
            object_hash = _object_hash(raw["entra_id"], salt, source)
            mailbox_hash = hash_mailbox(raw["mailbox"], salt)
            incoming_hashes.add(object_hash)
            by_object = session.scalar(
                select(Recipient).where(
                    Recipient.directory_source == source,
                    Recipient.directory_object_id_hash == object_hash,
                    Recipient.deleted_at.is_(None),
                )
            )
            by_mailbox = session.scalar(
                select(Recipient).where(Recipient.mailbox_sha256 == mailbox_hash, Recipient.deleted_at.is_(None))
            )
            if by_object is not None and by_mailbox is not None and by_object.recipient_id != by_mailbox.recipient_id:
                raise RuntimeError("directory object/mailbox collision requires operator resolution")
            if by_object is not None and not secrets.compare_digest(
                by_object.directory_object_id_hash or "", object_hash
            ):
                raise RuntimeError("directory object hash collision requires operator resolution")
            if by_object is None and by_mailbox is not None:
                raise RuntimeError("directory mailbox collides with a non-directory recipient")
            recipient = by_object
            if recipient is None:
                recipient = Recipient(
                    recipient_id=uuid.uuid4(),
                    employee_key=f"entra:{object_hash[:24]}",
                    mailbox=raw["mailbox"],
                    mailbox_sha256=mailbox_hash,
                    display_name=raw.get("display_name"),
                    department=raw.get("department"),
                    status=dm.RecipientStatus.ACTIVE,
                    last_snapshot_source="microsoft365",
                    directory_source=source,
                    directory_object_id_hash=object_hash,
                    directory_generation=next_generation,
                    directory_owned=True,
                )
                session.add(recipient)
                created += 1
            else:
                recipient.mailbox = raw["mailbox"]
                recipient.mailbox_sha256 = mailbox_hash
                recipient.display_name = raw.get("display_name")
                recipient.department = raw.get("department")
                recipient.status = dm.RecipientStatus.ACTIVE
                recipient.directory_generation = next_generation
                recipient.last_snapshot_source = "microsoft365"
                updated += 1
            session.flush()
            object_to_recipient[raw["entra_id"]] = recipient.recipient_id

        removal_hashes = {_object_hash(item, salt, source) for item in payload.get("removals", [])}
        if payload.get("mode") == "full":
            candidates = list(
                session.scalars(
                    select(Recipient).where(
                        Recipient.directory_source == source,
                        Recipient.directory_owned.is_(True),
                        Recipient.deleted_at.is_(None),
                    )
                )
            )
            removal_hashes.update(
                item.directory_object_id_hash
                for item in candidates
                if item.directory_object_id_hash and item.directory_object_id_hash not in incoming_hashes
            )
        if removal_hashes:
            removals = list(
                session.scalars(
                    select(Recipient).where(
                        Recipient.directory_source == source,
                        Recipient.directory_owned.is_(True),
                        Recipient.directory_object_id_hash.in_(removal_hashes),
                        Recipient.deleted_at.is_(None),
                    )
                )
            )
            for recipient in removals:
                recipient.status = dm.RecipientStatus.DEPARTED
                recipient.directory_generation = next_generation
                deactivated += 1

        group_changes = invalidated = 0
        for group_ref, entra_ids in payload.get("group_members", {}).items():
            group_ref_hash = _group_hash(group_ref, salt)
            groups = list(
                session.scalars(select(AudienceGroup).where(AudienceGroup.directory_group_ref_hash == group_ref_hash))
            )
            member_ids = sorted(
                {object_to_recipient[item] for item in entra_ids if item in object_to_recipient}, key=str
            )
            for group in groups:
                current = set(
                    session.scalars(
                        select(AudienceGroupMember.recipient_id).where(
                            AudienceGroupMember.audience_group_id == group.audience_group_id
                        )
                    )
                )
                if current == set(member_ids):
                    continue
                session.execute(
                    delete(AudienceGroupMember).where(AudienceGroupMember.audience_group_id == group.audience_group_id)
                )
                session.add_all(
                    [
                        AudienceGroupMember(
                            audience_group_member_id=uuid.uuid4(),
                            audience_group_id=group.audience_group_id,
                            recipient_id=recipient_id,
                        )
                        for recipient_id in member_ids
                    ]
                )
                group_changes += 1
                invalidated += _invalidate_group_campaigns(session, group.audience_group_id)

        state.cursor = payload.get("cursor")
        state.cursor_kind = payload.get("cursor_kind")
        state.generation = next_generation
        state.status = "healthy"
        state.last_error = None
        state.last_applied_at = datetime.now(UTC)
        state.updated_at = state.last_applied_at
        _clear_preview(state)
        state.last_counts = {
            **dict(state.last_counts or {}),
            "created": created,
            "updated": updated,
            "deactivated": deactivated,
            "groups_updated": group_changes,
            "campaigns_invalidated": invalidated,
        }
        ctx.audit_store.record(
            session=session,
            actor="worker:directory",
            action="directory.apply",
            object_type="system",
            object_id=job_id,
            detail={"requested_by": requested_by, **state.last_counts},
        )
        session.commit()
        return {
            "created": created,
            "updated": updated,
            "deactivated": deactivated,
            "groups_updated": group_changes,
            "campaigns_invalidated": invalidated,
        }


def discard_directory_preview(
    ctx: DirectoryJobContext,
    *,
    preview_id: str,
    requested_by: str,
    job_id: str,
) -> dict[str, bool]:
    scope_hash, fingerprint, _, _ = _scope(ctx)
    try:
        expected_preview_id = uuid.UUID(preview_id)
    except ValueError:
        raise RuntimeError("directory preview ID is malformed") from None
    with ctx.session_factory() as session:
        state = _state(session, scope_hash=scope_hash, fingerprint=fingerprint)
        if state.pending_preview_id != expected_preview_id:
            raise RuntimeError("directory preview is missing, stale or already discarded")
        _clear_preview(state)
        state.status = "discarded"
        state.last_error = None
        state.updated_at = datetime.now(UTC)
        ctx.audit_store.record(
            session=session,
            actor="worker:directory",
            action="directory.preview.discard",
            object_type="system",
            object_id=job_id,
            detail={"requested_by": requested_by, "discarded": True},
        )
        session.commit()
        return {"discarded": True}


def process_directory_sync(ctx: DirectoryJobContext, message: dict[str, Any]) -> None:
    payload = message.get("payload", {})
    if not isinstance(payload, dict):
        raise RuntimeError("directory job payload must be an object")
    job_id = _queue_uuid(payload, "job_id")
    requested_by = _queue_uuid(payload, "requested_by")
    action = payload.get("action")
    if not isinstance(action, str):
        raise RuntimeError("directory job action is required")
    if action == "preview":
        preview_directory(ctx, requested_by=requested_by, job_id=job_id)
        return
    if action == "apply":
        preview_id = payload.get("preview_id")
        if not isinstance(preview_id, str):
            raise RuntimeError("directory apply requires preview_id")
        apply_directory(ctx, preview_id=preview_id, requested_by=requested_by, job_id=job_id)
        return
    if action == "discard":
        preview_id = payload.get("preview_id")
        if not isinstance(preview_id, str):
            raise RuntimeError("directory discard requires preview_id")
        discard_directory_preview(ctx, preview_id=preview_id, requested_by=requested_by, job_id=job_id)
        return
    raise RuntimeError("unsupported directory job action")
