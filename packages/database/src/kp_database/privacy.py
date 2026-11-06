"""Data-minimization helpers shared by the tracking API and migrations.

Implements the HIGH-17 / WS-9 retention minimization: event client IPs are
stored as a /24 (IPv4) or /64 (IPv6) prefix instead of the full address, and
user agents are truncated. The salted mailbox hash (WS-12) lives here too so
seeding, CSV import, and migrations agree on the exact construction.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

CLIENT_IP_MAX = 45
USER_AGENT_MAX_LENGTH = 128


class PrivacyRequestStatus(StrEnum):
    """Persisted DSR workflow states.

    Only VERIFIED requests may disclose or mutate subject data.  IN_PROGRESS
    means fulfillment has begun; COMPLETED is terminal.
    """

    OPENED = "opened"
    VERIFIED = "verified"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REFUSED = "refused"


VERIFIED_PRIVACY_STATES = frozenset({PrivacyRequestStatus.VERIFIED.value, PrivacyRequestStatus.IN_PROGRESS.value})


def minimize_ip(value: str | None) -> str | None:
    """Reduce an IP to a coarse prefix so events cannot re-identify a device.

    IPv4 addresses are truncated to the /24 network; IPv6 to the /64 prefix.
    Unparseable values (already-minimized or malformed) are returned unchanged.
    """
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return value[:CLIENT_IP_MAX]
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Network((ip, 24), strict=False).network_address)
    return str(ipaddress.IPv6Network((ip, 64), strict=False).network_address)


def minimize_user_agent(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:USER_AGENT_MAX_LENGTH]


def hash_mailbox(mailbox: str, salt: bytes) -> str:
    """Deterministic salted SHA-256 of a mailbox for dedup lookups (HIGH-08).

    Double-hashes so the persisted hash from the unsalted era can be re-salted
    in-place by the WS-12 migration without access to the plaintext (the
    recipient mailbox is CipherText-encrypted). With the salt unknown, a DB
    dump alone is not enough for offline dictionary/rainbow attacks.
    """
    inner = hashlib.sha256(mailbox.lower().encode("utf-8")).digest()
    return hashlib.sha256(salt + inner).hexdigest()


@dataclass(frozen=True, slots=True)
class RecipientErasureResult:
    recipient_found: bool
    tombstoned_now: bool = False
    already_tombstoned: bool = False
    ledger_rows_purged: int = 0


def erase_recipient_data(
    session: Session,
    recipient_id: UUID,
    *,
    erased_at: datetime,
    pseudonym_key: bytes,
    pseudonym_key_version: str,
) -> bool:
    """Compatibility interface: report whether this call created a tombstone.

    Cleanup also reaches historical tombstones. Call the result-returning
    interface when recording purge counts or repeated-erasure remediation.
    """
    return erase_recipient_data_with_result(
        session,
        recipient_id,
        erased_at=erased_at,
        pseudonym_key=pseudonym_key,
        pseudonym_key_version=pseudonym_key_version,
    ).tombstoned_now


def erase_recipient_data_with_result(
    session: Session,
    recipient_id: UUID,
    *,
    erased_at: datetime,
    pseudonym_key: bytes,
    pseudonym_key_version: str,
) -> RecipientErasureResult:
    """Erase a recipient and all directly linked behavioral data.

    The recipient row is retained as an anonymous tombstone so historic
    aggregate/audit references remain structurally valid.  The random mailbox
    digest prevents later linkage or dictionary recovery.

    ``pseudonym_key`` / ``pseudonym_key_version`` are the active governed
    awareness-ledger key. Because the ledger pseudonym is keyed (re-identifiable
    while the key exists), right-to-erasure must also purge the subject's ledger
    rows; see :func:`kp_database.awareness_ledger.purge_recipient_awareness_ledger`.
    The caller fails closed (cannot resolve the key -> raises) before invoking
    this function, so erasure never silently leaves re-identifiable rows behind.
    """
    from kp_database.awareness_ledger import _validate_pseudonym_inputs, purge_recipient_awareness_ledger
    from kp_database.models import (
        AudienceGroupMember,
        Microsoft365IntegrationState,
        Recipient,
        RecipientAssignment,
        RecipientExclusion,
        TrackingEvent,
        TrackingToken,
        TrainingAssignment,
    )
    from kp_database.personal_data import ASSIGNMENT_LINKED_RECEIPT_MODELS
    from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
    from kp_database.retention_holds import require_no_retention_hold

    # Validate before any SQL writes or autoflush, including direct callers.
    _validate_pseudonym_inputs(
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
        key=pseudonym_key,
        key_version=pseudonym_key_version,
        as_of=erased_at,
    )
    require_no_retention_hold(session)
    recipient = session.get(Recipient, recipient_id, with_for_update=True, populate_existing=True)
    if recipient is None:
        return RecipientErasureResult(recipient_found=False)
    already_tombstoned = recipient.deleted_at is not None
    assignment_ids = list(
        session.scalars(
            select(RecipientAssignment.recipient_assignment_id).where(RecipientAssignment.recipient_id == recipient_id)
        )
    )
    token_ids: list[UUID] = []
    if assignment_ids:
        token_ids = list(
            session.scalars(
                select(TrackingToken.token_id).where(TrackingToken.recipient_assignment_id.in_(assignment_ids))
            )
        )
        if token_ids:
            session.execute(delete(TrackingEvent).where(TrackingEvent.token_id.in_(token_ids)))
        # Explicitly delete both assignment-linked mail receipts for this
        # subject before the assignments go, rather than relying on the FK
        # ``ondelete="SET NULL"`` (which would leave orphaned reply/reported
        # receipts carrying the subject's encrypted external message id). Reply
        # receipts previously escaped erasure entirely (KP-AUD-003).
        for receipt_model in ASSIGNMENT_LINKED_RECEIPT_MODELS:
            model: Any = receipt_model
            session.execute(
                delete(model)
                .where(model.recipient_assignment_id.in_(assignment_ids))
                .execution_options(synchronize_session=False)
            )
        session.execute(delete(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids)))
    session.execute(delete(TrackingEvent).where(TrackingEvent.recipient_id == recipient_id))
    session.execute(delete(TrainingAssignment).where(TrainingAssignment.recipient_id == recipient_id))
    session.execute(delete(RecipientExclusion).where(RecipientExclusion.recipient_id == recipient_id))
    session.execute(delete(AudienceGroupMember).where(AudienceGroupMember.recipient_id == recipient_id))
    pending_states = list(
        session.scalars(
            select(Microsoft365IntegrationState)
            .where(
                Microsoft365IntegrationState.kind == "directory",
                Microsoft365IntegrationState.pending_payload.is_not(None),
            )
            .limit(1001)
            .with_for_update()
        )
    )
    if len(pending_states) > 1000:
        raise RuntimeError("directory preview erasure exceeds the bounded lifecycle limit")
    for state in pending_states:
        state.pending_preview_id = None
        state.pending_preview_hash = None
        state.pending_payload = None
        state.pending_created_at = None
        state.pending_expires_at = None
        state.status = "discarded"
        state.last_error = "privacy_erasure"
        state.updated_at = erased_at
    if assignment_ids:
        session.execute(
            delete(RecipientAssignment).where(RecipientAssignment.recipient_assignment_id.in_(assignment_ids))
        )

    # Delete assignments before the ledger purge: a projector holds each
    # assignment FOR UPDATE until its ledger write commits. Waiting here makes
    # that projection visible to the following READ COMMITTED purge and stops
    # later projectors from recreating subject data from a deleted assignment.
    # Historical tombstones still retain the UUID needed for exact cleanup
    # with a governed retained key version; never derive it from their marker.
    ledger_rows_purged = purge_recipient_awareness_ledger(
        session,
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
        recipient_id=recipient_id,
        pseudonym_key=pseudonym_key,
        pseudonym_key_version=pseudonym_key_version,
    )

    if already_tombstoned:
        return RecipientErasureResult(
            recipient_found=True, already_tombstoned=True, ledger_rows_purged=ledger_rows_purged
        )
    marker = f"erased-{uuid4()}"
    recipient.employee_key = marker
    recipient.mailbox = marker
    recipient.mailbox_sha256 = hashlib.sha256(marker.encode()).hexdigest()
    recipient.display_name = None
    recipient.department = None
    recipient.last_snapshot_source = None
    recipient.directory_source = None
    recipient.directory_object_id_hash = None
    recipient.directory_generation = None
    recipient.directory_owned = False
    recipient.deleted_at = erased_at
    return RecipientErasureResult(recipient_found=True, tombstoned_now=True, ledger_rows_purged=ledger_rows_purged)
