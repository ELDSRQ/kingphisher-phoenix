"""Helpers shared by more than one operator route module.

Extracted verbatim from ``kp_operator_api.routers`` during the ARC-002 Item 2
split. Definitions live here exactly once so no security-relevant helper is
duplicated across the resource modules that import them.
"""

from __future__ import annotations

import re
import uuid

from fastapi import HTTPException
from kp_authorization.rbac import Principal
from kp_database.models import (
    Campaign,
    SystemSafetyState,
)
from kp_domain_verification.verification import (
    normalize_domain,
)
from kp_telemetry.errors import (
    NotFoundError,
    PermissionDeniedError,
)
from sqlalchemy.orm import Session


def _allowlisted_validation_message(exc: ValueError, *, allowed: frozenset[str], fallback: str) -> str:
    candidate = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) else None
    return candidate if candidate in allowed else fallback


_MAILBOX_LOCAL_PART = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}\Z")


def _normalize_mailbox(value: str, *, max_length: int) -> str:
    """Return a conservative, storage-safe mailbox or reject it.

    The browser's ``type=email`` control is only a convenience; callers may
    use the API directly.  Keep the server boundary deliberately simple:
    quoted local parts and Unicode domains are not accepted, while explicit
    punycode remains available where required.
    """

    candidate = value.strip().lower()
    if not candidate or len(candidate) > max_length or candidate.count("@") != 1:
        raise ValueError("mailbox is malformed")
    local, domain = candidate.split("@", 1)
    normalized_domain = normalize_domain(domain)
    if (
        _MAILBOX_LOCAL_PART.fullmatch(local) is None
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or normalized_domain is None
        or "." not in normalized_domain
    ):
        raise ValueError("mailbox is malformed")
    normalized = f"{local}@{normalized_domain}"
    if len(normalized) > max_length:
        raise ValueError("mailbox is malformed")
    return normalized


def _principal_uuid(principal: Principal) -> uuid.UUID:
    """Return the canonical caller UUID for persisted identity comparisons."""

    try:
        return uuid.UUID(principal.principal_id)
    except ValueError as exc:
        # The authentication adapter rejects this before route dispatch. Keep
        # direct/internal calls fail-closed without reflecting the identifier.
        raise PermissionDeniedError("authenticated principal identifier is invalid") from exc


def _get_campaign(session: Session, campaign_id: uuid.UUID) -> Campaign:
    campaign = session.get(Campaign, campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")
    return campaign


def _system_safety_state(
    session: Session,
    *,
    shared_lock: bool = False,
    exclusive_lock: bool = False,
) -> SystemSafetyState:
    """Load the singleton interlock, optionally participating in its lock.

    A missing row means the safety migration was not applied.  Treat that as
    an unavailable safety control, never as an implicitly disengaged stop.
    PostgreSQL shared/exclusive row locks linearize scheduling and provider
    sends against an operator engaging the stop.
    """

    if shared_lock and exclusive_lock:
        raise ValueError("only one safety-state lock mode may be requested")
    if shared_lock:
        state = session.get(
            SystemSafetyState,
            1,
            with_for_update={"read": True},
            populate_existing=True,
        )
    elif exclusive_lock:
        state = session.get(SystemSafetyState, 1, with_for_update=True, populate_existing=True)
    else:
        state = session.get(SystemSafetyState, 1, populate_existing=True)
    if state is None:
        raise HTTPException(status_code=503, detail="persistent emergency-stop state is unavailable")
    return state
