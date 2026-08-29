"""Purpose-scoped opaque bearers for awareness-training assignments.

Raw bearers are deterministic only to holders of the dedicated training key
and are never stored. The database stores a second domain-separated HMAC
verifier, matching the tracking-token at-rest design without allowing a
reminder worker to mint click/open tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from enum import StrEnum

_BEARER_CONTEXT = b"kp:training-bearer:v1\0"
_VERIFIER_CONTEXT = b"kp:training-verifier:v1\0"


class TrainingBearerPurpose(StrEnum):
    OPEN = "open"
    COMPLETE = "complete"


_PURPOSE_BYTES = {
    TrainingBearerPurpose.OPEN: b"O",
    TrainingBearerPurpose.COMPLETE: b"C",
}


def _key(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("training token HMAC key must be 32 bytes")
    return key


def _utc_timestamp(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("training bearer expiry must be timezone-aware")
    return int(value.astimezone(UTC).timestamp())


def training_bearer(
    assignment_id: uuid.UUID,
    expires_at: datetime,
    key: bytes,
    *,
    purpose: TrainingBearerPurpose,
) -> str:
    """Derive an opaque bearer scoped to one assignment, purpose, and expiry."""
    material = (
        _BEARER_CONTEXT + _PURPOSE_BYTES[purpose] + assignment_id.bytes + _utc_timestamp(expires_at).to_bytes(8, "big")
    )
    signature = hmac.new(_key(key), material, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def training_bearer_verifier(
    raw_bearer: str,
    key: bytes,
    *,
    purpose: TrainingBearerPurpose,
) -> str:
    """Return the only bearer representation persisted in the database."""
    return hmac.new(
        _key(key),
        _VERIFIER_CONTEXT + _PURPOSE_BYTES[purpose] + raw_bearer.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_training_bearer(
    raw_bearer: str,
    *,
    assignment_id: uuid.UUID,
    expires_at: datetime,
    key: bytes,
    purpose: TrainingBearerPurpose,
    now: datetime | None = None,
) -> bool:
    """Validate purpose, assignment binding, expiry binding, and MAC."""
    try:
        supplied = raw_bearer.encode("ascii")
    except UnicodeEncodeError:
        return False
    expected_expiry = _utc_timestamp(expires_at)
    current = _utc_timestamp(now or datetime.now(UTC))
    expected = training_bearer(assignment_id, expires_at, key, purpose=purpose).encode("ascii")
    return current < expected_expiry and hmac.compare_digest(supplied, expected)
