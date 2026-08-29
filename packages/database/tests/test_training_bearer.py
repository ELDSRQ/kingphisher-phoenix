from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta

from kp_database.training import (
    TrainingBearerPurpose,
    training_bearer,
    training_bearer_verifier,
    verify_training_bearer,
)

KEY = b"t" * 32
OTHER_KEY = b"x" * 32


def test_training_bearer_is_opaque_scoped_and_verifier_only_at_rest() -> None:
    assignment_id = uuid.uuid4()
    now = datetime(2026, 8, 1, tzinfo=UTC)
    expires_at = now + timedelta(days=30)

    bearer = training_bearer(assignment_id, expires_at, KEY, purpose=TrainingBearerPurpose.OPEN)
    verifier = training_bearer_verifier(bearer, KEY, purpose=TrainingBearerPurpose.OPEN)

    assert str(assignment_id) not in bearer
    decoded = base64.urlsafe_b64decode(bearer.encode("ascii") + b"=" * (-len(bearer) % 4))
    assert assignment_id.bytes not in decoded
    assert bearer not in verifier
    assert len(verifier) == 64
    assert verify_training_bearer(
        bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )


def test_training_bearer_rejects_wrong_assignment_key_expiry_and_tampering() -> None:
    assignment_id = uuid.uuid4()
    now = datetime(2026, 8, 1, tzinfo=UTC)
    expires_at = now + timedelta(days=30)
    bearer = training_bearer(assignment_id, expires_at, KEY, purpose=TrainingBearerPurpose.OPEN)

    assert not verify_training_bearer(
        bearer,
        assignment_id=uuid.uuid4(),
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )
    assert not verify_training_bearer(
        bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=OTHER_KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )
    assert not verify_training_bearer(
        bearer,
        assignment_id=assignment_id,
        expires_at=expires_at + timedelta(seconds=1),
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )
    assert not verify_training_bearer(
        bearer[:-1] + ("A" if bearer[-1] != "A" else "B"),
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )
    assert not verify_training_bearer(
        bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=expires_at,
    )
    assert not verify_training_bearer(
        bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=expires_at + timedelta(seconds=1),
    )


def test_training_bearer_rejects_cross_purpose_reuse() -> None:
    assignment_id = uuid.uuid4()
    now = datetime(2026, 8, 1, tzinfo=UTC)
    expires_at = now + timedelta(days=30)
    open_bearer = training_bearer(assignment_id, expires_at, KEY, purpose=TrainingBearerPurpose.OPEN)
    completion_bearer = training_bearer(
        assignment_id,
        expires_at,
        KEY,
        purpose=TrainingBearerPurpose.COMPLETE,
    )

    assert open_bearer != completion_bearer
    assert not verify_training_bearer(
        open_bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.COMPLETE,
        now=now,
    )
    assert not verify_training_bearer(
        completion_bearer,
        assignment_id=assignment_id,
        expires_at=expires_at,
        key=KEY,
        purpose=TrainingBearerPurpose.OPEN,
        now=now,
    )
