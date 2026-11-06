"""Preservation policy effects; PostgreSQL serialization is qualified separately."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, Response
from kp_database import retention_holds as holds
from kp_database.awareness_ledger import purge_recipient_awareness_ledger
from kp_database.models import CipherText, RetentionHold
from kp_database.privacy import erase_recipient_data
from kp_operator_api.routes import privacy
from kp_telemetry.errors import ConflictError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session


@pytest.fixture
def session(monkeypatch):  # type: ignore[no-untyped-def]
    for name in ["_active_key_id", "_active_key", "_prior_keys"]:
        monkeypatch.setattr(CipherText, name, getattr(CipherText, name))
    CipherText.configure_key(bytes.fromhex("17" * 32))
    engine = create_engine("sqlite://")
    RetentionHold.__table__.create(engine)
    monkeypatch.setattr(holds, "lock_hold_state", lambda _session, *, exclusive=False: None)
    with Session(engine) as value:
        yield value
    engine.dispose()


def create(session: Session, reference: str = "CASE-1"):  # type: ignore[no-untyped-def]
    row, changed = holds.create_retention_hold(
        session,
        hold_id=uuid4(),
        reference=reference,
        reason="Preserve records for review",
        actor="administrator",
        now=datetime.now(UTC),
    )
    assert changed
    session.commit()
    return row


def test_active_hold_blocks_both_raw_erasure_and_direct_keyed_ledger_purge(session: Session) -> None:
    create(session)
    recipient_id = uuid4()
    with pytest.raises(holds.RetentionHoldActive):
        erase_recipient_data(
            session, recipient_id, erased_at=datetime.now(UTC), pseudonym_key=b"x" * 32, pseudonym_key_version="v1"
        )
    with pytest.raises(holds.RetentionHoldActive):
        purge_recipient_awareness_ledger(
            session,
            tenant_scope="single_tenant_database",
            recipient_id=recipient_id,
            pseudonym_key=b"x" * 32,
            pseudonym_key_version="v1",
        )


def test_releasing_one_of_multiple_holds_does_not_resume_erasure(session: Session) -> None:
    first, second = create(session, "CASE-1"), create(session, "CASE-2")
    holds.release_retention_hold(
        session,
        hold_id=first.retention_hold_id,
        actor="administrator",
        reason="First case resolved",
        now=datetime.now(UTC),
    )
    session.commit()
    with pytest.raises(holds.RetentionHoldActive):
        holds.require_no_retention_hold(session)
    holds.release_retention_hold(
        session,
        hold_id=second.retention_hold_id,
        actor="administrator",
        reason="Second case resolved",
        now=datetime.now(UTC),
    )
    session.commit()
    holds.require_no_retention_hold(session)
    assert session.query(RetentionHold).count() == 2


def test_hold_creation_is_retry_safe_and_does_not_reactivate_released_history(session: Session) -> None:
    row = create(session)
    kwargs = dict(
        hold_id=row.retention_hold_id,
        reference=row.reference,
        reason=row.reason,
        actor=row.created_by,
        now=datetime.now(UTC),
    )
    again, changed = holds.create_retention_hold(session, **kwargs)
    assert again.retention_hold_id == row.retention_hold_id and not changed
    with pytest.raises(ValueError):
        holds.create_retention_hold(session, **{**kwargs, "reason": "Different case"})
    holds.release_retention_hold(
        session, hold_id=row.retention_hold_id, actor="administrator", reason="Resolved", now=datetime.now(UTC)
    )
    session.commit()
    again, changed = holds.create_retention_hold(session, **kwargs)
    assert not changed and again.released_at is not None


def test_hold_reasons_and_case_references_are_encrypted_at_rest(session: Session) -> None:
    row = create(session)
    stored = session.execute(text("SELECT reference, reason FROM retention_holds")).one()
    assert stored.reference.startswith("kpct.") and stored.reason.startswith("kpct.")
    assert row.reference not in stored.reference and row.reason not in stored.reason


def test_unsupported_isolation_fails_closed_without_acquiring_or_mutating() -> None:
    session = SimpleNamespace(
        connection=lambda: SimpleNamespace(
            dialect=SimpleNamespace(name="postgresql"), get_isolation_level=lambda: "REPEATABLE READ"
        )
    )
    with pytest.raises(holds.RetentionHoldStateUnavailable):
        holds.lock_hold_state(session)  # type: ignore[arg-type]


def test_release_is_idempotent_and_keeps_the_original_actor_reason_and_time(session: Session) -> None:
    row = create(session)
    released, changed = holds.release_retention_hold(
        session, hold_id=row.retention_hold_id, actor="first-admin", reason="Original decision", now=datetime.now(UTC)
    )
    assert changed and released is not None
    original_time = released.released_at
    released, changed = holds.release_retention_hold(
        session,
        hold_id=row.retention_hold_id,
        actor="second-admin",
        reason="Replacement decision",
        now=datetime.now(UTC),
    )
    assert not changed and released is not None
    assert (released.released_by, released.release_reason, released.released_at) == (
        "first-admin",
        "Original decision",
        original_time,
    )


def test_admin_mutations_are_audited_without_copying_case_text_into_audit(session: Session) -> None:
    events = []
    audit = SimpleNamespace(record=lambda **kwargs: events.append(kwargs))
    principal = SimpleNamespace(principal_id="admin")
    body = privacy.RetentionHoldCreate(hold_id=uuid4(), reference="sensitive-reference", reason="sensitive-reason")
    response = Response()
    result = privacy.set_retention_hold(body=body, response=response, session=session, audit=audit, principal=principal)
    assert result["active"] and "no-store" in response.headers["Cache-Control"]
    privacy.set_retention_hold(body=body, response=Response(), session=session, audit=audit, principal=principal)
    assert len(events) == 1 and events[0]["action"] == "retention_hold.set"
    assert "sensitive" not in str(events[0]["detail"])
    privacy.clear_retention_hold(
        hold_id=body.hold_id,
        body=privacy.RetentionHoldRelease(reason="private release reason"),
        response=Response(),
        session=session,
        audit=audit,
        principal=principal,
    )
    assert events[-1]["action"] == "retention_hold.released"
    assert "private release" not in str(events[-1]["detail"])


def test_api_hold_check_returns_conflict_without_leaking_the_case_reason(session: Session) -> None:
    create(session)
    with pytest.raises(ConflictError) as error:
        privacy._check_erasure_hold(session)
    assert "Preserve records for review" not in str(error.value)


def test_a_held_privacy_request_stays_verified_and_is_not_marked_fulfilled(session: Session, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from kp_domain_models import models as dm

    create(session)
    request = SimpleNamespace(request_type=dm.PrivacyRequestType.DELETION, status="verified", completed_at=None)
    monkeypatch.setattr(session, "get", lambda *_args: request)
    monkeypatch.setattr(privacy, "_recipients_for_request", lambda *_args: [])
    with pytest.raises(ConflictError):
        privacy.fulfill_privacy_request(
            request_id=uuid4(),
            body=privacy.PrivacyFulfillment(),
            session=session,
            audit=SimpleNamespace(),
            settings=SimpleNamespace(),
            principal=SimpleNamespace(principal_id="operator"),
        )
    assert request.status == "verified" and request.completed_at is None


def test_unverifiable_hold_state_never_permits_api_erasure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def unavailable(_session):  # type: ignore[no-untyped-def]
        raise holds.RetentionHoldStateUnavailable()

    monkeypatch.setattr(privacy, "require_no_retention_hold", unavailable)
    with pytest.raises(HTTPException) as error:
        privacy._check_erasure_hold(SimpleNamespace())  # type: ignore[arg-type]
    assert error.value.status_code == 503


@pytest.mark.parametrize("field", ["reason", "reference"])
def test_blank_hold_fields_are_rejected(field: str) -> None:
    values = {"hold_id": uuid4(), "reference": "CASE-1", "reason": "Preserve records", field: "   "}
    with pytest.raises(ValueError):
        privacy.RetentionHoldCreate(**values)
