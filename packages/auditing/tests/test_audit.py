"""Unit tests for the hash-chained audit writer/verifier."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from kp_auditing.audit import (
    GENESIS_HASH,
    AuditRecord,
    AuditVerifier,
    AuditWriter,
    canonical_bytes,
    chain_hash,
    make_nonce,
    sign_head,
    verify_head_signature,
)


def test_audit_record_generates_uuid_event_id() -> None:
    """Regression: default_factory was the UUID class, which raises with no args."""
    record = AuditRecord(
        actor="a",
        action="b",
        object_type="system",
        object_id="1",
        occurred_at=datetime.now(UTC),
        detail={},
        outcome="success",
        prev_hash=GENESIS_HASH,
        event_hash=chain_hash(GENESIS_HASH, b"", make_nonce()),
        nonce=make_nonce(),
    )
    assert isinstance(record.audit_event_id, UUID)


def test_chain_links_records_and_verifier_accepts() -> None:
    writer = AuditWriter()
    first = writer.append(
        actor="seed", action="seed.complete", object_type="campaign", object_id="c1", detail={"a": "b"}
    )
    second = writer.append(
        actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1", detail={"sent": 5}
    )
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.event_hash

    result = AuditVerifier().verify([first, second])
    assert result.ok
    assert result.checked == 2


def test_reset_to_links_into_persisted_head() -> None:
    """Multi-process resume: a fresh writer must chain from the stored head."""
    first_writer = AuditWriter()
    first = first_writer.append(actor="a", action="seed.complete", object_type="campaign", object_id="c1", detail={})
    head = first.event_hash

    second_writer = AuditWriter()
    second_writer.reset_to(head)
    next_record = second_writer.append(
        actor="b", action="campaign.deliver", object_type="campaign", object_id="c1", detail={}
    )
    assert next_record.prev_hash == head

    result = AuditVerifier().verify([first, next_record])
    assert result.ok


def test_tamper_detected() -> None:
    writer = AuditWriter()
    first = writer.append(actor="a", action="x", object_type="system", object_id="1", detail={})
    second = writer.append(actor="b", action="y", object_type="system", object_id="1", detail={})
    second.actor = "attacker"  # tamper
    result = AuditVerifier().verify([first, second])
    assert not result.ok


def test_canonical_bytes_ignores_detail_key_order() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    a = canonical_bytes("x", "y", "z", "1", at, {"b": 2, "a": 1})
    b = canonical_bytes("x", "y", "z", "1", at, {"a": 1, "b": 2})
    assert a == b


def test_head_signature_roundtrip() -> None:
    key = b"0123456789abcdef0123456789abcdef"
    sig = sign_head("a" * 64, key)
    assert verify_head_signature("a" * 64, sig, key)
    assert not verify_head_signature("b" * 64, sig, key)
