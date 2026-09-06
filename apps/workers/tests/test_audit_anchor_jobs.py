from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.audit_store import AuditHeadSnapshot
from kp_workers.audit_anchor_jobs import (
    AuditAnchorReadBackError,
    AuditIntegrityUnhealthyError,
    anchor_verified_head,
    maybe_publish_audit_anchor,
)
from kp_workers.providers.audit_anchor import AuditAnchor


class FakeProvider:
    def __init__(self, recent: list[AuditAnchor] | None = None) -> None:
        self.anchors: list[AuditAnchor] = []
        self._recent = recent or []

    def publish(self, anchor: AuditAnchor) -> str:
        self.anchors.append(anchor)
        return "created"

    def read_recent(self, limit: int) -> list[AuditAnchor]:
        return self._recent[:limit]

    def __enter__(self) -> FakeProvider:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class FakeQueue:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any], str]] = []

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str) -> None:
        self.published.append((topic, payload, idempotency_key))


def _ctx(
    problems: list[str] | None = None,
    snapshots: tuple[AuditHeadSnapshot | None, ...] = (),
    chain_empty: bool = False,
    positions: dict[int, str | None] | None = None,
) -> Any:
    values = iter(snapshots or (_head_snapshot(), _head_snapshot()))
    audit_store = SimpleNamespace(
        verify=lambda: list(problems or []),
        head_snapshot=lambda: next(values),
        is_chain_empty=lambda: chain_empty,
        hashes_by_sequence=lambda sequences: {s: (positions or {}).get(s) for s in sequences},
    )
    settings = SimpleNamespace(audit_anchor_interval_seconds=3600)
    return SimpleNamespace(audit_store=audit_store, settings=settings, queue=FakeQueue())


def _head(sequence: int = 3, event_hash: str = "ab" * 32) -> AuditAnchor:
    return AuditAnchor(sequence, event_hash, datetime(2026, 8, 27, 12, 0, tzinfo=UTC))


def _head_snapshot(sequence: int = 3, event_hash: str = "ab" * 32) -> AuditHeadSnapshot:
    return AuditHeadSnapshot(sequence, event_hash, datetime(2026, 8, 27, 12, 0, tzinfo=UTC))


def test_verified_stable_head_is_published() -> None:
    ctx = _ctx()
    provider = FakeProvider()

    assert anchor_verified_head(ctx, provider) == "created"
    assert provider.anchors == [_head()]


def test_empty_chain_is_a_healthy_no_op() -> None:
    # No signed head yet + an entirely empty chain -> skip, do not fail.
    ctx = _ctx(snapshots=(None, None), chain_empty=True)
    provider = FakeProvider()

    assert anchor_verified_head(ctx, provider) == "empty"
    assert provider.anchors == []


def test_missing_head_on_non_empty_chain_still_fails() -> None:
    # No signed head but the chain is NOT empty -> genuine corruption -> fail.
    ctx = _ctx(snapshots=(None, None), chain_empty=False)
    provider = FakeProvider()

    with pytest.raises(AuditIntegrityUnhealthyError, match="no signed audit head"):
        anchor_verified_head(ctx, provider)

    assert provider.anchors == []


def test_integrity_failure_blocks_publication() -> None:
    ctx = _ctx(["hash mismatch containing internal details"])
    provider = FakeProvider()

    with pytest.raises(AuditIntegrityUnhealthyError, match="1 problem"):
        anchor_verified_head(ctx, provider)

    assert provider.anchors == []


def test_persistent_head_change_blocks_publication() -> None:
    # Head advances on every attempt -> never stabilizes -> fail closed.
    ctx = _ctx(snapshots=(_head_snapshot(3), _head_snapshot(4, "cd" * 32)) * 6)
    provider = FakeProvider()

    with pytest.raises(AuditIntegrityUnhealthyError, match="did not stabilize"):
        anchor_verified_head(ctx, provider)

    assert provider.anchors == []


def test_head_that_stabilizes_on_retry_is_published() -> None:
    # First attempt races (3 -> 4), second attempt sees a stable head (3 == 3).
    ctx = _ctx(
        snapshots=(
            _head_snapshot(3),
            _head_snapshot(4, "cd" * 32),
            _head_snapshot(3),
            _head_snapshot(3),
        )
    )
    provider = FakeProvider()

    assert anchor_verified_head(ctx, provider) == "created"
    assert provider.anchors == [_head()]


def _anchor_digest(anchor: AuditAnchor) -> str:
    return hashlib.sha256(anchor.canonical_bytes()).hexdigest()


def test_new_anchor_is_chained_to_the_newest_existing_anchor() -> None:
    previous = AuditAnchor(2, "cd" * 32, datetime(2026, 8, 27, 11, 0, tzinfo=UTC))
    ctx = _ctx(positions={2: "cd" * 32})
    provider = FakeProvider(recent=[previous])

    assert anchor_verified_head(ctx, provider) == "created"
    published = provider.anchors[0]
    assert published.previous_anchor_hash == _anchor_digest(previous)


def test_read_back_mismatch_is_non_retryable_and_blocks_publication() -> None:
    # A previously anchored head is no longer at its sequence on the chain.
    stale = AuditAnchor(2, "cd" * 32, datetime(2026, 8, 27, 11, 0, tzinfo=UTC))
    ctx = _ctx(positions={2: "ee" * 32})
    provider = FakeProvider(recent=[stale])

    with pytest.raises(AuditAnchorReadBackError):
        anchor_verified_head(ctx, provider)
    assert provider.anchors == []
    assert AuditAnchorReadBackError.retryable is False


def test_read_back_missing_sequence_blocks_publication() -> None:
    # The chain is now shorter than a previously witnessed sequence.
    stale = AuditAnchor(9, "cd" * 32, datetime(2026, 8, 27, 11, 0, tzinfo=UTC))
    ctx = _ctx(positions={9: None})
    provider = FakeProvider(recent=[stale])

    with pytest.raises(AuditAnchorReadBackError):
        anchor_verified_head(ctx, provider)
    assert provider.anchors == []


def test_broken_anchor_chain_blocks_publication() -> None:
    older = AuditAnchor(1, "cd" * 32, datetime(2026, 8, 27, 10, 0, tzinfo=UTC))
    # newer claims a predecessor digest that does not match `older`.
    newer = AuditAnchor(
        2, "cd" * 32, datetime(2026, 8, 27, 11, 0, tzinfo=UTC), previous_anchor_hash="ab" * 32
    )
    ctx = _ctx(positions={1: "cd" * 32, 2: "cd" * 32})
    provider = FakeProvider(recent=[newer, older])

    with pytest.raises(AuditAnchorReadBackError):
        anchor_verified_head(ctx, provider)
    assert provider.anchors == []


def test_interval_bucket_is_the_queue_idempotency_boundary() -> None:
    ctx = _ctx()

    maybe_publish_audit_anchor(ctx, datetime(2026, 8, 27, 12, 34, tzinfo=UTC))

    topic, payload, key = ctx.queue.published[0]
    assert topic == "audit-anchor"
    assert payload == {}
    assert key.startswith("audit-anchor:")
