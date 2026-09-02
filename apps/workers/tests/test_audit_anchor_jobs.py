from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.audit_store import AuditHeadSnapshot
from kp_workers.audit_anchor_jobs import AuditIntegrityUnhealthyError, anchor_verified_head, maybe_publish_audit_anchor
from kp_workers.providers.audit_anchor import AuditAnchor


class FakeProvider:
    def __init__(self) -> None:
        self.anchors: list[AuditAnchor] = []

    def publish(self, anchor: AuditAnchor) -> str:
        self.anchors.append(anchor)
        return "created"


class FakeQueue:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any], str]] = []

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str) -> None:
        self.published.append((topic, payload, idempotency_key))


def _ctx(problems: list[str] | None = None, snapshots: tuple[AuditHeadSnapshot | None, ...] = ()) -> Any:
    values = iter(snapshots or (_head_snapshot(), _head_snapshot()))
    audit_store = SimpleNamespace(verify=lambda: list(problems or []), head_snapshot=lambda: next(values))
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


def test_interval_bucket_is_the_queue_idempotency_boundary() -> None:
    ctx = _ctx()

    maybe_publish_audit_anchor(ctx, datetime(2026, 8, 27, 12, 34, tzinfo=UTC))

    topic, payload, key = ctx.queue.published[0]
    assert topic == "audit-anchor"
    assert payload == {}
    assert key.startswith("audit-anchor:")
