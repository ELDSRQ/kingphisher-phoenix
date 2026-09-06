"""Unit tests for AuditStore.hashes_by_sequence (AUD-003 read-back support).

These run on an in-memory SQLite engine — the method reads only ``prev_hash``
and ``event_hash`` with portable SQL, so no Postgres profile is required.
"""

from __future__ import annotations

from kp_auditing.audit import GENESIS_HASH
from kp_database.audit_store import AuditStore
from sqlalchemy import create_engine, text


def _chain_engine(hashes: list[str]) -> object:
    """Build a minimal audit_events chain: hashes[i] links to hashes[i-1]."""
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE audit_events (prev_hash TEXT, event_hash TEXT)"))
        previous = GENESIS_HASH
        for event_hash in hashes:
            conn.execute(
                text("INSERT INTO audit_events (prev_hash, event_hash) VALUES (:prev, :hash)"),
                {"prev": previous, "hash": event_hash},
            )
            previous = event_hash
    return engine


def _store(engine: object) -> AuditStore:
    return AuditStore(engine)  # type: ignore[arg-type]


def test_hashes_by_sequence_maps_positions_to_event_hashes() -> None:
    chain = ["11" * 32, "22" * 32, "33" * 32]
    store = _store(_chain_engine(chain))

    result = store.hashes_by_sequence({1, 2, 3})

    assert result == {1: "11" * 32, 2: "22" * 32, 3: "33" * 32}


def test_positions_past_the_end_map_to_none() -> None:
    store = _store(_chain_engine(["11" * 32, "22" * 32]))

    assert store.hashes_by_sequence({2, 5}) == {2: "22" * 32, 5: None}


def test_non_positive_and_empty_requests_are_ignored() -> None:
    store = _store(_chain_engine(["11" * 32]))

    assert store.hashes_by_sequence(set()) == {}
    assert store.hashes_by_sequence({0, -1}) == {}


def test_a_fork_stops_the_walk_so_ambiguous_positions_fail_closed() -> None:
    # Two events both claim GENESIS as prev -> position 1 is ambiguous.
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE audit_events (prev_hash TEXT, event_hash TEXT)"))
        for event_hash in ("11" * 32, "aa" * 32):
            conn.execute(
                text("INSERT INTO audit_events (prev_hash, event_hash) VALUES (:prev, :hash)"),
                {"prev": GENESIS_HASH, "hash": event_hash},
            )

    assert _store(engine).hashes_by_sequence({1}) == {1: None}
