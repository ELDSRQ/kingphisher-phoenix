from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from kp_workers import program_jobs


class Session:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, error_type, _error, _traceback):
        if error_type is not None:
            self.rollback()

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def test_discovery_failure_is_bounded_and_does_not_escape_maintenance(monkeypatch, capsys) -> None:
    discover = Mock(side_effect=RuntimeError("password=must-not-be-logged"))
    monkeypatch.setattr(program_jobs, "active_adaptive_program_ids", discover)
    create = Mock()
    monkeypatch.setattr(program_jobs, "materialize_next_program_iteration", create)
    ctx = SimpleNamespace(session_factory=Session, audit_store=Mock())

    assert program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC)) == {
        "created": 0,
        "skipped": 0,
        "errored": 1,
    }
    assert not create.called
    assert "password=must-not-be-logged" not in capsys.readouterr().out
    assert discover.call_args.kwargs["limit"] == 500


@pytest.mark.parametrize("failure_at", ("session_open", "materialize", "audit", "commit"))
def test_one_program_failure_does_not_block_the_next(monkeypatch, failure_at) -> None:
    ids = (uuid4(), uuid4())
    discovery, first, second = Session(), Session(), Session()
    calls = iter((discovery, first, second))

    def factory():
        value = next(calls)
        if value is first and failure_at == "session_open":
            raise RuntimeError("cannot open first session")
        return value

    monkeypatch.setattr(program_jobs, "active_adaptive_program_ids", lambda *_a, **_kw: ids)

    def create(session, **_kw):
        if session is first and failure_at == "materialize":
            raise RuntimeError("bad first program")
        return SimpleNamespace(created=True, occurrence=None, adaptation=None)

    monkeypatch.setattr(program_jobs, "materialize_next_program_iteration", create)
    audit = Mock()
    if failure_at == "audit":
        audit.record.side_effect = (RuntimeError("bad audit"), None)
    if failure_at == "commit":
        first.commit = Mock(side_effect=RuntimeError("commit failed"))
    ctx = SimpleNamespace(session_factory=factory, audit_store=audit)

    result = program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))

    assert result == {"created": 1, "skipped": 0, "errored": 1}
    assert second.committed
    if failure_at != "session_open":
        assert first.rolled_back


def test_stalled_candidates_do_not_consume_the_draft_creation_budget(monkeypatch) -> None:
    ids = tuple(uuid4() for _ in range(110))
    monkeypatch.setattr(program_jobs, "active_adaptive_program_ids", lambda *_a, **_kw: ids)
    calls = 0

    def create(_session, **_kw):
        nonlocal calls
        calls += 1
        return SimpleNamespace(created=calls > 55, occurrence=None, adaptation=None)

    monkeypatch.setattr(program_jobs, "materialize_next_program_iteration", create)
    ctx = SimpleNamespace(session_factory=Session, audit_store=Mock())

    result = program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))

    assert result == {"created": 50, "skipped": 55, "errored": 0}
    assert calls == 105


def test_worker_audit_uses_aggregate_enrollment_without_roster_ids(monkeypatch) -> None:
    monkeypatch.setattr(program_jobs, "active_adaptive_program_ids", lambda *_a, **_kw: (uuid4(),))
    adaptation = SimpleNamespace(
        changes={"content_changed": False},
        enrollment={
            "base_population": 5,
            "enrolled": 3,
            "excluded_opt_out": 1,
            "excluded_scanner_only": 1,
            "excluded_opt_out_ids": ["private-recipient"],
            "excluded_scanner_only_ids": ["private-scanner"],
        },
    )
    monkeypatch.setattr(
        program_jobs,
        "materialize_next_program_iteration",
        lambda *_a, **_kw: SimpleNamespace(
            created=True,
            occurrence=None,
            adaptation=adaptation,
        ),
    )
    audit = Mock()

    program_jobs.maybe_materialize_due_program_iterations(
        SimpleNamespace(session_factory=Session, audit_store=audit), datetime.now(UTC)
    )

    enrollment = audit.record.call_args.kwargs["detail"]["enrollment"]
    assert enrollment == {"base_population": 5, "enrolled": 3, "excluded_opt_out": 1, "excluded_scanner_only": 1}


def test_cyclic_discovery_reaches_ready_program_after_500_stalled_programs(monkeypatch) -> None:
    ids = tuple(sorted((uuid4() for _ in range(501)), key=str))
    seen = []

    def discover(_session, *, limit, after_id):
        tail = tuple(item for item in ids if after_id is None or item > after_id)
        return (tail + tuple(item for item in ids if after_id is not None and item <= after_id))[:limit]

    def create(_session, *, program_id, retention_worker, **_kw):
        assert retention_worker is True
        seen.append(program_id)
        return SimpleNamespace(created=program_id == ids[-1], occurrence=None, adaptation=None)

    monkeypatch.setattr(program_jobs, "active_adaptive_program_ids", discover)
    monkeypatch.setattr(program_jobs, "materialize_next_program_iteration", create)
    ctx = SimpleNamespace(session_factory=Session, audit_store=Mock())
    assert program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))["created"] == 0
    assert program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC))["created"] == 1
    assert seen[500] == ids[-1]
    assert len(seen) == 1000


@pytest.mark.parametrize(
    ("mode", "configured", "actual", "permitted", "identity_query"),
    [
        ("development", "kingphisher", "kingphisher", True, True),
        ("managed", "kingphisher", "kingphisher", False, False),
        ("production", "kingphisher", "kingphisher", False, False),
        ("development", "kp_worker_retention", "kp_worker_retention", False, False),
        ("development", "kingphisher", "kp_worker_retention", False, True),
        (None, "kingphisher", "kingphisher", False, False),
    ],
)
def test_shared_owner_compatibility_requires_explicit_development_url_and_actual_login(
    mode, configured, actual, permitted, identity_query
) -> None:
    session = Mock()
    session.scalar.return_value = actual
    ctx = SimpleNamespace(
        settings=SimpleNamespace(
            runtime_mode=mode, database_url=f"postgresql+psycopg://{configured}:synthetic@localhost/task_test"
        )
    )
    assert program_jobs._development_shared_owner(ctx, session) is permitted
    assert session.scalar.called is identity_query


def test_legacy_owner_identity_query_denial_never_falls_back(monkeypatch) -> None:
    session = Session()
    session.scalar = Mock(side_effect=RuntimeError("denied"))
    ctx = SimpleNamespace(
        settings=SimpleNamespace(
            runtime_mode="development", database_url="postgresql+psycopg://kingphisher:synthetic@localhost/task_test"
        ),
        session_factory=lambda: session,
        audit_store=Mock(),
    )
    create = Mock()
    monkeypatch.setattr(program_jobs, "materialize_next_program_iteration", create)
    assert program_jobs.maybe_materialize_due_program_iterations(ctx, datetime.now(UTC)) == {
        "created": 0,
        "skipped": 0,
        "errored": 1,
    }
    create.assert_not_called()
