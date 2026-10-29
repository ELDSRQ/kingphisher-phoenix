"""W4-03: deterministic, explainable adaptation + enrollment decision logic.

These are pure-function tests (no database): they pin down the safety-critical
decisions directly — a scanner-only recipient is never enrolled, opt-out is
honored, and the difficulty adaptation is deterministic and records the signal
that drove each change.
"""

from __future__ import annotations

import uuid

from kp_database.program_service import (
    MAX_ADAPTIVE_LEVEL,
    MIN_ADAPTIVE_LEVEL,
    PriorIterationSignals,
    plan_iteration_adaptation,
    resolve_iteration_enrollment,
)


def _ids(n: int) -> list[uuid.UUID]:
    # Deterministic, distinct ids so sorted expectations are stable.
    return [uuid.UUID(int=i) for i in range(1, n + 1)]


def test_enrollment_never_enrolls_scanner_only() -> None:
    a, b, c, d = _ids(4)
    decision = resolve_iteration_enrollment({a, b, c, d}, opt_out_ids=set(), scanner_only_ids={c})
    assert c not in decision.enrolled
    assert decision.excluded_scanner_only == (c,)
    assert set(decision.enrolled) == {a, b, d}


def test_enrollment_honors_opt_out() -> None:
    a, b, c = _ids(3)
    decision = resolve_iteration_enrollment({a, b, c}, opt_out_ids={b}, scanner_only_ids=set())
    assert b not in decision.enrolled
    assert decision.excluded_opt_out == (b,)
    assert set(decision.enrolled) == {a, c}


def test_enrollment_scanner_reason_wins_when_both() -> None:
    (a,) = _ids(1)
    decision = resolve_iteration_enrollment({a}, opt_out_ids={a}, scanner_only_ids={a})
    assert decision.enrolled == ()
    assert decision.excluded_scanner_only == (a,)
    # Not double-counted under opt-out: the stricter no-scanner reason wins.
    assert decision.excluded_opt_out == ()


def test_enrollment_ignores_ids_outside_base_and_is_sorted() -> None:
    a, b, c, d = _ids(4)
    decision = resolve_iteration_enrollment({b, a}, opt_out_ids={c}, scanner_only_ids={d})
    assert decision.enrolled == (a, b)  # sorted, and c/d were never in the base
    assert decision.excluded_opt_out == ()
    assert decision.excluded_scanner_only == ()


def test_adaptation_high_susceptibility_eases_difficulty() -> None:
    signals = PriorIterationSignals(accepted=10, human_clicked=4, automation_suspected_clicked=0, reported=1)
    plan = plan_iteration_adaptation(3, signals)
    assert plan.difficulty_delta == -1
    assert plan.next_level == 2
    assert any(driver["signal"] == "human_click_rate" for driver in plan.drivers)


def test_adaptation_reports_without_clicks_escalates() -> None:
    signals = PriorIterationSignals(accepted=10, human_clicked=0, automation_suspected_clicked=0, reported=3)
    plan = plan_iteration_adaptation(2, signals)
    assert plan.difficulty_delta == 1
    assert plan.next_level == 3
    assert any(driver["signal"] == "reported_without_clicks" for driver in plan.drivers)


def test_adaptation_steady_between_thresholds() -> None:
    signals = PriorIterationSignals(accepted=10, human_clicked=1, automation_suspected_clicked=0, reported=0)
    plan = plan_iteration_adaptation(3, signals)
    assert plan.difficulty_delta == 0
    assert plan.next_level == 3
    assert any(driver["signal"] == "steady" for driver in plan.drivers)


def test_adaptation_clamps_to_bounds() -> None:
    hot = PriorIterationSignals(accepted=10, human_clicked=9, automation_suspected_clicked=0, reported=0)
    at_floor = plan_iteration_adaptation(MIN_ADAPTIVE_LEVEL, hot)
    assert at_floor.next_level == MIN_ADAPTIVE_LEVEL
    assert at_floor.difficulty_delta == 0  # cannot go below the floor

    resilient = PriorIterationSignals(accepted=10, human_clicked=0, automation_suspected_clicked=0, reported=5)
    at_ceiling = plan_iteration_adaptation(MAX_ADAPTIVE_LEVEL, resilient)
    assert at_ceiling.next_level == MAX_ADAPTIVE_LEVEL
    assert at_ceiling.difficulty_delta == 0  # cannot exceed the ceiling


def test_adaptation_automation_clicks_do_not_drive_difficulty() -> None:
    # Only suspected-automation clicks, no human signal: difficulty holds steady
    # and the automation signal is recorded as an exclusion driver, not behavior.
    signals = PriorIterationSignals(accepted=10, human_clicked=0, automation_suspected_clicked=7, reported=0)
    plan = plan_iteration_adaptation(3, signals)
    assert plan.difficulty_delta == 0
    assert signals.human_click_rate == 0.0
    assert any(driver["signal"] == "automation_suspected_clicked" for driver in plan.drivers)


def test_adaptation_is_deterministic() -> None:
    signals = PriorIterationSignals(accepted=12, human_clicked=5, automation_suspected_clicked=2, reported=1)
    assert plan_iteration_adaptation(4, signals) == plan_iteration_adaptation(4, signals)
