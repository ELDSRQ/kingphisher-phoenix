"""W4-03: adaptive campaign-program iteration generation.

A periodic, best-effort maintenance tick that materializes the next DRAFT
iteration of each ACTIVE adaptive program once its prior iteration has
completed. It is deliberately NOT an autonomous launcher:

* Every iteration it creates is a DRAFT campaign with no approval, launch gate,
  or RoE binding of its own. It must clear the normal approval + RoE + schedule
  gates like any hand-made campaign before it could ever send. This worker never
  approves, schedules, or sends, and the offensive send capability is never
  auto-armed by it (project invariant D-022).
* Generation is idempotent across restarts and replicas: the service locks the
  program row and the ``(program, occurrence)`` / ``(program, iteration)`` unique
  keys are the final backstop, so re-running this tick never double-generates.
* Enrollment honors opt-out/suppression and never enrolls a scanner-only
  (suspected-automation) recipient.

It is driven from the retention role's existing cadence (see the supervisor),
mirroring how the weekly digest piggy-backs that tick; it owns no queue topic
and publishes no messages.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from kp_database.program_service import (
    active_adaptive_program_ids,
    materialize_next_program_iteration,
)

if TYPE_CHECKING:
    from kp_workers.jobs import WorkerContext

#: Upper bound on iterations generated per tick, so a backlog cannot turn one
#: maintenance pass into an unbounded unit of work.
_MAX_ITERATIONS_PER_TICK = 50


def maybe_materialize_due_program_iterations(ctx: WorkerContext, now: datetime) -> dict[str, int]:
    """Generate at most one due DRAFT iteration per active adaptive program.

    Each program is handled in its own transaction so a single failure never
    blocks the others, and a poisoned transaction is rolled back rather than
    retried in place. Returns bounded counters for observability.
    """

    created = 0
    skipped = 0
    errored = 0
    with ctx.session_factory() as session:
        program_ids = active_adaptive_program_ids(session)
    for program_id in program_ids:
        if created >= _MAX_ITERATIONS_PER_TICK:
            break
        with ctx.session_factory() as session:
            try:
                result = materialize_next_program_iteration(session, program_id=program_id, now=now)
                if not result.created:
                    skipped += 1
                    session.rollback()
                    continue
                ctx.audit_store.record(
                    session=session,
                    actor="worker:program-iteration",
                    action="campaign_program.iteration.materialize",
                    object_type="campaign_program",
                    object_id=str(program_id),
                    detail={
                        "iteration_number": result.occurrence.occurrence_number if result.occurrence else None,
                        "iteration_campaign_id": (str(result.occurrence.campaign_id) if result.occurrence else None),
                        "state": "draft",
                        "adaptation": result.adaptation.changes if result.adaptation else None,
                        "enrollment": result.adaptation.enrollment if result.adaptation else None,
                    },
                )
                session.commit()
                created += 1
            except Exception:
                errored += 1
                session.rollback()
    return {"created": created, "skipped": skipped, "errored": errored}
