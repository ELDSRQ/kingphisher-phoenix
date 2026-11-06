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
from kp_telemetry.logging import get_logger
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from kp_workers.jobs import WorkerContext

#: Upper bound on iterations generated per tick, so a backlog cannot turn one
#: maintenance pass into an unbounded unit of work.
_MAX_ITERATIONS_PER_TICK = 50
_MAX_CANDIDATES_PER_TICK = 500


def _development_shared_owner(ctx: WorkerContext, session: Session) -> bool:
    """Preserve only the explicit legacy development owner configuration.

    A URL alone is not proof of the authenticated login. Managed, production,
    missing settings and mismatched actual identities always use the definer.
    Database errors propagate; denial never triggers a permissive fallback.
    """
    settings = getattr(ctx, "settings", None)
    if getattr(settings, "runtime_mode", None) != "development":
        return False
    configured = getattr(settings, "database_url", None)
    if not isinstance(configured, str):
        return False
    try:
        username = make_url(configured).username
    except (ValueError, TypeError):
        return False
    if username != "kingphisher":
        return False
    return bool(session.scalar(text("SELECT session_user")) == "kingphisher")


def maybe_materialize_due_program_iterations(ctx: WorkerContext, now: datetime) -> dict[str, int]:
    """Generate at most one due DRAFT iteration per active adaptive program.

    Each program is handled in its own transaction so a single failure never
    blocks the others, and a poisoned transaction is rolled back rather than
    retried in place. Returns bounded counters for observability.
    """

    created = 0
    skipped = 0
    errored = 0
    try:
        with ctx.session_factory() as session:
            retention_worker = not _development_shared_owner(ctx, session)
            program_ids = active_adaptive_program_ids(
                session,
                limit=_MAX_CANDIDATES_PER_TICK,
                after_id=getattr(ctx, "_adaptive_program_cursor", None),
            )
    except Exception as error:
        get_logger(__name__).warning("adaptive_program_discovery_failed", error_type=type(error).__name__[:64])
        return {"created": 0, "skipped": 0, "errored": 1}
    for program_id in program_ids[:_MAX_CANDIDATES_PER_TICK]:
        if created >= _MAX_ITERATIONS_PER_TICK:
            break
        # Advance for every attempted candidate, including stalled and failed
        # programs. A later tick wraps at the end of this stable UUID ordering.
        # The cursor is process-local and contains no roster or review data.
        setattr(ctx, "_adaptive_program_cursor", program_id)  # noqa: B010 - private cadence state, not WorkerContext API
        try:
            with ctx.session_factory() as session:
                result = materialize_next_program_iteration(
                    session, program_id=program_id, now=now, retention_worker=retention_worker
                )
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
                        "enrollment": {
                            key: result.adaptation.enrollment.get(key, 0)
                            for key in ("base_population", "enrolled", "excluded_opt_out", "excluded_scanner_only")
                        }
                        if result.adaptation
                        else None,
                    },
                )
                session.commit()
                created += 1
        except Exception as error:
            errored += 1
            get_logger(__name__).warning("adaptive_program_iteration_failed", error_type=type(error).__name__[:64])
    return {"created": created, "skipped": skipped, "errored": errored}
