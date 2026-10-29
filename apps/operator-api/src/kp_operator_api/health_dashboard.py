"""Operator health + mode-aware capability dashboard (KP-AUD-002/004/016/024).

The two-person IT team needs to diagnose routine outages without a developer.
This read-only endpoint translates raw technical state (migration head, DB/Redis
reachability, worker/topic liveness, AI-provider routing, RoE validity, audit
witness, TLS, backups) into *affected functionality* plus the *next safe action*
and a link to the console workflow that fixes it.

It reuses the existing readiness primitives rather than reimplementing them:

* ``main._database_is_ready`` / ``main._queue_is_ready`` — the same probes
  ``/readyz`` uses (lazy-imported to avoid an import cycle with ``main``).
* ``main._anchor_heartbeat_is_stale`` — the one AUD-003 definition of a stale
  audit anchor, shared with the privileged-mutation gate.
* ``console.runtime_status`` — the 11-role worker roster and PID liveness probe.
* ``JobQueue.queue_stats`` — non-sensitive per-topic depth and oldest-ready age.
* ``app.state.audit_verifier`` — the running audit-chain verification status.
* ``ai_providers`` registry + ``AiGenerationProvider`` + the gateway state file —
  desired (DB) vs active (runtime) generation routing.

Invariants: purely read-only (no state mutation); never returns a raw secret or
a raw exception string; RBAC-gated on VIEW_AGGREGATE exactly like the peer
``/console/status`` route; data that can lag its source is LABELLED ``stale``;
and it is authenticated, so it is not a public enumeration surface.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from kp_authorization.rbac import Capability, Principal
from kp_contracts.queue import AUDIT_ANCHOR_HEARTBEAT_KEY  # noqa: F401  (documents the heartbeat source)
from kp_database.models import AiGenerationProvider, RulesOfEngagement
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api import ai_providers as provider_registry
from kp_operator_api.auth import require_capability
from kp_operator_api.console.ai_providers import _STATE_FILENAME
from kp_operator_api.console.runtime_status import (
    LOCAL_WORKER_ROLES,
    _process_alive,
    _run_dir,
    _worker_pid_path,
)

router = APIRouter(prefix="/api/v1/console", tags=["console"])

#: Four plain-language capability states the console view renders.
State = Literal["available", "configured_unverified", "unavailable", "production_blocked"]
Severity = Literal["ok", "info", "warning", "critical"]

#: Worker role -> queue topic. Mirrors ``apps/workers/kp_workers.__main__.WORKERS``
#: (operator-api cannot import the worker application). A role absent from this
#: map has no queue topic (a background/integration role) and reports presence
#: from its supervisor PID alone. Keep aligned with that registry and with
#: ``runtime_status.LOCAL_WORKER_ROLES``.
_ROLE_TOPICS: dict[str, str] = {
    "audit-anchor": "audit-anchor",
    "ingestion": "ingest",
    "generation": "generate",
    "delivery": "deliver",
    "retention": "retention",
    "mailbox": "mailbox",
    "reply-mailbox": "reply-mailbox",
    "reminder": "remind",
    "alert": "alert",
    "directory": "directory",
    "curation": "curate",
}

#: Human-readable "what this role does" so an operator reads affected
#: functionality, not an internal worker name.
_ROLE_CAPABILITY: dict[str, str] = {
    "audit-anchor": "Tamper-evident audit anchoring",
    "ingestion": "Threat-feed ingestion",
    "generation": "Phishing-simulation content generation",
    "delivery": "Campaign email delivery",
    "retention": "Data-retention enforcement",
    "mailbox": "Reported-phish mailbox ingestion",
    "reply-mailbox": "Reply ingestion",
    "reminder": "Training reminders",
    "alert": "Operator alerts & digests",
    "directory": "Directory / recipient sync",
    "curation": "Forwarded-phish auto-curation",
}

#: A queue is slow, not broken, until its oldest ready message passes this age.
#: Past it the capability is degraded (work is backing up) but still "available".
_OLDEST_READY_WARN_SECONDS = 15 * 60.0

#: An RoE within this window of its end is flagged so a campaign is not blocked
#: mid-flight by a silently lapsed authorization.
_ROE_EXPIRY_WARN_SECONDS = 7 * 24 * 60 * 60.0


class HealthItem(BaseModel):
    """One capability's translated state. Never carries a secret or a raw error."""

    id: str
    capability: str
    state: State
    severity: Severity
    reason: str
    safe_action: str
    #: Console route hash the operator opens to fix it (e.g. "#settings").
    workflow: str | None = None
    #: When the evidence was observed (live probe) or the source timestamp
    #: (e.g. the last audit-anchor heartbeat). Always tz-aware ISO-8601 UTC.
    evidence_timestamp: str
    #: True when this evidence lags its source and must be read as possibly out
    #: of date (e.g. a stale audit anchor), never silently.
    stale: bool = False


class HealthDashboard(BaseModel):
    generated_at: str
    runtime_control: Literal["local_supervisor", "azure_control_plane"]
    #: Worst state across all items, for the view's headline banner.
    overall_state: State
    items: list[HealthItem]


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return normalized.isoformat()


# --- individual aggregators ------------------------------------------------
# Each returns one HealthItem. None of them mutate anything, and every one
# collapses an exception to a safe, bounded state rather than leaking it.


def _database_item(request: Request, *, now: datetime, managed: bool) -> HealthItem:
    from kp_operator_api.main import _database_is_ready

    stamp = _iso(now) or ""
    if managed:
        return HealthItem(
            id="database",
            capability="Application database",
            state="configured_unverified",
            severity="info",
            reason="PostgreSQL is a managed Azure service; this console cannot probe it directly.",
            safe_action="Check the database health in the Azure Container Apps control plane.",
            workflow="#azure-deployment",
            evidence_timestamp=stamp,
        )
    try:
        primary_ok = _database_is_ready(request.app.state.db_engine)
        audit_ok = primary_ok and _database_is_ready(request.app.state.audit_engine)
    except Exception:  # noqa: BLE001 - never surface a driver error to the operator
        primary_ok = audit_ok = False
    if primary_ok and audit_ok:
        return HealthItem(
            id="database",
            capability="Application database",
            state="available",
            severity="ok",
            reason="The application and audit databases both answered a trivial query.",
            safe_action="No action needed.",
            evidence_timestamp=stamp,
        )
    which = "application" if not primary_ok else "audit"
    return HealthItem(
        id="database",
        capability="Application database",
        state="unavailable",
        severity="critical",
        reason=f"The {which} database did not answer a health query, so nothing that reads or writes data will work.",
        safe_action="Confirm the database container is running, then use Settings to restart services.",
        workflow="#settings",
        evidence_timestamp=stamp,
    )


def _redis_item(request: Request, *, now: datetime, managed: bool) -> HealthItem:
    from kp_operator_api.main import _queue_is_ready

    stamp = _iso(now) or ""
    if managed:
        return HealthItem(
            id="redis",
            capability="Background job queue",
            state="configured_unverified",
            severity="info",
            reason="Redis is a managed Azure service; this console cannot probe it directly.",
            safe_action="Check the cache health in the Azure Container Apps control plane.",
            workflow="#azure-deployment",
            evidence_timestamp=stamp,
        )
    try:
        ready = _queue_is_ready(request.app.state.queue)
    except Exception:  # noqa: BLE001
        ready = False
    if ready:
        return HealthItem(
            id="redis",
            capability="Background job queue",
            state="available",
            severity="ok",
            reason="Redis answered a ping; sending, ingestion and reminders can be queued.",
            safe_action="No action needed.",
            evidence_timestamp=stamp,
        )
    return HealthItem(
        id="redis",
        capability="Background job queue",
        state="unavailable",
        severity="critical",
        reason="Redis did not answer; campaigns cannot be queued and no worker can pick up jobs.",
        safe_action="Confirm the Redis container is running, then use Settings to restart services.",
        workflow="#settings",
        evidence_timestamp=stamp,
    )


def _migration_item(request: Request, *, now: datetime, managed: bool) -> HealthItem:
    """Compare the DB's applied Alembic revision to the expected head on disk."""
    stamp = _iso(now) or ""
    expected = _expected_migration_head()
    current = _current_migration_revision(request)
    if expected is None:
        return HealthItem(
            id="migration",
            capability="Database schema version",
            state="configured_unverified",
            severity="info",
            reason="The expected schema version could not be read from the packaged migrations.",
            safe_action="Run the migration/qualification job to confirm the schema is current.",
            workflow="#settings",
            evidence_timestamp=stamp,
        )
    if current is None:
        return HealthItem(
            id="migration",
            capability="Database schema version",
            state="unavailable",
            severity="critical",
            reason="The database did not report an applied schema version, so it may be unreachable or uninitialised.",
            safe_action="Confirm the database is up and the migration job has run.",
            workflow="#settings",
            evidence_timestamp=stamp,
        )
    if current == expected:
        return HealthItem(
            id="migration",
            capability="Database schema version",
            state="available",
            severity="ok",
            reason="The database schema is at the expected version.",
            safe_action="No action needed.",
            evidence_timestamp=stamp,
        )
    return HealthItem(
        id="migration",
        capability="Database schema version",
        state="production_blocked",
        severity="critical",
        reason="The database schema is not at the version this build expects; features may behave unpredictably.",
        safe_action="Run the migration job to bring the schema to the expected head before using the platform.",
        workflow="#azure-deployment" if managed else "#settings",
        evidence_timestamp=stamp,
    )


def _expected_migration_head() -> str | None:
    try:
        import kp_database
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        ini_path = Path(kp_database.__file__).resolve().parents[2] / "alembic.ini"
        if not ini_path.is_file():
            return None
        config = Config(str(ini_path))
        head = ScriptDirectory.from_config(config).get_current_head()
        return head
    except Exception:  # noqa: BLE001 - a packaging quirk must not break the dashboard
        return None


def _current_migration_revision(request: Request) -> str | None:
    try:
        from sqlalchemy import text

        with request.app.state.db_engine.connect() as connection:
            value = connection.scalar(text("SELECT version_num FROM alembic_version"))
        return str(value) if value is not None else None
    except Exception:  # noqa: BLE001 - DB down / table missing degrades gracefully
        return None


def _worker_items(request: Request, *, now: datetime, managed: bool) -> list[HealthItem]:
    stamp = _iso(now) or ""
    settings = request.app.state.settings
    if managed:
        return [
            HealthItem(
                id=f"worker.{role}",
                capability=_ROLE_CAPABILITY.get(role, role),
                state="configured_unverified",
                severity="info",
                reason="Workers run as separate Azure Container Apps revisions; this console cannot probe them.",
                safe_action="Check the worker revision health in the Azure control plane.",
                workflow="#azure-deployment",
                evidence_timestamp=stamp,
            )
            for role in LOCAL_WORKER_ROLES
        ]

    queue = request.app.state.queue
    items: list[HealthItem] = []
    for role in LOCAL_WORKER_ROLES:
        alive = _process_alive(_worker_pid_path(settings, role))
        topic = _ROLE_TOPICS.get(role)
        oldest_age = _oldest_ready_age(queue, topic) if topic is not None else None
        items.append(_worker_item(role, alive=alive, oldest_age=oldest_age, stamp=stamp))
    return items


def _worker_item(role: str, *, alive: bool, oldest_age: float | None, stamp: str) -> HealthItem:
    capability = _ROLE_CAPABILITY.get(role, role)
    if not alive:
        return HealthItem(
            id=f"worker.{role}",
            capability=capability,
            state="unavailable",
            severity="critical",
            reason=f"The {role} worker process is not running, so {capability.lower()} has stopped.",
            safe_action="Use Settings to restart services; if it will not stay up, check the worker logs.",
            workflow="#settings",
            evidence_timestamp=stamp,
        )
    if oldest_age is not None and oldest_age > _OLDEST_READY_WARN_SECONDS:
        minutes = int(oldest_age // 60)
        return HealthItem(
            id=f"worker.{role}",
            capability=capability,
            state="available",
            severity="warning",
            reason=f"The {role} worker is running but its oldest queued job is ~{minutes} min old; work is backing up.",
            safe_action="Give it time to drain; if the backlog keeps growing, check the worker and its dependencies.",
            workflow="#queues",
            evidence_timestamp=stamp,
        )
    return HealthItem(
        id=f"worker.{role}",
        capability=capability,
        state="available",
        severity="ok",
        reason=f"The {role} worker is running and its queue is current.",
        safe_action="No action needed.",
        evidence_timestamp=stamp,
    )


def _oldest_ready_age(queue: Any, topic: str) -> float | None:
    try:
        stats = queue.queue_stats(topic)
    except Exception:  # noqa: BLE001 - a Redis blip must not break one worker row
        return None
    age = stats.get("oldest_ready_age_seconds")
    return float(age) if isinstance(age, int | float) else None


def _ai_provider_item(request: Request, session: Session | None, *, now: datetime, managed: bool) -> HealthItem:
    """Desired (DB active provider) vs active (the gateway's runtime state file)."""
    stamp = _iso(now) or ""
    if managed:
        return HealthItem(
            id="ai_provider",
            capability="AI generation provider",
            state="configured_unverified",
            severity="info",
            reason="The generation model is configured by the managed deployment, not from this console.",
            safe_action="No action needed from this console.",
            workflow="#azure-deployment",
            evidence_timestamp=stamp,
        )
    desired = _desired_provider(session)
    runtime = _runtime_provider(request.app.state.settings)
    if desired == provider_registry.LOCAL and runtime is None:
        return HealthItem(
            id="ai_provider",
            capability="AI generation provider",
            state="available",
            severity="ok",
            reason="Generation uses the on-prem local model; no content leaves the network.",
            safe_action="No action needed.",
            workflow="#modelcontrol",
            evidence_timestamp=stamp,
        )
    if desired != provider_registry.LOCAL and runtime == desired:
        return HealthItem(
            id="ai_provider",
            capability="AI generation provider",
            state="available",
            severity="info",
            reason=f"Generation is routed to the hosted provider '{desired}', which sends content to that third party.",
            safe_action="No action needed; switch back to the local model in AI model if that egress is not wanted.",
            workflow="#modelcontrol",
            evidence_timestamp=stamp,
        )
    return HealthItem(
        id="ai_provider",
        capability="AI generation provider",
        state="configured_unverified",
        severity="warning",
        reason=(
            "The selected generation provider and the running gateway's provider do not match; "
            "a restart to apply the selection may still be pending."
        ),
        safe_action="Restart services from Settings, then confirm the active provider in AI model.",
        workflow="#settings",
        evidence_timestamp=stamp,
    )


def _desired_provider(session: Session | None) -> str:
    if session is None:
        return provider_registry.LOCAL
    try:
        rows = session.scalars(select(AiGenerationProvider)).all()
    except Exception:  # noqa: BLE001
        return provider_registry.LOCAL
    for row in rows:
        if row.is_active:
            return str(row.provider)
    return provider_registry.LOCAL


def _runtime_provider(settings: Any) -> str | None:
    """Read only the provider name from the gateway state file; never the key."""
    try:
        path = _run_dir(settings) / _STATE_FILENAME
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, ValueError):
        return None
    provider = payload.get("provider") if isinstance(payload, dict) else None
    return str(provider) if isinstance(provider, str) and provider else None


def _roe_item(session: Session | None, *, now: datetime) -> HealthItem:
    stamp = _iso(now) or ""
    if session is None:
        return HealthItem(
            id="authorization_roe",
            capability="Campaign authorization (Rules of Engagement)",
            state="unavailable",
            severity="warning",
            reason="The signed authorizations could not be read because the database is unreachable.",
            safe_action="Restore the database, then review Domains & RoE.",
            workflow="#sending",
            evidence_timestamp=stamp,
        )
    try:
        rows = list(session.scalars(select(RulesOfEngagement)))
    except Exception:  # noqa: BLE001
        rows = []
    active_ends = [
        row.window_end
        for row in rows
        if row.revoked_at is None and row.window_end is not None and _as_utc(row.window_end) > now
    ]
    if not active_ends:
        return HealthItem(
            id="authorization_roe",
            capability="Campaign authorization (Rules of Engagement)",
            state="production_blocked",
            severity="warning",
            reason="No signed Rules of Engagement are currently in force; new campaigns cannot be authorized to send.",
            safe_action="Sign a Rules-of-Engagement in Domains & RoE before launching a campaign.",
            workflow="#sending",
            evidence_timestamp=stamp,
        )
    latest_end = max(_as_utc(end) for end in active_ends)
    remaining = (latest_end - now).total_seconds()
    if remaining <= _ROE_EXPIRY_WARN_SECONDS:
        days = max(0, int(remaining // 86400))
        return HealthItem(
            id="authorization_roe",
            capability="Campaign authorization (Rules of Engagement)",
            state="available",
            severity="warning",
            reason=f"The current authorization expires in ~{days} day(s); campaigns are blocked once it lapses.",
            safe_action="Sign a renewed Rules-of-Engagement in Domains & RoE before the window ends.",
            workflow="#sending",
            evidence_timestamp=_iso(latest_end) or stamp,
        )
    return HealthItem(
        id="authorization_roe",
        capability="Campaign authorization (Rules of Engagement)",
        state="available",
        severity="ok",
        reason="A signed Rules-of-Engagement is in force, so authorized campaigns may send.",
        safe_action="No action needed.",
        workflow="#sending",
        evidence_timestamp=_iso(latest_end) or stamp,
    )


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _audit_witness_item(request: Request, *, now: datetime) -> HealthItem:
    from kp_operator_api.main import _anchor_heartbeat_is_stale

    verifier = getattr(request.app.state, "audit_verifier", None)
    status = getattr(verifier, "status", "pending") if verifier is not None else "pending"
    try:
        anchor_at = request.app.state.last_successful_anchor_at()
    except Exception:  # noqa: BLE001
        anchor_at = None
    interval = request.app.state.audit_anchor_gate_interval_seconds
    stale = _anchor_heartbeat_is_stale(anchor_at, interval, now=now)
    anchor_stamp = _iso(anchor_at) or _iso(now) or ""

    if status in ("failing", "error"):
        return HealthItem(
            id="audit_witness",
            capability="Tamper-evident audit trail",
            state="production_blocked",
            severity="critical",
            reason="Audit-chain verification is reporting a problem; privileged changes are blocked until it clears.",
            safe_action="Open Audit to run verification and review; do not force changes.",
            workflow="#audit",
            evidence_timestamp=_iso(now) or "",
        )
    if stale:
        return HealthItem(
            id="audit_witness",
            capability="Tamper-evident audit trail",
            state="production_blocked",
            severity="critical",
            reason="The audit anchor has not advanced within its expected window; anchoring may have stalled.",
            safe_action="Check the audit-anchor worker; privileged changes stay gated until it recovers.",
            workflow="#audit",
            evidence_timestamp=anchor_stamp,
            stale=True,
        )
    if status != "ok":
        return HealthItem(
            id="audit_witness",
            capability="Tamper-evident audit trail",
            state="configured_unverified",
            severity="info",
            reason="Audit-chain verification has not completed its first pass yet.",
            safe_action="Give verification a moment; open Audit to run it on demand.",
            workflow="#audit",
            evidence_timestamp=_iso(now) or "",
        )
    return HealthItem(
        id="audit_witness",
        capability="Tamper-evident audit trail",
        state="available",
        severity="ok",
        reason="The audit chain verified intact and the anchor is current.",
        safe_action="No action needed.",
        workflow="#audit",
        evidence_timestamp=anchor_stamp,
    )


def _tls_item(request: Request, *, now: datetime, managed: bool) -> HealthItem:
    """Posture of the operator origin's transport, not a live certificate probe."""
    stamp = _iso(now) or ""
    origin = str(getattr(request.app.state, "trusted_operator_origin", "") or "")
    if managed:
        return HealthItem(
            id="tls_cert",
            capability="Transport security (TLS)",
            state="configured_unverified",
            severity="info",
            reason="TLS termination and the certificate are managed by Azure Container Apps.",
            safe_action="Confirm the certificate and its expiry in the Azure control plane.",
            workflow="#azure-deployment",
            evidence_timestamp=stamp,
        )
    if origin.startswith("https://"):
        return HealthItem(
            id="tls_cert",
            capability="Transport security (TLS)",
            state="configured_unverified",
            severity="info",
            reason="The operator origin is HTTPS; this console cannot verify the certificate's expiry from here.",
            safe_action="Confirm the certificate and renewal with your reverse proxy / terminator before production.",
            workflow="#settings",
            evidence_timestamp=stamp,
        )
    return HealthItem(
        id="tls_cert",
        capability="Transport security (TLS)",
        state="production_blocked",
        severity="warning",
        reason="The operator origin is plain HTTP; TLS must terminate in front of it before production use.",
        safe_action="Put the console behind an HTTPS reverse proxy before any production campaign.",
        workflow="#settings",
        evidence_timestamp=stamp,
    )


def _backup_item(request: Request, *, now: datetime, managed: bool) -> HealthItem:
    stamp = _iso(now) or ""
    if managed:
        return HealthItem(
            id="backup",
            capability="Backups / recovery",
            state="configured_unverified",
            severity="info",
            reason="Backups are handled by the managed Azure database service, not this console.",
            safe_action="Confirm the backup/restore policy in the Azure control plane.",
            workflow="#azure-deployment",
            evidence_timestamp=stamp,
        )
    newest = _newest_backup_mtime(request.app.state.settings)
    if newest is None:
        return HealthItem(
            id="backup",
            capability="Backups / recovery",
            state="configured_unverified",
            severity="warning",
            reason="No recovery snapshot was found in the expected location, so a restore point cannot be confirmed.",
            safe_action="Confirm scheduled backups are running and writing to data/recovery.",
            workflow="#settings",
            evidence_timestamp=stamp,
        )
    age_days = (now - newest).total_seconds() / 86400
    if age_days > 1.0:
        return HealthItem(
            id="backup",
            capability="Backups / recovery",
            state="available",
            severity="warning",
            reason=f"The most recent recovery snapshot is about {int(age_days)} day(s) old.",
            safe_action="Confirm the backup schedule is running if a daily restore point is expected.",
            workflow="#settings",
            evidence_timestamp=_iso(newest) or stamp,
            stale=True,
        )
    return HealthItem(
        id="backup",
        capability="Backups / recovery",
        state="available",
        severity="ok",
        reason="A recent recovery snapshot is present.",
        safe_action="No action needed.",
        workflow="#settings",
        evidence_timestamp=_iso(newest) or stamp,
    )


def _newest_backup_mtime(settings: Any) -> datetime | None:
    try:
        recovery_dir = _run_dir(settings).parent / "recovery"
        if not recovery_dir.is_dir():
            return None
        newest: float | None = None
        for entry in recovery_dir.iterdir():
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest:
                newest = mtime
        return datetime.fromtimestamp(newest, tz=UTC) if newest is not None else None
    except OSError:
        return None


# --- overall ---------------------------------------------------------------

_STATE_RANK: dict[State, int] = {
    "available": 0,
    "configured_unverified": 1,
    "production_blocked": 2,
    "unavailable": 3,
}


def _overall_state(items: list[HealthItem]) -> State:
    worst: State = "available"
    for item in items:
        if _STATE_RANK[item.state] > _STATE_RANK[worst]:
            worst = item.state
    return worst


@router.get("/health", response_model=HealthDashboard)
def get_health_dashboard(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> HealthDashboard:
    """Aggregate every operator-health signal into affected-functionality items.

    Read-only: it probes and reads state but mutates nothing. The DB session is
    opened defensively so a database outage degrades the DB-backed items to a
    safe state instead of failing the whole dashboard.
    """
    now = _now()
    settings = request.app.state.settings
    managed = bool(settings.config_is_managed)

    session: Session | None = None
    try:
        session = request.app.state.session_factory()
        items: list[HealthItem] = [
            _migration_item(request, now=now, managed=managed),
            _database_item(request, now=now, managed=managed),
            _redis_item(request, now=now, managed=managed),
            *_worker_items(request, now=now, managed=managed),
            _ai_provider_item(request, session, now=now, managed=managed),
            _roe_item(session, now=now),
            _audit_witness_item(request, now=now),
            _tls_item(request, now=now, managed=managed),
            _backup_item(request, now=now, managed=managed),
        ]
    finally:
        if session is not None:
            session.close()

    return HealthDashboard(
        generated_at=_iso(now) or "",
        runtime_control="azure_control_plane" if managed else "local_supervisor",
        overall_state=_overall_state(items),
        items=items,
    )
