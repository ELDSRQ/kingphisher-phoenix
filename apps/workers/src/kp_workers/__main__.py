"""Worker entry point for one role or the managed multi-role supervisor."""

from __future__ import annotations

import argparse
import os
import signal
import threading
from contextlib import ExitStack

from kp_contracts.queue import JobQueue
from kp_database.audit_store import AuditStore
from kp_database.models import CipherText
from kp_database.session import create_db_engine, make_session_factory
from kp_telemetry.logging import configure_logging

from kp_workers import jobs
from kp_workers.audit_anchor_jobs import process_audit_anchor
from kp_workers.config import WorkerSettings
from kp_workers.supervisor import RoleSpec, WorkerSupervisor

WORKERS = {
    "audit-anchor": ("audit-anchor", process_audit_anchor),
    "ingestion": ("ingest", jobs.process_ingestion),
    "generation": ("generate", jobs.process_generation),
    "delivery": ("deliver", jobs.process_delivery),
    "retention": ("retention", jobs.process_retention),
    "mailbox": ("mailbox", jobs.process_mailbox),
    "reminder": ("remind", jobs.process_reminder),
    "alert": ("alert", jobs.process_alert),
    "directory": ("directory", jobs.process_directory_sync),
}


def _context(settings: WorkerSettings, queue: JobQueue) -> jobs.WorkerContext:
    resources = ExitStack()
    try:
        engine = create_db_engine(settings.database_url)
        resources.callback(engine.dispose)
        # The anchor is a verifier, not an audit dispatcher. Its dedicated primary
        # login has only audit-chain SELECT plus two read-only verification
        # functions, so do not give that context the shared audit_writer DSN.
        if settings.worker_name == "audit-anchor":
            audit_engine = engine
        else:
            audit_engine = create_db_engine(settings.audit_database_url)
            resources.callback(audit_engine.dispose)
        session_factory = make_session_factory(engine)
        # Workers stage caller-attributed intent; only the database dispatcher can
        # turn committed intent into signed audit evidence.
        legacy_audit_key = settings.require_hmac() if settings.audit_hmac_key else None
        audit_store = AuditStore(audit_engine, legacy_audit_key)
        if settings.worker_name != "audit-anchor":
            audit_store.bind_intent_engine(engine)
        ciphertext_key_id, ciphertext_key, ciphertext_prior_keys = settings.require_cipher_keyring()
        CipherText.configure_keyring(ciphertext_key_id, ciphertext_key, ciphertext_prior_keys)
    except Exception:
        resources.close()
        raise
    return jobs.WorkerContext(
        settings,
        session_factory,
        audit_store,
        queue,
        close_callbacks=(resources.close,),
    )


def _enabled_roles(name: str) -> tuple[str, ...]:
    if name != "supervise":
        return (name,)
    configured = os.environ.get("KP_WORKER_ROLES", "")
    roles = tuple(dict.fromkeys(role.strip().lower() for role in configured.split(",") if role.strip()))
    if not roles:
        raise RuntimeError("KP_WORKER_ROLES must list at least one role in supervise mode")
    unknown = sorted(set(roles) - WORKERS.keys())
    if unknown:
        raise RuntimeError(f"KP_WORKER_ROLES contains unknown roles: {', '.join(unknown)}")
    return roles


def _role_settings(base: WorkerSettings, role: str) -> WorkerSettings:
    database_variable = f"KP_WORKER_DATABASE_URL_{role.upper().replace('-', '_')}"
    database_url = os.environ.get(database_variable)
    if base.worker_name == "supervise" and not database_url:
        raise RuntimeError(f"{database_variable} is required for supervised role {role}")
    values = base.model_dump(exclude={"worker_name", "database_url"})
    return WorkerSettings(
        **values,
        worker_name=role,
        database_url=database_url or base.database_url,
    )


def _install_shutdown_handlers(stop_event: threading.Event) -> None:
    def request_shutdown(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)


def main() -> None:
    parser = argparse.ArgumentParser(prog="kp-worker")
    parser.add_argument("name", choices=[*sorted(WORKERS), "supervise"])
    args = parser.parse_args()

    base_settings = WorkerSettings(worker_name=args.name)
    configure_logging(level=base_settings.log_level)
    roles = _enabled_roles(args.name)
    with ExitStack() as resources:
        queue = JobQueue(base_settings.redis_url)
        resources.callback(queue.close)
        role_specs: dict[str, RoleSpec] = {}
        for role in roles:
            settings = _role_settings(base_settings, role)
            topic, process = WORKERS[role]
            context = _context(settings, queue)
            resources.callback(context.close)
            role_specs[role] = RoleSpec(role, topic, process, context)

        stop_event = threading.Event()
        _install_shutdown_handlers(stop_event)
        WorkerSupervisor(role_specs).run(stop_event)


if __name__ == "__main__":
    main()
