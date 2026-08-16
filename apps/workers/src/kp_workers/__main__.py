"""Worker entry point: `kp-worker <name>` where name is one of
ingestion, generation, delivery, retention, mailbox, reminder, directory."""

from __future__ import annotations

import argparse
import sys

from kp_contracts.queue import JobQueue
from kp_database.audit_store import AuditStore
from kp_database.models import CipherText
from kp_database.session import create_db_engine, make_session_factory
from kp_telemetry.logging import configure_logging

from kp_workers import jobs
from kp_workers.config import WorkerSettings

WORKERS = {
    "ingestion": ("ingest", jobs.process_ingestion),
    "generation": ("generate", jobs.process_generation),
    "delivery": ("deliver", jobs.process_delivery),
    "retention": ("retention", jobs.process_retention),
    "mailbox": ("mailbox", jobs.process_mailbox),
    "reminder": ("remind", jobs.process_reminder),
    "alert": ("alert", jobs.process_alert),
    "directory": ("directory", jobs.process_directory_sync),
}


def main() -> None:
    parser = argparse.ArgumentParser(prog="kp-worker")
    parser.add_argument("name", choices=sorted(WORKERS))
    args = parser.parse_args()

    settings = WorkerSettings(worker_name=args.name)
    configure_logging(level=settings.log_level)

    engine = create_db_engine(settings.database_url)
    audit_engine = create_db_engine(settings.audit_database_url)
    session_factory = make_session_factory(engine)
    audit_store = AuditStore(audit_engine, settings.require_hmac())
    CipherText.configure_key(settings.require_kek())
    queue = JobQueue(settings.redis_url)

    topic, process = WORKERS[args.name]
    ctx = jobs.WorkerContext(settings, session_factory, audit_store, queue)
    try:
        jobs.run_loop(ctx, topic, process)
    except KeyboardInterrupt:
        queue.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
