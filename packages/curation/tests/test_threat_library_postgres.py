"""Concurrent deduplication on a fresh, preserved task-only PostgreSQL database."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from kp_curation.threat_library import ingest_threat_artifact
from kp_database.models import SourcePolicy, ThreatArtifact
from kp_domain_models import models as dm
from psycopg import sql
from sqlalchemy import Table, create_engine, event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres


def test_concurrent_identical_ingest_preserves_both_outer_transactions() -> None:
    explicit = os.environ.get("KP_THREAT_INGEST_TEST_URL")
    if explicit:
        url = make_url(explicit)
    else:
        assert os.environ.get("KP_TEST_PROFILE") == "postgres"
        source = make_url(os.environ["DATABASE_URL_TEST"])
        assert source.database == "kingphisher_test" or (source.database or "").startswith(
            ("kp_reconcile_qualification_", "kp_hold_qualification_", "kp_threat_ingest_qualification_")
        )
        name = f"kp_threat_ingest_qualification_{uuid4().hex}"
        admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
        with admin.connect() as connection:
            connection.connection.driver_connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        admin.dispose()
        url = source.set(database=name)
    assert (url.database or "").startswith("kp_threat_ingest_qualification_")
    engine = create_engine(url, connect_args={"options": "-c statement_timeout=20000 -c lock_timeout=10000"})
    # This proof owns a new database; it never clears or alters existing tables.
    cast(Table, SourcePolicy.__table__).create(engine)
    cast(Table, ThreatArtifact.__table__).create(engine)
    barrier = threading.Barrier(2, timeout=5)
    per_thread = threading.local()

    def synchronize_initial_reads(
        _connection: Any, _cursor: Any, statement: str, _parameters: Any, _context: Any, _many: bool
    ) -> None:
        if statement.startswith("SELECT threat_artifacts.threat_artifact_id") and not getattr(
            per_thread, "synchronized", False
        ):
            per_thread.synchronized = True
            barrier.wait()

    event.listen(engine, "after_cursor_execute", synchronize_initial_reads)

    def ingest(number: int):  # type: ignore[no-untyped-def]
        with Session(engine) as session:
            session.add(
                SourcePolicy(
                    source_key=f"outer-transaction-{number}",
                    owner="qualification",
                    license="synthetic",
                    parser="synthetic",
                    trust=dm.SourceTrust.PARTNER,
                    freshness=7,
                    enabled=True,
                )
            )
            policy = SimpleNamespace(
                enabled=True, freshness=7, last_success_at=None, consecutive_failures=0, source_key="synthetic"
            )
            result = ingest_threat_artifact(
                session,
                policy=policy,
                title="Synthetic qualification lure",
                raw_html="<p>Verify your account</p>",
                origin=dm.ArtifactOrigin.FEED,
            )
            # Both callers can still write and commit their own transaction.
            assert session.scalar(text("SELECT 1")) == 1
            session.commit()
            return result

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(ingest, number) for number in range(2)]
            results = [future.result(timeout=30) for future in futures]
        assert sum(result.created for result in results) == 1
        assert sum(result.deduplicated for result in results) == 1
        assert results[0].threat_artifact_id == results[1].threat_artifact_id
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(ThreatArtifact)) == 1
            assert session.scalar(select(func.count()).select_from(SourcePolicy)) == 2
    finally:
        event.remove(engine, "after_cursor_execute", synchronize_initial_reads)
        engine.dispose()
