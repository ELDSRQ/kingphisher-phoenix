"""Shared test harness for the curation package (W3-02).

Builds an in-memory SQLite engine with the threat-library tables created from the
ORM metadata, with a JSONB->JSON compile shim so the Postgres JSONB columns map
onto SQLite for fast, PG-free unit tests. The real Postgres schema is exercised
by the alembic migration test and the postgres-gated suites.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from kp_database.models import SourcePolicy, ThreatArtifact, ThreatBundleImport
from sqlalchemy import Engine, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type: JSONB, _compiler: Any, **_kwargs: Any) -> str:
    return "JSON"


@pytest.fixture
def engine() -> Engine:
    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    cast(Table, SourcePolicy.__table__).create(eng)
    cast(Table, ThreatArtifact.__table__).create(eng)
    cast(Table, ThreatBundleImport.__table__).create(eng)
    return eng
