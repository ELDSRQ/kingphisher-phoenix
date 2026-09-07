"""Audit store integration tests against a disposable, MIGRATED Postgres.

TST-002 (follow-up to the fixture uplift): this module used to build its schema
with ``Base.metadata.create_all()`` and then hand-reproduce migration behavior
on top of it -- it ``CREATE TABLE``d ``audit_chain_head`` itself and issued
``GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO audit_writer``.
That fixture was strictly *weaker* than the real deployed posture, so the tests
could not see it:

* migration ``0035_audit_owner_separation`` transfers ``audit_events`` and
  ``audit_chain_head`` to the **NOLOGIN** role ``audit_owner`` and revokes
  ``DELETE``/``TRUNCATE`` from ``audit_writer``; the blanket grant above put
  privileges back that the migration deliberately takes away, and
  ``create_all()`` never transferred ownership at all;
* migration ``0020`` makes audit append a **function-only** path: the
  SECURITY DEFINER dispatchers are the only way evidence reaches
  ``audit_events``, and ``kp_dispatch_audit_outbox`` explicitly *rejects* an
  intent whose ``origin_role`` is ``audit_writer``/``audit_owner``. Under
  ``create_all()`` the functions do not exist, so ``AuditStore`` silently fell
  back to its development owner-only direct-INSERT path and the tests exercised
  code that never runs against a migrated database.

The module now stands up an **isolated database taken to Alembic head** (the
pattern ``test_outbox_postgres`` / ``test_audit_anchor_permissions`` /
``test_migrations_fresh_install`` already use) instead of rebuilding the shared
``public`` schema, because these tests connect *as* ``audit_writer``: a fresh
database inherits the template's ``public`` ACL, whereas dropping and recreating
``public`` on the shared database would strip the schema-level ``USAGE`` that
``audit_writer`` needs. No table privilege is invented here -- ``audit_writer``
gets exactly what migrations ``0001``/``0002`` grant it, with ``0035``'s
ownership transfer and destructive-DML revoke intact.

These belong to the explicit ``make test-postgres`` profile and require its
disposable database, the ``audit_writer`` role and ``CREATEDB`` rights.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from _migrate_schema import isolated_migrated_database
from kp_database.audit_store import AuditStore
from kp_database.session import create_db_engine
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ProgrammingError

pytestmark = pytest.mark.postgres


TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
AUDIT_URL = os.environ.get(
    "AUDIT_DATABASE_URL_TEST", "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher_test"
)

# The database-resident signing root the migrated SECURITY DEFINER functions
# read from ``audit_integrity_secret``. Migrations create the (empty) table;
# installing the key is the deploy's job (scripts/azure_migrate.py), mirrored
# here exactly as ``test_outbox_postgres`` mirrors it.
AUDIT_ROOT_KEY_HEX = "0" * 64

_available = None


# Plain reachability gate, kept with this name and these semantics because
# ``test_migrations_fresh_install`` and ``test_migration_0010`` import
# ``requires_db`` from this module.
def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")

_audit_eligible = None


def _eligible_database() -> bool:
    """This module additionally needs CREATEDB and a provisioned audit role."""
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _audit_eligible
    if _audit_eligible is None:
        engine = create_db_engine(TEST_URL)
        try:
            with engine.connect() as connection:
                _audit_eligible = bool(
                    connection.scalar(
                        text(
                            "SELECT (rolsuper OR rolcreatedb) AND "
                            "EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') "
                            "FROM pg_roles WHERE rolname = current_user"
                        )
                    )
                )
        except Exception:
            _audit_eligible = False
        finally:
            engine.dispose()
    return _audit_eligible


requires_audit_database = pytest.mark.skipif(
    not _eligible_database(),
    reason="local Postgres with isolated-database rights and the audit_writer role is not reachable",
)


def _install_deploy_prerequisites(business_url: str) -> None:
    """Apply what a *deploy* applies on top of the migration chain -- no more.

    Migrations create the audit objects and ``REVOKE ALL ... FROM PUBLIC``; they
    never hand the audit connection its EXECUTE rights nor install the signing
    root, because those belong to ``scripts/azure_migrate.py`` (and are mirrored
    by ``test_outbox_postgres``). Deliberately absent: any TABLE grant. The
    table privileges under test must be exactly the ones migrations ``0001`` and
    ``0002`` grant and ``0035`` narrows.
    """
    engine = create_db_engine(business_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO audit_integrity_secret (singleton_id, key_hex) VALUES (1, :key) "
                    "ON CONFLICT (singleton_id) DO NOTHING"
                ),
                {"key": AUDIT_ROOT_KEY_HEX},
            )
            connection.execute(text("GRANT USAGE ON SCHEMA public TO audit_writer"))
            connection.execute(
                text(
                    "GRANT EXECUTE ON FUNCTION kp_dispatch_audit_outbox(uuid), "
                    "kp_dispatch_pending_audit(integer), kp_outbox_health(), "
                    "kp_verify_audit_head() TO audit_writer"
                )
            )
    finally:
        engine.dispose()


@contextmanager
def _migrated_audit_database() -> Iterator[tuple[str, str]]:
    """Disposable database at Alembic head, reachable by both credentials.

    Yields ``(business_url, audit_url)``: the same two distinct credentials the
    services use -- the least-privilege business role that stages intent and the
    ``audit_writer`` connection that dispatches and reads evidence.
    """
    with isolated_migrated_database(TEST_URL, prefix="kp_audit_store") as business_url:
        database_name = make_url(business_url).database
        audit_url = make_url(AUDIT_URL).set(database=database_name).render_as_string(hide_password=False)
        _install_deploy_prerequisites(business_url)
        yield business_url, audit_url


def _bound_store(audit_engine: Engine, business_engine: Engine) -> AuditStore:
    """Build the store exactly as a service does on a migrated database.

    No legacy HMAC key is supplied, so ``AuditStore``'s development
    owner-only direct-INSERT fallback can never engage: every event below is
    appended by the migrated ``kp_dispatch_*`` SECURITY DEFINER functions.
    """
    store = AuditStore(audit_engine)
    store.bind_intent_engine(business_engine)
    return store


@requires_audit_database
def test_audit_store_roundtrip_and_chain() -> None:
    with _migrated_audit_database() as (business_url, audit_url):
        business_engine = create_db_engine(business_url)
        audit_engine = create_db_engine(audit_url)
        try:
            audit = _bound_store(audit_engine, business_engine)

            first = audit.record(
                actor="seed",
                action="seed.complete",
                object_type="campaign",
                object_id="c1",
                detail={"pattern": "p1"},
            )
            second = audit.record(
                actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1", detail={"sent": 5}
            )

            assert first.prev_hash == "0" * 64
            assert second.prev_hash == first.event_hash
            assert audit.verify() == []
            snapshot = audit.head_snapshot()
            assert snapshot is not None
            assert snapshot.sequence == 2
            assert snapshot.event_hash == second.event_hash
            assert snapshot.signed_at.tzinfo is not None

            with business_engine.connect() as conn:
                rows = (
                    conn.execute(
                        text("SELECT action, detail, origin_role, chain_version FROM audit_events ORDER BY occurred_at")
                    )
                    .mappings()
                    .all()
                )
                business_role = conn.scalar(text("SELECT session_user"))
            assert [r["action"] for r in rows] == ["seed.complete", "campaign.deliver"]
            assert rows[1]["detail"] == {"sent": 5}
            # Written by the migrated dispatcher (chain v2), attributed to the
            # role that staged the intent. The audit connection may never be the
            # author of its own evidence -- kp_dispatch_audit_outbox rejects an
            # intent whose origin_role is audit_writer/audit_owner.
            assert {r["chain_version"] for r in rows} == {2}
            assert {r["origin_role"] for r in rows} == {business_role}
        finally:
            audit_engine.dispose()
            business_engine.dispose()


@requires_audit_database
def test_audit_store_resumes_from_persisted_head() -> None:
    with _migrated_audit_database() as (business_url, audit_url):
        business_engine = create_db_engine(business_url)
        engine_a = create_db_engine(audit_url)
        engine_b = create_db_engine(audit_url)
        try:
            store_a = _bound_store(engine_a, business_engine)
            store_a.record(actor="api", action="campaign.create", object_type="campaign", object_id="c1")
            first = store_a.record(actor="api", action="campaign.update", object_type="campaign", object_id="c1")

            store_b = _bound_store(engine_b, business_engine)
            second = store_b.record(actor="worker", action="campaign.deliver", object_type="campaign", object_id="c1")

            assert second.prev_hash == first.event_hash
            assert store_b.verify() == []
        finally:
            engine_b.dispose()
            engine_a.dispose()
            business_engine.dispose()


@requires_audit_database
def test_verify_detects_tampering_with_recorded_chain_material() -> None:
    """Rewriting a recorded event's canonical evidence breaks verification.

    Replaces the old ``test_verify_detects_tampered_detail``. On the migrated
    schema events are chain version 2, and a v2 event hashes the stored
    ``canonical_payload`` text -- which is where the recorded actor/action/detail
    actually live. The tamper is therefore applied to that column.

    KNOWN GAP (not introduced here): ``AuditStore.verify`` re-hashes the *stored*
    canonical text for v2 rows rather than rebuilding it from the columns, so an
    UPDATE of the ``detail`` COLUMN alone is invisible to verification. That is
    the AUD-003 open question already flagged in ``kp_database/audit_store.py``;
    the old fixture only appeared to cover it because ``create_all()`` produced
    chain-version-1 rows. See the TST-002 report.
    """
    with _migrated_audit_database() as (business_url, audit_url):
        business_engine = create_db_engine(business_url)
        audit_engine = create_db_engine(audit_url)
        try:
            audit = _bound_store(audit_engine, business_engine)
            audit.record(actor="a", action="campaign.create", object_type="campaign", object_id="c1")
            assert audit.verify() == []

            # Only the migration principal can reach these rows: audit_owner is
            # NOLOGIN and migration 0035 makes the migration role a member of it.
            with business_engine.begin() as conn:
                tampered = conn.execute(
                    text(
                        "UPDATE audit_events "
                        "SET canonical_payload = replace(canonical_payload, 'campaign.create', 'campaign.delete') "
                        "WHERE actor = 'a' RETURNING canonical_payload"
                    )
                ).scalar_one()
            assert "campaign.delete" in tampered
            assert audit.verify() != []
        finally:
            audit_engine.dispose()
            business_engine.dispose()


@requires_audit_database
def test_audit_writer_can_append_evidence_but_cannot_destroy_or_author_it() -> None:
    """The real least-privilege posture the old hand-rolled grants hid.

    The previous fixture granted ``SELECT, INSERT, UPDATE ON ALL TABLES`` to
    ``audit_writer``. On the migrated schema that role owns nothing (migration
    0035 hands ownership to the NOLOGIN ``audit_owner``), holds no destructive
    DML on the evidence tables, and holds nothing at all on
    ``transactional_outbox`` -- so it cannot stage the audit intents it later
    dispatches.
    """
    with _migrated_audit_database() as (business_url, audit_url):
        business_engine = create_db_engine(business_url)
        audit_engine = create_db_engine(audit_url)
        try:
            audit = _bound_store(audit_engine, business_engine)
            audit.record(actor="api", action="campaign.create", object_type="campaign", object_id="c1")

            privilege = text("SELECT has_table_privilege(CAST(:t AS text), CAST(:v AS text))")
            owner_of = text("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass(:t)")
            with audit_engine.connect() as conn:
                for table in ("audit_events", "audit_chain_head"):
                    qualified = f"public.{table}"
                    assert conn.scalar(owner_of, {"t": qualified}) == "audit_owner", table
                    assert conn.scalar(privilege, {"t": qualified, "v": "SELECT"}) is True, table
                    assert conn.scalar(privilege, {"t": qualified, "v": "INSERT"}) is True, table
                    assert conn.scalar(privilege, {"t": qualified, "v": "DELETE"}) is False, table
                    assert conn.scalar(privilege, {"t": qualified, "v": "TRUNCATE"}) is False, table
                # UPDATE on the single-row head is an explicit 0002 grant and
                # must survive; UPDATE on the append-only event log must not.
                assert conn.scalar(privilege, {"t": "public.audit_chain_head", "v": "UPDATE"}) is True
                assert conn.scalar(privilege, {"t": "public.audit_events", "v": "UPDATE"}) is False

            denied = (
                "DELETE FROM audit_events",
                "UPDATE audit_events SET detail = '{}'::jsonb",
                "TRUNCATE audit_events",
                "DELETE FROM audit_chain_head",
                # Self-authored intent is unreachable: the audit connection has
                # no privilege on the outbox at all.
                "INSERT INTO transactional_outbox (outbox_id, kind, payload, idempotency_key) "
                "VALUES (gen_random_uuid(), 'audit', '{}'::jsonb, 'self-authored')",
            )
            for statement in denied:
                with pytest.raises(ProgrammingError), audit_engine.begin() as conn:
                    conn.execute(text(statement))

            # The evidence recorded above survived every attempt.
            assert audit.head_snapshot() is not None
            assert audit.verify() == []
        finally:
            audit_engine.dispose()
            business_engine.dispose()
