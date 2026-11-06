"""Actual operator-role scheduling locks without occurrence-write privileges.

Fresh, preserved synthetic database; managed role bootstrap runs serially.
"""

from __future__ import annotations

import queue
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kp_database.models import Campaign, CampaignProgram, CipherText
from kp_database.program_service import require_program_active_for_schedule, set_campaign_program_state
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from test_adaptive_program_iterations import _adaptive_source, _recipient
from test_queue_reconcile_postgres import managed_database as _managed_database

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    url, admin, _, _ = managed_database
    previous = CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys
    CipherText.configure_key(b"p" * 32)
    factory = make_session_factory(admin)
    with factory() as session:
        program_id = _adaptive_source(session, [_recipient(f"schedule-{uuid4().hex}@example.test")])
        source = session.get(Campaign, session.get(CampaignProgram, program_id).source_campaign_id)
        standalone = Campaign(
            campaign_id=uuid4(),
            pattern_id=source.pattern_id,
            current_template_id=source.current_template_id,
            title="Standalone schedule-gate qualification",
            state=dm.CampaignState.DRAFT,
            sender_mailbox="training@example.test",
            training_domain="training.example.test",
            timezone="UTC",
            max_recipients=1,
            created_by=uuid4(),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(standalone)
        session.commit()
        source_id, standalone_id = source.campaign_id, standalone.campaign_id
    operator = create_engine(url.set(username="kp_operator", password="effect-operator"))
    yield program_id, source_id, standalone_id, admin, make_session_factory(operator)
    operator.dispose()
    CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous


def test_actual_operator_can_schedule_standalone_and_active_program_without_occurrence_update(subject):
    program_id, source_id, standalone_id, _, factory = subject
    with factory() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_operator"
        assert not session.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
        assert require_program_active_for_schedule(session, standalone_id) is None
        assert require_program_active_for_schedule(session, source_id).campaign_program_id == program_id
        assert not session.scalar(text("SELECT has_table_privilege('public.campaign_program_occurrences','UPDATE')"))
        with pytest.raises(DBAPIError) as denied:
            session.execute(
                text("UPDATE campaign_program_occurrences SET occurrence_number=occurrence_number WHERE false")
            )
        assert denied.value.orig.sqlstate == "42501"
        session.rollback()


def test_actual_operator_refuses_paused_program_without_broadening_occurrence_access(subject):
    program_id, source_id, _, _, factory = subject
    with factory() as session:
        set_campaign_program_state(
            session, program_id=program_id, state=dm.CampaignProgramState.PAUSED, expected_version=1
        )
        session.commit()
    with factory() as session, pytest.raises(ConflictError, match="paused"):
        require_program_active_for_schedule(session, source_id)


def _wait_for_real_lock_wait(admin, pid, future):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if future.done():
            pytest.fail("competing gate completed before the owning transaction released its program lock")
        with admin.connect() as observer:
            waiting = observer.scalar(
                text("SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid}
            )
        if waiting:
            return
        time.sleep(0.02)
    pytest.fail("competing gate did not reach the expected bounded PostgreSQL lock wait")


@pytest.mark.parametrize("first", ("schedule", "pause"))
def test_pause_and_schedule_remain_serialized_on_the_program_row(subject, first):
    program_id, source_id, _, admin, factory = subject
    backend = queue.Queue()

    def competing_transaction():
        with factory() as session:
            session.execute(text("SET LOCAL statement_timeout='5s'"))
            backend.put(session.scalar(text("SELECT pg_backend_pid()")))
            if first == "schedule":
                set_campaign_program_state(
                    session, program_id=program_id, state=dm.CampaignProgramState.PAUSED, expected_version=1
                )
                session.commit()
                return "paused"
            try:
                require_program_active_for_schedule(session, source_id)
            except ConflictError:
                session.rollback()
                return "paused_refused"
            pytest.fail("scheduling passed after the earlier pause committed")

    with ThreadPoolExecutor(max_workers=1) as executor, factory() as first_session:
        first_session.execute(text("SET LOCAL statement_timeout='5s'"))
        if first == "schedule":
            require_program_active_for_schedule(first_session, source_id)
        else:
            set_campaign_program_state(
                first_session, program_id=program_id, state=dm.CampaignProgramState.PAUSED, expected_version=1
            )
        future = executor.submit(competing_transaction)
        try:
            _wait_for_real_lock_wait(admin, backend.get(timeout=3), future)
        finally:
            first_session.commit()
        assert future.result(timeout=5) == ("paused" if first == "schedule" else "paused_refused")
