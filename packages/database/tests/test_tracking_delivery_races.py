"""Actual tracking/worker/operator logins at delivery and recall boundaries.

Uses real tracking HTTP routes and the worker's claim/correlation/send loop.
The transport is a bounded synthetic provider; no SMTP connection is opened.
All resources are fresh preserved synthetic qualification databases.
"""

from __future__ import annotations

import hashlib
import queue
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from kp_database.campaign_service import bind_campaign_training_resource, tracking_token_verifier
from kp_database.models import (
    Campaign,
    RecipientAssignment,
    RulesOfEngagement,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
    TrainingResource,
)
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_domain_models.roe import roe_signature_hex
from kp_operator_api.routes.campaigns import recall_campaign
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from kp_workers import jobs
from sqlalchemy import event, func, select, text
from test_delivery_recipient_races import deliver, receipt
from test_delivery_recipient_races import prepared as _prepared
from test_runtime_feature_role_effects import managed_database as _managed_database
from test_runtime_feature_role_effects import subject as _subject

pytestmark = pytest.mark.postgres
TRACKING_KEY = b"c" * 32
TRAINING_KEY = b"q" * 32
ROE_KEY = b"r" * 32
LIVE_AUTHORITY = jobs._live_delivery_authorization_reason


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _subject.__wrapped__(managed_database)


@pytest.fixture
def prepared(subject, monkeypatch):
    value = _prepared.__wrapped__(subject, monkeypatch)
    _, _, _, engines, _ = subject
    value.ctx.settings = SimpleNamespace(
        approval_policy=ApprovalPolicy.SINGLE_OPERATOR, require_roe_signing_key=lambda: ROE_KEY
    )
    # Exercise the actual live-authority locks as well as the production send
    # loop; only the unrelated launch/provider/safety fixture gates stay scoped.
    monkeypatch.setattr(jobs, "_live_delivery_authorization_reason", LIVE_AUTHORITY)
    with value.admin_factory() as session:
        campaign = session.get(Campaign, value.campaign_id)
        roe = session.get(RulesOfEngagement, campaign.roe_id)
        roe.target_domains = ["example.test"]
        roe.signature = roe_signature_hex(
            roe.terms_hash,
            roe.signer,
            roe.signed_at,
            authorizing_party=roe.authorizing_party,
            target_domains=roe.target_domains,
            window_start=roe.window_start,
            window_end=roe.window_end,
            signing_key=ROE_KEY,
        )
        resource = session.get(TrainingResource, campaign.training_resource_id)
        resource.knowledge_question = "Which action protects you?"
        resource.knowledge_options = ["Verify independently", "Trust urgency"]
        resource.knowledge_answer_index = 0
        bind_campaign_training_resource(campaign, resource)
        value.payload["template_hash"] = campaign.manifest_hash
        token = session.scalar(
            select(TrackingToken).where(TrackingToken.recipient_assignment_id == value.assignment_ids[0])
        )
        value.token_id = token.token_id
        value.bearer = secrets.token_urlsafe(32)
        token.token_hash = tracking_token_verifier(value.bearer, TRACKING_KEY)
        assignment = session.get(RecipientAssignment, value.assignment_ids[0])
        assignment.token_id = token.token_id
        value.payload["tracking_bearers"][str(value.assignment_ids[0])] = {
            "bearer": value.bearer,
            "verifier": token.token_hash,
            "checksum": hashlib.sha256(value.bearer.encode()).hexdigest(),
        }
        session.commit()
    value.click = "/v1/track/click/" + value.bearer
    value.pixel = "/v1/track/open/" + value.bearer
    app = create_app(
        TrackingApiSettings(
            _env_file=None,
            database_url=engines["tracking"].url.render_as_string(hide_password=False),
            tracking_token_hmac_key=TRACKING_KEY.hex(),
            training_token_hmac_key=TRAINING_KEY.hex(),
            rate_limit_token_per_min=100,
            rate_limit_ip_per_min=100,
        )
    )

    @event.listens_for(app.state.db_engine, "connect")
    def bounded_tracking_connection(connection, _):
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout='5s'")
        connection.commit()

    value.tracking_engine = app.state.db_engine
    with TestClient(app, raise_server_exceptions=False) as client:
        value.client = client
        yield value


def _wait_for_lock(prepared, backend_pid, future):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if future.done():
            pytest.fail("tracking did not wait for the held serialization boundary")
        with prepared.observer.connect() as connection:
            if connection.scalar(
                text("SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"), {"pid": backend_pid}
            ):
                return
        time.sleep(0.02)
    pytest.fail("tracking did not enter the expected bounded PostgreSQL lock wait")


def _observe_tracking_boundary(prepared, relation):
    backend = queue.Queue()

    @event.listens_for(prepared.tracking_engine, "before_cursor_execute")
    def boundary(connection, _cursor, statement, _parameters, _context, _executemany):
        if "FROM " + relation in statement and ("FOR SHARE" in statement or "FOR UPDATE" in statement):
            backend.put(connection.connection.driver_connection.info.backend_pid)

    return backend


def _recall(prepared, operator):
    app = SimpleNamespace(
        state=SimpleNamespace(audit_store=prepared.audit, queue=SimpleNamespace(publish=lambda *_, **__: None))
    )
    return recall_campaign(
        prepared.campaign_id,
        Request({"type": "http", "app": app}),
        session=operator,
        audit=prepared.audit,
        principal=prepared.principal,
    )


def _count(session, model, prepared):
    return session.scalar(select(func.count()).select_from(model).where(model.campaign_id == prepared.campaign_id))


def test_actual_click_and_knowledge_completion_coexist_with_held_provider_authority_locks(prepared, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def provider(*_, **__):
        entered.set()
        assert release.wait(5), "controller did not release bounded synthetic provider"
        return receipt()

    monkeypatch.setattr(jobs, "_send_email", provider)
    with ThreadPoolExecutor(max_workers=1) as executor:
        delivery = executor.submit(deliver, prepared)
        try:
            assert entered.wait(3), "delivery did not reach its provider with final authority locks"
            click = prepared.client.get(prepared.click, follow_redirects=False)
            assert click.status_code == 302
            opened = prepared.client.get(click.headers["location"])
            assert opened.status_code == 200
            match = re.search(r'action="([^"]+/complete)"', opened.text)
            assert match is not None
            assert prepared.client.post(match.group(1), data={"answer": "Verify independently"}).status_code == 200
            assert not release.is_set(), "tracking did not finish during provider overlap"
        finally:
            release.set()
        assert delivery.result(timeout=8).sent == 1
    with prepared.admin_factory() as session:
        assignment = session.get(RecipientAssignment, prepared.assignment_ids[0])
        assert assignment.send_state == dm.SendState.ACCEPTED
        training = session.scalar(
            select(TrainingAssignment).where(TrainingAssignment.recipient_assignment_id == prepared.assignment_ids[0])
        )
        assert training.completed_at is not None
        assert _count(session, TrackingEvent, prepared) == 4


@pytest.mark.parametrize("change", ("recall", "expire"))
def test_click_waits_campaign_before_assignment_and_revalidates_token_after_wait(prepared, change):
    backend = _observe_tracking_boundary(prepared, "campaigns")
    with ThreadPoolExecutor(max_workers=1) as executor, prepared.operator_factory() as operator:
        operator.execute(text("SET LOCAL statement_timeout='5s'"))
        operator.get(Campaign, prepared.campaign_id, with_for_update=True)
        click = executor.submit(prepared.client.get, prepared.click, follow_redirects=False)
        try:
            _wait_for_lock(prepared, backend.get(timeout=3), click)
            # The competing click must not own assignment UPDATE while waiting
            # for Campaign. This NOWAIT would fail with the previous ordering.
            assert (
                operator.scalar(
                    select(RecipientAssignment)
                    .where(RecipientAssignment.recipient_assignment_id == prepared.assignment_ids[0])
                    .with_for_update(nowait=True)
                )
                is not None
            )
            if change == "recall":
                assert _recall(prepared, operator)["tokens_revoked"] == len(prepared.assignment_ids)
            else:
                operator.get(TrackingToken, prepared.token_id).expires_at = datetime.now(UTC) - timedelta(seconds=1)
                operator.commit()
        finally:
            operator.rollback()
        assert click.result(timeout=8).status_code == 404
    assert prepared.client.get(prepared.pixel).status_code == 404
    with prepared.admin_factory() as session:
        assert _count(session, TrackingEvent, prepared) == 0
        assert _count(session, TrainingAssignment, prepared) == 0


@pytest.mark.parametrize("change", ("recall", "rotate"))
def test_pixel_waiting_assignment_refreshes_token_after_committed_authorization_change(prepared, change):
    backend = _observe_tracking_boundary(prepared, "recipient_assignments")
    with ThreadPoolExecutor(max_workers=1) as executor, prepared.operator_factory() as operator:
        operator.execute(text("SET LOCAL statement_timeout='5s'"))
        operator.get(RecipientAssignment, prepared.assignment_ids[0], with_for_update=True)
        pixel = executor.submit(prepared.client.get, prepared.pixel)
        try:
            _wait_for_lock(prepared, backend.get(timeout=3), pixel)
            if change == "recall":
                assert _recall(prepared, operator)["tokens_revoked"] == len(prepared.assignment_ids)
            else:
                token = operator.get(TrackingToken, prepared.token_id)
                token.token_hash = tracking_token_verifier(secrets.token_urlsafe(32), TRACKING_KEY)
                operator.commit()  # same row remains ACTIVE with the same assignment binding
        finally:
            operator.rollback()
        assert pixel.result(timeout=8).status_code == 404
    assert prepared.client.get(prepared.click, follow_redirects=False).status_code == 404
    with prepared.admin_factory() as session:
        assert _count(session, TrackingEvent, prepared) == 0


@pytest.mark.parametrize("operation", ("open", "complete"))
def test_waiting_training_request_refreshes_child_and_preserves_first_timestamp(prepared, operation):
    click = prepared.client.get(prepared.click, follow_redirects=False)
    assert click.status_code == 302
    training_path = click.headers["location"]
    if operation == "complete":
        opened = prepared.client.get(training_path)
        assert opened.status_code == 200
        match = re.search(r'action="([^"]+/complete)"', opened.text)
        assert match is not None
        target = match.group(1)
    else:
        target = training_path
    held, release = threading.Event(), threading.Event()
    guard = threading.Lock()
    backend = queue.Queue()
    queries, writes = [0], []
    field = "opened_at" if operation == "open" else "completed_at"

    @event.listens_for(prepared.tracking_engine, "before_cursor_execute")
    def before(connection, _cursor, statement, _parameters, context, _executemany):
        if "JOIN recipient_assignments" in statement and "FOR UPDATE OF recipient_assignments" in statement:
            with guard:
                index = queries[0]
                queries[0] += 1
            context.kp_first_parent_lock = index == 0
            if index == 1:
                backend.put(connection.connection.driver_connection.info.backend_pid)
        if statement.startswith("UPDATE training_assignments SET"):
            values = context.compiled_parameters[0]
            if field in values:
                writes.append(values[field])

    @event.listens_for(prepared.tracking_engine, "after_cursor_execute")
    def after(_connection, _cursor, _statement, _parameters, context, _executemany):
        if getattr(context, "kp_first_parent_lock", False):
            held.set()
            assert release.wait(5), "controller did not release first training transaction"

    def request():
        # Separate ASGI portals model two tracking workers. The async quiz
        # route performs synchronous database I/O, so sharing one TestClient
        # portal would serialize its event loop before the second lock query.
        # The fixture's original client owns the application's lifespan.
        client = TestClient(prepared.client.app, raise_server_exceptions=False)
        try:
            if operation == "open":
                return client.get(target)
            return client.post(target, data={"answer": "Verify independently"})
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(request)
        try:
            assert held.wait(3), "first training request did not acquire its parent lock"
            second = executor.submit(request)
            _wait_for_lock(prepared, backend.get(timeout=3), second)
        finally:
            release.set()
        assert first.result(timeout=8).status_code == second.result(timeout=8).status_code == 200
    assert len(writes) == 1, "waiting request rewrote the first immutable timestamp"
    with prepared.admin_factory() as session:
        training = session.scalar(
            select(TrainingAssignment).where(TrainingAssignment.recipient_assignment_id == prepared.assignment_ids[0])
        )
        assert getattr(training, field) == writes[0]
        assert _count(session, TrackingEvent, prepared) == (2 if operation == "open" else 4)


@pytest.mark.parametrize("purpose", ("open", "complete"))
def test_waiting_training_request_revalidates_rotated_purpose_verifier(prepared, purpose):
    click = prepared.client.get(prepared.click, follow_redirects=False)
    assert click.status_code == 302
    training_path = click.headers["location"]
    if purpose == "complete":
        opened = prepared.client.get(training_path)
        assert opened.status_code == 200
        match = re.search(r'action="([^"]+/complete)"', opened.text)
        assert match is not None
        target = match.group(1)
    else:
        target = training_path
    backend = _observe_tracking_boundary(prepared, "training_assignments")

    def request():
        if purpose == "open":
            return prepared.client.get(target)
        return prepared.client.post(target, data={"answer": "Verify independently"})

    with ThreadPoolExecutor(max_workers=1) as executor, prepared.operator_factory() as operator:
        operator.execute(text("SET LOCAL statement_timeout='5s'"))
        operator.get(RecipientAssignment, prepared.assignment_ids[0], with_for_update=True)
        waiting = executor.submit(request)
        try:
            _wait_for_lock(prepared, backend.get(timeout=3), waiting)
            training = operator.scalar(
                select(TrainingAssignment).where(
                    TrainingAssignment.recipient_assignment_id == prepared.assignment_ids[0]
                )
            )
            column = "training_token_hash" if purpose == "open" else "training_completion_token_hash"
            setattr(training, column, "f" * 64)
            operator.commit()
        finally:
            operator.rollback()
        assert waiting.result(timeout=8).status_code == 404
    with prepared.admin_factory() as session:
        assert _count(session, TrackingEvent, prepared) == (1 if purpose == "open" else 2)
        training = session.scalar(
            select(TrainingAssignment).where(TrainingAssignment.recipient_assignment_id == prepared.assignment_ids[0])
        )
        assert training.completed_at is None
        if purpose == "open":
            assert training.opened_at is None
