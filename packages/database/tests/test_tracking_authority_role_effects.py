"""Real managed tracking routes and narrowly scoped authorization row locks.

Fresh preserved synthetic databases, NOINHERIT logins and purpose-specific
synthetic keys only. No real recipients, provider calls or normal database use.
"""

from __future__ import annotations

import importlib.util
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
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
from kp_database.session import make_session_factory
from kp_database.training import TrainingBearerPurpose, training_bearer_verifier
from kp_domain_models import models as dm
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from sqlalchemy import func, select, text
from test_runtime_feature_role_effects import _deny
from test_runtime_feature_role_effects import managed_database as _managed_database
from test_runtime_feature_role_effects import subject as _subject

pytestmark = pytest.mark.postgres
TRACKING_KEY = b"t" * 32
TRAINING_KEY = b"l" * 32


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _subject.__wrapped__(managed_database)


def _upgrade(connection):
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0060_delivery_authority_locks.py"
    spec = importlib.util.spec_from_file_location("authority_locks_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with Operations.context(MigrationContext.configure(connection)):
        migration.upgrade()


def test_actual_tracking_click_training_quiz_and_replay_after_reproducing_both_undergrants(subject, managed_database):
    campaign_id, assignments, factory, engines, _ = subject
    _, admin, _, _ = managed_database
    bearer = secrets.token_urlsafe(32)
    correct = "Verify through a known independent contact"
    wrong = "Open the unexpected attachment immediately"
    with factory() as session:
        campaign = session.get(Campaign, campaign_id)
        resource = session.get(TrainingResource, campaign.training_resource_id)
        resource.knowledge_question = "How should you verify this request?"
        resource.knowledge_options = [correct, wrong]
        resource.knowledge_answer_index = 0
        bind_campaign_training_resource(campaign, resource)
        assignment = session.get(RecipientAssignment, assignments[0])
        token = TrackingToken(
            token_id=uuid4(),
            token_hash=tracking_token_verifier(bearer, TRACKING_KEY),
            token_prefix=bearer[:6],
            campaign_id=campaign_id,
            recipient_assignment_id=assignments[0],
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        session.add(token)
        session.flush()
        assignment.token_id = token.token_id
        assignment.send_state = dm.SendState.ACCEPTED
        session.commit()
    settings = TrackingApiSettings(
        _env_file=None,
        database_url=engines["tracking"].url.render_as_string(hide_password=False),
        tracking_token_hmac_key=TRACKING_KEY.hex(),
        training_token_hmac_key=TRAINING_KEY.hex(),
        rate_limit_token_per_min=100,
        rate_limit_ip_per_min=100,
    )
    app = create_app(settings)
    with app.state.db_engine.connect() as connection:
        assert connection.scalar(text("SELECT session_user")) == "kp_tracking"
        assert not connection.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
    click_path = "/v1/track/click/" + bearer
    with TestClient(app, raise_server_exceptions=False) as client:
        try:
            with admin.begin() as connection:
                connection.execute(text("REVOKE UPDATE(campaign_id) ON public.campaigns FROM kp_tracking"))
                connection.execute(
                    text("REVOKE UPDATE(training_resource_id) ON public.training_resources FROM kp_tracking")
                )
            assert client.get(click_path, follow_redirects=False).status_code == 503
            with factory() as session:
                assert session.scalar(select(func.count()).select_from(TrackingEvent)) == 0
                assert session.scalar(select(func.count()).select_from(TrainingAssignment)) == 0
            with admin.begin() as connection:
                connection.execute(text("GRANT UPDATE(campaign_id) ON public.campaigns TO kp_tracking"))
            assert client.get(click_path, follow_redirects=False).status_code == 503
            with factory() as session:
                assert session.scalar(select(func.count()).select_from(TrackingEvent)) == 0
                assert session.scalar(select(func.count()).select_from(TrainingAssignment)) == 0
        finally:
            with admin.begin() as connection:
                _upgrade(connection)
        click = client.get(click_path, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0 SyntheticLearner"})
        assert click.status_code == 302
        training_path = click.headers["location"]
        opened = client.get(training_path)
        assert opened.status_code == 200 and correct in opened.text
        match = re.search(r'action="(/v1/training/([^/]+)/complete)"', opened.text)
        assert match is not None
        completion_path, completion_bearer = match.groups()
        open_bearer = training_path.rsplit("/", 1)[1]
        assert completion_bearer != open_bearer
        assert client.post(training_path + "/complete", data={"answer": correct}).status_code == 404
        assert client.get("/v1/training/" + completion_bearer).status_code == 404
        assert client.post(completion_path, data={"answer": wrong}).status_code == 422
        assert client.post(completion_path, data={"answer": correct}).status_code == 200
        with factory() as session:
            training = session.scalar(
                select(TrainingAssignment).where(TrainingAssignment.recipient_assignment_id == assignments[0])
            )
            completed_at = training.completed_at
            assert completed_at is not None and training.status == dm.TrainingAssignmentStatus.COMPLETED
            assert training.training_token_hash == training_bearer_verifier(
                open_bearer, TRAINING_KEY, purpose=TrainingBearerPurpose.OPEN
            )
            assert training.training_completion_token_hash == training_bearer_verifier(
                completion_bearer, TRAINING_KEY, purpose=TrainingBearerPurpose.COMPLETE
            )
        assert client.post(completion_path).status_code == 200
        assert client.get(training_path).status_code == 200
        assert client.get(click_path, follow_redirects=False).status_code == 302
    with factory() as session:
        training = session.scalar(
            select(TrainingAssignment).where(TrainingAssignment.recipient_assignment_id == assignments[0])
        )
        assert training.completed_at == completed_at
        events = session.scalars(select(TrackingEvent).where(TrackingEvent.campaign_id == campaign_id)).all()
        assert len(events) == 4
        assert {event.event_type for event in events} == {
            dm.EventType.CLICKED,
            dm.EventType.TRAINING_STARTED,
            dm.EventType.HUMAN_INTERACTION_CONFIRMED,
            dm.EventType.TRAINING_COMPLETED,
        }


@pytest.mark.parametrize("kind", ("roe", "training"))
def test_actual_delivery_authorization_shared_locks_require_only_identity_column_update(subject, kind):
    campaign_id, _, factory, engines, _ = subject
    with factory() as session:
        campaign = session.get(Campaign, campaign_id)
        identifier = campaign.roe_id if kind == "roe" else campaign.training_resource_id
    model = RulesOfEngagement if kind == "roe" else TrainingResource
    with make_session_factory(engines["delivery"])() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_worker_delivery"
        row = session.get(model, identifier, with_for_update={"read": True}, populate_existing=True)
        assert row is not None


def test_lock_grants_do_not_authorize_revocation_content_approval_or_campaign_business_writes(subject):
    _, _, _, engines, _ = subject
    for column in ("revoked_at", "target_domains", "signature", "window_end"):
        _deny(engines["delivery"], f"UPDATE public.rules_of_engagement SET {column}={column} WHERE false")  # noqa: S608
    for role in ("delivery", "tracking"):
        for column in ("content", "version", "approval_state", "requires_completion"):
            _deny(engines[role], f"UPDATE public.training_resources SET {column}={column} WHERE false")  # noqa: S608
    for column in ("state", "current_template_id", "training_resource_id", "roe_id", "title"):
        _deny(engines["tracking"], f"UPDATE public.campaigns SET {column}={column} WHERE false")  # noqa: S608


def test_additive_authority_lock_migration_preserves_existing_logins_and_narrow_scope(managed_database):
    _, admin, _, _ = managed_database
    with admin.begin() as connection:
        before = connection.execute(
            text(
                "SELECT oid,rolpassword,rolinherit,rolcanlogin FROM pg_authid "
                "WHERE rolname IN ('kp_worker_delivery','kp_tracking') ORDER BY rolname"
            )
        ).all()
        for role, table, identity in (
            ("kp_worker_delivery", "rules_of_engagement", "roe_id"),
            ("kp_worker_delivery", "training_resources", "training_resource_id"),
            ("kp_tracking", "campaigns", "campaign_id"),
            ("kp_tracking", "training_resources", "training_resource_id"),
        ):
            connection.execute(text(f"REVOKE UPDATE({identity}) ON public.{table} FROM {role}"))  # noqa: S608
        _upgrade(connection)
        assert (
            connection.execute(
                text(
                    "SELECT oid,rolpassword,rolinherit,rolcanlogin FROM pg_authid "
                    "WHERE rolname IN ('kp_worker_delivery','kp_tracking') ORDER BY rolname"
                )
            ).all()
            == before
        )
        for role, table in (
            ("kp_worker_delivery", "rules_of_engagement"),
            ("kp_worker_delivery", "training_resources"),
            ("kp_tracking", "campaigns"),
            ("kp_tracking", "training_resources"),
        ):
            assert not connection.scalar(
                text("SELECT has_table_privilege(:role,:table,'UPDATE')"), {"role": role, "table": "public." + table}
            )
