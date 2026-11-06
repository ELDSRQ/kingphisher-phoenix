"""Delivery exclusion filtering and least privilege with actual role logins.

Only uniquely named preserved synthetic PostgreSQL databases are used. No
transport is contacted, and canonical role provisioning is serialized by hand.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.campaign_service import _excluded_recipient_ids
from kp_database.models import RecipientAssignment, RecipientExclusion, TrackingToken
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_workers.jobs import _gate_delivery_recipient
from sqlalchemy import text
from test_adaptive_program_iterations import _recipient
from test_runtime_feature_role_effects import _deny
from test_runtime_feature_role_effects import managed_database as _managed_database
from test_runtime_feature_role_effects import subject as _subject

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _subject.__wrapped__(managed_database)


def test_actual_delivery_filters_only_active_global_or_matching_campaign_exclusions(subject):
    campaign_id, _, factory, engines, _ = subject
    now = datetime.now(UTC)
    with factory() as session:
        recipients = [_recipient(f"exclusion-{uuid4().hex}@example.test") for _ in range(5)]
        session.add_all(recipients)
        session.flush()
        for index, recipient in enumerate(recipients):
            session.add(
                RecipientExclusion(
                    recipient_exclusion_id=uuid4(),
                    recipient_id=recipient.recipient_id,
                    exclusion_type=dm.ExclusionType.GLOBAL if index == 0 else dm.ExclusionType.CAMPAIGN_SPECIFIC,
                    campaign_id=None if index == 0 else (uuid4() if index == 4 else campaign_id),
                    expires_at=now - timedelta(days=1) if index == 2 else now + timedelta(days=1),
                    revoked_at=now if index == 3 else None,
                    reason="synthetic private reason",
                    created_by=uuid4(),
                    revoke_reason="synthetic private revocation reason" if index == 3 else None,
                    revoked_by=uuid4() if index == 3 else None,
                )
            )
        session.commit()
        expected = {recipient.recipient_id for recipient in recipients[:2]}
    with make_session_factory(engines["delivery"])() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_worker_delivery"
        assert not session.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
        assert _excluded_recipient_ids(session, campaign_id) == expected


def test_actual_delivery_rechecks_post_enqueue_exclusion_before_claim_or_transport(subject):
    campaign_id, assignments, factory, engines, _ = subject
    with factory() as session:
        assignment = session.get(RecipientAssignment, assignments[0])
        recipient_id = assignment.recipient_id
        session.add(
            TrackingToken(
                token_id=uuid4(),
                token_hash=uuid4().hex + uuid4().hex,
                token_prefix="qual58",
                campaign_id=campaign_id,
                recipient_assignment_id=assignments[0],
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        session.commit()  # assignment/token already queued before the exclusion exists
        session.add(
            RecipientExclusion(
                recipient_exclusion_id=uuid4(),
                recipient_id=recipient_id,
                exclusion_type=dm.ExclusionType.CAMPAIGN_SPECIFIC,
                campaign_id=campaign_id,
                reason="synthetic post-publication exclusion",
            )
        )
        session.commit()
    with make_session_factory(engines["delivery"])() as session:
        outcome = _gate_delivery_recipient(
            session,
            {},
            SimpleNamespace(),
            str(assignments[0]),
            campaign_id=campaign_id,
            excluded_ids=_excluded_recipient_ids(session, campaign_id),
        )
        assert outcome.target is None and outcome.blocked == 1 and outcome.commit
        session.commit()
    with factory() as session:
        assignment = session.get(RecipientAssignment, assignments[0])
        assert assignment.send_state == dm.SendState.EXPIRED
        assert assignment.failure_reason == "recipient_excluded"
        assert assignment.delivery_attempt_id is None


def test_delivery_cannot_read_private_exclusion_fields_or_mutate_exclusions(subject):
    _, _, _, engines, _ = subject
    for column in ("reason", "revoke_reason", "created_by", "revoked_by", "recipient_exclusion_id", "created_at"):
        _deny(engines["delivery"], f"SELECT {column} FROM public.recipient_exclusions")  # noqa: S608
    for statement in (
        "SELECT * FROM public.recipient_exclusions",
        "UPDATE public.recipient_exclusions SET revoked_at=now() WHERE false",
        "DELETE FROM public.recipient_exclusions WHERE false",
        "INSERT INTO public.recipient_exclusions(recipient_id) VALUES (NULL)",
    ):
        _deny(engines["delivery"], statement)
    for role in ("tracking", "generation"):
        _deny(engines[role], "SELECT recipient_id,revoked_at,expires_at,campaign_id FROM public.recipient_exclusions")


def test_additive_exclusion_migration_regrants_existing_login_without_broadening(managed_database):
    _, admin, _, _ = managed_database
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0058_delivery_exclusion_grants.py"
    spec = importlib.util.spec_from_file_location("exclusion_grants_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with admin.begin() as connection:
        before = connection.execute(
            text("SELECT oid,rolpassword,rolinherit,rolcanlogin FROM pg_authid WHERE rolname='kp_worker_delivery'")
        ).one()
        connection.execute(
            text(
                "REVOKE SELECT(recipient_id,revoked_at,expires_at,campaign_id) "
                "ON public.recipient_exclusions FROM kp_worker_delivery"
            )
        )
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert (
            connection.execute(
                text("SELECT oid,rolpassword,rolinherit,rolcanlogin FROM pg_authid WHERE rolname='kp_worker_delivery'")
            ).one()
            == before
        )
        for column in ("recipient_id", "revoked_at", "expires_at", "campaign_id"):
            assert connection.scalar(
                text(
                    "SELECT has_column_privilege('kp_worker_delivery','public.recipient_exclusions',:column,'SELECT')"
                ),
                {"column": column},
            )
        assert not connection.scalar(
            text("SELECT has_table_privilege('kp_worker_delivery','public.recipient_exclusions','SELECT')")
        )
        assert not connection.scalar(
            text("SELECT has_column_privilege('kp_worker_delivery','public.recipient_exclusions','reason','SELECT')")
        )
