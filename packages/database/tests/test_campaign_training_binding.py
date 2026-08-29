from __future__ import annotations

import hashlib
import importlib.util
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.campaign_service import (
    bind_campaign_training_resource,
    prepare_campaign,
    training_binding_error,
    training_resource_content_digest,
)
from kp_database.models import Campaign, TrainingResource
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0028_campaign_training_binding.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0028", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _campaign() -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid4(),
        pattern_id=uuid4(),
        current_template_id=uuid4(),
        title="Explicit lesson binding",
        state=dm.CampaignState.DRAFT,
        sender_mailbox="awareness@example.com",
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        timezone="UTC",
        max_recipients=10,
        expires_at=now + timedelta(days=2),
    )


def _resource(*, state: dm.TemplateApprovalState = dm.TemplateApprovalState.APPROVED) -> TrainingResource:
    return TrainingResource(
        training_resource_id=uuid4(),
        title="Verify urgent requests",
        kind="article",
        content="Pause and verify the request through a trusted, independent channel.",
        version=4,
        requires_completion=True,
        approval_state=state,
    )


def test_explicit_binding_freezes_resource_version_digest_and_campaign_manifest() -> None:
    campaign = _campaign()
    resource = _resource()

    bind_campaign_training_resource(campaign, resource)

    assert campaign.training_resource_id == resource.training_resource_id
    assert campaign.training_resource_version == 4
    assert campaign.training_resource_digest == training_resource_content_digest(resource)
    assert campaign.manifest_hash is not None and len(campaign.manifest_hash) == 64
    assert training_binding_error(campaign, resource) is None


def test_missing_superseded_or_mutated_binding_fails_closed_with_reconfiguration_action() -> None:
    campaign = _campaign()
    resource = _resource()
    missing = training_binding_error(campaign, None)
    assert missing is not None and "choose an approved lesson" in missing

    bind_campaign_training_resource(campaign, resource)
    resource.approval_state = dm.TemplateApprovalState.SUPERSEDED
    superseded = training_binding_error(campaign, resource)
    assert superseded is not None and "superseded" in superseded and "review the campaign again" in superseded

    resource.approval_state = dm.TemplateApprovalState.APPROVED
    resource.content = "Different content"
    mutated = training_binding_error(campaign, resource)
    assert mutated is not None and "content changed after review" in mutated


def test_launch_preparation_rechecks_resource_approval_before_creating_assignments() -> None:
    campaign = _campaign()
    campaign.state = dm.CampaignState.APPROVED
    resource = _resource()
    bind_campaign_training_resource(campaign, resource)
    resource.approval_state = dm.TemplateApprovalState.SUPERSEDED

    class _Session:
        def scalar(self, statement: object) -> Campaign:
            return campaign

        def get(self, model: object, identifier: object, **kwargs: object) -> TrainingResource | None:
            return resource if identifier == resource.training_resource_id else None

    with pytest.raises(ConflictError, match="superseded"):
        prepare_campaign(
            _Session(),  # type: ignore[arg-type]
            campaign,
            tracking_base_url="https://training.example.com",
            token_hmac_key=b"t" * 32,
        )


def test_migration_is_linear_additive_and_does_not_guess_legacy_review_evidence() -> None:
    migration = _load_migration()
    assert migration.revision == "0028_campaign_training_binding"
    assert migration.down_revision == "0027_recipient_exclusions"
    source = MIGRATION.read_text(encoding="utf-8")
    assert "UPDATE campaigns" not in source
    assert "DELETE FROM" not in source

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)
    migration.upgrade()
    sql = output.getvalue()
    assert "training_resource_version" in sql
    assert "training_resource_digest" in sql
    assert sql.count("NOT VALID") == 2


def test_model_keeps_legacy_binding_evidence_nullable_for_fail_closed_reconfiguration() -> None:
    assert Campaign.__table__.c.training_resource_version.nullable
    assert Campaign.__table__.c.training_resource_digest.nullable


def test_digest_is_backward_compatible_without_knowledge_check() -> None:
    """A lesson without a knowledge check keeps the legacy content digest.

    TRN-010 must not strand already-bound campaigns: the digest computation
    changes only for lessons that actually carry a knowledge check.
    """

    import hashlib

    resource = _resource()
    assert training_resource_content_digest(resource) == hashlib.sha256(resource.content.encode("utf-8")).hexdigest()


def test_digest_pins_knowledge_check_when_present() -> None:
    resource = _resource()
    resource.knowledge_question = "An unexpected message asks you to reset your password. What is the safest response?"
    resource.knowledge_options = [
        "Verify the request through a trusted, independent channel",
        "Act immediately so the request does not expire",
        "Reply with credentials to prove your identity",
    ]
    resource.knowledge_answer_index = 0
    content_only = hashlib.sha256(resource.content.encode("utf-8")).hexdigest()
    with_check = training_resource_content_digest(resource)
    assert with_check != content_only
    assert len(with_check) == 64

    # Any post-review change to the question, options, or answer index
    # invalidates the digest, so a campaign binding fails closed.
    bound = _campaign()
    bind_campaign_training_resource(bound, resource)
    assert training_binding_error(bound, resource) is None

    resource.knowledge_answer_index = 1
    assert training_binding_error(bound, resource) is not None
    assert "content changed after review" in training_binding_error(bound, resource)  # type: ignore[operator]


def test_knowledge_check_columns_are_all_or_nothing_in_the_model() -> None:
    assert TrainingResource.__table__.c.knowledge_question.nullable
    assert TrainingResource.__table__.c.knowledge_options.nullable
    assert TrainingResource.__table__.c.knowledge_answer_index.nullable


def test_migration_0033_adds_knowledge_check_with_all_or_nothing_constraint() -> None:
    migration_path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0033_training_knowledge_check.py"
    spec = importlib.util.spec_from_file_location("migration_0033", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.revision == "0033_training_knowledge_check"
    assert migration.down_revision == "0032_source_explicit_curation"

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)
    migration.upgrade()
    sql = output.getvalue()
    assert "knowledge_question" in sql
    assert "knowledge_options" in sql
    assert "knowledge_answer_index" in sql
    assert "knowledge_check_all_or_nothing" in sql
    assert {
        "ck_campaigns_training_resource_version_positive",
        "ck_campaigns_training_resource_digest_hex",
    } <= {str(constraint.name) for constraint in Campaign.__table__.constraints}
