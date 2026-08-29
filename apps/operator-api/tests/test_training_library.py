from __future__ import annotations

import uuid

import pytest
from kp_authorization import Principal, Role
from kp_database.models import TrainingResource
from kp_domain_models import models as dm
from kp_operator_api.training_library import (
    TrainingResourceCreate,
    TrainingResourceDecision,
    create_training_resource,
    decide_training_resource,
    list_training_resources,
    preview_training_resource,
    submit_training_resource,
)
from kp_telemetry.errors import ConflictError, PermissionDeniedError
from pydantic import ValidationError


class _Session:
    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, TrainingResource] = {}
        self.commits = 0

    def add(self, value: TrainingResource) -> None:
        self.rows[value.training_resource_id] = value

    def get(self, model: object, identifier: uuid.UUID, **kwargs: object) -> TrainingResource | None:
        del model, kwargs
        return self.rows.get(identifier)

    def scalars(self, _statement: object) -> _ScalarRows:
        return _ScalarRows(list(self.rows.values()))

    def commit(self) -> None:
        self.commits += 1


class _ScalarRows:
    def __init__(self, rows: list[TrainingResource]) -> None:
        self.rows = rows

    def all(self) -> list[TrainingResource]:
        return self.rows


class _Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def record(self, **values: object) -> None:
        self.actions.append(str(values["action"]))


def _principal(role: Role, subject_id: uuid.UUID | None = None) -> Principal:
    return Principal(str(subject_id or uuid.uuid4()), {role})


def _resource(state: dm.TemplateApprovalState, *, creator_id: uuid.UUID) -> TrainingResource:
    return TrainingResource(
        training_resource_id=uuid.uuid4(),
        title=f"{state.value.title()} lesson",
        kind="article",
        content="Report suspicious messages.",
        version=1,
        requires_completion=True,
        approval_state=state,
        created_by=creator_id,
    )


@pytest.mark.parametrize(
    "values",
    [
        {"title": " ", "content": "lesson"},
        {"title": "lesson", "content": "\x00"},
        {"title": "lesson\nheader", "content": "lesson"},
        {"title": "lesson", "content": "lesson", "source_ref": "source\rspoof"},
        {"title": "x" * 161, "content": "lesson"},
        {"title": "lesson", "content": "x" * 20_001},
    ],
)
def test_resource_authoring_fields_are_strictly_bounded(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        TrainingResourceCreate(**values)


def test_authority_flags_cannot_be_supplied_in_mutation_requests() -> None:
    with pytest.raises(ValidationError):
        TrainingResourceCreate.model_validate({"title": "Lesson", "content": "Safe text", "can_submit": True})
    with pytest.raises(ValidationError):
        TrainingResourceDecision.model_validate({"decision": "approved", "rationale": "Reviewed", "can_review": True})


_KNOWLEDGE_CHECK = {
    "knowledge_question": "An unexpected message asks you to reset your password. What is the safest response?",
    "knowledge_options": [
        "Verify the request through a trusted, independent channel",
        "Act immediately so the request does not expire",
        "Reply with credentials to prove your identity",
    ],
    "knowledge_answer_index": 0,
}


@pytest.mark.parametrize(
    "values",
    [
        # Partial knowledge check is refused: all-or-nothing.
        {**_KNOWLEDGE_CHECK, "knowledge_question": None},
        {**_KNOWLEDGE_CHECK, "knowledge_options": None},
        {**_KNOWLEDGE_CHECK, "knowledge_answer_index": None},
        # Answer index must point at a real option.
        {**_KNOWLEDGE_CHECK, "knowledge_answer_index": 3},
        # Options must be distinct and bounded.
        {**_KNOWLEDGE_CHECK, "knowledge_options": ["same", "same"]},
        {**_KNOWLEDGE_CHECK, "knowledge_options": ["only one"]},
        {**_KNOWLEDGE_CHECK, "knowledge_options": ["x" * 201, "y"]},
        # Question must contain bounded text.
        {**_KNOWLEDGE_CHECK, "knowledge_question": "   "},
        {**_KNOWLEDGE_CHECK, "knowledge_question": "x" * 501},
        # Options must not contain control characters.
        {**_KNOWLEDGE_CHECK, "knowledge_options": ["ok", "bad\x00option"]},
    ],
)
def test_knowledge_check_authoring_is_strictly_validated(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        TrainingResourceCreate.model_validate({"title": "Lesson", "content": "Safe text", **values})


def test_knowledge_check_is_stored_and_previewed_for_reviewers_only() -> None:
    session = _Session()
    audit = _Audit()
    author = _principal(Role.CAMPAIGN_AUTHOR)
    resource_view = create_training_resource(
        TrainingResourceCreate(title="Verify urgent requests", content="Safe lesson", **_KNOWLEDGE_CHECK),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=author,
    )
    resource_id = uuid.UUID(str(resource_view["training_resource_id"]))
    resource = session.rows[resource_id]
    assert resource.knowledge_question == _KNOWLEDGE_CHECK["knowledge_question"]
    assert resource.knowledge_options == _KNOWLEDGE_CHECK["knowledge_options"]
    assert resource.knowledge_answer_index == 0
    assert resource_view["has_knowledge_check"] is True

    reviewer = _principal(Role.SECURITY_APPROVER)
    preview = preview_training_resource(
        resource_id,
        session=session,  # type: ignore[arg-type]
        principal=reviewer,
    )
    check = preview["knowledge_check"]
    assert check == {
        "question": _KNOWLEDGE_CHECK["knowledge_question"],
        "options": _KNOWLEDGE_CHECK["knowledge_options"],
        "answer_index": 0,
    }
    assert "created_by" not in preview


def test_summary_without_knowledge_check_keeps_legacy_shape() -> None:
    session = _Session()
    audit = _Audit()
    author = _principal(Role.CAMPAIGN_AUTHOR)
    resource_view = create_training_resource(
        TrainingResourceCreate(title="Generic lesson", content="Safe text"),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=author,
    )
    assert resource_view["has_knowledge_check"] is False
    session = _Session()
    resource = TrainingResource(
        training_resource_id=uuid.UUID(str(resource_view["training_resource_id"])),
        title="Generic lesson",
        kind="article",
        content="Safe text",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.DRAFT,
        created_by=uuid.uuid4(),
    )
    session.add(resource)
    preview = preview_training_resource(
        resource.training_resource_id,
        session=session,  # type: ignore[arg-type]
        principal=_principal(Role.SECURITY_APPROVER),
    )
    assert "knowledge_check" not in preview
    assert preview["has_knowledge_check"] is False


def test_resource_lifecycle_is_audited_and_separates_author_from_reviewer() -> None:
    session = _Session()
    audit = _Audit()
    author = _principal(Role.CAMPAIGN_AUTHOR)
    resource_view = create_training_resource(
        TrainingResourceCreate(
            title="  Password reset warning signs  ",
            content="Treat <script>alert('x')</script> as literal training text.",
            source_ref=" internal:lesson-1 ",
        ),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=author,
    )
    resource_id = uuid.UUID(str(resource_view["training_resource_id"]))
    resource = session.rows[resource_id]
    assert resource.title == "Password reset warning signs"
    assert resource.kind == "article"
    assert resource.approval_state == dm.TemplateApprovalState.DRAFT
    assert resource_view["can_submit"] is True
    assert resource_view["can_review"] is False

    submitted = submit_training_resource(
        resource_id,
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=author,
    )
    assert resource.approval_state == dm.TemplateApprovalState.PENDING
    assert submitted["can_submit"] is False
    assert submitted["can_review"] is False
    with pytest.raises(PermissionDeniedError, match="cannot review"):
        decide_training_resource(
            resource_id,
            TrainingResourceDecision(decision="approved", rationale="self review"),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            principal=Principal(author.principal_id, {Role.SECURITY_APPROVER}),
        )

    reviewer = _principal(Role.SECURITY_APPROVER)
    decided = decide_training_resource(
        resource_id,
        TrainingResourceDecision(decision="approved", rationale="safe awareness guidance"),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=reviewer,
    )
    assert decided["approval_state"] == "approved"
    assert decided["can_submit"] is False
    assert decided["can_review"] is True
    assert audit.actions == [
        "training_resource.create",
        "training_resource.submit",
        "training_resource.approved",
    ]

    preview = preview_training_resource(
        resource_id,
        session=session,  # type: ignore[arg-type]
        principal=reviewer,
    )
    assert preview["content_type"] == "text/plain"
    assert preview["html_execution"] is False
    assert "<script>" in str(preview["content"])
    assert preview["can_submit"] is False
    assert preview["can_review"] is True
    assert "created_by" not in preview
    assert "reviewed_by" not in preview


def test_only_approved_resources_can_be_superseded() -> None:
    session = _Session()
    audit = _Audit()
    reviewer = _principal(Role.SECURITY_APPROVER)
    resource = TrainingResource(
        training_resource_id=uuid.uuid4(),
        title="Lesson",
        kind="article",
        content="Report suspicious messages.",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.PENDING,
        created_by=uuid.uuid4(),
    )
    session.add(resource)
    with pytest.raises(ConflictError, match="only an approved"):
        decide_training_resource(
            resource.training_resource_id,
            TrainingResourceDecision(decision="superseded", rationale="replacement available"),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            principal=reviewer,
        )
    resource.approval_state = dm.TemplateApprovalState.APPROVED
    result = decide_training_resource(
        resource.training_resource_id,
        TrainingResourceDecision(decision="superseded", rationale="replacement available"),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=reviewer,
    )
    assert result["approval_state"] == "superseded"
    assert result["can_submit"] is False
    assert result["can_review"] is False


_PERSONAS = (
    ("creator", {Role.CAMPAIGN_AUTHOR}, True),
    ("different_author", {Role.CAMPAIGN_AUTHOR}, False),
    ("pure_reviewer", {Role.SECURITY_APPROVER}, False),
    ("dual_role_creator", {Role.CAMPAIGN_AUTHOR, Role.SECURITY_APPROVER}, True),
    ("administrator", {Role.ADMINISTRATOR}, False),
    ("administrator_creator", {Role.ADMINISTRATOR}, True),
)

_AUTHORITY_MATRIX = {
    dm.TemplateApprovalState.DRAFT: {
        "creator": (True, False),
        "different_author": (False, False),
        "pure_reviewer": (False, False),
        "dual_role_creator": (True, False),
        "administrator": (False, False),
        "administrator_creator": (True, False),
    },
    dm.TemplateApprovalState.PENDING: {
        "creator": (False, False),
        "different_author": (False, False),
        "pure_reviewer": (False, True),
        "dual_role_creator": (False, False),
        "administrator": (False, True),
        "administrator_creator": (False, False),
    },
    dm.TemplateApprovalState.APPROVED: {
        "creator": (False, False),
        "different_author": (False, False),
        "pure_reviewer": (False, True),
        "dual_role_creator": (False, False),
        "administrator": (False, True),
        "administrator_creator": (False, False),
    },
    dm.TemplateApprovalState.REJECTED: {name: (False, False) for name, _roles, _same_author in _PERSONAS},
    dm.TemplateApprovalState.SUPERSEDED: {name: (False, False) for name, _roles, _same_author in _PERSONAS},
}


@pytest.mark.parametrize("state", list(_AUTHORITY_MATRIX))
@pytest.mark.parametrize(("persona", "roles", "same_author"), _PERSONAS)
def test_preview_authority_flags_cover_role_identity_and_state_matrix(
    state: dm.TemplateApprovalState,
    persona: str,
    roles: set[Role],
    same_author: bool,
) -> None:
    creator_id = uuid.uuid4()
    subject_id = creator_id if same_author else uuid.uuid4()
    principal = Principal(str(subject_id), roles)
    session = _Session()
    resource = _resource(state, creator_id=creator_id)
    session.add(resource)

    summary = preview_training_resource(
        resource.training_resource_id,
        session=session,  # type: ignore[arg-type]
        principal=principal,
    )

    assert (summary["can_submit"], summary["can_review"]) == _AUTHORITY_MATRIX[state][persona]
    assert "created_by" not in summary
    assert "reviewed_by" not in summary


def test_list_recomputes_authority_per_resource_without_exposing_identities() -> None:
    creator_id = uuid.uuid4()
    session = _Session()
    draft = _resource(dm.TemplateApprovalState.DRAFT, creator_id=creator_id)
    pending = _resource(dm.TemplateApprovalState.PENDING, creator_id=creator_id)
    session.add(draft)
    session.add(pending)
    principal = _principal(Role.ADMINISTRATOR)

    summaries = list_training_resources(
        approval_state=None,
        limit=100,
        offset=0,
        session=session,  # type: ignore[arg-type]
        principal=principal,
    )

    by_id = {summary["training_resource_id"]: summary for summary in summaries}
    draft_summary = by_id[str(draft.training_resource_id)]
    assert (draft_summary["can_submit"], draft_summary["can_review"]) == (
        False,
        False,
    )
    assert (
        by_id[str(pending.training_resource_id)]["can_submit"],
        by_id[str(pending.training_resource_id)]["can_review"],
    ) == (False, True)
    assert all("created_by" not in summary and "reviewed_by" not in summary for summary in summaries)
