from uuid import uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_database.models import TemplateVersion
from kp_domain_models import models as dm
from kp_operator_api.content_library import ContentClone, clone_template
from kp_operator_api.routes.patterns import _require_approvable_template_content
from kp_safety_validation.validator import SafetyValidator
from kp_telemetry.errors import SafetyRejectionError, ValidationError_


class Session:
    def __init__(self, source):
        self.source = source
        self.info = {"safety_validator": SafetyValidator(training_domains={"training.example"})}
        self.added = []
        self.commits = 0

    def get(self, model, identifier):
        return self.source

    def add(self, value):
        self.added.append(value)

    def commit(self):
        self.commits += 1


class Audit:
    def record(self, **kwargs):
        pass


def source_template():
    return TemplateVersion(
        template_version_id=uuid4(),
        subject="Original",
        plain_text="Original words",
        safe_html="<p>Original words</p>",
        raw_proposal={},
        version=1,
        model_id="synthetic",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )


def test_wording_copy_changes_both_alternatives_and_keeps_original_approved():
    source = source_template()
    session = Session(source)
    response = clone_template(
        source.template_version_id,
        ContentClone(reason="Adapt", subject="New", plain_text="New words"),
        session,
        Audit(),
        Principal(str(uuid4()), {Role.ADMINISTRATOR}),
    )
    draft = session.added[0]
    assert source.subject == "Original" and source.plain_text == "Original words"
    assert source.approval_state == dm.TemplateApprovalState.APPROVED
    assert draft.subject == "New" and draft.plain_text.startswith("New words")
    assert "{{ tracking.training_url }}" in draft.plain_text
    assert "New words" in draft.safe_html and "Original words" not in draft.safe_html
    assert "{{ tracking.training_url }}" in draft.safe_html
    assert draft.approval_state == dm.TemplateApprovalState.DRAFT
    assert draft.approval_hash is None and draft.campaign_id is None
    assert response["requires_human_review"] is True
    _require_approvable_template_content(draft)


@pytest.mark.parametrize("wording", ["Visit https://evil.example/harvest", "<script>alert(1)</script>"])
def test_unsafe_wording_never_persists_a_copy(wording):
    source = source_template()
    session = Session(source)
    with pytest.raises(SafetyRejectionError):
        clone_template(
            source.template_version_id,
            ContentClone(reason="Adapt", plain_text=wording),
            session,
            Audit(),
            Principal(str(uuid4()), {Role.ADMINISTRATOR}),
        )
    assert not session.added and session.commits == 0


@pytest.mark.parametrize("wording", ["&" * 40_000, "a" * 200_000])
def test_rebuilt_html_over_preview_boundary_never_persists_a_copy(wording):
    source = source_template()
    session = Session(source)
    with pytest.raises(ValidationError_, match="supported preview boundary"):
        clone_template(
            source.template_version_id,
            ContentClone(reason="Adapt", plain_text=wording),
            session,
            Audit(),
            Principal(str(uuid4()), {Role.ADMINISTRATOR}),
        )
    assert not session.added and session.commits == 0
