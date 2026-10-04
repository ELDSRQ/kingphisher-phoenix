"""`clone_flags` distinguishes originals from working copies for the console."""

from __future__ import annotations

import uuid

from kp_database.models import TemplateVersion
from kp_domain_models import models as dm
from kp_operator_api.content_library import clone_flags


def _tmpl(*, model_id: str = "qwen3-30b-a3b-aggregate", edited: object = None) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        version=1,
        generator_version="t",
        prompt_template_version="t",
        model_id=model_id,
        input_hash="a" * 64,
        raw_proposal={},
        subject="S",
        plain_text="P",
        safe_html="<p>P</p>",
        edited_content=edited,
        approval_state=dm.TemplateApprovalState.DRAFT,
    )


def test_generated_template_is_not_a_clone() -> None:
    assert clone_flags(_tmpl()) == {"is_clone": False, "cloned_from_subject": None}


def test_library_clone_is_flagged_with_source_subject() -> None:
    flags = clone_flags(_tmpl(edited={"cloned_from": str(uuid.uuid4()), "cloned_from_subject": "Q3 Invoice Lure"}))
    assert flags["is_clone"] is True
    assert flags["cloned_from_subject"] == "Q3 Invoice Lure"


def test_real_message_clone_is_flagged_by_model_id() -> None:
    flags = clone_flags(_tmpl(model_id="operator-clone/1"))
    assert flags["is_clone"] is True
    assert flags["cloned_from_subject"] is None
