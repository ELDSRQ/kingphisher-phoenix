from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from kp_operator_api.training_library import router as training_library_router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
TRAINING = APP[
    APP.index("/* ---------- training resource library ---------- */") : APP.index(
        "/* ---------- recipients ---------- */"
    )
]


def test_training_navigation_and_view_use_either_existing_capability() -> None:
    assert '["training", "Training lessons"]' in APP
    assert "training: [CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE]" in APP
    assert "requireAnyCapability(root, CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE)" in TRAINING
    assert "const canAuthorTraining = hasCapability(CAPABILITY.CREATE_CAMPAIGN);" in TRAINING
    assert "const canReviewTraining" not in TRAINING


def test_training_actions_are_driven_only_by_strict_server_resource_flags() -> None:
    assert "if (canAuthorTraining) controls.unshift" in TRAINING
    assert 'typeof resource.can_submit !== "boolean"' in TRAINING
    assert 'typeof resource.can_review !== "boolean"' in TRAINING
    assert "resources = payload.map(trainingResourceWithServerActions);" in TRAINING
    assert 'if (resource.can_submit === true && resource.approval_state === "draft")' in TRAINING
    assert 'if (resource.can_review === true && resource.approval_state === "pending")' in TRAINING
    assert 'if (resource.can_review === true && resource.approval_state === "approved")' in TRAINING
    assert "canAuthorTraining && resource" not in TRAINING
    assert "canReviewTraining" not in TRAINING
    assert 'text: "Safe text preview"' in TRAINING
    assert 'text: "Create training lesson"' in TRAINING
    assert 'text: "Submit for review"' in TRAINING
    assert 'text: "Approve"' in TRAINING
    assert 'text: "Reject"' in TRAINING
    assert 'text: "Supersede for future campaigns"' in TRAINING
    assert "canAuthorTraining || canReviewTraining" not in TRAINING


def test_creator_and_reviewer_combinations_fail_closed_from_response_flags() -> None:
    # A dual-role creator receives can_review=false, a different author receives
    # can_submit=false, and a pure reviewer receives can_review=true. The DOM
    # consults only those exact booleans, never reconstructing those identities.
    assert TRAINING.count("resource.can_submit === true") == 1
    assert TRAINING.count("resource.can_review === true") == 2
    assert "resource.created_by" not in TRAINING
    assert "sessionInfo().principal" not in TRAINING
    assert "hasCapability(CAPABILITY.APPROVE_TEMPLATE)" not in TRAINING
    assert 'resource.approval_state === "pending"' in TRAINING
    assert 'resource.approval_state === "approved"' in TRAINING
    assert 'resource.approval_state === "draft"' in TRAINING


def test_list_preview_and_every_mutation_validate_server_action_flags() -> None:
    assert "const preview = trainingResourceWithServerActions(" in TRAINING
    assert "resources = payload.map(trainingResourceWithServerActions);" in TRAINING
    assert TRAINING.count("trainingResourceWithServerActions(") == 5
    assert TRAINING.count("err.invalidTrainingActionAuthority") == 3
    assert TRAINING.count("await loadResources();") == 7
    assert "Training action authority is unavailable. Refresh before taking any action." in TRAINING


def test_training_api_paths_and_methods_exactly_match_the_backend() -> None:
    app = FastAPI()
    app.include_router(training_library_router)
    actual = {(method.upper(), path) for path, operations in app.openapi()["paths"].items() for method in operations}
    assert actual == {
        ("GET", "/api/v1/training-resources"),
        ("GET", "/api/v1/training-resources/{training_resource_id}/preview"),
        ("POST", "/api/v1/training-resources"),
        ("POST", "/api/v1/training-resources/{training_resource_id}/submit"),
        ("POST", "/api/v1/training-resources/{training_resource_id}/decision"),
    }
    assert "boundedCollection(`/training-resources?${params.toString()}`)" in TRAINING
    assert "api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/preview`)" in TRAINING
    assert 'await api("/training-resources", {' in TRAINING
    assert "api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/submit`, {" in TRAINING
    assert "api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/decision`, {" in TRAINING
    assert TRAINING.count('method: "POST"') == 3
    assert "JSON.stringify({ decision, rationale: values.rationale })" in TRAINING


def test_training_preview_is_explicit_text_and_never_executes_lesson_markup() -> None:
    assert 'text: preview.content || "(empty lesson)"' in TRAINING
    assert 'text: "Plain text"' in TRAINING
    assert "Markup-like characters are never executed" in TRAINING
    assert "innerHTML" not in TRAINING
    assert "safe_html" not in TRAINING
    assert "iframe" not in TRAINING.lower()


def test_training_mutations_require_review_ui_and_refresh_all_states() -> None:
    assert 'name: "rationale", label: "Review rationale"' in TRAINING
    assert "maxLength: 1000" in TRAINING
    assert "const confirmed = await confirmDialog" in TRAINING
    assert "A resource author cannot review their own lesson." in TRAINING
    assert "Campaigns already bound to it keep their immutable assignment." in TRAINING
    assert TRAINING.count("await loadResources();") == 7
    assert "Loading training lessons…" in TRAINING
    assert "Could not load training lessons:" in TRAINING
    assert "No training lessons match this review state." in TRAINING
    assert "Could not preview training lesson:" in TRAINING
    assert "Could not submit training lesson:" in TRAINING
    assert "Could not record training review:" in TRAINING
    assert "Could not create training lesson:" in TRAINING


def test_training_authoring_fields_match_server_boundaries() -> None:
    assert 'name: "title", label: "Lesson title", required: true, maxLength: 160' in TRAINING
    assert 'name: "content", label: "Lesson text", type: "textarea", required: true, maxLength: 20000' in TRAINING
    assert 'name: "source_ref", label: "Non-secret source reference (optional)", maxLength: 500' in TRAINING
    assert "source_ref: values.source_ref || null" in TRAINING
    assert 'const params = new URLSearchParams({ limit: "100" });' in TRAINING
