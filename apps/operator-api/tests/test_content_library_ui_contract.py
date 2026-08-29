from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from kp_operator_api.routers import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")


def test_library_gui_exposes_bounded_server_filters_and_clear_review_state() -> None:
    assert "Template library & review" in APP
    assert "Campaign-pattern library" in APP
    assert 'new URLSearchParams({ limit: "100" })' in APP
    assert 'params.set("approval_state"' in APP
    assert 'params.set("lure_category"' in APP
    assert 'params.set("difficulty_score"' in APP
    assert "Approved reusable" in APP
    assert "human review required" in APP


def test_library_gui_clones_only_to_draft_with_required_audit_reason() -> None:
    assert APP.count('text: "Clone as draft"') >= 2
    assert APP.count('name: "reason", label: "Audit reason"') >= 2
    assert APP.count("maxLength: 500") >= 2
    assert "/clone`" in APP
    assert "New DRAFT created" in APP
    assert "never copies a campaign binding" in APP
    assert "Independent human approval is required" in APP


def test_library_preview_never_executes_returned_html() -> None:
    assert "showLibraryTemplatePreview" in APP
    assert "safe_html_present" in APP
    assert "deliberately not executed in the operator console" in APP
    assert "Supporting source evidence is deliberately excluded" in APP
    assert ".innerHTML" not in APP


def test_library_route_contracts_are_wired() -> None:
    app = FastAPI()
    app.include_router(router)
    schema_paths = app.openapi()["paths"]
    routes = {(method.upper(), path) for path, operations in schema_paths.items() for method in operations}
    assert ("GET", "/api/v1/templates") in routes
    assert ("GET", "/api/v1/templates/{template_version_id}/preview") in routes
    assert ("POST", "/api/v1/templates/{template_version_id}/clone") in routes
    assert ("GET", "/api/v1/patterns") in routes
    assert ("GET", "/api/v1/patterns/{pattern_id}/preview") in routes
    assert ("POST", "/api/v1/patterns/{pattern_id}/clone") in routes
