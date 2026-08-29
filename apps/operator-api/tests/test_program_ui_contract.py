from __future__ import annotations

from pathlib import Path

from fastapi.routing import APIRoute
from kp_operator_api.program_routes import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
PROGRAM_VIEW = APP[
    APP.index("/* ---------- finite campaign programs ---------- */") : APP.index(
        "/* ---------- sending domains & rules of engagement ----------"
    )
]


def test_program_api_routes_match_gui_contract() -> None:
    routes = {
        (method, route.path)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert routes == {
        ("POST", "/api/v1/programs"),
        ("GET", "/api/v1/programs"),
        ("GET", "/api/v1/programs/{program_id}"),
        ("POST", "/api/v1/programs/{program_id}/pause"),
        ("POST", "/api/v1/programs/{program_id}/resume"),
    }


def test_program_planner_is_a_complete_gui_workflow() -> None:
    assert '["programs", "Programs"]' in APP
    assert "views.programs = async (root) =>" in PROGRAM_VIEW
    assert 'boundedCollection("/programs")' in PROGRAM_VIEW
    assert "api(`/programs/${program.campaign_program_id}`)" in PROGRAM_VIEW
    assert "source_campaign_id" in PROGRAM_VIEW
    assert "cadence_days" in PROGRAM_VIEW
    assert "occurrence_count" in PROGRAM_VIEW
    assert "expected_version: program.version" in PROGRAM_VIEW
    assert 'name: "rationale"' in PROGRAM_VIEW
    assert 'Date.parse(campaign.schedule_start || "") > Date.now()' in PROGRAM_VIEW
    assert 'result.created ? "Finite campaign program created" : "Existing matching program loaded"' in PROGRAM_VIEW


def test_program_planner_shows_exact_utc_and_independent_review_boundaries() -> None:
    assert "formatUtcInstant" in PROGRAM_VIEW
    assert "Exact UTC window" in PROGRAM_VIEW
    assert "timeline.occurrences" in PROGRAM_VIEW
    assert "`Run ${occurrence.occurrenceNumber} (UTC)`" in PROGRAM_VIEW
    assert 'el("th", { text: "Start UTC" })' in PROGRAM_VIEW
    assert 'el("th", { text: "End UTC" })' in PROGRAM_VIEW
    assert "Every later occurrence is a separate draft with an unfrozen audience" in PROGRAM_VIEW
    assert "no copied approvals and no Rules-of-Engagement binding" in PROGRAM_VIEW
    assert "Review, freeze, approve and schedule each one from Campaigns" in PROGRAM_VIEW
    assert "does not recall or cancel work that is already scheduled or queued" in PROGRAM_VIEW
    assert "fixed elapsed days in UTC" in PROGRAM_VIEW
    assert "local wall-clock time can shift when daylight-saving time changes" in PROGRAM_VIEW


def test_program_planner_does_not_claim_unimplemented_automation() -> None:
    lowered = PROGRAM_VIEW.lower()
    assert "cron" not in lowered
    assert "rrule" not in lowered
    assert "adaptive" not in lowered
    assert ".innerHTML" not in PROGRAM_VIEW
