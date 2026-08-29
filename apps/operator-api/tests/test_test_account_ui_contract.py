from __future__ import annotations

from pathlib import Path

from fastapi.routing import APIRoute
from kp_operator_api.routers import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
RECIPIENT_VIEW = APP[
    APP.index("/* ---------- recipients ---------- */") : APP.index("/* ---------- privacy ---------- */")
]


def test_recipient_view_uses_only_server_designation_state() -> None:
    assert "Server-designated test account" in APP
    assert "The console never infers eligibility from mailbox text, names, or departments" in APP
    assert "r.is_test_account" in APP
    assert "+test@example.com" not in APP
    assert 'el("th", { text: "Recipient reference" })' in APP
    assert "r.mailbox" not in RECIPIENT_VIEW


def test_designation_mutation_has_high_friction_confirmation_and_bounded_reason() -> None:
    assert "changeTestAccountDesignation" in APP
    assert "`DESIGNATE ${reference}`" in APP
    assert "maxLength: 500" in APP
    assert "maxlength: field.maxLength" in APP
    assert 'input.setAttribute("aria-describedby", helpId)' in APP
    assert "is_test_account: adding" in APP
    assert "confirm: true" in APP
    assert "reason: values.reason" in APP
    assert 'method: "PUT"' in APP
    assert "/test-account`" in APP


def test_designation_result_and_campaign_lock_are_honestly_presented() -> None:
    assert "Designation was already" in APP
    assert "no change was made" in APP
    assert "err.status === 409" in APP
    assert "frozen audience or assignment for a nonterminal campaign" in APP
    assert "await render()" in APP


def test_designation_controls_are_keyboard_and_screen_reader_accessible() -> None:
    assert '"aria-label": "Authorized recipient records and test-account designations"' in APP
    assert 'type: "button"' in APP
    assert '"aria-label": `${r.is_test_account ?' in APP
    assert "textContent only" in APP
    assert "innerHTML" in APP  # appears only in the explicit prohibition comment
    assert ".innerHTML" not in APP


def test_operator_api_route_matches_gui_contract() -> None:
    routes = {
        (method, route.path)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }

    assert ("PUT", "/api/v1/recipients/{recipient_id}/test-account") in routes
