from __future__ import annotations

from pathlib import Path

from kp_operator_api.routers import router

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text()


def test_console_exposes_gui_only_audience_workflow() -> None:
    assert 'api("/audience-groups")' in APP
    assert 'method: existing ? "PUT" : "POST"' in APP
    assert "/audience/preview" in APP
    assert "/audience/freeze" in APP
    assert "Freeze exact audience" in APP
    assert "sample_seed" in APP
    assert "No free-form queries are accepted" in APP


def test_console_uses_server_authority_after_the_audience_is_frozen() -> None:
    assert "if (c.can_submit === true)" in APP
    assert "if (c.can_schedule === true)" in APP
    assert "if (c.can_publish === true)" in APP
    assert 'typeof resource[flag] === "boolean"' in APP
    assert "if (!actionAuthorityValid)" in APP
    assert 'text: c.audience_frozen ? `frozen v${c.audience_version}` : "not frozen"' in APP


def test_operator_api_exposes_bounded_gui_audience_contract() -> None:
    routes = {(method, route.path) for route in router.routes for method in route.methods or set()}

    assert ("GET", "/api/v1/audience-groups") in routes
    assert ("POST", "/api/v1/audience-groups") in routes
    assert ("PUT", "/api/v1/audience-groups/{group_id}") in routes
    assert ("GET", "/api/v1/campaigns/{campaign_id}/audience") in routes
    assert ("PUT", "/api/v1/campaigns/{campaign_id}/audience") in routes
    assert ("GET", "/api/v1/campaigns/{campaign_id}/audience/preview") in routes
    assert ("POST", "/api/v1/campaigns/{campaign_id}/audience/freeze") in routes
