"""DEP-010 P2 — static monthly cost estimate (unit + wiring contract)."""

from __future__ import annotations

from pathlib import Path

from kp_operator_api.console.deployment_cost import estimate_monthly_cost

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_ROUTES = (
    _REPOSITORY_ROOT / "apps" / "operator-api" / "src" / "kp_operator_api" / "console" / "azure_deployment_routes.py"
).read_text(encoding="utf-8")
_APP_JS = (_REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console-js" / "app.js").read_text(encoding="utf-8")


def test_default_estimate_is_a_bounded_staging_range() -> None:
    est = estimate_monthly_cost({})
    assert est["currency"] == "USD"
    assert est["period"] == "month"
    assert est["environment"] == "staging"
    assert est["line_items"], "expected per-resource line items"
    assert 0 < est["monthly_low"] <= est["monthly_high"]
    # Sum of line items equals the reported range.
    assert round(sum(i["monthly_low"] for i in est["line_items"]), 2) == est["monthly_low"]
    assert round(sum(i["monthly_high"] for i in est["line_items"]), 2) == est["monthly_high"]
    assert est["disclaimer"]
    assert est["usage_notes"]


def test_production_costs_more_than_staging() -> None:
    staging = estimate_monthly_cost({"environment": "staging"})
    production = estimate_monthly_cost({"environment": "production"})
    assert production["environment"] == "production"
    assert production["monthly_low"] > staging["monthly_low"]
    assert production["monthly_high"] > staging["monthly_high"]


def test_runner_vm_line_only_for_private_mode() -> None:
    private = estimate_monthly_cost({"network_mode": "private"})
    starter = estimate_monthly_cost({"network_mode": "starter"})
    assert any("runner" in i["resource"].lower() for i in private["line_items"])
    assert not any("runner" in i["resource"].lower() for i in starter["line_items"])
    # Dropping the always-on runner VM lowers the floor.
    assert starter["monthly_low"] < private["monthly_low"]


def test_usage_metered_charges_are_excluded_from_the_range_and_noted() -> None:
    est = estimate_monthly_cost({})
    joined = " ".join(est["usage_notes"]).lower()
    assert "acs" in joined and "email" in joined  # ACS email is usage-metered, not in the range
    assert "excludes usage-metered" in est["disclaimer"].lower()


def test_validate_response_wires_the_cost_estimate() -> None:
    assert "from kp_operator_api.console.deployment_cost import estimate_monthly_cost" in _ROUTES
    assert '"cost_estimate": estimate_monthly_cost(values),' in _ROUTES


def test_wizard_renders_the_cost_estimate() -> None:
    assert "result.cost_estimate" in _APP_JS
    assert "Estimated monthly cost" in _APP_JS
