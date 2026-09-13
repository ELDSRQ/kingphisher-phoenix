"""DEP-010 static monthly-cost estimate for an Azure deployment.

The wizard used to show only a *time* estimate per stage. This adds a bounded,
non-binding **spend** estimate computed from the known resource set and the
operator's reviewed configuration — no live pricing API call (that would add an
egress path the console deliberately does not have).

The numbers are deliberately conservative ranges in USD/month for the East US 2
region, rounded, and clearly labelled as estimates. They intentionally EXCLUDE
usage-metered charges (ACS email volume, data egress, Log Analytics ingestion),
which are surfaced as separate usage notes rather than folded into the range.
Keep these figures easy to audit; they are guidance for the operator, never a
contractual quote.
"""

from __future__ import annotations

from typing import Any

# Rough always-on monthly USD ranges (low, high) for the fixed resource set.
# Container Apps with a kept replica bill continuously; scale-to-zero ones bill
# only on use and are shown near zero. Sources are Azure public list prices as
# of 2026; treat as estimates, not quotes.
_CONTAINER_APP_ACTIVE = (25.0, 45.0)  # per always-on small app (0.5 vCPU / 1 GiB)
_CONTAINER_APP_SCALE_TO_ZERO = (0.0, 8.0)  # ai-gateway: scale-to-zero
_POSTGRES_FLEXIBLE = (15.0, 70.0)  # burstable B-series flexible server
_REDIS_BASIC = (16.0, 55.0)  # Basic/Standard small cache
_KEY_VAULT = (0.0, 3.0)
_STORAGE = (1.0, 6.0)  # tfstate + runtime blobs
_LOG_ANALYTICS = (0.0, 10.0)  # low ingestion
_RUNNER_VM_NIGHTLY = (20.0, 45.0)  # D2s_v7 with nightly shutdown (~part-day)
_RUNNER_VM_ALWAYS_ON = (60.0, 95.0)  # if the nightly shutdown is disabled


def _line(resource: str, low: float, high: float, note: str = "") -> dict[str, Any]:
    return {"resource": resource, "monthly_low": round(low, 2), "monthly_high": round(high, 2), "note": note}


def estimate_monthly_cost(values: dict[str, str] | None = None) -> dict[str, Any]:
    """Return a bounded monthly-cost estimate for the reviewed configuration.

    ``values`` is the wizard's non-secret field map (as sent to /validate); only
    a few keys affect the estimate (environment, the two optional worker roles,
    network_mode). Missing/unknown values fall back to the standard staging path.
    """
    values = values or {}
    production = values.get("environment") == "production"
    # Production runs the operator + tracking at min 2 replicas (see main.tf);
    # staging runs a single replica each. The worker and migration job are one
    # each; ai-gateway is scale-to-zero in every environment.
    always_on_apps = 4 if production else 3  # operator, tracking, worker (+1 replica set in prod)

    line_items: list[dict[str, Any]] = [
        _line(
            f"Container Apps ({always_on_apps} always-on)",
            _CONTAINER_APP_ACTIVE[0] * always_on_apps,
            _CONTAINER_APP_ACTIVE[1] * always_on_apps,
            "operator + tracking + worker" + (" (min 2 replicas in production)" if production else ""),
        ),
        _line("AI gateway (scale-to-zero)", *_CONTAINER_APP_SCALE_TO_ZERO, "bills only while generating"),
        _line("PostgreSQL flexible server", *_POSTGRES_FLEXIBLE, "burstable tier; larger under load"),
        _line("Redis cache", *_REDIS_BASIC),
        _line("Key Vault", *_KEY_VAULT),
        _line("Storage (tfstate + runtime)", *_STORAGE),
        _line("Log Analytics / App Insights", *_LOG_ANALYTICS, "low ingestion; usage-metered"),
    ]

    # The self-hosted VNet runner only exists for private-mode deployments.
    if values.get("network_mode", "private") == "private":
        line_items.append(
            _line(
                "CI runner VM (D2s_v7)",
                *_RUNNER_VM_NIGHTLY,
                "with the nightly shutdown; ~2x if left always-on",
            )
        )

    low = sum(item["monthly_low"] for item in line_items)
    high = sum(item["monthly_high"] for item in line_items)

    usage_notes = [
        "ACS email is billed per message sent plus data — not included in the range above.",
        "Data egress and Log Analytics ingestion are usage-metered and vary with activity.",
    ]
    if values.get("enable_directory_sync") == "true":
        usage_notes.append("Microsoft Graph directory sync uses your existing Entra tenant (no added Azure charge).")

    return {
        "currency": "USD",
        "period": "month",
        "environment": "production" if production else "staging",
        "monthly_low": round(low, 2),
        "monthly_high": round(high, 2),
        "line_items": line_items,
        "usage_notes": usage_notes,
        "disclaimer": (
            "Non-binding estimate from Azure public list prices for East US 2; excludes usage-metered "
            "charges (ACS email, egress, log ingestion). Actual cost depends on region, tier, and load."
        ),
    }
