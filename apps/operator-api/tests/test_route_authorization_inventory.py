"""Complete operator-route authentication and capability inventory.

The manifest is intentionally explicit. Adding or weakening a route must fail
this test and receive an authorization review instead of silently inheriting a
nearby role or depending on the browser to hide an action.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from fastapi.routing import APIRoute
from kp_authorization import Capability, Principal, Role
from kp_domain_models import models as dm
from kp_operator_api.main import app
from kp_operator_api.routers import _require_campaign_approval_capability
from kp_telemetry.errors import PermissionDeniedError

RouteKey = tuple[str, str]


def _routes(*values: str) -> frozenset[RouteKey]:
    return frozenset((value.split(" ", 1)[0], value.split(" ", 1)[1]) for value in values)


# Each key is one OR-set enforced by one authentication dependency. Most sets
# contain one capability. The two multi-capability routes perform an additional
# endpoint-specific check where needed.
_ROUTES_BY_REQUIREMENT: tuple[tuple[frozenset[str], frozenset[RouteKey]], ...] = (
    (
        frozenset({"view_aggregate:results"}),
        _routes(
            "GET /api/v1/audience-groups",
            "GET /api/v1/campaigns/{campaign_id}/audience",
            "GET /api/v1/campaigns/{campaign_id}/audience/preview",
            "GET /api/v1/campaigns/{campaign_id}/review",
            "GET /api/v1/campaigns",
            "GET /api/v1/campaigns/{campaign_id}/report",
            "GET /api/v1/integrations/microsoft365/status",
            "GET /api/v1/analytics/campaigns/trend",
            "GET /api/v1/analytics/campaigns/{campaign_id}/funnel",
            "GET /api/v1/programs",
            "GET /api/v1/programs/{program_id}",
            "GET /api/v1/console/help",
            "GET /api/v1/console/status",
        ),
    ),
    (
        frozenset({"create:campaign"}),
        _routes(
            "POST /api/v1/audience-groups",
            "PUT /api/v1/audience-groups/{group_id}",
            "POST /api/v1/campaigns",
            "PUT /api/v1/campaigns/{campaign_id}/audience",
            "PUT /api/v1/campaigns/{campaign_id}/training-resource",
            "POST /api/v1/campaigns/{campaign_id}/audience/freeze",
            "POST /api/v1/campaigns/{campaign_id}/submit",
            "POST /api/v1/patterns/{pattern_id}/clone",
            "POST /api/v1/templates/{template_version_id}/clone",
            "POST /api/v1/programs",
            "POST /api/v1/training-resources",
            "POST /api/v1/training-resources/{training_resource_id}/submit",
        ),
    ),
    (
        frozenset({"approve:pattern", "create:campaign"}),
        _routes(
            "GET /api/v1/patterns",
            "GET /api/v1/patterns/{pattern_id}/preview",
        ),
    ),
    (
        frozenset({"approve:template", "create:campaign"}),
        _routes(
            "POST /api/v1/templates/preview",
            "GET /api/v1/templates",
            "GET /api/v1/templates/{template_version_id}/preview",
            "GET /api/v1/training-resources",
            "GET /api/v1/training-resources/{training_resource_id}/preview",
        ),
    ),
    (
        frozenset({"approve_privacy:campaign", "approve_security:campaign"}),
        _routes("POST /api/v1/campaigns/{campaign_id}/approvals/{approval_type}"),
    ),
    (
        frozenset({"schedule:campaign"}),
        _routes(
            "POST /api/v1/campaigns/{campaign_id}/publish",
            "POST /api/v1/campaigns/{campaign_id}/schedule",
            "POST /api/v1/campaigns/{campaign_id}/training/reminders",
            "POST /api/v1/programs/{program_id}/pause",
            "POST /api/v1/programs/{program_id}/resume",
        ),
    ),
    (frozenset({"send:campaign"}), _routes("POST /api/v1/campaigns/{campaign_id}/test-send")),
    (frozenset({"stop:campaign"}), _routes("POST /api/v1/campaigns/{campaign_id}/recall")),
    (
        frozenset({"view_named:results"}),
        _routes("GET /api/v1/campaigns/{campaign_id}/recipients"),
    ),
    (
        frozenset({"manage:recipients", "view_named:results"}),
        _routes("GET /api/v1/recipients"),
    ),
    (
        frozenset({"export_bulk:results"}),
        _routes(
            "GET /api/v1/campaigns/{campaign_id}/report.csv",
            "GET /api/v1/analytics/campaigns/trend.csv",
            "GET /api/v1/analytics/campaigns/{campaign_id}/funnel.csv",
        ),
    ),
    (frozenset({"submit:source"}), _routes("POST /api/v1/sources")),
    (
        frozenset({"manage:source"}),
        _routes(
            "GET /api/v1/sources",
            "POST /api/v1/sources/{source_id}/enable",
            "POST /api/v1/sources/{source_id}/disable",
            "POST /api/v1/sources/{source_id}/ingest",
            "POST /api/v1/sources/{source_id}/terms",
            "GET /api/v1/sources/{source_id}/terms/current",
            "POST /api/v1/sources/{source_id}/terms/revoke",
            "GET /api/v1/threats",
            "POST /api/v1/threats/{source_item_id}/activate",
            "POST /api/v1/threats/{source_item_id}/reject",
            "POST /api/v1/threats/{source_item_id}/merge-duplicate",
        ),
    ),
    (
        frozenset({"manage:recipients"}),
        _routes(
            "PUT /api/v1/recipients/{recipient_id}/test-account",
            "POST /api/v1/recipients/import",
            "POST /api/v1/recipients/import/preview",
            "POST /api/v1/recipients/import/apply",
            "POST /api/v1/recipients/sync-directory",
            "POST /api/v1/recipients/directory/preview",
            "POST /api/v1/recipients/directory/apply",
            "POST /api/v1/recipients/directory/discard",
            "POST /api/v1/integrations/reported-mail/poll",
        ),
    ),
    (
        frozenset({"manage:exclusions"}),
        _routes(
            "POST /api/v1/recipients/{recipient_id}/exclusions",
            "GET /api/v1/recipients/{recipient_id}/exclusions",
            "POST /api/v1/recipients/{recipient_id}/exclusions/{exclusion_id}/revoke",
        ),
    ),
    (
        frozenset({"subscribe:alerts"}),
        _routes(
            "POST /api/v1/alerts/subscriptions",
            "GET /api/v1/alerts/subscriptions",
            "DELETE /api/v1/alerts/subscriptions/{subscription_id}",
        ),
    ),
    (frozenset({"approve:pattern"}), _routes("POST /api/v1/patterns/{pattern_id}/approve")),
    (
        frozenset({"approve:template"}),
        _routes(
            "POST /api/v1/templates/{template_version_id}/decision",
            "GET /api/v1/templates/pending",
            "POST /api/v1/training-resources/{training_resource_id}/decision",
        ),
    ),
    (
        frozenset({"manage:job_queue"}),
        _routes(
            "GET /api/v1/queues/dead-letters",
            "GET /api/v1/queues/dead-letters/{topic}/{reference}",
            "POST /api/v1/queues/dead-letters/{topic}/{reference}/replay",
        ),
    ),
    (
        frozenset({"view:audit"}),
        _routes("GET /api/v1/audit", "POST /api/v1/audit/verify"),
    ),
    (
        frozenset({"use:kill_switch"}),
        _routes("POST /api/v1/kill-switch", "POST /api/v1/kill-switch/reset", "GET /api/v1/kill-switch"),
    ),
    (
        frozenset({"handle:privacy_requests"}),
        _routes(
            "GET /api/v1/privacy/notice",
            "GET /api/v1/privacy/requests",
            "POST /api/v1/privacy/requests",
            "POST /api/v1/privacy/requests/{request_id}/verify",
            "POST /api/v1/privacy/requests/{request_id}/export",
        ),
    ),
    (
        frozenset({"delete:data"}),
        _routes(
            "POST /api/v1/privacy/requests/{request_id}/fulfill",
            "DELETE /api/v1/recipients/{recipient_id}",
        ),
    ),
    (
        frozenset({"verify:sending_domain"}),
        _routes(
            "POST /api/v1/sending-domains/challenge",
            "POST /api/v1/sending-domains/verify",
            "GET /api/v1/sending-domains",
            "POST /api/v1/sending-domains/{domain}/revoke",
            "GET /api/v1/sending-domains/generate",
        ),
    ),
    (
        frozenset({"sign:rules_of_engagement"}),
        _routes("POST /api/v1/roe", "GET /api/v1/roe", "POST /api/v1/roe/{roe_id}/revoke"),
    ),
    (
        frozenset({"manage:roles"}),
        _routes(
            "GET /api/v1/console/azure-deployment",
            "POST /api/v1/console/azure-deployment/validate",
            "POST /api/v1/console/azure-deployment/orchestration/plan",
            "GET /api/v1/console/azure-deployment/orchestration/latest",
            "GET /api/v1/console/azure-deployment/orchestration/plans/{plan_id}",
            "POST /api/v1/console/azure-deployment/orchestration/plans/{plan_id}/apply",
            "POST /api/v1/console/azure-deployment/orchestration/plans/{plan_id}/advance",
            "POST /api/v1/console/azure-deployment/orchestration/plans/{plan_id}/retry",
            "GET /api/v1/console/onboarding",
            "POST /api/v1/console/onboarding/assist",
            "PUT /api/v1/console/onboarding",
            "POST /api/v1/console/onboarding/test",
            "GET /api/v1/console/config",
            "PUT /api/v1/console/config",
            "POST /api/v1/console/restart",
        ),
    ),
)

_DEDICATED_OR_PUBLIC_ROUTES: dict[RouteKey, tuple[str, str]] = {
    ("GET", "/livez"): ("kp_operator_api.main", "livez"),
    ("GET", "/readyz"): ("kp_operator_api.main", "readyz"),
    ("GET", "/healthz"): ("kp_operator_api.main", "healthz"),
    ("GET", "/api/v1/console/auth-mode"): ("kp_operator_api.console", "auth_mode"),
    ("GET", "/api/v1/console/oidc/start"): ("kp_operator_api.console", "oidc_start"),
    ("GET", "/api/v1/console/oidc/callback"): ("kp_operator_api.console", "oidc_callback"),
    # These authenticate through the OIDC session cookie or the local password
    # bootstrap rather than the normal bearer dependency.
    ("GET", "/api/v1/console/session"): ("kp_operator_api.console", "current_session"),
    ("POST", "/api/v1/console/session"): ("kp_operator_api.console", "create_session"),
    # Logout only expires a cookie and intentionally works for an absent or
    # expired session. The global same-origin gate still protects cookie use.
    ("POST", "/api/v1/console/logout"): ("kp_operator_api.console", "logout"),
    # Event Grid uses its tenant/audience/application/role token verifier and
    # exact subscription boundary, never console bearer/cookie authentication.
    ("POST", "/api/v1/integrations/acs/events"): (
        "kp_operator_api.acs_receipts",
        "receive_acs_event_grid",
    ),
}


def _iter_api_routes() -> Iterable[APIRoute]:
    for registered in app.routes:
        included_router = getattr(registered, "original_router", None)
        candidates = included_router.routes if included_router is not None else (registered,)
        for candidate in candidates:
            if isinstance(candidate, APIRoute):
                yield candidate


def _route_key(route: APIRoute) -> RouteKey:
    methods = set(route.methods or ()) - {"HEAD", "OPTIONS"}
    assert len(methods) == 1, f"route requires an explicit one-method review: {route.path} {methods}"
    return methods.pop(), route.path


def _dependency_requirements(route: APIRoute) -> tuple[frozenset[str], ...]:
    requirements: list[frozenset[str]] = []

    def walk(dependant: object) -> None:
        for dependency in getattr(dependant, "dependencies", ()):  # FastAPI dependency tree
            call = dependency.call
            for cell in getattr(call, "__closure__", ()) or ():
                value = cell.cell_contents
                if isinstance(value, Capability):
                    requirements.append(frozenset({f"{value.action}:{value.object}"}))
                elif isinstance(value, tuple) and value and all(isinstance(item, Capability) for item in value):
                    requirements.append(frozenset(f"{item.action}:{item.object}" for item in value))
            walk(dependency)

    walk(route.dependant)
    return tuple(requirements)


def _expected_protected_routes() -> dict[RouteKey, frozenset[str]]:
    expected: dict[RouteKey, frozenset[str]] = {}
    for requirement, routes in _ROUTES_BY_REQUIREMENT:
        for route in routes:
            assert route not in expected, f"duplicate route in authorization manifest: {route}"
            expected[route] = requirement
    return expected


def test_every_operator_route_has_exact_reviewed_authority() -> None:
    expected = _expected_protected_routes()
    actual = {_route_key(route): route for route in _iter_api_routes()}

    assert set(actual) == set(expected) | set(_DEDICATED_OR_PUBLIC_ROUTES)
    for key, requirement in expected.items():
        assert _dependency_requirements(actual[key]) == (requirement,), key
    for key, (module, endpoint) in _DEDICATED_OR_PUBLIC_ROUTES.items():
        route = actual[key]
        assert _dependency_requirements(route) == (), key
        assert (route.endpoint.__module__, route.endpoint.__name__) == (module, endpoint)


def test_no_capability_is_dead_or_missing_from_the_route_manifest() -> None:
    defined = {
        f"{capability.action}:{capability.object}"
        for capability in vars(Capability).values()
        if isinstance(capability, Capability)
    }
    used = {capability for requirement, _routes_for_requirement in _ROUTES_BY_REQUIREMENT for capability in requirement}

    assert used == defined


@pytest.mark.parametrize(
    ("approval_type", "allowed_roles"),
    [
        (dm.ApprovalType.SECURITY, {Role.SECURITY_APPROVER, Role.ADMINISTRATOR}),
        (dm.ApprovalType.PRIVACY, {Role.PRIVACY_APPROVER, Role.ADMINISTRATOR}),
    ],
)
def test_campaign_approval_lanes_reject_weaker_roles(
    approval_type: dm.ApprovalType,
    allowed_roles: set[Role],
) -> None:
    for role in Role:
        principal = Principal(subject_id="reviewer", roles={role})
        if role in allowed_roles:
            assert _require_campaign_approval_capability(approval_type, principal) is principal
        else:
            with pytest.raises(PermissionDeniedError, match="approval capability"):
                _require_campaign_approval_capability(approval_type, principal)
