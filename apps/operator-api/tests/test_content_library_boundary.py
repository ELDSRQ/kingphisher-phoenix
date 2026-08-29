from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute, APIRouter
from kp_operator_api import content_library, routers

EXPECTED_ROUTES = {
    ("POST", "/api/v1/templates/preview"),
    ("GET", "/api/v1/templates"),
    ("GET", "/api/v1/templates/{template_version_id}/preview"),
    ("POST", "/api/v1/templates/{template_version_id}/clone"),
    ("GET", "/api/v1/patterns"),
    ("GET", "/api/v1/patterns/{pattern_id}/preview"),
    ("POST", "/api/v1/patterns/{pattern_id}/clone"),
}


def _route_contract(router: APIRouter) -> dict[tuple[str, str], APIRoute]:
    routes = router.routes
    return {
        (method, route.path): route
        for route in routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
        if (method, route.path) in EXPECTED_ROUTES
    }


def test_content_library_module_owns_exact_public_route_contract() -> None:
    feature_routes = _route_contract(routers.router)

    assert set(feature_routes) == EXPECTED_ROUTES
    assert all(route.endpoint.__module__ == content_library.__name__ for route in feature_routes.values())


def test_aggregate_router_exposes_exact_content_library_api_contract() -> None:
    app = FastAPI()
    app.include_router(routers.router)
    schema_paths = app.openapi()["paths"]
    actual = {
        (method.upper(), path)
        for path, operations in schema_paths.items()
        for method in operations
        if (method.upper(), path) in EXPECTED_ROUTES
    }
    assert actual == EXPECTED_ROUTES


def test_content_library_schemas_and_helpers_do_not_leak_back_into_monolith() -> None:
    assert content_library.TemplatePreview.__module__ == content_library.__name__
    assert content_library.ContentClone.__module__ == content_library.__name__
    for name in (
        "TemplatePreview",
        "ContentClone",
        "_template_content",
        "_validate_template_content",
        "_render_template_preview",
        "_json_clone",
        "_pattern_preview",
    ):
        assert not hasattr(routers, name)
