from __future__ import annotations

from datetime import UTC, datetime, timedelta
from inspect import getsource
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from kp_operator_api.content_library import list_patterns, list_templates
from kp_operator_api.program_routes import list_programs
from kp_operator_api.program_routes import router as program_router
from kp_operator_api.routers import (
    _MAX_COVERING_ROE_CANDIDATES,
    _covering_roes,
    list_alert_subscriptions,
    list_campaigns,
    list_pending_templates,
    list_roes,
    list_sending_domains,
    list_sources,
    router,
)
from kp_operator_api.training_library import list_training_resources
from kp_operator_api.training_library import router as training_library_router
from kp_telemetry.errors import ConflictError

APP_JS = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(
    encoding="utf-8"
)


def _query_parameters(app: FastAPI, path: str) -> dict[str, dict[str, object]]:
    operation = app.openapi()["paths"][path]["get"]
    return {parameter["name"]: parameter["schema"] for parameter in operation["parameters"]}


def test_user_facing_collection_routes_have_strict_limit_and_offset_contracts() -> None:
    app = FastAPI()
    app.include_router(router)
    app.include_router(program_router)
    app.include_router(training_library_router)

    expected = {
        "/api/v1/campaigns": 200,
        "/api/v1/sources": 200,
        "/api/v1/alerts/subscriptions": 200,
        "/api/v1/templates/pending": 100,
        "/api/v1/sending-domains": 200,
        "/api/v1/roe": 200,
        "/api/v1/templates": 200,
        "/api/v1/patterns": 200,
        "/api/v1/training-resources": 200,
        "/api/v1/programs": 200,
    }
    for path, maximum_limit in expected.items():
        parameters = _query_parameters(app, path)
        assert parameters["limit"]["minimum"] == 1
        assert parameters["limit"]["maximum"] == maximum_limit
        assert parameters["offset"]["minimum"] == 0
        assert parameters["offset"]["maximum"] == 10_000


def test_collection_queries_apply_deterministic_database_paging() -> None:
    for endpoint in (
        list_campaigns,
        list_sources,
        list_alert_subscriptions,
        list_pending_templates,
        list_sending_domains,
        list_roes,
        list_templates,
        list_patterns,
        list_training_resources,
        list_programs,
    ):
        source = getsource(endpoint)
        assert ".order_by(" in source
        assert ".offset(offset)" in source
        assert ".limit(limit)" in source


def test_gui_collects_every_page_up_to_one_explicit_total_boundary() -> None:
    helper = APP_JS[APP_JS.index("const COLLECTION_PAGE_SIZE") : APP_JS.index("/* ---------- dialogs ----------")]
    assert "const COLLECTION_PAGE_SIZE = 100;" in helper
    assert "const COLLECTION_MAX_ITEMS = 1000;" in helper
    assert "const COLLECTION_MAX_REQUESTS = (COLLECTION_MAX_ITEMS / COLLECTION_PAGE_SIZE) + 1;" in helper
    assert 'params.set("limit", String(COLLECTION_PAGE_SIZE));' in helper
    assert 'params.set("offset", String(offset));' in helper
    assert "page.length > COLLECTION_PAGE_SIZE" in helper
    assert "offset >= COLLECTION_MAX_ITEMS" in helper
    assert "Narrow the filters and retry" in helper
    assert 'type: "button", text: "Retry"' in helper


def test_every_target_gui_collection_uses_the_bounded_fetcher() -> None:
    for endpoint in (
        'boundedCollection("/campaigns")',
        'boundedCollection("/sources")',
        'boundedCollection("/alerts/subscriptions")',
        'boundedCollection("/templates/pending")',
        'boundedCollection("/sending-domains", "domains")',
        'boundedCollection("/roe", "roes")',
        "boundedCollection(`/templates?${params}`)",
        "boundedCollection(`/patterns?${params}`)",
        "boundedCollection(`/training-resources?${params.toString()}`)",
        'boundedCollection("/programs")',
    ):
        assert endpoint in APP_JS

    assert APP_JS.count("collectionLoadError(") >= 9


class _ScalarResult:
    def all(self) -> list[object]:
        return [object()] * (_MAX_COVERING_ROE_CANDIDATES + 1)


class _CandidateSession:
    def scalars(self, statement: Any) -> _ScalarResult:
        compiled = str(statement)
        assert "rules_of_engagement.revoked_at IS NULL" in compiled
        assert "rules_of_engagement.window_start <=" in compiled
        assert "rules_of_engagement.window_end >=" in compiled
        assert statement._limit_clause.value == _MAX_COVERING_ROE_CANDIDATES + 1
        return _ScalarResult()


def test_schedule_refuses_excessive_active_roe_candidates_before_signature_work() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ConflictError, match="candidates exceed"):
        _covering_roes(
            _CandidateSession(),  # type: ignore[arg-type]
            schedule_start=now,
            schedule_end=now + timedelta(hours=1),
            signing_key=b"x" * 32,
        )
