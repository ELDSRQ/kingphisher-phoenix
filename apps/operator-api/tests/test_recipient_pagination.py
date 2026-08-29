from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from kp_authorization import Principal, Role
from kp_domain_models import models as dm
from kp_operator_api.routers import campaign_recipient_results, list_recipients, router
from kp_telemetry.errors import PermissionDeniedError

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
PAGE_HELPER = APP[APP.index("function boundedRecipientPage") : APP.index("async function openCampaignAnalytics")]
ANALYTICS = APP[APP.index("async function openCampaignAnalytics") : APP.index("/* Reviewed import outcomes")]
RECIPIENT_VIEW = APP[APP.index("views.recipients = async (root) =>") : APP.index("/* ---------- privacy ---------- */")]


class _Rows:
    def __init__(self, values: list[Any]) -> None:
        self._values = values

    def all(self) -> list[Any]:
        return self._values

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._values)


def _page_bounds(statement: Any) -> tuple[int, int]:
    limit_clause = statement._limit_clause
    offset_clause = statement._offset_clause
    return int(limit_clause.value), int(offset_clause.value)


class _GlobalSession:
    def __init__(self, recipients: list[Any]) -> None:
        self.recipients = recipients
        self.count_statement: Any = None
        self.page_statement: Any = None

    def scalar(self, statement: Any) -> int:
        self.count_statement = statement
        return len(self.recipients)

    def scalars(self, statement: Any) -> _Rows:
        self.page_statement = statement
        limit, offset = _page_bounds(statement)
        return _Rows(self.recipients[offset : offset + limit])


class _CampaignSession:
    def __init__(
        self,
        campaign_id: Any,
        rows: list[tuple[Any, Any]],
        *,
        state: Any = dm.CampaignState.COMPLETED,
    ) -> None:
        self.campaign = SimpleNamespace(campaign_id=campaign_id, state=state)
        self.rows = rows
        self.count_statement: Any = None
        self.page_statement: Any = None
        self.related_statements: list[Any] = []

    def get(self, _model: Any, _identifier: Any, **_kwargs: Any) -> Any:
        return self.campaign

    def scalar(self, statement: Any) -> int:
        self.count_statement = statement
        return len(self.rows)

    def execute(self, statement: Any) -> _Rows:
        self.page_statement = statement
        limit, offset = _page_bounds(statement)
        return _Rows(self.rows[offset : offset + limit])

    def scalars(self, statement: Any) -> _Rows:
        self.related_statements.append(statement)
        return _Rows([])


def _recipient(index: int) -> Any:
    return SimpleNamespace(
        recipient_id=uuid4(),
        department=f"Department {index % 7}",
        status=dm.RecipientStatus.ACTIVE,
        is_test_account=False,
    )


def test_global_recipient_query_and_envelope_are_bounded_beyond_one_page() -> None:
    session = _GlobalSession([_recipient(index) for index in range(501)])
    page = list_recipients(limit=500, offset=0, session=session, _principal=object())  # type: ignore[arg-type]

    assert len(page["items"]) == 500
    assert {key: page[key] for key in ("total", "limit", "offset", "truncated")} == {
        "total": 501,
        "limit": 500,
        "offset": 0,
        "truncated": True,
    }
    assert "count(*)" in str(session.count_statement).lower()
    assert "ORDER BY recipients.recipient_id" in str(session.page_statement)
    assert "LIMIT" in str(session.page_statement)
    assert "OFFSET" in str(session.page_statement)

    final_page = list_recipients(limit=500, offset=500, session=session, _principal=object())  # type: ignore[arg-type]
    assert len(final_page["items"]) == 1
    assert final_page["truncated"] is False


def test_campaign_recipient_query_bounds_rows_and_related_evidence() -> None:
    campaign_id = uuid4()
    rows = []
    for index in range(501):
        recipient = _recipient(index)
        assignment = SimpleNamespace(
            recipient_assignment_id=uuid4(),
            token_id=uuid4(),
            send_state=dm.SendState.QUEUED,
            failure_reason=None,
        )
        rows.append((assignment, recipient))
    session = _CampaignSession(campaign_id, rows)

    page = campaign_recipient_results(
        campaign_id=campaign_id,
        limit=500,
        offset=0,
        session=session,  # type: ignore[arg-type]
        _principal=object(),  # type: ignore[arg-type]
    )

    assert len(page["items"]) == 500
    assert page["total"] == 501
    assert page["truncated"] is True
    assert "count(*)" in str(session.count_statement).lower()
    assert "ORDER BY recipient_assignments.recipient_assignment_id" in str(session.page_statement)
    assert len(session.related_statements) == 2
    related_parameters = [statement.compile().params for statement in session.related_statements]
    bounded_lists = [value for params in related_parameters for value in params.values() if isinstance(value, list)]
    assert bounded_lists
    assert max(map(len, bounded_lists)) == 500


def test_campaign_recipient_results_expose_explicit_close_disposition() -> None:
    campaign_id = uuid4()
    token_id = uuid4()
    recipient = _recipient(0)
    active_assignment = SimpleNamespace(
        recipient_assignment_id=uuid4(),
        token_id=token_id,
        send_state=dm.SendState.DELIVERED,
        failure_reason=None,
    )
    quiet_assignment = SimpleNamespace(
        recipient_assignment_id=uuid4(),
        token_id=None,
        send_state=dm.SendState.DELIVERED,
        failure_reason=None,
    )

    class _EventsSession(_CampaignSession):
        def __init__(self) -> None:
            super().__init__(campaign_id, [(active_assignment, recipient), (quiet_assignment, recipient)])
            self.calls: list[Any] = []

        def scalars(self, statement: Any) -> _Rows:
            self.calls.append(statement)
            if len(self.calls) == 1:
                return _Rows(
                    [
                        SimpleNamespace(
                            token_id=token_id,
                            event_type=dm.EventType.HUMAN_INTERACTION_CONFIRMED,
                        )
                    ]
                )
            return _Rows([])

    page = campaign_recipient_results(
        campaign_id=campaign_id,
        limit=100,
        offset=0,
        session=_EventsSession(),  # type: ignore[arg-type]
        _principal=object(),  # type: ignore[arg-type]
    )

    active, quiet = page["items"]
    assert active["confirmed_interaction"] is True
    assert active["close_disposition"] == "activity_at_close"
    assert quiet["confirmed_interaction"] is False
    assert quiet["close_disposition"] == "no_activity_at_close"


def test_campaign_recipient_results_leave_disposition_open_for_nonterminal_campaigns() -> None:
    campaign_id = uuid4()
    assignment = SimpleNamespace(
        recipient_assignment_id=uuid4(),
        token_id=None,
        send_state=dm.SendState.DELIVERED,
        failure_reason=None,
    )
    session = _CampaignSession(
        campaign_id,
        [(assignment, _recipient(0))],
        state=dm.CampaignState.ACTIVE,
    )

    page = campaign_recipient_results(
        campaign_id=campaign_id,
        limit=100,
        offset=0,
        session=session,  # type: ignore[arg-type]
        _principal=object(),  # type: ignore[arg-type]
    )

    assert page["items"][0]["close_disposition"] is None


def test_every_browser_recipient_consumer_uses_and_validates_a_bounded_page() -> None:
    assert "payload.items.length <= payload.limit" in PAGE_HELPER
    assert 'throw new Error("The server returned an invalid bounded recipient page")' in PAGE_HELPER
    assert 'api("/recipients")' not in APP
    assert "`/campaigns/${campaign.campaign_id}/recipients?limit=500&offset=0`" in ANALYTICS
    assert ".then((payload) => boundedRecipientPage(payload, 500))" in ANALYTICS
    assert "const visibleResults = namedResults.items;" in ANALYTICS
    assert "namedResults.slice" not in ANALYTICS
    assert "namedResults.total" in ANALYTICS
    assert "namedResults.truncated" in ANALYTICS
    assert "`/recipients?limit=${RECIPIENT_PAGE_LIMIT}&offset=${recipientPageOffset}`" in RECIPIENT_VIEW
    assert "const recipients = recipientPage.items;" in RECIPIENT_VIEW
    assert 'text: "Previous recipients"' in RECIPIENT_VIEW
    assert 'text: "Next recipients"' in RECIPIENT_VIEW
    assert "recipientPage.truncated ? null" in RECIPIENT_VIEW
    assert "of ${recipientPage.total} recipients" in RECIPIENT_VIEW


def test_recipient_route_query_parameters_are_validated_at_the_api_boundary() -> None:
    app = FastAPI()
    app.include_router(router)
    schema = app.openapi()
    for path in ("/api/v1/recipients", "/api/v1/campaigns/{campaign_id}/recipients"):
        parameters = {item["name"]: item["schema"] for item in schema["paths"][path]["get"]["parameters"]}
        assert parameters["limit"] == {
            "type": "integer",
            "maximum": 500,
            "minimum": 1,
            "default": 100,
            "title": "Limit",
        }
        assert parameters["offset"] == {"type": "integer", "minimum": 0, "default": 0, "title": "Offset"}


def test_aggregate_only_roles_are_denied_both_named_recipient_routes() -> None:
    author = Principal("author", {Role.CAMPAIGN_AUTHOR})
    aggregate_reader = Principal("source", {Role.SOURCE_CURATOR})
    recipient_routes = {
        route.path: route
        for route in router.routes
        if isinstance(route, APIRoute)
        and route.path in {"/api/v1/recipients", "/api/v1/campaigns/{campaign_id}/recipients"}
    }
    assert len(recipient_routes) == 2
    for route in recipient_routes.values():
        capability_check = next(
            dependency.call
            for dependency in route.dependant.dependencies
            if getattr(dependency.call, "__name__", "") == "_check"
        )
        assert capability_check is not None
        for principal in (author, aggregate_reader):
            with pytest.raises(PermissionDeniedError):
                capability_check(principal)
