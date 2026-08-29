from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import kp_operator_api.routers as routers_module
import pytest
from fastapi import Request
from fastapi.routing import APIRoute
from kp_authorization.rbac import Principal, Role
from kp_database.audit_store import AuditStore
from kp_operator_api.main import _ERROR_STATUS
from kp_operator_api.routers import (
    DirectoryApply,
    apply_recipients_from_directory,
    discard_directory_preview,
    microsoft365_integration_status,
    poll_reported_mailbox,
    preview_recipients_from_directory,
    router,
)
from kp_telemetry.errors import ConflictError
from sqlalchemy.orm import Session


class _Session:
    def __init__(self, state: object | None = None, states: list[object] | None = None) -> None:
        self.state = state
        self.states = states or []
        self.executions: list[dict[str, Any]] = []
        self.committed = False

    def scalar(self, _statement: object) -> object | None:
        return self.state

    def scalars(self, _statement: object) -> list[object]:
        return self.states

    def execute(self, _statement: object, parameters: dict[str, Any]) -> None:
        self.executions.append(parameters)

    def commit(self) -> None:
        self.committed = True


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)

    def dispatch_pending_queue(self, _queue: object) -> None:
        raise AssertionError("test doubles never dispatch before commit")


def _state(
    *,
    kind: str,
    provider: str,
    state_status: str = "never",
    preview_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        kind=kind,
        provider=provider,
        scope_hash="1" * 64,
        config_fingerprint="2" * 64,
        status=state_status,
        last_attempt_at=None,
        last_success_at=None,
        last_applied_at=None,
        cursor=None,
        last_counts={},
        last_error=None,
        pending_preview_id=preview_id,
        pending_preview_hash="3" * 64 if preview_id else None,
        pending_expires_at=datetime.now(UTC) + timedelta(minutes=15) if preview_id else None,
        updated_at=None,
    )


def _request() -> Request:
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(queue=object()))))


def _principal() -> Principal:
    return Principal("operator-1", {Role.CAMPAIGN_OPERATOR})


def test_m365_gui_api_routes_are_wired() -> None:
    routes = {
        (method, route.path)
        for route in router.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert ("GET", "/api/v1/integrations/microsoft365/status") in routes
    assert ("POST", "/api/v1/recipients/directory/preview") in routes
    assert ("POST", "/api/v1/recipients/directory/apply") in routes
    assert ("POST", "/api/v1/recipients/directory/discard") in routes
    assert ("POST", "/api/v1/integrations/reported-mail/poll") in routes
    assert _ERROR_STATUS[ConflictError] == 409


def test_console_exposes_preview_apply_health_and_mailbox_canary() -> None:
    app = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text()
    assert "Preview directory changes" in app
    assert "Apply reviewed directory preview" in app
    assert "Discard directory preview" in app
    assert "Directory actions unavailable" in app
    assert "Reported-mail action unavailable" in app
    assert "/integrations/microsoft365/status" in app
    assert "/recipients/directory/discard" in app
    assert "/integrations/reported-mail/poll" in app
    assert "Reported-mail canary" in app


def test_status_fails_closed_without_durable_worker_readiness() -> None:
    payload = microsoft365_integration_status(
        session=cast(Session, _Session()),
        principal=_principal(),
    )

    assert payload["directory"]["configured"] is False
    assert payload["directory_preview_available"] is False
    assert payload["mailbox_poll_available"] is False
    assert "has not registered" in payload["directory_preview_unavailable_reason"]
    assert "has not registered" in payload["mailbox_poll_unavailable_reason"]


def test_integration_action_missing_state_never_depends_on_runtime_asserts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routers_module, "_integration_action_reason", lambda state, *, kind: None)

    with pytest.raises(ConflictError, match="state is unavailable"):
        routers_module._require_integration_action(cast(Session, _Session()), kind="directory")


def test_status_uses_only_non_secret_durable_readiness_metadata() -> None:
    preview_id = uuid.uuid4()
    payload = microsoft365_integration_status(
        session=cast(
            Session,
            _Session(
                states=[
                    _state(
                        kind="directory", provider="microsoft365", state_status="preview_ready", preview_id=preview_id
                    ),
                    _state(kind="mailbox", provider="microsoft365", state_status="healthy"),
                ]
            ),
        ),
        principal=_principal(),
    )

    assert payload["directory_preview_available"] is True
    assert payload["directory"]["apply_available"] is True
    assert payload["directory"]["discard_available"] is True
    assert payload["mailbox_poll_available"] is True
    serialized = json.dumps(payload, default=str)
    assert "scope_hash" not in serialized
    assert "config_fingerprint" not in serialized
    assert "1111111111111111" not in serialized
    assert "2222222222222222" not in serialized


@pytest.mark.parametrize("state_status", ["unconfigured", "configuration_error", "disabled", "unavailable"])
def test_directory_preview_refuses_dead_jobs(state_status: str) -> None:
    session = _Session(_state(kind="directory", provider="microsoft365", state_status=state_status))

    with pytest.raises(ConflictError, match="configuration|unavailable"):
        preview_recipients_from_directory(
            _request(),
            session=cast(Session, session),
            audit=cast(AuditStore, _Audit()),
            principal=_principal(),
        )

    assert session.executions == []
    assert session.committed is False


def test_apply_and_discard_require_available_worker_and_exact_pending_preview() -> None:
    preview_id = uuid.uuid4()
    unavailable = _Session(
        _state(kind="directory", provider="microsoft365", state_status="unavailable", preview_id=preview_id)
    )
    for endpoint in (apply_recipients_from_directory, discard_directory_preview):
        with pytest.raises(ConflictError, match="unavailable"):
            endpoint(
                DirectoryApply(preview_id=preview_id),
                _request(),
                session=cast(Session, unavailable),
                audit=cast(AuditStore, _Audit()),
                principal=_principal(),
            )
    assert unavailable.executions == []

    available = _Session(_state(kind="directory", provider="microsoft365", state_status="healthy"))
    with pytest.raises(ConflictError, match="missing, stale"):
        discard_directory_preview(
            DirectoryApply(preview_id=preview_id),
            _request(),
            session=cast(Session, available),
            audit=cast(AuditStore, _Audit()),
            principal=_principal(),
        )
    assert available.executions == []


def test_discard_queues_only_the_exact_pending_preview() -> None:
    preview_id = uuid.uuid4()
    session = _Session(
        _state(kind="directory", provider="microsoft365", state_status="preview_ready", preview_id=preview_id)
    )
    audit = _Audit()

    result = discard_directory_preview(
        DirectoryApply(preview_id=preview_id),
        _request(),
        session=cast(Session, session),
        audit=cast(AuditStore, audit),
        principal=_principal(),
    )

    queue_intent = session.executions[0]
    assert result["queued"] is True
    assert queue_intent["topic"] == "directory"
    assert json.loads(queue_intent["payload"])["action"] == "discard"
    assert json.loads(queue_intent["payload"])["preview_id"] == str(preview_id)
    assert audit.records[0]["action"] == "directory.discard.request"
    assert session.committed is True


def test_mailbox_poll_refuses_missing_or_unsupported_provider_state() -> None:
    for integration_state in (None, _state(kind="mailbox", provider="unsupported")):
        session = _Session(integration_state)
        with pytest.raises(ConflictError, match="registered|not supported"):
            poll_reported_mailbox(
                _request(),
                session=cast(Session, session),
                audit=cast(AuditStore, _Audit()),
                principal=_principal(),
            )
        assert session.executions == []
