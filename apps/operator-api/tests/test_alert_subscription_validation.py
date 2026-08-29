from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from kp_authorization import Principal, Role
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.routers import AlertSubscribe, subscribe_alerts
from kp_telemetry.errors import ValidationError_


class _Session:
    def __init__(self, campaign_id: uuid.UUID) -> None:
        self.campaign = SimpleNamespace(campaign_id=campaign_id)
        self.added: list[Any] = []
        self.commits = 0

    def get(self, model: object, object_id: uuid.UUID) -> object | None:
        del model
        return self.campaign if object_id == self.campaign.campaign_id else None

    def scalar(self, statement: object) -> None:
        del statement
        return None

    def add(self, value: Any) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **event: Any) -> None:
        self.events.append(event)


def _principal() -> Principal:
    return Principal(subject_id=str(uuid.uuid4()), roles={Role.CAMPAIGN_OPERATOR})


def test_operator_reads_the_same_alert_allowlist_environment_as_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KP_WORKER_ALERT_WEBHOOK_DOMAINS", "Hooks.Example, ntfy.example")

    settings = OperatorApiSettings(_env_file=None)

    assert settings.alert_webhook_domain_allowlist() == frozenset({"hooks.example", "ntfy.example"})


@pytest.mark.parametrize(
    "destination",
    [
        "https://blocked.example/topic",
        "https://allowed.example:8443/topic",
        "https://allowed.example/topic#fragment",
    ],
)
def test_disallowed_alert_destination_is_rejected_before_persistence(destination: str) -> None:
    campaign_id = uuid.uuid4()
    session = _Session(campaign_id)
    audit = _Audit()

    with pytest.raises(ValidationError_, match="configured domain allowlist|HTTPS URL"):
        subscribe_alerts(
            AlertSubscribe(campaign_id=campaign_id, channel="webhook", destination_url=destination),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=OperatorApiSettings(alert_webhook_domains="allowed.example"),
            principal=_principal(),
        )

    assert session.added == []
    assert session.commits == 0
    assert audit.events == []


def test_allowlisted_alert_destination_is_persisted() -> None:
    campaign_id = uuid.uuid4()
    session = _Session(campaign_id)
    audit = _Audit()

    result = subscribe_alerts(
        AlertSubscribe(
            campaign_id=campaign_id,
            channel="ntfy",
            destination_url="https://www.allowed.example/security-alerts",
        ),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=OperatorApiSettings(alert_webhook_domains="allowed.example"),
        principal=_principal(),
    )

    assert result["active"] is True
    assert len(session.added) == 1
    assert session.added[0].destination_url == "https://www.allowed.example/security-alerts"
    assert session.commits == 1
    assert len(audit.events) == 1
