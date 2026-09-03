"""Security and queue-contract tests for the ACS Event Grid webhook."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import jwt
import kp_operator_api.acs_receipts as receipt_module
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.acs_receipts import EventGridTokenVerifier
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from kp_workers.providers.acs_events import parse_acs_delivery_event
from pydantic import ValidationError

KEK = "01" * 32
AUDIT_HMAC = "02" * 32
CONSOLE_JWT = "03" * 32
RECEIPT_KEY = "04" * 32
TENANT_ID = "11111111-1111-4111-8111-111111111111"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
PUBLISHER = "4962773b-9cdb-44cf-a8bf-237846a00ab7"
SUBSCRIPTION = "acs-delivery-receipts"
TOPIC = (
    "/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/rg-kp-staging/"
    "providers/Microsoft.Communication/CommunicationServices/acs-kp-staging"
)


class _Verifier:
    def verify(self, authorization: str) -> None:
        if authorization != "Bearer event-grid-token":
            raise PermissionError


class _Queue:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any], str]] = []

    def publish(self, topic: str, payload: dict[str, Any], *, idempotency_key: str) -> str:
        self.published.append((topic, payload, idempotency_key))
        return "job-id"


def _settings(**overrides: object) -> OperatorApiSettings:
    values: dict[str, object] = {
        "audit_hmac_key": AUDIT_HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "console_static_dir": "/nonexistent-console-dir",
        "acs_receipt_signing_key": RECEIPT_KEY,
        "event_grid_tenant_id": TENANT_ID,
        "event_grid_audience": AUDIENCE,
        "event_grid_subscription_name": SUBSCRIPTION,
        "event_grid_topic": TOPIC,
        "event_grid_publisher_app_id": PUBLISHER,
    }
    values.update(overrides)
    return OperatorApiSettings(**values)


def _event(*, event_id: str = "event-1", event_type: str = receipt_module.DELIVERY_EVENT_TYPE) -> dict[str, Any]:
    return {
        "id": event_id,
        "topic": TOPIC,
        "subject": "sender/security@example.com/message/provider-message-1",
        "data": {
            "sender": "security@example.com",
            "recipient": "learner@example.net",
            "messageId": "provider-message-1",
            "status": "Delivered",
            "deliveryStatusDetails": {"statusMessage": "accepted by recipient MTA"},
        },
        "eventType": event_type,
        "dataVersion": "1.0",
        "metadataVersion": "1",
        "eventTime": datetime.now(UTC).isoformat(),
    }


@pytest.fixture()
def client() -> tuple[TestClient, _Queue]:
    app = create_app(_settings())
    queue = _Queue()
    app.state.event_grid_token_verifier = _Verifier()
    app.state.queue = queue
    app.state.audit_health_check = lambda: True
    return TestClient(app), queue


def _headers(**overrides: str) -> dict[str, str]:
    result = {
        "Authorization": "Bearer event-grid-token",
        "aeg-event-type": "Notification",
        "aeg-subscription-name": SUBSCRIPTION,
        "Content-Type": "application/json",
    }
    result.update(overrides)
    return result


def test_notification_is_hmac_bound_and_queued_once_per_event(client: tuple[TestClient, _Queue]) -> None:
    http, queue = client
    event = _event()
    event["unknownProviderField"] = "must-not-enter-redis"
    event["data"]["internetMessageId"] = "<private@example.net>"

    response = http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=[event])

    assert response.status_code == 200, response.text
    assert response.json() == {"accepted": 1}
    assert len(queue.published) == 1
    topic, payload, idempotency_key = queue.published[0]
    detail_hash = hashlib.sha256(
        json.dumps(
            event["data"]["deliveryStatusDetails"],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    minimized = {
        "id": "event-1",
        "eventType": receipt_module.DELIVERY_EVENT_TYPE,
        "dataVersion": "1.0",
        "metadataVersion": "1",
        "eventTime": event["eventTime"],
        "data": {
            "messageId": "provider-message-1",
            "status": "Delivered",
            "deliveryStatusDetailsHash": detail_hash,
        },
    }
    canonical = json.dumps(minimized, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    assert topic == "deliver"
    assert payload == {
        "job_type": "acs_delivery_receipt",
        "event": minimized,
        "signature": hmac.new(bytes.fromhex(RECEIPT_KEY), canonical, hashlib.sha256).hexdigest(),
    }
    parsed = parse_acs_delivery_event(
        payload["event"],
        supplied_signature=payload["signature"],
        signing_key=bytes.fromhex(RECEIPT_KEY),
    )
    assert parsed.provider_message_id == "provider-message-1"
    assert parsed.status == "delivered"
    assert parsed.status_detail_hash == detail_hash
    assert idempotency_key == f"acs-receipt:{hashlib.sha256(b'event-1').hexdigest()}"
    serialized_job = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "security@example.com",
        "learner@example.net",
        "subject",
        "topic",
        "internetMessageId",
        "unknownProviderField",
        "accepted by recipient MTA",
    ):
        assert forbidden not in serialized_job


def test_subscription_validation_is_authenticated_and_never_queued(client: tuple[TestClient, _Queue]) -> None:
    http, queue = client
    event = {
        "id": "validation-event",
        "topic": TOPIC,
        "subject": "",
        "data": {"validationCode": "validation-code"},
        "eventType": receipt_module.VALIDATION_EVENT_TYPE,
        "dataVersion": "1",
        "metadataVersion": "1",
        "eventTime": datetime.now(UTC).isoformat(),
    }
    headers = _headers(**{"aeg-event-type": "SubscriptionValidation"})

    response = http.post(receipt_module.WEBHOOK_PATH, headers=headers, json=[event])

    assert response.status_code == 200
    assert response.json() == {"validationResponse": "validation-code"}
    assert queue.published == []


def test_uppercased_subscription_name_header_is_accepted(client: tuple[TestClient, _Queue]) -> None:
    """Azure Event Grid delivers ``aeg-subscription-name`` upper-cased."""
    http, queue = client

    response = http.post(
        receipt_module.WEBHOOK_PATH,
        headers=_headers(**{"aeg-subscription-name": SUBSCRIPTION.upper()}),
        json=[_event()],
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"accepted": 1}
    assert len(queue.published) == 1


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"Authorization": "Bearer wrong"}, 401),
        ({"Authorization": ""}, 401),
        ({"aeg-subscription-name": "other-subscription"}, 403),
        ({"aeg-event-type": "Other"}, 400),
    ],
)
def test_authentication_subscription_and_request_type_fail_closed(
    client: tuple[TestClient, _Queue], headers: dict[str, str], status: int
) -> None:
    http, queue = client

    response = http.post(receipt_module.WEBHOOK_PATH, headers=_headers(**headers), json=[_event()])

    assert response.status_code == status
    assert queue.published == []


def test_console_administrator_token_cannot_authenticate_event_grid_ingress(
    client: tuple[TestClient, _Queue],
) -> None:
    http, queue = client
    settings = http.app.state.settings
    console_token = jwt.encode(
        {
            "sub": "console-administrator",
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "realm_access": {"roles": ["administrator"]},
        },
        settings.require_console_jwt_secret(),
        algorithm="HS256",
    )

    response = http.post(
        receipt_module.WEBHOOK_PATH,
        headers=_headers(Authorization=f"Bearer {console_token}"),
        json=[_event()],
    )

    assert response.status_code == 401
    assert queue.published == []


def test_only_documented_delivery_schema_is_accepted(client: tuple[TestClient, _Queue]) -> None:
    http, queue = client
    engagement = _event(event_type="Microsoft.Communication.EmailEngagementTrackingReportReceived")
    bad_detail = _event(event_id="event-2")
    bad_detail["data"]["deliveryStatusDetails"] = "free-form detail"

    assert http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=[engagement]).status_code == 400
    assert http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=[bad_detail]).status_code == 400
    assert queue.published == []


def test_batch_and_body_are_bounded_before_queueing(client: tuple[TestClient, _Queue]) -> None:
    http, queue = client
    too_many = [_event(event_id=f"event-{index}") for index in range(65)]

    response = http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=too_many)

    assert response.status_code == 400
    assert queue.published == []


def test_duplicate_json_keys_are_rejected(client: tuple[TestClient, _Queue]) -> None:
    http, queue = client
    raw = json.dumps([_event()]).replace('"id": "event-1"', '"id":"event-1","id":"event-2"', 1)

    response = http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), content=raw)

    assert response.status_code == 400
    assert queue.published == []


def test_unconfigured_local_ingress_is_unavailable() -> None:
    settings = _settings(
        acs_receipt_signing_key="",
        event_grid_tenant_id="",
        event_grid_audience="",
        event_grid_subscription_name="",
        event_grid_topic="",
    )
    app = create_app(settings)
    app.state.audit_health_check = lambda: True

    response = TestClient(app).post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=[_event()])

    assert response.status_code == 503


def test_unhealthy_audit_blocks_before_authentication_or_queue_mutation(
    client: tuple[TestClient, _Queue],
) -> None:
    http, queue = client
    http.app.state.audit_health_check = lambda: False

    response = http.post(receipt_module.WEBHOOK_PATH, headers=_headers(), json=[_event()])

    assert response.status_code == 503
    assert response.json()["code"] == "audit_integrity_unhealthy"
    assert queue.published == []


def test_partial_ingress_configuration_fails_application_assembly() -> None:
    settings = _settings(event_grid_topic="")

    with pytest.raises(ValueError, match="configuration is incomplete"):
        create_app(settings)


def test_managed_oidc_configuration_requires_receipt_boundary() -> None:
    with pytest.raises(ValidationError, match="managed ACS receipt ingress"):
        OperatorApiSettings(
            oidc_mode="oidc",
            approval_policy="enforce",
            config_store="managed",
        )


def test_token_verifier_checks_event_grid_application_and_role(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = EventGridTokenVerifier(_settings())
    monkeypatch.setattr(
        verifier._jwk_client,
        "get_signing_key_from_jwt",
        lambda _token: SimpleNamespace(key=object()),
    )
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "tid": TENANT_ID,
        "azp": PUBLISHER,
        "roles": [receipt_module.SUBSCRIBER_ROLE],
    }
    monkeypatch.setattr(receipt_module.jwt, "decode", lambda *_args, **_kwargs: claims)

    verifier.verify("Bearer token")
    claims["azp"] = "99999999-9999-4999-8999-999999999999"
    with pytest.raises(PermissionError, match="unauthorized"):
        verifier.verify("Bearer token")
