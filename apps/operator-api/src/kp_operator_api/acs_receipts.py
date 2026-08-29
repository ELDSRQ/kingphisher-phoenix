"""Authenticated Azure Event Grid ingress for ACS delivery receipts.

This public boundary accepts only the Event Grid schema used by Azure
Communication Services email delivery reports. The bearer token is verified
before the body is parsed, and the authenticated event is HMAC-bound before it
enters Redis so an internal queue writer cannot forge provider evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient

from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.oidc_provider import MAX_OIDC_JWKS_BYTES, OidcProviderResponseError, bounded_json

WEBHOOK_PATH = "/api/v1/integrations/acs/events"
SUBSCRIBER_ROLE = "AzureEventGridSecureWebhookSubscriber"
DELIVERY_EVENT_TYPE = "Microsoft.Communication.EmailDeliveryReportReceived"
VALIDATION_EVENT_TYPE = "Microsoft.EventGrid.SubscriptionValidationEvent"
_DELIVERY_STATUSES = frozenset(
    {"Delivered", "Bounced", "Suppressed", "Quarantined", "FilteredSpam", "Expanded", "Failed"}
)
_EVENT_ID = re.compile(r"[A-Za-z0-9._:/+-]{1,256}\Z")
_VALIDATION_CODE = re.compile(r"[^\x00-\x1f\x7f]{1,256}\Z")
_MICROSOFT_LOGIN_HOST = "login.microsoftonline.com"
_MAX_JWKS_URL_BYTES = 2048
_MAX_JWKS_RESPONSE_HEADERS = 64
_MAX_JWKS_RESPONSE_HEADER_BYTES = 16 * 1024
_MAX_JWKS_TOP_LEVEL_MEMBERS = 8
_MAX_JWKS_KEYS = 32
_MAX_JWK_MEMBERS = 32
_MAX_JWK_MEMBER_NAME_BYTES = 64
_MAX_JWK_STRING_BYTES = 16 * 1024
_MAX_JWK_LIST_ITEMS = 16

router = APIRouter()


class _InvalidPayload(ValueError):
    pass


def _validate_event_grid_jwks_url(url: str, *, tenant_id: str) -> None:
    """Allow only the tenant-derived Microsoft signing-key endpoint."""

    if len(url.encode("utf-8")) > _MAX_JWKS_URL_BYTES:
        raise jwt.PyJWKClientError("Event Grid JWKS URL is invalid")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise jwt.PyJWKClientError("Event Grid JWKS URL is invalid") from None
    expected_path = f"/{tenant_id}/discovery/v2.0/keys"
    if (
        parsed.scheme != "https"
        or parsed.hostname != _MICROSOFT_LOGIN_HOST
        or parsed.netloc != _MICROSOFT_LOGIN_HOST
        or port is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        # The URL is not read from the token or provider metadata. Keeping an
        # exact host/path allowlist also prevents future refactors from turning
        # this verifier into a private-network or Azure metadata request proxy.
        raise jwt.PyJWKClientError("Event Grid JWKS URL is invalid")


def _validate_jwks_headers(response: httpx.Response) -> None:
    raw_headers = response.headers.raw
    total_bytes = sum(len(name) + len(value) + 4 for name, value in raw_headers)
    if len(raw_headers) > _MAX_JWKS_RESPONSE_HEADERS or total_bytes > _MAX_JWKS_RESPONSE_HEADER_BYTES:
        raise OidcProviderResponseError("identity provider returned excessive response headers")


def _validate_jwk_member(value: Any) -> bool:
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= _MAX_JWK_STRING_BYTES
    if isinstance(value, list):
        return len(value) <= _MAX_JWK_LIST_ITEMS and all(
            isinstance(item, str) and len(item.encode("utf-8")) <= _MAX_JWK_STRING_BYTES for item in value
        )
    return value is None or isinstance(value, (bool, int, float))


def _validate_jwk_set(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or len(payload) > _MAX_JWKS_TOP_LEVEL_MEMBERS:
        raise jwt.PyJWKClientError("Event Grid JWKS response is invalid")
    keys = payload.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= _MAX_JWKS_KEYS:
        raise jwt.PyJWKClientError("Event Grid JWKS response is invalid")
    for key in keys:
        if not isinstance(key, dict) or not 1 <= len(key) <= _MAX_JWK_MEMBERS:
            raise jwt.PyJWKClientError("Event Grid JWKS response is invalid")
        if any(
            len(name.encode("utf-8")) > _MAX_JWK_MEMBER_NAME_BYTES or not _validate_jwk_member(value)
            for name, value in key.items()
        ):
            raise jwt.PyJWKClientError("Event Grid JWKS response is invalid")
    return payload


class _BoundedEventGridJWKClient(PyJWKClient):
    """Retain PyJWT key caching and rotation with a bounded HTTPS fetch."""

    def __init__(self, uri: str, *, tenant_id: str, timeout: float = 5.0) -> None:
        _validate_event_grid_jwks_url(uri, tenant_id=tenant_id)
        self._tenant_id = tenant_id
        super().__init__(uri, cache_jwk_set=True, lifespan=3600, timeout=timeout)

    def fetch_data(self) -> Any:
        _validate_event_grid_jwks_url(self.uri, tenant_id=self._tenant_id)
        try:
            timeout = httpx.Timeout(self.timeout)
            with (
                httpx.Client(
                    timeout=timeout,
                    follow_redirects=False,
                    headers=self.headers,
                    verify=self.ssl_context or True,
                ) as client,
                client.stream("GET", self.uri) as response,
            ):
                _validate_jwks_headers(response)
                response.raise_for_status()
                payload = bounded_json(response, max_bytes=MAX_OIDC_JWKS_BYTES)
        except (httpx.HTTPError, OidcProviderResponseError) as exc:
            raise jwt.PyJWKClientConnectionError("Event Grid JWKS fetch failed") from exc

        jwk_set = _validate_jwk_set(payload)
        # Cache only a fully read and validated set. A hostile or unavailable
        # rotation endpoint must not erase the last known-good signing keys.
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)  # type: ignore[arg-type]
        return jwk_set


class EventGridTokenVerifier:
    """Verify tenant, audience, caller application, role, and JWT lifetime."""

    def __init__(self, settings: OperatorApiSettings) -> None:
        self._tenant_id = str(uuid.UUID(settings.event_grid_tenant_id))
        self._audience = str(uuid.UUID(settings.event_grid_audience))
        self._publisher_app_id = str(uuid.UUID(settings.event_grid_publisher_app_id))
        self._issuers = (
            f"https://login.microsoftonline.com/{self._tenant_id}/v2.0",
            f"https://sts.windows.net/{self._tenant_id}/",
        )
        self._jwk_client = _BoundedEventGridJWKClient(
            f"https://{_MICROSOFT_LOGIN_HOST}/{self._tenant_id}/discovery/v2.0/keys",
            tenant_id=self._tenant_id,
        )

    def verify(self, authorization: str) -> None:
        if not authorization.startswith("Bearer "):
            raise PermissionError("missing bearer token")
        token = authorization.removeprefix("Bearer ").strip()
        if not token or len(token) > 16_384:
            raise PermissionError("malformed bearer token")
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                options={"require": ["exp", "iss", "aud"], "verify_iss": False},
            )
        except jwt.PyJWTError as exc:
            raise PermissionError("invalid bearer token") from exc

        issuer = claims.get("iss")
        tenant = claims.get("tid")
        caller = claims.get("azp") or claims.get("appid")
        roles = claims.get("roles")
        if (
            not isinstance(issuer, str)
            or not any(secrets.compare_digest(issuer, allowed) for allowed in self._issuers)
            or not isinstance(tenant, str)
            or not secrets.compare_digest(tenant.lower(), self._tenant_id)
            or not isinstance(caller, str)
            or not secrets.compare_digest(caller.lower(), self._publisher_app_id)
            or not isinstance(roles, list)
            or SUBSCRIBER_ROLE not in roles
        ):
            raise PermissionError("unauthorized Event Grid caller")


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidPayload("duplicate JSON key")
        result[key] = value
    return result


def _parse_batch(raw: bytes, *, max_events: int) -> list[dict[str, Any]]:
    try:
        payload = json.loads(raw, object_pairs_hook=_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _InvalidPayload) as exc:
        raise _InvalidPayload("invalid Event Grid JSON") from exc
    if not isinstance(payload, list) or not 1 <= len(payload) <= max_events:
        raise _InvalidPayload("Event Grid body must be a bounded non-empty array")
    if not all(isinstance(event, dict) for event in payload):
        raise _InvalidPayload("Event Grid events must be objects")
    return payload


def _validate_common_event(event: dict[str, Any], *, expected_topic: str) -> None:
    event_id = event.get("id")
    topic = event.get("topic")
    event_time = event.get("eventTime")
    if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None:
        raise _InvalidPayload("invalid Event Grid event ID")
    if not isinstance(topic, str) or not secrets.compare_digest(topic.casefold(), expected_topic.casefold()):
        raise _InvalidPayload("unexpected Event Grid topic")
    if not isinstance(event_time, str) or len(event_time) > 64:
        raise _InvalidPayload("invalid Event Grid timestamp")
    try:
        timestamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _InvalidPayload("invalid Event Grid timestamp") from exc
    if timestamp.tzinfo is None:
        raise _InvalidPayload("Event Grid timestamp must include a timezone")
    timestamp.astimezone(UTC)


def _validate_delivery_event(event: dict[str, Any], *, expected_topic: str) -> None:
    _validate_common_event(event, expected_topic=expected_topic)
    if event.get("eventType") != DELIVERY_EVENT_TYPE:
        raise _InvalidPayload("unsupported Event Grid event type")
    if event.get("dataVersion") != "1.0" or event.get("metadataVersion") != "1":
        raise _InvalidPayload("unsupported ACS delivery event schema version")
    subject = event.get("subject")
    if not isinstance(subject, str) or len(subject) > 1024:
        raise _InvalidPayload("invalid ACS event subject")
    data = event.get("data")
    if not isinstance(data, dict):
        raise _InvalidPayload("invalid ACS delivery event data")
    message_id = data.get("messageId")
    if not isinstance(message_id, str) or not 1 <= len(message_id) <= 512:
        raise _InvalidPayload("invalid ACS provider message ID")
    if data.get("status") not in _DELIVERY_STATUSES:
        raise _InvalidPayload("unsupported ACS delivery status")
    for mailbox_field in ("sender", "recipient"):
        mailbox = data.get(mailbox_field)
        if not isinstance(mailbox, str) or not 3 <= len(mailbox) <= 320 or "@" not in mailbox:
            raise _InvalidPayload("invalid ACS mailbox field")
    detail = data.get("deliveryStatusDetails")
    if detail is not None:
        if not isinstance(detail, dict) or len(detail) > 16:
            raise _InvalidPayload("invalid ACS delivery status details")
        status_message = detail.get("statusMessage")
        if status_message is not None and (not isinstance(status_message, str) or len(status_message) > 4096):
            raise _InvalidPayload("invalid ACS delivery status message")


def _validation_response(event: dict[str, Any], *, expected_topic: str) -> str:
    _validate_common_event(event, expected_topic=expected_topic)
    if event.get("eventType") != VALIDATION_EVENT_TYPE:
        raise _InvalidPayload("invalid subscription validation event")
    data = event.get("data")
    code = data.get("validationCode") if isinstance(data, dict) else None
    if not isinstance(code, str) or _VALIDATION_CODE.fullmatch(code) is None:
        raise _InvalidPayload("invalid subscription validation code")
    return code


def _canonical_event(event: dict[str, Any]) -> bytes:
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _minimize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields the delivery consumer needs; hash free-form detail."""

    data = event["data"]
    detail = data.get("deliveryStatusDetails")
    detail_hash = hashlib.sha256(_canonical_event(detail)).hexdigest() if detail is not None else None
    return {
        "id": event["id"],
        "eventType": event["eventType"],
        "dataVersion": event["dataVersion"],
        "metadataVersion": event["metadataVersion"],
        "eventTime": event["eventTime"],
        "data": {
            "messageId": data["messageId"],
            "status": data["status"],
            "deliveryStatusDetailsHash": detail_hash,
        },
    }


@router.post(WEBHOOK_PATH, response_model=None)
async def receive_acs_event_grid(request: Request) -> JSONResponse:
    """Authenticate, bound, validate, and queue an ACS Event Grid batch."""

    settings: OperatorApiSettings = request.app.state.settings
    verifier: EventGridTokenVerifier | None = request.app.state.event_grid_token_verifier
    if verifier is None:
        return JSONResponse(status_code=503, content={"detail": "ACS receipt ingress is unavailable"})
    try:
        verifier.verify(request.headers.get("authorization", ""))
    except PermissionError:
        return JSONResponse(status_code=401, content={"detail": "invalid Event Grid authentication"})

    subscription = request.headers.get("aeg-subscription-name", "")
    if not secrets.compare_digest(subscription, settings.event_grid_subscription_name):
        return JSONResponse(status_code=403, content={"detail": "unexpected Event Grid subscription"})
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        return JSONResponse(status_code=415, content={"detail": "application/json is required"})
    raw = await request.body()
    if not raw or len(raw) > settings.event_grid_max_body_bytes:
        return JSONResponse(status_code=413, content={"detail": "Event Grid body is outside the allowed size"})
    try:
        events = _parse_batch(raw, max_events=settings.event_grid_max_events)
        event_kind = request.headers.get("aeg-event-type", "")
        if event_kind == "SubscriptionValidation":
            if len(events) != 1:
                raise _InvalidPayload("subscription validation must contain one event")
            validation_code = _validation_response(events[0], expected_topic=settings.event_grid_topic)
            return JSONResponse(status_code=200, content={"validationResponse": validation_code})
        if event_kind != "Notification":
            raise _InvalidPayload("unsupported Event Grid request type")
        for event in events:
            _validate_delivery_event(event, expected_topic=settings.event_grid_topic)
    except _InvalidPayload:
        return JSONResponse(status_code=400, content={"detail": "invalid ACS Event Grid payload"})

    signing_key = settings.require_acs_receipt_signing_key()
    try:
        for event in events:
            minimized_event = _minimize_event(event)
            canonical = _canonical_event(minimized_event)
            signature = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
            event_id_hash = hashlib.sha256(str(event["id"]).encode("utf-8")).hexdigest()
            request.app.state.queue.publish(
                "deliver",
                {"job_type": "acs_delivery_receipt", "event": minimized_event, "signature": signature},
                idempotency_key=f"acs-receipt:{event_id_hash}",
            )
    except Exception:
        return JSONResponse(status_code=503, content={"detail": "receipt queue is unavailable"})
    return JSONResponse(status_code=200, content={"accepted": len(events)})
