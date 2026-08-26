"""WS-9 / HIGH-04 / HIGH-17 tests for the tracking API.

Exercises dedup of clicks, bearer-gated + rate-limited corrections, XFF
validation, per-token rate limiting, IP/UA minimization, the request-body cap
(HIGH-09 residual), security response headers, and CorrectionBody length
limits. The DB session dependency is overridden with a scripted fake so no
live Postgres is needed.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from kp_database.privacy import minimize_ip
from kp_domain_models import models as dm
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from kp_tracking_api.middleware import BodyLimitMiddleware
from kp_tracking_api.routers import _session
from sqlalchemy.dialects import postgresql
from starlette.types import Message


class _Token:
    token_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    recipient_assignment_id = uuid.uuid4()
    status = dm.TokenStatus.ACTIVE
    expires_at = None


class _FakeSession:
    """Scripted stand-in for the ORM session.

    `scalar` answers the dedup lookups (selects over TrackingEvent); all other
    selects (including the token lookup, which we patch out) return None.
    `execute` captures the race-safe INSERT statements.
    """

    def __init__(self, dedup_event: object | None = None) -> None:
        self.dedup_event = dedup_event
        self.scalar_results: list[object | None] = []
        self.get_results: dict[object, object] = {}
        self.added: list[object] = []
        self.executed: list[object] = []

    def scalar(self, stmt: object) -> object | None:  # noqa: ANN001
        if self.scalar_results:
            return self.scalar_results.pop(0)
        return self.dedup_event

    def get(self, model: object, identifier: object, **kwargs: object) -> object | None:
        return self.get_results.get(identifier)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def execute(self, stmt: object) -> object:
        self.executed.append(stmt)
        return None

    def commit(self) -> None:
        pass

    def flush(self) -> None:
        pass


def _insert_params(stmt: object) -> dict[str, object]:
    return dict(stmt.compile(dialect=postgresql.dialect()).params)  # type: ignore[attr-defined]


def _settings(
    *,
    corrections_secret: str = "s3cret",  # noqa: S107
    trusted_proxies: str = "",
    **kw: object,
) -> TrackingApiSettings:
    return TrackingApiSettings(
        corrections_secret=corrections_secret,
        trusted_proxies=trusted_proxies,
        training_base_url="http://train.local/awareness",
        rate_limit_ip_per_min=int(kw.get("rate_limit_ip_per_min", 60)),
        rate_limit_token_per_min=int(kw.get("rate_limit_token_per_min", 5)),
        rate_limit_global_per_min=int(kw.get("rate_limit_global_per_min", 3000)),
        rate_limit_max_keys=int(kw.get("rate_limit_max_keys", 10_000)),
        max_body_bytes=int(kw.get("max_body_bytes", 65_536)),
    )


def _client(
    monkeypatch: pytest.MonkeyPatch,
    settings: TrackingApiSettings,
    fake: _FakeSession,
) -> TestClient:
    app = create_app(settings)

    def _override() -> Iterator[_FakeSession]:
        yield fake

    app.dependency_overrides[_session] = _override

    def _resolve(token_hash: str, session: object) -> _Token | None:  # noqa: ANN001
        if token_hash == "deadbeef" * 8:
            return None
        return _Token()

    monkeypatch.setattr("kp_tracking_api.routers._resolve_active_token", _resolve)
    return TestClient(app)


def test_click_and_open_inserts_are_race_safe_noops_on_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    click_url = "/v1/track/click/" + "ab" * 32
    open_url = "/v1/track/open/" + "cd" * 32
    with client:
        # Repeated clicks/opens keep the same API responses; the partial
        # unique index makes the duplicate inserts no-ops in the database.
        assert client.get(click_url, follow_redirects=False).status_code == 302
        assert client.get(click_url, follow_redirects=False).status_code == 302
        assert client.get(open_url).status_code == 200
        assert client.get(open_url).status_code == 200
    assert len(fake.executed) == 4
    for stmt in fake.executed:
        sql = str(stmt.compile(dialect=postgresql.dialect()))
        assert "ON CONFLICT DO NOTHING" in sql
    assert _insert_params(fake.executed[0])["event_type"] == dm.EventType.CLICKED
    assert _insert_params(fake.executed[2])["event_type"] == dm.EventType.OPENED


def test_local_training_awareness_page(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    with client:
        response = client.get("/v1/training/awareness")
    assert response.status_code == 200
    assert "security awareness simulation" in response.text
    assert response.headers["cache-control"] == "no-store"


def test_open_records_minimized_ip_and_truncated_ua(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    url = "/v1/track/open/" + "ab" * 32
    long_ua = "Mozilla/5.0 " + "x" * 2000
    with client:
        resp = client.get(url, headers={"User-Agent": long_ua})
        assert resp.status_code == 200
        params = _insert_params(fake.executed[0])
        assert params["client_ip"] == "testclient"  # peer, XFF ignored
        assert params["user_agent"] == long_ua[:128]


def test_xff_only_trusted_behind_configured_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    untrusted = _FakeSession()
    client = _client(monkeypatch, _settings(trusted_proxies=""), untrusted)
    with client:
        client.get("/v1/track/open/" + "ab" * 32, headers={"X-Forwarded-For": "8.8.8.8"})
    assert _insert_params(untrusted.executed[0])["client_ip"] == "testclient"

    trusted = _FakeSession()
    client = _client(monkeypatch, _settings(trusted_proxies="testclient"), trusted)
    with client:
        client.get("/v1/track/open/" + "cd" * 32, headers={"X-Forwarded-For": "8.8.8.8"})
    assert _insert_params(trusted.executed[0])["client_ip"] == "8.8.8.0"


def test_corrections_requires_bearer_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    payload = {"token_hash": "ab" * 32, "correction": "opened", "rationale": "user clicked"}

    with client:
        assert client.post("/v1/corrections", json=payload).status_code == 401
        assert (
            client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
        )
        resp = client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer s3cret"})
        assert resp.status_code == 201, resp.text


def test_corrections_not_configured_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(corrections_secret=""), _FakeSession())
    payload = {"token_hash": "ab" * 32, "correction": "opened", "rationale": "reason"}
    with client:
        resp = client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer s3cret"})
        assert resp.status_code == 503


def test_corrections_rate_limited_per_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_ip_per_min=2), _FakeSession())
    payload = {"token_hash": "ab" * 32, "correction": "opened", "rationale": "reason"}
    headers = {"Authorization": "Bearer s3cret"}
    with client:
        assert client.post("/v1/corrections", json=payload, headers=headers).status_code == 201
        assert client.post("/v1/corrections", json=payload, headers=headers).status_code == 201
        assert client.post("/v1/corrections", json=payload, headers=headers).status_code == 429


def test_track_endpoints_rate_limited_per_token(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_token_per_min=2), _FakeSession())
    url = "/v1/track/open/" + "ab" * 32
    with client:
        assert client.get(url).status_code == 200
        assert client.get(url).status_code == 200
        assert client.get(url).status_code == 429


def test_malformed_token_rejected_before_limiter_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_max_keys=2), _FakeSession())
    with client:
        for index in range(100):
            assert client.get(f"/v1/track/open/not-a-hash-{index}").status_code == 404
        assert client.app.state.token_limiter.key_count == 0


def test_track_endpoints_rate_limited_per_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_ip_per_min=2), _FakeSession())
    with client:
        assert client.get("/v1/track/open/" + "ab" * 32).status_code == 200
        assert client.get("/v1/track/open/" + "cd" * 32).status_code == 200
        assert client.get("/v1/track/open/" + "ef" * 32).status_code == 429


def test_track_endpoints_have_global_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(
        monkeypatch,
        _settings(rate_limit_ip_per_min=100, rate_limit_global_per_min=2),
        _FakeSession(),
    )
    with client:
        assert client.get("/v1/track/open/" + "ab" * 32).status_code == 200
        assert client.get("/v1/track/open/" + "cd" * 32).status_code == 200
        assert client.get("/v1/track/open/" + "ef" * 32).status_code == 429


def test_access_log_contains_route_template_not_token_or_client(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    token_hash = "ab" * 32
    with client:
        assert client.get(f"/v1/track/open/{token_hash}").status_code == 200
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    access = next(record for record in records if record.get("event") == "request")
    serialized = json.dumps(access)
    assert token_hash not in serialized
    assert "testclient" not in serialized
    assert access["route"] == "/v1/track/open/{token_hash}"
    assert "path" not in access
    assert "client" not in access


def test_unknown_token_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    with client:
        assert client.get("/v1/track/open/" + "deadbeef" * 8).status_code == 404
        assert client.get("/v1/track/click/" + "deadbeef" * 8).status_code == 404


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.7", "203.0.113.0"),
        ("192.168.1.99", "192.168.1.0"),
        ("2001:db8:85a3:8d3:1319:8a2e:370:7348", "2001:db8:85a3:8d3::"),
        ("already:short", "already:short"),
        (None, None),
    ],
)
def test_minimize_ip_prefixes(raw: str | None, expected: str | None) -> None:
    assert minimize_ip(raw) == expected


def test_events_use_correct_occurred_at(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    before = datetime.now(UTC)
    with client:
        client.get("/v1/track/open/" + "ab" * 32)
    after = datetime.now(UTC)
    occurred_at = _insert_params(fake.executed[0])["occurred_at"]
    assert before <= occurred_at <= after  # type: ignore[operator]


def test_training_completion_creates_assignment_and_event(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    recipient_id = uuid.uuid4()
    fake.get_results[_Token.recipient_assignment_id] = type(
        "RecipientAssignment", (), {"recipient_id": recipient_id, "campaign_id": _Token.campaign_id}
    )()
    resource_id = uuid.uuid4()
    resource = type("TrainingResource", (), {"training_resource_id": resource_id})()
    fake.scalar_results = [None, resource, None]
    client = _client(monkeypatch, _settings(), fake)
    with client:
        response = client.post("/v1/training/" + "ab" * 32 + "/complete")
    assert response.status_code == 200, response.text
    training = next(item for item in fake.added if hasattr(item, "training_assignment_id"))
    event = next(item for item in fake.added if hasattr(item, "event_id"))
    assert training.resource_id == resource_id
    assert training.recipient_id == recipient_id
    assert training.status == dm.TrainingAssignmentStatus.COMPLETED
    assert event.event_type == dm.EventType.TRAINING_COMPLETED
    assert event.recipient_id == recipient_id


def test_training_completion_fails_closed_without_approved_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    fake.get_results[_Token.recipient_assignment_id] = type(
        "RecipientAssignment", (), {"recipient_id": uuid.uuid4(), "campaign_id": _Token.campaign_id}
    )()
    fake.scalar_results = [None, None]
    client = _client(monkeypatch, _settings(), fake)
    with client:
        response = client.post("/v1/training/" + "ab" * 32 + "/complete")
    assert response.status_code == 503
    assert fake.added == []


def test_training_completion_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    recipient_id = uuid.uuid4()
    fake.get_results[_Token.recipient_assignment_id] = type(
        "RecipientAssignment", (), {"recipient_id": recipient_id, "campaign_id": _Token.campaign_id}
    )()
    completed_at = datetime.now(UTC)
    training = type(
        "TrainingAssignment",
        (),
        {
            "training_assignment_id": uuid.uuid4(),
            "completed_at": completed_at,
            "status": dm.TrainingAssignmentStatus.COMPLETED,
        },
    )()
    existing_event = object()
    fake.scalar_results = [training, existing_event]
    client = _client(monkeypatch, _settings(), fake)
    with client:
        response = client.post("/v1/training/" + "ab" * 32 + "/complete")
    assert response.status_code == 200
    assert fake.added == []
    assert training.completed_at == completed_at


def test_body_limit_rejects_oversized_content_length(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(max_body_bytes=64), fake)
    payload = {"token_hash": "ab" * 32, "correction": "x" * 200, "rationale": "reason"}
    with client:
        resp = client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer s3cret"})
    assert resp.status_code == 413
    assert resp.json() == {"detail": "request body too large"}
    assert fake.executed == []
    assert fake.added == []


def _drive_body_limit(
    max_bytes: int, request_messages: list[Message], headers: list[tuple[bytes, bytes]]
) -> list[Message]:
    """Run BodyLimitMiddleware against a stub app that drains the request body."""
    sent: list[Message] = []

    async def stub_app(scope: object, receive: object, send: object) -> None:  # noqa: ANN001
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive() -> Message:
        return request_messages.pop(0)

    async def send(message: Message) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/corrections",
        "query_string": b"",
        "headers": headers,
    }
    middleware = BodyLimitMiddleware(stub_app, max_bytes=max_bytes)  # type: ignore[arg-type]
    asyncio.run(middleware(scope, receive, send))  # type: ignore[arg-type]
    return sent


def test_body_limit_rejects_streamed_body_without_content_length() -> None:
    # Two 8-byte chunks with no content-length header: the streaming guard
    # must abort with 413 once the cumulative size exceeds the cap.
    sent = _drive_body_limit(
        max_bytes=8,
        request_messages=[
            {"type": "http.request", "body": b"12345678", "more_body": True},
            {"type": "http.request", "body": b"12345678", "more_body": False},
        ],
        headers=[],
    )
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413
    assert b"request body too large" in sent[1]["body"]


def test_body_limit_allows_streamed_body_at_cap() -> None:
    sent = _drive_body_limit(
        max_bytes=8,
        request_messages=[
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678", "more_body": False},
        ],
        headers=[],
    )
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"ok"


def test_body_limit_pre_checks_content_length_header() -> None:
    sent = _drive_body_limit(
        max_bytes=8,
        request_messages=[{"type": "http.request", "body": b"", "more_body": False}],
        headers=[(b"content-length", b"100")],
    )
    assert sent[0]["status"] == 413


_EXPECTED_SECURITY_HEADERS = {
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
}


def test_security_headers_on_all_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(max_body_bytes=64), _FakeSession())
    with client:
        responses = [
            client.get("/healthz"),
            client.get("/v1/training/awareness"),
            client.get("/v1/track/open/" + "ab" * 32),
            client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False),
            client.get("/v1/track/open/" + "deadbeef" * 8),  # unknown token -> 404
            client.post(  # oversized body -> 413
                "/v1/corrections",
                json={"token_hash": "ab" * 32, "correction": "x" * 200, "rationale": "r"},
                headers={"Authorization": "Bearer s3cret"},
            ),
            client.get("/v1/track/open/" + "ef" * 32),  # rate limit not hit yet
        ]
    for resp in responses:
        for name, value in _EXPECTED_SECURITY_HEADERS.items():
            assert resp.headers[name] == value, (resp.status_code, name)
    # Route-set headers survive (setdefault semantics, not overwrite).
    click = responses[3]
    assert click.status_code == 302
    assert click.headers["location"] == "http://train.local/awareness"
    assert click.headers["cache-control"] == "no-store"


def test_correction_fields_reject_values_over_storage_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    headers = {"Authorization": "Bearer s3cret"}
    at_limit = {"token_hash": "ab" * 32, "correction": "c" * 2000, "rationale": "r" * 2000}
    with client:
        assert client.post("/v1/corrections", json=at_limit, headers=headers).status_code == 201
        assert (
            client.post("/v1/corrections", json={**at_limit, "correction": "c" * 2001}, headers=headers).status_code
            == 422
        )
        assert (
            client.post("/v1/corrections", json={**at_limit, "rationale": "r" * 2001}, headers=headers).status_code
            == 422
        )
