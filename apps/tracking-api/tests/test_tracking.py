"""WS-9 / HIGH-04 / HIGH-17 tests for the tracking API.

Exercises dedup of clicks, bearer-gated + rate-limited corrections, XFF
validation, per-token rate limiting, and IP/UA minimization. The DB session
dependency is overridden with a scripted fake so no live Postgres is needed.
"""

from __future__ import annotations

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
from kp_tracking_api.routers import _session


class _Token:
    token_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    status = dm.TokenStatus.ACTIVE
    expires_at = None


class _FakeSession:
    """Scripted stand-in for the ORM session.

    `scalar` answers the dedup lookups (selects over TrackingEvent); all other
    selects (including the token lookup, which we patch out) return None.
    """

    def __init__(self, dedup_event: object | None = None) -> None:
        self.dedup_event = dedup_event
        self.added: list[object] = []

    def scalar(self, stmt: object) -> object | None:  # noqa: ANN001
        return self.dedup_event

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def commit(self) -> None:
        pass

    def flush(self) -> None:
        pass


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


def test_click_is_deduplicated_like_open(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    url = "/v1/track/click/" + "ab" * 32
    with client:
        assert client.get(url, follow_redirects=False).status_code == 302
        assert len(fake.added) == 1
        fake.dedup_event = object()  # simulate the click now existing
        assert client.get(url, follow_redirects=False).status_code == 302
        assert len(fake.added) == 1


def test_open_records_minimized_ip_and_truncated_ua(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    url = "/v1/track/open/" + "ab" * 32
    long_ua = "Mozilla/5.0 " + "x" * 2000
    with client:
        resp = client.get(url, headers={"User-Agent": long_ua})
        assert resp.status_code == 200
        event = fake.added[0]
        assert event.client_ip == "testclient"  # peer, XFF ignored
        assert event.user_agent == long_ua[:128]


def test_xff_only_trusted_behind_configured_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    untrusted = _FakeSession()
    client = _client(monkeypatch, _settings(trusted_proxies=""), untrusted)
    with client:
        client.get("/v1/track/open/" + "ab" * 32, headers={"X-Forwarded-For": "8.8.8.8"})
    assert untrusted.added[0].client_ip == "testclient"

    trusted = _FakeSession()
    client = _client(monkeypatch, _settings(trusted_proxies="testclient"), trusted)
    with client:
        client.get("/v1/track/open/" + "cd" * 32, headers={"X-Forwarded-For": "8.8.8.8"})
    assert trusted.added[0].client_ip == "8.8.8.0"


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
    event = fake.added[0]
    assert before <= event.occurred_at <= after
