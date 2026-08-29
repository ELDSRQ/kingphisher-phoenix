"""WS-9 / HIGH-04 / HIGH-17 tests for the tracking API.

Exercises dedup of clicks, permanent no-write retirement of legacy
corrections, XFF validation, per-token rate limiting, IP/UA minimization, the
request-body cap (HIGH-09 residual), and security response headers. The DB
session dependency is overridden with a scripted fake so no live Postgres is
needed.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from kp_database.campaign_service import (
    campaign_content_manifest_hash,
    tracking_token_verifier,
    training_resource_content_digest,
)
from kp_database.models import RecipientAssignment
from kp_database.privacy import minimize_ip
from kp_database.training import TrainingBearerPurpose, training_bearer, training_bearer_verifier
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, KpError
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from kp_tracking_api.middleware import BodyLimitMiddleware
from kp_tracking_api.routers import (
    _assigned_training_resource,
    _campaign_training_resource,
    _resolve_active_token,
    _resolve_training_assignment,
    _session,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import Message


class _Token:
    token_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    recipient_assignment_id = uuid.uuid4()
    status = dm.TokenStatus.ACTIVE
    expires_at = None


class _RecipientAssignment:
    recipient_assignment_id = _Token.recipient_assignment_id
    recipient_id = uuid.uuid4()
    campaign_id = _Token.campaign_id
    token_id = _Token.token_id


TRACKING_KEY = b"k" * 32
TRAINING_KEY = b"t" * 32


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
        self.get_calls: list[tuple[object, object, dict[str, object]]] = []
        self.scalar_statements: list[object] = []
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0

    def scalar(self, stmt: object) -> object | None:  # noqa: ANN001
        self.scalar_statements.append(stmt)
        if self.scalar_results:
            return self.scalar_results.pop(0)
        return self.dedup_event

    def get(self, model: object, identifier: object, **kwargs: object) -> object | None:
        self.get_calls.append((model, identifier, kwargs))
        return self.get_results.get(identifier)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def execute(self, stmt: object) -> object:
        self.executed.append(stmt)
        return None

    def commit(self) -> None:
        self.commits += 1

    def flush(self) -> None:
        pass


def _insert_params(stmt: object) -> dict[str, object]:
    return dict(stmt.compile(dialect=postgresql.dialect()).params)  # type: ignore[attr-defined]


def _settings(
    *,
    trusted_proxies: str = "",
    **kw: object,
) -> TrackingApiSettings:
    return TrackingApiSettings(
        trusted_proxies=trusted_proxies,
        training_base_url="http://train.local/awareness",
        tracking_token_hmac_key=str(kw.get("tracking_token_hmac_key", TRACKING_KEY.hex())),
        training_token_hmac_key=str(kw.get("training_token_hmac_key", TRAINING_KEY.hex())),
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
    *,
    real_training: bool = False,
    client_address: tuple[str, int] = ("testclient", 50000),
) -> TestClient:
    app = create_app(settings)

    def _override() -> Iterator[_FakeSession]:
        yield fake

    app.dependency_overrides[_session] = _override
    fake.get_results.setdefault(_Token.recipient_assignment_id, _RecipientAssignment())

    def _resolve(token_hash: str, session: object, verifier_key: bytes) -> _Token | None:  # noqa: ANN001
        if token_hash == "deadbeef" * 8:
            return None
        return _Token()

    monkeypatch.setattr("kp_tracking_api.routers._resolve_active_token", _resolve)
    if not real_training:
        monkeypatch.setattr(
            "kp_tracking_api.routers._ensure_training_assignment",
            lambda *args, **kwargs: (object(), "T" * 75),
        )
    return TestClient(app, client=client_address)


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
    assert all(
        _insert_params(statement)["recipient_assignment_id"] == _Token.recipient_assignment_id
        for statement in fake.executed
    )
    assert fake.commits == 4


def test_click_event_and_training_assignment_commit_atomically_under_assignment_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeSession()
    observed_before_training: list[tuple[int, int]] = []

    def ensure_training(*_args: object, **_kwargs: object) -> tuple[object, str]:
        observed_before_training.append((len(fake.executed), fake.commits))
        return object(), "T" * 75

    client = _client(monkeypatch, _settings(), fake)
    monkeypatch.setattr("kp_tracking_api.routers._ensure_training_assignment", ensure_training)
    with client:
        response = client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False)

    assert response.status_code == 302
    assert observed_before_training == [(1, 0)]
    assert fake.commits == 1
    assert any(
        identifier == _Token.recipient_assignment_id and kwargs == {"with_for_update": True, "populate_existing": True}
        for _, identifier, kwargs in fake.get_calls
    )


def test_local_training_awareness_page(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    with client:
        response = client.get("/v1/training/awareness")
    assert response.status_code == 200
    assert "security awareness simulation" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")


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
    client = _client(
        monkeypatch,
        _settings(trusted_proxies="10.42.0.0/23"),
        trusted,
        client_address=("10.42.0.7", 50000),
    )
    with client:
        client.get("/v1/track/open/" + "cd" * 32, headers={"X-Forwarded-For": "8.8.8.8"})
    assert _insert_params(trusted.executed[0])["client_ip"] == "8.8.8.0"


def test_xff_walks_from_trusted_ingress_and_ignores_spoofed_leftmost_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeSession()
    client = _client(
        monkeypatch,
        _settings(trusted_proxies="10.42.0.0/23,127.0.0.1/32"),
        fake,
        client_address=("10.42.0.7", 50000),
    )

    with client:
        response = client.get(
            "/v1/track/open/" + "ef" * 32,
            headers={"X-Forwarded-For": "198.51.100.25, 203.0.113.9"},
        )

    assert response.status_code == 200
    assert _insert_params(fake.executed[0])["client_ip"] == "203.0.113.0"


def test_xff_scope_suffix_cannot_evade_ip_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(
        monkeypatch,
        _settings(trusted_proxies="10.42.0.0/23", rate_limit_ip_per_min=1),
        fake,
        client_address=("10.42.0.7", 50000),
    )
    with client:
        first = client.get(
            "/v1/track/open/" + "A" * 43,
            headers={"X-Forwarded-For": "8.8.8.8%attacker-one"},
        )
        second = client.get(
            "/v1/track/open/" + "B" * 43,
            headers={"X-Forwarded-For": "8.8.8.8%attacker-two"},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert _insert_params(fake.executed[0])["client_ip"] == "8.8.8.0"


def test_legacy_corrections_are_stably_gone_for_every_bearer_and_never_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    payload = {"token_hash": "ab" * 32, "correction": "opened", "rationale": "user clicked"}

    with client:
        responses = [
            client.post("/v1/corrections", json=payload),
            client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer wrong"}),
            client.post("/v1/corrections", json=payload, headers={"Authorization": "Bearer s3cret"}),
        ]
    for response in responses:
        assert response.status_code == 410
        assert response.json() == {
            "code": "legacy_corrections_retired",
            "detail": "legacy correction ingestion is retired; no correction was recorded",
        }
        assert response.headers["cache-control"] == "no-store"
    assert fake.added == []
    assert fake.executed == []
    # The schema remains available to in-process contract tests while its HTTP
    # endpoint is deliberately disabled on the public tracking service.
    operation = client.app.openapi()["paths"]["/v1/corrections"]["post"]
    assert "410" in operation["responses"]
    assert "requestBody" not in operation


def test_track_endpoints_rate_limited_per_token(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_token_per_min=2), _FakeSession())
    url = "/v1/track/open/" + "ab" * 32
    with client:
        assert client.get(url).status_code == 200
        assert client.get(url).status_code == 200
        assert client.get(url).status_code == 429


def test_case_distinct_bearers_do_not_share_a_rate_limit_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(rate_limit_token_per_min=1), _FakeSession())
    with client:
        assert client.get("/v1/track/open/" + "A" * 43).status_code == 200
        assert client.get("/v1/track/open/" + "a" * 43).status_code == 200


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
    secret_query = "recipient@example.com/" + "A" * 43
    with client:
        assert client.get(f"/v1/track/open/{token_hash}", params={"return_to": secret_query}).status_code == 200
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    access = next(record for record in records if record.get("event") == "request")
    serialized = json.dumps(access)
    assert token_hash not in serialized
    assert secret_query not in serialized
    assert "testclient" not in serialized
    assert access["route"] == "/v1/track/open/{token_hash}"
    assert "path" not in access
    assert "client" not in access


def test_unknown_token_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    with client:
        assert client.get("/v1/track/open/" + "deadbeef" * 8).status_code == 404
        assert client.get("/v1/track/click/" + "deadbeef" * 8).status_code == 404


def test_non_contract_methods_never_record_tracking_or_corrections(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    track_path = "/v1/track/open/" + "A" * 43
    with client:
        responses = [
            client.head(track_path),
            client.post(track_path),
            client.get("/v1/corrections"),
            client.put("/v1/corrections"),
        ]

    assert [response.status_code for response in responses] == [405, 405, 405, 405]
    assert fake.added == []
    assert fake.executed == []


def test_malformed_and_unknown_tokens_have_the_same_public_response(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    with client:
        malformed = client.get("/v1/track/open/not-a-bearer")
        unknown = client.get("/v1/track/open/" + "deadbeef" * 8)

    assert malformed.status_code == unknown.status_code == 404
    assert malformed.content == unknown.content == b'{"detail":"not found"}'
    assert malformed.headers["content-type"] == unknown.headers["content-type"]
    assert malformed.headers["cache-control"] == unknown.headers["cache-control"] == "no-store"


def test_valid_opaque_bearer_works_but_database_verifier_cannot_be_replayed() -> None:
    raw_bearer = "A" * 43
    stored_verifier = tracking_token_verifier(raw_bearer, TRACKING_KEY)
    token = _Token()

    class LookupSession:
        def __init__(self) -> None:
            self.executed: list[object] = []
            self.assignment = _RecipientAssignment()

        def scalar(self, statement: object) -> _Token | None:
            params = statement.compile(dialect=postgresql.dialect()).params  # type: ignore[attr-defined]
            return token if stored_verifier in params.values() else None

        def execute(self, statement: object) -> None:
            self.executed.append(statement)

        def get(self, model: object, identifier: object, **options: object) -> object | None:
            if model is RecipientAssignment and identifier == token.recipient_assignment_id:
                assert options == {"with_for_update": True, "populate_existing": True}
                return self.assignment
            return None

        def commit(self) -> None:
            pass

    session = LookupSession()
    assert _resolve_active_token(raw_bearer, session, TRACKING_KEY) is token  # type: ignore[arg-type]
    assert _resolve_active_token(stored_verifier, session, TRACKING_KEY) is None  # type: ignore[arg-type]

    app = create_app(_settings())

    def override() -> Iterator[LookupSession]:
        yield session

    app.dependency_overrides[_session] = override
    with TestClient(app) as client:
        assert client.get(f"/v1/track/open/{raw_bearer}").status_code == 200
        assert client.get(f"/v1/track/open/{stored_verifier}").status_code == 404


def test_tracking_fails_closed_when_verifier_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(tracking_token_hmac_key=""), _FakeSession())
    with client:
        response = client.get("/v1/track/open/" + "ab" * 32)
    assert response.status_code == 503


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


def test_click_opens_and_completes_training_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    recipient_id = uuid.uuid4()
    recipient_assignment = type(
        "RecipientAssignment",
        (),
        {
            "recipient_assignment_id": _Token.recipient_assignment_id,
            "recipient_id": recipient_id,
            "campaign_id": _Token.campaign_id,
            "token_id": _Token.token_id,
        },
    )()
    fake.get_results[_Token.recipient_assignment_id] = recipient_assignment
    fake.get_results[_Token.token_id] = _Token()
    resource_id = uuid.uuid4()
    resource = type(
        "TrainingResource",
        (),
        {
            "training_resource_id": resource_id,
            "title": "Safe <script>alert(1)</script>",
            "content": "Never run <img src=x onerror=alert(1)>",
            "version": 3,
            "requires_completion": True,
            "approval_state": dm.TemplateApprovalState.APPROVED,
            "knowledge_question": None,
            "knowledge_options": None,
            "knowledge_answer_index": None,
        },
    )()
    campaign = type(
        "Campaign",
        (),
        {
            "campaign_id": _Token.campaign_id,
            "pattern_id": uuid.uuid4(),
            "current_template_id": uuid.uuid4(),
            "training_resource_id": resource_id,
            "training_resource_version": resource.version,
            "training_resource_digest": training_resource_content_digest(resource),
        },
    )()
    campaign.manifest_hash = campaign_content_manifest_hash(campaign)
    fake.get_results[_Token.campaign_id] = campaign
    fake.get_results[resource_id] = resource
    fake.scalar_results = [None]
    client = _client(monkeypatch, _settings(), fake, real_training=True)
    with client:
        click = client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False)
        assert click.status_code == 302
        training_path = click.headers["location"]
        assert training_path.startswith("/v1/training/")
        raw_bearer = training_path.rsplit("/", 1)[-1]

        training = next(item for item in fake.added if hasattr(item, "training_assignment_id"))
        assert training.training_token_hash == training_bearer_verifier(
            raw_bearer,
            TRAINING_KEY,
            purpose=TrainingBearerPurpose.OPEN,
        )
        assert raw_bearer not in training.training_token_hash
        assert campaign.training_resource_id == resource_id

        # A later library retirement cannot rewrite or break an assignment
        # already bound to this campaign.
        resource.approval_state = dm.TemplateApprovalState.SUPERSEDED
        fake.scalar_results = [training]
        opened = client.get(training_path)
        assert opened.status_code == 200
        assert "Knowledge check" in opened.text
        assert "Submit answer" in opened.text
        assert "<script>" not in opened.text
        assert "&lt;script&gt;" in opened.text
        assert opened.headers["content-security-policy"].startswith("default-src 'none'")
        assert opened.headers["referrer-policy"] == "no-referrer"
        assert opened.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
        action_match = re.search(r'action="(/v1/training/([^/]+)/complete)"', opened.text)
        assert action_match is not None
        completion_path, completion_bearer = action_match.groups()
        assert completion_bearer != raw_bearer
        assert training.training_completion_token_hash == training_bearer_verifier(
            completion_bearer,
            TRAINING_KEY,
            purpose=TrainingBearerPurpose.COMPLETE,
        )

        fake.scalar_results = [training]
        assert client.post(training_path + "/complete").status_code == 404
        fake.scalar_results = [training]
        assert client.get(f"/v1/training/{completion_bearer}").status_code == 404

        # A missing or incorrect answer must not turn a page view into a
        # training pass. The same completion bearer remains usable to retry.
        fake.scalar_results = [training]
        missing = client.post(completion_path)
        assert missing.status_code == 422
        assert "Not quite" in missing.text
        assert training.completed_at is None

        fake.scalar_results = [training]
        incorrect = client.post(completion_path, data={"answer": "act_immediately"})
        assert incorrect.status_code == 422
        assert "Not quite" in incorrect.text
        assert training.completed_at is None

        fake.scalar_results = [training]
        completed = client.post(completion_path, data={"answer": "verify_independently"})
        assert completed.status_code == 200
        assert "Training complete" in completed.text
        first_completed_at = training.completed_at

        fake.scalar_results = [training]
        replay = client.post(completion_path)
        assert replay.status_code == 200
        assert training.completed_at == first_completed_at

    training = next(item for item in fake.added if hasattr(item, "training_assignment_id"))
    assert training.resource_id == resource_id
    assert training.recipient_id == recipient_id
    assert training.status == dm.TrainingAssignmentStatus.COMPLETED
    event_types = [_insert_params(statement)["event_type"] for statement in fake.executed]
    assert event_types == [
        dm.EventType.CLICKED,
        dm.EventType.TRAINING_STARTED,
        dm.EventType.HUMAN_INTERACTION_CONFIRMED,
        dm.EventType.HUMAN_INTERACTION_CONFIRMED,
        dm.EventType.TRAINING_COMPLETED,
    ]
    # The confirmed-human write is additive: the scanner-triggerable click is
    # neither relabelled nor removed, and each quiz retry remains a race-safe
    # insert/no-op against the immutable event ledger.
    confirmed = [
        _insert_params(statement)
        for statement in fake.executed
        if _insert_params(statement)["event_type"] == dm.EventType.HUMAN_INTERACTION_CONFIRMED
    ]
    assert len(confirmed) == 2
    assert all(item["recipient_assignment_id"] == recipient_assignment.recipient_assignment_id for item in confirmed)
    assert all(
        "ON CONFLICT DO NOTHING" in str(statement.compile(dialect=postgresql.dialect())) for statement in fake.executed
    )


def test_campaign_specific_knowledge_check_renders_and_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lesson with a knowledge check binds its own question and answer.

    TRN-010: the tracking page renders the campaign-bound question and
    options (never the correct-answer index), completes only on the correct
    option, and leaves the generic quiz untouched for legacy lessons.
    """

    fake = _FakeSession()
    recipient_assignment = type(
        "RecipientAssignment",
        (),
        {
            "recipient_assignment_id": _Token.recipient_assignment_id,
            "recipient_id": uuid.uuid4(),
            "campaign_id": _Token.campaign_id,
            "token_id": _Token.token_id,
        },
    )()
    fake.get_results[_Token.recipient_assignment_id] = recipient_assignment
    fake.get_results[_Token.token_id] = _Token()
    resource_id = uuid.uuid4()
    question = "An unexpected message asks you to reset your password. What is the safest response?"
    options = [
        "Verify the request through a trusted, independent channel",
        "Act immediately so the request does not expire",
        "Reply with credentials to prove your identity",
    ]
    resource = type(
        "TrainingResource",
        (),
        {
            "training_resource_id": resource_id,
            "title": "Password reset warning signs",
            "content": "Never reply with credentials.",
            "version": 3,
            "requires_completion": True,
            "approval_state": dm.TemplateApprovalState.APPROVED,
            "knowledge_question": question,
            "knowledge_options": options,
            "knowledge_answer_index": 0,
        },
    )()
    campaign = type(
        "Campaign",
        (),
        {
            "campaign_id": _Token.campaign_id,
            "pattern_id": uuid.uuid4(),
            "current_template_id": uuid.uuid4(),
            "training_resource_id": resource_id,
            "training_resource_version": resource.version,
            "training_resource_digest": training_resource_content_digest(resource),
        },
    )()
    campaign.manifest_hash = campaign_content_manifest_hash(campaign)
    fake.get_results[_Token.campaign_id] = campaign
    fake.get_results[resource_id] = resource
    fake.scalar_results = [None]
    client = _client(monkeypatch, _settings(), fake, real_training=True)
    with client:
        click = client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False)
        assert click.status_code == 302
        training_path = click.headers["location"]

        training = next(item for item in fake.added if hasattr(item, "training_assignment_id"))
        fake.scalar_results = [training]
        opened = client.get(training_path)
        assert opened.status_code == 200
        assert question in opened.text
        for option in options:
            assert option in opened.text
        # The correct-answer index must never appear in recipient-facing HTML.
        assert 'name="answer" value="0"' not in opened.text
        assert "answer_index" not in opened.text
        assert "correct answer" not in opened.text
        # The generic quiz text is replaced, not merged.
        assert "Act immediately so the request does not expire" in opened.text
        action_match = re.search(r'action="(/v1/training/([^/]+)/complete)"', opened.text)
        assert action_match is not None
        completion_path = action_match.group(1)

        fake.scalar_results = [training]
        wrong = client.post(completion_path, data={"answer": options[2]})
        assert wrong.status_code == 422
        assert "Not quite" in wrong.text
        assert training.completed_at is None

        fake.scalar_results = [training]
        unknown = client.post(completion_path, data={"answer": "not_an_option"})
        assert unknown.status_code == 422
        assert training.completed_at is None

        fake.scalar_results = [training]
        completed = client.post(completion_path, data={"answer": options[0]})
        assert completed.status_code == 200
        assert "Training complete" in completed.text
        assert training.completed_at is not None


def test_click_fails_closed_without_approved_training_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    fake.get_results[_Token.recipient_assignment_id] = type(
        "RecipientAssignment",
        (),
        {
            "recipient_assignment_id": _Token.recipient_assignment_id,
            "recipient_id": uuid.uuid4(),
            "campaign_id": _Token.campaign_id,
            "token_id": _Token.token_id,
        },
    )()
    fake.get_results[_Token.campaign_id] = type(
        "Campaign",
        (),
        {
            "training_resource_id": None,
            "training_resource_version": None,
            "training_resource_digest": None,
        },
    )()
    fake.scalar_results = [None]
    client = _client(monkeypatch, _settings(), fake, real_training=True)
    with client:
        response = client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False)
    assert response.status_code == 503
    assert response.json() == {
        "detail": (
            "campaign has no exact reviewed training lesson binding; choose an approved lesson "
            "and review the campaign again"
        )
    }
    assert fake.added == []


def test_campaign_training_binding_is_explicit_and_superseded_resource_fails_closed() -> None:
    fake = _FakeSession()
    campaign_id = uuid.uuid4()
    original_id = uuid.uuid4()
    original = type(
        "TrainingResource",
        (),
        {
            "training_resource_id": original_id,
            "approval_state": dm.TemplateApprovalState.APPROVED,
            "requires_completion": True,
            "version": 2,
            "content": "Review the sender and verify through a trusted channel.",
            "knowledge_question": None,
            "knowledge_options": None,
            "knowledge_answer_index": None,
        },
    )()
    campaign = type(
        "Campaign",
        (),
        {
            "campaign_id": campaign_id,
            "pattern_id": uuid.uuid4(),
            "current_template_id": uuid.uuid4(),
            "training_resource_id": original_id,
            "training_resource_version": original.version,
            "training_resource_digest": training_resource_content_digest(original),
        },
    )()
    campaign.manifest_hash = campaign_content_manifest_hash(campaign)
    fake.get_results[campaign_id] = campaign
    fake.get_results[original_id] = original

    assert _campaign_training_resource(fake, campaign_id) is original  # type: ignore[arg-type]
    assert campaign.training_resource_id == original_id
    assert any(
        identifier == campaign_id and kwargs.get("with_for_update") is True for _, identifier, kwargs in fake.get_calls
    )
    assert any(
        identifier == original_id and kwargs.get("with_for_update") is True for _, identifier, kwargs in fake.get_calls
    )

    original.approval_state = dm.TemplateApprovalState.SUPERSEDED
    with pytest.raises(HTTPException) as excinfo:
        _campaign_training_resource(fake, campaign_id)  # type: ignore[arg-type]
    assert excinfo.value.status_code == 503
    assert "superseded" in str(excinfo.value.detail)


def test_existing_assignment_revalidates_exact_lesson_content_without_stranding_superseded_resource() -> None:
    fake = _FakeSession()
    campaign_id = uuid.uuid4()
    resource_id = uuid.uuid4()
    resource = type(
        "TrainingResource",
        (),
        {
            "training_resource_id": resource_id,
            "content": "Pause and verify through a trusted channel.",
            "version": 3,
            "approval_state": dm.TemplateApprovalState.SUPERSEDED,
            "knowledge_question": None,
            "knowledge_options": None,
            "knowledge_answer_index": None,
        },
    )()
    campaign = type(
        "Campaign",
        (),
        {
            "training_resource_id": resource_id,
            "training_resource_version": resource.version,
            "training_resource_digest": training_resource_content_digest(resource),
        },
    )()
    training = type(
        "TrainingAssignment",
        (),
        {"campaign_id": campaign_id, "resource_id": resource_id},
    )()
    fake.get_results[campaign_id] = campaign
    fake.get_results[resource_id] = resource

    assert _assigned_training_resource(fake, training) is resource  # type: ignore[arg-type]

    resource.content = "Content changed after campaign review."
    with pytest.raises(HTTPException) as excinfo:
        _assigned_training_resource(fake, training)  # type: ignore[arg-type]
    assert excinfo.value.status_code == 503
    assert excinfo.value.detail == "training resource unavailable"


def test_click_fails_closed_when_training_key_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _settings(training_token_hmac_key=""), _FakeSession(), real_training=True)
    with client:
        response = client.get("/v1/track/click/" + "ab" * 32, follow_redirects=False)
    assert response.status_code == 503


def test_training_bearer_fails_closed_when_token_assignment_binding_drifted() -> None:
    assignment_id = uuid.uuid4()
    recipient_assignment_id = uuid.uuid4()
    expires_at = datetime.now(UTC) + timedelta(days=365)
    raw_bearer = training_bearer(
        assignment_id,
        expires_at,
        TRAINING_KEY,
        purpose=TrainingBearerPurpose.OPEN,
    )
    training = type(
        "TrainingAssignment",
        (),
        {
            "training_assignment_id": assignment_id,
            "recipient_assignment_id": recipient_assignment_id,
            "access_expires_at": expires_at,
        },
    )()
    token_id = uuid.uuid4()
    recipient_assignment = type(
        "RecipientAssignment",
        (),
        {
            "recipient_assignment_id": recipient_assignment_id,
            "campaign_id": uuid.uuid4(),
            "token_id": token_id,
        },
    )()
    token = type(
        "TrackingToken",
        (),
        {
            "token_id": token_id,
            "recipient_assignment_id": uuid.uuid4(),  # deliberately inconsistent
            "campaign_id": recipient_assignment.campaign_id,
            "status": dm.TokenStatus.ACTIVE,
        },
    )()
    fake = _FakeSession()
    fake.scalar_results = [training]
    fake.get_results[recipient_assignment_id] = recipient_assignment
    fake.get_results[token_id] = token

    assert (
        _resolve_training_assignment(
            raw_bearer,
            fake,  # type: ignore[arg-type]
            TRAINING_KEY,
            purpose=TrainingBearerPurpose.OPEN,
        )
        is None
    )


def test_training_resolution_locks_the_parent_assignment_serialization_boundary() -> None:
    assignment_id = uuid.uuid4()
    expires_at = datetime.now(UTC) + timedelta(days=365)
    raw_bearer = training_bearer(
        assignment_id,
        expires_at,
        TRAINING_KEY,
        purpose=TrainingBearerPurpose.OPEN,
    )
    training = type(
        "TrainingAssignment",
        (),
        {
            "training_assignment_id": assignment_id,
            "recipient_assignment_id": _Token.recipient_assignment_id,
            "access_expires_at": expires_at,
        },
    )()
    fake = _FakeSession()
    fake.scalar_results = [training]
    fake.get_results[_Token.recipient_assignment_id] = _RecipientAssignment()
    fake.get_results[_Token.token_id] = _Token()

    resolved = _resolve_training_assignment(
        raw_bearer,
        fake,  # type: ignore[arg-type]
        TRAINING_KEY,
        purpose=TrainingBearerPurpose.OPEN,
        for_update=True,
    )

    assert resolved is not None
    statement = fake.scalar_statements[0]
    sql = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[attr-defined]
    assert "JOIN recipient_assignments" in sql
    assert "FOR UPDATE OF recipient_assignments" in sql


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


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"invalid")],
        [(b"content-length", b"1"), (b"content-length", b"1")],
    ],
)
def test_body_limit_rejects_ambiguous_content_length(headers: list[tuple[bytes, bytes]]) -> None:
    sent = _drive_body_limit(
        max_bytes=8,
        request_messages=[{"type": "http.request", "body": b"", "more_body": False}],
        headers=headers,
    )
    assert sent[0]["status"] == 400
    assert b"invalid content length" in sent[1]["body"]


def test_body_limit_handles_unreasonably_large_content_length_without_an_exception() -> None:
    sent = _drive_body_limit(
        max_bytes=8,
        request_messages=[{"type": "http.request", "body": b"", "more_body": False}],
        headers=[(b"content-length", b"9" * 10_000)],
    )
    assert sent[0]["status"] == 413
    assert b"request body too large" in sent[1]["body"]


_EXPECTED_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-robots-tag": "noindex, nofollow, noarchive",
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
    assert click.headers["location"].startswith("/v1/training/")
    assert click.headers["cache-control"] == "no-store"


def test_legacy_correction_body_is_never_parsed_or_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    with client:
        response = client.post(
            "/v1/corrections",
            content=b"not-json",
            headers={"Authorization": "Bearer s3cret", "Content-Type": "application/json"},
        )
    assert response.status_code == 410
    assert response.json()["code"] == "legacy_corrections_retired"
    assert fake.added == []
    assert fake.executed == []


def test_oversized_request_targets_are_rejected_without_reflection_or_route_work(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _FakeSession()
    client = _client(monkeypatch, _settings(), fake)
    secret = "recipient@example.com/" + "A" * 43
    with client:
        path_response = client.get("/" + secret + "x" * 8192)
        query_response = client.get("/livez", params={"return_to": secret + "x" * 8192})

    for response in (path_response, query_response):
        assert response.status_code == 414
        assert response.json() == {"detail": "request target too large"}
        assert secret not in response.text
        assert response.headers["cache-control"] == "no-store"
    assert fake.added == []
    assert fake.executed == []
    assert secret not in capsys.readouterr().out


def test_public_exception_translation_never_reflects_internal_detail(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = _client(monkeypatch, _settings(), _FakeSession())
    secret = "postgresql://operator:password@example.test/private recipient@example.com " + "A" * 43

    def conflict() -> None:
        raise ConflictError(secret)

    def contract_failure() -> None:
        raise KpError(secret, secret)  # type: ignore[arg-type]

    def database_failure() -> None:
        raise SQLAlchemyError(secret)

    def unexpected_failure() -> None:
        raise RuntimeError(secret)

    client.app.add_api_route("/test/conflict", conflict)
    client.app.add_api_route("/test/contract", contract_failure)
    client.app.add_api_route("/test/database", database_failure)
    client.app.add_api_route("/test/unexpected", unexpected_failure)
    with client:
        responses = {
            "conflict": client.get("/test/conflict"),
            "contract": client.get("/test/contract"),
            "database": client.get("/test/database"),
            "unexpected": client.get("/test/unexpected"),
        }

    assert responses["conflict"].status_code == 409
    assert responses["conflict"].json() == {"code": "KP-005", "detail": "request conflicts with current state"}
    assert responses["contract"].status_code == 500
    assert responses["contract"].json() == {"code": "KP-010", "detail": "internal server error"}
    assert responses["database"].status_code == 503
    assert responses["database"].json() == {"detail": "service temporarily unavailable"}
    assert responses["unexpected"].status_code == 500
    assert responses["unexpected"].json() == {"detail": "internal server error"}
    for response in responses.values():
        assert secret not in response.text
        assert response.headers["cache-control"] == "no-store"
    logs = capsys.readouterr().out
    assert secret not in logs
    assert "RuntimeError" in logs
