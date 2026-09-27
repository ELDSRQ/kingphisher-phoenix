"""H8: the system-alert channel — non-campaign alerts to a team destination.

A draft awaiting review, a stalled audit anchor, or a weekly digest are not
tied to one campaign, so they travel on the "alert" topic with scope="system"
and dispatch to a single configured destination rather than a per-campaign
subscription. Off unless configured, so a deployment that has not opted in
silently no-ops.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext
from kp_workers.jobs import process_alert as process_alert_facade


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)


class _Session:
    def commit(self) -> None:
        pass


class _FakeSender:
    def __init__(self, *_a: Any, **_k: Any) -> None:
        self.webhook: list[tuple[str, str, dict]] = []
        self.ntfy: list[tuple[str, str, dict]] = []

    def send(self, destination: str, secret: str, payload: dict) -> None:
        self.webhook.append((destination, secret, payload))

    def send_ntfy(self, destination: str, secret: str, payload: dict) -> None:
        self.ntfy.append((destination, secret, payload))


def _context(settings: WorkerSettings) -> tuple[WorkerContext, _Audit]:
    audit = _Audit()

    @contextmanager
    def factory() -> Any:
        yield _Session()

    return WorkerContext(settings, factory, audit, SimpleNamespace()), audit  # type: ignore[arg-type]


def _settings(**overrides: Any) -> WorkerSettings:
    base: dict[str, Any] = {
        "_env_file": None,
        "training_token_hmac_key": "33" * 32,
        "alert_webhook_domains": "hooks.example.com",
        "runtime_mode": "development",
    }
    base.update(overrides)
    return WorkerSettings(**base)


_MSG = {
    "payload": {
        "scope": "system",
        "event_type": "decision.needed",
        "occurred_at": "2026-09-27T12:00:00+00:00",
        "detail": {"kind": "draft_awaiting_review", "template_version_id": "t1", "subject": "Test"},
    }
}


def test_configured_webhook_channel_delivers_and_audits(monkeypatch: pytest.MonkeyPatch) -> None:
    sender = _FakeSender()
    monkeypatch.setattr("kp_workers.followup_jobs.SignedWebhookSender", lambda *a, **k: sender)
    ctx, audit = _context(
        _settings(
            system_alert_channel="webhook",
            system_alert_destination="https://hooks.example.com/kp",
            system_alert_signing_secret="ab" * 16,
        )
    )
    process_alert_facade(ctx, _MSG)
    assert len(sender.webhook) == 1
    dest, _secret, payload = sender.webhook[0]
    assert dest == "https://hooks.example.com/kp"
    assert payload["event_type"] == "decision.needed"
    assert payload["scope"] == "system"
    assert [r["action"] for r in audit.records] == ["system_alert.deliver"]


def test_ntfy_channel_uses_send_ntfy(monkeypatch: pytest.MonkeyPatch) -> None:
    sender = _FakeSender()
    monkeypatch.setattr("kp_workers.followup_jobs.SignedWebhookSender", lambda *a, **k: sender)
    ctx, _ = _context(
        _settings(
            system_alert_channel="ntfy",
            system_alert_destination="https://hooks.example.com/topic",
            system_alert_signing_secret="ab" * 16,
        )
    )
    process_alert_facade(ctx, _MSG)
    assert len(sender.ntfy) == 1
    assert not sender.webhook


def test_unconfigured_channel_is_a_silent_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Default: no destination -> off. Must not construct a sender or deliver.
    constructed = {"n": 0}
    monkeypatch.setattr(
        "kp_workers.followup_jobs.SignedWebhookSender",
        lambda *a, **k: constructed.__setitem__("n", constructed["n"] + 1) or _FakeSender(),
    )
    ctx, audit = _context(_settings())  # system_alert_channel defaults to "none"
    process_alert_facade(ctx, _MSG)  # must not raise
    assert constructed["n"] == 0
    assert audit.records == []


def test_unknown_system_event_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kp_workers.followup_jobs.SignedWebhookSender", lambda *a, **k: _FakeSender())
    ctx, _ = _context(
        _settings(
            system_alert_channel="webhook",
            system_alert_destination="https://hooks.example.com/kp",
            system_alert_signing_secret="ab" * 16,
        )
    )
    with pytest.raises(ValueError, match="unsupported system alert event type"):
        process_alert_facade(ctx, {"payload": {"scope": "system", "event_type": "bogus.event"}})


def test_system_scope_does_not_require_a_subscription_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # A campaign alert without subscription_id raises; a system alert must not.
    monkeypatch.setattr("kp_workers.followup_jobs.SignedWebhookSender", lambda *a, **k: _FakeSender())
    ctx, _ = _context(_settings())
    # no subscription_id, scope=system -> handled by the system branch, no raise
    process_alert_facade(ctx, {"payload": {"scope": "system", "event_type": "digest.weekly"}})


def test_system_alert_enabled_property() -> None:
    assert _settings().system_alert_enabled is False
    assert _settings(system_alert_channel="webhook").system_alert_enabled is False  # no dest/secret
    assert (
        _settings(
            system_alert_channel="webhook",
            system_alert_destination="https://hooks.example.com/kp",
            system_alert_signing_secret="ab" * 16,
        ).system_alert_enabled
        is True
    )
