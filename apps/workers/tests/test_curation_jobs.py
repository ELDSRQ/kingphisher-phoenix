"""Curation fetch failures must be visible, not silently swallowed (R-11)."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import httpx
import pytest
from kp_workers import curation_jobs


def _settings() -> SimpleNamespace:
    return SimpleNamespace(mailpit_api_url="http://mailpit.test", curation_poll_limit=5)


class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.content = b""

    def json(self) -> dict:
        return {}


class _StubClient:
    def __init__(self, *, raise_on_get: bool, status_code: int = 200) -> None:
        self._raise = raise_on_get
        self._status = status_code

    def __enter__(self) -> _StubClient:
        return self

    def __exit__(self, *_: object) -> bool:
        return False

    def get(self, _url: str, params: dict | None = None) -> _Resp:
        if self._raise:
            raise httpx.ConnectError("mailpit unreachable")
        return _Resp(self._status)


def test_mailpit_non_200_logs_a_warning(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setattr(curation_jobs.httpx, "Client", lambda *a, **k: _StubClient(raise_on_get=False, status_code=503))
    with caplog.at_level(logging.WARNING):
        result = curation_jobs._fetch_mailpit_forwards(_settings(), "report-phish@corp.example")
    assert result == []
    assert any("mailpit search returned HTTP 503" in rec.getMessage() for rec in caplog.records)


def test_mailpit_fetch_exception_logs_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(curation_jobs.httpx, "Client", lambda *a, **k: _StubClient(raise_on_get=True))
    with caplog.at_level(logging.WARNING):
        result = curation_jobs._fetch_mailpit_forwards(_settings(), "report-phish@corp.example")
    assert result == []
    assert any("mailpit fetch failed" in rec.getMessage() for rec in caplog.records)
