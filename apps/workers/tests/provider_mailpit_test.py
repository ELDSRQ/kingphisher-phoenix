from __future__ import annotations

import httpx
from kp_workers.providers.mailpit import MailpitReportedMessageProvider


def test_mailpit_provider_returns_only_explicit_valid_reports() -> None:
    token = "ab" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "reported"}, {"ID": "ordinary"}]})
        if request.url.path.endswith("/reported"):
            return httpx.Response(
                200,
                json={
                    "Headers": {"X-KP-Reported": ["true"], "X-KP-Token-Hash": [token]},
                    "Created": "2026-02-03T04:05:06Z",
                    "Text": "sensitive message content",
                },
            )
        return httpx.Response(200, json={"Headers": {"X-KP-Reported": ["false"]}})

    provider = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    reports = provider.poll()
    assert len(reports) == 1
    assert reports[0].external_id == "reported"
    assert reports[0].token_hash == token
    assert reports[0].reported_at.isoformat() == "2026-02-03T04:05:06+00:00"


def test_mailpit_provider_rejects_malformed_contract() -> None:
    provider = MailpitReportedMessageProvider(
        "http://mailpit.test",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"messages": "wrong"})),
    )
    try:
        provider.poll()
    except ValueError as exc:
        assert "malformed" in str(exc)
    else:
        raise AssertionError("expected malformed response to fail closed")
