from __future__ import annotations

import json

import httpx
import pytest
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


def test_reported_mailbox_sends_bearer_auth() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"messages": []})

    MailpitReportedMessageProvider(
        "https://mailbox.test", bearer_token="secret", transport=httpx.MockTransport(handler)
    ).poll()
    assert requests[0].headers["authorization"] == "Bearer secret"


def test_mailpit_provider_paginates_past_fifty_and_uses_watermark() -> None:
    token = "cd" * 32
    messages = [f"message-{index}" for index in range(63)]
    summary_requests: list[int] = []
    detail_requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            start = int(request.url.params["start"])
            limit = int(request.url.params["limit"])
            summary_requests.append(start)
            return httpx.Response(
                200,
                json={
                    "messages": [{"ID": message_id} for message_id in messages[start : start + limit]],
                    "messages_count": len(messages),
                    "start": start,
                },
            )
        message_id = request.url.path.rsplit("/", 1)[-1]
        detail_requests.append(message_id)
        return httpx.Response(
            200,
            json={
                "Headers": {"X-KP-Reported": ["true"], "X-KP-Token-Hash": [token]},
                "Created": "2026-02-03T04:05:06Z",
            },
        )

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=50, transport=httpx.MockTransport(handler))

    first = provider.poll()
    assert len(first) == 63
    assert len({report.external_id for report in first}) == 63
    assert summary_requests == [0, 50]
    assert len(detail_requests) == 63
    assert provider.cursor == "message-0"

    resumed = MailpitReportedMessageProvider(
        "http://mailpit.test",
        limit=50,
        cursor=provider.cursor,
        transport=httpx.MockTransport(handler),
    )
    assert resumed.poll() == []
    assert summary_requests == [0, 50, 0]
    assert len(detail_requests) == 63

    # Repeating the same mailbox stops at the prior newest ID and emits no
    # duplicate report or detail request.
    assert provider.poll() == []
    assert summary_requests == [0, 50, 0, 0]
    assert len(detail_requests) == 63

    messages[:0] = ["message-new-1", "message-new-2"]
    new_reports = provider.poll()
    assert [report.external_id for report in new_reports] == ["message-new-1", "message-new-2"]
    assert len(detail_requests) == 65


def test_mailpit_provider_deduplicates_repeated_ids_within_a_poll() -> None:
    token = "ef" * 32
    detail_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal detail_requests
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "same"}, {"ID": "same"}]})
        detail_requests += 1
        return httpx.Response(
            200,
            json={
                "Headers": {"X-KP-Reported": "true", "X-KP-Token-Hash": token},
                "Created": "2026-02-03T04:05:06Z",
            },
        )

    reports = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler)).poll()

    assert [report.external_id for report in reports] == ["same"]
    assert detail_requests == 1


def test_mailpit_provider_fails_if_server_ignores_pagination() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [{"ID": "one"}, {"ID": "two"}]})

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=2, transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="pagination is unsupported"):
        provider.poll()


def test_mailpit_provider_does_not_advance_cursor_after_later_page_failure() -> None:
    token = "12" * 32
    fail_second_page = True
    details: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal fail_second_page
        if request.url.path == "/api/v1/messages":
            start = int(request.url.params["start"])
            if start == 2 and fail_second_page:
                fail_second_page = False
                return httpx.Response(200, content=b"not-json")
            items = ["one", "two", "three"][start : start + 2]
            return httpx.Response(
                200,
                json={"messages": [{"ID": item} for item in items], "messages_count": 3, "start": start},
            )
        message_id = request.url.path.rsplit("/", 1)[-1]
        details.append(message_id)
        return httpx.Response(
            200,
            json={
                "Headers": {"X-KP-Reported": "true", "X-KP-Token-Hash": token},
                "Created": "2026-02-03T04:05:06Z",
            },
        )

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=2, transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="not valid JSON"):
        provider.poll()
    reports = provider.poll()
    assert [report.external_id for report in reports] == ["one", "two", "three"]
    assert details == ["one", "two", "one", "two", "three"]


@pytest.mark.parametrize("target", ["summary", "detail"])
def test_mailpit_provider_bounds_response_bytes(target: str) -> None:
    oversized = json.dumps({"padding": "x" * 200}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            if target == "summary":
                return httpx.Response(200, content=oversized)
            return httpx.Response(200, json={"messages": [{"ID": "reported"}]})
        return httpx.Response(200, content=oversized)

    provider = MailpitReportedMessageProvider(
        "http://mailpit.test",
        max_summary_bytes=64,
        max_message_bytes=64,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ValueError, match="exceeds the configured response limit"):
        provider.poll()


@pytest.mark.parametrize(
    "detail",
    [
        [],
        {"Headers": []},
        {
            "Headers": {"X-KP-Reported": "true", "X-KP-Token-Hash": "ab" * 32},
            "Created": "not-a-date",
        },
    ],
)
def test_mailpit_provider_rejects_malformed_message_details(detail: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "reported"}]})
        return httpx.Response(200, json=detail)

    provider = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="malformed"):
        provider.poll()
