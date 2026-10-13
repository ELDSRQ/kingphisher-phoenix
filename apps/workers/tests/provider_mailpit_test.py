from __future__ import annotations

import json

import httpx
import pytest
from kp_workers.providers.mailpit import MailpitReportedMessageProvider

# These tests mirror the real Mailpit (v1.20.x) contract: the summary list
# (``/api/v1/messages``) carries the receipt time in ``Created``; the
# ``X-KP-Reported`` / ``X-KP-Token-Hash`` markers are only available from the
# per-message headers endpoint (``/api/v1/message/{id}/headers``). The message
# body endpoint (``/api/v1/message/{id}``) must never be fetched.

_CREATED = "2026-02-03T04:05:06Z"


def test_mailpit_provider_returns_only_explicit_valid_reports() -> None:
    token = "ab" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(
                200,
                json={
                    "messages": [
                        {"ID": "reported", "Created": _CREATED},
                        {"ID": "ordinary", "Created": _CREATED},
                    ]
                },
            )
        if request.url.path == "/api/v1/message/reported/headers":
            return httpx.Response(200, json={"X-KP-Reported": ["true"], "X-KP-Token-Hash": [token]})
        if request.url.path == "/api/v1/message/ordinary/headers":
            return httpx.Response(200, json={"X-KP-Reported": ["false"]})
        raise AssertionError(f"reported poll must fetch only headers, not {request.url.path}")

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
    header_requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            start = int(request.url.params["start"])
            limit = int(request.url.params["limit"])
            summary_requests.append(start)
            return httpx.Response(
                200,
                json={
                    "messages": [
                        {"ID": message_id, "Created": _CREATED} for message_id in messages[start : start + limit]
                    ],
                    "messages_count": len(messages),
                    "start": start,
                },
            )
        message_id = request.url.path.split("/")[-2]
        header_requests.append(message_id)
        return httpx.Response(200, json={"X-KP-Reported": ["true"], "X-KP-Token-Hash": [token]})

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=50, transport=httpx.MockTransport(handler))

    first = provider.poll()
    assert len(first) == 63
    assert len({report.external_id for report in first}) == 63
    assert summary_requests == [0, 50]
    assert len(header_requests) == 63
    assert provider.cursor == "message-0"

    resumed = MailpitReportedMessageProvider(
        "http://mailpit.test",
        limit=50,
        cursor=provider.cursor,
        transport=httpx.MockTransport(handler),
    )
    assert resumed.poll() == []
    assert summary_requests == [0, 50, 0]
    assert len(header_requests) == 63

    # Repeating the same mailbox stops at the prior newest ID and emits no
    # duplicate report or header request.
    assert provider.poll() == []
    assert summary_requests == [0, 50, 0, 0]
    assert len(header_requests) == 63

    messages[:0] = ["message-new-1", "message-new-2"]
    new_reports = provider.poll()
    assert [report.external_id for report in new_reports] == ["message-new-1", "message-new-2"]
    assert len(header_requests) == 65


def test_mailpit_provider_deduplicates_repeated_ids_within_a_poll() -> None:
    token = "ef" * 32
    header_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal header_requests
        if request.url.path == "/api/v1/messages":
            return httpx.Response(
                200,
                json={"messages": [{"ID": "same", "Created": _CREATED}, {"ID": "same", "Created": _CREATED}]},
            )
        header_requests += 1
        return httpx.Response(200, json={"X-KP-Reported": "true", "X-KP-Token-Hash": token})

    reports = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler)).poll()

    assert [report.external_id for report in reports] == ["same"]
    assert header_requests == 1


def test_mailpit_provider_fails_if_server_ignores_pagination() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [{"ID": "one"}, {"ID": "two"}]})

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=2, transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="pagination is unsupported"):
        provider.poll()


def test_mailpit_provider_does_not_advance_cursor_after_later_page_failure() -> None:
    token = "12" * 32
    fail_second_page = True
    headers_seen: list[str] = []

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
                json={
                    "messages": [{"ID": item, "Created": _CREATED} for item in items],
                    "messages_count": 3,
                    "start": start,
                },
            )
        message_id = request.url.path.split("/")[-2]
        headers_seen.append(message_id)
        return httpx.Response(200, json={"X-KP-Reported": "true", "X-KP-Token-Hash": token})

    provider = MailpitReportedMessageProvider("http://mailpit.test", limit=2, transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="not valid JSON"):
        provider.poll()
    reports = provider.poll()
    assert [report.external_id for report in reports] == ["one", "two", "three"]
    assert headers_seen == ["one", "two", "one", "two", "three"]


@pytest.mark.parametrize("target", ["summary", "headers"])
def test_mailpit_provider_bounds_response_bytes(target: str) -> None:
    oversized = json.dumps({"padding": "x" * 200}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            if target == "summary":
                return httpx.Response(200, content=oversized)
            return httpx.Response(200, json={"messages": [{"ID": "reported", "Created": _CREATED}]})
        return httpx.Response(200, content=oversized)

    provider = MailpitReportedMessageProvider(
        "http://mailpit.test",
        max_summary_bytes=64,
        max_message_bytes=64,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ValueError, match="exceeds the configured response limit"):
        provider.poll()


def test_mailpit_provider_rejects_non_dict_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "reported", "Created": _CREATED}]})
        return httpx.Response(200, json=[])

    provider = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="malformed"):
        provider.poll()


def test_mailpit_provider_rejects_malformed_report_timestamp() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "reported", "Created": "not-a-date"}]})
        return httpx.Response(200, json={"X-KP-Reported": ["true"], "X-KP-Token-Hash": ["ab" * 32]})

    provider = MailpitReportedMessageProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="malformed"):
        provider.poll()
