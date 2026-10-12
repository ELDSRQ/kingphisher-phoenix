from __future__ import annotations

import httpx
from kp_workers.providers.reply_mailbox import (
    MailpitReplyMailboxProvider,
    Microsoft365ReplyMailboxProvider,
    _extract_references,
)


def test_extract_references_collects_bounded_deduplicated_message_ids() -> None:
    refs = _extract_references(["<a@x>", "<b@x> <a@x>", "no brackets here", "<c@x>"])
    assert refs == ("<a@x>", "<b@x>", "<c@x>")


def test_m365_reply_provider_returns_header_only_candidates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/messages")
        assert "internetMessageHeaders" in request.url.params["$select"]
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "graph-msg-1",
                        "receivedDateTime": "2026-02-03T04:05:06Z",
                        "internetMessageId": "<reply-1@corp.example>",
                        "internetMessageHeaders": [
                            {"name": "In-Reply-To", "value": "<sent-1@corp.example>"},
                            {"name": "References", "value": "<root@corp.example> <sent-1@corp.example>"},
                            {"name": "Subject", "value": "Re: please review"},
                        ],
                    },
                    {
                        "id": "graph-msg-2",
                        "receivedDateTime": "2026-02-03T04:00:00Z",
                        "internetMessageId": "<unrelated@corp.example>",
                        "internetMessageHeaders": [{"name": "Subject", "value": "unrelated"}],
                    },
                ]
            },
        )

    provider = Microsoft365ReplyMailboxProvider(
        "https://graph.microsoft.com/v1.0",
        mailbox_id="replies@corp.example",
        bearer_token="secret",
        transport=httpx.MockTransport(handler),
    )
    result = provider.poll()
    assert result.status == "complete"
    assert len(result.messages) == 1
    candidate = result.messages[0]
    assert candidate.external_id == "graph-msg-1"
    assert candidate.referenced_message_ids == ("<sent-1@corp.example>", "<root@corp.example>")
    assert candidate.received_at.isoformat() == "2026-02-03T04:05:06+00:00"
    # A message without reference headers is counted, never surfaced.
    assert result.rejected_count == 1
    assert result.cursor == "graph-msg-1"


def test_m365_reply_provider_sends_bearer_auth() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": []})

    Microsoft365ReplyMailboxProvider(
        "https://mailbox.test",
        mailbox_id="replies@corp.example",
        bearer_token="shh",
        transport=httpx.MockTransport(handler),
    ).poll()
    assert requests[0].headers["authorization"] == "Bearer shh"


def test_m365_reply_provider_reports_error_without_exposing_messages() -> None:
    provider = Microsoft365ReplyMailboxProvider(
        "https://graph.microsoft.com/v1.0",
        mailbox_id="replies@corp.example",
        bearer_token="secret",
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )
    result = provider.poll()
    assert result.status == "error"
    assert result.messages == ()
    assert result.cursor is None


def test_mailpit_reply_provider_returns_only_messages_with_references() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": [{"ID": "reply"}, {"ID": "ordinary"}]})
        if request.url.path.endswith("/reply"):
            return httpx.Response(
                200,
                json={
                    "Headers": {
                        "In-Reply-To": ["<sent-9@corp.example>"],
                        "References": ["<sent-9@corp.example>"],
                    },
                    "Created": "2026-02-03T04:05:06Z",
                    "Text": "sensitive reply body that must never be returned",
                },
            )
        return httpx.Response(200, json={"Headers": {"Subject": ["hello"]}, "Created": "2026-02-03T04:05:06Z"})

    provider = MailpitReplyMailboxProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    replies = provider.poll()
    assert len(replies) == 1
    assert replies[0].external_id == "reply"
    assert replies[0].referenced_message_ids == ("<sent-9@corp.example>",)
    assert provider.cursor == "reply"


def test_mailpit_reply_provider_advances_watermark_and_skips_seen() -> None:
    messages = [{"ID": "m-1"}, {"ID": "m-0"}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/messages":
            return httpx.Response(200, json={"messages": messages})
        return httpx.Response(
            200,
            json={
                "Headers": {"References": ["<sent@corp.example>"]},
                "Created": "2026-02-03T04:05:06Z",
            },
        )

    provider = MailpitReplyMailboxProvider("http://mailpit.test", transport=httpx.MockTransport(handler))
    first = provider.poll()
    assert [item.external_id for item in first] == ["m-1", "m-0"]
    assert provider.cursor == "m-1"
    # A second poll with no new messages stops at the watermark and yields none.
    assert provider.poll() == []
