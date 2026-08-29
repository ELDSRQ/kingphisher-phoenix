from __future__ import annotations

from email.message import EmailMessage

import httpx
import pytest
from azure.core.credentials import AccessToken
from kp_workers.providers.microsoft365 import Microsoft365ReportedMailboxProvider


def _reported_mime(candidate: str = "candidate-opaque-value-0001") -> bytes:
    original = EmailMessage()
    original["X-KP-Report-Correlation"] = candidate
    original["Message-ID"] = "<original@example.com>"
    original.set_content("original")
    wrapper = EmailMessage()
    wrapper.set_content("reported")
    wrapper.add_attachment(
        original.as_bytes(),
        maintype="application",
        subtype="octet-stream",
        filename="original.eml",
    )
    return wrapper.as_bytes()


def _summary(message_id: str) -> dict[str, object]:
    return {
        "id": message_id,
        "receivedDateTime": "2026-08-27T12:30:00Z",
        "internetMessageId": f"<{message_id}@example.com>",
        "hasAttachments": True,
    }


def _provider(handler: httpx.MockTransport, **kwargs: object) -> Microsoft365ReportedMailboxProvider:
    return Microsoft365ReportedMailboxProvider(
        "https://graph.test/v1.0",
        mailbox_id="reports@example.com",
        bearer_token="provider-secret",
        transport=handler,
        **kwargs,
    )


def test_mailbox_provider_uses_only_dedicated_identity_client_id(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[dict[str, object]] = []

    class _ManagedCredential:
        def __init__(self, **kwargs: object) -> None:
            created.append(kwargs)

        def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
            return AccessToken("mailbox-token", 4_102_444_800)

    monkeypatch.setenv("AZURE_CLIENT_ID", "shared-worker-client-id")
    monkeypatch.setenv("KP_WORKER_REPORTED_MAILBOX_CLIENT_ID", "mailbox-client-id")
    monkeypatch.setattr("kp_workers.providers.microsoft365.ManagedIdentityCredential", _ManagedCredential)
    delta = (
        "https://graph.microsoft.com/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"
    )
    provider = Microsoft365ReportedMailboxProvider(
        "https://graph.microsoft.com/v1.0",
        mailbox_id="reports@example.com",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"value": [], "@odata.deltaLink": delta})),
    )

    assert provider.poll().status == "complete"
    assert created == [
        {
            "client_id": "mailbox-client-id",
        }
    ]


def test_mailbox_provider_rejects_missing_dedicated_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "shared-worker-client-id")
    monkeypatch.delenv("KP_WORKER_REPORTED_MAILBOX_CLIENT_ID", raising=False)

    with pytest.raises(ValueError, match="mailbox managed identity client ID"):
        Microsoft365ReportedMailboxProvider(
            "https://graph.microsoft.com/v1.0",
            mailbox_id="reports@example.com",
        )


def test_initial_delta_pages_preserve_cursor_and_deduplicate_replay_ids() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        if request.url.params.get("$skiptoken") == "page-2":
            return httpx.Response(
                200,
                json={
                    "value": [_summary("message-1"), _summary("message-2"), {"id": "deleted", "@removed": {}}],
                    "@odata.deltaLink": (
                        "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta"
                        "?$deltatoken=opaque-final"
                    ),
                },
            )
        return httpx.Response(
            200,
            json={
                "value": [_summary("message-1")],
                "@odata.nextLink": (
                    "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta"
                    "?$skiptoken=page-2"
                ),
            },
        )

    result = _provider(httpx.MockTransport(handler)).poll()

    assert result.status == "complete"
    assert result.complete is True
    assert result.cursor_kind == "delta"
    assert result.cursor is not None and "opaque-final" in result.cursor
    assert [message.external_id for message in result.messages] == ["message-1", "message-2"]
    assert result.duplicate_count == 1
    assert result.removed_count == 1
    assert result.messages[0].mime.candidate == "candidate-opaque-value-0001"
    assert result.messages[0].mime.evidence[0].source == "attached_original"
    list_requests = [request for request in requests if not request.url.path.endswith("/$value")]
    mime_requests = [request for request in requests if request.url.path.endswith("/$value")]
    assert list_requests[0].url.params["$top"] == "50"
    assert "$select" in list_requests[0].url.params
    assert "$select" not in list_requests[1].url.params
    assert len(mime_requests) == 2


def test_incremental_cursor_is_sent_opaquely_without_initial_parameters() -> None:
    requests: list[httpx.Request] = []
    cursor = (
        "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta"
        "?$deltatoken=opaque%2Bcursor"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"value": [], "@odata.deltaLink": cursor})

    result = _provider(httpx.MockTransport(handler)).poll(cursor)

    assert result.status == "complete"
    assert result.cursor == cursor
    assert requests[0].url.params["$deltatoken"] == "opaque+cursor"
    assert "$select" not in requests[0].url.params
    assert "$top" not in requests[0].url.params


def test_later_page_failure_discards_partial_messages_and_cursor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        if request.url.params.get("$skiptoken"):
            return httpx.Response(503, text="private.person@example.com provider-secret cursor-secret")
        return httpx.Response(
            200,
            json={
                "value": [_summary("message-1")],
                "@odata.nextLink": (
                    "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta"
                    "?$skiptoken=cursor-secret"
                ),
            },
        )

    result = _provider(httpx.MockTransport(handler)).poll()

    assert result.status == "error"
    assert result.error_code == "http"
    assert result.messages == ()
    assert result.cursor is None
    assert "person@example.com" not in repr(result)
    assert "provider-secret" not in repr(result)
    assert "cursor-secret" not in repr(result)


@pytest.mark.parametrize(
    "cursor",
    [
        "https://attacker.test/v1.0/users/x/mailFolders/inbox/messages/delta?$deltatoken=secret",
        "https://graph.test/v1.0/users/other/mailFolders/inbox/messages/delta?$deltatoken=secret",
        "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta#secret",
        "https://graph.test:99999/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta",
    ],
)
def test_persisted_cursor_is_same_origin_and_mailbox_scoped(cursor: str) -> None:
    result = _provider(httpx.MockTransport(lambda _: pytest.fail("unsafe cursor must not be requested"))).poll(cursor)

    assert result.status == "error"
    assert result.error_code == "unsafe_cursor"


def test_cross_origin_next_link_fails_closed() -> None:
    result = _provider(
        httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"value": [], "@odata.nextLink": "https://attacker.test/messages?$skiptoken=secret"},
            )
        )
    ).poll()

    assert result.status == "error"
    assert result.error_code == "unsafe_cursor"


def test_same_cursor_loop_fails_closed_without_exposing_partial_messages() -> None:
    cursor = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        return httpx.Response(200, json={"value": [_summary("one")], "@odata.nextLink": cursor})

    result = _provider(httpx.MockTransport(handler)).poll()

    assert result.status == "error"
    assert result.error_code == "cursor_loop"
    assert result.messages == ()
    assert result.cursor is None


def test_page_cap_returns_explicit_truncated_next_cursor() -> None:
    next_cursor = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$skiptoken=next"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        return httpx.Response(200, json={"value": [_summary("message-1")], "@odata.nextLink": next_cursor})

    result = _provider(httpx.MockTransport(handler), max_pages=1).poll()

    assert result.status == "truncated"
    assert result.truncated is True
    assert result.cursor == next_cursor
    assert result.cursor_kind == "next"
    assert len(result.messages) == 1


def test_graph_page_larger_than_requested_limit_fails_explicitly() -> None:
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"
    result = _provider(
        httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"value": [_summary("one"), _summary("two")], "@odata.deltaLink": delta},
            )
        ),
        page_size=1,
    ).poll()

    assert result.status == "error"
    assert result.error_code == "page_limit"


def test_message_cap_mid_page_is_explicit_and_has_no_unsafe_cursor() -> None:
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        return httpx.Response(200, json={"value": [_summary("one"), _summary("two")], "@odata.deltaLink": delta})

    result = _provider(httpx.MockTransport(handler), max_messages=1).poll()

    assert result.status == "truncated"
    assert result.cursor is None
    assert [message.external_id for message in result.messages] == ["one"]


def test_malformed_and_oversized_mime_are_rejected_without_blocking_delta() -> None:
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/bad/$value"):
            return httpx.Response(200, content=b"not an RFC message")
        if request.url.path.endswith("/large/$value"):
            return httpx.Response(200, content=b"x" * 200)
        return httpx.Response(200, json={"value": [_summary("bad"), _summary("large")], "@odata.deltaLink": delta})

    result = _provider(httpx.MockTransport(handler), max_mime_bytes=100).poll()

    assert result.status == "complete"
    assert result.messages == ()
    assert result.rejected_count == 2
    assert result.cursor == delta


def test_declared_content_types_fail_closed_at_the_graph_boundary() -> None:
    invalid_delta = _provider(
        httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=b'{"value":[]}',
            )
        )
    ).poll()
    assert invalid_delta.status == "error"
    assert invalid_delta.error_code == "content_type"

    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, headers={"Content-Type": "application/json"}, content=_reported_mime())
        return httpx.Response(200, json={"value": [_summary("one")], "@odata.deltaLink": delta})

    invalid_mime = _provider(httpx.MockTransport(handler)).poll()
    assert invalid_mime.status == "error"
    assert invalid_mime.error_code == "content_type"
    assert invalid_mime.messages == ()


@pytest.mark.parametrize("received", ["2026-08-27", "2026-08-27T12:30:00"])
def test_message_summary_requires_graph_datetime_offset(received: str) -> None:
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"
    summary = _summary("one")
    summary["receivedDateTime"] = received
    result = _provider(
        httpx.MockTransport(lambda _: httpx.Response(200, json={"value": [summary], "@odata.deltaLink": delta}))
    ).poll()

    assert result.status == "complete"
    assert result.messages == ()
    assert result.rejected_count == 1


def test_delta_response_bytes_are_stream_bounded() -> None:
    result = _provider(
        httpx.MockTransport(lambda _: httpx.Response(200, content=b'{"value":"' + b"x" * 200 + b'"}')),
        max_response_bytes=64,
    ).poll()

    assert result.status == "error"
    assert result.error_code == "response_too_large"
    assert result.messages == ()
    assert result.cursor is None


def test_ambiguous_mime_remains_untrusted_evidence() -> None:
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"
    ambiguous = EmailMessage()
    ambiguous["X-KP-Report-Correlation"] = "outer-candidate-00000001"
    ambiguous.set_content("wrapper")
    ambiguous.add_attachment(
        _reported_mime("attached-candidate-0001"),
        maintype="application",
        subtype="octet-stream",
        filename="original.eml",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=ambiguous.as_bytes())
        return httpx.Response(200, json={"value": [_summary("ambiguous")], "@odata.deltaLink": delta})

    result = _provider(httpx.MockTransport(handler)).poll()

    assert result.status == "complete"
    assert result.messages[0].mime.disposition == "ambiguous"
    assert result.messages[0].mime.candidate is None


def test_429_retry_after_is_bounded() -> None:
    attempts = 0
    waits: list[float] = []
    delta = "https://graph.test/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"value": [], "@odata.deltaLink": delta})

    result = _provider(
        httpx.MockTransport(handler), max_retries=1, max_retry_after_seconds=2, sleep=waits.append
    ).poll()

    assert result.status == "complete"
    assert attempts == 2
    assert waits == [2.0]

    too_long = _provider(
        httpx.MockTransport(lambda _: httpx.Response(429, headers={"Retry-After": "10"})),
        max_retry_after_seconds=1,
        sleep=lambda _: pytest.fail("must not exceed configured delay"),
    ).poll()
    assert too_long.status == "error"
    assert too_long.error_code == "retry_after"


class _RotatingCredential:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = iter(tokens)

    def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
        assert scopes == ("https://graph.microsoft.com/.default",)
        return AccessToken(next(self._tokens), 4_102_444_800)


def test_managed_identity_auth_is_refreshed_and_redacted() -> None:
    requests: list[httpx.Request] = []
    delta = (
        "https://graph.microsoft.com/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$deltatoken=end"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/$value"):
            return httpx.Response(200, content=_reported_mime())
        return httpx.Response(200, json={"value": [_summary("message")], "@odata.deltaLink": delta})

    result = Microsoft365ReportedMailboxProvider(
        "https://graph.microsoft.com/v1.0",
        mailbox_id="reports@example.com",
        credential=_RotatingCredential(["managed-secret-1", "managed-secret-2"]),  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    ).poll()

    assert result.status == "complete"
    assert [request.headers["authorization"] for request in requests] == [
        "Bearer managed-secret-1",
        "Bearer managed-secret-2",
    ]
    assert "managed-secret" not in repr(result)


def test_managed_identity_failure_returns_only_redacted_error_code() -> None:
    class _BrokenCredential:
        def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
            raise RuntimeError("alice@example.com sensitive credential diagnostics")

    result = Microsoft365ReportedMailboxProvider(
        "https://graph.microsoft.com/v1.0",
        mailbox_id="reports@example.com",
        credential=_BrokenCredential(),  # type: ignore[arg-type]
        transport=httpx.MockTransport(lambda _: pytest.fail("request must not be sent")),
    ).poll()

    assert result.status == "error"
    assert result.error_code == "authentication"
    assert "alice@example.com" not in repr(result)
    assert "sensitive" not in repr(result)


def test_missing_terminal_delta_cursor_is_an_error() -> None:
    result = _provider(httpx.MockTransport(lambda _: httpx.Response(200, json={"value": []}))).poll()

    assert result.status == "error"
    assert result.error_code == "missing_delta_cursor"
