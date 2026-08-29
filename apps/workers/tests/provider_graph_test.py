from __future__ import annotations

import gzip
from types import SimpleNamespace

import httpx
import pytest
from azure.core.credentials import AccessToken
from kp_workers.providers.graph import (
    GraphDirectoryProvider,
    GraphRequestError,
    GraphRetryLimitError,
)


def test_cursor_path_binding_fails_closed_for_an_invalid_parser_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kp_workers.providers.graph.urlparse", lambda _value: SimpleNamespace(path=None))

    with pytest.raises(ValueError, match="origin|malformed"):
        GraphDirectoryProvider._required_cursor_path("https://graph.test/v1.0/users/delta")


def test_graph_provider_auth_pagination_validation_and_bounds() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"value": [{"id": "2", "mail": "bob@example.com"}]})
        if request.url.path == "/users":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "1", "mail": "Alice@Example.com", "displayName": "Alice", "unused": "drop"},
                        {"id": "bad", "mail": "not-an-email"},
                    ],
                    "@odata.nextLink": "https://graph.test/users?page=2",
                },
            )
        pytest.fail("unexpected Graph request")

    users = GraphDirectoryProvider(
        "https://graph.test",
        bearer_token="secret-token",
        max_users=2,
        transport=httpx.MockTransport(handler),
    ).users()
    assert [user.mailbox for user in users] == ["alice@example.com", "bob@example.com"]
    assert requests[0].headers["authorization"] == "Bearer secret-token"
    assert requests[0].url.params["$select"] == "id,mail,displayName,department"


def test_graph_provider_rejects_cross_origin_pagination() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test",
        api_key="gateway-key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": "https://attacker.test/users"})
        ),
    )
    try:
        provider.users()
    except ValueError as exc:
        assert "origin" in str(exc)
    else:
        raise AssertionError("expected cross-origin pagination to fail closed")


class _RotatingCredential:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = iter(tokens)
        self.scopes: list[tuple[str, ...]] = []

    def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
        self.scopes.append(scopes)
        return AccessToken(next(self._tokens), 4_102_444_800)


def test_microsoft_graph_uses_managed_identity_and_refreshes_each_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.params.get("page") != "2":
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "1", "mail": "alice@example.com"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2",
                },
            )
        return httpx.Response(200, json={"value": [{"id": "2", "mail": "bob@example.com"}]})

    credential = _RotatingCredential(["managed-token-1", "managed-token-2"])
    users = GraphDirectoryProvider(
        "https://graph.microsoft.com/v1.0",
        credential=credential,
        transport=httpx.MockTransport(handler),
    ).users()

    assert [user.employee_key for user in users] == ["1", "2"]
    assert credential.scopes == [
        ("https://graph.microsoft.com/.default",),
        ("https://graph.microsoft.com/.default",),
    ]
    assert [request.headers["authorization"] for request in requests] == [
        "Bearer managed-token-1",
        "Bearer managed-token-2",
    ]


def test_managed_identity_credential_honors_user_assigned_client_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[dict[str, object]] = []

    class _ManagedCredential(_RotatingCredential):
        def __init__(self, **kwargs: object) -> None:
            created.append(kwargs)
            super().__init__(["managed-token"])

    monkeypatch.setenv("KP_WORKER_GRAPH_CLIENT_ID", "managed-identity-client-id")
    monkeypatch.setattr("kp_workers.providers.graph.ManagedIdentityCredential", _ManagedCredential)
    provider = GraphDirectoryProvider(
        "https://graph.microsoft.com/v1.0",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"value": []})),
    )

    assert provider.users() == []
    assert created == [
        {
            "client_id": "managed-identity-client-id",
        }
    ]


def test_directory_provider_ignores_generic_azure_client_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "shared-worker-client-id")
    monkeypatch.delenv("KP_WORKER_GRAPH_CLIENT_ID", raising=False)

    with pytest.raises(ValueError, match="directory managed identity client ID"):
        GraphDirectoryProvider("https://graph.microsoft.com/v1.0")


def test_selected_groups_are_used_instead_of_tenant_wide_users(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_paths: list[str] = []
    group_id = "44444444-4444-4444-8444-444444444444"
    monkeypatch.setenv("KP_WORKER_GRAPH_GROUP_IDS", group_id)

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        return httpx.Response(200, json={"value": [{"id": "1", "mail": "alice@example.com"}]})

    users = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(handler),
    ).users()

    assert [user.mailbox for user in users] == ["alice@example.com"]
    assert requested_paths == [f"/v1.0/groups/{group_id}/transitiveMembers/microsoft.graph.user"]
    assert "/v1.0/users" not in requested_paths


def test_managed_identity_failure_stops_before_graph_request() -> None:
    requests = 0

    class _BrokenCredential:
        def get_token(self, *scopes: str, **kwargs: object) -> AccessToken:
            raise RuntimeError("credential unavailable with sensitive diagnostics")

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, json={"value": []})

    provider = GraphDirectoryProvider(
        "https://graph.microsoft.com/v1.0",
        credential=_BrokenCredential(),  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(RuntimeError, match="Microsoft Graph authentication failed") as caught:
        provider.users()
    assert "sensitive diagnostics" not in str(caught.value)
    assert requests == 0


def test_local_mock_remains_credential_free() -> None:
    seen_headers: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(200, json={"value": []})

    users = GraphDirectoryProvider("http://mock-graph", transport=httpx.MockTransport(handler)).users()

    assert users == []
    assert "authorization" not in seen_headers[0]
    assert "x-api-key" not in seen_headers[0]


def test_credential_free_arbitrary_remote_gateway_is_rejected() -> None:
    with pytest.raises(ValueError, match="require an explicit"):
        GraphDirectoryProvider("https://directory.example")


def test_graph_response_is_bounded() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test",
        api_key="gateway-key",
        max_response_bytes=32,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b'{"value":["' + b"x" * 64 + b'"]}')),
    )

    with pytest.raises(ValueError, match="maximum size"):
        provider.users()


def test_graph_response_bound_applies_after_http_decompression() -> None:
    expanded = b'{"value":"' + b"x" * 512 + b'"}'
    compressed = gzip.compress(expanded)
    provider = GraphDirectoryProvider(
        "https://graph.test",
        api_key="gateway-key",
        max_response_bytes=128,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Encoding": "gzip", "Content-Length": str(len(compressed))},
                content=compressed,
            )
        ),
    )

    with pytest.raises(ValueError, match="maximum size"):
        provider.users()


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/html"},
        {"Content-Length": "not-a-number"},
    ],
)
def test_graph_rejects_declared_non_json_or_malformed_length(headers: dict[str, str]) -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test",
        api_key="gateway-key",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, headers=headers, content=b'{"value":[]}')),
    )

    with pytest.raises(ValueError, match="malformed"):
        provider.users()


def test_change_feed_initial_to_delta_preserves_stable_identity_and_removals() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        initial_page = not request.url.params.get("$skiptoken") and not request.url.params.get("$deltatoken")
        if request.url.path == "/v1.0/users/delta" and initial_page:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "entra-1",
                            "mail": "old@example.com",
                            "userPrincipalName": "alice@example.onmicrosoft.com",
                            "displayName": "Alice",
                            "department": "Security",
                            "accountEnabled": True,
                            "userType": "Member",
                        }
                    ],
                    "@odata.nextLink": "https://graph.test/v1.0/users/delta?$skiptoken=opaque-1",
                },
            )
        if request.url.params.get("$skiptoken") == "opaque-1":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "entra-1", "mail": "renamed@example.com", "accountEnabled": True},
                        {"id": "entra-removed", "@removed": {"reason": "deleted"}},
                        {"id": "invalid-without-address"},
                    ],
                    "@odata.deltaLink": "https://graph.test/v1.0/users/delta?$deltatoken=opaque-2",
                },
            )
        assert request.url.params.get("$deltatoken") == "opaque-2"
        return httpx.Response(
            200,
            json={
                "value": [{"id": "entra-1", "@removed": {"reason": "changed"}}],
                "@odata.deltaLink": "https://graph.test/v1.0/users/delta?$deltatoken=opaque-3",
            },
        )

    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(handler),
    )
    initial = provider.fetch_changes()

    assert initial.complete is True
    assert initial.truncated is False
    assert initial.cursor_kind == "delta"
    assert initial.cursor == "https://graph.test/v1.0/users/delta?$deltatoken=opaque-2"
    assert initial.pages == 2
    assert initial.rejected_count == 1
    assert len(initial.users) == 1
    assert initial.users[0].entra_id == "entra-1"
    assert initial.users[0].mailbox == "renamed@example.com"
    assert initial.users[0].account_enabled is True
    assert initial.removals[0].entra_id == "entra-removed"
    assert requests[0].url.params["$select"].startswith("id,mail,userPrincipalName")
    assert "$select" not in requests[1].url.params

    incremental = provider.fetch_changes(initial.cursor)
    assert incremental.complete is True
    assert incremental.users == ()
    assert [item.entra_id for item in incremental.removals] == ["entra-1"]
    assert incremental.cursor == "https://graph.test/v1.0/users/delta?$deltatoken=opaque-3"


def test_change_feed_uses_upn_when_mail_is_absent() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "entra-1",
                            "mail": None,
                            "userPrincipalName": "UPN@Example.com",
                            "accountEnabled": False,
                            "userType": "Guest",
                        }
                    ],
                    "@odata.deltaLink": "https://graph.test/v1.0/users/delta?$deltatoken=upn",
                },
            )
        ),
    )

    result = provider.fetch_changes()

    assert result.users[0].mailbox == "upn@example.com"
    assert result.users[0].mail is None
    assert result.users[0].user_principal_name == "upn@example.com"
    assert result.users[0].account_enabled is False
    assert result.users[0].user_type == "Guest"


def test_selected_groups_traverse_pages_and_deduplicate_stable_ids() -> None:
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.params.get("$skiptoken") == "2":
            return httpx.Response(200, json={"value": [{"id": "only-a", "mail": "a@example.com"}]})
        if request.url.path.endswith("/group-a/transitiveMembers/microsoft.graph.user"):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "shared", "mail": "first@example.com"}],
                    "@odata.nextLink": (
                        "https://graph.test/v1.0/groups/group-a/transitiveMembers/microsoft.graph.user?$skiptoken=2"
                    ),
                },
            )
        return httpx.Response(
            200,
            json={"value": [{"id": "shared", "mail": "latest@example.com"}]},
        )

    result = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(handler),
    ).fetch_group_members(["group-a", "group-b", "group-a"])

    assert result.complete is True
    assert result.pages == 3
    assert result.cursor is None
    assert result.cursor_kind is None
    assert [(user.entra_id, user.mailbox) for user in result.users] == [
        ("shared", "latest@example.com"),
        ("only-a", "a@example.com"),
    ]
    assert requested_paths == [
        "/v1.0/groups/group-a/transitiveMembers/microsoft.graph.user",
        "/v1.0/groups/group-a/transitiveMembers/microsoft.graph.user",
        "/v1.0/groups/group-b/transitiveMembers/microsoft.graph.user",
    ]


@pytest.mark.parametrize("group_ids", [[], ["../users"], ["group/a"]])
def test_selected_groups_reject_empty_or_malformed_ids(group_ids: list[str]) -> None:
    provider = GraphDirectoryProvider("https://graph.test/v1.0", api_key="gateway-key")

    with pytest.raises(ValueError, match="group id|required"):
        provider.fetch_group_members(group_ids)


def test_page_and_user_caps_return_explicit_incomplete_results() -> None:
    page_limited = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_pages=1,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [{"id": "1", "mail": "one@example.com"}],
                    "@odata.nextLink": "https://graph.test/v1.0/users/delta?$skiptoken=later",
                },
            )
        ),
    ).fetch_changes()
    assert page_limited.complete is False
    assert page_limited.truncated is True
    assert page_limited.cursor_kind == "next"

    user_limited = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_users=1,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "1", "mail": "one@example.com"},
                        {"id": "2", "mail": "two@example.com"},
                    ],
                    "@odata.deltaLink": "https://graph.test/v1.0/users/delta?$deltatoken=unsafe",
                },
            )
        ),
    ).fetch_changes()
    assert user_limited.complete is False
    assert user_limited.truncated is True
    assert len(user_limited.users) == 1
    assert user_limited.cursor is None


def test_later_page_failure_returns_no_partial_result_and_redacts_cursor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "secret-cursor" not in str(request.url):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "1", "mail": "person@example.com"}],
                    "@odata.nextLink": "https://graph.test/v1.0/users/delta?$skiptoken=secret-cursor",
                },
            )
        return httpx.Response(503, text="private.person@example.com bearer-secret")

    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        bearer_token="bearer-secret",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GraphRequestError) as caught:
        provider.fetch_changes()
    assert str(caught.value) == "Microsoft Graph request failed with HTTP 503"
    assert "secret-cursor" not in str(caught.value)
    assert "person@example.com" not in str(caught.value)
    assert "bearer-secret" not in str(caught.value)


@pytest.mark.parametrize(
    "cursor",
    [
        "https://attacker.test/v1.0/users/delta?$deltatoken=secret",
        "https://graph.test@attacker.test/v1.0/users/delta",
        "https://graph.test/v1.0/users/delta#fragment",
    ],
)
def test_change_feed_rejects_malicious_persisted_cursors(cursor: str) -> None:
    provider = GraphDirectoryProvider("https://graph.test/v1.0", api_key="gateway-key")

    with pytest.raises(ValueError, match="origin|malformed"):
        provider.fetch_changes(cursor)


def test_change_feed_rejects_cross_origin_delta_cursor() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"value": [], "@odata.deltaLink": "https://attacker.test/delta?token=secret"},
            )
        ),
    )

    with pytest.raises(ValueError, match="origin"):
        provider.fetch_changes()


def test_change_feed_rejects_same_cursor_loop_before_returning_partial_data() -> None:
    cursor = "https://graph.test/v1.0/users/delta"
    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [{"id": "one", "mail": "one@example.com"}],
                    "@odata.nextLink": cursor,
                },
            )
        ),
    )

    with pytest.raises(ValueError, match="cursor loop"):
        provider.fetch_changes()


def test_legacy_users_adapter_never_returns_a_silent_partial_snapshot() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_users=1,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "one", "mail": "one@example.com"},
                        {"id": "two", "mail": "two@example.com"},
                    ]
                },
            )
        ),
    )

    with pytest.raises(GraphRetryLimitError, match="configured bounds"):
        provider.users()


def test_429_honors_bounded_retry_after_then_succeeds() -> None:
    attempts = 0
    waits: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(
            200,
            json={"value": [], "@odata.deltaLink": "https://graph.test/v1.0/users/delta?$deltatoken=done"},
        )

    result = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_retries=1,
        max_retry_after_seconds=2,
        sleep=waits.append,
        transport=httpx.MockTransport(handler),
    ).fetch_changes()

    assert result.complete is True
    assert attempts == 2
    assert waits == [2.0]


def test_429_excessive_wait_and_attempts_fail_closed() -> None:
    excessive_wait = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_retry_after_seconds=1,
        sleep=lambda _: pytest.fail("must not sleep past the configured bound"),
        transport=httpx.MockTransport(lambda _: httpx.Response(429, headers={"Retry-After": "10"})),
    )
    with pytest.raises(GraphRetryLimitError, match="configured maximum"):
        excessive_wait.fetch_changes()

    attempts = 0

    def always_limited(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(429, headers={"Retry-After": "0"})

    attempt_limited = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        api_key="gateway-key",
        max_retries=1,
        sleep=lambda _: None,
        transport=httpx.MockTransport(always_limited),
    )
    with pytest.raises(GraphRetryLimitError, match="retry limit"):
        attempt_limited.fetch_changes()
    assert attempts == 2


def test_transport_failures_do_not_retain_pii_token_or_cursor() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("alice@example.com token=opaque-secret bearer-secret")

    provider = GraphDirectoryProvider(
        "https://graph.test/v1.0",
        bearer_token="bearer-secret",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GraphRequestError) as caught:
        provider.fetch_changes("https://graph.test/v1.0/users/delta?$deltatoken=opaque-secret")
    assert str(caught.value) == "Microsoft Graph request failed"
    assert caught.value.__cause__ is None


def test_fetch_users_is_a_legacy_compatibility_adapter() -> None:
    provider = GraphDirectoryProvider(
        "https://graph.test",
        api_key="gateway-key",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"value": [{"id": "1", "mail": "one@example.com"}]})
        ),
    )

    assert provider.fetch_users() == provider.users()
