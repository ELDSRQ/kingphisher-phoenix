from __future__ import annotations

import httpx
from kp_workers.providers.graph import GraphDirectoryProvider


def test_graph_provider_auth_pagination_validation_and_bounds() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/users":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "1", "mail": "Alice@Example.com", "displayName": "Alice", "unused": "drop"},
                        {"id": "bad", "mail": "not-an-email"},
                    ],
                    "@odata.nextLink": "https://graph.test/page2",
                },
            )
        return httpx.Response(200, json={"value": [{"id": "2", "mail": "bob@example.com"}]})

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
