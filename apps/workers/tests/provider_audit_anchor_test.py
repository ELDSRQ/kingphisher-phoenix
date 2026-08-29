from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from kp_workers.providers.audit_anchor import (
    AuditAnchor,
    AuditAnchorError,
    AuditAnchorMismatchError,
    AzureBlobAuditAnchorProvider,
)


class FakeCredential:
    def __init__(self) -> None:
        self.scopes: list[str] = []
        self.closed = False

    def get_token(self, *scopes: str, **_kwargs: Any) -> Any:
        self.scopes.extend(scopes)
        return SimpleNamespace(token="test-token")

    def close(self) -> None:
        self.closed = True


def _anchor() -> AuditAnchor:
    return AuditAnchor(
        sequence=42,
        event_hash="ab" * 32,
        signed_at=datetime(2026, 8, 27, 12, 0, tzinfo=UTC),
    )


def _provider(handler: Any, credential: FakeCredential | None = None) -> AzureBlobAuditAnchorProvider:
    return AzureBlobAuditAnchorProvider(
        "https://auditaccount.blob.core.windows.net/audit-head-anchors",
        credential=credential or FakeCredential(),  # type: ignore[arg-type]
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_anchor_is_minimal_canonical_and_non_pii() -> None:
    anchor = _anchor()
    document = json.loads(anchor.canonical_bytes())

    assert document == {
        "event_hash": "ab" * 32,
        "schema_version": 1,
        "sequence": 42,
        "signed_at": "2026-08-27T12:00:00.000000Z",
    }
    assert anchor.blob_name == f"v1/{42:020d}-{'ab' * 32}.json"


def test_create_uses_managed_identity_and_create_only_condition() -> None:
    requests: list[httpx.Request] = []
    credential = FakeCredential()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201)

    provider = _provider(handler, credential)
    assert provider.publish(_anchor()) == "created"

    request = requests[0]
    assert request.method == "PUT"
    assert request.headers["if-none-match"] == "*"
    assert request.headers["x-ms-blob-type"] == "BlockBlob"
    assert request.headers["authorization"] == "Bearer test-token"
    assert request.url.path.endswith(_anchor().blob_name)
    assert credential.scopes == ["https://storage.azure.com/.default"]


def test_same_content_collision_is_idempotent() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.method == "PUT":
            return httpx.Response(412)
        return httpx.Response(200, content=_anchor().canonical_bytes())

    assert _provider(handler).publish(_anchor()) == "exists"
    assert methods == ["PUT", "GET"]


def test_different_content_collision_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(412)
        return httpx.Response(200, content=b'{"event_hash":"different"}\n')

    with pytest.raises(AuditAnchorMismatchError, match="different content"):
        _provider(handler).publish(_anchor())


def test_collision_response_is_bounded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(412)
        return httpx.Response(200, headers={"Content-Length": "5000"}, content=b"x" * 5000)

    with pytest.raises(AuditAnchorError, match="maximum size"):
        _provider(handler).publish(_anchor())


def test_external_clients_and_credentials_are_not_closed() -> None:
    credential = FakeCredential()
    client = httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(201)))
    provider = AzureBlobAuditAnchorProvider(
        "https://auditaccount.blob.core.windows.net/audit-head-anchors",
        credential=credential,  # type: ignore[arg-type]
        client=client,
    )

    provider.close()

    assert credential.closed is False
    assert client.is_closed is False
    client.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://auditaccount.blob.core.windows.net/audit-head-anchors",
        "https://evil.example/audit-head-anchors",
        "https://auditaccount.blob.core.windows.net/a/b",
        "https://auditaccount.blob.core.windows.net/a?sig=secret",
    ],
)
def test_container_url_rejects_non_azure_or_secret_bearing_endpoints(url: str) -> None:
    with pytest.raises(ValueError, match="Azure Blob container"):
        AzureBlobAuditAnchorProvider(url, credential=FakeCredential())  # type: ignore[arg-type]
