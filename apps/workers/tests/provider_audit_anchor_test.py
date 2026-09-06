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
    LocalWormAuditAnchorProvider,
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
        "previous_anchor_hash": None,
        "schema_version": 2,
        "sequence": 42,
        "signed_at": "2026-08-27T12:00:00.000000Z",
    }
    assert anchor.blob_name == f"v1/{42:020d}-{'ab' * 32}.json"
    assert anchor.leaf_name == f"{42:020d}-{'ab' * 32}.json"


def test_previous_anchor_hash_is_embedded_and_round_trips() -> None:
    chained = AuditAnchor(
        sequence=43,
        event_hash="cd" * 32,
        signed_at=datetime(2026, 8, 27, 13, 0, tzinfo=UTC),
        previous_anchor_hash="ef" * 32,
    )
    document = json.loads(chained.canonical_bytes())
    assert document["previous_anchor_hash"] == "ef" * 32

    parsed = AuditAnchor.from_bytes(chained.canonical_bytes())
    assert parsed == chained


def test_from_bytes_accepts_legacy_v1_documents() -> None:
    legacy = json.dumps(
        {"event_hash": "ab" * 32, "schema_version": 1, "sequence": 7, "signed_at": "2026-08-27T12:00:00.000000Z"},
        sort_keys=True,
    ).encode("ascii")
    parsed = AuditAnchor.from_bytes(legacy)
    assert parsed.sequence == 7
    assert parsed.previous_anchor_hash is None


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b'{"schema_version": 9, "event_hash": "ab", "sequence": 1, "signed_at": "x"}',
        b'{"schema_version": 2, "sequence": 1, "signed_at": "2026-08-27T12:00:00Z"}',
        b"x" * 5000,
    ],
)
def test_from_bytes_fails_closed_on_malformed_documents(payload: bytes) -> None:
    with pytest.raises(AuditAnchorError):
        AuditAnchor.from_bytes(payload)


def test_mismatch_error_is_non_retryable() -> None:
    assert AuditAnchorMismatchError.retryable is False
    assert AuditAnchorError.retryable is True


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


def _list_xml(leaf_names: list[str], next_marker: str = "") -> bytes:
    blobs = "".join(f"<Blob><Name>v1/{name}</Name></Blob>" for name in leaf_names)
    marker = f"<NextMarker>{next_marker}</NextMarker>" if next_marker else "<NextMarker/>"
    return (
        f'<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>{blobs}</Blobs>{marker}'
        "</EnumerationResults>"
    ).encode("ascii")


def _stored(sequence: int) -> AuditAnchor:
    return AuditAnchor(sequence, "ab" * 32, datetime(2026, 8, 27, 12, 0, tzinfo=UTC))


def test_read_recent_returns_newest_anchors_first() -> None:
    stored = {anchor.blob_name: anchor.canonical_bytes() for anchor in (_stored(1), _stored(2), _stored(3))}

    leaf_names = [_stored(1).leaf_name, _stored(2).leaf_name, _stored(3).leaf_name]

    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.query.decode() if isinstance(request.url.query, bytes) else request.url.query
        if "comp=list" in query:
            return httpx.Response(200, content=_list_xml(leaf_names))
        return httpx.Response(200, content=stored[request.url.path.split("/", 2)[2]])

    anchors = _provider(handler).read_recent(2)
    assert [anchor.sequence for anchor in anchors] == [3, 2]


def test_read_recent_ignores_objects_outside_the_layout_prefix() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.query.decode() if isinstance(request.url.query, bytes) else request.url.query
        if "comp=list" in query:
            # A stray object and a nested path must not be treated as anchors.
            body = (
                '<?xml version="1.0"?><EnumerationResults><Blobs>'
                "<Blob><Name>unrelated.txt</Name></Blob>"
                "<Blob><Name>v1/nested/x.json</Name></Blob>"
                f"<Blob><Name>{_stored(5).blob_name}</Name></Blob>"
                "</Blobs><NextMarker/></EnumerationResults>"
            ).encode("ascii")
            return httpx.Response(200, content=body)
        return httpx.Response(200, content=_stored(5).canonical_bytes())

    anchors = _provider(handler).read_recent(8)
    assert [anchor.sequence for anchor in anchors] == [5]


def test_local_worm_provider_create_exists_and_mismatch(tmp_path: Any) -> None:
    provider = LocalWormAuditAnchorProvider(tmp_path)
    anchor = AuditAnchor(3, "ab" * 32, datetime(2026, 8, 27, 12, 0, tzinfo=UTC), previous_anchor_hash="cd" * 32)

    assert provider.publish(anchor) == "created"
    # Same content is idempotent.
    assert provider.publish(anchor) == "exists"

    # Same key, different content -> non-retryable mismatch (create-only WORM).
    tampered = AuditAnchor(3, "ab" * 32, datetime(2026, 8, 27, 12, 0, tzinfo=UTC))
    with pytest.raises(AuditAnchorMismatchError):
        provider.publish(tampered)


def test_local_worm_read_recent_is_newest_first(tmp_path: Any) -> None:
    provider = LocalWormAuditAnchorProvider(tmp_path)
    for sequence in (1, 2, 3):
        provider.publish(AuditAnchor(sequence, "ab" * 32, datetime(2026, 8, 27, 12, 0, tzinfo=UTC)))

    recent = provider.read_recent(2)
    assert [anchor.sequence for anchor in recent] == [3, 2]

    assert LocalWormAuditAnchorProvider(tmp_path / "empty").read_recent(4) == []
