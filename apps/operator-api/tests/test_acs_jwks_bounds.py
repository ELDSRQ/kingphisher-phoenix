"""Hostile-response and rotation tests for the ACS Event Grid JWKS boundary."""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Self

import httpx
import jwt
import kp_operator_api.acs_receipts as receipt_module
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from kp_operator_api.acs_receipts import EventGridTokenVerifier
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.oidc_provider import MAX_OIDC_JWKS_BYTES

TENANT_ID = "11111111-1111-4111-8111-111111111111"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
PUBLISHER = "4962773b-9cdb-44cf-a8bf-237846a00ab7"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"


class _Chunks(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.iterated = False

    def __iter__(self) -> Iterator[bytes]:
        self.iterated = True
        yield from self.chunks


def _response(
    stream: httpx.SyncByteStream,
    *,
    status_code: int = 200,
    headers: list[tuple[bytes, bytes]] | dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers,
        stream=stream,
        request=httpx.Request("GET", JWKS_URL),
    )


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key="02" * 32,
        ciphertext_kek="01" * 32,
        console_jwt_secret="03" * 32,
        acs_receipt_signing_key="04" * 32,
        event_grid_tenant_id=TENANT_ID,
        event_grid_audience=AUDIENCE,
        event_grid_subscription_name="acs-delivery-receipts",
        event_grid_topic=(
            "/subscriptions/33333333-3333-4333-8333-333333333333/"
            "resourceGroups/rg/providers/Microsoft.Communication/CommunicationServices/acs"
        ),
        event_grid_publisher_app_id=PUBLISHER,
    )


class _Client:
    responses: list[httpx.Response] = []
    requests: list[tuple[str, str]] = []
    init_kwargs: list[dict[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        type(self).init_kwargs.append(kwargs)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    @contextmanager
    def stream(self, method: str, url: str, **_kwargs: object) -> Iterator[httpx.Response]:
        type(self).requests.append((method, url))
        yield type(self).responses.pop(0)


def _install_client(monkeypatch: pytest.MonkeyPatch, *responses: httpx.Response) -> None:
    _Client.responses = list(responses)
    _Client.requests = []
    _Client.init_kwargs = []
    monkeypatch.setattr("kp_operator_api.acs_receipts.httpx.Client", _Client)


def _public_jwk(private_key: rsa.RSAPrivateKey, *, kid: str) -> dict[str, str]:
    jwk: dict[str, str] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def _token(private_key: rsa.RSAPrivateKey, *, kid: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            "tid": TENANT_ID,
            "aud": AUDIENCE,
            "azp": PUBLISHER,
            "roles": [receipt_module.SUBSCRIBER_ROLE],
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _json_response(payload: object) -> httpx.Response:
    body = json.dumps(payload).encode("utf-8")
    return _response(
        _Chunks(body),
        headers={"content-type": "application/json", "content-length": str(len(body))},
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/metadata/identity/oauth2/token",
        f"https://169.254.169.254/{TENANT_ID}/discovery/v2.0/keys",
        f"https://login.microsoftonline.com.evil.example/{TENANT_ID}/discovery/v2.0/keys",
        f"https://login.microsoftonline.com@127.0.0.1/{TENANT_ID}/discovery/v2.0/keys",
        f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys?next=http://127.0.0.1",
    ],
)
def test_jwks_url_allowlist_blocks_private_and_metadata_egress(url: str) -> None:
    with pytest.raises(jwt.PyJWKClientError, match="JWKS URL is invalid"):
        receipt_module._BoundedEventGridJWKClient(url, tenant_id=TENANT_ID)  # noqa: SLF001


def test_jwks_url_is_revalidated_immediately_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_client(monkeypatch)
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001
    client.uri = "http://169.254.169.254/metadata/instance"

    with pytest.raises(jwt.PyJWKClientError, match="JWKS URL is invalid"):
        client.fetch_data()

    assert _Client.requests == []


@pytest.mark.parametrize("status_code", [302, 503])
def test_redirect_and_error_statuses_are_not_followed_or_read(
    monkeypatch: pytest.MonkeyPatch, status_code: int
) -> None:
    provider_secret = b"provider-secret-must-not-escape"
    stream = _Chunks(provider_secret)
    _install_client(
        monkeypatch,
        _response(stream, status_code=status_code, headers={"location": "http://169.254.169.254/metadata"}),
    )
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed") as caught:
        client.fetch_data()

    assert provider_secret.decode() not in str(caught.value)
    assert stream.iterated is False
    assert _Client.init_kwargs[0]["follow_redirects"] is False


def test_excessive_headers_are_rejected_before_body_read(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _Chunks(b'{"keys": []}')
    headers = [(f"x-field-{index}".encode(), b"value") for index in range(65)]
    _install_client(monkeypatch, _response(stream, headers=headers))
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed"):
        client.fetch_data()

    assert stream.iterated is False


def test_declared_body_limit_is_enforced_before_body_read(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _Chunks(b'{"keys": []}')
    _install_client(
        monkeypatch,
        _response(stream, headers={"content-length": str(MAX_OIDC_JWKS_BYTES + 1)}),
    )
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed"):
        client.fetch_data()

    assert stream.iterated is False


def test_compressed_body_is_bounded_after_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    expanded = b'{"keys":[],"padding":"' + b"x" * MAX_OIDC_JWKS_BYTES + b'"}'
    compressed = gzip.compress(expanded)
    _install_client(
        monkeypatch,
        _response(
            _Chunks(compressed),
            headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
        ),
    )
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed"):
        client.fetch_data()


@pytest.mark.parametrize("body", [b"\xff", b'{"keys":'])
def test_jwks_requires_utf8_json(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    _install_client(monkeypatch, _response(_Chunks(body)))
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed"):
        client.fetch_data()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"keys": []},
        {"keys": [{} for _ in range(33)]},
        {"keys": [{f"member-{index}": "value" for index in range(33)}]},
        {"keys": [{"kid": "key-1", "nested": {"not": "a JWK scalar"}}]},
    ],
)
def test_jwks_schema_and_key_counts_are_bounded(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    _install_client(monkeypatch, _json_response(payload))
    client = receipt_module._BoundedEventGridJWKClient(JWKS_URL, tenant_id=TENANT_ID)  # noqa: SLF001

    with pytest.raises(jwt.PyJWKClientError, match="JWKS response is invalid"):
        client.fetch_data()


def test_valid_keys_are_cached_and_rotated_with_bounded_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_one = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_two = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _install_client(
        monkeypatch,
        _json_response({"keys": [_public_jwk(key_one, kid="key-1")]}),
        _json_response({"keys": [_public_jwk(key_two, kid="key-2")]}),
    )
    verifier = EventGridTokenVerifier(_settings())

    verifier.verify(f"Bearer {_token(key_one, kid='key-1')}")
    verifier.verify(f"Bearer {_token(key_one, kid='key-1')}")
    verifier.verify(f"Bearer {_token(key_two, kid='key-2')}")
    verifier.verify(f"Bearer {_token(key_two, kid='key-2')}")

    assert _Client.requests == [("GET", JWKS_URL), ("GET", JWKS_URL)]
    for kwargs in _Client.init_kwargs:
        timeout = kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert (timeout.connect, timeout.read, timeout.write, timeout.pool) == (5.0, 5.0, 5.0, 5.0)
        assert kwargs["follow_redirects"] is False
        assert kwargs["verify"] is True


def test_invalid_rotation_does_not_erase_cached_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key_one = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unknown_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _install_client(
        monkeypatch,
        _json_response({"keys": [_public_jwk(key_one, kid="key-1")]}),
        _json_response({"keys": []}),
    )
    verifier = EventGridTokenVerifier(_settings())
    known_token = _token(key_one, kid="key-1")

    verifier.verify(f"Bearer {known_token}")
    with pytest.raises(PermissionError, match="invalid bearer token"):
        verifier.verify(f"Bearer {_token(unknown_key, kid='unknown-key')}")
    verifier.verify(f"Bearer {known_token}")

    assert _Client.requests == [("GET", JWKS_URL), ("GET", JWKS_URL)]
