"""Adversarial transport tests for OIDC discovery, token and JWKS JSON."""

from __future__ import annotations

import asyncio
import gzip
import json
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Self

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from kp_operator_api import auth as auth_module
from kp_operator_api import console as console_module
from kp_operator_api.auth import BoundedPyJWKClient, OidcIdP
from kp_operator_api.oidc_provider import OidcProviderResponseError, bounded_json, bounded_json_async
from kp_telemetry.errors import AuthenticationError

_PUBLIC_TEST_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _stable_oidc_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        auth_module.socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [
            (auth_module.socket.AF_INET, auth_module.socket.SOCK_STREAM, 6, "", (_PUBLIC_TEST_IP, port))
        ],
    )


class _SyncChunks(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.iterated = False

    def __iter__(self) -> Iterator[bytes]:
        self.iterated = True
        yield from self.chunks


class _AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.iterated = True
        for chunk in self.chunks:
            yield chunk


def _response(
    stream: httpx.SyncByteStream | httpx.AsyncByteStream,
    *,
    headers: list[tuple[bytes, bytes]] | dict[str, str] | None = None,
    status_code: int = 200,
    method: str = "GET",
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers,
        stream=stream,
        request=httpx.Request(method, "https://id.example/provider"),
    )


def test_sync_reader_accepts_declared_chunked_and_compressed_json() -> None:
    body = b'{"issuer":"https://id.example"}'
    declared = _response(_SyncChunks(body), headers={"content-length": str(len(body))})
    chunked = _response(_SyncChunks(body[:8], body[8:]))
    compressed_body = gzip.compress(body)
    compressed = _response(
        _SyncChunks(compressed_body),
        headers={"content-encoding": "gzip", "content-length": str(len(compressed_body))},
    )

    for response in (declared, chunked, compressed):
        assert bounded_json(response, max_bytes=1024) == {"issuer": "https://id.example"}


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"2"), (b"content-length", b"2")],
        {"content-length": ""},
        {"content-length": "-1"},
        {"content-length": "2, 2"},
    ],
)
def test_sync_reader_rejects_duplicate_or_malformed_length_before_read(
    headers: list[tuple[bytes, bytes]] | dict[str, str],
) -> None:
    stream = _SyncChunks(b"{}")
    with pytest.raises(OidcProviderResponseError):
        bounded_json(_response(stream, headers=headers), max_bytes=1024)
    assert stream.iterated is False


def test_readers_bound_chunked_and_compressed_decoded_bytes() -> None:
    expanded = b'{"value":"' + b"x" * 2_000 + b'"}'
    compressed = gzip.compress(expanded)
    assert len(compressed) < 128

    sync_response = _response(
        _SyncChunks(compressed),
        headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
    )
    with pytest.raises(OidcProviderResponseError, match="maximum size"):
        bounded_json(sync_response, max_bytes=128)

    async_response = _response(
        _AsyncChunks(expanded[:40], expanded[40:]),
        method="POST",
    )
    with pytest.raises(OidcProviderResponseError, match="maximum size"):
        asyncio.run(bounded_json_async(async_response, max_bytes=128))

    async_compressed = _response(
        _AsyncChunks(compressed),
        headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
        method="POST",
    )
    with pytest.raises(OidcProviderResponseError, match="maximum size"):
        asyncio.run(bounded_json_async(async_compressed, max_bytes=128))


def test_async_reader_rejects_malformed_length_before_read() -> None:
    stream = _AsyncChunks(b"{}")
    response = _response(stream, headers={"content-length": "not-a-number"}, method="POST")

    with pytest.raises(OidcProviderResponseError, match="malformed Content-Length"):
        asyncio.run(bounded_json_async(response, max_bytes=1024))

    assert stream.iterated is False


class _AsyncResponseContext:
    def __init__(self, response: httpx.Response) -> None:
        self.response = response

    async def __aenter__(self) -> httpx.Response:
        return self.response

    async def __aexit__(self, *_args: object) -> None:
        pass


class _AsyncClient:
    response: httpx.Response
    requests: list[tuple[str, str]] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        pass

    def stream(self, method: str, url: str, **_kwargs: object) -> _AsyncResponseContext:
        type(self).requests.append((method, url))
        return _AsyncResponseContext(type(self).response)


def test_async_discovery_accepts_normal_compressed_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        {
            "issuer": "https://id.example",
            "authorization_endpoint": "https://id.example/authorize",
            "token_endpoint": "https://id.example/token",
        }
    ).encode()
    compressed = gzip.compress(body)
    _AsyncClient.response = _response(
        _AsyncChunks(compressed),
        headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
    )
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    metadata = asyncio.run(console_module._oidc_metadata("https://id.example"))

    assert metadata["authorization_endpoint"] == "https://id.example/authorize"


def test_async_discovery_maps_oversize_to_content_free_authentication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_secret = "provider-secret-never-echo"
    _AsyncClient.requests = []
    _AsyncClient.response = _response(
        _AsyncChunks((provider_secret + "x" * (64 * 1024)).encode()),
        headers={"content-length": str(64 * 1024 + len(provider_secret))},
    )
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    with pytest.raises(AuthenticationError, match="identity provider discovery failed") as caught:
        asyncio.run(console_module._oidc_metadata("https://id.example"))

    assert provider_secret not in str(caught.value)
    assert _AsyncClient.requests == [
        ("GET", f"https://{_PUBLIC_TEST_IP}/.well-known/openid-configuration"),
    ]


def test_async_discovery_rejects_wrong_issuer_type_as_stable_schema_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _AsyncClient.response = _response(_AsyncChunks(b'{"issuer":42}'))
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    with pytest.raises(AuthenticationError, match="invalid issuer"):
        asyncio.run(console_module._oidc_metadata("https://id.example"))


@pytest.mark.parametrize(
    "response",
    [
        _response(_AsyncChunks(b"[]"), method="POST"),
        _response(
            _AsyncChunks(b"provider-secret-never-echo"),
            headers={"content-length": str(64 * 1024 + 1)},
            method="POST",
        ),
        _response(
            _AsyncChunks(b"{}"),
            headers=[(b"content-length", b"2"), (b"content-length", b"2")],
            method="POST",
        ),
        _response(_AsyncChunks(b'{"secret":"provider-secret-never-echo"'), method="POST"),
    ],
)
def test_async_token_exchange_maps_transport_and_schema_failures_without_content(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
) -> None:
    _AsyncClient.response = response
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    with pytest.raises(AuthenticationError, match="invalid token response") as caught:
        asyncio.run(
            console_module._oidc_token_response(
                "https://id.example/token",
                {"code": "code"},
                issuer="https://id.example",
            )
        )

    assert "provider-secret-never-echo" not in str(caught.value)


def test_async_token_exchange_accepts_normal_chunked_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _AsyncClient.response = _response(
        _AsyncChunks(b'{"access_token":"access",', b'"id_token":"identity"}'),
        method="POST",
    )
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    assert asyncio.run(
        console_module._oidc_token_response(
            "https://id.example/token",
            {"code": "code"},
            issuer="https://id.example",
        )
    ) == {"access_token": "access", "id_token": "identity"}


def test_rejected_token_exchange_does_not_read_or_echo_provider_body(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _AsyncChunks(b'{"error_description":"provider-secret-never-echo"}')
    _AsyncClient.response = _response(stream, status_code=400, method="POST")
    monkeypatch.setattr(console_module.httpx, "AsyncClient", _AsyncClient)

    with pytest.raises(AuthenticationError, match="rejected the authorization code") as caught:
        asyncio.run(
            console_module._oidc_token_response(
                "https://id.example/token",
                {"code": "code"},
                issuer="https://id.example",
            )
        )

    assert "provider-secret-never-echo" not in str(caught.value)
    assert stream.iterated is False


def test_real_bounded_jwks_verification_caches_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer = "https://id.example"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
    provider_payloads = {
        f"{issuer}/.well-known/openid-configuration": {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
        },
        f"{issuer}/jwks": {"keys": [public_jwk]},
    }
    requests: list[str] = []

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        @contextmanager
        def stream(self, method: str, url: str, **_kwargs: object) -> Iterator[httpx.Response]:
            assert method == "GET"
            logical_url = url.replace(f"https://{_PUBLIC_TEST_IP}", issuer)
            requests.append(logical_url)
            body = json.dumps(provider_payloads[logical_url]).encode()
            yield httpx.Response(200, content=body, request=httpx.Request("GET", url))

    monkeypatch.setattr(auth_module.httpx, "Client", Client)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "roles": ["operator"],
            "iss": issuer,
            "aud": "api://operator",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    idp = OidcIdP(issuer, "api://operator")

    first = idp.verify(token)
    second = idp.verify(token)

    assert first == second
    assert requests.count(f"{issuer}/.well-known/openid-configuration") == 1
    assert requests.count(f"{issuer}/jwks") == 1


def test_oversized_jwks_maps_to_content_free_authentication_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider_secret = "provider-secret-never-echo"
    stream = _SyncChunks(provider_secret.encode())

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        @contextmanager
        def stream(self, _method: str, _url: str, **_kwargs: object) -> Iterator[httpx.Response]:
            yield _response(stream, headers={"content-length": str(256 * 1024 + 1)})

    monkeypatch.setattr(auth_module.httpx, "Client", Client)
    idp = OidcIdP("https://id.example", "api://operator")
    idp._jwk_client = BoundedPyJWKClient("https://id.example/jwks")
    token = jwt.encode(
        {"sub": str(uuid.uuid4())},
        "test-secret-at-least-thirty-two-bytes",
        algorithm="HS256",
        headers={"kid": "key-1"},
    )

    with pytest.raises(AuthenticationError, match="invalid or expired token") as caught:
        idp.verify(token)

    assert provider_secret not in str(caught.value)
    assert stream.iterated is False


def test_bounded_jwks_refuses_redirect_and_disables_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    init_kwargs: list[dict[str, object]] = []

    class Client:
        def __init__(self, **kwargs: object) -> None:
            init_kwargs.append(kwargs)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        @contextmanager
        def stream(self, _method: str, url: str, **_kwargs: object) -> Iterator[httpx.Response]:
            yield httpx.Response(
                302,
                headers={"location": "https://attacker.example/jwks"},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(auth_module.httpx, "Client", Client)
    client = BoundedPyJWKClient("https://id.example/jwks")

    with pytest.raises(jwt.PyJWKClientConnectionError, match="JWKS fetch failed"):
        client.fetch_data()

    assert init_kwargs[0]["follow_redirects"] is False
    assert init_kwargs[0]["trust_env"] is False


def test_bounded_jwks_refresh_failure_does_not_clear_cached_set(monkeypatch: pytest.MonkeyPatch) -> None:
    jwks = {"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "key-1", "alg": "HS256", "use": "sig"}]}
    calls = 0

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        @contextmanager
        def stream(self, _method: str, url: str, **_kwargs: object) -> Iterator[httpx.Response]:
            nonlocal calls
            calls += 1
            if calls == 1:
                yield httpx.Response(200, json=jwks, request=httpx.Request("GET", url))
            else:
                yield _response(
                    _SyncChunks(b"{}"),
                    headers={"content-length": str(256 * 1024 + 1)},
                )

    monkeypatch.setattr(auth_module.httpx, "Client", Client)
    client = BoundedPyJWKClient("https://id.example/jwks", lifespan=3600)

    first = client.get_jwk_set()
    assert first.keys[0].key_id == "key-1"
    assert client.get_jwk_set().keys[0].key_id == "key-1"
    assert calls == 1
    with pytest.raises(jwt.PyJWKClientConnectionError):
        client.get_jwk_set(refresh=True)
    assert client.get_jwk_set().keys[0].key_id == "key-1"
    assert calls == 2
