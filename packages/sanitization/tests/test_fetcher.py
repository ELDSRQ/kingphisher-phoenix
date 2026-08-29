"""Regression tests for SecureFetcher SSRF / DNS-rebinding protection."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from types import SimpleNamespace

import httpx
import pytest
from kp_sanitization import fetcher
from kp_sanitization.fetcher import (
    DeniedAddressError,
    DomainNotAllowedError,
    FetchError,
    OversizedResponseError,
    SecureFetcher,
    _pinned_url,
    _resolve_pinned,
)


@pytest.fixture
def fetcher_fx() -> SecureFetcher:
    return SecureFetcher(allowlist={"advisory.example.com"})


def _fake_addrinfo(ip: str) -> list[tuple]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


GLOBAL_V4 = "8.8.8.8"
GLOBAL_V6 = "2001:4860:4860::8888"


def test_scheme_must_be_https(fetcher_fx: SecureFetcher) -> None:
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch("http://advisory.example.com/feed")


def test_credentials_in_url_rejected(fetcher_fx: SecureFetcher) -> None:
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch("https://user:pass@advisory.example.com/feed")


def test_non_allowlisted_domain_rejected(fetcher_fx: SecureFetcher) -> None:
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch("https://evil.example/feed")


@pytest.mark.parametrize(
    "host",
    [
        "sub.advisory.example.com",
        "advisory.example.com.evil.example",
        "wwww.advisory.example.com",
        "www.evil.example",
        "www.advisory.example.com.evil.example",
    ],
)
def test_lookalike_hosts_rejected_before_dns(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    """Anything other than base_domain / www.base_domain is rejected, and DNS is
    never consulted for a disallowed host."""
    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *a, **k: pytest.fail("DNS must not be consulted for a disallowed host"),
    )
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch(f"https://{host}/feed")


def test_non_standard_port_rejected(fetcher_fx: SecureFetcher) -> None:
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch("https://advisory.example.com:8443/feed")


def test_private_resolution_rejected(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("127.0.0.1"))
    with pytest.raises(DeniedAddressError):
        fetcher_fx.fetch("https://advisory.example.com/feed")


def test_cloud_metadata_resolution_rejected(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("169.254.169.254"))
    with pytest.raises(DeniedAddressError):
        fetcher_fx.fetch("https://advisory.example.com/latest/meta-data/")


class _ResponseContext:
    def __init__(self, response: object) -> None:
        self.response = response

    def __enter__(self) -> object:
        return self.response

    def __exit__(self, *args: object) -> None:
        return None


class _StreamingClient:
    def stream(self, method: str, url: str, **kwargs: object) -> _ResponseContext:
        assert method == "GET"
        return _ResponseContext(self.get(url, **kwargs))


class _FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        content: bytes = b"<feed/>",
        content_type: str = "text/xml",
        headers: dict[str, str] | httpx.Headers | None = None,
        chunks: list[bytes] | None = None,
        status_code: int = 200,
    ) -> None:
        self.status_code = status_code
        if isinstance(headers, httpx.Headers):
            self.headers = headers
        else:
            self.headers = {"content-type": content_type, **(headers or {})}
        self.is_redirect = False
        self.url = url
        self._content = content
        self._chunks = chunks
        self.chunks_yielded = 0

    def iter_bytes(self, chunk_size: int | None = None) -> Iterator[bytes]:
        if self._chunks is not None:
            for chunk in self._chunks:
                self.chunks_yielded += 1
                yield chunk
            return
        size = chunk_size or len(self._content) or 1
        for offset in range(0, len(self._content), size):
            self.chunks_yielded += 1
            yield self._content[offset : offset + size]


def _fake_response(
    url: str,
    *,
    content: bytes = b"<feed/>",
    content_type: str = "text/xml",
    headers: dict[str, str] | httpx.Headers | None = None,
    chunks: list[bytes] | None = None,
    status_code: int = 200,
) -> _FakeResponse:
    return _FakeResponse(
        url,
        content=content,
        content_type=content_type,
        headers=headers,
        chunks=chunks,
        status_code=status_code,
    )


def test_fetch_pins_connection_to_validated_ip(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """The request must go to the validated public IP, not the hostname, with
    the real hostname preserved for SNI and the Host header."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    captured: dict[str, object] = {}

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
            captured["url"] = url
            captured["headers"] = kwargs.get("headers", {})
            captured["extensions"] = kwargs.get("extensions", {})
            return _fake_response(url)

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    result = fetcher_fx.fetch("https://advisory.example.com/feed")
    assert captured["url"].startswith(f"https://{GLOBAL_V4}/feed")
    assert captured["headers"]["Host"] == "advisory.example.com"
    assert captured["extensions"]["sni_hostname"] == "advisory.example.com"
    assert result.content == b"<feed/>"


@pytest.mark.parametrize("content_type", ["application/json", "application/stix+json", "text/csv"])
def test_structured_feed_content_types_are_allowed(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch, content_type: str
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            pass

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return _fake_response(url, content=b"{}", content_type=content_type)

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    assert fetcher_fx.fetch("https://advisory.example.com/feed").content_type == content_type


def test_redirect_revalidates_and_pins_each_hop(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each hop re-resolves and re-pins, so a rebinding host cannot switch to a
    private address between hops."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    hits: list[str] = []

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            hits.append(url)
            if len(hits) == 1:
                return SimpleNamespace(
                    status_code=302,
                    headers={"content-type": "text/html", "location": "https://advisory.example.com/latest"},
                    is_redirect=True,
                    content=b"",
                    url=url,
                )
            return _fake_response(url, content=b"<feed/>")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    result = fetcher_fx.fetch("https://advisory.example.com/feed")
    assert len(hits) == 2
    assert result.final_url == "https://advisory.example.com/latest"
    assert all(GLOBAL_V4 in h for h in hits)


def test_redirect_to_www_variant_allowed_and_pinned(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """Feeds configured as base_domain often redirect to www.base_domain; the
    www-variant passes allowlist re-validation and is still pinned to the
    validated IP with the real www hostname for SNI/Host."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    requests: list[dict[str, str]] = []

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            requests.append(
                {
                    "url": url,
                    "host": str(kwargs.get("headers", {}).get("Host", "")),
                    "sni": str(kwargs.get("extensions", {}).get("sni_hostname", "")),
                }
            )
            if len(requests) == 1:
                return SimpleNamespace(
                    status_code=301,
                    headers={"content-type": "text/html", "location": "https://www.advisory.example.com/feed"},
                    is_redirect=True,
                    content=b"",
                    url=url,
                )
            return _fake_response(url, content=b"<feed/>")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    result = fetcher_fx.fetch("https://advisory.example.com/feed")
    assert result.final_url == "https://www.advisory.example.com/feed"
    assert len(requests) == 2
    assert all(r["url"].startswith(f"https://{GLOBAL_V4}/") for r in requests)
    assert requests[0]["host"] == "advisory.example.com"
    assert requests[1]["host"] == "www.advisory.example.com"
    assert requests[1]["sni"] == "www.advisory.example.com"


def test_direct_www_url_allowed_when_bare_domain_allowlisted(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return _fake_response(url, content=b"<feed/>")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    assert (
        fetcher_fx.fetch("https://www.advisory.example.com/feed").final_url == "https://www.advisory.example.com/feed"
    )


def test_bare_domain_allowed_when_www_form_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reverse direction: a source configured as www.example.com accepts the
    bare domain too (canonicalization strips the leading www.)."""
    www_fetcher = SecureFetcher(allowlist={"www.advisory.example.com"})
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return _fake_response(url, content=b"<feed/>")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    assert www_fetcher.fetch("https://advisory.example.com/feed").status_code == 200


def test_redirect_to_arbitrary_host_denied(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """A redirect off the allowlisted domain (base or www variant) is denied
    before any request is issued to the target host."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    issued: list[str] = []

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            issued.append(url)
            return SimpleNamespace(
                status_code=302,
                headers={"content-type": "text/html", "location": "https://evil.example/feed"},
                is_redirect=True,
                content=b"",
                url=url,
            )

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(DomainNotAllowedError, match="evil.example"):
        fetcher_fx.fetch("https://advisory.example.com/feed")
    assert len(issued) == 1


def test_redirect_to_private_resolution_denied(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS-rebinding attempt: first hop resolves public, redirect hop resolves
    private -> the second hop is denied and no internal request is issued."""
    calls = {"n": 0}

    def _flip(*a: object, **k: object) -> list[tuple]:
        calls["n"] += 1
        ip = GLOBAL_V4 if calls["n"] == 1 else "10.0.0.5"
        return _fake_addrinfo(ip)

    monkeypatch.setattr(fetcher.socket, "getaddrinfo", _flip)
    issued: list[str] = []

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            issued.append(url)
            return SimpleNamespace(
                status_code=302,
                headers={"content-type": "text/html", "location": "https://advisory.example.com/internal"},
                is_redirect=True,
                content=b"",
                url=url,
            )

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(DeniedAddressError):
        fetcher_fx.fetch("https://advisory.example.com/feed")
    # The first (public) hop was issued; the rebinding hop to 10.0.0.5 was
    # denied before any second request went out.
    assert len(issued) == 1


def test_oversized_response_rejected(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    big = b"x" * (fetcher.DEFAULT_MAX_SIZE_BYTES + 1)

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return _fake_response(url, content=big)

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(fetcher.OversizedResponseError):
        fetcher_fx.fetch("https://advisory.example.com/feed")


def test_oversized_chunked_response_stops_streaming_early(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing Content-Length must not cause the complete body to be buffered."""
    bounded_fetcher = SecureFetcher(allowlist={"advisory.example.com"}, max_size=10)
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    response = _fake_response("https://8.8.8.8/feed", chunks=[b"123456", b"789012", b"never-read"])

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return response

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(fetcher.OversizedResponseError, match="exceeds limit 10"):
        bounded_fetcher.fetch("https://advisory.example.com/feed")
    assert response.chunks_yielded == 2


def test_oversized_declared_response_is_rejected_without_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    bounded_fetcher = SecureFetcher(allowlist={"advisory.example.com"}, max_size=10)
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))
    response = _fake_response(
        "https://8.8.8.8/feed",
        headers={"content-length": "11"},
        chunks=[b"must-not-read"],
    )

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return response

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(fetcher.OversizedResponseError, match="declared response size"):
        bounded_fetcher.fetch("https://advisory.example.com/feed")
    assert response.chunks_yielded == 0


def test_untrusted_content_type_rejected(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return _fake_response(url, content_type="application/octet-stream")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(fetcher.UnsupportedContentTypeError):
        fetcher_fx.fetch("https://advisory.example.com/feed")


def test_resolve_pinned_rejects_all_private(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("192.168.1.1") + _fake_addrinfo("127.0.0.1")
    )
    with pytest.raises(DeniedAddressError):
        _resolve_pinned("https://advisory.example.com/feed", {"advisory.example.com"})


@pytest.mark.parametrize(
    "address",
    [
        "100.64.0.1",  # carrier-grade NAT / shared address space
        "192.0.2.1",  # IANA documentation reservation
        "240.0.0.1",  # IPv4 reserved space
        "224.0.0.1",  # IPv4 multicast (classified global by ipaddress)
        "ff02::1",  # IPv6 multicast
        "::ffff:127.0.0.1",  # mapped IPv4 loopback
        "::ffff:100.64.0.1",  # mapped IPv4 CGNAT
    ],
)
def test_resolve_pinned_rejects_non_global_and_non_unicast_addresses(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(address))
    with pytest.raises(DeniedAddressError, match="not a global unicast"):
        _resolve_pinned("https://advisory.example.com/feed", {"advisory.example.com"})


@pytest.mark.parametrize("address", [GLOBAL_V4, GLOBAL_V6, "::ffff:8.8.8.8"])
def test_resolve_pinned_accepts_global_unicast_addresses(monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(address))
    _, _, resolved = _resolve_pinned("https://advisory.example.com/feed", {"advisory.example.com"})
    assert resolved == [address]


def test_pinned_ipv6_url_is_bracketed_and_preserves_path_and_query() -> None:
    assert (
        _pinned_url("https://advisory.example.com/feed/latest?format=json", "advisory.example.com", 443, GLOBAL_V6)
        == f"https://[{GLOBAL_V6}]/feed/latest?format=json"
    )


def test_fetch_pins_global_ipv6_with_original_host_for_tls(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V6))
    captured: dict[str, object] = {}

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            captured["url"] = url
            captured["headers"] = kwargs["headers"]
            captured["extensions"] = kwargs["extensions"]
            return _fake_response(url)

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    assert fetcher_fx.fetch("https://advisory.example.com/feed").content == b"<feed/>"
    assert captured["url"] == f"https://[{GLOBAL_V6}]/feed"
    assert captured["headers"]["Host"] == "advisory.example.com"
    assert captured["extensions"]["sni_hostname"] == "advisory.example.com"


def test_http_error_is_wrapped(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            raise fetcher.httpx.ConnectError("boom")

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)
    with pytest.raises(FetchError):
        fetcher_fx.fetch("https://advisory.example.com/feed")


@pytest.mark.parametrize(
    "url",
    [
        "https://advisory.example.com:bad/feed",
        "https://[::1/feed",
        "https:////advisory.example.com/feed",
        "https://advisory.example.com/\nfeed",
        "https://advisory.example.com/" + ("x" * 4096),
    ],
)
def test_malformed_or_ambiguous_urls_fail_before_dns(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("DNS must not run for malformed URLs"),
    )
    with pytest.raises(DomainNotAllowedError):
        fetcher_fx.fetch(url)


def test_invalid_allowlist_entries_do_not_expand_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    invalid = SecureFetcher(allowlist={"com", "https://advisory.example.com", "*.example.com"})
    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("DNS must not run without a valid allowlist domain"),
    )
    with pytest.raises(DomainNotAllowedError):
        invalid.fetch("https://advisory.example.com/feed")
    with pytest.raises(ValueError, match="malformed"):
        invalid.add_domain("example.com:443")


def _install_static_response(
    monkeypatch: pytest.MonkeyPatch,
    response: _FakeResponse,
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *args, **kwargs: _fake_addrinfo(GLOBAL_V4))

    class _Client(_StreamingClient):
        def __init__(self, **kwargs: object) -> None:
            return None

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> object:
            return response

    monkeypatch.setattr(fetcher.httpx, "Client", _Client)


@pytest.mark.parametrize(
    "headers",
    [
        httpx.Headers(
            [
                (b"content-type", b"text/xml"),
                (b"content-length", b"5"),
                (b"content-length", b"6"),
            ]
        ),
        {"content-length": "5", "transfer-encoding": "chunked"},
        {"content-length": "-1"},
        {"transfer-encoding": "compress"},
        {"content-encoding": "unknown"},
    ],
)
def test_ambiguous_or_unsupported_response_framing_is_rejected(
    fetcher_fx: SecureFetcher,
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str] | httpx.Headers,
) -> None:
    response = _fake_response(f"https://{GLOBAL_V4}/feed", headers=headers)
    _install_static_response(monkeypatch, response)
    with pytest.raises(FetchError):
        fetcher_fx.fetch("https://advisory.example.com/feed")


def test_missing_content_type_fails_closed_before_body_read(
    fetcher_fx: SecureFetcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _fake_response(f"https://{GLOBAL_V4}/feed")
    response.headers = {}
    _install_static_response(monkeypatch, response)

    with pytest.raises(FetchError, match="missing content-type"):
        fetcher_fx.fetch("https://advisory.example.com/feed")
    assert response.chunks_yielded == 0


def test_compressed_decoded_body_remains_size_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    bounded = SecureFetcher(allowlist={"advisory.example.com"}, max_size=8)
    response = _fake_response(
        f"https://{GLOBAL_V4}/feed",
        headers={"content-encoding": "gzip", "content-length": "4"},
        chunks=[b"12345", b"67890"],
    )
    _install_static_response(monkeypatch, response)
    with pytest.raises(OversizedResponseError, match="exceeds limit 8"):
        bounded.fetch("https://advisory.example.com/feed")


def test_upstream_http_error_does_not_disclose_query_secret(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _fake_response(f"https://{GLOBAL_V4}/feed", status_code=503)
    _install_static_response(monkeypatch, response)
    with pytest.raises(FetchError) as raised:
        fetcher_fx.fetch("https://advisory.example.com/feed?api_key=do-not-log")
    assert "do-not-log" not in str(raised.value)
