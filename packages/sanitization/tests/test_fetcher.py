"""Regression tests for SecureFetcher SSRF / DNS-rebinding protection."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from kp_sanitization import fetcher
from kp_sanitization.fetcher import (
    DeniedAddressError,
    DomainNotAllowedError,
    FetchError,
    SecureFetcher,
    _resolve_pinned,
)


@pytest.fixture
def fetcher_fx() -> SecureFetcher:
    return SecureFetcher(allowlist={"advisory.example.com"})


def _fake_addrinfo(ip: str) -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


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


def _fake_response(url: str, *, content: bytes = b"<feed/>", content_type: str = "text/xml") -> SimpleNamespace:
    return SimpleNamespace(
        status_code=200,
        headers={"content-type": content_type},
        is_redirect=False,
        content=content,
        url=url,
    )


def test_fetch_pins_connection_to_validated_ip(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """The request must go to the validated public IP, not the hostname, with
    the real hostname preserved for SNI and the Host header."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))
    captured: dict[str, object] = {}

    class _Client:
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
    assert captured["url"].startswith("https://203.0.113.10/feed")
    assert captured["headers"]["Host"] == "advisory.example.com"
    assert captured["extensions"]["sni_hostname"] == "advisory.example.com"
    assert result.content == b"<feed/>"


@pytest.mark.parametrize("content_type", ["application/json", "application/stix+json", "text/csv"])
def test_structured_feed_content_types_are_allowed(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch, content_type: str
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))

    class _Client:
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
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))
    hits: list[str] = []

    class _Client:
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
    assert all("203.0.113.10" in h for h in hits)


def test_redirect_to_www_variant_allowed_and_pinned(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    """Feeds configured as base_domain often redirect to www.base_domain; the
    www-variant passes allowlist re-validation and is still pinned to the
    validated IP with the real www hostname for SNI/Host."""
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))
    requests: list[dict[str, str]] = []

    class _Client:
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
    assert all(r["url"].startswith("https://203.0.113.10/") for r in requests)
    assert requests[0]["host"] == "advisory.example.com"
    assert requests[1]["host"] == "www.advisory.example.com"
    assert requests[1]["sni"] == "www.advisory.example.com"


def test_direct_www_url_allowed_when_bare_domain_allowlisted(
    fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))

    class _Client:
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
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))

    class _Client:
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
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))
    issued: list[str] = []

    class _Client:
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
        ip = "203.0.113.10" if calls["n"] <= 2 else "10.0.0.5"
        return _fake_addrinfo(ip)

    monkeypatch.setattr(fetcher.socket, "getaddrinfo", _flip)
    issued: list[str] = []

    class _Client:
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
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))
    big = b"x" * (fetcher.DEFAULT_MAX_SIZE_BYTES + 1)

    class _Client:
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


def test_untrusted_content_type_rejected(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))

    class _Client:
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


def test_http_error_is_wrapped(fetcher_fx: SecureFetcher, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetcher.socket, "getaddrinfo", lambda *a, **k: _fake_addrinfo("203.0.113.10"))

    class _Client:
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
