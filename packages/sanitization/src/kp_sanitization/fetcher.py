"""Secure content fetcher.

Implements SAN-001: allowlisted HTTPS fetching with redirect limits, final-domain
validation, DNS-rebinding protection, private/link-local/metadata address denial,
response-size and content-type limits, and timeouts. Fails closed.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
]

_ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/rss+xml", "application/xml", "text/xml"}

DEFAULT_MAX_SIZE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 10.0


@dataclass
class FetchResult:
    url: str
    final_url: str
    content: bytes
    content_type: str
    status_code: int = field(default=0)


class FetchError(Exception):
    """Base for all fetcher failures; all paths fail closed."""


class DeniedAddressError(FetchError):
    """URL resolved to a private/blocked address."""


class DomainNotAllowedError(FetchError):
    """Final domain is not on the allowlist."""


class OversizedResponseError(FetchError):
    """Response exceeded the size limit."""


class UnsupportedContentTypeError(FetchError):
    """Response content type is not allowlisted."""


def _resolve_allowed(url: str, allowlist: set[str], port_override: int | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DomainNotAllowedError(f"non-HTTPS scheme rejected: {parsed.scheme}")
    if parsed.username or parsed.password:
        raise DomainNotAllowedError("credentials in URL are prohibited")
    host = (parsed.hostname or "").lower()
    if host not in allowlist:
        raise DomainNotAllowedError(f"domain {host} not in allowlist")
    port = parsed.port or (port_override or 443)
    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = {ipaddress.ip_address(info[4][0]) for info in addrinfos[:8]}
    except OSError as exc:
        raise DomainNotAllowedError(f"DNS resolution failed for {host}") from exc
    for ip in ips:
        for net in BLOCKED_IP_NETWORKS:
            if ip in net:
                raise DeniedAddressError(f"resolved {ip} is a blocked address")
    return host


class SecureFetcher:
    def __init__(
        self,
        allowlist: set[str] | None = None,
        max_size: int = DEFAULT_MAX_SIZE_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._allowlist = allowlist or set()
        self._max_size = max_size
        self._max_redirects = max_redirects
        self._timeout = timeout

    def add_domain(self, domain: str) -> None:
        self._allowlist.add(domain.lower())

    def fetch(self, url: str) -> FetchResult:
        # Pre-validate before any network I/O.
        _resolve_allowed(url, self._allowlist)
        hops = 0
        current = url
        final = url
        status = 0
        content_type = ""
        data = b""
        with httpx.Client(follow_redirects=False, timeout=self._timeout, http2=False) as client:
            while True:
                _resolve_allowed(current, self._allowlist)
                try:
                    response = client.get(
                        current,
                        headers={"User-Agent": "kingphisher-ingestion/0.1 (+https://internal)"},
                    )
                except httpx.HTTPError as exc:
                    raise FetchError(f"request failed: {exc}") from exc
                status = response.status_code
                content_type = response.headers.get("content-type", "").split(";")[0].lower()
                if response.is_redirect:
                    hops += 1
                    if hops > self._max_redirects:
                        raise FetchError(f"redirect limit exceeded ({self._max_redirects})")
                    location = response.headers.get("location")
                    if not location:
                        raise FetchError("redirect without location")
                    current = str(httpx.URL(current).join(location))
                    if urlparse(current).scheme != "https":
                        raise DomainNotAllowedError("redirect escaped HTTPS")
                    continue
                data = response.content
                final = str(response.url)
                break
        if status >= 400:
            raise FetchError(f"HTTP {status} for {current}")
        if len(data) > self._max_size:
            raise OversizedResponseError(f"response size {len(data)} exceeds limit {self._max_size}")
        if content_type not in _ALLOWED_CONTENT_TYPES:
            raise UnsupportedContentTypeError(f"content type {content_type!r} not allowed")
        return FetchResult(url=url, final_url=final, content=data, content_type=content_type, status_code=status)
