"""Secure content fetcher.

Implements SAN-001: allowlisted HTTPS fetching with redirect limits, final-domain
validation, DNS-rebinding protection, private/link-local/metadata address denial,
response-size and content-type limits, and timeouts. Fails closed.

DNS-rebinding protection: every hop resolves its hostname ONCE, validates that
every returned address is public, and then opens the connection against the
pinned IP (with the real hostname preserved for TLS SNI and the Host header), so
an attacker cannot answer a public address at validation time and a private one
at request time. Redirects re-enter the same pinned-resolution path.
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
    ipaddress.ip_network("169.254.0.0/16"),  # includes 169.254.169.254 metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_ALLOWED_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "text/csv",
    "application/json",
    "application/stix+json",
    "application/rss+xml",
    "application/xml",
    "text/xml",
}

DEFAULT_MAX_SIZE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 10.0

_ALLOWED_PORTS = {443}


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


def _resolve_pinned(url: str, allowlist: set[str]) -> tuple[str, int, list[str]]:
    """Resolve `url`'s host and return (host, port, pinned_public_ips).

    Validates scheme, allowlist membership, port, and that EVERY resolved
    address is public. Raises a FetchError subclass on any violation.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DomainNotAllowedError(f"non-HTTPS scheme rejected: {parsed.scheme}")
    if parsed.username or parsed.password:
        raise DomainNotAllowedError("credentials in URL are prohibited")
    host = (parsed.hostname or "").lower()
    if host not in allowlist:
        raise DomainNotAllowedError(f"domain {host} not in allowlist")
    port = parsed.port or 443
    if port not in _ALLOWED_PORTS:
        raise DomainNotAllowedError(f"port {port} is not allowed (only {sorted(_ALLOWED_PORTS)})")
    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DomainNotAllowedError(f"DNS resolution failed for {host}") from exc
    ips = {ipaddress.ip_address(info[4][0]) for info in addrinfos[:16]}
    for ip in ips:
        for net in BLOCKED_IP_NETWORKS:
            if ip in net:
                raise DeniedAddressError(f"resolved {ip} is a blocked address")
    if not ips:
        raise DomainNotAllowedError(f"no addresses resolved for {host}")
    return host, port, sorted(str(ip) for ip in ips)


def _pinned_url(url: str, host: str, port: int, ip: str) -> str:
    """Rewrite `url`'s host to the pinned IP, preserving path/query."""
    parsed = urlparse(url)
    netloc = ip if port == 443 else f"{ip}:{port}"
    return f"https://{netloc}{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"


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
        host, port, _ = _resolve_pinned(url, self._allowlist)
        hops = 0
        current = url
        final = url
        status = 0
        content_type = ""
        data = b""
        with httpx.Client(follow_redirects=False, timeout=self._timeout, http2=False) as client:
            while True:
                host, port, pinned_ips = _resolve_pinned(current, self._allowlist)
                ip = pinned_ips[0]
                try:
                    response = client.get(
                        _pinned_url(current, host, port, ip),
                        headers={
                            "User-Agent": "kingphisher-ingestion/0.1 (+https://internal)",
                            "Host": host if port == 443 else f"{host}:{port}",
                        },
                        extensions={"sni_hostname": host},
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
                final = current
                break
        if status >= 400:
            raise FetchError(f"HTTP {status} for {current}")
        if len(data) > self._max_size:
            raise OversizedResponseError(f"response size {len(data)} exceeds limit {self._max_size}")
        if content_type not in _ALLOWED_CONTENT_TYPES:
            raise UnsupportedContentTypeError(f"content type {content_type!r} not allowed")
        return FetchResult(url=url, final_url=final, content=data, content_type=content_type, status_code=status)
