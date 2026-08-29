"""Secure content fetcher.

Implements SAN-001: allowlisted HTTPS fetching with redirect limits, final-domain
validation (base_domain or its www-variant only), DNS-rebinding protection,
private/link-local/metadata address denial, response-size and content-type
limits, and timeouts. Fails closed.

DNS-rebinding protection: every hop resolves its hostname ONCE, validates that
every returned address is public, and then opens the connection against the
pinned IP (with the real hostname preserved for TLS SNI and the Host header), so
an attacker cannot answer a public address at validation time and a private one
at request time. Redirects re-enter the same pinned-resolution path.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

_ALLOWED_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "text/csv",
    "application/json",
    "application/atom+xml",
    "application/stix+json",
    "application/rss+xml",
    "application/xml",
    "text/xml",
}

DEFAULT_MAX_SIZE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 10.0

_ALLOWED_PORTS = {443}
_ALLOWED_CONTENT_ENCODINGS = {"br", "deflate", "gzip", "identity", "zstd"}
_READ_CHUNK_SIZE = 64 * 1024
_MAX_URL_LENGTH = 4096
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)


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


def _host_allowed(host: str, allowlist: set[str]) -> bool:
    """Exact-match host check: only base_domain and www.base_domain are allowed.

    The allowlisted domain is canonicalized by stripping one leading "www.",
    so a source configured as e.g. kaspersky.com also accepts www.kaspersky.com
    (and vice versa) after redirects. Nothing looser — subdomains, lookalikes,
    and any other host are rejected.
    """
    for domain in allowlist:
        base = _canonical_domain(domain).removeprefix("www.")
        if not base:
            continue
        try:
            if ipaddress.ip_address(base):
                return host == base
        except ValueError:
            pass
        if host == base or host == f"www.{base}":
            return True
    return False


def _canonical_domain(value: str) -> str:
    """Return a conservative ASCII DNS name, or an empty string if invalid."""
    if not isinstance(value, str):
        return ""
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "." not in domain or any(ord(character) < 33 for character in domain):
        return ""
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = domain.split(".")
    if not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    return domain


def _header_values(headers: httpx.Headers | object, name: str) -> list[str]:
    """Read a header without collapsing duplicate field lines.

    Real httpx responses expose ``get_list``. The fallback keeps the helper
    usable with the small response doubles in unit tests.
    """
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        return [str(value) for value in getter(name)]
    get_one = getattr(headers, "get", None)
    if not callable(get_one):
        return []
    value = get_one(name)
    return [] if value is None else [str(value)]


def _single_header(headers: httpx.Headers | object, name: str, *, required: bool = False) -> str | None:
    values = _header_values(headers, name)
    if len(values) > 1:
        raise FetchError(f"upstream response has duplicate {name} headers")
    if not values:
        if required:
            raise FetchError(f"upstream response is missing {name}")
        return None
    return values[0].strip()


def _validate_response_framing(headers: httpx.Headers | object, *, max_size: int) -> None:
    content_length = _single_header(headers, "content-length")
    transfer_encoding = _single_header(headers, "transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        raise FetchError("upstream response has ambiguous transfer framing")
    if transfer_encoding is not None and transfer_encoding.lower() != "chunked":
        raise FetchError("upstream response uses an unsupported transfer encoding")
    if content_length is not None:
        if re.fullmatch(r"[0-9]+", content_length) is None or len(content_length) > 19:
            raise FetchError("upstream response Content-Length is malformed")
        declared_size = int(content_length)
        if declared_size > max_size:
            raise OversizedResponseError(f"declared response size exceeds limit {max_size}")

    content_encoding = _single_header(headers, "content-encoding")
    if content_encoding:
        encodings = [part.strip().lower() for part in content_encoding.split(",")]
        if not encodings or any(not part or part not in _ALLOWED_CONTENT_ENCODINGS for part in encodings):
            raise FetchError("upstream response uses an unsupported content encoding")


def _is_global_unicast(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is safe to use as an Internet destination.

    A positive policy is intentionally used here. Maintaining a denylist of
    private ranges misses special-purpose networks such as CGNAT and future
    IANA allocations. ``is_global`` excludes those ranges, while the explicit
    unicast checks close classifications (notably multicast) that Python may
    otherwise also describe as global.

    IPv4-mapped IPv6 addresses are classified according to their embedded IPv4
    destination as well as their IPv6 representation. This prevents mapped
    loopback/private addresses from bypassing the IPv4 policy.
    """
    mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
    destination = mapped or ip
    return (
        ip.is_global
        and destination.is_global
        and not ip.is_multicast
        and not destination.is_multicast
        and not ip.is_unspecified
        and not destination.is_unspecified
    )


def _resolve_pinned(url: str, allowlist: set[str]) -> tuple[str, int, list[str]]:
    """Resolve `url`'s host and return (host, port, pinned_public_ips).

    Validates scheme, allowlist membership, port, and that EVERY resolved
    address is public. Raises a FetchError subclass on any violation.
    """
    if (
        not isinstance(url, str)
        or not url
        or len(url) > _MAX_URL_LENGTH
        or any(ord(character) < 32 for character in url)
    ):
        raise DomainNotAllowedError("URL is malformed or exceeds the supported length")
    try:
        parsed = urlparse(url)
        host = _canonical_domain(parsed.hostname or "")
        port = parsed.port or 443
    except (TypeError, ValueError):
        raise DomainNotAllowedError("URL authority is malformed") from None
    if parsed.scheme != "https":
        raise DomainNotAllowedError(f"non-HTTPS scheme rejected: {parsed.scheme}")
    if parsed.username or parsed.password:
        raise DomainNotAllowedError("credentials in URL are prohibited")
    if not host:
        raise DomainNotAllowedError("URL host is malformed")
    if not _host_allowed(host, allowlist):
        raise DomainNotAllowedError(f"domain {host} not in allowlist")
    if port not in _ALLOWED_PORTS:
        raise DomainNotAllowedError(f"port {port} is not allowed (only {sorted(_ALLOWED_PORTS)})")
    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DomainNotAllowedError(f"DNS resolution failed for {host}") from exc
    try:
        ips = {ipaddress.ip_address(info[4][0]) for info in addrinfos}
    except (IndexError, TypeError, ValueError) as exc:
        raise DeniedAddressError(f"DNS resolution returned an invalid address for {host}") from exc
    for ip in ips:
        if not _is_global_unicast(ip):
            raise DeniedAddressError(f"resolved {ip} is not a global unicast address")
    if not ips:
        raise DomainNotAllowedError(f"no addresses resolved for {host}")
    return host, port, sorted(str(ip) for ip in ips)


def _pinned_url(url: str, host: str, port: int, ip: str) -> str:
    """Rewrite `url`'s host to the pinned IP, preserving path/query."""
    parsed = urlparse(url)
    address = ipaddress.ip_address(ip)
    literal = f"[{address}]" if isinstance(address, ipaddress.IPv6Address) else str(address)
    netloc = literal if port == 443 else f"{literal}:{port}"
    return f"https://{netloc}{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"


class SecureFetcher:
    def __init__(
        self,
        allowlist: set[str] | None = None,
        max_size: int = DEFAULT_MAX_SIZE_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if max_size < 1 or max_redirects < 0 or timeout <= 0:
            raise ValueError("fetch limits and timeout must be positive")
        self._allowlist = {_canonical_domain(domain) for domain in (allowlist or set())}
        self._allowlist.discard("")
        self._max_size = max_size
        self._max_redirects = max_redirects
        self._timeout = timeout

    def add_domain(self, domain: str) -> None:
        normalized = _canonical_domain(domain)
        if not normalized:
            raise ValueError("allowlisted domain is malformed")
        self._allowlist.add(normalized)

    def fetch(self, url: str) -> FetchResult:
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
                    with client.stream(
                        "GET",
                        _pinned_url(current, host, port, ip),
                        headers={
                            "User-Agent": "kingphisher-ingestion/0.1 (+https://internal)",
                            "Host": host if port == 443 else f"{host}:{port}",
                        },
                        extensions={"sni_hostname": host},
                    ) as response:
                        status = response.status_code
                        if response.is_redirect:
                            hops += 1
                            if hops > self._max_redirects:
                                raise FetchError(f"redirect limit exceeded ({self._max_redirects})")
                            location = _single_header(response.headers, "location", required=True)
                            if not location:
                                raise FetchError("redirect without location")
                            try:
                                current = str(httpx.URL(current).join(location))
                            except (httpx.InvalidURL, ValueError):
                                raise FetchError("redirect location is malformed") from None
                            if urlparse(current).scheme != "https":
                                raise DomainNotAllowedError("redirect escaped HTTPS")
                            continue
                        if status >= 400:
                            raise FetchError(f"upstream returned HTTP {status}")
                        content_type_header = _single_header(response.headers, "content-type", required=True)
                        if content_type_header is None:
                            raise FetchError("upstream response is missing content-type")
                        content_type = content_type_header.split(";", 1)[0].strip().lower()
                        if content_type not in _ALLOWED_CONTENT_TYPES:
                            raise UnsupportedContentTypeError(f"content type {content_type!r} not allowed")
                        _validate_response_framing(response.headers, max_size=self._max_size)

                        body = bytearray()
                        for chunk in response.iter_bytes(chunk_size=_READ_CHUNK_SIZE):
                            if len(body) + len(chunk) > self._max_size:
                                raise OversizedResponseError(f"response size exceeds limit {self._max_size}")
                            body.extend(chunk)
                        data = bytes(body)
                        final = current
                        break
                except httpx.HTTPError:
                    raise FetchError("upstream request failed") from None
        return FetchResult(url=url, final_url=final, content=data, content_type=content_type, status_code=status)
