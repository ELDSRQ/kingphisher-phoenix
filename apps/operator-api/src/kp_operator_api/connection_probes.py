"""Onboarding connection-test probes (extracted from ``console.py``).

The console's connection test resolves each candidate endpoint through an
egress policy before ever dialing it: only exact, pinned, already-vetted socket
addresses are connected to, DNS is never re-resolved after the policy check,
and loopback/private targets are rejected unless the deployment explicitly
allows development loopback. SMTP and webhook probes follow the same pinning
discipline. This module owns that policy and the probe implementations; the
``console`` router re-exports these names so route handlers and operator tests
that reference ``console._probe_http`` / ``console._PinnedSMTPSSL`` / etc.
behave identically.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import smtplib
import socket
import ssl
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, urlparse

import httpx

# Maximum number of A/AAAA answers a pinned endpoint may return. A hostname
# that resolves to more distinct addresses than this fails closed instead of
# being probed against a subset of its addresses.
_MAX_EGRESS_DNS_ANSWERS = 32

if TYPE_CHECKING:
    pass


def _facade(name: str) -> Any:
    """Resolve one probe name through the ``console`` module object.

    The connection-test suite patches ``kp_operator_api.console._pinned_http_status``
    and ``kp_operator_api.console._connect_pinned`` to exercise the probes without
    real sockets. This module is imported by console (which re-exports its
    names), so resolving those cross-calls through the console module object at
    call time keeps the patches intercepting exactly as they did when the probe
    code lived inside console.py. The import is deferred to avoid an eager
    import cycle: console imports this module, so this module must not import
    console at module load.
    """
    from kp_operator_api import console as _console  # noqa: PLC0415

    return getattr(_console, name)


def _safe_url(raw: str, *, https_only: bool = False) -> str:
    parsed = urlparse(raw)
    schemes = {"https"} if https_only else {"http", "https"}
    if (
        parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port is not None
        and not 1 <= parsed.port <= 65535
    ):
        raise ValueError("invalid endpoint")
    return raw


_ACS_ENDPOINT_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.communication\.azure\.com\Z")


def _validated_acs_endpoint(raw: str) -> str:
    """Return one exact public ACS endpoint; reject lookalikes and URL paths."""
    if not raw or raw != raw.strip():
        raise ValueError("invalid ACS endpoint")
    try:
        parsed = urlparse(_safe_url(raw, https_only=True))
    except ValueError:
        raise ValueError("invalid ACS endpoint") from None
    host = (parsed.hostname or "").lower()
    if (
        _ACS_ENDPOINT_HOST.fullmatch(host) is None
        or (parsed.port or 443) != 443
        or parsed.params
        or parsed.query
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("invalid ACS endpoint")
    return raw


def _microsoft365_probe_url(base: str, mailbox: str, folder: str) -> str:
    safe_base = _safe_url(base.strip(), https_only=True)
    parsed = urlparse(safe_base)
    if parsed.query:
        raise ValueError("Microsoft Graph base URL must not contain a query")
    normalized_mailbox = mailbox.strip()
    normalized_folder = folder.strip()
    if (
        len(normalized_mailbox) > 320
        or re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized_mailbox) is None
        or any(ord(character) < 32 for character in normalized_mailbox)
    ):
        raise ValueError("reported mailbox identifier is malformed")
    if (
        not normalized_folder
        or len(normalized_folder) > 256
        or any(ord(character) < 32 for character in normalized_folder)
    ):
        raise ValueError("reported mailbox folder identifier is malformed")
    endpoint = (
        f"{safe_base.rstrip('/')}/users/{quote(normalized_mailbox, safe='')}"
        f"/mailFolders/{quote(normalized_folder, safe='')}/messages/delta?$top=1&$select=id"
    )
    if len(endpoint) > 4096:
        raise ValueError("Microsoft Graph probe URL is too long")
    return endpoint


class _EndpointPolicyError(ValueError):
    """The endpoint resolves outside the connection-test egress policy."""


class _ResolvedTarget:
    """One already-vetted socket address used without a second DNS lookup."""

    def __init__(self, family: int, sockaddr: tuple[Any, ...], ip: str) -> None:
        self.family = family
        self.sockaddr = sockaddr
        self.ip = ip


def _explicit_loopback_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _resolve_pinned_target(host: str, port: int, *, allow_loopback: bool = False) -> _ResolvedTarget:
    """Resolve once, reject non-public results, and return one pinned address.

    Every answer is checked rather than only the first one. A hostname with a
    public answer plus a private/link-local answer therefore fails closed. The
    returned numeric socket address is used directly by the protocol clients,
    closing the validate-then-resolve DNS-rebinding gap.
    """

    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not answers or len(answers) > _MAX_EGRESS_DNS_ANSWERS:
        raise _EndpointPolicyError("endpoint returned an invalid number of addresses")

    loopback_host = allow_loopback and _explicit_loopback_host(host)
    resolved: list[_ResolvedTarget] = []
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise _EndpointPolicyError("endpoint resolved to an unsupported address family")
        ip_text = str(sockaddr[0]).split("%", 1)[0]
        address = ipaddress.ip_address(ip_text)
        if loopback_host and address.is_loopback:
            pass
        elif not address.is_global or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise _EndpointPolicyError("endpoint must resolve only to public addresses")
        resolved.append(_ResolvedTarget(family, cast(tuple[Any, ...], sockaddr), str(address)))
    return resolved[0]


class _ResolvedSetupAssistEndpoint:
    """A setup-assist URL pinned to one vetted address with its TLS identity."""

    def __init__(self, request_url: str, host_header: str, sni_hostname: str | None) -> None:
        self.request_url = request_url
        self.host_header = host_header
        self.sni_hostname = sni_hostname

    @property
    def extensions(self) -> dict[str, str]:
        return {"sni_hostname": self.sni_hostname} if self.sni_hostname is not None else {}


def _resolve_setup_assist_endpoint(
    base_url: str,
    *,
    settings: Any,
    destination_key: str,
) -> _ResolvedSetupAssistEndpoint:
    """Validate, resolve once, and pin the configured setup-assist service."""
    if (
        not base_url
        or base_url != base_url.strip()
        or len(base_url.encode("utf-8")) > 2048
        or any(character.isspace() or ord(character) == 127 for character in base_url)
    ):
        raise _EndpointPolicyError("setup assistant endpoint is invalid")
    try:
        safe_base = _safe_url(base_url)
        parsed_base = urlparse(safe_base)
    except ValueError:
        raise _EndpointPolicyError("setup assistant endpoint is invalid") from None
    if parsed_base.params or parsed_base.query or parsed_base.fragment:
        raise _EndpointPolicyError("setup assistant endpoint is invalid")
    allow_loopback = _allow_development_loopback(settings, destination_key, safe_base)
    if parsed_base.scheme != "https" and not allow_loopback:
        raise _EndpointPolicyError("setup assistant endpoint requires HTTPS")

    raw_endpoint = safe_base.rstrip("/") + "/setup-assist"
    parsed = urlparse(raw_endpoint)
    host = cast(str, parsed.hostname)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = _facade("_resolve_pinned_target")(host, port, allow_loopback=allow_loopback)
    ip_literal = f"[{target.ip}]" if ":" in target.ip else target.ip
    default_port = 443 if parsed.scheme == "https" else 80
    pinned_netloc = ip_literal if port == default_port else f"{ip_literal}:{port}"
    host_literal = f"[{host}]" if ":" in host else host
    host_header = host_literal if port == default_port else f"{host_literal}:{port}"
    return _ResolvedSetupAssistEndpoint(
        request_url=parsed._replace(netloc=pinned_netloc).geturl(),
        host_header=host_header,
        sni_hostname=host if parsed.scheme == "https" else None,
    )


def _connect_pinned(target: _ResolvedTarget, *, timeout: float) -> socket.socket:
    connection = socket.socket(target.family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(target.sockaddr)
    except Exception:
        connection.close()
        raise
    return connection


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, target: _ResolvedTarget, *, timeout: float) -> None:
        self._pinned_target = target
        super().__init__(host, port, timeout=timeout)

    def connect(self) -> None:
        self.sock = _facade("_connect_pinned")(self._pinned_target, timeout=cast(float, self.timeout))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, target: _ResolvedTarget, *, timeout: float) -> None:
        self._pinned_target = target
        self._tls_context = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._tls_context)

    def connect(self) -> None:
        raw_socket = _facade("_connect_pinned")(self._pinned_target, timeout=cast(float, self.timeout))
        try:
            # Keep the operator-supplied hostname for SNI and certificate
            # validation even though the TCP connection uses the pinned IP.
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _pinned_http_status(raw: str, target: _ResolvedTarget, headers: dict[str, str] | None) -> int:
    parsed = urlparse(raw)
    host = cast(str, parsed.hostname)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection: http.client.HTTPConnection
    if parsed.scheme == "https":
        connection = _PinnedHTTPSConnection(host, port, target, timeout=3.0)
    else:
        connection = _PinnedHTTPConnection(host, port, target, timeout=3.0)
    target_path = parsed.path or "/"
    if parsed.params:
        target_path += f";{parsed.params}"
    if parsed.query:
        target_path += f"?{parsed.query}"
    try:
        connection.request("GET", target_path, headers=headers or {})
        response = connection.getresponse()
        try:
            return response.status
        finally:
            response.close()
    finally:
        connection.close()


#: Categorised connection failures. "It failed" is not actionable; an operator
#: needs to know whether to fix a credential, a firewall rule, a DNS record or
#: a TLS setting, and those need different people and different escalations.
CONNECTION_GUIDANCE: dict[str, str] = {
    "auth": "The endpoint rejected the credentials. Check the username, password, token or API key.",
    "dns": ("The hostname could not be resolved. Check the spelling, and that this host can resolve it."),
    "timeout": (
        "The endpoint did not respond in time. This usually means a firewall or network path is "
        "blocking it, not a wrong password."
    ),
    "refused": ("The connection was refused. The service is probably not listening on that host and port."),
    "tls": (
        "The TLS handshake failed. Check whether the port expects STARTTLS or implicit SSL, and "
        "that the certificate is trusted."
    ),
    "config": "The address is not usable as written. Check the format, scheme and port.",
    "policy": (
        "The endpoint is blocked by outbound safety policy. Use a public address; only the documented "
        "localhost development services are permitted exceptions."
    ),
    "transport": "Credentials are not sent over plaintext connections. Enable TLS and try again.",
    "http_error": (
        "The endpoint answered, but not with a success status. Check the path and whether the service is healthy."
    ),
    "unknown": "The connection failed for an unrecognised reason. Check the service logs for detail.",
}


def _http_failure_kind(exc: Exception) -> str:
    if isinstance(exc, _EndpointPolicyError):
        return "policy"
    if isinstance(exc, ValueError):
        return "config"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, httpx.ConnectTimeout | httpx.ReadTimeout | httpx.PoolTimeout):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        # httpx folds DNS and refusal into ConnectError; the message is the only
        # way to tell an operator which of the two to go and fix.
        text = str(exc).lower()
        if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
            return "dns"
        if "refused" in text:
            return "refused"
        if "certificate" in text or "ssl" in text or "tls" in text:
            return "tls"
        return "unknown"
    if isinstance(exc, httpx.HTTPError):
        return "unknown"
    return "unknown"


def _probe_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    reachable_only: bool = False,
    accept_auth_challenge: bool = False,
    require_2xx: bool = False,
    allow_loopback: bool = False,
) -> tuple[bool, str | None]:
    """Return (ok, error_kind). error_kind is None on success."""
    try:
        safe_url = _safe_url(url)
        parsed = urlparse(safe_url)
        loopback_transport = allow_loopback and _explicit_loopback_host(cast(str, parsed.hostname))
        if headers and parsed.scheme != "https" and not loopback_transport:
            return False, "transport"
        target = _facade("_resolve_pinned_target")(
            cast(str, parsed.hostname),
            parsed.port or (443 if parsed.scheme == "https" else 80),
            allow_loopback=allow_loopback,
        )
        status_code = _facade("_pinned_http_status")(safe_url, target, headers)
    except (http.client.HTTPException, httpx.HTTPError, OSError, ValueError) as exc:
        return False, _http_failure_kind(exc)
    if status_code in {401, 403}:
        if reachable_only and accept_auth_challenge:
            return True, None
        return False, "auth"
    if require_2xx:
        return (True, None) if 200 <= status_code < 300 else (False, "http_error")
    if reachable_only:
        return (status_code < 500, None if status_code < 500 else "http_error")
    if 200 <= status_code < 400:
        return True, None
    return False, "http_error"


def _test_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    reachable_only: bool = False,
    allow_loopback: bool = False,
) -> bool:
    ok, _ = _probe_http(url, headers=headers, reachable_only=reachable_only, allow_loopback=allow_loopback)
    return ok


def _parse_smtp_address(address: str) -> tuple[str, int]:
    try:
        parsed = urlparse(f"//{address}")
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError("invalid SMTP endpoint") from exc
    if (
        not host
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in host)
    ):
        raise ValueError("invalid SMTP endpoint")
    return host, port


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, host: str, port: int, target: _ResolvedTarget, *, timeout: float) -> None:
        self._pinned_target = target
        super().__init__(host, port, timeout=timeout)

    def _get_socket(self, _host: str, _port: int, timeout: float) -> socket.socket:
        return cast(socket.socket, _facade("_connect_pinned")(self._pinned_target, timeout=timeout))


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, host: str, port: int, target: _ResolvedTarget, *, timeout: float) -> None:
        self._pinned_target = target
        self._tls_hostname = host
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())

    def _get_socket(self, _host: str, _port: int, timeout: float) -> socket.socket:
        raw_socket = _facade("_connect_pinned")(self._pinned_target, timeout=timeout)
        try:
            # ``self._host`` remains the original hostname, preserving SNI and
            # certificate hostname verification for implicit TLS.
            return self.context.wrap_socket(raw_socket, server_hostname=self._tls_hostname)
        except Exception:
            raw_socket.close()
            raise


def _probe_smtp(
    address: str,
    use_tls: bool,
    *,
    use_ssl: bool = False,
    username: str | None = None,
    password: str | None = None,
    allow_loopback: bool = False,
) -> tuple[bool, str | None]:
    """Return (ok, error_kind). Distinguishes auth, TLS, DNS and firewall cases."""
    try:
        host, port = _parse_smtp_address(address)
        loopback_transport = allow_loopback and _explicit_loopback_host(host)
        if username and password and not (use_tls or use_ssl or loopback_transport):
            return False, "transport"
        target = _facade("_resolve_pinned_target")(host, port, allow_loopback=allow_loopback)
    except (OSError, ValueError) as exc:
        return False, _http_failure_kind(exc)
    try:
        client = (
            _PinnedSMTPSSL(host, port, target, timeout=3.0) if use_ssl else _PinnedSMTP(host, port, target, timeout=3.0)
        )
        with client:
            if use_tls:
                # The pinned SMTP client retains the original hostname in
                # ``_host``; smtplib passes it to wrap_socket for verification.
                client.starttls(context=ssl.create_default_context())
            if username and password:
                client.login(username, password)
            client.noop()
        return True, None
    except _EndpointPolicyError:
        return False, "policy"
    except socket.gaierror:
        return False, "dns"
    except (TypeError, ValueError):
        return False, "config"
    except smtplib.SMTPAuthenticationError:
        return False, "auth"
    except ssl.SSLError:
        return False, "tls"
    except smtplib.SMTPNotSupportedError:
        # Most often STARTTLS requested on a port that does not offer it.
        return False, "tls"
    except TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except OSError as exc:
        text = str(exc).lower()
        if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
            return False, "dns"
        if "timed out" in text:
            return False, "timeout"
        return False, "unknown"
    except smtplib.SMTPException:
        return False, "unknown"


def _test_smtp(
    address: str,
    use_tls: bool,
    *,
    use_ssl: bool = False,
    username: str | None = None,
    password: str | None = None,
    allow_loopback: bool = False,
) -> bool:
    ok, _ = _probe_smtp(
        address,
        use_tls,
        use_ssl=use_ssl,
        username=username,
        password=password,
        allow_loopback=allow_loopback,
    )
    return ok


def _auth_headers(values: dict[str, str], prefix: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    bearer = values.get(f"{prefix}_BEARER_TOKEN", "")
    api_key = values.get(f"{prefix}_API_KEY", "")
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def _selected_destination(values: dict[str, str], primary_key: str, fallback_key: str | None = None) -> tuple[str, str]:
    primary = values.get(primary_key, "")
    if primary or fallback_key is None:
        return primary_key, primary
    return fallback_key, values.get(fallback_key, "")


def _credentials_for_destination(
    transient: dict[str, str], merged: dict[str, str], *, destination_changed: bool
) -> dict[str, str]:
    # A caller may test a new endpoint before saving it, but credentials loaded
    # from the env file belong to the saved endpoint. Never attach those saved
    # secrets to a different caller-supplied destination. Transient credentials
    # remain usable so a complete new configuration can still be tested.
    return transient if destination_changed else merged


_DEV_LOOPBACK_PORTS: dict[str, frozenset[int]] = {
    "OPERATOR_API_OIDC_ISSUER": frozenset({8443}),
    "MOCK_GRAPH_URL": frozenset({8181}),
    "MOCK_AI_URL": frozenset({8282}),
    "KP_WORKER_MAILPIT_API_URL": frozenset({8025}),
    "KP_WORKER_MAILPIT_SMTP": frozenset({1025}),
    "KP_WORKER_SMTP_ADDRESS": frozenset({1025}),
    "OPERATOR_API_TRAINING_BASE_URL": frozenset({8001}),
}


def _allow_development_loopback(settings: Any, destination_key: str, raw: str, *, smtp: bool = False) -> bool:
    if not settings.dev_auth_mode or destination_key not in _DEV_LOOPBACK_PORTS:
        return False
    try:
        if smtp:
            host, port = _parse_smtp_address(raw)
        else:
            parsed = urlparse(_safe_url(raw))
            host = cast(str, parsed.hostname)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError):
        return False
    return _explicit_loopback_host(host) and port in _DEV_LOOPBACK_PORTS[destination_key]


def _probe_webhook(raw: str) -> tuple[bool, str | None]:
    try:
        parsed = urlparse(_safe_url(raw, https_only=True))
        host = parsed.hostname
        if host is None:
            return False, "config"
        port = parsed.port or 443
        target = _facade("_resolve_pinned_target")(host, port)
        raw_socket = _facade("_connect_pinned")(target, timeout=3.0)
        try:
            tls_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host)
        except Exception:
            raw_socket.close()
            raise
        with tls_socket:
            return True, None
    except (OSError, ValueError, ssl.SSLError) as exc:
        return False, _http_failure_kind(exc)


def _test_webhook(raw: str) -> bool:
    ok, _ = _probe_webhook(raw)
    return ok


def _connection_test_result(
    component: str,
    *,
    ok: bool,
    error_kind: str | None,
    verification_scope: str,
    message: str | None = None,
    reachable_unverified: bool = False,
) -> dict[str, Any]:
    if reachable_unverified:
        return {
            "component": component,
            "ok": False,
            "outcome": "reachable_unverified",
            "save_allowed": True,
            "verification_scope": verification_scope,
            "error_kind": None,
            "message": message or "The endpoint is reachable, but authentication was not verified.",
        }
    if ok:
        return {
            "component": component,
            "ok": True,
            "outcome": "verified",
            "save_allowed": True,
            "verification_scope": verification_scope,
            "error_kind": None,
            "message": message or "Connection successful.",
        }
    kind = error_kind or "unknown"
    return {
        "component": component,
        "ok": False,
        "outcome": "failed",
        "save_allowed": False,
        "verification_scope": verification_scope,
        "error_kind": kind,
        "message": message or CONNECTION_GUIDANCE.get(kind, CONNECTION_GUIDANCE["unknown"]),
    }
