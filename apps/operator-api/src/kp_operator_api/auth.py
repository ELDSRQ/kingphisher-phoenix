"""OIDC JWT verification and RBAC enforcement.

JWT verification is strict: signature (JWKS or dev shared secret), `iss`,
`aud`, `exp`, and `nbf` all checked. Roles are mapped to kp-authorization
capabilities; endpoints call `require()`/`require_any()` on the resolved
Principal. Unknown roles fail closed (no implicit capability) rather than
granting anything. Entra object IDs (`oid`) are preferred as stable principal
IDs; UUID `sub` claims remain a compatibility fallback for the dev IdP and
existing Keycloak deployments.
"""

from __future__ import annotations

import ipaddress
import socket
import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass
from threading import Lock
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient
from kp_authorization.rbac import (
    AuthorizationError,
    Capability,
    Principal,
    Role,
    require,
    require_any,
)
from kp_telemetry.errors import AuthenticationError, PermissionDeniedError

from kp_operator_api.oidc_provider import (
    MAX_OIDC_DISCOVERY_BYTES,
    MAX_OIDC_JWKS_BYTES,
    OidcProviderResponseError,
    bounded_json,
)

_MAX_OIDC_URL_BYTES = 2048
_MAX_OIDC_ALLOWED_ORIGINS = 8
_MAX_OIDC_DNS_ANSWERS = 32
_LOCAL_OIDC_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class OidcEndpointPolicyError(ValueError):
    """A content-free failure at the identity-provider egress boundary."""


@dataclass(frozen=True, slots=True)
class ResolvedOidcEndpoint:
    """One validated endpoint whose request URL is pinned to a vetted address."""

    url: str
    request_url: str
    host_header: str
    sni_hostname: str | None

    @property
    def extensions(self) -> dict[str, str]:
        return {"sni_hostname": self.sni_hostname} if self.sni_hostname is not None else {}


@dataclass(frozen=True, slots=True)
class _OidcUrlParts:
    scheme: str
    host: str
    port: int
    path: str
    query: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port


def _canonical_oidc_host(value: str) -> str:
    if "%" in value:
        raise OidcEndpointPolicyError("identity provider endpoint host is invalid")
    candidate = value.rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        raise OidcEndpointPolicyError("identity provider endpoint host is invalid")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            encoded = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            raise OidcEndpointPolicyError("identity provider endpoint host is invalid") from None
        labels = encoded.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise OidcEndpointPolicyError("identity provider endpoint host is invalid") from None
        return encoded


def _parse_oidc_url(url: str, *, endpoint_name: str, issuer: bool = False) -> _OidcUrlParts:
    error = f"identity provider {endpoint_name} is invalid"
    if (
        not isinstance(url, str)
        or not url
        or len(url.encode("utf-8")) > _MAX_OIDC_URL_BYTES
        or url != url.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in url)
    ):
        raise OidcEndpointPolicyError(error)
    try:
        parsed = urlsplit(url)
        port = parsed.port
        host = _canonical_oidc_host(parsed.hostname or "")
    except (TypeError, ValueError, OidcEndpointPolicyError):
        raise OidcEndpointPolicyError(error) from None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (issuer and parsed.query)
        or (parsed.path and not parsed.path.startswith("/"))
    ):
        raise OidcEndpointPolicyError(error)
    return _OidcUrlParts(
        scheme=parsed.scheme,
        host=host,
        port=port or (443 if parsed.scheme == "https" else 80),
        path=parsed.path or "/",
        query=parsed.query,
    )


def _validated_allowed_origins(values: Collection[str]) -> frozenset[tuple[str, str, int]]:
    if len(values) > _MAX_OIDC_ALLOWED_ORIGINS:
        raise OidcEndpointPolicyError("identity provider endpoint allowlist is invalid")
    origins: set[tuple[str, str, int]] = set()
    for value in values:
        parts = _parse_oidc_url(value, endpoint_name="endpoint allowlist origin")
        if parts.scheme != "https" or parts.path != "/" or parts.query:
            raise OidcEndpointPolicyError("identity provider endpoint allowlist is invalid")
        origins.add(parts.origin)
    return frozenset(origins)


def validate_oidc_endpoint(
    url: str,
    *,
    issuer: str,
    endpoint_name: str,
    allowed_origins: Collection[str] = (),
) -> str:
    """Validate endpoint syntax and bind it to the issuer's exact origin.

    Callers that must support a provider with split endpoint hosts may pass a
    small, explicit collection of origin-only HTTPS URLs. DNS safety is still
    enforced later by :func:`resolve_oidc_endpoint` immediately before use.
    """

    issuer_parts = _parse_oidc_url(issuer, endpoint_name="issuer", issuer=True)
    endpoint_parts = _parse_oidc_url(url, endpoint_name=endpoint_name)
    local_http = issuer_parts.scheme == "http" and issuer_parts.host in _LOCAL_OIDC_HTTP_HOSTS
    if issuer_parts.scheme == "http" and not local_http:
        raise OidcEndpointPolicyError("identity provider issuer is invalid")
    if endpoint_parts.scheme == "http" and not (local_http and endpoint_parts.origin == issuer_parts.origin):
        raise OidcEndpointPolicyError(f"identity provider {endpoint_name} is invalid")
    accepted_origins = {issuer_parts.origin, *_validated_allowed_origins(allowed_origins)}
    if endpoint_parts.origin not in accepted_origins:
        raise OidcEndpointPolicyError(f"identity provider {endpoint_name} is not issuer-bound")
    return url


def _is_global_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    destination = mapped or address
    return (
        address.is_global
        and destination.is_global
        and not address.is_multicast
        and not destination.is_multicast
        and not address.is_unspecified
        and not destination.is_unspecified
    )


def resolve_oidc_endpoint(
    url: str,
    *,
    issuer: str,
    endpoint_name: str,
    allowed_origins: Collection[str] = (),
) -> ResolvedOidcEndpoint:
    """Resolve once, reject every unsafe answer, and return a pinned request."""

    validate_oidc_endpoint(
        url,
        issuer=issuer,
        endpoint_name=endpoint_name,
        allowed_origins=allowed_origins,
    )
    parts = _parse_oidc_url(url, endpoint_name=endpoint_name)
    local_http = parts.scheme == "http" and parts.host in _LOCAL_OIDC_HTTP_HOSTS
    try:
        answers = socket.getaddrinfo(
            parts.host,
            parts.port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError:
        raise OidcEndpointPolicyError(f"identity provider {endpoint_name} could not be resolved") from None
    if not answers or len(answers) > _MAX_OIDC_DNS_ANSWERS:
        raise OidcEndpointPolicyError(f"identity provider {endpoint_name} returned invalid DNS results")
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise OidcEndpointPolicyError(f"identity provider {endpoint_name} returned invalid DNS results")
        try:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except (IndexError, TypeError, ValueError):
            raise OidcEndpointPolicyError(f"identity provider {endpoint_name} returned invalid DNS results") from None
        if local_http:
            if not address.is_loopback:
                raise OidcEndpointPolicyError(
                    f"identity provider {endpoint_name} returned a non-loopback development address"
                )
        elif not _is_global_unicast(address):
            raise OidcEndpointPolicyError(f"identity provider {endpoint_name} must resolve only to public addresses")
        addresses.add(address)
    if not addresses or len(addresses) > _MAX_OIDC_DNS_ANSWERS:
        raise OidcEndpointPolicyError(f"identity provider {endpoint_name} returned invalid DNS results")

    address = sorted(addresses, key=lambda item: (item.version, int(item)))[0]
    literal = f"[{address}]" if isinstance(address, ipaddress.IPv6Address) else str(address)
    default_port = 443 if parts.scheme == "https" else 80
    pinned_netloc = literal if parts.port == default_port else f"{literal}:{parts.port}"
    host_literal = f"[{parts.host}]" if ":" in parts.host else parts.host
    host_header = host_literal if parts.port == default_port else f"{host_literal}:{parts.port}"
    return ResolvedOidcEndpoint(
        url=url,
        request_url=urlunsplit((parts.scheme, pinned_netloc, parts.path, parts.query, "")),
        host_header=host_header,
        sni_hostname=parts.host if parts.scheme == "https" else None,
    )


class BoundedPyJWKClient(PyJWKClient):
    """PyJWT's normal cache/refresh behavior with a bounded HTTP fetch."""

    def __init__(
        self,
        uri: str,
        *,
        issuer: str | None = None,
        allowed_origins: Collection[str] = (),
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: Any | None = None,
    ) -> None:
        endpoint_parts = _parse_oidc_url(uri, endpoint_name="JWKS endpoint")
        host_literal = f"[{endpoint_parts.host}]" if ":" in endpoint_parts.host else endpoint_parts.host
        default_port = 443 if endpoint_parts.scheme == "https" else 80
        inferred_issuer = (
            f"{endpoint_parts.scheme}://{host_literal}"
            f"{f':{endpoint_parts.port}' if endpoint_parts.port != default_port else ''}"
        )
        self._issuer = issuer or inferred_issuer
        self._allowed_origins = tuple(allowed_origins)
        validate_oidc_endpoint(
            uri,
            issuer=self._issuer,
            endpoint_name="JWKS endpoint",
            allowed_origins=self._allowed_origins,
        )
        super().__init__(
            uri,
            cache_keys=cache_keys,
            max_cached_keys=max_cached_keys,
            cache_jwk_set=cache_jwk_set,
            lifespan=lifespan,
            headers=headers,
            timeout=timeout,
            ssl_context=ssl_context,
        )

    def fetch_data(self) -> Any:
        try:
            endpoint = resolve_oidc_endpoint(
                self.uri,
                issuer=self._issuer,
                endpoint_name="JWKS endpoint",
                allowed_origins=self._allowed_origins,
            )
            headers = {**(self.headers or {}), "Host": endpoint.host_header}
            with (
                httpx.Client(
                    timeout=self.timeout,
                    follow_redirects=False,
                    headers=headers,
                    verify=self.ssl_context or True,
                    trust_env=False,
                    http2=False,
                ) as client,
                client.stream(
                    "GET",
                    endpoint.request_url,
                    extensions=endpoint.extensions,
                ) as response,
            ):
                if response.is_redirect:
                    raise OidcProviderResponseError("identity provider JWKS endpoint redirected")
                response.raise_for_status()
                jwk_set = bounded_json(response, max_bytes=MAX_OIDC_JWKS_BYTES)
        except (httpx.HTTPError, OidcEndpointPolicyError, OidcProviderResponseError) as exc:
            raise jwt.PyJWKClientConnectionError("identity provider JWKS fetch failed") from exc
        if not isinstance(jwk_set, dict):
            raise jwt.PyJWKClientError("identity provider JWKS response is invalid")
        # Match PyJWKClient: cache only a successful fetch so a transient or
        # hostile refresh cannot erase a still-valid cached key set.
        if self.jwk_set_cache is not None:
            # PyJWT's runtime fetch_data stores the raw mapping here even
            # though its public type annotation says PyJWKSet.
            self.jwk_set_cache.put(jwk_set)  # type: ignore[arg-type]
        return jwk_set


class DevIdP:
    """Dev-only IdP client (shared-secret HS256). Production uses OIDC + JWKS.

    The dev secret is the dedicated console JWT secret, never the audit HMAC
    key, so a console token cannot forge the audit-chain signature.
    """

    def __init__(self, issuer: str, audience: str, dev_secret: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self.dev_secret = dev_secret

    def verify(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self.dev_secret,
                algorithms=["HS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return _claims_to_principal(claims)


class OidcIdP:
    """Provider-neutral JWT verification using validated OIDC discovery.

    Discovery is lazy so a temporarily unavailable provider does not prevent
    the API process from starting. Its result and the JWKS set are cached, but
    every token still receives full signature, issuer, audience and lifetime
    validation.
    """

    def __init__(self, issuer: str, audience: str, *, http_timeout: float = 5.0) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self._http_timeout = http_timeout
        self._discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            validate_oidc_endpoint(self.issuer, issuer=self.issuer, endpoint_name="issuer")
        except OidcEndpointPolicyError as exc:
            raise AuthenticationError("identity provider issuer is invalid") from exc
        self._jwk_client: PyJWKClient | None = None
        self._discovery_lock = Lock()

    def _discover_jwk_client(self) -> PyJWKClient:
        if self._jwk_client is not None:
            return self._jwk_client
        with self._discovery_lock:
            if self._jwk_client is not None:
                return self._jwk_client
            try:
                endpoint = resolve_oidc_endpoint(
                    self._discovery_url,
                    issuer=self.issuer,
                    endpoint_name="discovery endpoint",
                )
                with (
                    httpx.Client(
                        timeout=self._http_timeout,
                        follow_redirects=False,
                        headers={"Host": endpoint.host_header},
                        trust_env=False,
                        http2=False,
                    ) as client,
                    client.stream(
                        "GET",
                        endpoint.request_url,
                        extensions=endpoint.extensions,
                    ) as response,
                ):
                    if response.is_redirect:
                        raise OidcProviderResponseError("identity provider discovery redirected")
                    response.raise_for_status()
                    metadata = bounded_json(response, max_bytes=MAX_OIDC_DISCOVERY_BYTES)
            except (httpx.HTTPError, OidcEndpointPolicyError, OidcProviderResponseError) as exc:
                raise AuthenticationError("identity provider discovery failed") from exc
            if not isinstance(metadata, dict):
                raise AuthenticationError("identity provider discovery returned invalid metadata")
            metadata_issuer = metadata.get("issuer")
            if not isinstance(metadata_issuer, str) or metadata_issuer.rstrip("/") != self.issuer:
                raise AuthenticationError("identity provider discovery returned an invalid issuer")
            jwks_uri = metadata.get("jwks_uri")
            if not isinstance(jwks_uri, str):
                raise AuthenticationError("identity provider discovery has no JWKS endpoint")
            try:
                validated_jwks_uri = validate_oidc_endpoint(
                    jwks_uri,
                    issuer=self.issuer,
                    endpoint_name="JWKS endpoint",
                )
                self._jwk_client = BoundedPyJWKClient(
                    validated_jwks_uri,
                    issuer=self.issuer,
                    cache_jwk_set=True,
                    lifespan=3600,
                    timeout=self._http_timeout,
                )
            except OidcEndpointPolicyError as exc:
                raise AuthenticationError("identity provider discovery returned an invalid JWKS endpoint") from exc
            return self._jwk_client

    def verify(self, token: str) -> Principal:
        return _claims_to_principal(self.verify_claims(token))

    def verify_claims(self, token: str, *, audience: str | None = None) -> dict[str, Any]:
        try:
            signing_key = self._discover_jwk_client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience or self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except (httpx.HTTPError, jwt.PyJWTError) as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return claims


_ROLE_ALIASES: dict[str, Role] = {
    "operator": Role.CAMPAIGN_OPERATOR,
    "campaign-operator": Role.CAMPAIGN_OPERATOR,
    "campaign_operator": Role.CAMPAIGN_OPERATOR,
    "admin": Role.ADMINISTRATOR,
    "administrator": Role.ADMINISTRATOR,
}


def _claims_to_principal(claims: dict[str, Any]) -> Principal:
    # Entra `sub` is pairwise and opaque. Its `oid` is the stable UUID used by
    # directory and audit records. UUID `sub` remains the deliberate fallback
    # for the local dev IdP and Keycloak, which do not emit an Entra `oid`.
    principal_claim = "oid" if "oid" in claims else "sub"
    subject = claims.get(principal_claim)
    if subject is None:
        raise AuthenticationError("token is missing a stable principal identifier")
    try:
        uuid.UUID(str(subject))
    except (AttributeError, ValueError) as exc:
        raise PermissionDeniedError("token principal identifier must be a UUID") from exc
    role_names: list[str] = []
    entra_roles = claims.get("roles")
    if isinstance(entra_roles, list):
        role_names.extend(name for name in entra_roles if isinstance(name, str))
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        realm_roles = realm_access.get("roles")
        if isinstance(realm_roles, list):
            role_names.extend(name for name in realm_roles if isinstance(name, str))
    roles: set[Role] = set()
    for name in role_names:
        role = _ROLE_ALIASES.get(name)
        if role is None:
            try:
                role = Role(name)
            except ValueError:
                continue
        roles.add(role)
    # Fail closed: unrecognized or absent roles grant no capability.
    return Principal(subject_id=str(subject), roles=roles)


def make_idp(issuer: str, audience: str, *, mode: str, dev_secret: str) -> OidcIdP | DevIdP:
    if mode == "oidc":
        return OidcIdP(issuer, audience)
    if mode == "dev":
        return DevIdP(issuer, audience, dev_secret)
    raise ValueError(f"unsupported OIDC mode: {mode!r}")


def get_principal(request: Request) -> Principal:
    idp: OidcIdP | DevIdP = request.app.state.idp
    authorization = request.headers.get("Authorization", "")
    token = (
        authorization.removeprefix("Bearer ")
        if authorization.startswith("Bearer ")
        else request.cookies.get("kp_oidc_session", "")
    )
    if not token:
        raise AuthenticationError("missing bearer token")
    principal = idp.verify(token)
    user_limiter = request.app.state.user_limiter
    if not user_limiter.allow(principal.subject_id):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
    return principal


def require_capability(capability: Capability) -> Callable[..., Principal]:
    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        try:
            require(principal, capability)
        except AuthorizationError as exc:
            raise PermissionDeniedError("required capability is not assigned") from exc
        return principal

    return _check


def require_any_capability(*capabilities: Capability) -> Callable[..., Principal]:
    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        try:
            require_any(principal, *capabilities)
        except AuthorizationError as exc:
            raise PermissionDeniedError("none of the required capabilities are assigned") from exc
        return principal

    return _check
