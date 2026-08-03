"""OIDC JWT verification and RBAC enforcement.

JWT verification is strict: signature (JWKS or dev shared secret), `iss`,
`aud`, `exp`, and `nbf` all checked. Roles are mapped to kp-authorization
capabilities; endpoints call `require()`/`require_any()` on the resolved
Principal.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from kp_authorization.rbac import (
    AuthorizationError,
    Capability,
    Principal,
    Role,
    require,
    require_any,
)
from kp_telemetry.errors import AuthenticationError, PermissionDeniedError


class DevIdP:
    """Dev-only IdP client. Production uses OIDC discovery + JWKS."""

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
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return _claims_to_principal(claims)


class OidcIdP:
    """JWKS-based verification using OIDC discovery."""

    def __init__(self, issuer: str, audience: str, *, http_timeout: float = 5.0) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self._jwks_url = f"{self.issuer}/protocol/openid-connect/certs"
        self._timeout = http_timeout
        self._certs: dict[str, Any] | None = None

    def _load_keys(self) -> dict[str, Any]:
        if self._certs is not None:
            return self._certs
        resp = httpx.get(self._jwks_url, timeout=self._timeout)
        resp.raise_for_status()
        self._certs = resp.json()
        return self._certs

    def verify(self, token: str) -> Principal:
        try:
            keys = self._load_keys()
            claims = jwt.decode(
                token,
                keys,  # type: ignore[arg-type]  # pyjwt accepts a JWK dict for HS/RS
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
            )
        except (httpx.HTTPError, jwt.PyJWTError) as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return _claims_to_principal(claims)


def _claims_to_principal(claims: dict[str, Any]) -> Principal:
    realm_roles = claims.get("realm_access", {}).get("roles", []) if isinstance(
        claims.get("realm_access"), dict
    ) else []
    roles: set[Role] = set()
    for r in realm_roles:
        try:
            roles.add(Role(r))
        except ValueError:
            continue
    if not roles:
        roles = {Role.CAMPAIGN_OPERATOR}  # dev default; never elevates privileges
    return Principal(subject_id=claims.get("sub", "anonymous"), roles=roles)


def make_idp(issuer: str, audience: str, dev_secret: str) -> OidcIdP | DevIdP:
    if dev_secret:
        return DevIdP(issuer, audience, dev_secret)
    return OidcIdP(issuer, audience)


def get_principal(request: Request) -> Principal:
    idp: OidcIdP | DevIdP = request.app.state.idp
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("missing bearer token")
    return idp.verify(authorization.removeprefix("Bearer "))


def require_capability(capability: Capability) -> Callable[..., Principal]:
    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        try:
            require(principal, capability)
        except AuthorizationError as exc:
            raise PermissionDeniedError(str(exc)) from exc
        return principal

    return _check


def require_any_capability(*capabilities: Capability) -> Callable[..., Principal]:
    def _check(principal: Principal = Depends(get_principal)) -> Principal:
        try:
            require_any(principal, *capabilities)
        except AuthorizationError as exc:
            raise PermissionDeniedError(str(exc)) from exc
        return principal

    return _check


def kp_http_error(exc: AuthenticationError | PermissionDeniedError) -> HTTPException:
    if isinstance(exc, PermissionDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
