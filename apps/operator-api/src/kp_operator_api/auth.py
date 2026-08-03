"""OIDC JWT verification and RBAC enforcement.

JWT verification is strict: signature (JWKS or dev shared secret), `iss`,
`aud`, `exp`, and `nbf` all checked. Roles are mapped to kp-authorization
capabilities; endpoints call `require()`/`require_any()` on the resolved
Principal. Unknown roles fail closed (no implicit capability) rather than
granting anything.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return _claims_to_principal(claims)


class OidcIdP:
    """JWKS-based verification using OIDC discovery (PyJWT 2.x PyJWKClient)."""

    def __init__(self, issuer: str, audience: str, *, http_timeout: float = 5.0) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self._jwks_url = f"{self.issuer}/protocol/openid-connect/certs"
        self._client = PyJWKClient(self._jwks_url, cache_jwk_set=True, lifespan=3600, timeout=http_timeout)

    def verify(self, token: str) -> Principal:
        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
            )
        except (httpx.HTTPError, jwt.PyJWTError) as exc:
            raise AuthenticationError("invalid or expired token") from exc
        return _claims_to_principal(claims)


_ROLE_ALIASES: dict[str, Role] = {
    "operator": Role.CAMPAIGN_OPERATOR,
    "campaign-operator": Role.CAMPAIGN_OPERATOR,
    "campaign_operator": Role.CAMPAIGN_OPERATOR,
    "admin": Role.ADMINISTRATOR,
    "administrator": Role.ADMINISTRATOR,
}


def _claims_to_principal(claims: dict[str, Any]) -> Principal:
    subject = claims.get("sub")
    if not subject:
        raise AuthenticationError("token is missing a subject")
    realm_roles = (
        claims.get("realm_access", {}).get("roles", []) if isinstance(claims.get("realm_access"), dict) else []
    )
    roles: set[Role] = set()
    for name in realm_roles:
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
    if not authorization.startswith("Bearer "):
        raise AuthenticationError("missing bearer token")
    principal = idp.verify(authorization.removeprefix("Bearer "))
    user_limiter = request.app.state.user_limiter
    if not user_limiter.allow(principal.subject_id):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
    return principal


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
