"""OIDC JWT verification and RBAC enforcement.

JWT verification is strict: signature (JWKS or dev shared secret), `iss`,
`aud`, `exp`, and `nbf` all checked. Roles are mapped to kp-authorization
capabilities; endpoints call `require()`/`require_any()` on the resolved
Principal. Unknown roles fail closed (no implicit capability) rather than
granting anything. Subjects must be parseable UUIDs because audit/DB fields
are UUID-typed; a non-UUID `sub` is rejected at this identity boundary.
"""

from __future__ import annotations

import uuid
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
        return _claims_to_principal(self.verify_claims(token))

    def verify_claims(self, token: str, *, audience: str | None = None) -> dict[str, Any]:
        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience or self.audience,
                issuer=self.issuer,
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
    subject = claims.get("sub")
    if subject is None:
        raise AuthenticationError("token is missing a subject")
    # HIGH-02 residual: routers feed `principal.principal_id` straight into
    # `uuid.UUID(...)` for UUID-typed audit/DB columns, so a provider whose
    # `sub` is not a UUID (e.g. `auth0|123`) surfaced there as ValueError -> 500.
    # Fail closed here with a 403-class rejection instead. Console tokens carry
    # the stable CONSOLE_OPERATOR_UUID and Entra object IDs are UUIDs, so
    # intended deployments are unaffected.
    try:
        uuid.UUID(str(subject))
    except ValueError as exc:
        raise PermissionDeniedError(
            f"token 'sub' claim {subject!r} is not a valid UUID; principal IDs must be UUIDs"
        ) from exc
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
