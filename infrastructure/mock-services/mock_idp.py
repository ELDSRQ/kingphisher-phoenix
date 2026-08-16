"""Mock OIDC IdP for local development.

Serves an OIDC discovery document plus a real RS256 JWKS `/certs` endpoint, so
the operator API's `OidcIdP` verifier (PyJWKClient) is fully exercisable on a
laptop without Keycloak. Tokens are signed with a freshly generated RSA key at
startup and carry valid kp-authorization role names.

This is explicitly a *mock*: it holds no credentials, issues no real tokens of
value, and must never be deployed outside the disposable local stack.
"""

from __future__ import annotations

import datetime
import hashlib
import html
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

ISSUER = "http://localhost:8443/realms/kingphisher"
AUDIENCE = "kp-operator-api"
CLIENT_ID = "kp-operator-console"
REDIRECT_URI = "http://localhost:8000/api/v1/console/oidc/callback"
CODE_TTL_SECONDS = 120

_PRINCIPALS: dict[str, tuple[str, list[str]]] = {
    "author": ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ["campaign_author"]),
    "security": ("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ["security_approver"]),
    "privacy": ("cccccccc-cccc-4ccc-8ccc-cccccccccccc", ["privacy_approver"]),
    "operator": ("dddddddd-dddd-4ddd-8ddd-dddddddddddd", ["campaign_operator"]),
    "administrator": ("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ["administrator"]),
}

app = FastAPI(title="mock-idp")


def _b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return jwt.utils.base64url_encode(raw).decode("ascii")


_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_NUMBERS = _PRIVATE_KEY.public_key().public_numbers()
_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Derived JWK fields for the discovery document.
_JWK = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "mock-idp-1",
    "n": _b64url(_PUBLIC_NUMBERS.n),
    "e": _b64url(_PUBLIC_NUMBERS.e),
}


def _issued_and_expiry() -> tuple[int, int]:
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    return now, now + 3600


@dataclass(frozen=True)
class AuthorizationCode:
    client_id: str
    redirect_uri: str
    nonce: str
    code_challenge: str
    subject: str
    roles: list[str]
    expires_at: float


_CODES: dict[str, AuthorizationCode] = {}


def _prune_codes() -> None:
    now = time.monotonic()
    for code in [key for key, value in _CODES.items() if value.expires_at <= now]:
        _CODES.pop(code, None)
    # This is a disposable single-user IdP, but keep attacker-controlled state bounded.
    while len(_CODES) >= 256:
        _CODES.pop(next(iter(_CODES)))


def _pkce_challenge(verifier: str) -> str:
    return jwt.utils.base64url_encode(hashlib.sha256(verifier.encode()).digest()).decode("ascii")


@app.get("/.well-known/openid-configuration")
@app.get("/realms/kingphisher/.well-known/openid-configuration")
def discovery() -> dict[str, str | list[str]]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
        "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
        "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/realms/kingphisher/protocol/openid-connect/certs")
def certs() -> dict[str, list]:
    return {"keys": [_JWK]}


@app.get("/realms/kingphisher/protocol/openid-connect/auth", response_class=HTMLResponse)
def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    nonce: str,
    code_challenge: str,
    code_challenge_method: str,
    principal: str = "",
) -> Response:
    if (
        response_type != "code"
        or client_id != CLIENT_ID
        or redirect_uri != REDIRECT_URI
        or "openid" not in scope.split()
        or code_challenge_method != "S256"
        or len(code_challenge) != 43
        or not state
        or not nonce
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid authorization request")
    if not principal:
        hidden = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        fields = "".join(
            f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value, quote=True)}">'
            for key, value in hidden.items()
        )
        buttons = "".join(
            f'<button type="submit" name="principal" value="{name}">Continue as {name}</button>' for name in _PRINCIPALS
        )
        return HTMLResponse(
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>Local mock sign-in</title>'
            "<body><h1>Local mock identity provider</h1>"
            "<p>Development only. Choose a distinct role-bearing identity.</p>"
            f'<form method="get">{fields}{buttons}</form></body></html>'
        )
    identity = _PRINCIPALS.get(principal)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown mock principal")
    _prune_codes()
    code = secrets.token_urlsafe(32)
    _CODES[code] = AuthorizationCode(
        client_id=client_id,
        redirect_uri=redirect_uri,
        nonce=nonce,
        code_challenge=code_challenge,
        subject=identity[0],
        roles=identity[1],
        expires_at=time.monotonic() + CODE_TTL_SECONDS,
    )
    return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=303)


@app.post("/realms/kingphisher/protocol/openid-connect/token")
async def token(request: Request) -> dict[str, str]:
    form = {key: values[-1] for key, values in parse_qs((await request.body()).decode()).items()}
    code = form.get("code", "")
    authorization = _CODES.pop(code, None)
    if (
        form.get("grant_type") != "authorization_code"
        or authorization is None
        or authorization.expires_at <= time.monotonic()
        or form.get("client_id") != authorization.client_id
        or form.get("redirect_uri") != authorization.redirect_uri
        or not secrets.compare_digest(_pkce_challenge(form.get("code_verifier", "")), authorization.code_challenge)
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or expired authorization code")
    iat, exp = _issued_and_expiry()
    common = {
        "iss": ISSUER,
        "sub": authorization.subject,
        "iat": iat,
        "exp": exp,
        "realm_access": {"roles": authorization.roles},
    }
    access_token = jwt.encode(
        {
            **common,
            "aud": AUDIENCE,
        },
        _PEM,
        algorithm="RS256",
        headers={"kid": "mock-idp-1"},
    )
    id_token = jwt.encode(
        {**common, "aud": CLIENT_ID, "nonce": authorization.nonce},
        _PEM,
        algorithm="RS256",
        headers={"kid": "mock-idp-1"},
    )
    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": "3600",
    }
