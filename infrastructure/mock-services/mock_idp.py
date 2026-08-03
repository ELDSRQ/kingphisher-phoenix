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
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request

ISSUER = "http://localhost:8443/realms/kingphisher"
AUDIENCE = "kp-operator-api"

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


@app.get("/.well-known/openid-configuration")
def discovery() -> dict[str, str | list[str]]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
        "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
        "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/realms/kingphisher/protocol/openid-connect/certs")
def certs() -> dict[str, list]:
    return {"keys": [_JWK]}


@app.post("/realms/kingphisher/protocol/openid-connect/token")
async def token(request: Request) -> dict[str, str]:
    body = await request.body()
    nonce = hashlib.sha256(body).hexdigest()[:16]
    iat, exp = _issued_and_expiry()
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": str(uuid4()),
            "iat": iat,
            "exp": exp,
            "realm_access": {"roles": ["campaign_operator", "administrator"]},
            "nonce": nonce,
        },
        _PEM,
        algorithm="RS256",
        headers={"kid": "mock-idp-1"},
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": "3600",
        "refresh_token": "",
    }
