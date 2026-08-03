"""Mock OIDC IdP for local development.

Serves a minimal OIDC discovery document plus a JWKS-compatible `/certs`
endpoint and a fixed `sub` claim, so the operator API's `OidcIdP` verifier has
something to call. Local dev generally uses the HS256 `DevIdP` path (driven by
`OPERATOR_API_AUDIT_HMAC_KEY`), but this mock keeps the full OIDC flow testable
on a laptop without standing up Keycloak.

This is explicitly a *mock*: it holds no credentials, issues no real tokens of
value, and must never be deployed outside the disposable local stack.
"""

from __future__ import annotations

import datetime
import hashlib
from uuid import uuid4

import jwt
from fastapi import FastAPI, Request

ISSUER = "http://localhost:8443/realms/kingphisher"
AUDIENCE = "kp-operator-api"
AUDIENCE_DEV = "kingphisher-operator"

app = FastAPI(title="mock-idp")


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
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
    }


@app.get("/realms/kingphisher/protocol/openid-connect/certs")
def certs() -> dict[str, list]:
    return {"keys": []}


@app.post("/realms/kingphisher/protocol/openid-connect/token")
async def token(request: Request) -> dict[str, str]:
    body = await request.body()
    nonce = hashlib.sha256(body).hexdigest()[:16]
    iat, exp = _issued_and_expiry()
    dev_secret = "dev-secret"  # noqa: S105 - disposable local mock, not a real credential
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": [AUDIENCE, AUDIENCE_DEV],
            "sub": str(uuid4()),
            "iat": iat,
            "exp": exp,
            "realm_access": {"roles": ["operator", "campaign-operator", "administrator"]},
            "nonce": nonce,
        },
        dev_secret,
        algorithm="HS256",
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": "3600",
        "refresh_token": "",
    }
