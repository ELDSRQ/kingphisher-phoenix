"""Protocol tests for the disposable local OIDC provider."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import jwt
import mock_idp
from fastapi.testclient import TestClient


def _authorization(client: TestClient, *, principal: str = "security", verifier: str = "v" * 48):
    challenge = mock_idp._pkce_challenge(verifier)
    params = {
        "response_type": "code",
        "client_id": mock_idp.CLIENT_ID,
        "redirect_uri": mock_idp.REDIRECT_URI,
        "scope": "openid profile",
        "state": "expected-state",
        "nonce": "expected-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "principal": principal,
    }
    response = client.get("/realms/kingphisher/protocol/openid-connect/auth", params=params, follow_redirects=False)
    return response, verifier


def test_realm_discovery_advertises_pkce() -> None:
    with TestClient(mock_idp.app) as client:
        response = client.get("/realms/kingphisher/.well-known/openid-configuration")
    assert response.status_code == 200
    assert response.json()["issuer"] == mock_idp.ISSUER
    assert response.json()["code_challenge_methods_supported"] == ["S256"]


def test_authorization_screen_offers_distinct_approvers() -> None:
    challenge = mock_idp._pkce_challenge("v" * 48)
    with TestClient(mock_idp.app) as client:
        response = client.get(
            "/realms/kingphisher/protocol/openid-connect/auth",
            params={
                "response_type": "code",
                "client_id": mock_idp.CLIENT_ID,
                "redirect_uri": mock_idp.REDIRECT_URI,
                "scope": "openid",
                "state": "state",
                "nonce": "nonce",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
    assert response.status_code == 200
    assert "Continue as security" in response.text
    assert "Continue as privacy" in response.text


def test_code_exchange_issues_role_access_token_and_nonce_id_token() -> None:
    with TestClient(mock_idp.app) as client:
        authorization, verifier = _authorization(client)
        assert authorization.status_code == 303
        query = parse_qs(urlparse(authorization.headers["location"]).query)
        assert query["state"] == ["expected-state"]
        response = client.post(
            "/realms/kingphisher/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "client_id": mock_idp.CLIENT_ID,
                "redirect_uri": mock_idp.REDIRECT_URI,
                "code": query["code"][0],
                "code_verifier": verifier,
            },
        )
    assert response.status_code == 200
    tokens = response.json()
    public_key = jwt.PyJWK.from_dict(mock_idp._JWK).key
    access = jwt.decode(tokens["access_token"], public_key, algorithms=["RS256"], audience=mock_idp.AUDIENCE)
    identity = jwt.decode(tokens["id_token"], public_key, algorithms=["RS256"], audience=mock_idp.CLIENT_ID)
    assert access["realm_access"]["roles"] == ["security_approver"]
    assert identity["nonce"] == "expected-nonce"
    assert identity["sub"] == access["sub"]


def test_code_is_one_time_and_pkce_is_enforced() -> None:
    with TestClient(mock_idp.app) as client:
        authorization, _verifier = _authorization(client, principal="privacy")
        code = parse_qs(urlparse(authorization.headers["location"]).query)["code"][0]
        form = {
            "grant_type": "authorization_code",
            "client_id": mock_idp.CLIENT_ID,
            "redirect_uri": mock_idp.REDIRECT_URI,
            "code": code,
            "code_verifier": "incorrect-verifier",
        }
        assert client.post("/realms/kingphisher/protocol/openid-connect/token", data=form).status_code == 400
        # Failed verification consumes the code, preventing online verifier guessing.
        form["code_verifier"] = "v" * 48
        assert client.post("/realms/kingphisher/protocol/openid-connect/token", data=form).status_code == 400
