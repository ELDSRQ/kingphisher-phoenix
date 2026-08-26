"""P-3: the console must not pretend to edit externally-managed configuration.

On Azure Container Apps the filesystem is ephemeral and configuration comes
from Terraform and Key Vault. A console write there used to "succeed" and then
vanish on the next restart, which is worse than an explicit refusal because it
looks like it worked. These tests pin the refusal.
"""

from __future__ import annotations

import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
SALT = "0f0e0d0c0b0a09080706050403020100"


def _settings(**overrides: object) -> OperatorApiSettings:
    base: dict[str, object] = {
        "audit_hmac_key": HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "recipient_hash_salt": SALT,
        "console_static_dir": "/nonexistent-console-dir",
    }
    base.update(overrides)
    return OperatorApiSettings(**base)  # type: ignore[arg-type]


def _token(settings: OperatorApiSettings) -> str:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["administrator"]},
    }
    return jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")


def test_config_store_defaults_to_env_file() -> None:
    settings = _settings()
    assert settings.config_store == "env_file"
    assert settings.config_is_managed is False


def test_managed_flag_follows_the_setting() -> None:
    assert _settings(config_store="managed").config_is_managed is True


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("put", "/api/v1/console/config", {"values": {}}),
        ("put", "/api/v1/console/onboarding", {}),
        ("post", "/api/v1/console/restart", {}),
    ],
)
def test_managed_deployment_refuses_local_mutations(method: str, path: str, body: dict[str, object]) -> None:
    settings = _settings(config_store="managed")
    app = create_app(settings)
    with TestClient(app) as client:
        resp = getattr(client, method)(path, json=body, headers={"Authorization": f"Bearer {_token(settings)}"})
    assert resp.status_code == 409, resp.text
    # The refusal has to say what to do instead, or it is just an obstacle.
    assert "terraform" in resp.text.lower() or "containerapp" in resp.text.lower()


def test_env_file_deployment_still_allows_local_mutations() -> None:
    # The disposable local stack must keep working exactly as before.
    settings = _settings(config_store="env_file")
    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.put(
            "/api/v1/console/config",
            json={"values": {}},
            headers={"Authorization": f"Bearer {_token(settings)}"},
        )
    assert resp.status_code != 409
