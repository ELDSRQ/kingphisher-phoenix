"""P-3: the console must not pretend to edit externally-managed configuration.

On Azure Container Apps the filesystem is ephemeral and configuration comes
from Terraform and Key Vault. A console write there used to "succeed" and then
vanish on the next restart, which is worse than an explicit refusal because it
looks like it worked. These tests pin the refusal.
"""

from __future__ import annotations

import traceback
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from pydantic import ValidationError

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


def test_managed_acs_validation_does_not_reflect_nested_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "token=private https://provider.invalid/body /private/repo actor=someone Traceback"

    def fail_signing_key(_settings: OperatorApiSettings) -> bytes:
        raise RuntimeError(secret)

    monkeypatch.setattr(OperatorApiSettings, "require_acs_receipt_signing_key", fail_signing_key)

    with pytest.raises(ValidationError) as caught:
        _settings(
            oidc_mode="oidc",
            approval_policy="enforce",
            config_store="managed",
        )

    message = str(caught.value)
    assert "managed ACS receipt ingress is not securely configured" in message
    assert "verify the signing key and Event Grid identifiers" in message
    assert not any(
        fragment in message + caplog.text for fragment in (secret, "provider.invalid", "/private/repo", "Traceback")
    )


def test_operator_validation_error_and_traceback_hide_secret_inputs() -> None:
    secret = "SECRET_OPERATOR_TOKEN"

    with pytest.raises(ValidationError) as caught:
        _settings(
            oidc_mode="oidc",
            approval_policy="single-admin",
            domain_verification_key=secret,
        )

    rendered = f"{caught.value!s}\n{caught.value!r}\n{''.join(traceback.format_exception(caught.value))}"
    assert "OPERATOR_API_APPROVAL_POLICY=single-admin is not permitted" in rendered
    assert secret not in rendered
    assert "input_value=" not in rendered


@pytest.mark.parametrize(
    ("field", "method"),
    [
        ("audit_hmac_key", "require_secret_key"),
        ("roe_signing_key", "require_roe_signing_key"),
        ("domain_verification_key", "require_domain_verification_key"),
        ("ciphertext_kek", "require_cipher_kek"),
        ("recipient_hash_salt", "require_recipient_hash_salt"),
        ("tracking_token_hmac_key", "require_tracking_token_hmac_key"),
        ("training_token_hmac_key", "require_training_token_hmac_key"),
    ],
)
def test_operator_secret_parsers_suppress_nested_exception_chains(field: str, method: str) -> None:
    secret = "SECRET_NOT_HEX/private/key.pem"
    settings = _settings(**{field: secret})

    with pytest.raises(RuntimeError) as caught:
        getattr(settings, method)()

    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert "private/key.pem" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_operator_ciphertext_keyring_supports_bounded_decrypt_only_rotation_keys() -> None:
    settings = _settings(
        ciphertext_key_id="active-2",
        ciphertext_prior_keys=f"retired-1={'11' * 32},retired_0={'22' * 32}",
    )

    key_id, active_key, prior_keys = settings.require_cipher_keyring()

    assert key_id == "active-2"
    assert active_key == bytes.fromhex(KEK)
    assert prior_keys == {"retired-1": b"\x11" * 32, "retired_0": b'"' * 32}


@pytest.mark.parametrize(
    "overrides",
    [
        {"ciphertext_key_id": "invalid.key/id"},
        {"ciphertext_prior_keys": "missing-separator"},
        {"ciphertext_prior_keys": "primary=" + "11" * 32},
        {"ciphertext_prior_keys": "old=" + KEK},
        {"ciphertext_prior_keys": ",".join(f"old{index}={'11' * 32}" for index in range(5))},
    ],
)
def test_operator_ciphertext_keyring_rejects_invalid_rotation_configuration_without_echo(
    overrides: dict[str, str],
) -> None:
    settings = _settings(**overrides)

    with pytest.raises(RuntimeError) as caught:
        settings.require_cipher_keyring()

    rendered = "".join(traceback.format_exception(caught.value))
    assert "invalid.key/id" not in rendered
    assert KEK not in rendered
    assert caught.value.__cause__ is None


def test_operator_ciphertext_prior_key_parser_redacts_malformed_key_material() -> None:
    secret = "SECRET_NOT_HEX/private/key.pem"
    settings = _settings(ciphertext_prior_keys=f"old={secret}")

    with pytest.raises(RuntimeError) as caught:
        settings.require_cipher_keyring()

    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert "private/key.pem" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
