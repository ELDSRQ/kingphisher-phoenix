"""Startup configuration diagnostics must never render secret inputs."""

from __future__ import annotations

import traceback
from pathlib import Path

import pytest
from kp_tracking_api.config import TrackingApiSettings
from pydantic import ValidationError


def test_tracking_validation_error_and_traceback_hide_secret_inputs() -> None:
    secret = "SECRET_TRACKING_TOKEN"

    with pytest.raises(ValidationError) as caught:
        TrackingApiSettings(
            _env_file=None,
            rate_limit_backend="redis",
            redis_url="",
            tracking_token_hmac_key=secret,
        )

    rendered = f"{caught.value!s}\n{caught.value!r}\n{''.join(traceback.format_exception(caught.value))}"
    assert "TRACKING_API_REDIS_URL is required" in rendered
    assert secret not in rendered
    assert "input_value=" not in rendered


@pytest.mark.parametrize(
    ("field", "method"),
    [
        ("tracking_token_hmac_key", "require_tracking_token_hmac_key"),
        ("training_token_hmac_key", "require_training_token_hmac_key"),
    ],
)
def test_tracking_key_parsers_suppress_nested_exception_chains(field: str, method: str) -> None:
    secret = "SECRET_NOT_HEX/private/key.pem"
    settings = TrackingApiSettings(_env_file=None, **{field: secret})

    with pytest.raises(RuntimeError) as caught:
        getattr(settings, method)()

    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert "private/key.pem" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "trusted_proxies",
    [
        "0.0.0.0/0",
        "::/0",
        "10.42.0.1/23",
        "10.42.0.0/23,10.42.0.0/24",
        "not-an-address",
        "10.42.0.0/23,",
        ",".join(f"192.0.2.{index}/32" for index in range(17)),
    ],
)
def test_trusted_proxy_networks_fail_closed(trusted_proxies: str) -> None:
    with pytest.raises(ValidationError, match="TRACKING_API_TRUSTED_PROXIES"):
        TrackingApiSettings(_env_file=None, trusted_proxies=trusted_proxies)


def test_trusted_proxy_networks_are_canonical_and_match_only_ip_peers() -> None:
    settings = TrackingApiSettings(
        _env_file=None,
        trusted_proxies="10.42.0.0/23,127.0.0.1,::1",
    )

    assert settings.trusted_proxies == "10.42.0.0/23,127.0.0.1/32,::1/128"
    assert settings.is_trusted_proxy("10.42.1.255") is True
    assert settings.is_trusted_proxy("10.42.2.1") is False
    assert settings.is_trusted_proxy("testclient") is False


def test_tracking_runtime_keeps_proxy_parsing_inside_the_application() -> None:
    entrypoint = (Path(__file__).resolve().parents[1] / "src" / "kp_tracking_api" / "__main__.py").read_text(
        encoding="utf-8"
    )

    assert "proxy_headers=False" in entrypoint
