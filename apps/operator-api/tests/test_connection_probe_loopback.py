"""Dev-mode loopback allowlist for the onboarding connection probes.

The console probes local developer services (Mailpit, mock graph/AI, OIDC) only
when the destination is an explicit loopback host on a reviewed port and the API
is in dev auth mode. ``KP_WORKER_SMTP_ADDRESS`` on Mailpit's SMTP port (1025)
must be allowed exactly like the existing ``KP_WORKER_MAILPIT_SMTP`` entry;
anything loopback on an unlisted port, or any non-loopback address, stays
blocked so the outbound safety policy has real teeth.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from kp_operator_api.connection_probes import _allow_development_loopback


def _settings(dev_auth_mode: bool = True) -> object:
    return SimpleNamespace(dev_auth_mode=dev_auth_mode)


@pytest.mark.parametrize(
    ("destination_key", "raw", "smtp"),
    [
        ("KP_WORKER_SMTP_ADDRESS", "localhost:1025", True),
        ("KP_WORKER_SMTP_ADDRESS", "127.0.0.1:1025", True),
        ("KP_WORKER_MAILPIT_SMTP", "localhost:1025", True),
    ],
)
def test_dev_loopback_allows_reviewed_smtp_destinations(destination_key: str, raw: str, smtp: bool) -> None:
    assert _allow_development_loopback(_settings(), destination_key, raw, smtp=smtp)


def test_dev_loopback_denies_unlisted_smtp_port() -> None:
    assert _allow_development_loopback(_settings(), "KP_WORKER_SMTP_ADDRESS", "localhost:587", smtp=True) is False


def test_dev_loopback_denies_non_loopback() -> None:
    assert (
        _allow_development_loopback(_settings(), "KP_WORKER_SMTP_ADDRESS", "smtp.example.com:1025", smtp=True) is False
    )


def test_dev_loopback_requires_dev_auth_mode() -> None:
    allowed = _allow_development_loopback(
        _settings(dev_auth_mode=False),
        "KP_WORKER_SMTP_ADDRESS",
        "localhost:1025",
        smtp=True,
    )
    assert allowed is False


def test_dev_loopback_denies_unmanaged_destination_key() -> None:
    assert _allow_development_loopback(_settings(), "KP_WORKER_UNKNOWN_ADDRESS", "localhost:1025", smtp=True) is False
