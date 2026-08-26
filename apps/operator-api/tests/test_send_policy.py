"""T-06 send-safety policy at the operator boundary.

Covers the two controls that stop one administrator from mailing a simulation
unilaterally: the approval policy and the recipient-domain allowlist. Both are
exercised at the decision layer rather than over HTTP, so no live Postgres or
OIDC provider is required.
"""

from __future__ import annotations

import pytest
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.send_policy import resolve_recipient_policy
from kp_telemetry.errors import ValidationError_
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


# --- approval policy configuration -------------------------------------------------


def test_single_admin_policy_is_rejected_under_oidc() -> None:
    # The whole point of the two-person rule is that it cannot be switched off
    # in the deployment that reaches real mailboxes.
    with pytest.raises(ValidationError, match="single-admin is not permitted"):
        _settings(oidc_mode="oidc", approval_policy="single-admin")


def test_enforce_policy_is_allowed_under_oidc() -> None:
    assert _settings(oidc_mode="oidc", approval_policy="enforce").approval_policy is ApprovalPolicy.ENFORCE


def test_single_admin_policy_is_allowed_in_dev_auth() -> None:
    # The offline demo stack stays usable for one operator.
    assert _settings(oidc_mode="dev", approval_policy="single-admin").approval_policy is ApprovalPolicy.SINGLE_ADMIN


def test_default_policy_is_single_admin_for_the_dev_stack() -> None:
    assert _settings().approval_policy is ApprovalPolicy.SINGLE_ADMIN


# --- recipient domain allowlist ----------------------------------------------------


def test_allowlist_reads_the_shared_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    # One variable configures both the API and the workers, so the two cannot
    # silently disagree about who may be mailed.
    monkeypatch.setenv("KP_ALLOWED_RECIPIENT_DOMAINS", "corp.example, partner.example")
    assert _settings().recipient_domain_allowlist() == frozenset({"corp.example", "partner.example"})


def test_import_policy_fails_closed_when_allowlist_unset_outside_dev_auth() -> None:
    settings = _settings(oidc_mode="oidc", approval_policy="enforce", allowed_recipient_domains="")
    with pytest.raises(ValidationError_) as excinfo:
        resolve_recipient_policy(settings)
    assert excinfo.value.http_status == 422
    assert "KP_ALLOWED_RECIPIENT_DOMAINS" in str(excinfo.value)


def test_import_policy_returns_configured_allowlist() -> None:
    settings = _settings(oidc_mode="oidc", approval_policy="enforce", allowed_recipient_domains="corp.example")
    allowlist, unrestricted = resolve_recipient_policy(settings)
    assert allowlist == frozenset({"corp.example"})
    assert unrestricted is False


def test_import_policy_allows_all_only_in_dev_auth() -> None:
    # The offline stack must stay usable, but the caller audits that this
    # import ran with no domain restriction at all.
    allowlist, unrestricted = resolve_recipient_policy(_settings(oidc_mode="dev", allowed_recipient_domains=""))
    assert allowlist == frozenset()
    assert unrestricted is True
