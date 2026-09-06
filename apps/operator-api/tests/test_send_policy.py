"""T-06 send-safety policy at the operator boundary.

Covers the two controls that stop one administrator from mailing a simulation
unilaterally: the approval policy and the recipient-domain allowlist. Both are
exercised at the decision layer rather than over HTTP, so no live Postgres or
OIDC provider is required.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
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


def test_single_admin_policy_is_allowed_only_in_marked_dev_stack() -> None:
    # PLT-002: the offline demo stack stays usable for one operator, but ONLY
    # when it is explicitly marked as a throwaway dev stack (KP_DEV_STACK=1).
    settings = _settings(oidc_mode="dev", approval_policy="single-admin", dev_stack=True)
    assert settings.approval_policy is ApprovalPolicy.SINGLE_ADMIN


def test_single_admin_policy_is_rejected_in_dev_auth_without_the_marker() -> None:
    # PLT-002: dev-auth alone is no longer enough; without KP_DEV_STACK a stray
    # single-admin cannot silently switch off separation-of-duties.
    with pytest.raises(ValidationError, match="single-admin is not permitted"):
        _settings(oidc_mode="dev", approval_policy="single-admin")


def test_default_policy_is_enforce() -> None:
    # PLT-002: the safe two-person default, regardless of auth mode.
    assert _settings().approval_policy is ApprovalPolicy.ENFORCE
    assert _settings(oidc_mode="dev", dev_stack=True).approval_policy is ApprovalPolicy.ENFORCE


def test_managed_config_refuses_dev_auth() -> None:
    # PLT-002: a managed (hardened) posture must run real OIDC; managed+dev-auth
    # used to silently skip every managed check, now it refuses to start.
    with pytest.raises(ValidationError, match="requires OPERATOR_API_OIDC_MODE=oidc"):
        _settings(config_store="managed", oidc_mode="dev", approval_policy="enforce")


def test_env_file_dev_stack_still_starts() -> None:
    # The running .105 stack: config_store=env_file + oidc_mode=dev must NOT be
    # refused by the managed guard, and stays usable with the dev marker.
    settings = _settings(
        config_store="env_file",
        oidc_mode="dev",
        approval_policy="single-admin",
        dev_stack=True,
    )
    assert settings.config_is_managed is False
    assert settings.approval_policy is ApprovalPolicy.SINGLE_ADMIN


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


def test_import_policy_allows_all_only_in_marked_dev_stack() -> None:
    # The offline stack must stay usable, but the caller audits that this
    # import ran with no domain restriction at all. PLT-002: allow-all now also
    # requires the explicit KP_DEV_STACK marker, not just dev-auth.
    allowlist, unrestricted = resolve_recipient_policy(
        _settings(oidc_mode="dev", dev_stack=True, allowed_recipient_domains="")
    )
    assert allowlist == frozenset()
    assert unrestricted is True


def test_import_policy_fails_closed_in_dev_auth_without_the_marker() -> None:
    # PLT-002: dev-auth without KP_DEV_STACK must NOT silently allow-all.
    settings = _settings(oidc_mode="dev", allowed_recipient_domains="")
    with pytest.raises(ValidationError_):
        resolve_recipient_policy(settings)


# --- policy visibility for the console -------------------------------------------


@pytest.mark.parametrize("policy", ["enforce", "single-admin"])
def test_session_reports_the_active_approval_policy(tmp_path: Path, policy: str) -> None:
    # The console decides from this value whether to offer "Schedule" on a
    # draft. If it were wrong the operator would be handed an action the API
    # rejects with a 409 they cannot act on.
    env_file = tmp_path / ".env"
    env_file.write_text("KP_CONSOLE_PASSWORD=correct-horse-battery-staple\n", encoding="utf-8")
    # single-admin requires the explicit dev-stack marker under dev-auth (PLT-002).
    settings = _settings(oidc_mode="dev", approval_policy=policy, dev_stack=True, env_file=str(env_file))

    app = create_app(settings)
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/console/session",
            json={"password": "correct-horse-battery-staple"},
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["approval_policy"] == policy
