"""W1-07 (KP-AUD-019): session epoch revocation + credential rotation machine.

Proves the three acceptance points:
  (a) a local session minted before a password rotation / before logout is
      rejected afterward, while a freshly minted one works;
  (b) a simulated failed new-secret application leaves the OLD password (and the
      existing sessions) working — no half-rotation;
  (c) every rotation is audited, and no audit record carries a secret value.

The epoch-enforcement path is exercised through the real ``get_principal``
dependency with a hand-built request (no DB, no network). The logout and
rotation handlers are called directly with a fake session + fake audit, exactly
as ``test_ai_providers`` drives the W1-04 generation path.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from fastapi import HTTPException
from kp_authorization import Principal, Role
from kp_database.models import ConsoleSessionEpoch, CredentialRotation
from kp_operator_api import console as console_module
from kp_operator_api.auth import (
    CONSOLE_SESSION_EPOCH_MARKER,
    DevIdP,
    console_run_dir,
    console_session_epoch_floor,
    get_principal,
)
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.console import (
    CONSOLE_OPERATOR_UUID,
    CredentialRotationApplyError,
    PasswordRotateRequest,
    logout,
    request_live_gated_rotation,
    rotate_console_password,
)
from kp_telemetry.errors import AuthenticationError, ConflictError

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
ISSUER = "http://localhost:8443/realms/kingphisher"
AUDIENCE = "kp-operator-api"
OLD_PASSWORD = "correct-horse-battery1"  # >= 12 chars, letter + digit
NEW_PASSWORD = "fresh-stapler-tango2"


# --- shared fakes ------------------------------------------------------------


class _FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **event: Any) -> None:
        self.events.append(event)


class _FakeSession:
    """Minimal Session stand-in for the two W1-07 singleton/keyed rows."""

    def __init__(self) -> None:
        self.epoch_row: ConsoleSessionEpoch | None = None
        self.rotation_rows: dict[str, CredentialRotation] = {}
        self.commits = 0

    def get(self, model: object, identifier: object) -> Any:
        if model is ConsoleSessionEpoch:
            return self.epoch_row
        if model is CredentialRotation:
            return self.rotation_rows.get(identifier)  # type: ignore[arg-type]
        return None

    def add(self, row: Any) -> None:
        if isinstance(row, ConsoleSessionEpoch):
            self.epoch_row = row
        elif isinstance(row, CredentialRotation):
            self.rotation_rows[row.credential] = row

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commits += 1


def _settings(env_file: Path) -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=str(env_file),
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        console_static_dir="/nonexistent-console-dir",
    )


def _request(settings: OperatorApiSettings) -> Any:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))


def _principal() -> Principal:
    return Principal(subject_id=str(uuid.uuid4()), roles={Role.ADMINISTRATOR})


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / ".env"
    path.write_text(f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}\n", encoding="utf-8")
    return path


def _write_marker(settings: OperatorApiSettings, epoch: int) -> None:
    run_dir = console_run_dir(settings)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / CONSOLE_SESSION_EPOCH_MARKER).write_text(json.dumps({"epoch": epoch}), encoding="utf-8")


def _marker_epoch(settings: OperatorApiSettings) -> int:
    return console_session_epoch_floor(settings)


def _token(epoch: int | None, *, exp: int = 2_000_000_000) -> str:
    claims: dict[str, Any] = {
        "sub": CONSOLE_OPERATOR_UUID,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": exp,
        "realm_access": {"roles": ["administrator"]},
    }
    if epoch is not None:
        claims["epoch"] = epoch
    return jwt.encode(claims, CONSOLE_JWT, algorithm="HS256")


def _auth_request(settings: OperatorApiSettings, token: str) -> Any:
    idp = DevIdP(ISSUER, AUDIENCE, CONSOLE_JWT)
    state = SimpleNamespace(idp=idp, settings=settings, user_limiter=SimpleNamespace(allow=lambda _subject: True))
    return SimpleNamespace(
        app=SimpleNamespace(state=state),
        headers={"Authorization": f"Bearer {token}"},
        cookies={},
    )


# --- (a) epoch enforcement: stale tokens rejected, fresh ones accepted -------


def test_floor_zero_accepts_tokens_with_or_without_epoch(env_file: Path) -> None:
    settings = _settings(env_file)
    # No marker -> floor 0 -> nothing is revoked yet.
    assert _marker_epoch(settings) == 0
    assert get_principal(_auth_request(settings, _token(0))).subject_id == CONSOLE_OPERATOR_UUID
    # A legacy token with no epoch claim still works while the floor is 0.
    assert get_principal(_auth_request(settings, _token(None))).subject_id == CONSOLE_OPERATOR_UUID


def test_token_before_epoch_bump_is_rejected_and_fresh_one_works(env_file: Path) -> None:
    settings = _settings(env_file)
    stale = _token(0)
    # Before the bump the token validates.
    assert get_principal(_auth_request(settings, stale)).subject_id == CONSOLE_OPERATOR_UUID
    # A logout/rotation raises the floor to 1.
    _write_marker(settings, 1)
    with pytest.raises(AuthenticationError):
        get_principal(_auth_request(settings, stale))
    # A token with no epoch claim is also rejected once the floor is above 0.
    with pytest.raises(AuthenticationError):
        get_principal(_auth_request(settings, _token(None)))
    # A freshly minted token stamped with the new epoch works.
    assert get_principal(_auth_request(settings, _token(1))).subject_id == CONSOLE_OPERATOR_UUID


def test_corrupt_epoch_marker_fails_closed(env_file: Path) -> None:
    settings = _settings(env_file)
    run_dir = console_run_dir(settings)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / CONSOLE_SESSION_EPOCH_MARKER).write_text("this is not json", encoding="utf-8")
    # Even a high-epoch token is rejected when the floor cannot be trusted.
    with pytest.raises(AuthenticationError):
        get_principal(_auth_request(settings, _token(99)))


# --- (a) logout bumps the epoch and revokes existing sessions ----------------


def test_logout_bumps_epoch_and_audits_without_secret(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(oidc_mode="dev"))))

    response = logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert response.status_code == 204
    assert session.epoch_row is not None and session.epoch_row.epoch == 1
    assert _marker_epoch(settings) == 1
    revoke = [event for event in audit.events if event["action"] == "console-session.revoke"]
    assert revoke and revoke[0]["detail"] == {"session_epoch": 1, "reason": "logout"}
    assert OLD_PASSWORD not in json.dumps(audit.events, default=str)


def test_logout_is_a_noop_for_managed_oidc(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(oidc_mode="oidc"))))
    logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert session.epoch_row is None
    assert audit.events == []
    assert _marker_epoch(settings) == 0


# --- (b)+(c) rotation: success path -----------------------------------------


def _rotate(
    env_file: Path,
    *,
    current: str,
    new: str,
    confirm: str | None = None,
) -> tuple[Any, _FakeSession, _FakeAudit, OperatorApiSettings]:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    body = PasswordRotateRequest(
        current_password=current, new_password=new, confirm=confirm if confirm is not None else new
    )
    result = rotate_console_password(
        body=body,
        request=_request(settings),
        session=session,
        audit=audit,
        settings=settings,
        principal=_principal(),
    )
    return result, session, audit, settings


def test_rotation_success_revokes_old_sessions_and_audits_without_secret(env_file: Path) -> None:
    result, session, audit, settings = _rotate(env_file, current=OLD_PASSWORD, new=NEW_PASSWORD)

    # The new password is durably in place; the old one no longer verifies.
    assert console_module._verify_console_password(env_file, NEW_PASSWORD) is True
    assert console_module._verify_console_password(env_file, OLD_PASSWORD) is False

    # Session epoch bumped -> every pre-rotation token is now rejected.
    assert session.epoch_row is not None and session.epoch_row.epoch == 1
    assert _marker_epoch(settings) == 1

    # Rotation state machine settled (generation == applied_generation).
    row = session.rotation_rows["console_password"]
    assert (row.generation, row.applied_generation, row.state) == (1, 1, "idle")

    # The freshly minted session is stamped with the new epoch and validates.
    fresh = jwt.decode(result.token, CONSOLE_JWT, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER)
    assert fresh["epoch"] == 1

    # Every rotation step is audited; no secret value appears anywhere.
    actions = [event["action"] for event in audit.events]
    assert "credential-rotation.begin" in actions
    assert "credential-rotation.applied" in actions
    serialized = json.dumps(audit.events, default=str)
    assert OLD_PASSWORD not in serialized and NEW_PASSWORD not in serialized


def test_rotation_requires_correct_current_password(env_file: Path) -> None:
    with pytest.raises(AuthenticationError):
        _rotate(env_file, current="wrong-password9", new=NEW_PASSWORD)
    # Nothing rotated: old password intact, no epoch bump.
    assert f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}" in env_file.read_text(encoding="utf-8")


def test_rotation_rejects_confirmation_mismatch(env_file: Path) -> None:
    with pytest.raises(HTTPException) as excinfo:
        _rotate(env_file, current=OLD_PASSWORD, new=NEW_PASSWORD, confirm="different-value1")
    assert excinfo.value.status_code == 422
    assert f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}" in env_file.read_text(encoding="utf-8")


# --- (b) rotation: failed new-secret application leaves old secret working ---


def test_failed_application_leaves_old_secret_and_sessions_working(
    env_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise console_module._AtomicEnvUpdateError("simulated env write failure")

    monkeypatch.setattr(console_module, "set_console_password", _boom)

    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    body = PasswordRotateRequest(current_password=OLD_PASSWORD, new_password=NEW_PASSWORD, confirm=NEW_PASSWORD)
    with pytest.raises(ConflictError):
        rotate_console_password(
            body=body,
            request=_request(settings),
            session=session,
            audit=audit,
            settings=settings,
            principal=_principal(),
        )

    # The OLD password is still the only one that works (no half-rotation).
    content = env_file.read_text(encoding="utf-8")
    assert f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}" in content
    assert NEW_PASSWORD not in content

    # The epoch was NOT bumped: existing sessions remain valid.
    assert session.epoch_row is None
    assert _marker_epoch(settings) == 0

    # The rotation is recorded as blocked drift (generation ahead of applied).
    row = session.rotation_rows["console_password"]
    assert (row.generation, row.applied_generation, row.state) == (1, 0, "failed")

    # Begin + failure are audited; still no secret value anywhere.
    actions = [event["action"] for event in audit.events]
    assert actions == ["credential-rotation.begin", "credential-rotation.failed"]
    serialized = json.dumps(audit.events, default=str)
    assert OLD_PASSWORD not in serialized and NEW_PASSWORD not in serialized


def test_weak_new_password_fails_closed(env_file: Path) -> None:
    with pytest.raises(HTTPException) as excinfo:
        _rotate(env_file, current=OLD_PASSWORD, new="short", confirm="short")
    assert excinfo.value.status_code == 422
    # Old secret intact; policy rejection did not rotate anything.
    assert f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}" in env_file.read_text(encoding="utf-8")


def test_apply_helper_wraps_verification_failure(env_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # set_console_password "succeeds" but the value does not verify afterward.
    monkeypatch.setattr(console_module, "set_console_password", lambda *_a, **_k: None)
    with pytest.raises(CredentialRotationApplyError):
        console_module._apply_console_password_rotation(env_file, NEW_PASSWORD)


# --- live-gated external rotation performs nothing ---------------------------


def test_live_gated_rotation_records_pending_without_acting() -> None:
    session = _FakeSession()
    audit = _FakeAudit()
    generation = request_live_gated_rotation(session, audit, "provider:smtp", actor=CONSOLE_OPERATOR_UUID)
    assert generation == 1
    row = session.rotation_rows["provider:smtp"]
    assert (row.state, row.live_gated, row.applied_generation) == ("pending_live", True, 0)
    assert [event["action"] for event in audit.events] == ["credential-rotation.pending-live"]
