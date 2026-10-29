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
from fastapi.testclient import TestClient
from kp_authorization import Principal, Role
from kp_database.models import ConsoleSessionEpoch, CredentialRotation
from kp_operator_api import console as console_module
from kp_operator_api import deps
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
    reconcile_session_epoch,
    request_live_gated_rotation,
    rotate_console_password,
)
from kp_operator_api.main import create_app
from kp_telemetry.errors import AuthenticationError, ConflictError
from sqlalchemy.exc import SQLAlchemyError

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


class _FakeThrottle:
    def __init__(self, *, locked: bool = False) -> None:
        self._locked = locked
        self.failures = 0
        self.successes = 0

    def locked(self, _ip: str) -> bool:
        return self._locked

    def record_failure(self, _ip: str) -> None:
        self.failures += 1

    def record_success(self, _ip: str) -> None:
        self.successes += 1


class _FakeSession:
    """Minimal Session stand-in for the two W1-07 singleton/keyed rows."""

    def __init__(self, *, fail_commit_on: set[int] | None = None) -> None:
        self.epoch_row: ConsoleSessionEpoch | None = None
        self.rotation_rows: dict[str, CredentialRotation] = {}
        self.commits = 0
        self.rollbacks = 0
        self.locked_for_update = False
        self._fail_commit_on = fail_commit_on or set()

    def get(self, model: object, identifier: object, *, with_for_update: bool = False) -> Any:
        if model is ConsoleSessionEpoch:
            if with_for_update:
                self.locked_for_update = True
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
        if self.commits in self._fail_commit_on:
            raise SQLAlchemyError(f"simulated commit failure #{self.commits}")

    def rollback(self) -> None:
        self.rollbacks += 1


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


def _request(settings: OperatorApiSettings, *, throttle: _FakeThrottle | None = None) -> Any:
    state = SimpleNamespace(settings=settings, login_throttle=throttle or _FakeThrottle())
    return SimpleNamespace(app=SimpleNamespace(state=state), client=SimpleNamespace(host="test-ip"))


def _logout_request(settings: OperatorApiSettings, *, token: str | None, oidc_mode: str = "dev") -> Any:
    idp = DevIdP(ISSUER, AUDIENCE, CONSOLE_JWT)
    state = SimpleNamespace(settings=SimpleNamespace(oidc_mode=oidc_mode), idp=idp)
    cookies = {"kp_oidc_session": token} if token else {}
    return SimpleNamespace(app=SimpleNamespace(state=state), headers={}, cookies=cookies)


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


# --- (a)/N1 logout only bumps for a signature-valid session ------------------


def test_logout_with_valid_token_bumps_epoch_and_audits_real_actor(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    request = _logout_request(settings, token=_token(0))

    response = logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert response.status_code == 204
    assert session.epoch_row is not None and session.epoch_row.epoch == 1
    assert session.locked_for_update is True  # N7: the bump locks the singleton row
    assert _marker_epoch(settings) == 1
    revoke = [event for event in audit.events if event["action"] == "console-session.revoke"]
    assert revoke and revoke[0]["detail"] == {"session_epoch": 1, "reason": "logout"}
    # Attributed to the real principal from the token, not a hardcoded UUID.
    assert revoke[0]["actor"] == CONSOLE_OPERATOR_UUID
    assert OLD_PASSWORD not in json.dumps(audit.events, default=str)


def test_logout_accepts_an_expired_but_signature_valid_token(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    # exp in the past: a normal logout of an already-expired session still revokes.
    request = _logout_request(settings, token=_token(0, exp=1))
    logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert session.epoch_row is not None and session.epoch_row.epoch == 1


def test_unauthenticated_logout_does_not_bump_epoch(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    request = _logout_request(settings, token=None)
    response = logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert response.status_code == 204  # the cookie is still cleared
    assert session.epoch_row is None  # ... but nothing is revoked / written
    assert audit.events == []
    assert _marker_epoch(settings) == 0


def test_forged_logout_token_does_not_bump_epoch(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    forged = jwt.encode(
        {"sub": CONSOLE_OPERATOR_UUID, "iss": ISSUER, "aud": AUDIENCE, "exp": 2_000_000_000},
        "a-different-secret-that-is-at-least-32-bytes",
        algorithm="HS256",
    )
    request = _logout_request(settings, token=forged)
    logout(request=request, session=session, audit=audit, settings=settings)  # type: ignore[arg-type]
    assert session.epoch_row is None
    assert audit.events == []
    assert _marker_epoch(settings) == 0


def test_logout_is_a_noop_for_managed_oidc(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    request = _logout_request(settings, token=_token(0), oidc_mode="oidc")
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
    assert session.locked_for_update is True  # N7: the bump locks the singleton row
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


def test_weak_new_password_rejected_before_any_rotation_state(env_file: Path) -> None:
    # N4a: policy validation happens BEFORE _begin_credential_rotation, so a weak
    # password is a clean 422 and never a committed `rotating`/blocked-drift row.
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    body = PasswordRotateRequest(current_password=OLD_PASSWORD, new_password="short", confirm="short")
    with pytest.raises(HTTPException) as excinfo:
        rotate_console_password(
            body=body,
            request=_request(settings),
            session=session,
            audit=audit,
            settings=settings,
            principal=_principal(),
        )
    assert excinfo.value.status_code == 422
    assert f"KP_CONSOLE_PASSWORD={OLD_PASSWORD}" in env_file.read_text(encoding="utf-8")
    # No rotation row was created and nothing was audited (not mislabeled failed).
    assert session.rotation_rows == {}
    assert audit.events == []


def test_rotation_locked_out_by_throttle(env_file: Path) -> None:
    # N5: the current-password check reuses the login lockout.
    settings = _settings(env_file)
    session = _FakeSession()
    audit = _FakeAudit()
    body = PasswordRotateRequest(current_password=OLD_PASSWORD, new_password=NEW_PASSWORD, confirm=NEW_PASSWORD)
    with pytest.raises(HTTPException) as excinfo:
        rotate_console_password(
            body=body,
            request=_request(settings, throttle=_FakeThrottle(locked=True)),
            session=session,
            audit=audit,
            settings=settings,
            principal=_principal(),
        )
    assert excinfo.value.status_code == 429


def test_rotation_records_failure_for_unwrapped_oserror(env_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # N4b: an error env_store does not wrap (e.g. OSError) is still caught, the
    # row is marked failed with a value-free audit, and the old secret stays.
    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("disk full")

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
    assert console_module._verify_console_password(env_file, OLD_PASSWORD) is True
    assert session.epoch_row is None
    row = session.rotation_rows["console_password"]
    assert (row.generation, row.applied_generation, row.state) == (1, 0, "failed")
    assert [event["action"] for event in audit.events] == [
        "credential-rotation.begin",
        "credential-rotation.failed",
    ]


def test_apply_helper_wraps_verification_failure(env_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # set_console_password "succeeds" but the value does not verify afterward.
    monkeypatch.setattr(console_module, "set_console_password", lambda *_a, **_k: None)
    with pytest.raises(CredentialRotationApplyError):
        console_module._apply_console_password_rotation(env_file, NEW_PASSWORD)


# --- N2: marker loss / drift reconcile converges toward MORE revocation ------


def test_reconcile_rewrites_marker_up_to_db_epoch(env_file: Path) -> None:
    # data/run was wiped: DB epoch is 5 but the marker is missing (reads as 0),
    # silently un-revoking every previously revoked token. Reconcile fixes it.
    settings = _settings(env_file)
    session = _FakeSession()
    session.epoch_row = ConsoleSessionEpoch(id=1, epoch=5)
    assert _marker_epoch(settings) == 0  # marker missing -> fail-open floor
    reconcile_session_epoch(session, _FakeAudit(), settings)
    assert _marker_epoch(settings) == 5
    # A token below the restored floor is rejected again.
    with pytest.raises(AuthenticationError):
        get_principal(_auth_request(settings, _token(4)))


def test_reconcile_never_lowers_the_marker(env_file: Path) -> None:
    settings = _settings(env_file)
    _write_marker(settings, 9)
    session = _FakeSession()
    session.epoch_row = ConsoleSessionEpoch(id=1, epoch=3)
    reconcile_session_epoch(session, _FakeAudit(), settings)
    assert _marker_epoch(settings) == 9  # never lowered toward the smaller DB value


def test_reconcile_is_best_effort_on_db_error(env_file: Path) -> None:
    settings = _settings(env_file)
    session = _FakeSession(fail_commit_on={1})  # any DB touch would fail
    session.rotation_rows["console_password"] = CredentialRotation(
        credential="console_password", generation=1, applied_generation=0, state="rotating", live_gated=False
    )
    # best_effort swallows the SQLAlchemyError instead of breaking the login it runs under.
    reconcile_session_epoch(session, _FakeAudit(), settings, best_effort=True)
    assert session.rollbacks == 1


# --- N3: post-apply commit fault leaves a reconcilable stuck rotation --------


def test_post_apply_commit_fault_is_converged_by_reconcile(env_file: Path) -> None:
    settings = _settings(env_file)
    # commit #1 (begin) succeeds; commit #2 (epoch bump + applied) fails AFTER the
    # new password is already written.
    session = _FakeSession(fail_commit_on={2})
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
    # The new password is live, but the epoch was not bumped and the marker was
    # not advanced: an old token is still (transiently) valid — the vulnerability.
    assert console_module._verify_console_password(env_file, NEW_PASSWORD) is True
    assert _marker_epoch(settings) == 0
    assert get_principal(_auth_request(settings, _token(0))).subject_id == CONSOLE_OPERATOR_UUID

    # The next login/rotation reconciles the stuck `rotating` row committed at
    # begin: the epoch is bumped forward and old tokens are rejected.
    recovered = _FakeSession()
    recovered.epoch_row = ConsoleSessionEpoch(id=1, epoch=0)
    recovered.rotation_rows["console_password"] = CredentialRotation(
        credential="console_password", generation=1, applied_generation=0, state="rotating", live_gated=False
    )
    reconcile_session_epoch(recovered, _FakeAudit(), settings)
    assert recovered.epoch_row.epoch == 1
    assert recovered.rotation_rows["console_password"].state == "idle"
    assert _marker_epoch(settings) == 1
    with pytest.raises(AuthenticationError):
        get_principal(_auth_request(settings, _token(0)))


# --- N8: HTTP-level tests through the real app/dependency stack --------------


def _http_app(env_file: Path):
    app = create_app(_settings(env_file))
    app.state.audit_health_check = lambda: True  # pass the audit mutation gate in-process
    return app


def _fake_db_overrides(app, session: _FakeSession, audit: _FakeAudit) -> None:
    app.dependency_overrides[deps.get_session] = lambda: session
    app.dependency_overrides[deps.get_audit_store] = lambda: audit


def test_http_unauthenticated_logout_does_not_bump(env_file: Path) -> None:
    app = _http_app(env_file)
    session = _FakeSession()
    _fake_db_overrides(app, session, _FakeAudit())
    with TestClient(app) as client:
        resp = client.post("/api/v1/console/logout")
    assert resp.status_code == 204
    assert session.epoch_row is None  # N1: no revocation for an anonymous caller


def test_http_valid_logout_bumps_epoch(env_file: Path) -> None:
    app = _http_app(env_file)
    session = _FakeSession()
    _fake_db_overrides(app, session, _FakeAudit())
    with TestClient(app) as client:
        token = client.post("/api/v1/console/session", json={"password": OLD_PASSWORD}).json()["token"]
        client.cookies.set("kp_oidc_session", token)
        # A browser logout sends same-origin fetch metadata with the cookie.
        resp = client.post("/api/v1/console/logout", headers={"Sec-Fetch-Site": "same-origin"})
    assert resp.status_code == 204
    assert session.epoch_row is not None and session.epoch_row.epoch == 1


def test_http_rotate_requires_a_bearer_and_the_capability(env_file: Path) -> None:
    app = _http_app(env_file)
    _fake_db_overrides(app, _FakeSession(), _FakeAudit())
    body = {"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD, "confirm": NEW_PASSWORD}
    with TestClient(app) as client:
        # No credential at all.
        assert client.post("/api/v1/console/password/rotate", json=body).status_code == 401
        # A valid signature but a role without manage:roles.
        weak = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "iss": ISSUER,
                "aud": AUDIENCE,
                "exp": 2_000_000_000,
                "realm_access": {"roles": ["campaign-operator"]},
            },
            CONSOLE_JWT,
            algorithm="HS256",
        )
        denied = client.post("/api/v1/console/password/rotate", json=body, headers={"Authorization": f"Bearer {weak}"})
    assert denied.status_code == 403


def test_http_rotate_wrong_current_password_is_rejected(env_file: Path) -> None:
    app = _http_app(env_file)
    _fake_db_overrides(app, _FakeSession(), _FakeAudit())
    with TestClient(app) as client:
        token = client.post("/api/v1/console/session", json={"password": OLD_PASSWORD}).json()["token"]
        resp = client.post(
            "/api/v1/console/password/rotate",
            json={"current_password": "wrong-password9", "new_password": NEW_PASSWORD, "confirm": NEW_PASSWORD},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 401
    assert console_module._verify_console_password(env_file, OLD_PASSWORD) is True


def test_http_rotate_success_revokes_prior_token(env_file: Path) -> None:
    app = _http_app(env_file)
    _fake_db_overrides(app, _FakeSession(), _FakeAudit())
    with TestClient(app) as client:
        token = client.post("/api/v1/console/session", json={"password": OLD_PASSWORD}).json()["token"]
        # The pre-rotation token works on an authenticated endpoint.
        assert client.get("/api/v1/console/status", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        rotate = client.post(
            "/api/v1/console/password/rotate",
            json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD, "confirm": NEW_PASSWORD},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert rotate.status_code == 200, rotate.text
        # The pre-rotation token is now rejected (epoch floor raised to 1).
        after = client.get("/api/v1/console/status", headers={"Authorization": f"Bearer {token}"})
    assert after.status_code == 401
    assert console_module._verify_console_password(env_file, NEW_PASSWORD) is True


# --- live-gated external rotation performs nothing ---------------------------


def test_live_gated_rotation_records_pending_without_acting() -> None:
    session = _FakeSession()
    audit = _FakeAudit()
    generation = request_live_gated_rotation(session, audit, "provider:smtp", actor=CONSOLE_OPERATOR_UUID)
    assert generation == 1
    row = session.rotation_rows["provider:smtp"]
    assert (row.state, row.live_gated, row.applied_generation) == ("pending_live", True, 0)
    assert [event["action"] for event in audit.events] == ["credential-rotation.pending-live"]
