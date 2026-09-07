"""Local ``.env`` configuration store for the browser console.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split. This module owns the console's whole relationship with the local
environment file: the key allowlist, the secret-key set, the managed-deployment
refusal, and the atomic, durable, recoverable commit path (REL-031). Every
other console module imports these definitions rather than re-implementing
them, so the write path exists exactly once.
"""

from __future__ import annotations

import fcntl
import hmac
import os
import stat
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from dotenv import dotenv_values, set_key
from fastapi import HTTPException, Request, status
from kp_telemetry.errors import ConflictError, PermissionDeniedError

CONSOLE_PASSWORD_KEY = "KP_CONSOLE_PASSWORD"  # noqa: S105


_SECRET_KEYS: frozenset[str] = frozenset(
    {
        CONSOLE_PASSWORD_KEY,
        "OPERATOR_API_AUDIT_HMAC_KEY",
        "OPERATOR_API_CIPHERTEXT_KEK",
        "OPERATOR_API_CONSOLE_JWT_SECRET",
        "OPERATOR_API_OIDC_CLIENT_SECRET",
        "KP_WORKER_AUDIT_HMAC_KEY",
        "KP_WORKER_CIPHERTEXT_KEK",
        "KP_WORKER_SMTP_PASSWORD",
        "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
        "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD",
        "KP_WORKER_AI_BEARER_TOKEN",
        "KP_WORKER_AI_API_KEY",
        "KP_WORKER_GRAPH_BEARER_TOKEN",
        "KP_WORKER_GRAPH_API_KEY",
        "MAILPIT_API_PASSWORD",
    }
)


def _env_path(request: Request) -> Path:
    return Path(request.app.state.settings.env_file or ".env")


MANAGED_CONFIG_MESSAGE = (
    "this deployment reads its configuration from Terraform and Key Vault, not from a file the "
    "console can edit. Change the value in infrastructure/terraform (or the corresponding Key Vault "
    "secret) and re-run the Azure deployment workflow. Editing it here would be discarded on the "
    "next container restart."
)


MANAGED_PROCESS_MESSAGE = (
    "this deployment runs as Azure Container Apps revisions, which have no local supervisor to "
    "signal. Restart or scale the container app instead (az containerapp revision restart)."
)


def _reject_if_managed(request: Request, message: str) -> None:
    """Refuse local-only console actions when configuration is externally managed.

    Without this the console appears to succeed on Azure: it writes a file on an
    ephemeral layer that disappears on the next restart, which is a worse
    failure than an explicit refusal because it looks like it worked.
    """
    if request.app.state.settings.config_is_managed:
        raise ConflictError(message)


def _env_values(path: Path) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


class _AtomicEnvUpdateError(RuntimeError):
    """A sanitized, fail-closed local configuration commit failure."""


_ENV_UPDATE_THREAD_LOCK = threading.Lock()
_MAX_ENV_VALUE_BYTES = 64 * 1024


_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        CONSOLE_PASSWORD_KEY,
        "OPERATOR_API_HOST",
        "OPERATOR_API_PORT",
        "OPERATOR_API_OIDC_ISSUER",
        "OPERATOR_API_OIDC_AUDIENCE",
        "OPERATOR_API_OIDC_MODE",
        "OPERATOR_API_OIDC_CLIENT_ID",
        "OPERATOR_API_OIDC_CLIENT_SECRET",
        "OPERATOR_API_OIDC_REDIRECT_URI",
        "OPERATOR_API_OIDC_SCOPES",
        "OPERATOR_API_LOG_LEVEL",
        "OPERATOR_API_RATE_LIMIT_USER_PER_MIN",
        "OPERATOR_API_RATE_LIMIT_IP_PER_MIN",
        "OPERATOR_API_MAX_BODY_BYTES",
        "OPERATOR_API_TRACKING_BASE_URL",
        "OPERATOR_API_TRAINING_BASE_URL",
        "OPERATOR_API_TRAINING_DOMAINS",
        "OPERATOR_API_APP_NAME",
        "OPERATOR_API_AUDIT_HMAC_KEY",
        "OPERATOR_API_CIPHERTEXT_KEK",
        "OPERATOR_API_CONSOLE_JWT_SECRET",
        "TRACKING_API_HOST",
        "TRACKING_API_PORT",
        "KP_WORKER_AUDIT_HMAC_KEY",
        "KP_WORKER_CIPHERTEXT_KEK",
        "KP_WORKER_POLL_SECONDS",
        "KP_WORKER_LOG_LEVEL",
        "KP_WORKER_MAILPIT_SMTP",
        "KP_WORKER_MAILPIT_API_URL",
        "KP_WORKER_PROVIDER_TIMEOUT_SECONDS",
        "KP_WORKER_MAILBOX_POLL_LIMIT",
        "KP_WORKER_REMINDER_BATCH_SIZE",
        "KP_WORKER_REMINDER_SENDER",
        "KP_WORKER_ALERT_WEBHOOK_DOMAINS",
        "KP_WORKER_ALERT_WEBHOOK_URL",
        "KP_WORKER_SMTP_ADDRESS",
        "KP_WORKER_SMTP_USERNAME",
        "KP_WORKER_SMTP_PASSWORD",
        "KP_WORKER_SMTP_STARTTLS",
        "KP_WORKER_SMTP_SSL",
        "KP_WORKER_SMTP_SENDER",
        "KP_WORKER_EMAIL_PROVIDER",
        "KP_WORKER_ACS_EMAIL_ENDPOINT",
        "KP_WORKER_ACS_CLIENT_ID",
        "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
        "KP_WORKER_ACS_SENDING_DOMAIN",
        "KP_WORKER_ACS_SENDER_LOCAL_PART",
        "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
        "KP_WORKER_ACS_DOMAIN_VERIFICATION_STATUS",
        "KP_WORKER_ACS_SPF_VERIFICATION_STATUS",
        "KP_WORKER_ACS_DKIM_VERIFICATION_STATUS",
        "KP_WORKER_ACS_DKIM2_VERIFICATION_STATUS",
        "KP_WORKER_ACS_READINESS_CHECKED_AT",
        "KP_WORKER_ACS_DAILY_MESSAGE_LIMIT",
        "KP_WORKER_ACS_MESSAGES_PER_MINUTE",
        "KP_WORKER_ACS_RAMP_BATCH_SIZE",
        "KP_WORKER_ACS_RAMP_INTERVAL_SECONDS",
        "KP_WORKER_REPORTED_MAILBOX_URL",
        "KP_WORKER_REPORTED_MAILBOX_PROVIDER",
        "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
        "KP_WORKER_REPORTED_MAILBOX_ID",
        "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID",
        "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD",
        "KP_WORKER_AI_BASE_URL",
        "KP_WORKER_AI_BEARER_TOKEN",
        "KP_WORKER_AI_API_KEY",
        "KP_WORKER_GRAPH_BASE_URL",
        "KP_WORKER_GRAPH_CLIENT_ID",
        "KP_WORKER_GRAPH_GROUP_IDS",
        "KP_WORKER_MICROSOFT_TENANT_ID",
        "KP_WORKER_GRAPH_BEARER_TOKEN",
        "KP_WORKER_GRAPH_API_KEY",
        "KP_WORKER_GRAPH_MAX_USERS",
        "KP_WORKER_GRAPH_MAX_PAGES",
        "KP_WORKER_TRAINING_BASE_URL",
        "KP_WORKER_TRAINING_DOMAINS",
        "AZURE_GRAPH_TENANT_ID",
        "AZURE_GRAPH_CLIENT_ID",
        "AZURE_GRAPH_CERT_PATH",
        "AZURE_GRAPH_CERT_THUMBPRINT",
        "OPERATOR_API_ONBOARDING_COMPLETED",
        "MOCK_IDP_URL",
        "MOCK_GRAPH_URL",
        "MOCK_AI_URL",
        "MAILPIT_URL",
        "MAILPIT_API_PASSWORD",
    }
)
# Database DSNs embed credentials and are deliberately not exposed or writable
# through the console. ``scripts/bootstrap_env.sh`` generates and synchronizes
# those credentials; the local console launcher invokes that bootstrap step.


def _selected_binding_destination(values: dict[str, str], primary: str, fallback: str) -> str:
    return values.get(primary) or values.get(fallback, "")


def _require_fresh_credentials_for_rebound_destinations(
    current: dict[str, str],
    desired: dict[str, str],
) -> None:
    """Keep stored credentials bound to the destination they were entered for.

    This runs under the same advisory lock as the eventual env-file replace.
    Consequently another console process cannot change a destination between
    this comparison and the atomic commit. Blank secret fields retain their
    normal meaning only when the credential's destination is unchanged.
    """

    candidate = {**current, **desired}
    email_provider = candidate.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp"
    mailbox_provider = candidate.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
    oidc_mode = candidate.get("OPERATOR_API_OIDC_MODE", "dev").strip()
    bindings: tuple[tuple[str, object, object, tuple[str, ...], bool], ...] = (
        (
            "OIDC issuer",
            (
                current.get("OPERATOR_API_OIDC_MODE", "dev").strip(),
                current.get("OPERATOR_API_OIDC_ISSUER", ""),
                current.get("OPERATOR_API_OIDC_CLIENT_ID", ""),
            ),
            (
                oidc_mode,
                candidate.get("OPERATOR_API_OIDC_ISSUER", ""),
                candidate.get("OPERATOR_API_OIDC_CLIENT_ID", ""),
            ),
            ("OPERATOR_API_OIDC_CLIENT_SECRET",),
            oidc_mode == "oidc",
        ),
        (
            "AI service base URL",
            _selected_binding_destination(current, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL"),
            _selected_binding_destination(candidate, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL"),
            ("KP_WORKER_AI_BEARER_TOKEN", "KP_WORKER_AI_API_KEY"),
            bool(_selected_binding_destination(candidate, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")),
        ),
        (
            "Graph service base URL",
            _selected_binding_destination(current, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL"),
            _selected_binding_destination(candidate, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL"),
            ("KP_WORKER_GRAPH_BEARER_TOKEN", "KP_WORKER_GRAPH_API_KEY"),
            bool(_selected_binding_destination(candidate, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")),
        ),
        (
            "reported-mailbox provider or base URL",
            (
                current.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit",
                _selected_binding_destination(
                    current,
                    "KP_WORKER_REPORTED_MAILBOX_URL",
                    "KP_WORKER_MAILPIT_API_URL",
                ),
            ),
            (
                mailbox_provider,
                _selected_binding_destination(
                    candidate,
                    "KP_WORKER_REPORTED_MAILBOX_URL",
                    "KP_WORKER_MAILPIT_API_URL",
                ),
            ),
            ("KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN", "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD"),
            mailbox_provider in {"mailpit", "microsoft365"},
        ),
        (
            "SMTP provider or destination",
            (
                current.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp",
                _selected_binding_destination(current, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP"),
            ),
            (
                email_provider,
                _selected_binding_destination(candidate, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP"),
            ),
            ("KP_WORKER_SMTP_PASSWORD",),
            email_provider == "smtp",
        ),
        (
            "ACS provider or endpoint",
            (
                current.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp",
                current.get("KP_WORKER_ACS_EMAIL_ENDPOINT", ""),
            ),
            (email_provider, candidate.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")),
            ("KP_WORKER_ACS_EMAIL_CONNECTION_STRING",),
            email_provider == "azure_communication_services",
        ),
    )
    for label, previous_identity, candidate_identity, credential_keys, active in bindings:
        if not active or previous_identity == candidate_identity:
            continue
        existing_credentials = tuple(key for key in credential_keys if current.get(key, "").strip())
        if existing_credentials and any(not desired.get(key, "").strip() for key in existing_credentials):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"changing the {label} requires re-entering every configured credential in the same save; "
                    "blank secret fields cannot preserve credentials across destinations"
                ),
            )


def _validate_env_fields(values: dict[str, str]) -> None:
    """Validate every proposed field before creating staging or recovery files."""
    for key, value in values.items():
        if key not in _ALLOWED_KEYS:
            raise PermissionDeniedError(f"rejected configuration keys: {[key]}")
        if "\x00" in value or "\r" in value or "\n" in value:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} must be a single-line value",
            )
        if key in _SECRET_KEYS and value and not value.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} cannot be a whitespace-only secret",
            )
        if len(value.encode("utf-8")) > _MAX_ENV_VALUE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} exceeds the configuration value size limit",
            )


def _safe_env_mode(original_mode: int | None) -> int:
    """Preserve an owner-readable mode only when it does not expose secrets."""
    if original_mode is None:
        return 0o600
    mode = stat.S_IMODE(original_mode)
    # Owner read/write plus optional group read is sufficiently restrictive for
    # a local secret-bearing env file. Never retain execute, group-write, or
    # any world permission from a mistakenly permissive source file.
    if mode in {0o600, 0o640}:
        return mode
    return 0o600


def _write_private_file(fd: int, content: bytes) -> None:
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()


def _fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_env_file(source: Path, target: Path) -> None:
    os.replace(source, target)


def _create_recovery_copy(path: Path, content: bytes) -> Path:
    descriptor, raw_recovery = tempfile.mkstemp(
        prefix=f"{path.name}.recovery.",
        suffix=".bak",
        dir=path.parent,
    )
    recovery = Path(raw_recovery)
    try:
        os.fchmod(descriptor, 0o600)
        _write_private_file(descriptor, content)
        _fsync_path(recovery)
    except Exception:
        # This copy belongs only to the failed current attempt and was never a
        # valid recovery artifact. Older recovery copies are never touched.
        with suppress(OSError):
            recovery.unlink(missing_ok=True)
        raise
    return recovery


def _restore_original_after_sync_failure(
    path: Path,
    original: bytes,
    original_existed: bool,
    mode: int,
    directory_fd: int,
) -> bool:
    """Best-effort rollback when the post-replace directory sync fails."""
    try:
        if not original_existed:
            path.unlink(missing_ok=True)
            with suppress(OSError):
                os.fsync(directory_fd)
            return True
        descriptor, raw_rollback = tempfile.mkstemp(
            prefix=f"{path.name}.rollback.",
            suffix=".tmp",
            dir=path.parent,
        )
        rollback = Path(raw_rollback)
        try:
            _write_private_file(descriptor, original)
            os.chmod(rollback, mode)
            # Even a repeated sync error must not prevent restoring the
            # original logical contents. The retained recovery copy remains
            # the durability fallback if the filesystem cannot sync.
            with suppress(OSError):
                _fsync_path(rollback)
            _replace_env_file(rollback, path)
            with suppress(OSError):
                os.fsync(directory_fd)
            return True
        finally:
            rollback.unlink(missing_ok=True)
    except OSError:
        return False


def _atomic_update_env(
    path: Path,
    desired: dict[str, str],
    *,
    validate_candidate: Callable[[dict[str, str]], None] | None = None,
) -> list[str]:
    """Apply a complete env update with one durable, recoverable replacement.

    A process-local lock prevents same-process thread races, while an advisory
    lock on the containing directory coordinates independent API processes
    without creating lock metadata before validation. All mutation happens in
    an isolated file on the same filesystem as the target.
    """
    parent = path.parent
    staged: Path | None = None
    replaced = False
    original = b""
    original_existed = False
    mode = 0o600
    directory_fd = -1
    with _ENV_UPDATE_THREAD_LOCK:
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
            fcntl.flock(directory_fd, fcntl.LOCK_EX)
            try:
                original = path.read_bytes()
                original_existed = True
                mode = _safe_env_mode(path.stat().st_mode)
            except FileNotFoundError:
                original = b""
                original_existed = False
                mode = 0o600

            current = _env_values(path)
            effective = {key: value for key, value in desired.items() if not (key in _SECRET_KEYS and not value)}
            _validate_env_fields(effective)
            _require_fresh_credentials_for_rebound_destinations(current, desired)
            candidate = {**current, **effective}
            if validate_candidate is not None:
                validate_candidate(candidate)
            changed = [key for key, value in effective.items() if current.get(key, "") != value]
            if not changed:
                return []

            descriptor, raw_staged = tempfile.mkstemp(
                prefix=f"{path.name}.staged.",
                suffix=".tmp",
                dir=parent,
            )
            staged = Path(raw_staged)
            os.fchmod(descriptor, 0o600)
            _write_private_file(descriptor, original)
            for key in changed:
                result = set_key(str(staged), key, effective[key])
                if result[0] is not True:
                    raise _AtomicEnvUpdateError("configuration staging failed")

            staged_values = _env_values(staged)
            if any(staged_values.get(key) != effective[key] for key in changed):
                raise _AtomicEnvUpdateError("configuration staging verification failed")
            os.chmod(staged, mode)
            _fsync_path(staged)
            _create_recovery_copy(path, original)
            os.fsync(directory_fd)
            _replace_env_file(staged, path)
            staged = None
            replaced = True
            try:
                os.fsync(directory_fd)
            except OSError:
                restored = _restore_original_after_sync_failure(
                    path,
                    original,
                    original_existed,
                    mode,
                    directory_fd,
                )
                replaced = not restored
                raise
            return changed
        except (HTTPException, PermissionDeniedError):
            raise
        except Exception:
            message = "configuration update failed"
            if not replaced:
                message += "; original configuration is unchanged"
            else:
                message += "; use the retained recovery copy"
            raise _AtomicEnvUpdateError(message) from None
        finally:
            if staged is not None:
                with suppress(OSError):
                    staged.unlink(missing_ok=True)
            if directory_fd >= 0:
                try:
                    fcntl.flock(directory_fd, fcntl.LOCK_UN)
                finally:
                    os.close(directory_fd)


def _console_password(path: Path) -> str | None:
    return _env_values(path).get(CONSOLE_PASSWORD_KEY)


def _verify_console_password(path: Path, supplied: str) -> bool:
    stored = _console_password(path)
    if not stored:
        return False
    return hmac.compare_digest(stored, supplied)
