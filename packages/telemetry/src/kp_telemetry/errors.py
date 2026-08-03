"""Error taxonomy from the reconstructed spec §27.2.

Each error code maps to a fail-closed behavior. Services should raise
KpError subclasses and translate them to HTTP/queue outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    VALIDATION = "KP-001"
    AUTHENTICATION = "KP-002"
    AUTHORIZATION = "KP-003"
    NOT_FOUND = "KP-004"
    CONFLICT = "KP-005"
    DEPENDENCY_UNAVAILABLE = "KP-006"
    SAFETY_REJECTION = "KP-007"
    AUDIT_FAILURE = "KP-008"
    KILL_SWITCH_ACTIVE = "KP-009"
    CONTRACT_VIOLATION = "KP-010"


@dataclass
class KpError(Exception):
    code: ErrorCode
    message: str
    http_status: int = 500
    detail: dict[str, Any] | None = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ValidationError_(KpError):
    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(ErrorCode.VALIDATION, message, http_status=422, detail=detail)


class AuthenticationError(KpError):
    def __init__(self, message: str = "authentication failed") -> None:
        super().__init__(ErrorCode.AUTHENTICATION, message, http_status=401)


class PermissionDeniedError(KpError):
    def __init__(self, message: str = "permission denied") -> None:
        super().__init__(ErrorCode.AUTHORIZATION, message, http_status=403)


class NotFoundError(KpError):
    def __init__(self, message: str = "not found") -> None:
        super().__init__(ErrorCode.NOT_FOUND, message, http_status=404)


class ConflictError(KpError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.CONFLICT, message, http_status=409)


class DependencyUnavailableError(KpError):
    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(ErrorCode.DEPENDENCY_UNAVAILABLE, message, http_status=503, detail=detail)


class SafetyRejectionError(KpError):
    """GEN-004: deterministic safety validator rejected content."""

    def __init__(self, message: str, reasons: list[str] | None = None) -> None:
        super().__init__(
            ErrorCode.SAFETY_REJECTION,
            message,
            http_status=422,
            detail={"reasons": reasons or []},
        )


class AuditFailureError(KpError):
    """KP-008: no mutation may succeed without a successful audit write."""

    def __init__(self, message: str = "audit write failed; operation not performed") -> None:
        super().__init__(ErrorCode.AUDIT_FAILURE, message, http_status=503)


class KillSwitchActiveError(KpError):
    def __init__(self, message: str = "kill switch is active") -> None:
        super().__init__(ErrorCode.KILL_SWITCH_ACTIVE, message, http_status=503)


class ContractViolationError(KpError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.CONTRACT_VIOLATION, message, http_status=500)
