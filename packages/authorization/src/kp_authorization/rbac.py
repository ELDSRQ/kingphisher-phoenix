"""Role-based access control.

Implements the reconstructed spec: the seven roles from AUTH-002, positive and
negative permission checks, and the hard rule that an author cannot approve
their own campaign.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar


class Role(StrEnum):
    SOURCE_CURATOR = "source_curator"
    CAMPAIGN_AUTHOR = "campaign_author"
    SECURITY_APPROVER = "security_approver"
    PRIVACY_APPROVER = "privacy_approver"
    CAMPAIGN_OPERATOR = "campaign_operator"
    AUDITOR = "auditor"
    ADMINISTRATOR = "administrator"


@dataclass(frozen=True)
class Capability:
    action: str
    object: str

    APPROVE_CAMPAIGN: ClassVar[Capability]
    APPROVE_SECURITY: ClassVar[Capability]
    APPROVE_PRIVACY: ClassVar[Capability]
    CREATE_CAMPAIGN: ClassVar[Capability]
    SCHEDULE_CAMPAIGN: ClassVar[Capability]
    STOP_CAMPAIGN: ClassVar[Capability]
    SEND_CAMPAIGN: ClassVar[Capability]
    MANAGE_SOURCES: ClassVar[Capability]
    SUBMIT_SOURCE: ClassVar[Capability]
    VIEW_NAMED_RESULTS: ClassVar[Capability]
    VIEW_AGGREGATE: ClassVar[Capability]
    EXPORT_BULK: ClassVar[Capability]
    VIEW_AUDIT: ClassVar[Capability]
    MANAGE_RECIPIENTS: ClassVar[Capability]
    MANAGE_EXCLUSIONS: ClassVar[Capability]
    HANDLE_PRIVACY: ClassVar[Capability]
    APPROVE_PATTERN: ClassVar[Capability]
    MANAGE_ROLES: ClassVar[Capability]
    USE_KILL_SWITCH: ClassVar[Capability]
    SUBSCRIBE_ALERTS: ClassVar[Capability]


# Capability identifiers used across the platform. Defined once here as class
# attributes (so `Capability.CREATE_CAMPAIGN` works) and aliased to module-level
# names (so `from kp_authorization import CREATE_CAMPAIGN` works).
Capability.APPROVE_CAMPAIGN = Capability("approve", "campaign")
Capability.APPROVE_SECURITY = Capability("approve_security", "campaign")
Capability.APPROVE_PRIVACY = Capability("approve_privacy", "campaign")
Capability.CREATE_CAMPAIGN = Capability("create", "campaign")
Capability.SCHEDULE_CAMPAIGN = Capability("schedule", "campaign")
Capability.STOP_CAMPAIGN = Capability("stop", "campaign")
Capability.SEND_CAMPAIGN = Capability("send", "campaign")
Capability.MANAGE_SOURCES = Capability("manage", "source")
Capability.SUBMIT_SOURCE = Capability("submit", "source")
Capability.VIEW_NAMED_RESULTS = Capability("view_named", "results")
Capability.VIEW_AGGREGATE = Capability("view_aggregate", "results")
Capability.EXPORT_BULK = Capability("export_bulk", "results")
Capability.VIEW_AUDIT = Capability("view", "audit")
Capability.MANAGE_RECIPIENTS = Capability("manage", "recipients")
Capability.MANAGE_EXCLUSIONS = Capability("manage", "exclusions")
Capability.HANDLE_PRIVACY = Capability("handle", "privacy_requests")
Capability.APPROVE_PATTERN = Capability("approve", "pattern")
Capability.MANAGE_ROLES = Capability("manage", "roles")
Capability.USE_KILL_SWITCH = Capability("use", "kill_switch")
Capability.SUBSCRIBE_ALERTS = Capability("subscribe", "alerts")

APPROVE_CAMPAIGN = Capability.APPROVE_CAMPAIGN
APPROVE_SECURITY = Capability.APPROVE_SECURITY
APPROVE_PRIVACY = Capability.APPROVE_PRIVACY
CREATE_CAMPAIGN = Capability.CREATE_CAMPAIGN
SCHEDULE_CAMPAIGN = Capability.SCHEDULE_CAMPAIGN
STOP_CAMPAIGN = Capability.STOP_CAMPAIGN
SEND_CAMPAIGN = Capability.SEND_CAMPAIGN
MANAGE_SOURCES = Capability.MANAGE_SOURCES
SUBMIT_SOURCE = Capability.SUBMIT_SOURCE
VIEW_NAMED_RESULTS = Capability.VIEW_NAMED_RESULTS
VIEW_AGGREGATE = Capability.VIEW_AGGREGATE
EXPORT_BULK = Capability.EXPORT_BULK
VIEW_AUDIT = Capability.VIEW_AUDIT
MANAGE_RECIPIENTS = Capability.MANAGE_RECIPIENTS
MANAGE_EXCLUSIONS = Capability.MANAGE_EXCLUSIONS
HANDLE_PRIVACY = Capability.HANDLE_PRIVACY
APPROVE_PATTERN = Capability.APPROVE_PATTERN
MANAGE_ROLES = Capability.MANAGE_ROLES
USE_KILL_SWITCH = Capability.USE_KILL_SWITCH
SUBSCRIBE_ALERTS = Capability.SUBSCRIBE_ALERTS

_ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    Role.SOURCE_CURATOR: frozenset([SUBMIT_SOURCE, MANAGE_SOURCES, APPROVE_PATTERN, VIEW_AGGREGATE]),
    Role.CAMPAIGN_AUTHOR: frozenset([CREATE_CAMPAIGN, VIEW_AGGREGATE]),
    Role.SECURITY_APPROVER: frozenset([APPROVE_CAMPAIGN, APPROVE_SECURITY, VIEW_NAMED_RESULTS,
                                       VIEW_AGGREGATE, STOP_CAMPAIGN]),
    Role.PRIVACY_APPROVER: frozenset([APPROVE_CAMPAIGN, APPROVE_PRIVACY, HANDLE_PRIVACY,
                                      VIEW_NAMED_RESULTS, VIEW_AGGREGATE, MANAGE_EXCLUSIONS]),
    Role.CAMPAIGN_OPERATOR: frozenset([SCHEDULE_CAMPAIGN, SEND_CAMPAIGN, STOP_CAMPAIGN,
                                       USE_KILL_SWITCH, VIEW_AGGREGATE, MANAGE_RECIPIENTS,
                                       APPROVE_CAMPAIGN, SUBSCRIBE_ALERTS]),
    Role.AUDITOR: frozenset([VIEW_AUDIT, VIEW_NAMED_RESULTS, VIEW_AGGREGATE]),
    Role.ADMINISTRATOR: frozenset([
        APPROVE_CAMPAIGN, APPROVE_SECURITY, APPROVE_PRIVACY, CREATE_CAMPAIGN, SCHEDULE_CAMPAIGN,
        STOP_CAMPAIGN, SEND_CAMPAIGN, MANAGE_SOURCES, SUBMIT_SOURCE, VIEW_NAMED_RESULTS,
        VIEW_AGGREGATE, EXPORT_BULK, VIEW_AUDIT, MANAGE_RECIPIENTS, MANAGE_EXCLUSIONS,
        HANDLE_PRIVACY, APPROVE_PATTERN, MANAGE_ROLES, USE_KILL_SWITCH, SUBSCRIBE_ALERTS,
    ]),
}


@dataclass
class Principal:
    """Authenticated caller. `subject_id` is the opaque principal identifier."""

    subject_id: str
    roles: set[Role] = field(default_factory=set)

    @property
    def principal_id(self) -> str:
        """Backward-compatible alias for `subject_id`."""
        return self.subject_id

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def capabilities(self) -> frozenset[Capability]:
        caps: set[Capability] = set()
        for role in self.roles:
            caps |= _ROLE_CAPABILITIES[role]
        return frozenset(caps)

    def can(self, capability: Capability) -> bool:
        return capability in self.capabilities()


class AuthorizationError(PermissionError):
    """Raised when a principal lacks the capability (KP-003)."""


def require(principal: Principal, capability: Capability) -> None:
    if not principal.can(capability):
        raise AuthorizationError(
            f"principal {principal.subject_id} lacks capability {capability.action}:{capability.object}"
        )


def require_any(principal: Principal, *capabilities: Capability) -> None:
    if not any(principal.can(capability) for capability in capabilities):
        names = ", ".join(f"{c.action}:{c.object}" for c in capabilities)
        raise AuthorizationError(
            f"principal {principal.subject_id} lacks any of: {names}"
        )


def self_approval_blocked(principal: Principal, author_id: str, object_type: str) -> None:
    """CAMP-002: an author cannot approve their own campaign."""
    if principal.subject_id == author_id:
        raise AuthorizationError(
            f"self-approval is prohibited: {object_type} author {author_id} may not approve own work"
        )


def roles_for_names(names: Iterable[str]) -> set[Role]:
    return {Role(name) for name in names}
