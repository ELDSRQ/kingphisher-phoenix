"""Role-based access control.

Implements the reconstructed spec: the seven roles from AUTH-002, positive and
negative permission checks, and the hard rule that an author cannot approve
their own campaign.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Set
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar

_CAPABILITY_PART = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


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
    DELETE_DATA: ClassVar[Capability]
    APPROVE_PATTERN: ClassVar[Capability]
    APPROVE_TEMPLATE: ClassVar[Capability]
    MANAGE_ROLES: ClassVar[Capability]
    USE_KILL_SWITCH: ClassVar[Capability]
    SUBSCRIBE_ALERTS: ClassVar[Capability]
    VERIFY_DOMAIN: ClassVar[Capability]
    SIGN_ROE: ClassVar[Capability]
    MANAGE_QUEUE: ClassVar[Capability]

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or _CAPABILITY_PART.fullmatch(self.action) is None:
            raise ValueError("capability action is invalid")
        if not isinstance(self.object, str) or _CAPABILITY_PART.fullmatch(self.object) is None:
            raise ValueError("capability object is invalid")


# Capability identifiers used across the platform. Defined once here as class
# attributes (so `Capability.CREATE_CAMPAIGN` works) and aliased to module-level
# names (so `from kp_authorization import CREATE_CAMPAIGN` works).
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
Capability.DELETE_DATA = Capability("delete", "data")
Capability.APPROVE_PATTERN = Capability("approve", "pattern")
Capability.APPROVE_TEMPLATE = Capability("approve", "template")
Capability.MANAGE_ROLES = Capability("manage", "roles")
Capability.USE_KILL_SWITCH = Capability("use", "kill_switch")
Capability.SUBSCRIBE_ALERTS = Capability("subscribe", "alerts")
Capability.VERIFY_DOMAIN = Capability("verify", "sending_domain")
Capability.SIGN_ROE = Capability("sign", "rules_of_engagement")
Capability.MANAGE_QUEUE = Capability("manage", "job_queue")

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
DELETE_DATA = Capability.DELETE_DATA
APPROVE_PATTERN = Capability.APPROVE_PATTERN
APPROVE_TEMPLATE = Capability.APPROVE_TEMPLATE
MANAGE_ROLES = Capability.MANAGE_ROLES
USE_KILL_SWITCH = Capability.USE_KILL_SWITCH
SUBSCRIBE_ALERTS = Capability.SUBSCRIBE_ALERTS
VERIFY_DOMAIN = Capability.VERIFY_DOMAIN
SIGN_ROE = Capability.SIGN_ROE
MANAGE_QUEUE = Capability.MANAGE_QUEUE

_ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    Role.SOURCE_CURATOR: frozenset([SUBMIT_SOURCE, MANAGE_SOURCES, APPROVE_PATTERN, VIEW_AGGREGATE]),
    Role.CAMPAIGN_AUTHOR: frozenset([CREATE_CAMPAIGN, VIEW_AGGREGATE]),
    Role.SECURITY_APPROVER: frozenset(
        [APPROVE_SECURITY, APPROVE_TEMPLATE, VIEW_NAMED_RESULTS, VIEW_AGGREGATE, STOP_CAMPAIGN]
    ),
    Role.PRIVACY_APPROVER: frozenset(
        [
            APPROVE_PRIVACY,
            HANDLE_PRIVACY,
            DELETE_DATA,
            VIEW_NAMED_RESULTS,
            VIEW_AGGREGATE,
            MANAGE_EXCLUSIONS,
        ]
    ),
    Role.CAMPAIGN_OPERATOR: frozenset(
        [
            SCHEDULE_CAMPAIGN,
            SEND_CAMPAIGN,
            STOP_CAMPAIGN,
            USE_KILL_SWITCH,
            VIEW_AGGREGATE,
            MANAGE_RECIPIENTS,
            SUBSCRIBE_ALERTS,
            VERIFY_DOMAIN,
            SIGN_ROE,
            MANAGE_QUEUE,
        ]
    ),
    Role.AUDITOR: frozenset([VIEW_AUDIT, VIEW_NAMED_RESULTS, VIEW_AGGREGATE]),
    Role.ADMINISTRATOR: frozenset(
        [
            APPROVE_SECURITY,
            APPROVE_PRIVACY,
            CREATE_CAMPAIGN,
            SCHEDULE_CAMPAIGN,
            STOP_CAMPAIGN,
            SEND_CAMPAIGN,
            MANAGE_SOURCES,
            SUBMIT_SOURCE,
            VIEW_NAMED_RESULTS,
            VIEW_AGGREGATE,
            EXPORT_BULK,
            VIEW_AUDIT,
            MANAGE_RECIPIENTS,
            MANAGE_EXCLUSIONS,
            HANDLE_PRIVACY,
            DELETE_DATA,
            APPROVE_PATTERN,
            APPROVE_TEMPLATE,
            MANAGE_ROLES,
            USE_KILL_SWITCH,
            SUBSCRIBE_ALERTS,
            VERIFY_DOMAIN,
            SIGN_ROE,
            MANAGE_QUEUE,
        ]
    ),
}


@dataclass(frozen=True)
class Principal:
    """Authenticated caller. `subject_id` is the opaque principal identifier."""

    subject_id: str
    roles: Set[Role] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.subject_id, str)
            or not self.subject_id
            or self.subject_id != self.subject_id.strip()
            or len(self.subject_id) > 255
            or any(ord(character) < 32 or ord(character) == 127 for character in self.subject_id)
        ):
            raise ValueError("principal subject identifier is required")
        # Authentication adapters commonly build a mutable ``set``. Snapshot
        # it here so later caller mutation cannot change the authority already
        # attached to this authenticated principal. Invalid runtime members
        # remain fail-closed rather than acquiring StrEnum-equivalent grants.
        try:
            roles = frozenset(role for role in self.roles if isinstance(role, Role))
        except TypeError as exc:
            raise ValueError("principal roles must be an iterable of roles") from exc
        object.__setattr__(self, "roles", roles)

    @property
    def principal_id(self) -> str:
        """Backward-compatible alias for `subject_id`."""
        return self.subject_id

    def has_role(self, role: Role) -> bool:
        if not isinstance(role, Role):
            return False
        return role in self.roles

    def capabilities(self) -> frozenset[Capability]:
        caps: set[Capability] = set()
        for role in self.roles:
            caps.update(_ROLE_CAPABILITIES[role])
        return frozenset(caps)

    def can(self, capability: Capability) -> bool:
        return capability in self.capabilities()


class AuthorizationError(PermissionError):
    """Raised when a principal lacks the capability (KP-003)."""


def require(principal: Principal, capability: Capability) -> None:
    if not principal.can(capability):
        # Do not put an opaque subject identifier into exception text: callers
        # may surface or aggregate this message. Audit code already has the
        # authenticated principal as structured context.
        raise AuthorizationError(f"required capability is not assigned: {capability.action}:{capability.object}")


def require_any(principal: Principal, *capabilities: Capability) -> None:
    if not any(principal.can(capability) for capability in capabilities):
        names = ", ".join(f"{c.action}:{c.object}" for c in capabilities)
        suffix = f": {names}" if names else ""
        raise AuthorizationError(f"none of the required capabilities are assigned{suffix}")


def self_approval_blocked(principal: Principal, author_id: str, object_type: str) -> None:
    """CAMP-002: an author cannot approve their own campaign."""
    try:
        same_subject = uuid.UUID(principal.subject_id) == uuid.UUID(author_id)
    except (AttributeError, TypeError, ValueError):
        same_subject = principal.subject_id == author_id
    if same_subject:
        raise AuthorizationError("self-approval is prohibited")


def roles_for_names(names: Iterable[str]) -> set[Role]:
    if isinstance(names, (str, bytes)):
        raise ValueError("role names must be an iterable of canonical names")
    resolved: set[Role] = set()
    try:
        for name in names:
            if not isinstance(name, str):
                raise ValueError("role names must be strings")
            try:
                resolved.add(Role(name))
            except ValueError:
                raise ValueError("unknown role name") from None
    except TypeError as exc:
        raise ValueError("role names must be an iterable of canonical names") from exc
    return resolved
