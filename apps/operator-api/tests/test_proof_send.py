"""UX-011 §2b — proof send to the SERVER-DESIGNATED test mailbox.

The property these tests exist to defend: **a caller cannot influence where a
proof send goes.** The destination is derived only from server state (the
`Recipient.is_test_account` designation that a `manage:recipients` holder sets
under audit), it is never read from the request, and an attempt to supply one
is a 422 rather than a silently ignored field.

The rest of the suite pins the surrounding fences: capability, campaign state,
throttle, emergency stop, recipient-domain allowlist (fail-closed under
PLT-002), RoE coverage, the "never a live recipient of this campaign" rule,
audit on both success and every refusal, and the absence of ANY campaign,
recipient, assignment, token or approval mutation.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from kp_authorization.rbac import Principal, Role
from kp_database.models import Campaign, Recipient, RulesOfEngagement, SystemSafetyState
from kp_domain_models import models as dm
from kp_operator_api import routers
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app
from kp_telemetry.errors import ConflictError, ValidationError_

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

DESIGNATED = "proof-mailbox@corp.example"
ATTACKER = "attacker@evil.example"


def _settings(**overrides: Any) -> OperatorApiSettings:
    values: dict[str, Any] = {
        "audit_hmac_key": HMAC,
        "ciphertext_kek": KEK,
        "console_jwt_secret": CONSOLE_JWT,
        "allowed_recipient_domains": "corp.example",
    }
    values.update(overrides)
    return OperatorApiSettings(**values)


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)

    @property
    def actions(self) -> list[str]:
        return [record["action"] for record in self.records]

    @property
    def reasons(self) -> list[str]:
        return [record["detail"].get("reason") for record in self.records]


class _Scalars:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def first(self) -> Any:
        return self._rows[0] if self._rows else None


class _Session:
    """Records every write attempt so "mutates nothing" can be asserted."""

    def __init__(
        self,
        *,
        campaign: Any,
        test_accounts: list[Recipient],
        stop_engaged: bool = False,
        roe: RulesOfEngagement | None = None,
        assignment_id: uuid.UUID | None = None,
    ) -> None:
        self.campaign = campaign
        self.test_accounts = test_accounts
        self.roe = roe
        self.assignment_id = assignment_id
        self.safety = SimpleNamespace(emergency_stop_engaged=stop_engaged, generation=1)
        self.commits = 0
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.executed: list[Any] = []
        self.enqueued: list[dict[str, Any]] = []

    def get(self, model: Any, identifier: Any, **_kwargs: Any) -> Any:
        if model is Campaign:
            return self.campaign if identifier == self.campaign.campaign_id else None
        if model is SystemSafetyState:
            return self.safety
        if model is RulesOfEngagement:
            return self.roe
        return None

    def scalars(self, statement: Any) -> _Scalars:
        assert statement.column_descriptions[0]["entity"] is Recipient
        return _Scalars(sorted(self.test_accounts, key=lambda row: row.recipient_id))

    def scalar(self, _statement: Any) -> Any:
        return self.assignment_id

    def execute(self, statement: Any, params: Any = None) -> Any:
        self.executed.append((statement, params))
        if isinstance(params, dict) and "topic" in params:
            self.enqueued.append(params)
        return SimpleNamespace(rowcount=1)

    def add(self, value: Any) -> None:  # pragma: no cover - must never happen
        self.added.append(value)

    def delete(self, value: Any) -> None:  # pragma: no cover - must never happen
        self.deleted.append(value)

    def commit(self) -> None:
        self.commits += 1


def _campaign(state: dm.CampaignState = dm.CampaignState.DRAFT, roe_id: uuid.UUID | None = None) -> Any:
    return SimpleNamespace(
        campaign_id=uuid.uuid4(),
        title="Quarterly drill",
        state=state,
        current_template_id=uuid.uuid4(),
        manifest_hash="a" * 64,
        roe_id=roe_id,
        created_by=uuid.uuid4(),
    )


def _recipient(mailbox: str, *, is_test_account: bool = True, recipient_id: uuid.UUID | None = None) -> Recipient:
    return Recipient(
        recipient_id=recipient_id or uuid.uuid4(),
        employee_key="ek",
        mailbox=mailbox,
        mailbox_sha256="b" * 64,
        display_name="Proof Mailbox",
        is_test_account=is_test_account,
        status=dm.RecipientStatus.ACTIVE,
        deleted_at=None,
    )


def _request(settings: OperatorApiSettings) -> Any:
    return SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=settings,
                user_limiter=None,
                audit_store=SimpleNamespace(dispatch_pending_queue=lambda _queue: 0),
                queue=object(),
            )
        )
    )


def _principal(role: Role = Role.CAMPAIGN_AUTHOR) -> Principal:
    return Principal(subject_id=str(uuid.uuid4()), roles={role})


def _call(
    session: _Session,
    audit: _Audit,
    *,
    settings: OperatorApiSettings | None = None,
    principal: Principal | None = None,
    body: routers.ProofSendRequest | None = None,
    request: Any = None,
) -> dict[str, Any]:
    resolved_settings = settings or _settings()
    resolved_request = request if request is not None else _request(resolved_settings)
    return routers.proof_send_campaign(
        campaign_id=session.campaign.campaign_id,
        body=body or routers.ProofSendRequest(confirm=True, reason="see how the lure lands"),
        request=resolved_request,  # type: ignore[arg-type]
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=principal or _principal(),
    )


# --------------------------------------------------------------------------
# THE property: the destination is server-derived and unreachable by a caller
# --------------------------------------------------------------------------


def test_destination_is_derived_from_the_server_designated_test_account() -> None:
    designated = _recipient(DESIGNATED)
    session = _Session(campaign=_campaign(), test_accounts=[designated])
    audit = _Audit()

    result = _call(session, audit)

    assert result["destination"] == "server_designated_test_account"
    assert result["proof_recipient_id"] == str(designated.recipient_id)
    # The queue payload carries an id the server chose, and NO mailbox at all.
    (queued,) = session.enqueued
    assert queued["topic"] == "deliver"
    assert DESIGNATED not in queued["payload"]
    payload = json.loads(queued["payload"])
    assert payload["job_type"] == "proof_send"
    assert payload["proof_recipient_id"] == str(designated.recipient_id)
    assert not any("mail" in key or key == "to" for key in payload)


def test_a_client_supplied_destination_is_rejected_not_ignored() -> None:
    for field in ("mailbox", "recipient_id", "to", "email", "destination", "proof_recipient_id"):
        with pytest.raises(ValueError):
            routers.ProofSendRequest(confirm=True, reason="probe", **{field: ATTACKER})


def test_a_client_supplied_destination_is_rejected_over_http() -> None:
    settings = _settings()
    app = create_app(settings)
    app.state.audit_health_check = lambda: True
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["campaign_author"]},
    }
    token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/campaigns/{uuid.uuid4()}/proof-send",
            json={"confirm": True, "reason": "probe", "mailbox": ATTACKER},
            headers={"Authorization": f"Bearer {token}"},
        )
    # Rejected on request validation, before any database or provider work: a
    # smuggled destination is a hard 422, never a silently dropped field.
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any(error["type"] == "extra_forbidden" and error["loc"][-1] == "mailbox" for error in errors)


def test_only_designated_active_test_accounts_are_eligible() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[])
    with pytest.raises(ConflictError, match="no server-designated test account"):
        _call(session, _Audit())


def test_selection_is_deterministic_and_not_influenced_by_row_order() -> None:
    low = _recipient("low@corp.example", recipient_id=uuid.UUID(int=1))
    high = _recipient("high@corp.example", recipient_id=uuid.UUID(int=2))
    forward = _Session(campaign=_campaign(), test_accounts=[low, high])
    reverse = _Session(campaign=_campaign(), test_accounts=[high, low])

    assert _call(forward, _Audit())["proof_recipient_id"] == str(low.recipient_id)
    assert _call(reverse, _Audit())["proof_recipient_id"] == str(low.recipient_id)


# --------------------------------------------------------------------------
# Fences
# --------------------------------------------------------------------------


def test_engaged_emergency_stop_refuses_and_is_audited() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)], stop_engaged=True)
    audit = _Audit()

    with pytest.raises(ConflictError, match="emergency stop"):
        _call(session, audit)

    assert session.enqueued == []
    assert audit.actions == ["campaign.proof-send.blocked"]
    assert audit.reasons == ["global_emergency_stop"]


def test_unset_allowlist_fails_closed_outside_a_marked_dev_stack() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
    with pytest.raises(ValidationError_, match="KP_ALLOWED_RECIPIENT_DOMAINS"):
        _call(session, _Audit(), settings=_settings(allowed_recipient_domains=""))
    assert session.enqueued == []


def test_a_designated_mailbox_outside_the_allowlist_is_refused() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient("proof@elsewhere.example")])
    audit = _Audit()

    with pytest.raises(ConflictError, match="allowlist"):
        _call(session, audit)

    assert session.enqueued == []
    assert audit.reasons == ["domain_not_allowed"]


def test_a_bound_roe_still_binds_the_proof_destination() -> None:
    roe_id = uuid.uuid4()
    roe = SimpleNamespace(roe_id=roe_id, target_domains=["other.example"])
    session = _Session(
        campaign=_campaign(roe_id=roe_id),
        test_accounts=[_recipient(DESIGNATED)],
        roe=roe,  # type: ignore[arg-type]
    )
    audit = _Audit()

    with pytest.raises(ConflictError, match="Rules-of-Engagement"):
        _call(session, audit)

    assert session.enqueued == []
    assert audit.reasons == ["target_domain_not_roe_covered"]


def test_a_mailbox_this_campaign_already_contacts_is_never_proofed() -> None:
    session = _Session(
        campaign=_campaign(),
        test_accounts=[_recipient(DESIGNATED)],
        assignment_id=uuid.uuid4(),
    )
    audit = _Audit()

    with pytest.raises(ConflictError, match="already a recipient"):
        _call(session, audit)

    assert session.enqueued == []
    assert audit.reasons == ["recipient_already_assigned"]


def test_only_pre_decision_campaign_states_can_be_proofed() -> None:
    for state in (dm.CampaignState.APPROVED, dm.CampaignState.SCHEDULED, dm.CampaignState.ACTIVE):
        session = _Session(campaign=_campaign(state), test_accounts=[_recipient(DESIGNATED)])
        audit = _Audit()
        with pytest.raises(ConflictError, match="draft or pending approval"):
            _call(session, audit)
        assert session.enqueued == []
        assert audit.reasons == ["campaign_state_not_proofable"]

    for state in (dm.CampaignState.DRAFT, dm.CampaignState.PENDING_APPROVAL):
        session = _Session(campaign=_campaign(state), test_accounts=[_recipient(DESIGNATED)])
        assert _call(session, _Audit())["queued"] is True


def test_confirmation_and_reason_are_required() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
    with pytest.raises(ValidationError_, match="confirm"):
        _call(session, _Audit(), body=routers.ProofSendRequest(confirm=False, reason="x"))
    with pytest.raises(ValidationError_, match="reason"):
        _call(session, _Audit(), body=routers.ProofSendRequest(confirm=True, reason="   "))
    assert session.enqueued == []


def test_repeat_requests_are_throttled_and_the_refusal_is_audited() -> None:
    settings = _settings()
    request = _request(settings)
    principal = _principal()
    audit = _Audit()
    sessions = [
        _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
        for _ in range(routers._PROOF_SEND_ACTOR_LIMIT + 1)
    ]

    for session in sessions[:-1]:
        assert _call(session, audit, settings=settings, principal=principal, request=request)["queued"] is True

    with pytest.raises(HTTPException) as excinfo:
        _call(sessions[-1], audit, settings=settings, principal=principal, request=request)
    assert excinfo.value.status_code == 429
    assert sessions[-1].enqueued == []
    assert audit.reasons[-1] == "throttled"


def test_the_deployment_wide_window_caps_a_crowd_of_actors() -> None:
    settings = _settings()
    request = _request(settings)
    audit = _Audit()
    refused = 0
    # Each actor gets a fresh per-actor window, so only the deployment-wide
    # limiter can stop this.
    for _ in range(routers._PROOF_SEND_GLOBAL_LIMIT + 3):
        session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
        try:
            _call(session, audit, settings=settings, principal=_principal(), request=request)
        except HTTPException as exc:
            assert exc.status_code == 429
            refused += 1
    assert refused == 3


# --------------------------------------------------------------------------
# Audit + "changes nothing"
# --------------------------------------------------------------------------


def test_a_successful_proof_is_audited_and_mutates_no_campaign_state() -> None:
    campaign = _campaign()
    before = dict(vars(campaign))
    designated = _recipient(DESIGNATED)
    session = _Session(campaign=campaign, test_accounts=[designated])
    audit = _Audit()

    _call(session, audit)

    assert vars(campaign) == before
    assert session.added == []
    assert session.deleted == []
    # The only statement executed is the transactional-outbox insert.
    assert len(session.executed) == 1 and session.enqueued
    (record,) = audit.records
    assert record["action"] == "campaign.proof-send.queued"
    assert record["object_type"] == "campaign"
    assert record["detail"]["destination"] == "server_designated_test_account"
    assert record["detail"]["proof_recipient_id"] == str(designated.recipient_id)


def test_no_tracking_token_or_assignment_is_created() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
    _call(session, _Audit())
    (queued,) = session.enqueued
    for forbidden in ("tracking_bearers", "recipient_assignment_ids", "launch_manifest_hash", "test_send"):
        assert forbidden not in queued["payload"]
    assert '"job_type"' in queued["payload"] and "proof_send" in queued["payload"]


def test_the_masked_mailbox_stays_behind_view_named_results() -> None:
    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
    author = _call(session, _Audit(), principal=_principal(Role.CAMPAIGN_AUTHOR))
    assert "masked_mailbox" not in author

    session = _Session(campaign=_campaign(), test_accounts=[_recipient(DESIGNATED)])
    approver = _call(session, _Audit(), principal=_principal(Role.SECURITY_APPROVER))
    assert approver["masked_mailbox"] and DESIGNATED not in approver["masked_mailbox"]


def test_the_action_flag_reflects_state_and_capability_without_a_destination() -> None:
    campaign = _campaign()
    flags = routers._campaign_action_flags(
        campaign,  # type: ignore[arg-type]
        None,
        [],
        _principal(Role.CAMPAIGN_AUTHOR),
        routers.ApprovalPolicy.ENFORCE,
    )
    assert flags["can_proof_send"] is True
    assert flags["can_test_send"] is False

    scheduled = _campaign(dm.CampaignState.SCHEDULED)
    assert (
        routers._campaign_action_flags(
            scheduled,  # type: ignore[arg-type]
            None,
            [],
            _principal(Role.CAMPAIGN_AUTHOR),
            routers.ApprovalPolicy.ENFORCE,
        )["can_proof_send"]
        is False
    )
    assert (
        routers._campaign_action_flags(
            campaign,  # type: ignore[arg-type]
            None,
            [],
            _principal(Role.AUDITOR),
            routers.ApprovalPolicy.ENFORCE,
        )["can_proof_send"]
        is False
    )
