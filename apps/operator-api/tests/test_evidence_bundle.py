"""UX-011 §7 — read-only campaign evidence bundle (evidence.zip).

A single artefact answering "who approved this, under which RoE, against which
launch manifest and canary evidence". It is a projection of existing rows behind
the existing EXPORT_BULK capability; it never contains mailboxes or display
names, and it computes a per-member sha256 manifest.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from kp_database.models import Campaign, CampaignApproval, CampaignLaunchGate, RulesOfEngagement
from kp_domain_models import models as dm
from kp_operator_api import routers


def _campaign(roe_id):  # noqa: ANN001, ANN202
    now = datetime.now(UTC)
    return SimpleNamespace(
        campaign_id=uuid4(),
        title="Evidence drill",
        state=dm.CampaignState.COMPLETED,
        schedule_start=now - timedelta(days=2),
        schedule_end=now - timedelta(days=1),
        sender_mailbox="drills@corp.example",
        sender_display_name="IT Security",
        manifest_hash="a" * 64,
        training_resource_id=uuid4(),
        training_resource_version=1,
        training_resource_digest="b" * 64,
        roe_id=roe_id,
    )


def _gate(campaign_id):  # noqa: ANN001, ANN202
    return SimpleNamespace(
        state="full_published",
        review_manifest_hash="c" * 64,
        content_manifest_hash="d" * 64,
        template_approval_hash="e" * 64,
        audience_manifest_hash="f" * 64,
        canary_manifest_hash="1" * 64,
        canary_evidence_hash="2" * 64,
        provider="acs",
        provider_config_hash="3" * 64,
        submitted_by=uuid4(),
    )


def _approval():  # noqa: ANN202
    return SimpleNamespace(
        approval_type=dm.ApprovalType.SECURITY,
        approver_id=uuid4(),
        decision=dm.ApprovalDecision.APPROVED,
        rationale="Checklist complete",
        decided_at=datetime.now(UTC),
        launch_manifest_hash="c" * 64,
    )


def _roe(roe_id):  # noqa: ANN001, ANN202
    now = datetime.now(UTC)
    return SimpleNamespace(
        roe_id=roe_id,
        signer="alice@corp.example",
        authorizing_party="Acme CISO",
        terms_hash="9" * 64,
        signature_version=2,
        signed_at=now - timedelta(days=10),
        window_start=now - timedelta(days=5),
        window_end=now + timedelta(days=5),
        target_domains=["corp.example"],
        revoked_at=None,
    )


class _Rows:
    def __init__(self, rows) -> None:  # noqa: ANN001
        self._rows = rows

    def __iter__(self):  # noqa: ANN204
        return iter(self._rows)


class _EvidenceSession:
    def __init__(self, campaign, gate, approvals, roe) -> None:  # noqa: ANN001
        self._campaign = campaign
        self._gate = gate
        self._approvals = approvals
        self._roe = roe

    def get(self, model, _key, **_kwargs):  # noqa: ANN001, ANN202
        if model is Campaign:
            return self._campaign
        if model is CampaignLaunchGate:
            return self._gate
        if model is RulesOfEngagement:
            return self._roe
        return None

    def scalars(self, statement):  # noqa: ANN001, ANN202
        assert statement.column_descriptions[0]["entity"] is CampaignApproval
        return _Rows(self._approvals)


def _bundle(session) -> dict[str, bytes]:  # noqa: ANN001
    response = routers.campaign_evidence_bundle(
        campaign_id=uuid4(), session=session, _principal=object()  # type: ignore[arg-type]
    )
    assert response.media_type == "application/zip"
    assert "evidence.zip" in response.headers["Content-Disposition"]
    with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_evidence_bundle_contains_approvals_roe_and_manifest() -> None:
    roe_id = uuid4()
    campaign = _campaign(roe_id)
    session = _EvidenceSession(campaign, _gate(campaign.campaign_id), [_approval()], _roe(roe_id))
    members = _bundle(session)

    assert set(members) == {"campaign.json", "approvals.json", "roe.json", "manifest.sha256"}

    campaign_doc = json.loads(members["campaign.json"])
    assert campaign_doc["content_manifest_hash"] == "a" * 64
    assert campaign_doc["launch_gate"]["canary_evidence_hash"] == "2" * 64

    approvals_doc = json.loads(members["approvals.json"])
    assert approvals_doc[0]["approval_type"] == "security"
    assert approvals_doc[0]["decision"] == "approved"

    roe_doc = json.loads(members["roe.json"])
    assert roe_doc["signer"] == "alice@corp.example"
    assert roe_doc["target_domains"] == ["corp.example"]

    # No mailboxes/display names anywhere in the bundle.
    blob = b"".join(members.values())
    assert b"@" in blob  # sender/signer addresses are allowed
    assert b"person" not in blob.lower()

    # manifest.sha256 lists a correct digest for every other member.
    manifest = members["manifest.sha256"].decode()
    for name in ("approvals.json", "campaign.json", "roe.json"):
        assert f"{hashlib.sha256(members[name]).hexdigest()}  {name}" in manifest


def test_evidence_bundle_handles_a_campaign_with_no_roe() -> None:
    campaign = _campaign(None)
    session = _EvidenceSession(campaign, _gate(campaign.campaign_id), [], None)
    members = _bundle(session)
    assert json.loads(members["roe.json"]) is None
    assert json.loads(members["approvals.json"]) == []
