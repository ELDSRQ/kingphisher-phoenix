"""Sending-domain onboarding wizard + signed Rules-of-Engagement routes.

Extracted from ``kp_operator_api.routers`` (facade keeps the module object and
re-exports the names below so test imports and in-module references keep
working).  The routes register on their own prefixless :class:`APIRouter`
which ``routers.router`` includes at the same position the cluster occupied,
preserving route registration order.

Trust boundary: every route in this module is operator-facing behind the
shared bearer gate and per-route capability checks; RoE signing and domain
verification fail closed (missing keys raise stable non-reflective 500s).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import RulesOfEngagement, VerifiedDomain
from kp_domain_models.roe import (
    ROE_SIGNATURE_VERSION,
    normalize_roe_domains,
    roe_signature_hex,
)
from kp_domain_verification.lookalike import candidate_sending_domains
from kp_domain_verification.verification import (
    RelayKind,
    normalize_domain,
    required_dns_records,
    verify_domain,
)
from kp_telemetry.errors import ConflictError, NotFoundError, ValidationError_
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1")

_GUI_COLLECTION_MAX_LIMIT = 200
_GUI_COLLECTION_MAX_OFFSET = 10_000


def _domain_verification_failure(error: str | None) -> str:
    if error == "challenge TXT record not found":
        return "domain not verified: challenge TXT record not found"
    if error is not None and error.startswith("not a usable domain:"):
        return "not a usable domain"
    if error is not None and error.startswith("dns error:"):
        return "domain verification unavailable because the DNS lookup failed"
    return "domain verification failed"


# --- Sending-domain onboarding wizard + signed Rules-of-Engagement ---------


class SendingDomainChallenge(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    relay: RelayKind = "smtp"
    relay_address: str | None = Field(default=None, max_length=64)
    dmarc_address: str | None = Field(default=None, max_length=255)


class SendingDomainVerify(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class LookalikeRequest(BaseModel):
    brand: str = Field(min_length=1, max_length=128)
    base_domain: str = Field(min_length=1, max_length=253)
    limit: int = Field(default=6, ge=1, le=10)
    relay: RelayKind = "smtp"
    relay_address: str | None = Field(default=None, max_length=64)
    dmarc_address: str | None = Field(default=None, max_length=255)


class RoeCreate(BaseModel):
    authorizing_party: str = Field(min_length=1, max_length=255)
    terms: str = Field(min_length=1, max_length=8192)
    window_start: datetime
    window_end: datetime
    target_domains: list[str] = Field(min_length=1, max_length=100)


class RoeRevoke(BaseModel):
    reason: str | None = Field(default=None, max_length=1024)


def _domain_verification_key(settings: OperatorApiSettings) -> bytes:
    try:
        return settings.require_domain_verification_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="domain verification key is unavailable") from exc


def _roe_signing_key(settings: OperatorApiSettings) -> bytes:
    try:
        return settings.require_roe_signing_key()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="Rules-of-Engagement signing key is unavailable") from exc


@router.post("/sending-domains/challenge", status_code=status.HTTP_200_OK)
def sending_domain_challenge(
    body: SendingDomainChallenge,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Mint the ownership challenge for a sending domain and the DNS records.

    The TXT value is deterministic per domain under the deployment's
    verification key, so re-requesting the challenge never rotates it mid-
    verification. The records block is the exact thing to paste into the
    operator's DNS zone (challenge TXT, provider SPF, DMARC, DKIM placeholder).
    """
    domain = normalize_domain(body.domain)
    if domain is None:
        raise ValidationError_("not a usable domain")
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    records = required_dns_records(
        domain,
        signing_key=key,
        relay=body.relay,
        relay_address=body.relay_address,
        dmarc_address=body.dmarc_address,
    )
    return {
        "domain": domain,
        "status": "awaiting_dns",
        "dns_records": [
            {"type": r.record_type, "name": r.name, "value": r.value, "ttl": r.ttl, "note": r.note} for r in records
        ],
    }


@router.post("/sending-domains/verify", status_code=status.HTTP_200_OK)
def sending_domain_verify(
    body: SendingDomainVerify,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Check the challenge TXT in live DNS and record the proof of control.

    Fail-closed: a DNS error, a missing record, or a wrong value is reported
    as unverified and nothing is recorded. Only after this succeeds may the
    domain be named as an RoE target domain or used as a sending domain.
    """
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    result = verify_domain(body.domain, signing_key=key)
    if not result.verified:
        raise ValidationError_(_domain_verification_failure(result.error))
    existing = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == result.domain))
    now = datetime.now(UTC)
    if existing is None:
        existing = VerifiedDomain(
            verified_domain_id=uuid.uuid4(),
            domain=result.domain,
            challenge_token=result.token or "",
            verified_at=now,
            verified_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
        )
        session.add(existing)
    else:
        existing.verified_at = now
        existing.verified_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
        existing.active = True
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="domain.verify",
        object_type="verified_domain",
        object_id=result.domain,
        detail={"verified": True},
    )
    session.commit()
    return {"domain": result.domain, "verified": True}


@router.get("/sending-domains", status_code=status.HTTP_200_OK)
def list_sending_domains(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    rows = list(
        session.scalars(
            select(VerifiedDomain)
            .order_by(VerifiedDomain.verified_at.desc(), VerifiedDomain.verified_domain_id.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return {"domains": [{"domain": row.domain, "verified_at": row.verified_at, "active": row.active} for row in rows]}


@router.post("/sending-domains/{domain}/revoke", status_code=status.HTTP_200_OK)
def revoke_sending_domain(
    domain: str,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Retire a verified domain: it can no longer be named in a new RoE.

    Delivery is unaffected: an RoE already signed over the domain remains the
    authorization until that RoE is revoked or its window ends — verification
    is the precondition for signing, not a live delivery check.
    """
    row = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == domain))
    if row is None:
        raise NotFoundError("verified domain not found")
    if not row.active:
        raise ConflictError("domain is already revoked")
    row.active = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="domain.revoke",
        object_type="verified_domain",
        object_id=domain,
    )
    session.commit()
    return {"domain": domain, "active": False}


@router.get("/sending-domains/generate", status_code=status.HTTP_200_OK)
def lookalike_candidates(
    request: Request,
    brand: str,
    base_domain: str,
    limit: int = 6,
    relay: RelayKind = "smtp",
    relay_address: str | None = None,
    dmarc_address: str | None = None,
    principal: Principal = Depends(require_capability(Capability.VERIFY_DOMAIN)),
) -> dict[str, Any]:
    """Candidate sending hostnames for a lure brand, with ready-to-paste DNS.

    Every candidate is a subdomain of an operator-controlled base domain:
    registerable by definition, and it joins the sending pool only after the
    same DNS challenge verifies.
    """
    settings = request.app.state.settings
    key = _domain_verification_key(settings)
    if normalize_domain(base_domain) is None:
        raise ValidationError_("not a usable base domain")
    candidates = candidate_sending_domains(
        base_domain,
        brand,
        limit=limit,
        signing_key=key,
        relay=relay,
        relay_address=relay_address,
        dmarc_address=dmarc_address,
    )
    return {
        "candidates": [
            {
                "domain": candidate.domain,
                "dns_records": [
                    {"type": r.record_type, "name": r.name, "value": r.value, "ttl": r.ttl, "note": r.note}
                    for r in candidate.records
                ],
            }
            for candidate in candidates
        ]
    }


@router.post("/roe", status_code=status.HTTP_201_CREATED)
def create_roe(
    body: RoeCreate,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    """Sign a Rules-of-Engagement over verified target domains.

    Signature version 2 binds the terms hash, authorizing party, normalized
    domain set, full engagement window, signer, and signing time. Every target
    domain must be active and DNS-verified; self-asserted scope is rejected.
    """
    if body.window_end <= body.window_start:
        raise ValidationError_("window_end must be after window_start")
    if body.window_start.tzinfo is None or body.window_end.tzinfo is None:
        raise ValidationError_("RoE window timestamps must include a timezone offset")
    authorizing_party = body.authorizing_party.strip()
    domains: list[str] = []
    for raw in body.target_domains:
        domain = normalize_domain(raw)
        if domain is None:
            raise ValidationError_("not a usable target domain")
        verified = session.scalar(select(VerifiedDomain).where(VerifiedDomain.domain == domain))
        if verified is None or not verified.active:
            raise ValidationError_("one or more target domains are not DNS-verified")
        domains.append(domain)
    domains = list(normalize_roe_domains(domains))

    now = datetime.now(UTC)
    terms_hash = hashlib.sha256(body.terms.encode("utf-8")).hexdigest()
    signing_key = _roe_signing_key(request.app.state.settings)
    signature = roe_signature_hex(
        terms_hash,
        principal.principal_id,
        now,
        authorizing_party=authorizing_party,
        target_domains=domains,
        window_start=body.window_start,
        window_end=body.window_end,
        signature_version=ROE_SIGNATURE_VERSION,
        signing_key=signing_key,
    )
    roe = RulesOfEngagement(
        roe_id=uuid.uuid4(),
        signer=principal.principal_id,
        authorizing_party=authorizing_party,
        terms_text=body.terms,
        terms_hash=terms_hash,
        signature=signature,
        signature_version=ROE_SIGNATURE_VERSION,
        signed_at=now,
        window_start=body.window_start,
        window_end=body.window_end,
        target_domains=domains,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    session.add(roe)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="roe.sign",
        object_type="rules_of_engagement",
        object_id=str(roe.roe_id),
        detail={
            "terms_hash": terms_hash,
            "authorizing_party": authorizing_party,
            "window_start": body.window_start.isoformat(),
            "window_end": body.window_end.isoformat(),
            "target_domains": domains,
            "signature": signature,
            "signature_version": ROE_SIGNATURE_VERSION,
        },
    )
    session.commit()
    return {
        "roe_id": str(roe.roe_id),
        "signer": principal.principal_id,
        "terms_hash": terms_hash,
        "signature": signature,
        "signature_version": ROE_SIGNATURE_VERSION,
        "signed_at": now.isoformat(),
    }


@router.get("/roe", status_code=status.HTTP_200_OK)
def list_roes(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    rows = list(
        session.scalars(
            select(RulesOfEngagement)
            .order_by(RulesOfEngagement.signed_at.desc(), RulesOfEngagement.roe_id.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return {
        "roes": [
            {
                "roe_id": str(row.roe_id),
                "signer": row.signer,
                "authorizing_party": row.authorizing_party,
                "terms_hash": row.terms_hash,
                "signature": row.signature,
                "signature_version": row.signature_version,
                "signed_at": row.signed_at,
                "window_start": row.window_start,
                "window_end": row.window_end,
                "target_domains": list(row.target_domains or []),
                "revoked_at": row.revoked_at,
                "revoked_reason": row.revoked_reason,
            }
            for row in rows
        ]
    }


@router.post("/roe/{roe_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_roe(
    roe_id: uuid.UUID,
    body: RoeRevoke,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SIGN_ROE)),
) -> dict[str, Any]:
    """Revoke an RoE immediately: delivery of its campaigns fails closed.

    The row is kept for the audit trail; only the revocation fields change.
    """
    roe = session.get(RulesOfEngagement, roe_id)
    if roe is None:
        raise NotFoundError("rules of engagement not found")
    if roe.revoked_at is not None:
        raise ConflictError("rules of engagement already revoked")
    roe.revoked_at = datetime.now(UTC)
    roe.revoked_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
    roe.revoked_reason = body.reason
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="roe.revoke",
        object_type="rules_of_engagement",
        object_id=str(roe.roe_id),
        detail={"reason": body.reason},
    )
    session.commit()
    return {"roe_id": str(roe.roe_id), "revoked_at": roe.revoked_at}
