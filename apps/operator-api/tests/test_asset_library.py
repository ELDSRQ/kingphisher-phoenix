"""Route-level tests for the reusable image-asset library.

Hermetic: the route functions are called directly with a fake session/audit (no
DB), mirroring test_template_logo. Proves upload validates raster bytes and
stores a DRAFT, approval enforces separation of duties and gates use, and
applying an APPROVED asset inlines it into ``safe_html`` as a data:image that
survives the sanitizer + SafetyValidator, with deterministic banner/logo slots.
"""

from __future__ import annotations

import base64
import struct
import uuid
import zlib
from typing import Any

import pytest
from kp_authorization import Principal, Role
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import TemplateAsset, TemplateVersion
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.routes.assets import (
    ApplyAssetRequest,
    AssetApprovalRequest,
    AssetUploadRequest,
    apply_asset_to_template,
    approve_asset,
    upload_asset,
)
from kp_telemetry.errors import ConflictError, PermissionDeniedError, ValidationError_

_KEK = "01" * 32
_HMAC = "02" * 32
_CONSOLE_JWT = "03" * 32
_BODY = (
    f'<table><tr><td><p style="color:#005a9c">Security notice</p>'
    f'<a href="{TRAINING_URL_PLACEHOLDER}">Verify</a></td></tr></table>'
)


def _png(width: int, height: int) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress((b"\x00" + b"\xff\xff\xff" * width) * height)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


class _Session:
    def __init__(self, *objects: Any) -> None:
        self.store: dict[Any, Any] = {}
        for obj in objects:
            self._index(obj)
        self.commits = 0

    def _index(self, obj: Any) -> None:
        if isinstance(obj, TemplateAsset):
            self.store[(TemplateAsset, obj.asset_id)] = obj
        elif isinstance(obj, TemplateVersion):
            self.store[(TemplateVersion, obj.template_version_id)] = obj

    def get(self, model: Any, identifier: uuid.UUID) -> Any:
        return self.store.get((model, identifier))

    def add(self, obj: Any) -> None:
        self._index(obj)

    def commit(self) -> None:
        self.commits += 1

    def refresh(self, _obj: Any) -> None:
        pass


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **event: Any) -> None:
        self.events.append(event)


def _settings(policy: ApprovalPolicy = ApprovalPolicy.ENFORCE) -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=_HMAC,
        ciphertext_kek=_KEK,
        console_jwt_secret=_CONSOLE_JWT,
        console_static_dir="/nonexistent-console-dir",
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        approval_policy=policy,
    )


def _principal() -> Principal:
    return Principal(str(uuid.uuid4()), {Role.SECURITY_APPROVER})


def _template(
    state: dm.TemplateApprovalState = dm.TemplateApprovalState.DRAFT,
    safe_html: str | None = _BODY,
) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        version=1,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="a" * 64,
        raw_proposal={},
        subject="Security notice",
        plain_text=f"Review {TRAINING_URL_PLACEHOLDER}",
        safe_html=safe_html,
        approval_state=state,
    )


def _approved_asset(kind: dm.AssetKind, uploader: uuid.UUID | None = None) -> TemplateAsset:
    content = _png(8, 8)
    return TemplateAsset(
        asset_id=uuid.uuid4(),
        kind=kind,
        name=f"{kind.value}-asset",
        media_type="image/png",
        width=8,
        height=8,
        byte_size=len(content),
        sha256="b" * 64,
        content=content,
        provenance={"generator": "FLUX.2-klein-4B"},
        approval_state=dm.AssetApprovalState.APPROVED,
        requested_by=uploader or uuid.uuid4(),
    )


# --- upload -----------------------------------------------------------------

def test_upload_valid_png_stores_draft() -> None:
    session, audit = _Session(), _Audit()
    body = AssetUploadRequest(
        kind=dm.AssetKind.BANNER,
        name="ms365 banner",
        brand="microsoft",
        content_base64=base64.b64encode(_png(600, 188)).decode(),
        provenance={"generator": "FLUX.2-klein-4B", "seed": 7},
    )
    result = upload_asset(body, session=session, audit=audit, principal=_principal())  # type: ignore[arg-type]
    assert result["kind"] == "banner"
    assert result["approval_state"] == "draft"
    assert result["media_type"] == "image/png"
    assert (result["width"], result["height"]) == (600, 188)
    assert session.commits == 1
    assert audit.events[0]["action"] == "asset.upload"


def test_upload_rejects_svg() -> None:
    body = AssetUploadRequest(
        kind=dm.AssetKind.LOGO,
        name="evil",
        content_base64=base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg"/>').decode(),
    )
    with pytest.raises(ValidationError_):
        upload_asset(body, session=_Session(), audit=_Audit(), principal=_principal())  # type: ignore[arg-type]


def test_upload_rejects_bad_base64() -> None:
    body = AssetUploadRequest(kind=dm.AssetKind.LOGO, name="x", content_base64="not*base64*")
    with pytest.raises(ValidationError_):
        upload_asset(body, session=_Session(), audit=_Audit(), principal=_principal())  # type: ignore[arg-type]


# --- approve ----------------------------------------------------------------

def test_approve_rejects_self_review_under_enforce() -> None:
    uploader = _principal()
    asset = _approved_asset(dm.AssetKind.BANNER, uploader=uuid.UUID(uploader.principal_id))
    asset.approval_state = dm.AssetApprovalState.DRAFT
    session = _Session(asset)
    with pytest.raises(PermissionDeniedError):
        approve_asset(
            asset.asset_id,
            AssetApprovalRequest(decision=dm.ApprovalDecision.APPROVED),
            settings=_settings(ApprovalPolicy.ENFORCE),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=uploader,
        )


def test_approve_allows_self_review_single_operator_and_sets_hash() -> None:
    uploader = _principal()
    asset = _approved_asset(dm.AssetKind.BANNER, uploader=uuid.UUID(uploader.principal_id))
    asset.approval_state = dm.AssetApprovalState.DRAFT
    session = _Session(asset)
    result = approve_asset(
        asset.asset_id,
        AssetApprovalRequest(decision=dm.ApprovalDecision.APPROVED),
        settings=_settings(ApprovalPolicy.SINGLE_OPERATOR),
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        principal=uploader,
    )
    assert result["approval_state"] == "approved"
    assert asset.approval_hash and len(asset.approval_hash) == 64


def test_approve_conflicts_when_not_draft() -> None:
    asset = _approved_asset(dm.AssetKind.BANNER)  # already APPROVED
    with pytest.raises(ConflictError):
        approve_asset(
            asset.asset_id,
            AssetApprovalRequest(decision=dm.ApprovalDecision.APPROVED),
            settings=_settings(),
            session=_Session(asset),  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=_principal(),
        )


# --- apply to template ------------------------------------------------------

def _apply(session: _Session, template: TemplateVersion, asset: TemplateAsset) -> dict[str, Any]:
    return apply_asset_to_template(
        template.template_version_id,
        ApplyAssetRequest(asset_id=asset.asset_id),
        settings=_settings(),
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        principal=_principal(),
    )


def test_apply_banner_inlines_data_image_and_preserves_link() -> None:
    template = _template()
    asset = _approved_asset(dm.AssetKind.BANNER)
    result = _apply(_Session(template, asset), template, asset)
    assert "data:image/png;base64" in template.safe_html
    assert TRAINING_URL_PLACEHOLDER in template.safe_html
    assert result["applied_slots"] == ["banner"]
    assert template.edited_content["assets"]["banner"].startswith("data:image/png;base64,")


def test_apply_banner_then_logo_are_both_present_banner_first() -> None:
    template = _template()
    banner = _approved_asset(dm.AssetKind.BANNER)
    logo = _approved_asset(dm.AssetKind.LOGO)
    session = _Session(template, banner, logo)
    _apply(session, template, banner)
    result = _apply(session, template, logo)
    assert sorted(result["applied_slots"]) == ["banner", "logo"]
    # banner block (full-width img) precedes the centered logo block
    assert template.safe_html.count("<img") == 2
    assert template.safe_html.index('width:100%') < template.safe_html.index("max-height:48px")


def test_apply_rejects_unapproved_asset() -> None:
    template = _template()
    asset = _approved_asset(dm.AssetKind.BANNER)
    asset.approval_state = dm.AssetApprovalState.DRAFT
    with pytest.raises(ConflictError):
        _apply(_Session(template, asset), template, asset)


def test_apply_rejects_non_draft_template() -> None:
    template = _template(state=dm.TemplateApprovalState.APPROVED)
    asset = _approved_asset(dm.AssetKind.BANNER)
    with pytest.raises(ConflictError):
        _apply(_Session(template, asset), template, asset)
    assert template.safe_html == _BODY  # unchanged


def test_apply_rejects_template_without_body() -> None:
    template = _template(safe_html="   ")
    asset = _approved_asset(dm.AssetKind.BANNER)
    with pytest.raises(ValidationError_):
        _apply(_Session(template, asset), template, asset)
