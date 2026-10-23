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
    asset_usage,
    retire_asset,
    upload_asset,
)
from kp_sanitization.image_asset import inspect_raster_image
from kp_telemetry.errors import ConflictError, PermissionDeniedError, ValidationError_

_KEK = "01" * 32
_HMAC = "02" * 32
_CONSOLE_JWT = "03" * 32
_BODY = (
    f'<table><tr><td><p style="color:#005a9c">Security notice</p>'
    f'<a href="{TRAINING_URL_PLACEHOLDER}">Verify</a></td></tr></table>'
)


def _png(width: int, height: int, *, compression_level: int = -1) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress((b"\x00" + b"\xff\xff\xff" * width) * height, level=compression_level)
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

    def scalars(self, _statement: Any) -> list[Any]:
        # The usage route Python-filters on edited_content; the DB-side WHERE is
        # only a prefilter, so returning every stored TemplateVersion is faithful.
        return [v for (model, _id), v in self.store.items() if model is TemplateVersion]


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
    assert template.safe_html.index("width:100%") < template.safe_html.index("max-height:48px")


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


def test_apply_banner_logo_decorative_all_coexist() -> None:
    template = _template()
    banner = _approved_asset(dm.AssetKind.BANNER)
    logo = _approved_asset(dm.AssetKind.LOGO)
    decorative = _approved_asset(dm.AssetKind.DECORATIVE)
    session = _Session(template, banner, logo, decorative)
    _apply(session, template, banner)
    _apply(session, template, logo)
    result = _apply(session, template, decorative)
    assert sorted(result["applied_slots"]) == ["banner", "decorative", "logo"]
    # Decorative no longer evicts the banner: three distinct images are present.
    assert template.safe_html.count("<img") == 3
    assert template.edited_content["assets"].keys() == {"banner", "logo", "decorative"}


@pytest.mark.parametrize("existing_slot", [False, True], ids=["single-large-image", "combined-slots-too-large"])
def test_apply_oversized_body_rejects_without_changing_template(existing_slot: bool) -> None:
    template = _template()
    asset = _approved_asset(dm.AssetKind.BANNER)
    # Both images are valid uploads; base64 expansion can exceed the HTML cap
    # either alone or when combined with another occupied slot.
    size = 250 if existing_slot else 350
    content = _png(size, size, compression_level=0)
    info = inspect_raster_image(content)
    asset.content = content
    asset.byte_size = info.byte_size
    asset.sha256 = info.sha256
    session, audit = _Session(template, asset), _Audit()
    if existing_slot:
        _apply(session, template, asset)
        asset = _approved_asset(dm.AssetKind.LOGO)
        asset.content = content
        asset.byte_size = info.byte_size
        asset.sha256 = info.sha256
        session.add(asset)

    previous_html = template.safe_html
    previous_edited = template.edited_content
    previous_commits = session.commits
    with pytest.raises(ValidationError_, match="too large"):
        apply_asset_to_template(
            template.template_version_id,
            ApplyAssetRequest(asset_id=asset.asset_id),
            settings=_settings(),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            principal=_principal(),
        )
    assert template.safe_html == previous_html
    assert template.edited_content == previous_edited
    assert session.commits == previous_commits
    assert audit.events == []


def test_apply_preserves_allowed_body_images_and_removes_disallowed_images() -> None:
    allowed = "https://brand.example/logo.png"
    blocked = "https://untrusted.example/pixel.png"
    template = _template(safe_html=f'<img src="{allowed}" /><img src="{blocked}" />' + _BODY)
    asset = _approved_asset(dm.AssetKind.BANNER)
    settings = _settings()
    settings.safe_html_image_hosts = "brand.example"
    session = _Session(template, asset)
    apply_asset_to_template(
        template.template_version_id,
        ApplyAssetRequest(asset_id=asset.asset_id),
        settings=settings,
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert allowed in template.safe_html
    assert blocked not in template.safe_html
    assert template.safe_html.count("<img") == 2
    assert TRAINING_URL_PLACEHOLDER in template.safe_html


# --- retire -----------------------------------------------------------------


def test_retire_approved_asset_supersedes() -> None:
    asset = _approved_asset(dm.AssetKind.BANNER)  # already APPROVED
    session = _Session(asset)
    audit = _Audit()
    result = retire_asset(asset.asset_id, session=session, audit=audit, principal=_principal())  # type: ignore[arg-type]
    assert result["approval_state"] == "superseded"
    assert asset.approval_state == dm.AssetApprovalState.SUPERSEDED
    assert audit.events[0]["action"] == "asset.retire"


def test_retire_rejects_non_approved_asset() -> None:
    asset = _approved_asset(dm.AssetKind.BANNER)
    asset.approval_state = dm.AssetApprovalState.DRAFT
    with pytest.raises(ConflictError):
        retire_asset(asset.asset_id, session=_Session(asset), audit=_Audit(), principal=_principal())  # type: ignore[arg-type]


def test_retired_asset_cannot_be_applied() -> None:
    template = _template()
    asset = _approved_asset(dm.AssetKind.BANNER)
    asset.approval_state = dm.AssetApprovalState.SUPERSEDED
    with pytest.raises(ConflictError):
        _apply(_Session(template, asset), template, asset)


# --- usage ------------------------------------------------------------------


def test_usage_lists_templates_that_applied_the_asset() -> None:
    using = _template()
    other = _template()
    banner = _approved_asset(dm.AssetKind.BANNER)
    logo = _approved_asset(dm.AssetKind.LOGO)
    session = _Session(using, other, banner, logo)
    _apply(session, using, banner)
    _apply(session, using, logo)
    _apply(session, other, logo)

    banner_usage = asset_usage(banner.asset_id, session=session, _principal=_principal())  # type: ignore[arg-type]
    assert banner_usage["template_count"] == 1
    assert banner_usage["templates"][0]["template_version_id"] == str(using.template_version_id)
    assert banner_usage["templates"][0]["slots"] == ["banner"]

    logo_usage = asset_usage(logo.asset_id, session=session, _principal=_principal())  # type: ignore[arg-type]
    assert logo_usage["template_count"] == 2


def test_usage_empty_when_asset_unused() -> None:
    template = _template()
    unused = _approved_asset(dm.AssetKind.BANNER)
    session = _Session(template, unused)
    result = asset_usage(unused.asset_id, session=session, _principal=_principal())  # type: ignore[arg-type]
    assert result["template_count"] == 0
    assert result["templates"] == []
