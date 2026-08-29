from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

import kp_operator_api.routers as routers_module
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from kp_authorization.rbac import Principal, Role
from kp_operator_api.routers import (
    CampaignAudienceUpdate,
    _domain_verification_key,
    _roe_signing_key,
    update_campaign_audience,
)
from kp_telemetry.errors import ValidationError_


class _SecretSettings:
    def require_domain_verification_key(self) -> bytes:
        raise RuntimeError("password=must-not-log path=/private/domain-key")

    def require_roe_signing_key(self) -> bytes:
        raise RuntimeError("token=must-not-log path=/private/roe-key")


@pytest.mark.parametrize(
    ("load_key", "expected_detail"),
    [
        (_domain_verification_key, "domain verification key is unavailable"),
        (_roe_signing_key, "Rules-of-Engagement signing key is unavailable"),
    ],
)
def test_missing_signing_keys_have_stable_non_reflective_500s(
    load_key: Any,
    expected_detail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = FastAPI()

    @app.get("/failure")
    def failure() -> dict[str, bool]:
        load_key(cast(Any, _SecretSettings()))
        return {"ok": True}

    with TestClient(app) as client:
        response = client.get("/failure")

    assert response.status_code == 500
    assert response.json() == {"detail": expected_detail}
    rendered = f"{response.text}\n{caplog.text}"
    assert "must-not-log" not in rendered
    assert "/private/" not in rendered
    assert "Traceback" not in rendered


@pytest.mark.parametrize(
    ("backend_message", "public_message"),
    [
        ("sample_seed is required when sample_size is set", "sample_seed is required when sample_size is set"),
        ("password=must-not-log postgresql://internal/private", "campaign audience configuration is invalid"),
    ],
)
def test_audience_validation_uses_only_allowlisted_feedback(
    backend_message: str,
    public_message: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    campaign_id = uuid.uuid4()
    monkeypatch.setattr(
        routers_module,
        "_get_campaign",
        lambda _session, _campaign_id: SimpleNamespace(campaign_id=campaign_id),
    )

    def fail_configuration(*_args: object, **_kwargs: object) -> None:
        raise ValueError(backend_message)

    monkeypatch.setattr(routers_module, "configure_campaign_audience", fail_configuration)
    with pytest.raises(ValidationError_) as captured:
        update_campaign_audience(
            campaign_id,
            CampaignAudienceUpdate(),
            session=cast(Any, object()),
            audit=cast(Any, object()),
            principal=Principal(str(uuid.uuid4()), {Role.CAMPAIGN_AUTHOR}),
        )

    assert captured.value.message == public_message
    rendered = f"{captured.value.message}\n{caplog.text}"
    assert "password=must-not-log" not in rendered
    assert "postgresql://" not in rendered
    assert "Traceback" not in rendered
