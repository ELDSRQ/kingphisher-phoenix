from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_authorization import Principal, Role
from kp_operator_api.auth import require_any_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_session
from kp_operator_api.main import create_app
from kp_operator_api.routers import (
    ApprovalSubmit,
    CampaignCreate,
    ExclusionCreate,
    ExclusionRevoke,
    PrivacyFulfillment,
    PrivacyRequestCreate,
    SourceCreate,
)
from kp_telemetry.errors import PermissionDeniedError
from pydantic import ValidationError

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


def _campaign_body(**overrides: object) -> dict[str, object]:
    start = datetime.now(UTC) + timedelta(hours=1)
    body: dict[str, object] = {
        "pattern_id": str(uuid4()),
        "template_version_id": str(uuid4()),
        "training_resource_id": str(uuid4()),
        "title": "Quarterly exercise",
        "sender_mailbox": "simulation@example.com",
        "training_domain": "training.example.com",
        "schedule_start": start.isoformat(),
        "schedule_end": (start + timedelta(hours=1)).isoformat(),
        "timezone": "UTC",
        "max_recipients": 10,
    }
    body.update(overrides)
    return body


def test_request_models_normalize_storage_bound_values() -> None:
    campaign = CampaignCreate.model_validate(
        _campaign_body(
            title="  Quarterly exercise  ",
            sender_mailbox="  Simulation@Example.COM ",
            training_domain="Training.Example.COM.",
            timezone=" UTC ",
        )
    )
    source = SourceCreate.model_validate(
        {"name": "  CISA advisories  ", "source_type": "rss", "base_domain": "WWW.CISA.GOV."}
    )
    privacy = PrivacyRequestCreate.model_validate(
        {"request_type": "access_export", "requester_mailbox": " Person@Example.COM "}
    )
    corrections = PrivacyFulfillment.model_validate(
        {"corrections": {"mailbox": " New.Person@Example.COM ", "display_name": " New Person "}}
    )

    assert campaign.title == "Quarterly exercise"
    assert campaign.sender_mailbox == "simulation@example.com"
    assert campaign.training_domain == "training.example.com"
    assert campaign.timezone == "UTC"
    assert source.name == "CISA advisories"
    assert source.base_domain == "www.cisa.gov"
    assert privacy.requester_mailbox == "person@example.com"
    assert corrections.corrections == {"mailbox": "new.person@example.com", "display_name": "New Person"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"title": "   "},
        {"sender_mailbox": "not-a-mailbox"},
        {"sender_mailbox": "header@example.com\r\nBcc: victim@example.com"},
        {"sender_mailbox": f"{'x' * 245}@example.com"},
        {"training_domain": "https://training.example.com/path"},
        {"timezone": "Not/A_Timezone"},
        {"schedule_start": datetime.now(), "schedule_end": datetime.now() + timedelta(hours=1)},
    ],
)
def test_campaign_model_rejects_values_the_browser_cannot_be_trusted_to_filter(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CampaignCreate.model_validate(_campaign_body(**overrides))


@pytest.mark.parametrize("domain", ["localhost", "https://feed.example/path", "feed.example:444", "bad domain"])
def test_source_model_rejects_non_host_base_domains(domain: str) -> None:
    with pytest.raises(ValidationError):
        SourceCreate.model_validate({"name": "Feed", "source_type": "rss", "base_domain": domain})


def test_source_create_rejects_client_selected_license_state() -> None:
    with pytest.raises(ValidationError):
        SourceCreate.model_validate(
            {
                "name": "Feed",
                "source_type": "rss",
                "base_domain": "feed.example.com",
                "license_state_id": str(uuid4()),
            }
        )


@pytest.mark.parametrize(
    "mailbox",
    [
        "",
        "person",
        "person@localhost",
        "two@@example.com",
        "a b@example.com",
        ".person@example.com",
        "a..b@example.com",
    ],
)
def test_privacy_request_rejects_malformed_mailboxes(mailbox: str) -> None:
    with pytest.raises(ValidationError):
        PrivacyRequestCreate.model_validate({"request_type": "deletion", "requester_mailbox": mailbox})


@pytest.mark.parametrize(
    "corrections",
    [
        {},
        {"unsupported": "value"},
        {"employee_key": None},
        {"employee_key": "   "},
        {"employee_key": "x" * 257},
        {"mailbox": None},
        {"mailbox": "invalid"},
        {"display_name": "x" * 257},
        {"department": "x" * 257},
    ],
)
def test_privacy_corrections_fail_before_database_mutation(corrections: dict[str, str | None]) -> None:
    with pytest.raises(ValidationError):
        PrivacyFulfillment.model_validate({"corrections": corrections})


def test_optional_rationales_are_trimmed_and_bounded() -> None:
    assert ApprovalSubmit.model_validate({"decision": "approved", "rationale": " reviewed "}).rationale == "reviewed"
    assert ExclusionCreate.model_validate({"exclusion_type": "global", "reason": " requested "}).reason == "requested"
    with pytest.raises(ValidationError):
        ApprovalSubmit.model_validate({"decision": "approved", "rationale": "x" * 2001})
    with pytest.raises(ValidationError):
        ExclusionCreate.model_validate({"exclusion_type": "global", "reason": "x" * 501})


def test_exclusion_lifecycle_rationales_and_expiry_are_strict() -> None:
    future = datetime.now(UTC) + timedelta(days=1)
    created = ExclusionCreate.model_validate(
        {
            "exclusion_type": "global",
            "reason": "  approved accommodation  ",
            "expires_at": future.isoformat(),
        }
    )
    revoked = ExclusionRevoke.model_validate({"confirm": True, "rationale": "  request withdrawn  "})

    assert created.reason == "approved accommodation"
    assert created.expires_at == future
    assert revoked.rationale == "request withdrawn"
    for invalid in (
        {"exclusion_type": "global"},
        {"exclusion_type": "global", "reason": "   "},
        {
            "exclusion_type": "global",
            "reason": "expired",
            "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        },
        {
            "exclusion_type": "global",
            "reason": "naive",
            "expires_at": (datetime.now() + timedelta(days=1)).isoformat(),
        },
        {"exclusion_type": "global", "reason": "valid", "unexpected": True},
    ):
        with pytest.raises(ValidationError):
            ExclusionCreate.model_validate(invalid)
    with pytest.raises(ValidationError):
        ExclusionRevoke.model_validate({"confirm": True, "rationale": " "})


def test_minimized_recipient_listing_accepts_managers_and_named_result_roles_only() -> None:
    from kp_authorization import Capability

    checker = require_any_capability(Capability.VIEW_NAMED_RESULTS, Capability.MANAGE_RECIPIENTS)

    assert checker(Principal(str(uuid4()), {Role.CAMPAIGN_OPERATOR})).has_role(Role.CAMPAIGN_OPERATOR)
    assert checker(Principal(str(uuid4()), {Role.AUDITOR})).has_role(Role.AUDITOR)
    with pytest.raises(PermissionDeniedError):
        checker(Principal(str(uuid4()), {Role.CAMPAIGN_AUTHOR}))


class _MissingSession:
    def get(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@pytest.fixture(scope="module")
def boundary_client() -> Iterator[TestClient]:
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        recipient_hash_salt="01" * 16,
        tracking_token_hmac_key="34" * 32,
        roe_signing_key="11" * 32,
        domain_verification_key="22" * 32,
        database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
        audit_database_url="postgresql+psycopg://unused:unused@localhost:1/unused",
    )
    app = create_app(settings)
    app.state.audit_verifier.status = "ok"
    app.state.audit_store = SimpleNamespace(
        outbox_health=lambda: {"overdue_pending": 0, "failed": 0, "dispatching_stale": 0}
    )

    def missing_session() -> Iterator[_MissingSession]:
        yield _MissingSession()

    app.dependency_overrides[get_session] = missing_session
    client = TestClient(app)
    yield client
    client.close()


def _headers() -> dict[str, str]:
    settings = OperatorApiSettings()
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "exp": 2_000_000_000,
            "nbf": 0,
            "realm_access": {"roles": ["administrator"]},
        },
        CONSOLE_JWT.encode(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/campaigns", _campaign_body(sender_mailbox="invalid")),
        ("/api/v1/sources", {"name": "Feed", "source_type": "rss", "base_domain": "https://bad"}),
        ("/api/v1/privacy/requests", {"request_type": "deletion", "requester_mailbox": "invalid"}),
        (
            f"/api/v1/privacy/requests/{uuid4()}/fulfill",
            {"corrections": {"employee_key": None}},
        ),
        (
            f"/api/v1/campaigns/{uuid4()}/approvals/security",
            {"decision": "approved", "rationale": "x" * 2001},
        ),
        (
            f"/api/v1/recipients/{uuid4()}/exclusions",
            {"exclusion_type": "global", "reason": "x" * 2001},
        ),
    ],
)
def test_direct_api_calls_apply_server_side_boundaries(
    boundary_client: TestClient,
    path: str,
    body: dict[str, object],
) -> None:
    response = boundary_client.post(path, json=body, headers=_headers())

    assert response.status_code == 422
    assert len(response.content) < 4096
    assert "Traceback" not in response.text
