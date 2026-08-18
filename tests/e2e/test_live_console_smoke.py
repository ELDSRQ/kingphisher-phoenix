"""Opt-in, browserless smoke test for a running local stack.

Set ``KP_E2E_PASSWORD`` to enable the authenticated checks. The test deliberately
uses only Python's standard library so the release gate does not need a browser
binary or another package download.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import jwt
import pytest

OPERATOR_URL = os.getenv("KP_E2E_OPERATOR_URL", "http://127.0.0.1:8000").rstrip("/")
TRACKING_URL = os.getenv("KP_E2E_TRACKING_URL", "http://127.0.0.1:8001").rstrip("/")


@pytest.fixture(autouse=True, scope="module")
def _require_live_stack() -> None:
    if not os.getenv("KP_E2E_PASSWORD"):
        pytest.skip("set KP_E2E_PASSWORD to run live console smoke tests")


def _request(path: str, *, base: str = OPERATOR_URL, token: str | None = None) -> tuple[int, bytes, str]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(f"{base}{path}", headers=headers)  # noqa: S310 -- operator-provided HTTP(S) E2E target
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310
            return response.status, response.read(), response.headers.get_content_type()
    except HTTPError as error:
        return error.code, error.read(), error.headers.get_content_type()


def _json_request(
    path: str,
    *,
    token: str | None = None,
    method: str = "GET",
    body: dict[str, object] | None = None,
) -> tuple[int, object]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    request = Request(  # noqa: S310 -- guarded, operator-provided HTTP(S) E2E target
        f"{OPERATOR_URL}{path}", data=data, headers=headers, method=method
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, json.load(response)
    except HTTPError as error:
        try:
            payload: object = json.load(error)
        except json.JSONDecodeError:
            payload = error.read().decode(errors="replace")
        return error.code, payload


def _login() -> str:
    password = os.getenv("KP_E2E_PASSWORD")
    assert password
    request = Request(  # noqa: S310 -- operator-provided HTTP(S) E2E target
        f"{OPERATOR_URL}/api/v1/console/session",
        data=json.dumps({"password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:  # noqa: S310
        assert response.status == 200
        body = json.load(response)
    token = body.get("token")
    assert isinstance(token, str) and token
    return token


def _principal_token(*roles: str) -> str:
    secret = os.environ["OPERATOR_API_CONSOLE_JWT_SECRET"]
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": os.getenv("OPERATOR_API_OIDC_ISSUER", "http://localhost:8443/realms/kingphisher"),
            "aud": os.getenv("OPERATOR_API_OIDC_AUDIENCE", "kp-operator-api"),
            "nbf": now - timedelta(seconds=5),
            "exp": now + timedelta(minutes=10),
            "realm_access": {"roles": list(roles)},
        },
        secret,
        algorithm="HS256",
    )


def test_health_endpoints() -> None:
    assert _request("/healthz")[0] == 200
    assert _request("/healthz", base=TRACKING_URL)[0] == 200


def test_console_shell_and_assets() -> None:
    status, html, content_type = _request("/console/")
    assert status == 200
    assert content_type == "text/html"
    assert b"/console/app.js" in html and b"/console/styles.css" in html

    js_status, js, js_type = _request("/console/app.js")
    css_status, css, css_type = _request("/console/styles.css")
    assert (js_status, css_status) == (200, 200)
    assert js and css
    assert js_type in {"text/javascript", "application/javascript"}
    assert css_type == "text/css"
    assert b'api("/audit/verify"),' not in js
    assert js.count(b'api("/audit/verify", { method: "POST" })') >= 2


def test_login_and_core_api_authorization() -> None:
    unauthenticated, _, _ = _request("/api/v1/console/status")
    assert unauthenticated in {401, 403}

    token = _login()
    authenticated, payload, content_type = _request("/api/v1/console/status", token=token)
    assert authenticated == 200
    assert content_type == "application/json"
    assert isinstance(json.loads(payload), dict)


def test_single_administrator_campaign_lifecycle_and_alert_health() -> None:
    """Create and safely future-schedule a draft campaign with one local operator."""
    if os.getenv("KP_E2E_LIFECYCLE") != "1":
        pytest.skip("set KP_E2E_LIFECYCLE=1 to permit local lifecycle mutations")
    if urlparse(OPERATOR_URL).hostname not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("campaign lifecycle E2E is restricted to a loopback operator API")
    if not os.getenv("OPERATOR_API_CONSOLE_JWT_SECRET"):
        pytest.fail("OPERATOR_API_CONSOLE_JWT_SECRET is required to mint local dev principals")

    status, mode = _json_request("/api/v1/console/auth-mode")
    assert status == 200 and mode == {"auth_mode": "dev", "deployment_mode": "single_tenant"}

    administrator = _login()

    patterns_status, patterns = _json_request("/api/v1/patterns", token=administrator)
    templates_status, templates = _json_request("/api/v1/templates", token=administrator)
    recipients_status, recipients = _json_request("/api/v1/recipients", token=administrator)
    assert patterns_status == templates_status == 200
    assert recipients_status == 200
    approved_patterns = [row for row in patterns if row["approval_state"] == "approved"]  # type: ignore[union-attr]
    approved_templates = [row for row in templates if row["approval_state"] == "approved"]  # type: ignore[union-attr]
    assert approved_patterns and approved_templates, "seed at least one approved pattern and template"

    start = datetime.now(UTC) + timedelta(days=1)
    created_status, created = _json_request(
        "/api/v1/campaigns",
        token=administrator,
        method="POST",
        body={
            "pattern_id": approved_patterns[0]["campaign_pattern_id"],
            "template_version_id": approved_templates[0]["template_version_id"],
            "title": f"E2E readiness {uuid.uuid4()}",
            "sender_mailbox": "awareness@example.com",
            "training_domain": "example.com",
            "schedule_start": start.isoformat(),
            "schedule_end": (start + timedelta(hours=1)).isoformat(),
            "timezone": "UTC",
            # The campaign engine intentionally fails closed instead of
            # sampling when eligible recipients exceed the declared cap.
            "max_recipients": max(1, len(recipients)),  # type: ignore[arg-type]
        },
    )
    assert created_status == 201, created
    campaign_id = created["campaign_id"]  # type: ignore[index]

    subscription_status, subscription = _json_request(
        "/api/v1/alerts/subscriptions",
        token=administrator,
        method="POST",
        body={"campaign_id": campaign_id, "channel": "web"},
    )
    assert subscription_status == 201 and subscription["active"] is True  # type: ignore[index]

    scheduled_status, scheduled = _json_request(
        f"/api/v1/campaigns/{campaign_id}/schedule", token=administrator, method="POST"
    )
    assert scheduled_status == 200 and scheduled["state"] == "scheduled"  # type: ignore[index]

    alerts_status, alerts = _json_request(
        f"/api/v1/alerts/subscriptions?campaign_id={campaign_id}", token=administrator
    )
    assert alerts_status == 200 and any(item["active"] for item in alerts)  # type: ignore[union-attr]
    ntfy_status, ntfy = _json_request(
        "/api/v1/alerts/subscriptions",
        token=administrator,
        method="POST",
        body={
            "campaign_id": campaign_id,
            "channel": "ntfy",
            "destination_url": f"https://ntfy.sh/kp-disposable-{campaign_id}",
        },
    )
    assert ntfy_status == 201 and ntfy["active"] is True  # type: ignore[index]
    assert isinstance(ntfy["signing_secret"], str) and ntfy["signing_secret"]  # type: ignore[index]
    provider_status, provider = _json_request("/api/v1/console/status", token=administrator)
    assert provider_status == 200
    assert provider["operator_api"] and provider["tracking_api"]  # type: ignore[index]
    assert provider["postgres"] and provider["redis"]  # type: ignore[index]
    assert provider["workers"]["alert"] and provider["workers"]["directory"]  # type: ignore[index]


def test_onboarding_contract_and_local_connectors() -> None:
    administrator = _login()
    status, onboarding = _json_request("/api/v1/console/onboarding", token=administrator)
    assert status == 200
    assert isinstance(onboarding, dict)
    assert isinstance(onboarding.get("complete"), bool)
    steps = onboarding.get("steps")
    assert isinstance(steps, list)
    assert {step["id"] for step in steps} >= {"identity", "graph", "smtp", "mailbox", "ai", "training"}
    assert all(field.get("value", "") == "" for step in steps for field in step["fields"] if field["secret"])
    assert all(step.get("prerequisites") and step.get("estimated_minutes") for step in steps)
    assert all(field.get("where_to_find") for step in steps for field in step["fields"])

    for component in ("identity", "graph", "ai", "smtp"):
        test_status, result = _json_request(
            "/api/v1/console/onboarding/test",
            token=administrator,
            method="POST",
            body={"component": component, "values": {}},
        )
        assert test_status == 200 and result["ok"] is True, (component, result)  # type: ignore[index]

    sync_status, sync = _json_request("/api/v1/recipients/sync-directory", token=administrator, method="POST")
    assert sync_status == 202 and sync["queued"] is True  # type: ignore[index]
    job_id = sync["job_id"]  # type: ignore[index]
    for _ in range(10):
        audit_status, events = _json_request("/api/v1/audit", token=administrator)
        assert audit_status == 200
        if any(
            event.get("action") == "directory.sync" and event.get("object_id") == job_id
            for event in events  # type: ignore[union-attr]
        ):
            break
        time.sleep(0.5)
    else:
        pytest.fail("directory worker did not record a completed sync")


def test_azure_deployment_wizard_contract() -> None:
    administrator = _login()
    status, wizard = _json_request("/api/v1/console/azure-deployment", token=administrator)
    assert status == 200
    steps = wizard["steps"]  # type: ignore[index]
    assert {step["id"] for step in steps} == {
        "azure_foundation",
        "azure_identity_dns",
        "azure_integrations",
        "azure_automation",
    }
    assert all(field["secret"] is False for step in steps for field in step["fields"])
    assert all(field["where_to_find"] for step in steps for field in step["fields"])
    values = {
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "communication_data_location": "United States",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }
    validation_status, validation = _json_request(
        "/api/v1/console/azure-deployment/validate",
        token=administrator,
        method="POST",
        body={"values": values},
    )
    assert validation_status == 200 and validation["ok"] is True  # type: ignore[index]


def test_setup_help_and_assistant() -> None:
    administrator = _login()
    help_status, help_content = _json_request("/api/v1/console/help", token=administrator)
    assert help_status == 200
    assert any(item["term"] == "OIDC" for item in help_content["glossary"])  # type: ignore[index]
    assert any(item["term"] == "Terraform state" for item in help_content["glossary"])  # type: ignore[index]
    assert any(item["id"] == "azure-deployment" for item in help_content["topics"])  # type: ignore[index]

    assist_status, assistance = _json_request(
        "/api/v1/console/onboarding/assist",
        token=administrator,
        method="POST",
        body={"component": "identity", "question": "What is OIDC?", "values": {}},
    )
    assert assist_status == 200
    assert isinstance(assistance["answer"], str) and assistance["answer"]  # type: ignore[index]
    assert assistance["source"] in {"configured-ai", "curated"}  # type: ignore[index]
    assert assistance["warnings"]  # type: ignore[index]

    fake_token = "FAKE-DISPOSABLE-token=not-a-real-credential"
    fake_api_key = "sk-disposable-only-123456789"
    filtered_status, filtered = _json_request(
        "/api/v1/console/onboarding/assist",
        token=administrator,
        method="POST",
        body={
            "component": "identity",
            "question": f"Why do {fake_token} and {fake_api_key} fail?",
            "values": {"OPERATOR_API_OIDC_CLIENT_SECRET": "fake-submitted-secret"},
        },
    )
    assert filtered_status == 200
    assert filtered["warnings"]  # type: ignore[index]
    response_text = str(filtered)
    assert fake_token not in response_text
    assert fake_api_key not in response_text
    assert "fake-submitted-secret" not in response_text

    webhook_status, webhook_help = _json_request(
        "/api/v1/console/onboarding/assist",
        token=administrator,
        method="POST",
        body={
            "component": "webhook",
            "question": "What is an allowed webhook domain, and do I need an MTA or mail relay?",
            "values": {},
        },
    )
    assert webhook_status == 200
    assert "does not require an MTA or mail relay" in webhook_help["answer"]  # type: ignore[index]
    assert webhook_help["suggestions"] == {}  # type: ignore[index]
    assert webhook_help["warnings"] == [  # type: ignore[index]
        "AI suggestions are advisory. Review them and run the connection test before saving."
    ]
