"""Safe GUI orchestration of the one allowlisted Azure workflow."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import textwrap
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from kp_operator_api import deployment_orchestration
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deployment_orchestration import (
    DEPLOYMENT_CONFIG_KEYS,
    EXPECTED_WORKFLOW_SHA256,
    INTERNAL_ACS_CONFIG_DEFAULTS,
    MAX_DEPLOYMENT_CONFIG_BYTES,
    PUBLIC_DEPLOYMENT_CONFLICT,
    PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE,
    PUBLIC_DEPLOYMENT_UNAVAILABLE,
    REQUIRED_WORKFLOW_INPUTS,
    DeploymentConflict,
    DeploymentOrchestrator,
    DeploymentUnavailable,
    DispatchIndeterminate,
    GitHubWorkflowGateway,
    MemoryPlanStore,
    RedisPlanStore,
    WorkflowConfiguration,
    WorkflowPreflight,
)
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
PASSWORD = "correct-horse-battery-staple"
COMMIT_SHA = "a" * 40
WORKFLOW_ID = 123
WORKFLOW_BLOB_SHA = "b" * 40
ENVIRONMENT_DIGEST = "c" * 64
WORKFLOW_BYTES = (Path(__file__).resolve().parents[3] / ".github" / "workflows" / "azure-deploy.yml").read_bytes()


def _values() -> dict[str, str]:
    return {
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "environment": "staging",
        "deployment_stage": "foundation_bootstrap",
        "network_mode": "private",
        "location": "eastus2",
        "name_prefix": "kp",
        "entra_tenant_id": "22222222-2222-2222-2222-222222222222",
        "entra_client_id": "33333333-3333-3333-3333-333333333333",
        "operator_fqdn": "awareness.example.com",
        "tracking_fqdn": "awareness-track.example.com",
        "acs_resource_mode": "provision",
        "acs_existing_communication_service_id": "",
        "acs_existing_email_endpoint": "",
        "acs_existing_email_domain_id": "",
        "acs_sending_domain": "mail.example.com",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security Awareness",
        "acs_dns_zone_id": "",
        "acs_daily_message_limit": "1000",
        "acs_messages_per_minute": "20",
        "acs_ramp_batch_size": "10",
        "acs_ramp_interval_seconds": "60",
        "communication_data_location": "United States",
        "ai_endpoint": "https://ai-gateway.example.com",
        "enable_directory_sync": "false",
        "directory_group_ids": "",
        "enable_reported_mailbox": "false",
        "reported_mailbox_address": "",
        "reported_mailbox_folder": "inbox",
        "alert_webhook_domains": "ntfy.example.com",
        "allowed_recipient_domains": "example.com",
        "ciphertext_active_key_id": "primary",
        "ciphertext_prior_key_ids": "",
        "ciphertext_prior_keys_secret_id": "",
        "azure_deployment_client_id": "55555555-5555-4555-8555-555555555555",
        "tf_state_resource_group": "rg-kp-state",
        "tf_state_storage_account": "kptfstateprod",
        "tf_state_container": "tfstate",
        "runner_label": "azure-vnet",
    }


class FakeAudit:
    def __init__(self, order: list[str] | None = None) -> None:
        self.events: list[dict[str, Any]] = []
        self.order = order

    def record(self, **event: Any) -> None:
        if self.order is not None and str(event.get("action", "")).endswith("apply.request"):
            self.order.append("audit")
        self.events.append(event)


class SyncChunks(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes, fail_on_read: bool = False) -> None:
        self.chunks = chunks
        self.fail_on_read = fail_on_read
        self.iterated = False

    def __iter__(self):  # noqa: ANN204
        self.iterated = True
        if self.fail_on_read:
            raise AssertionError("response body must not be read")
        yield from self.chunks


def _gateway(handler: Any) -> GitHubWorkflowGateway:
    configuration = WorkflowConfiguration(
        repository="example/security-platform",
        ref="main",
        token="github-installation-token-value",
    )
    client = httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer test"},
    )
    return GitHubWorkflowGateway(configuration, client=client)


def _preflight(
    environment: str = "staging",
    *,
    commit_sha: str = COMMIT_SHA,
    workflow_content_sha256: str = EXPECTED_WORKFLOW_SHA256,
    environment_metadata_sha256: str = ENVIRONMENT_DIGEST,
    tf_state_resource_group: str = "rg-kp-state",
    tf_state_storage_account: str = "kptfstateprod",
    tf_state_container: str = "tfstate",
) -> WorkflowPreflight:
    return WorkflowPreflight(
        commit_sha=commit_sha,
        workflow_id=WORKFLOW_ID,
        workflow_blob_sha=WORKFLOW_BLOB_SHA,
        workflow_content_sha256=workflow_content_sha256,
        environment_metadata_sha256=environment_metadata_sha256,
        environment=environment,
        required_reviewer_count=1,
        admin_bypass_allowed=False,
        deployment_branch_policy_present=True,
        tf_state_resource_group=tf_state_resource_group,
        tf_state_storage_account=tf_state_storage_account,
        tf_state_container=tf_state_container,
    )


def _successful_jobs(phase: str = "foundation_bootstrap") -> list[dict[str, Any]]:
    steps_by_job: dict[str, list[dict[str, str]]] = {}
    for job, step in DeploymentOrchestrator._required_recovery_steps(phase):  # noqa: SLF001 - contract fixture
        steps_by_job.setdefault(job, []).append({"name": step, "status": "completed", "conclusion": "success"})
    return [
        {
            "name": job,
            "status": "completed",
            "conclusion": "success",
            "steps": steps,
        }
        for job, steps in steps_by_job.items()
    ]


def _successful_activity(phase: str = "foundation_bootstrap") -> list[dict[str, str]]:
    activity: list[dict[str, str]] = []
    for job in _successful_jobs(phase):
        activity.append(
            {
                "kind": "job",
                "job": "",
                "name": str(job["name"]),
                "status": "completed",
                "conclusion": "success",
            }
        )
        activity.extend(
            {
                "kind": "step",
                "job": str(job["name"]),
                "name": str(step["name"]),
                "status": "completed",
                "conclusion": "success",
            }
            for step in job["steps"]
        )
    return activity


def _with_evidence_digest(value: dict[str, Any]) -> dict[str, Any]:
    value = dict(value)
    value["evidence_digest"] = (
        "sha256:" + hashlib.sha256(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    )
    return value


def _successful_evidence_bundle(run_id: int, run_attempt: int, correlation: str) -> dict[str, Any]:
    reviewed = DeploymentOrchestrator.workflow_inputs(_values())["deployment_config"]
    reviewed_digest = "sha256:" + hashlib.sha256(reviewed.encode()).hexdigest()
    workflow_run = {"run_id": str(run_id), "run_attempt": str(run_attempt)}
    resource_group = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-kp"
    domain_id = f"{resource_group}/providers/Microsoft.Communication/emailServices/kp-email/domains/mail.example.com"
    live = _with_evidence_digest(
        {
            "schema": "kp.acs-live-readiness.v1",
            "observed_at": datetime.now(UTC).isoformat(),
            "result": "foundation_bootstrap_domain_pending",
            "phase": "foundation_bootstrap",
            "resource_mode": "provision",
            "subscription_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "resource_ids": {
                "communication_service_id": (
                    f"{resource_group}/providers/Microsoft.Communication/CommunicationServices/kp-acs"
                ),
                "email_service_id": f"{resource_group}/providers/Microsoft.Communication/emailServices/kp-email",
                "email_domain_id": domain_id,
                "sender_username_id": f"{domain_id}/senderUsernames/awareness",
            },
            "statuses": {
                "domain": "notstarted",
                "spf": "notstarted",
                "dkim": "notstarted",
                "dkim2": "notstarted",
                "sender": "not_observed",
                "association": "not_linked",
            },
            "reviewed_commit_sha": COMMIT_SHA,
            "reviewed_deployment_digest": reviewed_digest,
            "workflow_run": workflow_run,
            "api_version": "2023-04-01",
            "scope_limits": {
                "dns_provider_state_only": True,
                "inbox_placement_proven": False,
                "event_grid_delivery_proven": False,
                "human_mailbox_validation_proven": False,
            },
        }
    )
    stage_result = _with_evidence_digest(
        {
            "schema": "kp.acs-stage-result.v1",
            "recorded_at": datetime.now(UTC).isoformat(),
            "result": "foundation_bootstrap_pending_dns",
            "phase": "foundation_bootstrap",
            "reviewed_commit_sha": COMMIT_SHA,
            "reviewed_deployment_digest": reviewed_digest,
            "deployment_request_id": correlation,
            "source_evidence_digests": {
                "acs_live_readiness": live["evidence_digest"],
                "acs_verification_initiation": "sha256:" + "e" * 64,
            },
            "workflow_run": workflow_run,
            "claims": {
                "domain_verification_proven": False,
                "association_proven": False,
                "sender_proven": False,
                "workloads_deployed": False,
                "receipt_subscription_activated": False,
                "mail_delivery_proven": False,
                "inbox_placement_proven": False,
                "human_mailbox_validation_proven": False,
            },
        }
    )
    initiation = _with_evidence_digest(
        {
            "schema": "kp.acs-verification-initiation.v1",
            "recorded_at": datetime.now(UTC).isoformat(),
            "result": "accepted_pending_control_plane_verification",
            "phase": "foundation_bootstrap",
            "resource_mode": "provision",
            "subscription_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "email_domain_id": domain_id,
            "api_version": "2023-04-01",
            "verification_types": ["Domain", "SPF", "DKIM", "DKIM2"],
            "verification_state": "pending_external_dns_and_control_plane_readback",
            "dns_guidance_status": "manual_dns_required",
            "reviewed_commit_sha": COMMIT_SHA,
            "reviewed_deployment_digest": reviewed_digest,
            "deployment_request_id": correlation,
            "workflow_run": workflow_run,
            "scope_limits": {
                "provider_response_body_recorded": False,
                "verification_marked_complete": False,
                "workloads_unlocked": False,
                "repeat_foundation_dispatch_may_be_required": True,
            },
        }
    )
    stage_result = _with_evidence_digest(
        {
            **{key: value for key, value in stage_result.items() if key != "evidence_digest"},
            "source_evidence_digests": {
                "acs_live_readiness": live["evidence_digest"],
                "acs_verification_initiation": initiation["evidence_digest"],
            },
        }
    )
    return {
        "artifact_sha256": "sha256:" + "f" * 64,
        "stage_result": stage_result,
        "live_readiness": live,
        "stage_source": initiation,
    }


def _successful_gateway(order: list[str] | None = None) -> GitHubWorkflowGateway:
    state: dict[str, Any] = {"dispatched": False, "correlation": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            assert request.url.path.endswith("/actions/workflows/azure-deploy.yml/dispatches")
            payload = json.loads(request.content)
            assert payload["ref"] == "main"
            assert payload["inputs"]["network_mode"] == "private"
            assert payload["inputs"]["reviewed_commit_sha"] == COMMIT_SHA
            assert re.fullmatch(r"kp-[0-9a-f]{32}-1", payload["inputs"]["deployment_request_id"])
            reviewed_config = json.loads(payload["inputs"]["deployment_config"])
            assert reviewed_config == {
                **{key: _values().get(key, "") for key in DEPLOYMENT_CONFIG_KEYS},
                **INTERNAL_ACS_CONFIG_DEFAULTS,
            }
            state["correlation"] = payload["inputs"]["deployment_request_id"]
            assert set(payload["inputs"]) == {
                "environment",
                "network_mode",
                "deployment_phase",
                "deployment_config",
                "deployment_request_id",
                "reviewed_commit_sha",
            }
            if order is not None:
                order.append("dispatch")
            state["dispatched"] = True
            return httpx.Response(204)
        if request.url.path.endswith("/actions/workflows/azure-deploy.yml/runs"):
            if order is not None and not state["dispatched"]:
                order.append("baseline")
            runs = [
                {
                    "id": 10,
                    "workflow_id": WORKFLOW_ID,
                    "event": "workflow_dispatch",
                    "head_sha": COMMIT_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-08-26T10:00:00Z",
                    "html_url": "https://github.com/example/security-platform/actions/runs/10",
                    "display_title": "manual-old-run",
                }
            ]
            if state["dispatched"]:
                runs.insert(
                    0,
                    {
                        "id": 501,
                        "workflow_id": WORKFLOW_ID,
                        "event": "workflow_dispatch",
                        "head_sha": COMMIT_SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "created_at": "2026-08-27T10:00:00Z",
                        "html_url": "https://github.com/example/security-platform/actions/runs/501",
                        "display_title": state["correlation"],
                    },
                )
            return httpx.Response(200, json={"workflow_runs": runs})
        if request.url.path.endswith("/actions/runs/501/jobs"):
            return httpx.Response(
                200,
                json={"jobs": _successful_jobs()},
            )
        if request.url.path.endswith("/actions/runs/501"):
            return httpx.Response(
                200,
                json={
                    "id": 501,
                    "workflow_id": WORKFLOW_ID,
                    "event": "workflow_dispatch",
                    "head_sha": COMMIT_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-08-27T10:00:00Z",
                    "html_url": "https://github.com/example/security-platform/actions/runs/501",
                    "display_title": state["correlation"],
                },
            )
        raise AssertionError(f"unexpected GitHub request: {request.method} {request.url}")

    gateway = _gateway(handler)
    gateway.acs_evidence_artifact = (  # type: ignore[method-assign]
        lambda run_id, run_attempt: _successful_evidence_bundle(run_id, run_attempt, str(state["correlation"]))
    )
    return gateway


def _service(
    handler: Any | None = None,
    *,
    preflight: Any | None = None,
) -> DeploymentOrchestrator:
    return DeploymentOrchestrator(
        MemoryPlanStore(),
        _gateway(handler) if handler else _successful_gateway(),
        preflight=preflight or (lambda environment: _preflight(environment)),
    )


def _app(tmp_path, service: DeploymentOrchestrator, audit: FakeAudit | None = None):  # noqa: ANN001
    env_file = tmp_path / ".env"
    env_file.write_text(f"KP_CONSOLE_PASSWORD={PASSWORD}{os.linesep}", encoding="utf-8")
    settings = OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=str(env_file),
        console_static_dir="/nonexistent-console-dir",
    )
    app = create_app(settings)
    app.state.deployment_orchestrator = service
    app.state.audit_store = audit or FakeAudit()
    app.state.audit_health_check = lambda: True
    return app


def _token(client: TestClient) -> str:
    response = client.post("/api/v1/console/session", json={"password": PASSWORD})
    assert response.status_code == 200
    return str(response.json()["token"])


def _headers(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(client)}"}


def test_plan_apply_status_is_allowlisted_audited_and_redacted(tmp_path) -> None:  # noqa: ANN001
    order: list[str] = []
    audit = FakeAudit(order)
    service = DeploymentOrchestrator(
        MemoryPlanStore(),
        _successful_gateway(order),
        preflight=lambda environment: _preflight(environment),
    )
    with TestClient(_app(tmp_path, service, audit)) as client:
        headers = _headers(client)
        planned = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": _values()},
        )
        assert planned.status_code == 200, planned.text
        plan = planned.json()
        assert plan["state"] == "reviewed"
        assert plan["inputs"]["network_mode"] == "private"
        assert plan["review"]["deployment_stage"] == "foundation_bootstrap"
        assert "token" not in json.dumps(plan).lower()

        secret_reason = client.post(
            f"/api/v1/console/azure-deployment/orchestration/plans/{plan['plan_id']}/apply",
            headers=headers,
            json={
                "confirm": True,
                "review_digest": plan["review_digest"],
                "rationale": "token=github_pat_this_must_never_reach_audit",
            },
        )
        assert secret_reason.status_code == 403
        assert "github_pat" not in json.dumps(audit.events)

        refused = client.post(
            f"/api/v1/console/azure-deployment/orchestration/plans/{plan['plan_id']}/apply",
            headers=headers,
            json={"confirm": False, "review_digest": plan["review_digest"], "rationale": "approved staging"},
        )
        assert refused.status_code == 403

        applied = client.post(
            f"/api/v1/console/azure-deployment/orchestration/plans/{plan['plan_id']}/apply",
            headers=headers,
            json={"confirm": True, "review_digest": plan["review_digest"], "rationale": "approved staging"},
        )
        assert applied.status_code == 200, applied.text
        assert applied.json()["state"] == "dispatch_accepted"
        assert order == ["baseline", "audit", "dispatch"]

        status = client.get(f"/api/v1/console/azure-deployment/orchestration/plans/{plan['plan_id']}", headers=headers)
        assert status.status_code == 200
        body = status.json()
        assert body["state"] == "workflow_succeeded"
        assert body["run_id"] == 501
        assert body["run"]["url"] == "https://github.com/example/security-platform/actions/runs/501"
        assert body["recovery"]["verification"]["connector_verified"] is True
        assert not any(key in json.dumps(body).lower() for key in ("password", "connection_string"))
        assert any(event["action"] == "deployment.apply.request" for event in audit.events)
        review_event = next(event for event in audit.events if event["action"] == "deployment.plan.review")
        assert review_event["detail"]["commit_sha"] == COMMIT_SHA
        assert review_event["detail"]["workflow_content_sha256"] == EXPECTED_WORKFLOW_SHA256


def test_production_plan_is_blocked_before_preflight_while_staging_remains_available(tmp_path) -> None:  # noqa: ANN001
    preflight_calls: list[str] = []

    def unexpected_production_preflight(environment: str) -> WorkflowPreflight:
        preflight_calls.append(environment)
        if environment == "production":
            raise AssertionError("blocked production planning must not contact GitHub")
        return _preflight(environment)

    service = _service(preflight=unexpected_production_preflight)
    audit = FakeAudit()
    with TestClient(_app(tmp_path, service, audit)) as client:
        headers = _headers(client)
        production = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": {**_values(), "environment": "production"}},
        )
        staging = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": _values()},
        )

    assert production.status_code == 409
    assert production.json() == {
        "code": "KP-005",
        "detail": (
            "KP-005: production deployment planning is blocked until custom-domain, certificate, edge restriction, "
            "live HSTS, backup/restore, and rollback gates are verifiable; use staging for bootstrap"
        ),
    }
    assert preflight_calls == ["staging"]
    assert staging.status_code == 200, staging.text
    assert staging.json()["review"]["environment"] == "staging"
    assert all(event.get("detail", {}).get("environment") != "production" for event in audit.events)


def test_latest_and_advance_routes_restore_owner_plan_and_create_only_next_stage(tmp_path) -> None:  # noqa: ANN001
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    audit = FakeAudit()
    with TestClient(_app(tmp_path, service, audit)) as client:
        headers = _headers(client)
        created = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": _values()},
        ).json()
        latest = client.get(
            "/api/v1/console/azure-deployment/orchestration/latest?environment=staging",
            headers=headers,
        )
        assert latest.status_code == 200
        assert latest.json()["plan"]["plan_id"] == created["plan_id"]

        stored = store.load(created["plan_id"])
        assert stored is not None
        stored["state"] = "workflow_succeeded"
        stored["acs_evidence"] = {
            "status": "verified",
            "schema": "kp.acs-stage-result.v1",
            "deployment_stage": "foundation_bootstrap",
            "evidence_digest": "sha256:" + "1" * 64,
        }
        store.save(stored)
        advanced = client.post(
            f"/api/v1/console/azure-deployment/orchestration/plans/{created['plan_id']}/advance",
            headers=headers,
            json={"confirm": True, "review_digest": created["review_digest"]},
        )

    assert advanced.status_code == 200, advanced.text
    assert advanced.json()["review"]["deployment_stage"] == "foundation_finalize"
    assert advanced.json()["plan_id"] != created["plan_id"]
    assert any(event["action"] == "deployment.stage.advance" for event in audit.events)


def test_staging_foundation_plan_accepts_unverified_acs_without_weakening_workloads(tmp_path) -> None:  # noqa: ANN001
    foundation = {
        **_values(),
        "deployment_stage": "foundation_bootstrap",
    }
    with TestClient(_app(tmp_path, _service())) as client:
        headers = _headers(client)
        planned = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": foundation},
        )
        workloads = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": {**foundation, "deployment_stage": "workloads"}},
        )
    assert planned.status_code == 200, planned.text
    assert planned.json()["review"]["deployment_stage"] == "foundation_bootstrap"
    reviewed_config = json.loads(DeploymentOrchestrator.workflow_inputs(foundation)["deployment_config"])
    assert reviewed_config["acs_readiness_checked_at"] == ""
    assert "deployment_config" not in planned.json()["inputs"]
    assert workloads.status_code == 409


def test_managed_plan_rejects_missing_ai_before_creating_work(tmp_path) -> None:  # noqa: ANN001
    with TestClient(_app(tmp_path, _service())) as client:
        response = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=_headers(client),
            json={"values": {**_values(), "ai_endpoint": ""}},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "first template" in body["errors"]["ai_endpoint"]
    assert "plan_id" not in body


def test_network_mode_is_reviewed_and_private_runner_is_enforced(tmp_path) -> None:  # noqa: ANN001
    starter = {
        **_values(),
        "environment": "staging",
        "deployment_stage": "foundation_bootstrap",
        "network_mode": "starter",
        "runner_label": "",
    }
    assert DeploymentOrchestrator.workflow_inputs(starter)["network_mode"] == "starter"
    for invalid in (
        {**starter, "deployment_stage": "workloads"},
        {**starter, "environment": "production"},
    ):
        with pytest.raises(DeploymentConflict, match="network mode"):
            DeploymentOrchestrator.workflow_inputs(invalid)

    with TestClient(_app(tmp_path, _service())) as client:
        headers = _headers(client)
        starter_result = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": starter},
        ).json()
        starter_plan = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers=headers,
            json={"values": starter},
        )
        private_result = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {**_values(), "runner_label": "self-hosted"}},
        ).json()

    assert starter_result["ok"] is True
    assert any("transition to private" in warning for warning in starter_result["warnings"])
    assert starter_plan.status_code == 409
    assert "private azure-vnet runner" in starter_plan.text
    assert private_result["ok"] is False
    assert private_result["errors"]["runner_label"] == (
        "Private mode requires the exact protected runner label azure-vnet."
    )


def test_plan_binds_reviewed_terraform_state_identity() -> None:
    service = _service()
    with pytest.raises(DeploymentConflict, match="Terraform state identity"):
        service.create_plan({**_values(), "tf_state_container": "wrong-state"}, actor="operator")


def test_routes_require_auth_healthy_audit_and_reject_unknown_keys(tmp_path) -> None:  # noqa: ANN001
    app = _app(tmp_path, _service())
    with TestClient(app) as client:
        path = "/api/v1/console/azure-deployment/orchestration/plan"
        assert client.post(path, json={"values": _values()}).status_code == 401
        headers = _headers(client)
        injected = client.post(path, headers=headers, json={"values": {**_values(), "command": "terraform destroy"}})
        assert injected.status_code == 403
        app.state.audit_health_check = lambda: False
        unhealthy = client.post(path, headers=headers, json={"values": _values()})
        assert unhealthy.status_code == 503
        assert unhealthy.json()["code"] == "audit_integrity_unhealthy"


def test_cookie_apply_rejects_cross_origin(tmp_path) -> None:  # noqa: ANN001
    app = _app(tmp_path, _service())
    with TestClient(app) as client:
        token = _token(client)
        plan = client.post(
            "/api/v1/console/azure-deployment/orchestration/plan",
            headers={"Authorization": f"Bearer {token}"},
            json={"values": _values()},
        ).json()
        client.cookies.set("kp_oidc_session", token)
        response = client.post(
            f"/api/v1/console/azure-deployment/orchestration/plans/{plan['plan_id']}/apply",
            headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
            json={"confirm": True, "review_digest": plan["review_digest"], "rationale": "approved staging"},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "csrf_rejected"


def test_confirmed_dispatch_rejection_can_be_retried_once() -> None:
    dispatches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatches
        if request.method == "GET":
            return httpx.Response(200, json={"workflow_runs": []})
        dispatches += 1
        return httpx.Response(422 if dispatches == 1 else 204)

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    first = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    assert first["state"] == "dispatch_failed"
    second = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="fixed workflow access",
        retry=True,
        audit=lambda _detail: None,
    )
    assert second["state"] == "dispatch_accepted"
    assert second["attempt"] == 2


def test_indeterminate_dispatch_cannot_be_retried() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"workflow_runs": []})
        raise httpx.ReadTimeout("unknown", request=request)

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    result = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    assert result["state"] == "dispatch_indeterminate"
    with pytest.raises(DeploymentConflict, match="rejected a dispatch"):
        service.apply(
            plan["plan_id"],
            plan["review_digest"],
            actor="operator",
            rationale="unsafe duplicate retry",
            retry=True,
            audit=lambda _detail: None,
        )


def test_indeterminate_dispatch_can_recover_by_exact_run_identity() -> None:
    state: dict[str, str | bool] = {"correlation": "", "dispatched": False}

    def run_payload() -> dict[str, Any]:
        return {
            "id": 901,
            "workflow_id": WORKFLOW_ID,
            "event": "workflow_dispatch",
            "head_sha": COMMIT_SHA,
            "status": "completed",
            "conclusion": "success",
            "display_title": state["correlation"],
            "html_url": "https://github.com/example/security-platform/actions/runs/901",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            state["correlation"] = json.loads(request.content)["inputs"]["deployment_request_id"]
            state["dispatched"] = True
            raise httpx.ReadTimeout("unknown", request=request)
        if request.url.path.endswith("/actions/workflows/azure-deploy.yml/runs"):
            return httpx.Response(200, json={"workflow_runs": [run_payload()] if state["dispatched"] else []})
        if request.url.path.endswith("/actions/runs/901/jobs"):
            return httpx.Response(200, json={"jobs": []})
        if request.url.path.endswith("/actions/runs/901"):
            return httpx.Response(200, json=run_payload())
        raise AssertionError(f"unexpected request: {request.url}")

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    submitted = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    recovered = service.get_plan(plan["plan_id"], actor="operator")

    assert submitted["state"] == "dispatch_indeterminate"
    assert recovered["state"] == "evidence_unverified"
    assert recovered["run_id"] == 901
    assert recovered["operator_action"]["reconcile_only"] is True


@pytest.mark.parametrize("conclusion", ["neutral", "skipped"])
def test_confirmed_non_successful_completion_is_reconcile_only(conclusion: str) -> None:
    gateway = _successful_gateway()
    service = DeploymentOrchestrator(
        MemoryPlanStore(),
        gateway,
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    submitted = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    stored = service.store.load(plan["plan_id"])
    assert stored is not None
    stored["run_id"] = 501
    stored["run"] = {
        "status": "completed",
        "conclusion": conclusion,
    }
    service.store.save(stored)

    original_run = gateway.run
    gateway.run = lambda run_id: {**original_run(run_id), "conclusion": conclusion}  # type: ignore[method-assign]
    refreshed = service.get_plan(plan["plan_id"], actor="operator")

    assert submitted["state"] == "dispatch_accepted"
    assert refreshed["state"] == "run_failed"
    assert refreshed["operator_action"]["retry_allowed"] is False
    assert refreshed["operator_action"]["reconcile_only"] is True


def test_gateway_never_exposes_response_body_or_accepts_arbitrary_origin() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="access_token=super-secret")

    gateway = _gateway(handler)
    with pytest.raises(DispatchIndeterminate) as caught:
        gateway.dispatch(DeploymentOrchestrator.workflow_inputs(_values()))
    assert "super-secret" not in str(caught.value)
    assert gateway.workflow_url == ("https://github.com/example/security-platform/actions/workflows/azure-deploy.yml")


@pytest.mark.parametrize(
    ("repository", "ref", "token"),
    [
        ("../security-platform", "main", "github-installation-token-value"),
        ("example/..", "main", "github-installation-token-value"),
        ("example/security-platform", "../main", "github-installation-token-value"),
        ("example/security-platform", "main/", "github-installation-token-value"),
        ("example/security-platform", "feature//unsafe", "github-installation-token-value"),
        ("example/security-platform", ".hidden/main", "github-installation-token-value"),
        ("example/security-platform", "release.lock", "github-installation-token-value"),
        ("example/security-platform", "main", " github-installation-token-value "),
        ("example/security-platform", "main", "github:installation:token:value"),
    ],
)
def test_configuration_rejects_path_ambiguity_and_non_token_header_material(
    monkeypatch: pytest.MonkeyPatch,
    repository: str,
    ref: str,
    token: str,
) -> None:
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE", "github_actions")
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY", repository)
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_REF", ref)
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN", token)

    with pytest.raises(DeploymentUnavailable):
        WorkflowConfiguration.from_environment()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://attacker.example",
        "http://api.github.com",
        "https://api.github.com:444",
        "https://credential@api.github.com",
        "https://api.github.com/unexpected/",
    ],
)
def test_gateway_rejects_a_non_github_api_origin(base_url: str) -> None:
    configuration = WorkflowConfiguration(
        repository="example/security-platform",
        ref="main",
        token="github-installation-token-value",
    )

    with (
        httpx.Client(
            base_url=base_url,
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
        ) as client,
        pytest.raises(DeploymentUnavailable, match="API origin is invalid"),
    ):
        GitHubWorkflowGateway(configuration, client=client)


def _acs_artifact_zip() -> bytes:
    evidence = _successful_evidence_bundle(501, 1, "kp-" + "a" * 32 + "-1")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("acs-live-readiness.json", json.dumps(evidence["live_readiness"]))
        bundle.writestr("acs-verification-initiation.json", json.dumps(evidence["stage_source"]))
        bundle.writestr("acs-stage-result.json", json.dumps(evidence["stage_result"]))
        bundle.writestr("checkpoints.ndjson", "{}\n")
    return stream.getvalue()


@pytest.mark.parametrize("artifact_state", ["duplicate", "expired", "digest_mismatch"])
def test_gateway_rejects_ambiguous_expired_or_hash_mismatched_acs_artifact(artifact_state: str) -> None:
    archive = _acs_artifact_zip()
    archive_digest = "sha256:" + hashlib.sha256(archive).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/runs/501/artifacts"):
            artifact = {
                "id": 77,
                "name": "azure-deployment-evidence-501-1",
                "size_in_bytes": len(archive),
                "expired": artifact_state == "expired",
                "digest": "sha256:" + "0" * 64 if artifact_state == "digest_mismatch" else archive_digest,
                "archive_download_url": (
                    "https://api.github.com/repos/example/security-platform/actions/artifacts/77/zip"
                ),
            }
            artifacts = [artifact, dict(artifact)] if artifact_state == "duplicate" else [artifact]
            return httpx.Response(200, json={"total_count": len(artifacts), "artifacts": artifacts})
        if request.url.path.endswith("/actions/artifacts/77/zip"):
            return httpx.Response(200, content=archive)
        raise AssertionError(request.url)

    with pytest.raises(DeploymentUnavailable, match="deployment evidence is malformed"):
        _gateway(handler).acs_evidence_artifact(501, 1)


def test_gateway_reads_one_exact_bounded_acs_stage_artifact() -> None:
    archive = _acs_artifact_zip()
    digest = "sha256:" + hashlib.sha256(archive).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/runs/501/artifacts"):
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "artifacts": [
                        {
                            "id": 77,
                            "name": "azure-deployment-evidence-501-1",
                            "size_in_bytes": len(archive),
                            "expired": False,
                            "digest": digest,
                            "archive_download_url": (
                                "https://api.github.com/repos/example/security-platform/actions/artifacts/77/zip"
                            ),
                        }
                    ],
                },
            )
        if request.url.path.endswith("/actions/artifacts/77/zip"):
            return httpx.Response(200, content=archive)
        raise AssertionError(request.url)

    evidence = _gateway(handler).acs_evidence_artifact(501, 1)

    assert evidence["artifact_sha256"] == digest
    assert evidence["stage_result"]["schema"] == "kp.acs-stage-result.v1"
    assert evidence["live_readiness"]["schema"] == "kp.acs-live-readiness.v1"


def test_reviewed_config_is_canonical_complete_and_rejects_credential_material() -> None:
    first = DeploymentOrchestrator.workflow_inputs(_values())
    second = DeploymentOrchestrator.workflow_inputs(dict(reversed(list(_values().items()))))
    assert first == second
    assert json.loads(first["deployment_config"]) == {
        **{key: _values().get(key, "") for key in DEPLOYMENT_CONFIG_KEYS},
        **INTERNAL_ACS_CONFIG_DEFAULTS,
    }
    with pytest.raises(DeploymentConflict, match="credentials or tokens"):
        DeploymentOrchestrator.workflow_inputs(
            {**_values(), "acs_sender_display_name": "token=github_pat_never_return_this_secret_value"}
        )
    with pytest.raises(DeploymentConflict, match="fixed workflow limit"):
        DeploymentOrchestrator.workflow_inputs(
            {**_values(), "directory_group_ids": "a" * (MAX_DEPLOYMENT_CONFIG_BYTES + 1)}
        )
    raw_prior_key = "ab" * 32
    with pytest.raises(DeploymentConflict, match="ciphertext recovery metadata is invalid") as caught:
        DeploymentOrchestrator.workflow_inputs(
            {
                **_values(),
                "ciphertext_active_key_id": "rotated",
                "ciphertext_prior_key_ids": "primary",
                "ciphertext_prior_keys_secret_id": f"primary={raw_prior_key}",
            }
        )
    assert raw_prior_key not in str(caught.value)


def test_workflow_recovery_preflight_reuses_validated_file_and_never_surfaces_secret_output() -> None:
    workflow = WORKFLOW_BYTES.decode("utf-8")
    lifecycle = workflow.split("- name: Validate ciphertext key-rotation lifecycle metadata", maxsplit=1)[1].split(
        "- name: Plan ACS foundation bootstrap", maxsplit=1
    )[0]
    assert 'Path(os.environ["RUNNER_TEMP"]) / "reviewed.auto.tfvars.json"' in lifecycle
    assert "REVIEWED_DEPLOYMENT_CONFIG" not in lifecycle
    assert '"--query", "{id:id,enabled:attributes.enabled,expires:attributes.expires,tags:tags}"' in lifecycle
    assert "capture_output=True" in lifecycle
    assert "metadata_result.stderr" not in lifecycle
    assert "ciphertext prior-key reference is missing or inaccessible" in lifecycle
    assert "len(metadata_result.stdout.encode" in lifecycle
    assert "set(previous_prior).issubset(prior_key_ids)" in lifecycle
    assert "active_key_id != previous_active" in lifecycle
    assert "rolling pre-stage and promotion" in lifecycle
    assert lifecycle.lstrip().startswith("working-directory: infrastructure/terraform")
    assert workflow.index("active ciphertext key changes are blocked") < workflow.index(
        "- name: Plan ACS foundation bootstrap"
    )
    assert "ciphertext_prior_key_value" not in workflow
    assert "ciphertext_prior_keys_value" not in workflow


def _run_workflow_recovery_preflight(
    tmp_path: Path,
    *,
    active: str = "primary",
    prior: str = "retired",
    previous_active: str = "primary",
    previous_prior: list[str] | None = None,
    az_mode: str = "valid",
    phase: str = "workloads",
    state_exists: bool = True,
    state_accessible: bool = True,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    workflow = WORKFLOW_BYTES.decode("utf-8")
    lifecycle = workflow.split("- name: Validate ciphertext key-rotation lifecycle metadata", maxsplit=1)[1].split(
        "- name: Plan ACS foundation bootstrap", maxsplit=1
    )[0]
    source = lifecycle.split("python3 - <<'PY'", maxsplit=1)[1].split("\n          PY", maxsplit=1)[0]
    source = textwrap.dedent(source)
    subscription = "11111111-1111-1111-1111-111111111111"
    vault_id = (
        f"/subscriptions/{subscription}/resourceGroups/rg-kp-staging/providers/Microsoft.KeyVault/vaults/kp-vault"
    )
    prior_reference = f"{vault_id}/secrets/ciphertext-prior-keys" if prior else ""
    (tmp_path / "reviewed.auto.tfvars.json").write_text(
        json.dumps(
            {
                "ciphertext_active_key_id": active,
                "ciphertext_prior_key_ids": prior,
                "ciphertext_prior_keys_secret_id": prior_reference,
            }
        ),
        encoding="utf-8",
    )
    terraform = tmp_path / "terraform"
    terraform.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

if sys.argv[1:] != ["output", "-json"]:
    raise SystemExit(2)
if os.environ["FAKE_STATE_ACCESSIBLE"] != "true":
    raise SystemExit(1)
if os.environ["FAKE_STATE_EXISTS"] != "true":
    print("{}")
else:
    print(json.dumps({
        "ciphertext_keyring": {"value": json.loads(os.environ["FAKE_PREVIOUS"])},
        "key_vault_id": {"value": os.environ["FAKE_VAULT_ID"]},
    }))
""",
        encoding="utf-8",
    )
    terraform.chmod(0o700)
    az = tmp_path / "az"
    az.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

mode = os.environ["FAKE_AZ_MODE"]
if mode == "missing":
    print(os.environ["FAKE_RAW_SECRET"], file=sys.stderr)
    raise SystemExit(3)
expires = "2020-01-01T00:00:00Z" if mode == "expired" else None
print(json.dumps({
    "id": "https://kp-vault.vault.azure.net/secrets/ciphertext-prior-keys/version-1",
    "enabled": mode != "disabled",
    "expires": expires,
    "tags": {
        "kp-ciphertext-format": "kpct-rotation-v1",
        "kp-ciphertext-prior-key-ids": os.environ["FAKE_PRIOR"],
        "kp-ciphertext-active-key-id": os.environ["FAKE_ACTIVE"],
    },
}))
""",
        encoding="utf-8",
    )
    az.chmod(0o700)
    environment = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path),
        "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
        "FAKE_PREVIOUS": json.dumps(
            {"active_key_id": previous_active, "prior_key_ids": previous_prior or [], "prior_key_source": "none"}
        ),
        "FAKE_VAULT_ID": vault_id,
        "FAKE_AZ_MODE": az_mode,
        "FAKE_ACTIVE": active,
        "FAKE_PRIOR": prior,
        "FAKE_RAW_SECRET": "ab" * 32,
        "DEPLOYMENT_PHASE": phase,
        "FAKE_STATE_EXISTS": str(state_exists).lower(),
        "FAKE_STATE_ACCESSIBLE": str(state_accessible).lower(),
    }
    return subprocess.run(  # noqa: S603 - executes the checked-in workflow source with fixed test shims
        [sys.executable, "-c", source],
        cwd=Path(__file__).resolve().parents[3] / "infrastructure" / "terraform",
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_workflow_recovery_preflight_accepts_matching_metadata(tmp_path: Path) -> None:
    result = _run_workflow_recovery_preflight(tmp_path)

    assert result.returncode == 0, result.stderr


def test_workflow_recovery_preflight_allows_only_initial_foundation_without_state(tmp_path: Path) -> None:
    initial = _run_workflow_recovery_preflight(
        tmp_path / "initial",
        prior="",
        phase="foundation_bootstrap",
        state_exists=False,
    )
    assert initial.returncode == 0, initial.stderr

    missing_workload_state = _run_workflow_recovery_preflight(
        tmp_path / "missing-workload-state",
        prior="",
        state_exists=False,
    )
    assert missing_workload_state.returncode != 0
    assert "ACS bootstrap state is required" in missing_workload_state.stderr

    inaccessible_foundation = _run_workflow_recovery_preflight(
        tmp_path / "inaccessible-foundation",
        prior="",
        phase="foundation_bootstrap",
        state_accessible=False,
    )
    assert inaccessible_foundation.returncode != 0
    assert "ciphertext lifecycle state is inaccessible" in inaccessible_foundation.stderr


def test_workflow_recovery_preflight_refuses_foundation_active_id_drift_before_plan(tmp_path: Path) -> None:
    result = _run_workflow_recovery_preflight(
        tmp_path,
        active="rotated",
        prior="",
        phase="foundation_bootstrap",
    )

    assert result.returncode != 0
    assert "active ciphertext key changes are blocked" in result.stderr


@pytest.mark.parametrize(
    ("az_mode", "message"),
    [
        ("missing", "ciphertext prior-key reference is missing or inaccessible"),
        ("disabled", "ciphertext prior-key reference is disabled"),
        ("expired", "ciphertext prior-key reference is expired"),
    ],
)
def test_workflow_recovery_preflight_rejects_stale_or_unknown_reference_without_echo(
    tmp_path: Path,
    az_mode: str,
    message: str,
) -> None:
    result = _run_workflow_recovery_preflight(tmp_path, az_mode=az_mode)

    assert result.returncode != 0
    assert message in result.stderr
    assert "ab" * 32 not in result.stdout + result.stderr


def test_workflow_recovery_preflight_refuses_key_lifecycle_regressions(tmp_path: Path) -> None:
    removal = _run_workflow_recovery_preflight(
        tmp_path / "removal",
        active="primary",
        prior="",
        previous_active="primary",
        previous_prior=["retired"],
    )
    assert removal.returncode != 0
    assert "prior decrypt-only keys cannot be removed" in removal.stderr

    active_drift = _run_workflow_recovery_preflight(
        tmp_path / "active-drift",
        active="rotated",
        prior="primary",
        previous_active="primary",
    )
    assert active_drift.returncode != 0
    assert "active ciphertext key changes are blocked" in active_drift.stderr


@pytest.mark.parametrize("matching_runs", [0, 2])
def test_status_never_misattributes_unrelated_or_ambiguous_runs(matching_runs: int) -> None:
    state: dict[str, Any] = {"dispatched": False, "correlation": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            state["correlation"] = json.loads(request.content)["inputs"]["deployment_request_id"]
            state["dispatched"] = True
            return httpx.Response(204)
        if request.url.path.endswith("/actions/workflows/azure-deploy.yml/runs"):
            runs: list[dict[str, Any]] = []
            if state["dispatched"]:
                runs.append(
                    {
                        "id": 700,
                        "workflow_id": WORKFLOW_ID,
                        "event": "workflow_dispatch",
                        "head_sha": COMMIT_SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "created_at": "2026-08-27T11:00:00Z",
                        "html_url": "https://github.com/example/security-platform/actions/runs/700",
                        "display_title": "manual-unrelated-run",
                    }
                )
                for index in range(matching_runs):
                    runs.append(
                        {
                            "id": 800 + index,
                            "workflow_id": WORKFLOW_ID,
                            "event": "workflow_dispatch",
                            "head_sha": COMMIT_SHA,
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": "2026-08-27T11:00:00Z",
                            "html_url": f"https://github.com/example/security-platform/actions/runs/{800 + index}",
                            "display_title": state["correlation"],
                        }
                    )
            return httpx.Response(200, json={"workflow_runs": runs})
        raise AssertionError("an unrelated run must never be fetched as this deployment")

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    submitted = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    refreshed = service.get_plan(plan["plan_id"], actor="operator")
    assert submitted["state"] == "dispatch_accepted"
    if matching_runs == 0:
        assert refreshed["state"] == "dispatch_accepted"
        assert refreshed["run_id"] is None
    else:
        assert refreshed["state"] == "dispatch_indeterminate"
        assert refreshed["run_id"] is None
        assert "Multiple" in refreshed["last_error"]


def test_recorded_plan_expiry_is_enforced_even_after_store_save() -> None:
    now = [datetime(2026, 8, 27, 12, tzinfo=UTC)]
    service = DeploymentOrchestrator(
        MemoryPlanStore(),
        _successful_gateway(),
        clock=lambda: now[0],
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    now[0] += timedelta(seconds=24 * 60 * 60 + 1)
    with pytest.raises(DeploymentConflict, match="expired"):
        service.get_plan(plan["plan_id"], actor="operator")


def test_plan_operation_lock_serializes_apply_and_refresh() -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    assert store.acquire_operation(plan["plan_id"], "first-request") is True

    with pytest.raises(DeploymentConflict, match="currently being updated"):
        service.get_plan(plan["plan_id"], actor="operator")

    store.release_operation(plan["plan_id"], "wrong-request")
    assert store.acquire_operation(plan["plan_id"], "second-request") is False
    store.release_operation(plan["plan_id"], "first-request")
    assert service.get_plan(plan["plan_id"], actor="operator")["state"] == "reviewed"


def test_latest_plan_index_and_advance_create_new_digest_bound_stage_without_redispatch() -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    bootstrap = service.create_plan(_values(), actor="operator")
    stored = store.load(bootstrap["plan_id"])
    assert stored is not None
    stored["state"] = "workflow_succeeded"
    stored["acs_evidence"] = {
        "status": "verified",
        "schema": "kp.acs-stage-result.v1",
        "deployment_stage": "foundation_bootstrap",
        "evidence_digest": "sha256:" + "1" * 64,
    }
    store.save(stored)

    finalized = service.advance_plan(bootstrap["plan_id"], bootstrap["review_digest"], actor="operator")

    assert finalized["plan_id"] != bootstrap["plan_id"]
    assert finalized["review"]["deployment_stage"] == "foundation_finalize"
    assert finalized["inputs"]["deployment_stage"] == "foundation_finalize"
    assert "deployment_phase" not in finalized["inputs"]
    assert finalized["stage_predecessor"] == {
        "plan_id": bootstrap["plan_id"],
        "deployment_stage": "foundation_bootstrap",
        "review_digest": bootstrap["review_digest"],
        "evidence_digest": "sha256:" + "1" * 64,
    }
    assert finalized["review_digest"] != bootstrap["review_digest"]
    assert store.load(bootstrap["plan_id"])["state"] == "workflow_succeeded"  # type: ignore[index]
    assert service.get_latest_plan("staging", actor="operator")["plan_id"] == finalized["plan_id"]  # type: ignore[index]
    assert service.get_latest_plan("staging", actor="different-operator") is None
    with pytest.raises(DeploymentConflict, match="already been submitted"):
        service.apply(
            bootstrap["plan_id"],
            bootstrap["review_digest"],
            actor="operator",
            rationale="must not redispatch old plan",
            retry=False,
            audit=lambda _detail: None,
        )


def test_advance_requires_verified_exact_stage_evidence() -> None:
    service = _service()
    plan = service.create_plan(_values(), actor="operator")

    with pytest.raises(DeploymentConflict, match="stage evidence is not verified"):
        service.advance_plan(plan["plan_id"], plan["review_digest"], actor="operator")


@pytest.mark.parametrize("capacity", ["attempt", "checkpoint"])
def test_apply_rejects_exhausted_capacity_before_acquiring_leases(capacity: str) -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    public = service.create_plan(_values(), actor="operator")
    stored = store.load(public["plan_id"])
    assert stored is not None
    if capacity == "attempt":
        stored["attempt"] = deployment_orchestration.MAX_DEPLOYMENT_ATTEMPTS
    else:
        while len(stored["checkpoints"]) <= (
            deployment_orchestration.MAX_CHECKPOINTS - deployment_orchestration.CHECKPOINT_RESERVE_PER_ATTEMPT
        ):
            service._append_checkpoint(  # noqa: SLF001 - construct valid bounded stored evidence
                stored,
                "workflow_status_observed",
                evidence={"run_id": len(stored["checkpoints"]) + 1, "status": "running"},
            )
    store.save(stored)

    with pytest.raises(DeploymentConflict, match="safe attempt or checkpoint limit"):
        service.apply(
            public["plan_id"],
            public["review_digest"],
            actor="operator",
            rationale="approved staging",
            retry=False,
            audit=lambda _detail: None,
        )

    assert store.environments == {}
    assert store.attempts == set()


def test_initial_dispatch_intent_write_failure_releases_all_acquired_leases() -> None:
    class FailingStore(MemoryPlanStore):
        fail_next_save = False

        def save(self, plan: dict[str, Any]) -> None:
            if self.fail_next_save:
                self.fail_next_save = False
                raise DeploymentUnavailable("deployment plan storage is unavailable")
            super().save(plan)

    store = FailingStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    store.fail_next_save = True

    with pytest.raises(DeploymentUnavailable, match="deployment plan storage is unavailable"):
        service.apply(
            plan["plan_id"],
            plan["review_digest"],
            actor="operator",
            rationale="approved staging",
            retry=False,
            audit=lambda _detail: None,
        )

    assert store.environments == {}
    assert store.attempts == set()
    assert store.operations == {}


def test_redis_environment_lease_is_atomic_owner_bound_and_renewed(monkeypatch: pytest.MonkeyPatch) -> None:
    class AtomicRedis:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}
            self.expiry: dict[str, int] = {}
            self.eval_calls = 0

        def eval(self, script: str, _keys: int, key: str, *arguments: Any) -> int:
            self.eval_calls += 1
            if "local current" in script:
                owner, ttl = str(arguments[0]), int(arguments[1])
                current = self.values.get(key)
                if current is None:
                    self.values[key] = owner
                    self.expiry[key] = ttl
                    return 1
                if current == owner:
                    self.expiry[key] = ttl
                    return 1
                return 0
            token = str(arguments[0])
            if self.values.get(key) == token:
                self.values.pop(key)
                self.expiry.pop(key, None)
                return 1
            return 0

        def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
            if nx and key in self.values:
                return False
            self.values[key] = value
            if ex is not None:
                self.expiry[key] = ex
            return True

        def close(self) -> None:
            return None

    client = AtomicRedis()
    monkeypatch.setattr(
        deployment_orchestration.redis.Redis,
        "from_url",
        lambda *_args, **_kwargs: client,
    )
    store = RedisPlanStore("redis://unused")

    assert store.acquire_environment("staging", "plan-one") is True
    client.expiry["kp:deployment:active:staging"] = 1
    assert store.acquire_environment("staging", "plan-one") is True
    assert client.expiry["kp:deployment:active:staging"] == deployment_orchestration.ACTIVE_TTL_SECONDS
    assert store.acquire_environment("staging", "plan-two") is False
    store.release_environment("staging", "plan-two")
    assert client.values["kp:deployment:active:staging"] == "plan-one"
    store.release_environment("staging", "plan-one")
    assert "kp:deployment:active:staging" not in client.values
    assert store.acquire_operation("plan-one", "operation-one") is True
    assert store.acquire_operation("plan-one", "operation-two") is False
    store.release_operation("plan-one", "operation-two")
    assert client.values["kp:deployment:operation:plan-one"] == "operation-one"
    store.release_operation("plan-one", "operation-one")
    assert "kp:deployment:operation:plan-one" not in client.values
    assert client.eval_calls == 7


def _github_preflight_response(
    request: httpx.Request,
    *,
    workflow_state: str = "active",
    environment_protected: bool = True,
    admin_bypass_allowed: bool = False,
) -> httpx.Response:
    path = request.url.path
    if path.endswith("/commits/main"):
        return httpx.Response(200, json={"sha": COMMIT_SHA})
    if path.endswith("/actions/workflows/azure-deploy.yml"):
        return httpx.Response(
            200,
            json={"id": WORKFLOW_ID, "path": ".github/workflows/azure-deploy.yml", "state": workflow_state},
        )
    if path.endswith("/contents/.github/workflows/azure-deploy.yml"):
        assert request.url.params["ref"] == COMMIT_SHA
        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "size": len(WORKFLOW_BYTES),
                "sha": WORKFLOW_BLOB_SHA,
                "content": base64.b64encode(WORKFLOW_BYTES).decode("ascii"),
            },
        )
    if path.endswith("/environments/staging"):
        protection_rules = (
            [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"id": 7, "login": "reviewer"}}],
                }
            ]
            if environment_protected
            else []
        )
        return httpx.Response(
            200,
            json={
                "name": "staging",
                "can_admins_bypass": admin_bypass_allowed,
                "protection_rules": protection_rules,
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
            },
        )
    if path.endswith("/environments/staging/variables"):
        assert request.url.params["per_page"] == "100"
        variables = [
            {"name": "TF_STATE_RESOURCE_GROUP", "value": "rg-kp-state"},
            {"name": "TF_STATE_STORAGE_ACCOUNT", "value": "kptfstateprod"},
            {"name": "TF_STATE_CONTAINER", "value": "tfstate"},
        ]
        return httpx.Response(200, json={"total_count": len(variables), "variables": variables})
    raise AssertionError(f"unexpected preflight request: {request.method} {request.url}")


def test_gateway_preflight_proves_fixed_revision_inputs_and_protected_environment() -> None:
    gateway = _gateway(_github_preflight_response)
    snapshot = gateway.preflight("staging")
    assert snapshot.commit_sha == COMMIT_SHA
    assert snapshot.workflow_content_sha256 == EXPECTED_WORKFLOW_SHA256
    assert snapshot.required_reviewer_count == 1
    assert snapshot.admin_bypass_allowed is False
    assert snapshot.deployment_branch_policy_present is True
    public = snapshot.review_payload()
    assert public["input_contract"] == "exact_pinned_workflow_content"
    assert '"login"' not in json.dumps(public).lower()
    assert '"reviewer"' not in json.dumps(public).lower()


def test_checked_in_workflow_and_connector_digest_are_reviewed_together() -> None:
    assert hashlib.sha256(WORKFLOW_BYTES).hexdigest() == EXPECTED_WORKFLOW_SHA256
    workflow = WORKFLOW_BYTES.decode("utf-8")
    for input_name in REQUIRED_WORKFLOW_INPUTS:
        assert f"\n      {input_name}:" in workflow
    assert workflow.startswith("name: Azure deployment\nrun-name: ${{ inputs.deployment_request_id }}\n")
    assert 'if [[ "$GITHUB_SHA" != "$REVIEWED_COMMIT_SHA" ]]' in workflow
    assert workflow.index("- name: Refuse source drift after GUI review") < workflow.index(
        "- name: Authenticate to Azure"
    )
    assert "needs: [qualify, guard]" in workflow
    assert len(REQUIRED_WORKFLOW_INPUTS) <= 25
    assert "reviewed.auto.tfvars.json" in workflow
    assert "if: inputs.deployment_phase == 'workloads'" in workflow
    hermetic_gate = workflow[workflow.index("- name: Required hermetic no-skip suite") :]
    assert hermetic_gate.index("run: make test") < hermetic_gate.index("- name: Required PostgreSQL integration gate")
    assert "if: inputs.deployment_phase" not in hermetic_gate.split("run: make test", 1)[0]
    foundation_apply = workflow[
        workflow.index("- name: Plan ACS foundation bootstrap") : workflow.index(
            "- name: Publish non-secret integration bootstrap plan"
        )
    ]
    assert "if: inputs.deployment_phase == 'foundation_bootstrap'" in foundation_apply
    assert '-var="deploy_workloads=false"' in foundation_apply
    assert foundation_apply.index("terraform plan -out=foundation-bootstrap.tfplan") < foundation_apply.index(
        "- name: Enforce ACS foundation bootstrap plan allowlist"
    )
    assert 'if isinstance(change, dict) and "delete" in change.get("change", {}).get("actions", [])' in foundation_apply
    assert foundation_apply.index("- name: Enforce ACS foundation bootstrap plan allowlist") < foundation_apply.index(
        "terraform apply -auto-approve foundation-bootstrap.tfplan"
    )
    assert workflow.count('-backend-config="resource_group_name=$TF_STATE_RESOURCE_GROUP"') == 1


@pytest.mark.parametrize(
    ("failure_suffix", "status_code", "message"),
    [
        ("/commits/main", 404, "configured deployment ref"),
        ("/actions/workflows/azure-deploy.yml", 404, "deployment workflow"),
        ("/environments/staging", 403, "verify read permissions"),
    ],
)
def test_preflight_fails_closed_for_missing_or_uninspectable_metadata(
    failure_suffix: str,
    status_code: int,
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(failure_suffix):
            return httpx.Response(status_code, text="github_pat_secret-must-not-escape")
        return _github_preflight_response(request)

    with pytest.raises(DeploymentUnavailable, match=message) as caught:
        _gateway(handler).preflight("staging")
    assert "github_pat" not in str(caught.value)


def test_preflight_rejects_oversized_metadata_before_parsing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, content=b"{" + b"x" * (1024 * 1024) + b"}")
        return _github_preflight_response(request)

    with pytest.raises(DeploymentUnavailable, match="exceeds the connector limit"):
        _gateway(handler).preflight("staging")


def test_preflight_pre_rejects_declared_oversize_without_reading_body() -> None:
    guarded = SyncChunks(b'{"sha":"' + COMMIT_SHA.encode() + b'"}', fail_on_read=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(
                200,
                headers={"content-length": str(deployment_orchestration.MAX_GITHUB_METADATA_BYTES + 1)},
                stream=guarded,
            )
        return _github_preflight_response(request)

    with pytest.raises(DeploymentUnavailable, match="exceeds the connector limit"):
        _gateway(handler).preflight("staging")
    assert guarded.iterated is False


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"42"), (b"content-length", b"42")],
        [(b"content-length", b"forty-two")],
        [(b"content-length", b"9" * 100)],
        [(b"content-length", b"-1")],
    ],
)
def test_preflight_rejects_duplicate_or_malformed_content_length(
    headers: list[tuple[bytes, bytes]],
) -> None:
    guarded = SyncChunks(b'{"sha":"' + COMMIT_SHA.encode() + b'"}', fail_on_read=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, headers=headers, stream=guarded)
        return _github_preflight_response(request)

    with pytest.raises(DeploymentUnavailable, match="metadata is malformed"):
        _gateway(handler).preflight("staging")
    assert guarded.iterated is False


def test_status_and_activity_accept_bounded_chunked_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/actions/workflows/azure-deploy.yml/runs"):
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=SyncChunks(b'{"workflow_', b'runs":[]}'),
            )
        if request.url.path.endswith("/actions/runs/501/jobs"):
            return httpx.Response(
                200,
                headers={"content-type": "application/vnd.github+json"},
                stream=SyncChunks(b'{"jo', b'bs":[]}'),
            )
        if request.url.path.endswith("/actions/runs/501"):
            payload = json.dumps(
                {
                    "id": 501,
                    "workflow_id": WORKFLOW_ID,
                    "event": "workflow_dispatch",
                    "head_sha": COMMIT_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-08-27T10:00:00Z",
                    "display_title": "kp-request",
                }
            ).encode()
            return httpx.Response(
                200,
                headers={"content-type": "application/json; charset=utf-8"},
                stream=SyncChunks(payload[:10], payload[10:]),
            )
        raise AssertionError(f"unexpected request: {request.url}")

    gateway = _gateway(handler)
    assert gateway.recent_runs() == []
    assert gateway.activity(501) == []
    assert gateway.run(501)["run_id"] == 501


def test_recent_runs_uses_bounded_pagination_and_deduplicates_page_drift() -> None:
    pages: list[int] = []

    def run_row(run_id: int) -> dict[str, Any]:
        return {
            "id": run_id,
            "workflow_id": WORKFLOW_ID,
            "event": "workflow_dispatch",
            "head_sha": COMMIT_SHA,
            "status": "in_progress",
            "conclusion": None,
            "display_title": f"run-{run_id}",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        assert request.url.params["per_page"] == str(deployment_orchestration.RUNS_PER_PAGE)
        rows = [run_row(run_id) for run_id in range(1, 101)] if page == 1 else [run_row(100), run_row(101)]
        return httpx.Response(200, json={"workflow_runs": rows})

    runs = _gateway(handler).recent_runs()

    assert pages == [1, 2]
    assert len(runs) == 101
    assert len({run["run_id"] for run in runs}) == 101


@pytest.mark.parametrize(
    "change",
    [
        {"event": "push"},
        {"status": "completed", "conclusion": None},
        {"status": {"secret": "value"}, "conclusion": None},
        {"conclusion": {"secret": "value"}},
        {"status": "unknown", "conclusion": None},
        {"id": True},
    ],
)
def test_run_status_rejects_unbound_or_impossible_provider_state(change: dict[str, Any]) -> None:
    payload = {
        "id": 501,
        "workflow_id": WORKFLOW_ID,
        "event": "workflow_dispatch",
        "head_sha": COMMIT_SHA,
        "status": "completed",
        "conclusion": "success",
        "display_title": "kp-request",
        **change,
    }

    with pytest.raises(DeploymentUnavailable, match="invalid workflow run"):
        _gateway(lambda _request: httpx.Response(200, json=payload)).run(501)


@pytest.mark.parametrize("identity_drift", ["workflow", "commit"])
def test_correlated_run_must_match_reviewed_workflow_and_commit(identity_drift: str) -> None:
    state: dict[str, Any] = {"correlation": "", "dispatched": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            state["correlation"] = json.loads(request.content)["inputs"]["deployment_request_id"]
            state["dispatched"] = True
            return httpx.Response(204)
        if request.url.path.endswith("/actions/workflows/azure-deploy.yml/runs"):
            row = {
                "id": 501,
                "workflow_id": WORKFLOW_ID + (1 if identity_drift == "workflow" else 0),
                "event": "workflow_dispatch",
                "head_sha": "d" * 40 if identity_drift == "commit" else COMMIT_SHA,
                "status": "in_progress",
                "conclusion": None,
                "display_title": state["correlation"],
            }
            return httpx.Response(200, json={"workflow_runs": [row] if state["dispatched"] else []})
        raise AssertionError("identity drift must be rejected before a run detail request")

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    refreshed = service.get_plan(plan["plan_id"], actor="operator")

    assert refreshed["state"] == "dispatch_indeterminate"
    assert refreshed["run_id"] is None
    assert "identity changed" in refreshed["last_error"]


def test_run_url_and_activity_fields_are_strictly_allowlisted() -> None:
    gateway = _gateway(lambda _request: httpx.Response(500))
    safe = gateway._safe_run(  # noqa: SLF001 - security boundary unit test
        {
            "id": 501,
            "workflow_id": WORKFLOW_ID,
            "event": "workflow_dispatch",
            "head_sha": COMMIT_SHA,
            "status": "in_progress",
            "conclusion": None,
            "html_url": "https://github.com/example/security-platform/actions/runs/501/../../settings",
        }
    )
    activity = gateway._safe_activity(  # noqa: SLF001 - security boundary unit test
        "job",
        {"name": "Build", "status": "token=provider-secret", "conclusion": {"secret": "value"}},
    )

    assert safe["url"] == gateway.workflow_url
    assert activity["status"] == "unknown"
    assert activity["conclusion"] == ""
    assert "secret" not in json.dumps(activity)


def test_success_without_required_activity_is_evidence_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service()
    plan = service.create_plan(_values(), actor="operator")
    service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )

    def unavailable_activity(_run_id: int) -> list[dict[str, str]]:
        raise DeploymentUnavailable("GitHub workflow activity is unavailable")

    monkeypatch.setattr(service.gateway, "activity", unavailable_activity)
    refreshed = service.get_plan(plan["plan_id"], actor="operator")

    assert refreshed["state"] == "evidence_unverified"
    assert refreshed["activity"] == []
    assert refreshed["activity_available"] is False
    assert refreshed["operator_action"]["retry_allowed"] is False
    assert refreshed["operator_action"]["reconcile_only"] is True


def test_success_with_missing_final_acs_artifact_is_evidence_unverified() -> None:
    gateway = _successful_gateway()

    def missing_artifact(_run_id: int, _run_attempt: int) -> dict[str, Any]:
        raise DeploymentUnavailable("GitHub deployment evidence is unavailable")

    gateway.acs_evidence_artifact = missing_artifact  # type: ignore[method-assign]
    service = DeploymentOrchestrator(
        MemoryPlanStore(),
        gateway,
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )

    refreshed = service.get_plan(plan["plan_id"], actor="operator")

    assert refreshed["state"] == "evidence_unverified"
    assert refreshed["acs_evidence"] == {
        "status": "evidence_unverified",
        "schema": "kp.acs-stage-result.v1",
        "deployment_stage": "foundation_bootstrap",
    }
    assert refreshed["stage_action"]["kind"] == "reconcile"
    assert refreshed["stage_action"]["enabled"] is False


def test_failed_required_workflow_step_is_named_and_never_connector_verified() -> None:
    activity = _successful_activity("workloads")
    failed_step = next(
        row for row in activity if row["kind"] == "step" and row["name"] == "Refuse destructive workload changes"
    )
    failed_step["conclusion"] = "failure"

    recovery = DeploymentOrchestrator._recovery_contract(  # noqa: SLF001 - exact evidence contract
        "workloads",
        activity=activity,
        activity_available=True,
        terminal=True,
        run_succeeded=True,
    )
    verification = recovery["verification"]

    assert verification["status"] == "evidence_unverified"
    assert verification["connector_verified"] is False
    assert verification["missing_required_activity"] == []
    assert verification["failed_required_activity"] == [
        "Deploy reviewed Azure phase / Refuse destructive workload changes"
    ]
    assert all(check["status"] == "not_verified_by_connector" for check in verification["checks"].values())


def test_status_caps_chunked_decoded_bytes_before_json_parsing() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=SyncChunks(
                b"x" * 200_000,
                b"y" * (deployment_orchestration.MAX_GITHUB_STATUS_BYTES - 200_000 + 1),
            ),
        )

    with pytest.raises(DeploymentUnavailable, match="workflow status is unavailable"):
        _gateway(handler).recent_runs()


def test_status_rejects_unrequested_content_encoding() -> None:
    compressed = gzip.compress(b"x" * (deployment_orchestration.MAX_GITHUB_STATUS_BYTES + 1))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
            stream=SyncChunks(compressed),
        )

    with pytest.raises(DeploymentUnavailable, match="workflow status is malformed"):
        _gateway(handler).recent_runs()


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"content-type": "text/html"},
        {"content-type": "application/json, text/html"},
    ],
)
def test_status_rejects_missing_or_ambiguous_json_content_type(headers: dict[str, str]) -> None:
    guarded = SyncChunks(b'{"workflow_runs":[]}', fail_on_read=True)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers=headers, stream=guarded)

    with pytest.raises(DeploymentUnavailable, match="workflow status is malformed"):
        _gateway(handler).recent_runs()
    assert guarded.iterated is False


@pytest.mark.parametrize("body", [b"\xff", b"{not-json", b""])
def test_status_rejects_malformed_utf8_or_json_without_echo(body: bytes) -> None:
    secret = b"github_pat_secret-must-not-escape"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=SyncChunks(body + secret),
        )

    with pytest.raises(DeploymentUnavailable, match="workflow status is malformed") as caught:
        _gateway(handler).recent_runs()
    assert secret.decode() not in str(caught.value)


def test_activity_rejects_declared_oversize_without_reading_body() -> None:
    guarded = SyncChunks(b'{"jobs":[]}', fail_on_read=True)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(deployment_orchestration.MAX_GITHUB_ACTIVITY_BYTES + 1)},
            stream=guarded,
        )

    with pytest.raises(DeploymentUnavailable, match="workflow activity is unavailable"):
        _gateway(handler).activity(501)
    assert guarded.iterated is False


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (400, deployment_orchestration.DispatchRejected),
        (401, deployment_orchestration.DispatchRejected),
        (403, deployment_orchestration.DispatchRejected),
        (404, deployment_orchestration.DispatchRejected),
        (422, deployment_orchestration.DispatchRejected),
        (408, deployment_orchestration.DispatchIndeterminate),
        (425, deployment_orchestration.DispatchIndeterminate),
        (429, deployment_orchestration.DispatchIndeterminate),
        (500, deployment_orchestration.DispatchIndeterminate),
    ],
)
def test_dispatch_classifies_status_without_reading_hostile_error_body(
    status_code: int,
    expected: type[Exception],
) -> None:
    guarded = SyncChunks(b"github_pat_secret" * 100_000, fail_on_read=True)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(
            status_code,
            headers={"content-length": str(10 * 1024 * 1024)},
            stream=guarded,
        )

    with pytest.raises(expected) as caught:
        _gateway(handler).dispatch(DeploymentOrchestrator.workflow_inputs(_values()))
    assert guarded.iterated is False
    assert "github_pat" not in str(caught.value)


def test_preflight_rejects_disabled_workflow_and_unprotected_environment() -> None:
    with pytest.raises(DeploymentUnavailable, match="disabled"):
        _gateway(lambda request: _github_preflight_response(request, workflow_state="disabled_manually")).preflight(
            "staging"
        )
    with pytest.raises(DeploymentUnavailable, match="no required reviewer"):
        _gateway(lambda request: _github_preflight_response(request, environment_protected=False)).preflight("staging")
    with pytest.raises(DeploymentUnavailable, match="administrator approval bypass"):
        _gateway(lambda request: _github_preflight_response(request, admin_bypass_allowed=True)).preflight("staging")


@pytest.mark.parametrize(
    ("environment_change", "message"),
    [
        ({"deployment_branch_policy": None}, "branch policy metadata is malformed"),
        (
            {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": False}},
            "no deployment branch protection",
        ),
    ],
)
def test_preflight_requires_protected_deployment_branches(
    environment_change: dict[str, Any],
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _github_preflight_response(request)
        if request.url.path.endswith("/environments/staging"):
            return httpx.Response(200, json={**response.json(), **environment_change})
        return response

    with pytest.raises(DeploymentUnavailable, match=message):
        _gateway(handler).preflight("staging")


def test_preflight_requires_non_self_reviewable_approval() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _github_preflight_response(request)
        if request.url.path.endswith("/environments/staging"):
            payload = response.json()
            payload["protection_rules"][0]["prevent_self_review"] = False
            return httpx.Response(200, json=payload)
        return response

    with pytest.raises(DeploymentUnavailable, match="allows reviewer self-approval"):
        _gateway(handler).preflight("staging")


def test_preflight_rejects_omitted_admin_bypass_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _github_preflight_response(request)
        if request.url.path.endswith("/environments/staging"):
            payload = response.json()
            payload.pop("can_admins_bypass")
            return httpx.Response(200, json=payload)
        return response

    with pytest.raises(DeploymentUnavailable, match="environment metadata is malformed"):
        _gateway(handler).preflight("staging")


def test_preflight_rejects_an_unrecognized_workflow_input_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    altered = WORKFLOW_BYTES.replace(b"      reviewed_commit_sha:\n", b"      removed_input:\n", 1)
    monkeypatch.setattr(deployment_orchestration, "EXPECTED_WORKFLOW_SHA256", hashlib.sha256(altered).hexdigest())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/contents/.github/workflows/azure-deploy.yml"):
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "encoding": "base64",
                    "size": len(altered),
                    "sha": WORKFLOW_BLOB_SHA,
                    "content": base64.b64encode(altered).decode("ascii"),
                },
            )
        return _github_preflight_response(request)

    with pytest.raises(DeploymentUnavailable, match="input contract is incomplete"):
        _gateway(handler).preflight("staging")


@pytest.mark.parametrize("drift", ["commit", "workflow", "environment", "terraform_state"])
def test_apply_fails_closed_when_reviewed_source_drifts_before_dispatch(drift: str) -> None:
    snapshots = [_preflight(), _preflight()]
    if drift == "commit":
        snapshots[1] = _preflight(commit_sha="d" * 40)
    elif drift == "workflow":
        snapshots[1] = _preflight(workflow_content_sha256="d" * 64)
    elif drift == "terraform_state":
        snapshots[1] = _preflight(tf_state_container="replacement-state")
    else:
        snapshots[1] = _preflight(environment_metadata_sha256="d" * 64)
    calls = iter(snapshots)
    dispatched = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched
        if request.method == "POST":
            dispatched = True
            return httpx.Response(204)
        return httpx.Response(200, json={"workflow_runs": []})

    service = _service(handler, preflight=lambda _environment: next(calls))
    plan = service.create_plan(_values(), actor="operator")
    audited = False

    def audit(_detail: dict[str, Any]) -> None:
        nonlocal audited
        audited = True

    with pytest.raises(DeploymentConflict, match="create and review a new plan"):
        service.apply(
            plan["plan_id"],
            plan["review_digest"],
            actor="operator",
            rationale="approved staging",
            retry=False,
            audit=audit,
        )
    status = service.get_plan(plan["plan_id"], actor="operator", refresh=False)
    assert status["state"] == "review_required"
    assert dispatched is False
    assert audited is True


def test_apply_records_no_dispatch_when_last_moment_preflight_loses_permission() -> None:
    calls = 0

    def preflight(environment: str) -> WorkflowPreflight:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise DeploymentUnavailable("the GitHub connector cannot inspect deployment workflow")
        return _preflight(environment)

    dispatched = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched
        if request.method == "POST":
            dispatched = True
            return httpx.Response(204)
        return httpx.Response(200, json={"workflow_runs": []})

    service = _service(handler, preflight=preflight)
    plan = service.create_plan(_values(), actor="operator")
    with pytest.raises(DeploymentUnavailable, match="cannot inspect"):
        service.apply(
            plan["plan_id"],
            plan["review_digest"],
            actor="operator",
            rationale="approved staging",
            retry=False,
            audit=lambda _detail: None,
        )
    status = service.get_plan(plan["plan_id"], actor="operator", refresh=False)
    assert status["state"] == "dispatch_failed"
    assert "no workflow was dispatched" in status["last_error"]
    assert dispatched is False


def test_plan_digest_and_dispatch_are_bound_to_reviewed_commit() -> None:
    service = _service()
    plan = service.create_plan(_values(), actor="operator")
    assert plan["source_revision"]["commit_sha"] == COMMIT_SHA
    assert plan["source_revision"]["workflow_content_sha256"] == EXPECTED_WORKFLOW_SHA256
    assert '"login"' not in json.dumps(plan["source_revision"]).lower()
    assert '"reviewer"' not in json.dumps(plan["source_revision"]).lower()


def test_public_configuration_does_not_claim_live_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE", "github_actions")
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY", "example/security-platform")
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_REF", "main")
    monkeypatch.setenv("OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN", "github-installation-token-value")
    configuration = DeploymentOrchestrator.public_configuration()
    assert configuration["configured"] is True
    assert configuration["ready"] is False
    assert configuration["readiness_status"] == "requires_reviewed_plan_preflight"
    assert any("does not return protected secret values" in item for item in configuration["preflight_limitations"])


def test_public_configuration_redacts_arbitrary_connector_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "github_pat_private https://provider.invalid/body /private/repo actor=someone Traceback"

    def fail_configuration(_cls: type[WorkflowConfiguration]) -> WorkflowConfiguration:
        raise DeploymentUnavailable(secret)

    monkeypatch.setattr(WorkflowConfiguration, "from_environment", classmethod(fail_configuration))

    configuration = DeploymentOrchestrator.public_configuration()

    assert configuration["reason"] == PUBLIC_DEPLOYMENT_UNAVAILABLE
    assert not any(fragment in json.dumps(configuration) for fragment in (secret, "provider.invalid", "/private/repo"))


@pytest.mark.parametrize(
    ("operation", "method", "path", "body", "error_type", "public_message"),
    [
        (
            "create_plan",
            "post",
            "/api/v1/console/azure-deployment/orchestration/plan",
            {"values": _values()},
            DeploymentUnavailable,
            PUBLIC_DEPLOYMENT_UNAVAILABLE,
        ),
        (
            "get_plan",
            "get",
            f"/api/v1/console/azure-deployment/orchestration/plans/{'a' * 32}",
            None,
            DeploymentConflict,
            PUBLIC_DEPLOYMENT_CONFLICT,
        ),
        (
            "apply",
            "post",
            f"/api/v1/console/azure-deployment/orchestration/plans/{'a' * 32}/apply",
            {"confirm": True, "review_digest": "b" * 64, "rationale": "approved staging"},
            DeploymentUnavailable,
            PUBLIC_DEPLOYMENT_UNAVAILABLE,
        ),
        (
            "apply",
            "post",
            f"/api/v1/console/azure-deployment/orchestration/plans/{'a' * 32}/retry",
            {"confirm": True, "review_digest": "b" * 64, "rationale": "approved staging"},
            DeploymentConflict,
            PUBLIC_DEPLOYMENT_CONFLICT,
        ),
    ],
)
def test_gui_deployment_routes_redact_arbitrary_exception_messages(
    tmp_path,  # noqa: ANN001
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    operation: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    error_type: type[DeploymentUnavailable] | type[DeploymentConflict],
    public_message: str,
) -> None:
    secret = "github_pat_private https://provider.invalid/body /private/repo actor=someone Traceback"
    service = _service()

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise error_type(secret)

    monkeypatch.setattr(service, operation, fail)
    with TestClient(_app(tmp_path, service)) as client:
        headers = _headers(client)
        response = (
            getattr(client, method)(path, headers=headers, json=body)
            if body is not None
            else getattr(client, method)(path, headers=headers)
        )

    assert response.status_code == 409
    assert response.json() == {"code": "KP-005", "detail": f"KP-005: {public_message}"}
    combined = response.text + caplog.text
    assert not any(
        fragment in combined for fragment in (secret, "provider.invalid", "/private/repo", "actor=someone", "Traceback")
    )


def test_known_deployment_guidance_remains_exact_at_gui_boundary(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    service = _service()
    message = "GitHub workflow status is unavailable"

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise DeploymentUnavailable(message)

    monkeypatch.setattr(service, "get_plan", fail)
    with TestClient(_app(tmp_path, service)) as client:
        response = client.get(
            f"/api/v1/console/azure-deployment/orchestration/plans/{'a' * 32}", headers=_headers(client)
        )

    assert response.status_code == 409
    assert response.json()["detail"] == f"KP-005: {message}"


def test_public_plan_redacts_unrecognized_durable_error() -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    stored = store.plans[plan["plan_id"]]
    stored["last_error"] = {"provider_body": "token=private https://provider.invalid/body actor=someone"}

    public = service.get_plan(plan["plan_id"], actor="operator", refresh=False)

    assert public["last_error"] == PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE
    assert not any(
        fragment in json.dumps(public) for fragment in ("token=private", "provider.invalid", "actor=someone")
    )


def test_plan_exposes_preservation_first_recovery_contract_and_evidence_fields() -> None:
    service = _service()
    plan = service.create_plan(_values(), actor="operator")

    recovery = plan["recovery"]
    policy = recovery["policy"]
    assert policy["strategy"] == "reconcile_existing_operation"
    assert policy["automatic_cleanup_allowed"] is False
    assert set(policy["preservation_required"]) == {
        "working_tree",
        "python_environment",
        "terraform_provider_cache",
        "container_images",
        "compose_containers",
        "build_cache",
        "named_volumes",
        "databases",
        "runtime_state",
        "qualification_evidence",
    }
    assert set(policy["prohibited_automatic_actions"]) == {
        "delete_files",
        "prune_build_cache",
        "remove_images",
        "remove_containers",
        "remove_volumes",
        "drop_databases",
        "compose_down",
        "reset_working_tree",
    }
    evidence = recovery["verification"]
    assert evidence["status"] == "awaiting_protected_workflow"
    assert evidence["connector_verified"] is False
    assert set(evidence["checks"]) == {"disk", "runtime", "images", "platform", "volumes", "databases"}
    assert all(check["blocking"] is True for check in evidence["checks"].values())
    assert all(check["status"] == "awaiting_pinned_workflow" for check in evidence["checks"].values())
    assert "free_bytes_before_build" in evidence["checks"]["disk"]["required_fields"]
    assert "required_image_digests" in evidence["checks"]["images"]["required_fields"]
    assert "preservation_decision" in evidence["checks"]["volumes"]["required_fields"]
    assert "backup_or_recovery_evidence" in evidence["checks"]["databases"]["required_fields"]
    assert plan["operator_action"] == {
        "next_action": "Review the preservation and preflight evidence requirements, then approve this plan.",
        "retry_allowed": False,
        "reconcile_only": False,
        "destructive_cleanup_allowed": False,
    }


def test_operation_checkpoints_are_append_only_hash_chained_and_attempt_bound() -> None:
    dispatches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatches
        if request.method == "GET":
            return httpx.Response(200, json={"workflow_runs": []})
        dispatches += 1
        return httpx.Response(422 if dispatches == 1 else 204)

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    first = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    second = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="confirmed rejection corrected",
        retry=True,
        audit=lambda _detail: None,
    )

    assert first["state"] == "dispatch_failed"
    assert second["state"] == "dispatch_accepted"
    checkpoints = second["checkpoints"]
    assert [checkpoint["sequence"] for checkpoint in checkpoints] == list(range(1, len(checkpoints) + 1))
    assert checkpoints[0]["phase"] == "plan_reviewed"
    assert checkpoints[-1]["phase"] == "dispatch_accepted"
    assert {checkpoint["attempt"] for checkpoint in checkpoints} == {0, 1, 2}
    previous_digest = None
    for checkpoint in checkpoints:
        assert checkpoint["previous_digest"] == previous_digest
        unsigned = {key: value for key, value in checkpoint.items() if key != "digest"}
        assert (
            checkpoint["digest"]
            == hashlib.sha256(json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
        )
        previous_digest = checkpoint["digest"]


def test_indeterminate_reentry_reconciles_without_redispatch_or_checkpoint_churn() -> None:
    dispatches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatches
        if request.method == "POST":
            dispatches += 1
            raise httpx.ReadTimeout("outcome unknown", request=request)
        return httpx.Response(200, json={"workflow_runs": []})

    service = _service(handler)
    plan = service.create_plan(_values(), actor="operator")
    submitted = service.apply(
        plan["plan_id"],
        plan["review_digest"],
        actor="operator",
        rationale="approved staging",
        retry=False,
        audit=lambda _detail: None,
    )
    first_refresh = service.get_plan(plan["plan_id"], actor="operator")
    second_refresh = service.get_plan(plan["plan_id"], actor="operator")

    assert dispatches == 1
    assert submitted["state"] == first_refresh["state"] == second_refresh["state"] == "dispatch_indeterminate"
    assert first_refresh["checkpoints"] == second_refresh["checkpoints"]
    assert second_refresh["operator_action"] == {
        "next_action": (
            "Inspect GitHub Actions for the displayed correlation ID, then refresh; do not retry or clean up resources."
        ),
        "retry_allowed": False,
        "reconcile_only": True,
        "destructive_cleanup_allowed": False,
    }


@pytest.mark.parametrize(
    ("last_phase", "expected_state"),
    [
        ("audit_evidence_committed", "dispatch_failed"),
        ("source_revalidated", "dispatch_indeterminate"),
    ],
)
def test_interrupted_dispatch_reentry_uses_checkpoint_to_choose_safe_recovery(
    last_phase: str,
    expected_state: str,
) -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    public = service.create_plan(_values(), actor="operator")
    stored = store.load(public["plan_id"])
    assert stored is not None
    stored.update(
        {
            "attempt": 1,
            "state": "dispatching",
            "baseline_run_ids": [],
            "correlation_id": f"kp-{public['plan_id']}-1",
        }
    )
    service._append_checkpoint(  # noqa: SLF001 - exercise durable crash recovery seam
        stored,
        "dispatch_intent_saved",
        evidence={"baseline_run_count": 0, "retry": False},
    )
    service._append_checkpoint(stored, "audit_evidence_committed")  # noqa: SLF001
    if last_phase == "source_revalidated":
        service._append_checkpoint(  # noqa: SLF001
            stored,
            "source_revalidated",
            evidence={"source_revision_digest": "d" * 64},
        )
    store.save(stored)

    recovered = service.get_plan(public["plan_id"], actor="operator")

    assert recovered["state"] == expected_state
    assert recovered["operator_action"]["retry_allowed"] is False
    assert recovered["operator_action"]["reconcile_only"] is True
    assert recovered["operator_action"]["destructive_cleanup_allowed"] is False
    assert recovered["checkpoints"][-1]["evidence"]["retry_safe"] is False
    assert recovered["checkpoints"][-1]["phase"] == (
        "dispatch_interrupted" if last_phase == "audit_evidence_committed" else "dispatch_indeterminate"
    )


@pytest.mark.parametrize("tamper", ["checkpoint", "recovery"])
def test_tampered_recovery_state_fails_closed_with_bounded_error(tamper: str) -> None:
    store = MemoryPlanStore()
    service = DeploymentOrchestrator(
        store,
        _successful_gateway(),
        preflight=lambda environment: _preflight(environment),
    )
    plan = service.create_plan(_values(), actor="operator")
    stored = store.plans[plan["plan_id"]]
    if tamper == "checkpoint":
        stored["checkpoints"][0]["evidence"]["review_digest"] = "f" * 64
    else:
        stored["recovery"]["policy"]["automatic_cleanup_allowed"] = True

    with pytest.raises(DeploymentUnavailable, match="deployment plan storage is malformed") as caught:
        service.get_plan(plan["plan_id"], actor="operator", refresh=False)

    assert str(caught.value) == "deployment plan storage is malformed"
