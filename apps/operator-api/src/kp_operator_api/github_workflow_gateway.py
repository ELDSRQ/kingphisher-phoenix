"""GitHub workflow gateway for the reviewed Azure deployment.

A narrow connector: reads the checked-in azure-deploy.yml workflow from the
configured repository/ref and dispatches reviewed deployment events. It never
accepts a command, path, repository, ref, or credential from the browser.

Trust boundary: server-side HTTPS calls to the GitHub API only. Responses are
size-bounded and JSON-decoded with a bounded decoder; workflow content is
pinned by EXPECTED_WORKFLOW_SHA256 (resolved through the kp_operator_api
deployment facade so operator tests can override it).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import secrets
import zipfile
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from kp_operator_api.deployment_common import (
    _ACTIVITY_STATUSES,
    _COMMIT_SHA,
    _JSON_CONTENT_TYPE,
    _RUN_STATUSES,
    _SENSITIVE_ACTIVITY,
    _TERMINAL_RESULTS,
    ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS,
    ACS_EVIDENCE_ARTIFACT_PATH,
    MAX_ACS_ARTIFACT_BYTES,
    MAX_ACS_EVIDENCE_BYTES,
    MAX_ACTIVITY,
    MAX_BASELINE_RUNS,
    MAX_GITHUB_ACTIVITY_BYTES,
    MAX_GITHUB_METADATA_BYTES,
    MAX_GITHUB_STATUS_BYTES,
    MAX_RUN_PAGES,
    MAX_STEPS_PER_JOB,
    MAX_WORKFLOW_BYTES,
    REQUIRED_WORKFLOW_INPUTS,
    RUNS_PER_PAGE,
    WORKFLOW_FILE,
    WORKFLOW_PATH,
    DeploymentUnavailable,
    DispatchIndeterminate,
    DispatchRejected,
    WorkflowConfiguration,
    WorkflowPreflight,
)


def _facade(name: str) -> Any:
    """Resolve a name on the deployment_orchestration facade at call time.

    The gateway reads EXPECTED_WORKFLOW_SHA256 through the facade so operator
    tests that monkeypatch deployment_orchestration.EXPECTED_WORKFLOW_SHA256
    keep intercepting after the class extraction.
    """

    import kp_operator_api.deployment_orchestration as facade

    return getattr(facade, name)


class GitHubWorkflowGateway:
    """Fixed-origin GitHub API client; response bodies never cross the boundary."""

    def __init__(self, configuration: WorkflowConfiguration, *, client: httpx.Client | None = None) -> None:
        self.configuration = configuration
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url="https://api.github.com",
            timeout=8.0,
            follow_redirects=False,
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {configuration.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "kingphisher-deployment-orchestrator/1",
            },
        )
        base_url = self._client.base_url
        if (
            base_url.scheme != "https"
            or base_url.host != "api.github.com"
            or base_url.port is not None
            or base_url.userinfo
            or base_url.path != "/"
            or base_url.query
            or base_url.fragment
        ):
            if self._owns_client:
                self._client.close()
            raise DeploymentUnavailable("the server-side GitHub API origin is invalid")
        self._client.headers["Accept-Encoding"] = "identity"

    def close(self) -> None:
        """Close only the HTTP client created by this gateway."""
        if self._owns_client:
            self._client.close()

    @property
    def workflow_url(self) -> str:
        return f"https://github.com/{self.configuration.repository}/actions/workflows/{WORKFLOW_FILE}"

    def _workflow_api(self, suffix: str = "") -> str:
        return f"/repos/{self.configuration.repository}/actions/workflows/{WORKFLOW_FILE}{suffix}"

    def _get_json(
        self,
        path: str,
        *,
        purpose: str,
        params: dict[str, str | int] | None = None,
        max_bytes: int = MAX_GITHUB_METADATA_BYTES,
        unavailable_message: str | None = None,
        malformed_message: str | None = None,
        preserve_access_semantics: bool = True,
    ) -> dict[str, Any]:
        unavailable = unavailable_message or f"GitHub {purpose} is unavailable"
        malformed = malformed_message or f"GitHub {purpose} metadata is malformed"
        try:
            with self._client.stream("GET", path, params=params) as response:
                if preserve_access_semantics and response.status_code in {401, 403}:
                    raise DeploymentUnavailable(
                        f"the GitHub connector cannot inspect {purpose}; verify read permissions"
                    )
                if preserve_access_semantics and response.status_code == 404:
                    raise DeploymentUnavailable(f"GitHub {purpose} is missing or is not visible to the connector")
                if not 200 <= response.status_code < 300:
                    raise DeploymentUnavailable(unavailable)

                content_lengths = response.headers.get_list("content-length")
                if len(content_lengths) > 1:
                    raise DeploymentUnavailable(malformed)
                if content_lengths:
                    declared = content_lengths[0]
                    if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None:
                        raise DeploymentUnavailable(malformed)
                    if int(declared) > max_bytes:
                        raise DeploymentUnavailable(
                            f"GitHub {purpose} metadata exceeds the connector limit"
                            if preserve_access_semantics
                            else unavailable
                        )

                content_encodings = response.headers.get_list("content-encoding")
                if len(content_encodings) > 1 or (
                    content_encodings and content_encodings[0].strip().lower() not in {"", "identity"}
                ):
                    raise DeploymentUnavailable(malformed)
                content_types = response.headers.get_list("content-type")
                if len(content_types) != 1:
                    raise DeploymentUnavailable(malformed)
                media_type = content_types[0].split(";", maxsplit=1)[0].strip()
                if _JSON_CONTENT_TYPE.fullmatch(media_type) is None:
                    raise DeploymentUnavailable(malformed)

                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > max_bytes:
                        raise DeploymentUnavailable(
                            f"GitHub {purpose} metadata exceeds the connector limit"
                            if preserve_access_semantics
                            else unavailable
                        )
                    body.extend(chunk)
        except DeploymentUnavailable:
            raise
        except httpx.HTTPError:
            raise DeploymentUnavailable(unavailable) from None
        try:
            payload = json.loads(bytes(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise DeploymentUnavailable(malformed) from None
        if not isinstance(payload, dict):
            raise DeploymentUnavailable(malformed)
        return payload

    @staticmethod
    def _bounded_response_bytes(response: httpx.Response, *, max_bytes: int) -> bytes:
        content_lengths = response.headers.get_list("content-length")
        if len(content_lengths) > 1:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        if content_lengths:
            declared = content_lengths[0]
            if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None or int(declared) > max_bytes:
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        encodings = response.headers.get_list("content-encoding")
        if len(encodings) > 1 or (encodings and encodings[0].strip().lower() not in {"", "identity"}):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > max_bytes:
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _safe_artifact_redirect(value: str) -> bool:
        try:
            parsed = urlsplit(value)
            host = (parsed.hostname or "").lower()
            return bool(
                parsed.scheme == "https"
                and parsed.port is None
                and parsed.username is None
                and parsed.password is None
                and not parsed.fragment
                and (
                    host == "pipelines.actions.githubusercontent.com"
                    or host.endswith(".actions.githubusercontent.com")
                    or host.endswith(".blob.core.windows.net")
                )
            )
        except ValueError:
            return False

    def _artifact_archive(self, path: str) -> bytes:
        """Download one bounded ZIP without forwarding GitHub credentials cross-origin."""

        try:
            with self._client.stream("GET", path) as response:
                if response.status_code == 200:
                    return self._bounded_response_bytes(response, max_bytes=MAX_ACS_ARTIFACT_BYTES)
                if response.status_code != 302:
                    raise DeploymentUnavailable("GitHub deployment evidence is unavailable")
                locations = response.headers.get_list("location")
                if len(locations) != 1 or not self._safe_artifact_redirect(locations[0]):
                    raise DeploymentUnavailable("GitHub deployment evidence is malformed")
                location = locations[0]
            # Use an isolated client so the GitHub bearer token is never sent to
            # the short-lived object-storage URL.
            with (
                httpx.Client(
                    timeout=8.0,
                    follow_redirects=False,
                    headers={"Accept-Encoding": "identity", "User-Agent": "kingphisher-deployment-orchestrator/1"},
                ) as artifact_client,
                artifact_client.stream("GET", location) as artifact_response,
            ):
                if artifact_response.status_code != 200:
                    raise DeploymentUnavailable("GitHub deployment evidence is unavailable")
                return self._bounded_response_bytes(artifact_response, max_bytes=MAX_ACS_ARTIFACT_BYTES)
        except DeploymentUnavailable:
            raise
        except httpx.HTTPError:
            raise DeploymentUnavailable("GitHub deployment evidence is unavailable") from None

    def acs_evidence_artifact(self, run_id: int, run_attempt: int) -> dict[str, Any]:
        """Return the one exact ACS live-read artifact from a completed workflow attempt."""

        expected_name = f"azure-deployment-evidence-{run_id}-{run_attempt}"
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}/artifacts",
            params={"per_page": 100},
            purpose="deployment evidence",
            max_bytes=MAX_GITHUB_STATUS_BYTES,
            unavailable_message="GitHub deployment evidence is unavailable",
            malformed_message="GitHub deployment evidence is malformed",
            preserve_access_semantics=False,
        )
        artifacts = payload.get("artifacts")
        total_count = payload.get("total_count")
        if (
            not isinstance(artifacts, list)
            or len(artifacts) > 100
            or not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count != len(artifacts)
            or any(not isinstance(item, dict) for item in artifacts)
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        matches = [item for item in artifacts if item.get("name") == expected_name]
        if len(matches) != 1:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        artifact = matches[0]
        artifact_id = artifact.get("id")
        artifact_size = artifact.get("size_in_bytes")
        artifact_digest = artifact.get("digest")
        archive_url = artifact.get("archive_download_url")
        expected_url = (
            f"https://api.github.com/repos/{self.configuration.repository}/actions/artifacts/{artifact_id}/zip"
        )
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or not 0 < artifact_id <= 2**63 - 1
            or not isinstance(artifact_size, int)
            or isinstance(artifact_size, bool)
            or not 0 < artifact_size <= MAX_ACS_ARTIFACT_BYTES
            or artifact.get("expired") is not False
            or not isinstance(artifact_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest) is None
            or archive_url != expected_url
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        archive = self._artifact_archive(f"/repos/{self.configuration.repository}/actions/artifacts/{artifact_id}/zip")
        if len(archive) != artifact_size:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        archive_sha256 = f"sha256:{hashlib.sha256(archive).hexdigest()}"
        if not secrets.compare_digest(archive_sha256, artifact_digest):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                members = bundle.infolist()
                names = [member.filename for member in members]
                if (
                    not 1 <= len(members) <= len(ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS)
                    or len(set(names)) != len(names)
                    or ACS_EVIDENCE_ARTIFACT_PATH not in names
                    or any(
                        name not in ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS
                        or member.is_dir()
                        or member.file_size
                        > (MAX_ACS_ARTIFACT_BYTES if name == "checkpoints.ndjson" else MAX_ACS_EVIDENCE_BYTES)
                        or member.compress_size > MAX_ACS_ARTIFACT_BYTES
                        for name, member in zip(names, members, strict=True)
                    )
                    or bundle.testzip() is not None
                ):
                    raise DeploymentUnavailable("GitHub deployment evidence is malformed")
                evidence_bytes = bundle.read(ACS_EVIDENCE_ARTIFACT_PATH)
                live_bytes = bundle.read("acs-live-readiness.json")
        except (KeyError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
        if not 0 < len(evidence_bytes) <= MAX_ACS_EVIDENCE_BYTES:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        try:
            evidence = json.loads(evidence_bytes.decode("utf-8"))
            live_evidence = json.loads(live_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
        if not isinstance(evidence, dict) or not isinstance(live_evidence, dict):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        phase = evidence.get("phase")
        if not isinstance(phase, str):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_path = {
            "foundation_bootstrap": "acs-verification-initiation.json",
            "foundation_finalize": "acs-finalize-readback.json",
            "workloads": None,
        }.get(phase, "invalid")
        expected_paths = {"checkpoints.ndjson", "acs-live-readiness.json", "acs-stage-result.json"}
        if isinstance(source_path, str) and source_path != "invalid":
            expected_paths.add(source_path)
        if source_path == "invalid" or set(names) != expected_paths:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_evidence: dict[str, Any] | None = None
        if isinstance(source_path, str):
            try:
                with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                    source_evidence = json.loads(bundle.read(source_path).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, KeyError, zipfile.BadZipFile):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
            if not isinstance(source_evidence, dict):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        return {
            "artifact_sha256": artifact_digest,
            "stage_result": evidence,
            "live_readiness": live_evidence,
            "stage_source": source_evidence,
        }

    def preflight(self, environment: str) -> WorkflowPreflight:
        """Prove the fixed workflow revision and protected environment metadata."""

        if environment not in {"staging", "production"}:
            raise DeploymentUnavailable("the fixed workflow environment is invalid")
        repository_api = f"/repos/{self.configuration.repository}"
        encoded_ref = quote(self.configuration.ref, safe="")
        commit_payload = self._get_json(
            f"{repository_api}/commits/{encoded_ref}",
            purpose="configured deployment ref",
        )
        commit_sha = commit_payload.get("sha")
        if not isinstance(commit_sha, str) or _COMMIT_SHA.fullmatch(commit_sha) is None:
            raise DeploymentUnavailable("GitHub configured deployment ref metadata is malformed")

        workflow_payload = self._get_json(self._workflow_api(), purpose="deployment workflow")
        if workflow_payload.get("path") != WORKFLOW_PATH:
            raise DeploymentUnavailable("GitHub deployment workflow path does not match the fixed connector")
        if workflow_payload.get("state") != "active":
            raise DeploymentUnavailable("the fixed GitHub deployment workflow is disabled")
        workflow_id = workflow_payload.get("id")
        if not isinstance(workflow_id, int) or isinstance(workflow_id, bool) or not 0 < workflow_id <= 2**63 - 1:
            raise DeploymentUnavailable("GitHub deployment workflow metadata is malformed")

        content_payload = self._get_json(
            f"{repository_api}/contents/{WORKFLOW_PATH}",
            purpose="deployment workflow content",
            params={"ref": commit_sha},
        )
        encoded_content = content_payload.get("content")
        workflow_blob_sha = content_payload.get("sha")
        size = content_payload.get("size")
        if (
            content_payload.get("type") != "file"
            or content_payload.get("encoding") != "base64"
            or not isinstance(encoded_content, str)
            or len(encoded_content) > MAX_WORKFLOW_BYTES * 2
            or not isinstance(size, int)
            or not 0 < size <= MAX_WORKFLOW_BYTES
            or not isinstance(workflow_blob_sha, str)
            or _COMMIT_SHA.fullmatch(workflow_blob_sha) is None
        ):
            raise DeploymentUnavailable("GitHub deployment workflow content metadata is malformed")
        try:
            compact_content = "".join(encoded_content.split())
            workflow_content = base64.b64decode(compact_content, validate=True)
        except (ValueError, TypeError) as exc:
            raise DeploymentUnavailable("GitHub deployment workflow content is malformed") from exc
        if len(workflow_content) != size:
            raise DeploymentUnavailable("GitHub deployment workflow content size is inconsistent")
        workflow_content_sha256 = hashlib.sha256(workflow_content).hexdigest()
        if not secrets.compare_digest(workflow_content_sha256, _facade("EXPECTED_WORKFLOW_SHA256")):
            raise DeploymentUnavailable("the configured ref does not contain the reviewed deployment workflow")
        try:
            workflow_text = workflow_content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DeploymentUnavailable("GitHub deployment workflow content is malformed") from exc
        missing_inputs = [name for name in REQUIRED_WORKFLOW_INPUTS if f"\n      {name}:" not in workflow_text]
        if missing_inputs:
            raise DeploymentUnavailable("the fixed deployment workflow input contract is incomplete")

        environment_payload = self._get_json(
            f"{repository_api}/environments/{environment}",
            purpose=f"protected {environment} environment",
        )
        if environment_payload.get("name") != environment:
            raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
        rules = environment_payload.get("protection_rules")
        admin_bypass_allowed = environment_payload.get("can_admins_bypass")
        if not isinstance(rules, list) or len(rules) > 20 or not isinstance(admin_bypass_allowed, bool):
            raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
        if admin_bypass_allowed:
            raise DeploymentUnavailable(f"the GitHub {environment} environment allows administrator approval bypass")
        normalized_rules: list[dict[str, Any]] = []
        required_reviewer_count = 0
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("type"), str) or len(rule["type"]) > 64:
                raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
            normalized_rule: dict[str, Any] = {"type": rule["type"]}
            if rule["type"] == "required_reviewers":
                reviewers = rule.get("reviewers")
                prevent_self_review = rule.get("prevent_self_review")
                if not isinstance(reviewers, list) or len(reviewers) > 6 or not isinstance(prevent_self_review, bool):
                    raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                reviewer_keys: list[str] = []
                for reviewer in reviewers:
                    if not isinstance(reviewer, dict) or reviewer.get("type") not in {"User", "Team"}:
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    identity = reviewer.get("reviewer")
                    if not isinstance(identity, dict):
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    identity_key = identity.get("node_id", identity.get("id", identity.get("login")))
                    if (
                        not isinstance(identity_key, str | int)
                        or isinstance(identity_key, bool)
                        or len(str(identity_key)) > 256
                    ):
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    reviewer_keys.append(f"{reviewer['type']}:{identity_key}")
                required_reviewer_count += len(reviewer_keys)
                normalized_rule["reviewers"] = sorted(reviewer_keys)
                normalized_rule["prevent_self_review"] = prevent_self_review
                if not prevent_self_review:
                    raise DeploymentUnavailable(f"the GitHub {environment} environment allows reviewer self-approval")
            elif rule["type"] == "wait_timer":
                wait_timer = rule.get("wait_timer")
                if not isinstance(wait_timer, int) or isinstance(wait_timer, bool) or not 0 <= wait_timer <= 43_200:
                    raise DeploymentUnavailable("GitHub protected environment wait timer metadata is malformed")
                normalized_rule["wait_timer"] = wait_timer
            normalized_rules.append(normalized_rule)
        if required_reviewer_count < 1:
            raise DeploymentUnavailable(f"the GitHub {environment} environment has no required reviewer protection")
        branch_policy = environment_payload.get("deployment_branch_policy")
        if not isinstance(branch_policy, dict):
            raise DeploymentUnavailable("GitHub protected environment branch policy metadata is malformed")
        protected_branches = branch_policy.get("protected_branches")
        custom_branch_policies = branch_policy.get("custom_branch_policies")
        if not isinstance(protected_branches, bool) or not isinstance(custom_branch_policies, bool):
            raise DeploymentUnavailable("GitHub protected environment branch policy metadata is malformed")
        if not protected_branches and not custom_branch_policies:
            raise DeploymentUnavailable(f"the GitHub {environment} environment has no deployment branch protection")
        normalized_branch_policy = {
            "protected_branches": protected_branches,
            "custom_branch_policies": custom_branch_policies,
        }
        variables_payload = self._get_json(
            f"{repository_api}/environments/{environment}/variables",
            purpose=f"protected {environment} environment variables",
            params={"per_page": 100},
        )
        variables = variables_payload.get("variables")
        total_count = variables_payload.get("total_count")
        if (
            not isinstance(variables, list)
            or len(variables) > 100
            or not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count != len(variables)
            or any(not isinstance(variable, dict) for variable in variables)
        ):
            raise DeploymentUnavailable("GitHub protected environment variable metadata is malformed")
        protected_values: dict[str, str] = {}
        required_variables = {
            "TF_STATE_RESOURCE_GROUP",
            "TF_STATE_STORAGE_ACCOUNT",
            "TF_STATE_CONTAINER",
        }
        for variable in variables:
            name = variable.get("name")
            value = variable.get("value")
            if name not in required_variables:
                continue
            if name in protected_values or not isinstance(value, str) or len(value) > 128:
                raise DeploymentUnavailable("GitHub protected environment variable metadata is malformed")
            protected_values[str(name)] = value
        if set(protected_values) != required_variables:
            raise DeploymentUnavailable("GitHub protected environment Terraform state variables are incomplete")
        terraform_state_identity = {
            "resource_group": protected_values["TF_STATE_RESOURCE_GROUP"],
            "storage_account": protected_values["TF_STATE_STORAGE_ACCOUNT"],
            "container": protected_values["TF_STATE_CONTAINER"],
        }
        terraform_state_patterns = {
            "resource_group": r"[A-Za-z0-9_.()\-]{1,90}",
            "storage_account": r"[a-z0-9]{3,24}",
            "container": r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?",
        }
        if any(
            re.fullmatch(terraform_state_patterns[key], value) is None
            for key, value in terraform_state_identity.items()
        ):
            raise DeploymentUnavailable("GitHub protected environment Terraform state variables are malformed")
        protected_metadata = {
            "environment": environment,
            "can_admins_bypass": admin_bypass_allowed,
            "protection_rules": sorted(normalized_rules, key=lambda rule: json.dumps(rule, sort_keys=True)),
            "deployment_branch_policy": normalized_branch_policy,
            "terraform_state_identity": terraform_state_identity,
        }
        environment_metadata_sha256 = hashlib.sha256(
            json.dumps(protected_metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return WorkflowPreflight(
            commit_sha=commit_sha,
            workflow_id=workflow_id,
            workflow_blob_sha=workflow_blob_sha,
            workflow_content_sha256=workflow_content_sha256,
            environment_metadata_sha256=environment_metadata_sha256,
            environment=environment,
            required_reviewer_count=required_reviewer_count,
            admin_bypass_allowed=admin_bypass_allowed,
            deployment_branch_policy_present=True,
            tf_state_resource_group=terraform_state_identity["resource_group"],
            tf_state_storage_account=terraform_state_identity["storage_account"],
            tf_state_container=terraform_state_identity["container"],
        )

    def recent_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        seen_run_ids: set[int] = set()
        for page in range(1, MAX_RUN_PAGES + 1):
            payload = self._get_json(
                self._workflow_api("/runs"),
                params={"event": "workflow_dispatch", "per_page": RUNS_PER_PAGE, "page": page},
                purpose="workflow status",
                max_bytes=MAX_GITHUB_STATUS_BYTES,
                unavailable_message="GitHub workflow status is unavailable",
                malformed_message="GitHub workflow status is malformed",
                preserve_access_semantics=False,
            )
            rows = payload.get("workflow_runs") if isinstance(payload, dict) else None
            if (
                not isinstance(rows, list)
                or len(rows) > RUNS_PER_PAGE
                or any(not isinstance(row, dict) for row in rows)
            ):
                raise DeploymentUnavailable("GitHub workflow status is malformed")
            for row in rows:
                safe_run = self._safe_run(row)
                run_id = int(safe_run["run_id"])
                if run_id not in seen_run_ids:
                    seen_run_ids.add(run_id)
                    runs.append(safe_run)
            if len(rows) < RUNS_PER_PAGE:
                break
        return runs[:MAX_BASELINE_RUNS]

    def dispatch(self, inputs: dict[str, str]) -> None:
        try:
            with self._client.stream(
                "POST",
                self._workflow_api("/dispatches"),
                json={"ref": self.configuration.ref, "inputs": inputs},
            ) as response:
                status_code = response.status_code
        except httpx.RequestError:
            raise DispatchIndeterminate("GitHub dispatch outcome is unknown; inspect Actions before retrying") from None
        if status_code == 204:
            return
        # Only the documented, pre-dispatch GitHub rejection classes are safe
        # to retry. A timeout, rate-limit, or unfamiliar client-error response
        # can be observed after an intermediary or GitHub accepted the request,
        # so treating every 4xx as conclusive could duplicate a deployment.
        if status_code in {400, 401, 403, 404, 422}:
            raise DispatchRejected("GitHub rejected the fixed workflow dispatch")
        raise DispatchIndeterminate("GitHub dispatch outcome is unknown; inspect Actions before retrying")

    def run(self, run_id: int) -> dict[str, Any]:
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}",
            purpose="workflow run status",
            max_bytes=MAX_GITHUB_STATUS_BYTES,
            unavailable_message="GitHub workflow run status is unavailable",
            malformed_message="GitHub workflow run status is malformed",
            preserve_access_semantics=False,
        )
        return self._safe_run(payload)

    def activity(self, run_id: int) -> list[dict[str, str]]:
        """Return bounded job/step state, never raw workflow logs."""
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}/jobs",
            params={"filter": "latest", "per_page": 20},
            purpose="workflow activity",
            max_bytes=MAX_GITHUB_ACTIVITY_BYTES,
            unavailable_message="GitHub workflow activity is unavailable",
            malformed_message="GitHub workflow activity is unavailable",
            preserve_access_semantics=False,
        )
        jobs = payload.get("jobs")
        if not isinstance(jobs, list) or len(jobs) > 20 or any(not isinstance(job, dict) for job in jobs):
            raise DeploymentUnavailable("GitHub workflow activity is unavailable")
        activity: list[dict[str, str]] = []
        for job in jobs:
            safe_job = self._safe_activity("job", job)
            activity.append(safe_job)
            steps = job.get("steps")
            if isinstance(steps, list):
                if len(steps) > MAX_STEPS_PER_JOB or any(not isinstance(step, dict) for step in steps):
                    raise DeploymentUnavailable("GitHub workflow activity is unavailable")
                activity.extend(self._safe_activity("step", step, job_name=safe_job["name"]) for step in steps)
            if len(activity) > MAX_ACTIVITY:
                raise DeploymentUnavailable("GitHub workflow activity is unavailable")
        return activity

    def _safe_run(self, row: dict[str, Any]) -> dict[str, Any]:
        run_id = row.get("id")
        run_attempt = row.get("run_attempt", 1)
        status = row.get("status")
        conclusion = row.get("conclusion")
        workflow_id = row.get("workflow_id")
        event = row.get("event")
        head_sha = row.get("head_sha")
        created_at = row.get("created_at")
        html_url = row.get("html_url")
        display_title = row.get("display_title")
        if (
            not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or not 0 < run_id <= 2**63 - 1
            or not isinstance(run_attempt, int)
            or isinstance(run_attempt, bool)
            or not 1 <= run_attempt <= 100
            or not isinstance(status, str)
            or status not in _RUN_STATUSES
            or not isinstance(workflow_id, int)
            or isinstance(workflow_id, bool)
            or not 0 < workflow_id <= 2**63 - 1
            or event != "workflow_dispatch"
            or not isinstance(head_sha, str)
            or _COMMIT_SHA.fullmatch(head_sha) is None
            or (status == "completed" and (not isinstance(conclusion, str) or conclusion not in _TERMINAL_RESULTS))
            or (status != "completed" and conclusion is not None)
        ):
            raise DeploymentUnavailable("GitHub returned an invalid workflow run")
        return {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "workflow_id": workflow_id,
            "event": event,
            "head_sha": head_sha,
            "status": status,
            "conclusion": conclusion,
            "created_at": created_at if isinstance(created_at, str) and len(created_at) <= 64 else None,
            "run_name": display_title if isinstance(display_title, str) and len(display_title) <= 64 else "",
            "url": html_url if self._safe_run_url(html_url, run_id) else self.workflow_url,
        }

    def _safe_run_url(self, value: Any, run_id: int) -> bool:
        if not isinstance(value, str) or len(value) > 512:
            return False
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.netloc == "github.com"
            and parsed.path == f"/{self.configuration.repository}/actions/runs/{run_id}"
            and not parsed.query
            and not parsed.fragment
        )

    @staticmethod
    def _safe_activity(kind: str, row: dict[str, Any], *, job_name: str = "") -> dict[str, str]:
        name = row.get("name")
        status = row.get("status")
        conclusion = row.get("conclusion")
        safe_name = re.sub(r"[^A-Za-z0-9 ._:/()\[\]-]", "?", name if isinstance(name, str) else kind)[:120]
        if _SENSITIVE_ACTIVITY.search(safe_name):
            safe_name = "[redacted activity name]"
        activity = {
            "kind": kind,
            "name": safe_name,
            "status": status if isinstance(status, str) and status in _ACTIVITY_STATUSES else "unknown",
            "conclusion": (conclusion if isinstance(conclusion, str) and conclusion in _TERMINAL_RESULTS else ""),
        }
        if kind == "step":
            activity["job"] = job_name[:120]
        return activity
