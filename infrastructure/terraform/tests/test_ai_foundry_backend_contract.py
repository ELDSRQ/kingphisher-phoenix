"""Static contracts for AI-015 "Path D": the Azure AI Foundry Serverless backend.

Production/managed AI runs the lightweight ai-gateway against a Foundry
pay-per-token endpoint with Entra managed-identity auth (decision D-0001);
local/development keeps the self-hosted llama.cpp server and must be unaffected.
These tests pin that split by asserting on the text of the Terraform manifests,
mirroring ``test_audit_anchor_contract.py``.
"""

from pathlib import Path

TERRAFORM_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = TERRAFORM_DIR.parents[1]
MAIN = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
VARIABLES = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
OUTPUTS = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")

GATEWAY = MAIN.split('resource "azurerm_container_app" "ai_gateway"', maxsplit=1)[1].split(
    'resource "azurerm_container_app" "operator"', maxsplit=1
)[0]
WORKER = MAIN.split('resource "azurerm_container_app" "worker"', maxsplit=1)[1].split(
    'resource "azurerm_role_assignment" "communication_sender"', maxsplit=1
)[0]


def _variable(name: str) -> str:
    return VARIABLES.split(f'variable "{name}"', maxsplit=1)[1].split("\n}\n", maxsplit=1)[0]


def test_foundry_model_is_a_variable_defaulting_to_gpt_oss_120b() -> None:
    block = _variable("ai_foundry_model")
    # Not hardcoded: the model is selectable by configuration, with the
    # reviewed default from decision D-0001.
    assert 'default     = "gpt-oss-120b"' in block
    assert "must be 1-128 characters" in block
    # The endpoint and the Foundry resource are separate, optional variables.
    endpoint = _variable("ai_foundry_endpoint")
    assert 'default     = ""' in endpoint
    resource = _variable("ai_foundry_resource_id")
    assert 'default     = ""' in resource
    assert r"Microsoft\\.CognitiveServices/accounts" in resource


def test_managed_gateway_points_at_foundry_over_an_authenticated_upstream() -> None:
    # The upstream base is the Foundry endpoint (never a loopback sidecar)...
    assert "value = trimspace(var.ai_foundry_endpoint)" in GATEWAY
    assert "http://localhost:18081/v1" not in GATEWAY
    # ...and outbound auth is Entra managed identity, not an API key.
    assert 'name  = "KP_AI_GATEWAY_UPSTREAM_AUTH_MODE"' in GATEWAY
    assert 'value = "entra"' in GATEWAY
    assert 'name  = "KP_AI_GATEWAY_UPSTREAM_MANAGED_IDENTITY_CLIENT_ID"' in GATEWAY
    assert 'value = azurerm_user_assigned_identity.workload["ai-gateway"].client_id' in GATEWAY
    # No model credential of any kind is wired into the gateway container.
    for forbidden in ("KP_AI_GATEWAY_UPSTREAM_API_KEY", "ai-foundry-key", "foundry-api-key"):
        assert forbidden not in GATEWAY


def test_managed_gateway_scales_to_zero_for_true_zero_idle_cost() -> None:
    # Path D's whole justification: no weights, no inference container, no idle
    # bill. A min_replicas of 1 (the old sidecar posture) would defeat it.
    assert "min_replicas = 0" in GATEWAY
    assert "max_replicas = 1" in GATEWAY


def test_gateway_identity_gets_cognitive_services_user_on_the_foundry_resource() -> None:
    assignment = MAIN.split('resource "azurerm_role_assignment" "ai_gateway_foundry_user"', maxsplit=1)[1].split(
        "\n}\n", maxsplit=1
    )[0]
    assert "scope                = trimspace(var.ai_foundry_resource_id)" in assignment
    assert 'role_definition_name = "Cognitive Services User"' in assignment
    # The gateway's USER-ASSIGNED identity, not a shared/system principal.
    assert 'azurerm_user_assigned_identity.workload["ai-gateway"].principal_id' in assignment
    assert "local.ai_gateway_deployed" in assignment


def test_worker_pin_and_gateway_model_come_from_one_variable() -> None:
    # The pin is configuration-bound: the gateway returns this identity and the
    # worker refuses anything else, so both must read the same local.
    pinned = (
        "ai_model_id = local.ai_foundry_backend ? trimspace(var.ai_foundry_model) : "
        '"llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"'
    )
    assert pinned in MAIN
    assert "KP_WORKER_AI_MODEL_ID = local.ai_model_id" in MAIN
    gateway_model = GATEWAY.split('name  = "KP_AI_GATEWAY_MODEL_ID"', maxsplit=1)[1].split("\n      }", maxsplit=1)[0]
    assert "value = local.ai_model_id" in gateway_model
    assert 'output "ai_model_id"' in OUTPUTS


def test_local_self_hosted_identity_is_preserved_when_no_foundry_endpoint() -> None:
    # The fallback branch keeps the bake-off-selected local identity, so a
    # deployment that does not configure Foundry is unchanged.
    assert 'ai_foundry_backend = trimspace(var.ai_foundry_endpoint) != ""' in MAIN
    assert '"llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"' in MAIN


def test_empty_foundry_endpoint_deploys_no_gateway_and_fails_the_plan() -> None:
    # Fail safe: an opted-in gateway with no endpoint has no backend, so the
    # plan is rejected rather than producing an app that only 502s.
    guard = MAIN.split('resource "terraform_data" "workload_config_guard"', maxsplit=1)[1].split(
        'resource "azurerm_resource_group" "main"', maxsplit=1
    )[0]
    assert "|| local.ai_foundry_backend" in guard
    assert "deploy_ai_gateway=true requires ai_foundry_endpoint" in guard
    # Every consumer is count-gated on the same local (no dangling [0] index).
    assert "count                        = local.ai_gateway_deployed ? 1 : 0" in GATEWAY
    assert "local.ai_gateway_deployed" in OUTPUTS.split('output "ai_gateway_internal_url"', maxsplit=1)[1]


def test_gateway_upstream_auth_defaults_to_unauthenticated_local() -> None:
    # The switch lives only in the managed manifest: the gateway's own default
    # must stay "none" so the local llama.cpp stack is byte-for-byte unchanged.
    config = (PROJECT_ROOT / "apps" / "ai-gateway" / "src" / "kp_ai_gateway" / "config.py").read_text(encoding="utf-8")
    assert 'upstream_auth_mode: UpstreamAuthMode = "none"' in config
    assert "https://cognitiveservices.azure.com/.default" in config
    assert "local.ai_foundry_backend" in MAIN


def test_gateway_bounds_reasoning_effort_and_completion_tokens() -> None:
    # P0 reliability: the gateway must send bounded reasoning effort and a
    # completion-token cap so an unbounded reasoning run cannot blow the worker
    # timeout (the generation dead-lettering root cause).
    assert 'name  = "KP_AI_GATEWAY_REASONING_EFFORT"' in GATEWAY
    assert "value = var.ai_reasoning_effort" in GATEWAY
    assert 'name  = "KP_AI_GATEWAY_MAX_COMPLETION_TOKENS"' in GATEWAY
    assert "value = tostring(var.ai_max_completion_tokens)" in GATEWAY
    effort = _variable("ai_reasoning_effort")
    assert 'default     = "low"' in effort
    assert "minimal" in effort and "high" in effort
    tokens = _variable("ai_max_completion_tokens")
    assert "positive integer" in tokens
    # Temperature must be omittable: some current GA models 400 on any explicit
    # temperature (gpt-5.6-terra). The gateway gates it on ai_send_temperature.
    assert 'name  = "KP_AI_GATEWAY_SEND_TEMPERATURE"' in GATEWAY
    assert "value = tostring(var.ai_send_temperature)" in GATEWAY
    assert 'variable "ai_send_temperature"' in VARIABLES


def test_worker_provider_timeout_is_pinned_durably() -> None:
    # Durably pins the provider timeout in IaC, superseding any live hotfix.
    assert 'name  = "KP_WORKER_PROVIDER_TIMEOUT_SECONDS"' in WORKER
    assert "value = tostring(var.worker_provider_timeout_seconds)" in WORKER
    block = _variable("worker_provider_timeout_seconds")
    assert "between 1 and 60" in block


def test_extraction_model_is_pinned_across_gateway_and_worker() -> None:
    # P1: the extract model id is wired identically to the gateway and worker
    # (one local) so the extract pin cannot drift, mirroring the generation pin.
    assert "ai_extract_model_id = trimspace(var.ai_extract_model)" in MAIN
    assert 'name  = "KP_AI_GATEWAY_EXTRACT_MODEL_ID"' in GATEWAY
    assert "value = local.ai_extract_model_id" in GATEWAY
    assert 'name  = "KP_AI_GATEWAY_EXTRACT_REASONING_EFFORT"' in GATEWAY
    assert "value = var.ai_extract_reasoning_effort" in GATEWAY
    assert "KP_WORKER_AI_EXTRACT_MODEL_ID = local.ai_extract_model_id" in MAIN
    assert 'variable "ai_extract_model"' in VARIABLES
    effort = _variable("ai_extract_reasoning_effort")
    assert "none" in effort


def test_discovery_is_gateway_only_and_gated() -> None:
    # P3: /discover is enabled only when both a model id and the Responses base
    # URL are set; empty disables it (env_ignore_empty). It is the only web path.
    assert "ai_discover_model_id = trimspace(var.ai_discover_model)" in MAIN
    assert 'name  = "KP_AI_GATEWAY_DISCOVER_MODEL_ID"' in GATEWAY
    assert "value = local.ai_discover_model_id" in GATEWAY
    assert 'name  = "KP_AI_GATEWAY_RESPONSES_BASE_URL"' in GATEWAY
    assert "value = trimspace(var.ai_responses_base_url)" in GATEWAY
    assert 'variable "ai_discover_model"' in VARIABLES
    assert 'variable "ai_responses_base_url"' in VARIABLES
