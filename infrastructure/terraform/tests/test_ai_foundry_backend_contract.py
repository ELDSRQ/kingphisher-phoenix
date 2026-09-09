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
