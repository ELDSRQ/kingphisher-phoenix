#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# azure-idle.sh — idle/resume the expensive Azure tier to cut cost between real
# sends, per docs/HYBRID-AZURE-LOCAL-PLAN.md (Path B) and docs/AZURE-IDLE.md.
#
#   preflight  read-only: prove every precondition a real terraform plan needs
#   status     read-only: Postgres power state, Container App revisions, ACR/Redis
#   stop       idle: stop Postgres (retains data) + plan/confirm/apply environments/idle.tfvars
#   start      resume: start Postgres + plan/confirm/apply the data plane back on
#
#   guard-plan <plan.json>  read-only: machine-readable destroy guard over a
#              `terraform show -json` plan. Refuses a plan that would destroy or
#              replace PostgreSQL, the WORM audit-anchor storage, or the CI runner
#              VM, and prints the destroy summary. Runs anywhere, touches nothing.
#
#   plan-idle  non-interactive: the idle plan + the guard, and NOTHING else.
#   apply-idle non-interactive: re-plan, guard, stop Postgres, apply that SAVED plan.
#              Reachable ONLY from .github/workflows/azure-idle.yml — see
#              require_dispatch_confirmation() below. There is no local equivalent.
#
# SAFE BY DESIGN:
#   - Postgres is STOPPED, never destroyed (it carries prevent_destroy; stop retains
#     data and auto-restarts within ~7 days). An already-stopped server is a logged
#     no-op, exactly like scripts/operator/azure-nightly-shutdown.sh.
#   - Every plan, on every path, is run through the machine-readable destroy guard
#     before anything can be applied.
#   - The INTERACTIVE commands (`stop`, `start`, and the default) ALWAYS show a plan
#     and require you to type 'yes' after reviewing it. There is deliberately NO
#     --yes flag and no environment variable that skips it: that confirmation is
#     the gate protecting a destroy of ACR, Redis and the Container Apps.
#   - The one non-interactive path (`apply-idle`) does not weaken that gate, it
#     MOVES it: it refuses unless it is running inside GitHub Actions AND the
#     workflow's own `confirm` dispatch input was the exact string IDLE, which a
#     human types into the dispatch form. It is additionally behind the `staging`
#     GitHub environment's required reviewer.
#   - Every precondition is checked BEFORE terraform runs, so a missing backend
#     variable or a missing Azure role prints one sentence naming it, not a
#     terraform stack trace.
#
# WHY THIS FILE HAD TO GROW: `terraform` here declares `backend "azurerm" {}`
# (empty) and 13 variables with no default. Both are supplied by
# .github/workflows/azure-deploy.yml at run time, so a bare `terraform plan` in
# infrastructure/terraform can never work. This script reproduces exactly what
# the workflow does — same backend keys, same reviewed configuration, same live
# ACS control-plane readback — so the idle posture is one reviewable command.
#
# Requires: az (logged in), gh (authenticated, read-only), terraform, python3.
# ---------------------------------------------------------------------------
set -euo pipefail

export AZURE_LOGGING_ENABLE_LOG_FILE=false

RG="${KP_RG:-rg-kp-staging}"
ENVNAME="${KP_ENV:-staging}"
REPO="${KP_REPO:-ELDSRQ/kingphisher-phoenix}"
OPERATOR_APP="${KP_OPERATOR_APP:-ca-kp-staging-operator}"
OIDC_CLIENT_ID="${KP_OIDC_CLIENT_ID:-97466174-d0ac-460c-94e8-7b6ff3c83da5}"
NETWORK_MODE="${KP_NETWORK_MODE:-private}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="$REPO_ROOT/infrastructure/terraform"
VARFILE="environments/${ENVNAME}.tfvars"
IDLE_VARFILE="environments/idle.tfvars"
# The reviewed deployment configuration is NOT duplicated here. It lives in one
# place — the dispatch script that feeds the same JSON to the deploy workflow —
# and is read out of it at run time so the two can never drift.
CONFIG_SOURCE="${KP_DEPLOYMENT_CONFIG_FILE:-$REPO_ROOT/scripts/operator/deployment-preflight/dispatch-staging-workloads.sh}"

WORKDIR=""
PLAN_FILE=".idle.tfplan"
cleanup() { [ -z "$WORKDIR" ] || rm -rf "$WORKDIR"; rm -f "$TF_DIR/$PLAN_FILE"; }
trap cleanup EXIT

die() { echo "!! $*" >&2; exit 1; }
note() { echo "   $*"; }
step() { echo "==> $*"; }

# A preflight failure must always name the thing that is missing AND how to
# supply it. `fix` renders that second half consistently.
fail_with_fix() {
  local what="$1"; shift
  echo >&2
  echo "!! PREFLIGHT FAILED: $what" >&2
  echo >&2
  while [ $# -gt 0 ]; do echo "   $1" >&2; shift; done
  echo >&2
  exit 2
}

need() { command -v "$1" >/dev/null 2>&1 || fail_with_fix "$1 is not on PATH" "Install $1 and re-run."; }

# ---------------------------------------------------------------------------
# Backend configuration. versions.tf declares `backend "azurerm" {}` with no
# values, so the state location comes entirely from the caller. The deploy
# workflow reads it from the staging ENVIRONMENT variables TF_STATE_* (they are
# environment-scoped, not repository-scoped) at
# .github/workflows/azure-deploy.yml "Initialize Terraform", with the state key
# "<environment>/kingphisher.tfstate". This mirrors that exactly.
# ---------------------------------------------------------------------------
gh_env_var() {
  local name="$1"
  # A missing variable must fall through to the named-precondition failure below,
  # not abort the script under `set -e -o pipefail`.
  gh variable get "$name" --repo "$REPO" --env "$ENVNAME" 2>/dev/null | tr -d '\r\n' || true
}

resolve_backend() {
  TF_STATE_RESOURCE_GROUP="${KP_TF_STATE_RESOURCE_GROUP:-}"
  TF_STATE_STORAGE_ACCOUNT="${KP_TF_STATE_STORAGE_ACCOUNT:-}"
  TF_STATE_CONTAINER="${KP_TF_STATE_CONTAINER:-}"
  if [ -z "$TF_STATE_RESOURCE_GROUP" ] || [ -z "$TF_STATE_STORAGE_ACCOUNT" ] || [ -z "$TF_STATE_CONTAINER" ]; then
    need gh
    gh auth status >/dev/null 2>&1 || fail_with_fix \
      "gh is not authenticated, so the Terraform state location cannot be read" \
      "Run: gh auth login" \
      "Or supply the state location directly:" \
      "  export KP_TF_STATE_RESOURCE_GROUP=... KP_TF_STATE_STORAGE_ACCOUNT=... KP_TF_STATE_CONTAINER=..."
    TF_STATE_RESOURCE_GROUP="${TF_STATE_RESOURCE_GROUP:-$(gh_env_var TF_STATE_RESOURCE_GROUP)}"
    TF_STATE_STORAGE_ACCOUNT="${TF_STATE_STORAGE_ACCOUNT:-$(gh_env_var TF_STATE_STORAGE_ACCOUNT)}"
    TF_STATE_CONTAINER="${TF_STATE_CONTAINER:-$(gh_env_var TF_STATE_CONTAINER)}"
  fi
  TF_STATE_KEY="${KP_TF_STATE_KEY:-${ENVNAME}/kingphisher.tfstate}"
  local missing=""
  [ -n "$TF_STATE_RESOURCE_GROUP" ] || missing="$missing TF_STATE_RESOURCE_GROUP"
  [ -n "$TF_STATE_STORAGE_ACCOUNT" ] || missing="$missing TF_STATE_STORAGE_ACCOUNT"
  [ -n "$TF_STATE_CONTAINER" ] || missing="$missing TF_STATE_CONTAINER"
  [ -z "$missing" ] || fail_with_fix \
    "the Terraform backend location is incomplete (missing:$missing)" \
    "These are GitHub ENVIRONMENT variables on the '$ENVNAME' environment (not repo-level)." \
    "Inspect them with:" \
    "  gh variable list --repo $REPO --env $ENVNAME" \
    "Or override locally:" \
    "  export KP_TF_STATE_RESOURCE_GROUP=... KP_TF_STATE_STORAGE_ACCOUNT=... KP_TF_STATE_CONTAINER=..."
}

# The state container is data plane. Subscription Owner does NOT grant blob data
# access and the account has shared-key auth disabled, so `terraform init` fails
# with an opaque 403 AuthorizationPermissionMismatch. Probe it read-only first
# and, if it is missing, print the exact one-time grant.
check_state_access() {
  local probe
  if probe="$(az storage blob list \
        --account-name "$TF_STATE_STORAGE_ACCOUNT" \
        --container-name "$TF_STATE_CONTAINER" \
        --auth-mode login --num-results 1 --query "[].name" -o tsv 2>&1)"; then
    return 0
  fi
  case "$probe" in
    *"do not have the required permissions"*|*AuthorizationPermissionMismatch*|*Forbidden*|*403*)
      local oid scope
      oid="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
      scope="/subscriptions/$(az account show --query id -o tsv)/resourceGroups/${TF_STATE_RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${TF_STATE_STORAGE_ACCOUNT}"
      fail_with_fix \
        "this Azure login cannot read the Terraform state container '$TF_STATE_CONTAINER'" \
        "Owner on the subscription is a CONTROL-plane role; blob content needs a DATA-plane role," \
        "and the state account has shared-key auth disabled, so there is no key fallback." \
        "Grant it once (this is a WRITE to Azure RBAC — run it yourself, deliberately):" \
        "  az role assignment create \\" \
        "    --assignee-object-id ${oid:-<your-object-id>} \\" \
        "    --assignee-principal-type User \\" \
        "    --role \"Storage Blob Data Contributor\" \\" \
        "    --scope \"$scope\"" \
        "Role propagation takes a minute or two; then re-run this command."
      ;;
    *)
      fail_with_fix \
        "the Terraform state container '$TF_STATE_CONTAINER' is not reachable" \
        "Azure reported: $(printf '%s' "$probe" | head -1)" \
        "Confirm the state account exists and this login can see it:" \
        "  az storage account show -n $TF_STATE_STORAGE_ACCOUNT -g $TF_STATE_RESOURCE_GROUP"
      ;;
  esac
}

tf_init() {
  step "terraform init (backend: $TF_STATE_STORAGE_ACCOUNT/$TF_STATE_CONTAINER key=$TF_STATE_KEY)"
  ( cd "$TF_DIR" && terraform init -input=false -reconfigure \
      -backend-config="resource_group_name=$TF_STATE_RESOURCE_GROUP" \
      -backend-config="storage_account_name=$TF_STATE_STORAGE_ACCOUNT" \
      -backend-config="container_name=$TF_STATE_CONTAINER" \
      -backend-config="key=$TF_STATE_KEY" \
      -backend-config="use_azuread_auth=true" >/dev/null ) \
    || fail_with_fix "terraform init failed against the real backend" \
         "Re-run the init by hand to see the provider/backend error:" \
         "  cd $TF_DIR && terraform init -reconfigure \\" \
         "    -backend-config=\"resource_group_name=$TF_STATE_RESOURCE_GROUP\" \\" \
         "    -backend-config=\"storage_account_name=$TF_STATE_STORAGE_ACCOUNT\" \\" \
         "    -backend-config=\"container_name=$TF_STATE_CONTAINER\" \\" \
         "    -backend-config=\"key=$TF_STATE_KEY\" \\" \
         "    -backend-config=\"use_azuread_auth=true\""
  note "backend initialised."
}

# ---------------------------------------------------------------------------
# Variable supply. 13 variables in variables.tf have NO default and are not in
# environments/<env>.tfvars: subscription_id, operator_fqdn, tracking_fqdn,
# entra_tenant_id, entra_client_id, acs_sending_domain, acs_sender_local_part,
# acs_sender_display_name, acs_daily_message_limit, acs_messages_per_minute,
# acs_ramp_batch_size, acs_ramp_interval_seconds, allowed_recipient_domains.
#
# The workflow gets them from the reviewed deployment_config JSON, then REPLACES
# every ACS readiness assertion with a live control-plane readback before
# Terraform sees them. The same JSON already exists, committed and secret-free,
# in dispatch-staging-workloads.sh — so it is read from there rather than copied,
# and the ACS readback is redone here read-only against Azure.
#
# That readback is not optional bookkeeping. The ACS domain association and the
# sender username are created with count = ... && acs_domain_live_ready, and both
# carry prevent_destroy. Stale or empty readiness strings would drive those counts
# to 0 and terraform would refuse the whole plan.
# ---------------------------------------------------------------------------
build_tfvars() {
  local out="$1"
  [ -f "$CONFIG_SOURCE" ] || fail_with_fix \
    "the reviewed deployment configuration source is missing" \
    "Expected it at: $CONFIG_SOURCE" \
    "Point at another file with: export KP_DEPLOYMENT_CONFIG_FILE=/path/to/dispatch-script.sh"
  python3 - "$CONFIG_SOURCE" "$RG" "$ENVNAME" "$out" <<'PYVARS'
import json
import re
import subprocess
import sys
from datetime import UTC, datetime

API_VERSION = "2023-04-01"
config_source, resource_group, environment, out_path = sys.argv[1:5]


def fail(message):
    print(f"!! {message}", file=sys.stderr)
    raise SystemExit(2)


def az_json(args, label):
    try:
        done = subprocess.run(["az", *args, "--only-show-errors"], capture_output=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        fail(f"{label} could not be read from Azure")
    if done.returncode != 0:
        detail = (done.stderr.decode("utf-8", "replace").strip().splitlines() or ["unknown error"])[-1]
        fail(f"{label} could not be read from Azure: {detail}")
    try:
        return json.loads(done.stdout or "null")
    except ValueError:
        fail(f"{label} returned malformed JSON")


# ---- 1. the reviewed configuration, read out of the dispatch script ----------
source = open(config_source, encoding="utf-8").read()
match = re.search(r"^CONFIG='(\{.*\})'$", source, re.MULTILINE)
if match is None:
    fail(
        f"no reviewed CONFIG JSON found in {config_source}; the deploy path's single "
        "source of truth is the CONFIG='{...}' line in that script"
    )
try:
    config = json.loads(match.group(1))
except ValueError:
    fail(f"the CONFIG JSON in {config_source} is not valid JSON")
if not isinstance(config, dict):
    fail(f"the CONFIG JSON in {config_source} is not an object")

# ---- 2. the same deterministic transforms the workflow applies ---------------
for key in (
    "acs_daily_message_limit", "acs_messages_per_minute",
    "acs_ramp_batch_size", "acs_ramp_interval_seconds",
):
    if key not in config:
        fail(f"the reviewed configuration is missing {key}")
    try:
        config[key] = int(config[key])
    except (TypeError, ValueError):
        fail(f"the reviewed configuration value for {key} is not an integer")
config["graph_endpoint"] = (
    "https://graph.microsoft.com/v1.0" if config.pop("enable_directory_sync", "false") == "true" else ""
)
config["reported_mailbox_endpoint"] = (
    "https://graph.microsoft.com/v1.0" if config.pop("enable_reported_mailbox", "false") == "true" else ""
)

# ---- 3. live ACS readback (read-only) ---------------------------------------
sending_domain = str(config.get("acs_sending_domain", "")).strip().lower()
sender_local_part = str(config.get("acs_sender_local_part", "")).strip().lower()
if not sending_domain or not sender_local_part:
    fail("the reviewed configuration has no ACS sending domain / sender local part")


def discover(resource_type, label):
    rows = az_json(
        [
            "resource", "list", "-g", resource_group, "--resource-type", resource_type,
            "--query", "[].{id:id,application:tags.application,environment:tags.environment}",
            "-o", "json",
        ],
        f"{label} discovery",
    ) or []
    matches = [
        row["id"] for row in rows
        if isinstance(row, dict)
        and row.get("application") == "kingphisher-phoenix"
        and row.get("environment") == environment
        and isinstance(row.get("id"), str)
    ]
    if len(matches) != 1:
        fail(f"{label} discovery did not resolve exactly one project resource in {resource_group}")
    return matches[0]


email_service_id = discover("Microsoft.Communication/EmailServices", "Email Communication Service")
communication_service_id = discover("Microsoft.Communication/CommunicationServices", "Communication Service")
email_domain_id = f"{email_service_id}/domains/{sending_domain}"
sender_username_id = f"{email_domain_id}/senderUsernames/{sender_local_part}"


def arm_get(resource_id, query, label):
    return az_json(
        [
            "rest", "--method", "get",
            "--uri", f"https://management.azure.com{resource_id}?api-version={API_VERSION}",
            "--query", query, "-o", "json",
        ],
        label,
    )


observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
domain = arm_get(
    email_domain_id,
    "{Domain:properties.verificationStates.Domain.status,"
    "SPF:properties.verificationStates.SPF.status,"
    "DKIM:properties.verificationStates.DKIM.status,"
    "DKIM2:properties.verificationStates.DKIM2.status,"
    "fromSenderDomain:properties.fromSenderDomain}",
    "ACS email domain readiness",
) or {}
if str(domain.get("fromSenderDomain", "")).lower() != sending_domain:
    fail("the live ACS email domain does not match the reviewed sending domain")
statuses = {key.lower(): str(domain.get(key, "")).lower() for key in ("Domain", "SPF", "DKIM", "DKIM2")}

linked = arm_get(communication_service_id, "properties.linkedDomains", "ACS domain association") or []
if not isinstance(linked, list):
    fail("the live ACS domain association readback is malformed")
statuses["association"] = (
    "verified" if sum(str(v).lower() == email_domain_id.lower() for v in linked) == 1 else "not_linked"
)

sender = arm_get(
    sender_username_id,
    "{username:properties.username,displayName:properties.displayName}",
    "ACS sender username",
) or {}
statuses["sender"] = "verified" if str(sender.get("username", "")).lower() == sender_local_part else "not_observed"

domain_verified = all(statuses[k] == "verified" for k in ("domain", "spf", "dkim", "dkim2"))
for key, config_key in (
    ("domain", "acs_domain_verification_status"),
    ("spf", "acs_spf_verification_status"),
    ("dkim", "acs_dkim_verification_status"),
    ("dkim2", "acs_dkim2_verification_status"),
    ("sender", "acs_sender_username_status"),
    ("association", "acs_domain_association_status"),
):
    config[config_key] = statuses[key]
config["acs_readiness_checked_at"] = observed_at if domain_verified else ""

if not domain_verified:
    fail(
        "the live ACS domain is not fully Verified "
        f"(Domain={statuses['domain']} SPF={statuses['spf']} DKIM={statuses['dkim']} DKIM2={statuses['dkim2']}). "
        "The ACS domain association and sender username carry prevent_destroy and would be planned for "
        "destruction, so terraform would refuse the plan. Re-verify the domain before idling: "
        "see docs/AZURE-IDLE.md."
    )

# ---- 4. write the var-file (no secrets; same key contract as the workflow) ---
with open(out_path, "w", encoding="utf-8") as target:
    json.dump(config, target, separators=(",", ":"), sort_keys=True)

print(
    "   ACS readback: Domain/SPF/DKIM/DKIM2=verified  association="
    f"{statuses['association']}  sender={statuses['sender']}  observed_at={observed_at}",
    file=sys.stderr,
)
PYVARS
}

# Cross-check that every no-default variable actually has a value once the
# var-files are layered, so a missing one is named here rather than surfacing as
# a terraform prompt or stack trace.
check_required_variables() {
  local generated="$1"; shift
  python3 - "$TF_DIR/variables.tf" "$TF_DIR/$VARFILE" "$generated" "$*" <<'PYREQ'
import json
import re
import sys

variables_tf, env_tfvars, generated, cli_vars = sys.argv[1:5]
source = open(variables_tf, encoding="utf-8").read()

no_default = []
for match in re.finditer(r'variable\s+"([^"]+)"\s*\{', source):
    index, depth = match.end() - 1, 0
    while True:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        index += 1
    if re.search(r"^\s*default\s*=", source[match.end():index], re.MULTILINE) is None:
        no_default.append(match.group(1))

supplied = set(json.load(open(generated, encoding="utf-8")))
for line in open(env_tfvars, encoding="utf-8"):
    name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
    if name:
        supplied.add(name.group(1))
supplied.update(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", cli_vars))

missing = [name for name in no_default if name not in supplied]
if missing:
    print("!! PREFLIGHT FAILED: required Terraform variables have no local value", file=sys.stderr)
    print("", file=sys.stderr)
    for name in missing:
        print(f"   missing: {name}", file=sys.stderr)
    print("", file=sys.stderr)
    print("   They come from the reviewed deployment configuration — the CONFIG='{...}'", file=sys.stderr)
    print("   line in scripts/operator/deployment-preflight/dispatch-staging-workloads.sh,", file=sys.stderr)
    print("   which is the same JSON the deploy workflow consumes. Add the key there (it", file=sys.stderr)
    print("   must stay secret-free), or point at another dispatch script with", file=sys.stderr)
    print("   KP_DEPLOYMENT_CONFIG_FILE.", file=sys.stderr)
    raise SystemExit(2)
print(f"   variable contract complete ({len(no_default)} no-default variables all supplied).", file=sys.stderr)
PYREQ
}

# The private data plane is why CI runs on a self-hosted VNet runner. Key Vault
# and the audit storage account have public network access DISABLED, and
# terraform must read (and, when idling, delete the redis-url secret through) the
# Key Vault data plane. From outside the VNet that cannot work, so say so up
# front instead of letting terraform fail mid-refresh.
check_data_plane_reachability() {
  local vault public
  vault="$(az keyvault list -g "$RG" --query "[0].name" -o tsv 2>/dev/null || true)"
  [ -n "$vault" ] || { note "no Key Vault found in $RG — skipping data-plane reachability check."; return 0; }
  public="$(az keyvault show -n "$vault" -g "$RG" --query "properties.publicNetworkAccess" -o tsv 2>/dev/null || echo "?")"
  if [ "$public" = "Disabled" ] && [ "${KP_INSIDE_VNET:-0}" != "1" ]; then
    fail_with_fix \
      "Key Vault '$vault' has public network access DISABLED, so terraform cannot run from here" \
      "network_mode=private puts Key Vault, Postgres, Redis and the registry on private" \
      "endpoints. terraform must read every azurerm_key_vault_secret through the vault's" \
      "DATA plane, and 'stop' additionally DELETES the redis-url secret — neither is" \
      "reachable from outside the VNet, so plan and apply both fail there." \
      "" \
      "Run this from inside the VNet instead (the self-hosted CI runner VM):" \
      "  az vm start -g $RG -n \$(az vm list -g $RG --query \"[0].name\" -o tsv)" \
      "  # then, on that VM: KP_INSIDE_VNET=1 scripts/operator/azure-idle.sh stop" \
      "  #   (add KP_KEEP_CI_RUNNER=1 so the apply does not destroy the VM it runs on)" \
      "" \
      "Set KP_INSIDE_VNET=1 to acknowledge you are already inside the VNet and proceed."
  fi
  note "Key Vault '$vault' public network access: $public${KP_INSIDE_VNET:+ (KP_INSIDE_VNET=1 acknowledged)}"
}

check_azure_login() {
  need az
  az account show >/dev/null 2>&1 || fail_with_fix \
    "not logged in to Azure" "Run: az login"
  az group show --name "$RG" --query name -o tsv >/dev/null 2>&1 || fail_with_fix \
    "resource group '$RG' is not visible to this Azure login" \
    "Check the subscription: az account show" \
    "Or point at another group: export KP_RG=<resource-group>"
}

pg_server() {
  az postgres flexible-server list -g "$RG" --query "[0].name" -o tsv 2>/dev/null
}

pg_state() {
  az postgres flexible-server show -g "$RG" -n "$1" --query state -o tsv 2>/dev/null || echo "unknown"
}

# A terraform plan error the operator cannot act on is worse than no plan at
# all. Translate the ones we already know the cause of.
explain_plan_failure() {
  local log="$1"
  if grep -q 'redis-url' "$log" && grep -q 'does not identify an element' "$log"; then
    echo >&2
    echo "   DIAGNOSIS: the idle posture (deploy_data_plane=false) is not yet expressible in" >&2
    echo "   infrastructure/terraform/main.tf. local.secret_values drops the \"redis-url\"" >&2
    echo "   secret when the data plane is off, but two places still index it unconditionally:" >&2
    echo "     - local.workload_secret_access feeds azurerm_role_assignment.workload_secret" >&2
    echo "     - local.common_secrets" >&2
    echo "   Both need to be filtered/merged on local.data_plane before 'stop' can plan." >&2
    echo "   See docs/AZURE-IDLE.md, 'Known blocker: redis-url is indexed unconditionally'." >&2
  fi
  if grep -qi 'ForbiddenByFirewall\|Public network access is disabled\|dial tcp' "$log"; then
    echo >&2
    echo "   DIAGNOSIS: this looks like the private data plane refusing a connection." >&2
    echo "   terraform must reach Key Vault from inside the VNet — run it on the" >&2
    echo "   self-hosted CI runner VM. See docs/AZURE-IDLE.md." >&2
  fi
}

# ---------------------------------------------------------------------------
# The machine-readable destroy guard.
#
# "Read the plan carefully" is not a control. This parses `terraform show -json`
# — the structured plan, never the human rendering — and refuses outright if the
# plan would delete or replace anything on the protected list:
#
#   * the PostgreSQL flexible server and its database (the data),
#   * the WORM audit-anchor storage account / container / immutability policy,
#   * the self-hosted CI runner VM, because when this runs as a GitHub Actions
#     job that VM *is* the runner executing it; destroying it mid-run kills the
#     job halfway through a destroy of the rest of the tier.
#
# It also names the two resources in the idle destroy set that are NOT in the
# documented "Container Apps + ACR + Redis" summary, so nobody is surprised.
# ---------------------------------------------------------------------------
guard_plan_json() {
  python3 - "$1" <<'PYGUARD'
import json
import os
import sys

plan_path = sys.argv[1]

# (type, name) pairs; the index/module prefix of an address is irrelevant.
PROTECTED_TYPES = {
    "azurerm_postgresql_flexible_server",
    "azurerm_postgresql_flexible_server_database",
}
PROTECTED_NAMED = {
    ("azurerm_storage_account", "audit_anchor"),
    ("azurerm_storage_container", "audit_anchor"),
    ("azurerm_storage_container_immutability_policy", "audit_anchor"),
    ("azurerm_linux_virtual_machine", "ci_runner"),
    # The vault holds every runtime secret. Nothing in the idle posture should
    # remove it, and if a plan ever proposes to, that is a bug worth stopping on
    # rather than discovering afterwards.
    ("azurerm_key_vault", "main"),
}
WHY = {
    "azurerm_postgresql_flexible_server": "the PostgreSQL server holds the data; idle STOPS it, never removes it",
    "azurerm_postgresql_flexible_server_database": "the application database holds the data",
    "azurerm_storage_account": "the audit anchor is WORM/immutable and is retained on purpose",
    "azurerm_storage_container": "the audit anchor is WORM/immutable and is retained on purpose",
    "azurerm_storage_container_immutability_policy": "removing the immutability policy would unlock the audit anchor",
    "azurerm_linux_virtual_machine": "this VM is the self-hosted runner executing the job",
}
# Beyond the documented "Container Apps + ACR + Redis". Both are gated on
# deploy_workloads and the next workloads deploy recreates them.
SURPRISING = {
    ("azurerm_eventgrid_system_topic", "acs_delivery"):
        "ACS delivery Event Grid system topic (gated on deploy_workloads; the next workloads deploy recreates it)",
    ("azurerm_eventgrid_system_topic_event_subscription", "acs_delivery"):
        "ACS delivery receipt subscription (gated on deploy_workloads; recreated with the topic)",
    ("azurerm_role_definition", "acs_email_sender"):
        "custom ACS email-sender role definition (gated on deploy_workloads; recreated by the next workloads deploy)",
    ("azurerm_role_assignment", "communication_sender"):
        "ACS email-sender role assignment (gated on deploy_workloads; recreated with the role definition)",
}

annotate = os.environ.get("GITHUB_ACTIONS", "") == "true"


def emit_error(message):
    print(f"::error::{message}" if annotate else f"!! {message}", file=sys.stderr)


try:
    with open(plan_path, encoding="utf-8") as handle:
        plan = json.load(handle)
except (OSError, ValueError) as problem:
    emit_error(f"the structured plan at {plan_path} could not be read as JSON: {problem}")
    emit_error("the guard refuses a plan it cannot parse; nothing was applied.")
    raise SystemExit(3) from None
if not isinstance(plan, dict):
    emit_error(f"the structured plan at {plan_path} is not a terraform plan document")
    raise SystemExit(3)

changes = plan.get("resource_changes")
if not isinstance(changes, list):
    emit_error(f"the structured plan at {plan_path} has no resource_changes array")
    raise SystemExit(3)

destroyed, replaced, created, updated, violations, surprises = [], [], [], [], [], []
for change in changes:
    if not isinstance(change, dict):
        continue
    detail = change.get("change") or {}
    actions = detail.get("actions") or []
    address = str(change.get("address", "<unknown>"))
    kind = str(change.get("type", ""))
    name = str(change.get("name", ""))
    removes = "delete" in actions
    is_replace = removes and "create" in actions
    if is_replace:
        replaced.append(address)
    elif removes:
        destroyed.append(address)
    elif "create" in actions:
        created.append(address)
    elif "update" in actions:
        updated.append(address)
    if removes and (kind in PROTECTED_TYPES or (kind, name) in PROTECTED_NAMED):
        violations.append((address, "replace" if is_replace else "destroy", WHY.get(kind, "protected resource")))
    if removes and (kind, name) in SURPRISING:
        surprises.append((address, SURPRISING[(kind, name)]))

print("")
print("=== destroy guard — from `terraform show -json`, not from the human plan ===")
print(f"    create : {len(created)}")
print(f"    update : {len(updated)}")
print(f"    replace: {len(replaced)}")
print(f"    DESTROY: {len(destroyed)}")
if destroyed:
    print("")
    print("    resources this plan DESTROYS:")
    for address in sorted(destroyed):
        print(f"      - {address}")
if replaced:
    print("")
    print("    resources this plan REPLACES (destroy + create):")
    for address in sorted(replaced):
        print(f"      ~ {address}")
if surprises:
    print("")
    print('    beyond the documented "Container Apps + ACR + Redis" destroy set:')
    for address, reason in sorted(surprises):
        print(f"      ! {address}")
        print(f"          {reason}")
print("")
sys.stdout.flush()

if violations:
    emit_error("the plan would remove a PROTECTED resource; refusing to apply it.")
    for address, action, reason in sorted(violations):
        emit_error(f"{action}: {address} — {reason}")
    print("")
    print("    Nothing was applied. The idle posture must never remove these; if the plan", file=sys.stderr)
    print("    really shows one, the state or the variables are wrong — investigate before", file=sys.stderr)
    print("    re-running. See docs/AZURE-IDLE.md.", file=sys.stderr)
    raise SystemExit(3)

print("    guard OK — no protected resource is destroyed or replaced.")
PYGUARD
}

# Plan into a saved file, then guard it. Every path that can change Azure goes
# through here, so no plan can be applied that the guard has not seen.
run_plan() {
  # $1 = human label, remaining args = extra terraform plan flags
  local label="$1"; shift
  local planlog; planlog="$WORKDIR/plan.log"
  step "terraform plan ($label) in $TF_DIR"
  if ! ( cd "$TF_DIR" && terraform plan -input=false "$@" -out="$PLAN_FILE" 2>&1 | tee "$planlog" ); then
    explain_plan_failure "$planlog"
    die "plan failed"
  fi
  if grep -q 'Error:' "$planlog"; then
    explain_plan_failure "$planlog"
    die "plan failed"
  fi
  step "destroy guard (structured plan)"
  if ! ( cd "$TF_DIR" && terraform show -json "$PLAN_FILE" ) > "$WORKDIR/plan.json"; then
    rm -f "$TF_DIR/$PLAN_FILE"
    die "the saved plan could not be rendered as JSON, so it cannot be guarded"
  fi
  if ! guard_plan_json "$WORKDIR/plan.json"; then
    rm -f "$TF_DIR/$PLAN_FILE"
    exit 3
  fi
}

# The single saved-plan apply in this script. It runs only what was planned and
# guarded moments earlier — never a bare re-resolution of the configuration.
apply_saved_plan() {
  ( cd "$TF_DIR" && terraform apply -input=false "$PLAN_FILE" )
  rm -f "$TF_DIR/$PLAN_FILE"
}

# ---------------------------------------------------------------------------
# The interactive gate. Nothing local skips this.
# ---------------------------------------------------------------------------
confirm_apply() {
  # $1 = human label, remaining args = extra terraform plan flags
  local label="$1"; shift
  run_plan "$label" "$@"
  echo
  echo "  REVIEW THE PLAN ABOVE. For 'stop' it must destroy ONLY the registry, Redis,"
  echo "  their private endpoints/role/secret, and (if idling) the Container Apps —"
  echo "  and must show NO destroy/replace of Postgres or the audit storage."
  read -r -p "  Type 'yes' to apply this plan: " ans
  [ "$ans" = "yes" ] || { rm -f "$TF_DIR/$PLAN_FILE"; die "aborted — nothing applied"; }
  apply_saved_plan
}

# ---------------------------------------------------------------------------
# The workflow-only gate for `apply-idle`.
#
# The interactive commands are unchanged and remain the default. This path does
# not remove the human confirmation, it relocates it into the dispatch form of
# .github/workflows/azure-idle.yml: mode=apply is refused there unless `confirm`
# is the exact string IDLE, and the value is passed through to this check so the
# script itself refuses too. Outside a GitHub Actions job there is no way in.
# ---------------------------------------------------------------------------
require_dispatch_confirmation() {
  local command_name="$1"
  [ "${GITHUB_ACTIONS:-}" = "true" ] || fail_with_fix \
    "'$command_name' is the workflow-only path and this is not a GitHub Actions job" \
    "It exists because terraform must reach the private Key Vault data plane from" \
    "inside the VNet, with GitHub OIDC credentials — neither is available locally." \
    "Interactively, use:" \
    "  $0 stop"
  [ "${KP_IDLE_DISPATCH_CONFIRM:-}" = "IDLE" ] || fail_with_fix \
    "'$command_name' was not given the dispatch confirmation" \
    "The apply mode of .github/workflows/azure-idle.yml requires its 'confirm'" \
    "dispatch input to be the exact string IDLE, typed by the operator." \
    "Re-dispatch the workflow with mode=apply and confirm=IDLE."
}

repatch_oidc() {
  step "re-patching operator OIDC env (reverts on every deploy)"
  az containerapp update --name "$OPERATOR_APP" -g "$RG" --set-env-vars \
    "OPERATOR_API_OIDC_SCOPES=openid profile api://${OIDC_CLIENT_ID}/console" \
    "OPERATOR_API_OIDC_AUDIENCE=${OIDC_CLIENT_ID}" >/dev/null \
    && note "OIDC env re-patched." || note "(operator app not up yet — re-patch after it is)"
}

# ---------------------------------------------------------------------------
# Everything a real plan needs, checked in dependency order and reported by name.
# ---------------------------------------------------------------------------
GENERATED_TFVARS=""
run_preflight() {
  local cli_vars="$1"
  need terraform; need python3
  check_azure_login
  resolve_backend
  note "state backend: ${TF_STATE_STORAGE_ACCOUNT}/${TF_STATE_CONTAINER} key=${TF_STATE_KEY}"
  check_state_access
  note "state container readable by this login."
  check_data_plane_reachability
  # Portable across BSD and GNU mktemp: BSD accepts a bare -t prefix, GNU
  # requires the template to end in at least three X's. This script is written
  # on macOS but RUNS on the Linux VNet runner, where the bare form fails with
  # "mktemp: too few X's in template".
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/kp-azure-idle.XXXXXXXX")"
  chmod 700 "$WORKDIR"
  GENERATED_TFVARS="$WORKDIR/reviewed.local.tfvars.json"
  step "assembling reviewed variables from $(basename "$CONFIG_SOURCE") + live ACS readback"
  build_tfvars "$GENERATED_TFVARS"
  check_required_variables "$GENERATED_TFVARS" "$cli_vars"
  tf_init
}

cmd_preflight() {
  run_preflight "environment= network_mode= acs_deployment_stage= deploy_workloads= deploy_data_plane="
  echo
  echo "PREFLIGHT OK — 'stop' and 'start' can reach a real terraform plan."
}

cmd_status() {
  local pg; pg="$(pg_server || true)"
  echo "=== resource group: $RG ==="
  if [ -n "$pg" ]; then
    echo "Postgres '$pg' state: $(pg_state "$pg")"
  else
    echo "Postgres: none found"
  fi
  echo "--- Container Apps (name : running revision) ---"
  az containerapp list -g "$RG" --query "[].{n:name,rev:properties.latestReadyRevisionName}" -o tsv 2>/dev/null || echo "  (none)"
  echo "--- ACR present: $(az acr list -g "$RG" --query "length(@)" -o tsv 2>/dev/null || echo '?') | Redis present: $(az redisenterprise list -g "$RG" --query "length(@)" -o tsv 2>/dev/null || echo '?') ---"
  echo
  echo "=== terraform preflight ==="
  echo "(run '$0 preflight' for the fatal, fully-checked version)"
}

# Stop the server only when it is actually running. An already-stopped server is
# a logged no-op — the same contract azure-nightly-shutdown.sh holds — not an
# "Code: ServerIsNotReady" error dressed up as a failure.
stop_postgres() {
  local pg state
  pg="$(pg_server)" || true
  [ -n "$pg" ] || die "no Postgres server found in $RG"
  state="$(pg_state "$pg")"
  case "$state" in
    Ready)
      step "stopping Postgres '$pg' (retains data; ~7-day auto-restart)"
      az postgres flexible-server stop -g "$RG" -n "$pg" >/dev/null 2>&1 \
        && note "stopped." \
        || die "could not stop Postgres '$pg'"
      ;;
    *)
      step "Postgres '$pg' is already not running (state=$state) — nothing to stop"
      ;;
  esac
}

start_postgres() {
  local pg state
  pg="$(pg_server)" || true
  [ -n "$pg" ] || die "no Postgres server found in $RG"
  state="$(pg_state "$pg")"
  case "$state" in
    Ready)
      step "Postgres '$pg' is already running (state=$state) — nothing to start"
      ;;
    *)
      step "starting Postgres '$pg' (state=$state)"
      az postgres flexible-server start -g "$RG" -n "$pg" >/dev/null 2>&1 \
        && note "started." \
        || die "could not start Postgres '$pg'"
      ;;
  esac
}

# acs_deployment_stage=workloads keeps the ACS domain association and sender
# username MANAGED. Both carry prevent_destroy, so leaving the stage at its
# "disabled" default would drive their count to 0 and terraform would refuse the
# whole plan rather than idle anything.
common_plan_vars() {
  printf '%s\n' \
    "-var-file=$VARFILE" \
    "-var-file=$GENERATED_TFVARS" \
    "-var=environment=$ENVNAME" \
    "-var=network_mode=$NETWORK_MODE" \
    "-var=acs_deployment_stage=workloads"
}

IDLE_PREFLIGHT_VARS="environment= network_mode= acs_deployment_stage= deploy_workloads= deploy_data_plane= deploy_ai_gateway= deploy_ci_runner="

# The flag list every idle plan uses, on every path — interactive or workflow —
# so the three commands cannot drift apart.
#
# environments/idle.tfvars is the committed, reviewable idle posture:
# deploy_workloads=false, deploy_data_plane=false, deploy_ai_gateway=false,
# deploy_ci_runner=false. The first two are also passed explicitly so the
# destroy-scope of this command is visible in the command line itself.
#
# KP_KEEP_CI_RUNNER=1 adds a CLI `-var=deploy_ci_runner=true`, which OUTRANKS the
# `deploy_ci_runner = false` in the var-file (CLI -var beats -var-file; a
# TF_VAR_ environment variable would NOT — it loses to a var-file). Without it an
# apply run from the runner VM destroys the VM executing it, mid-apply.
idle_plan_flags() {
  common_plan_vars
  printf '%s\n' "-var-file=$IDLE_VARFILE" "-var=deploy_workloads=false" "-var=deploy_data_plane=false"
  [ "${KP_KEEP_CI_RUNNER:-0}" != "1" ] || printf '%s\n' "-var=deploy_ci_runner=true"
}

note_ci_runner_retention() {
  if [ "${KP_KEEP_CI_RUNNER:-0}" = "1" ]; then
    note "KP_KEEP_CI_RUNNER=1 — the self-hosted runner VM is kept (use this when idling FROM it)."
  else
    note "KP_KEEP_CI_RUNNER is not 1 — idle.tfvars will DESTROY the self-hosted runner VM."
  fi
}

idle_epilogue() {
  echo "    NOTE: this destroyed the container registry. Every image is gone and MUST be"
  echo "    rebuilt and re-pushed before the next deploy — see docs/AZURE-IDLE.md."
  echo "    RESUME ORDER: PostgreSQL first, then the apps."
}

cmd_stop() {
  run_preflight "$IDLE_PREFLIGHT_VARS"
  stop_postgres
  local -a flags
  while IFS= read -r flag; do flags+=("$flag"); done < <(idle_plan_flags)
  note_ci_runner_retention
  confirm_apply "idle: ACR+Redis+workloads OFF" "${flags[@]}"
  echo "==> IDLED. Tier-1 (ACS/domain/DNS) stays up at ~\$0. Resume with: $0 start"
  idle_epilogue
}

# ---------------------------------------------------------------------------
# The two non-interactive halves used by .github/workflows/azure-idle.yml.
#
# They exist because the idle posture CANNOT be applied from the operator's
# machine: network_mode=private puts Key Vault behind a private endpoint, and
# terraform must refresh ~25 azurerm_key_vault_secret resources through the vault
# DATA plane and DELETE the redis-url secret. Only a job on the VNet runner, with
# GitHub OIDC credentials, can reach both.
# ---------------------------------------------------------------------------
cmd_plan_idle() {
  run_preflight "$IDLE_PREFLIGHT_VARS"
  local -a flags
  while IFS= read -r flag; do flags+=("$flag"); done < <(idle_plan_flags)
  note_ci_runner_retention
  run_plan "idle: ACR+Redis+workloads OFF (plan only)" "${flags[@]}"
  rm -f "$TF_DIR/$PLAN_FILE"
  echo
  echo "==> PLAN ONLY — nothing was applied and nothing in Azure changed."
  echo "    PostgreSQL was not stopped; only 'apply-idle' does that."
}

cmd_apply_idle() {
  require_dispatch_confirmation "apply-idle"
  run_preflight "$IDLE_PREFLIGHT_VARS"
  local -a flags
  while IFS= read -r flag; do flags+=("$flag"); done < <(idle_plan_flags)
  note_ci_runner_retention
  # Plan and guard BEFORE stopping Postgres, so a guard refusal leaves Azure
  # exactly as it was.
  run_plan "idle: ACR+Redis+workloads OFF" "${flags[@]}"
  stop_postgres
  apply_saved_plan
  echo "==> IDLED. Tier-1 (ACS/domain/DNS) stays up at ~\$0. Resume with: $0 start"
  idle_epilogue
}

cmd_guard_plan() {
  [ -n "${1:-}" ] || die "usage: $0 guard-plan <terraform-show-json-file>"
  [ -f "$1" ] || die "no such structured plan file: $1"
  guard_plan_json "$1"
}

cmd_start() {
  local want_workloads=0
  [ "${1:-}" != "--workloads" ] || want_workloads=1
  run_preflight "environment= network_mode= acs_deployment_stage= deploy_workloads= deploy_data_plane="
  start_postgres
  local -a flags
  while IFS= read -r flag; do flags+=("$flag"); done < <(common_plan_vars)
  if [ "$want_workloads" -eq 1 ]; then
    # A workloads resume needs real, digest-pinned images. `stop` destroyed ACR,
    # so unless they have been re-pushed the image variables fall back to
    # "bootstrap.invalid/...:pending" and the Container Apps come up broken.
    for image_var in KP_OPERATOR_IMAGE KP_TRACKING_IMAGE KP_WORKER_IMAGE KP_MIGRATION_IMAGE; do
      [ -n "${!image_var:-}" ] || fail_with_fix \
        "'start --workloads' needs digest-pinned images and $image_var is unset" \
        "'$0 stop' destroys the container registry, so the images no longer exist." \
        "The supported resume is to rebuild and re-push them through the deploy workflow:" \
        "  scripts/operator/deployment-preflight/dispatch-staging-workloads.sh" \
        "Only if the images are already back in ACR, set all four and retry:" \
        "  export KP_OPERATOR_IMAGE=<registry>/operator-api@sha256:..." \
        "  export KP_TRACKING_IMAGE=<registry>/tracking-api@sha256:..." \
        "  export KP_WORKER_IMAGE=<registry>/worker@sha256:..." \
        "  export KP_MIGRATION_IMAGE=<registry>/migration@sha256:..."
    done
    flags+=(
      "-var=deploy_workloads=true" "-var=deploy_data_plane=true"
      "-var=operator_image=$KP_OPERATOR_IMAGE"
      "-var=tracking_image=$KP_TRACKING_IMAGE"
      "-var=worker_image=$KP_WORKER_IMAGE"
      "-var=migration_image=$KP_MIGRATION_IMAGE"
    )
    confirm_apply "resume: ACR+Redis+workloads ON" "${flags[@]}"
    repatch_oidc
    echo "==> RESUMED. Log in at the operator console and verify before a real send."
  else
    # Default resume: bring the freely-destroyable infra back (ACR + Redis + their
    # private endpoints) WITHOUT workloads, because there are no images yet.
    flags+=("-var=deploy_workloads=false" "-var=deploy_data_plane=true")
    confirm_apply "resume: ACR+Redis ON, workloads still OFF" "${flags[@]}"
    echo "==> INFRASTRUCTURE RESUMED (registry + Redis are back, empty)."
    echo "    Next: rebuild and push the images, which also deploys the workloads:"
    echo "      scripts/operator/deployment-preflight/dispatch-staging-workloads.sh"
    echo "    (Use '$0 start --workloads' only when the images are already in ACR.)"
  fi
}

case "${1:-status}" in
  status)     cmd_status ;;
  preflight)  cmd_preflight ;;
  stop)       cmd_stop ;;
  start)      shift; cmd_start "${1:-}" ;;
  guard-plan) shift; cmd_guard_plan "${1:-}" ;;
  plan-idle)  cmd_plan_idle ;;
  apply-idle) cmd_apply_idle ;;
  *) echo "usage: $0 {status|preflight|stop|start [--workloads]|guard-plan <plan.json>|plan-idle|apply-idle}"; exit 2 ;;
esac
