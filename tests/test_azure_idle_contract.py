"""Offline contract checks for the deep operator idle.

`scripts/operator/azure-idle.sh stop` destroys the container registry, the
Enterprise Redis and the Container Apps. It is the most destructive routine
operation in the repository, so its contract is pinned here rather than left to
review:

* the plan is ALWAYS shown and ALWAYS gated on the operator typing 'yes' — there
  is no flag, argument or environment variable that skips it,
* it initialises the Terraform backend exactly the way
  `.github/workflows/azure-deploy.yml` does, from the same GitHub environment
  variables and the same state key,
* every Terraform variable without a default is actually supplied, and it is
  supplied by READING the deploy path's single source of truth rather than by
  keeping a second copy of it,
* the ACS readiness strings are replaced by a live readback, because the ACS
  domain association and sender username carry prevent_destroy,
* an already-stopped PostgreSQL server is a logged no-op, not an error,
* a missing precondition is reported by name with the command that fixes it,
  never as a raw Terraform stack trace,
* no secret is committed.

Nothing here touches Azure, GitHub or Terraform. The script is exercised against
`az`, `gh` and `terraform` shims, and its embedded Python programs are executed
directly.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "operator" / "azure-idle.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "azure-deploy.yml"
DISPATCH = REPO_ROOT / "scripts" / "operator" / "deployment-preflight" / "dispatch-staging-workloads.sh"
TERRAFORM_DIR = REPO_ROOT / "infrastructure" / "terraform"
VARIABLES_TF = TERRAFORM_DIR / "variables.tf"
IDLE_TFVARS = TERRAFORM_DIR / "environments" / "idle.tfvars"
STAGING_TFVARS = TERRAFORM_DIR / "environments" / "staging.tfvars"
RUNBOOK = REPO_ROOT / "docs" / "AZURE-IDLE.md"

SENDING_DOMAIN = "mail.floridamanevolved.us"
SENDER_LOCAL_PART = "awareness"
EMAIL_SERVICE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-kp-staging"
    "/providers/Microsoft.Communication/EmailServices/email-kp-staging"
)
COMMUNICATION_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-kp-staging"
    "/providers/Microsoft.Communication/CommunicationServices/acs-kp-staging"
)


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _embedded_program(name: str) -> str:
    """Extract a `python3 - ... <<'MARKER'` program from the script verbatim."""
    match = re.search(rf"<<'{name}'\n(.*?)\n{name}\n", _source(SCRIPT), flags=re.DOTALL)
    assert match is not None, f"no embedded python program {name!r} in azure-idle.sh"
    return match.group(1)


def _no_default_variables() -> list[str]:
    """Every variable in variables.tf that has no default at the top level."""
    source = _source(VARIABLES_TF)
    names = []
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
        if re.search(r"^\s*default\s*=", source[match.end() : index], re.MULTILINE) is None:
            names.append(match.group(1))
    return names


AZ_SHIM = """import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("az " + " ".join(args) + "\\n")

state = json.loads(os.environ["KP_TEST_AZURE"])


def emit(value):
    if isinstance(value, (dict, list)):
        print(json.dumps(value))
    else:
        print(value)
    raise SystemExit(0)


if args[:2] == ["account", "show"]:
    emit(state["subscription_id"] if "--query" in args and "id" in args else
         {"id": state["subscription_id"]})
if args[:2] == ["group", "show"]:
    emit("rg-kp-staging")
if args[:2] == ["ad", "signed-in-user"]:
    emit("11111111-1111-1111-1111-111111111111")
if args[:3] == ["storage", "blob", "list"]:
    if not state["state_container_readable"]:
        sys.stderr.write(
            "ERROR: \\nYou do not have the required permissions needed to perform "
            "this operation.\\n"
        )
        raise SystemExit(1)
    emit("")
if args[:2] == ["keyvault", "list"]:
    emit("kv-kp-staging")
if args[:2] == ["keyvault", "show"]:
    emit(state["key_vault_public_network_access"])
if args[:3] == ["postgres", "flexible-server", "list"]:
    emit(state["postgres_name"])
if args[:3] == ["postgres", "flexible-server", "show"]:
    emit(state["postgres_state"])
if args[:3] == ["postgres", "flexible-server", "stop"]:
    raise SystemExit(0)
if args[:3] == ["postgres", "flexible-server", "start"]:
    raise SystemExit(0)
if args[:2] == ["containerapp", "list"]:
    emit("")
if args[:2] == ["acr", "list"] or args[:2] == ["redisenterprise", "list"]:
    emit("0")
if args[:2] == ["resource", "list"]:
    kind = args[args.index("--resource-type") + 1]
    identifier = (
        os.environ["KP_TEST_EMAIL_SERVICE_ID"]
        if kind == "Microsoft.Communication/EmailServices"
        else os.environ["KP_TEST_COMMUNICATION_ID"]
    )
    emit([{"id": identifier, "application": "kingphisher-phoenix", "environment": "staging"}])
if args[:1] == ["rest"]:
    uri = args[args.index("--uri") + 1]
    verified = state["acs_verified"]
    status = "Verified" if verified else "NotStarted"
    if "/senderUsernames/" in uri:
        emit({"username": os.environ["KP_TEST_SENDER"], "displayName": "Security Awareness"})
    if "/domains/" in uri:
        emit({
            "Domain": status, "SPF": status, "DKIM": status, "DKIM2": status,
            "fromSenderDomain": os.environ["KP_TEST_DOMAIN"],
        })
    emit([os.environ["KP_TEST_EMAIL_SERVICE_ID"] + "/domains/" + os.environ["KP_TEST_DOMAIN"]])
sys.stderr.write("unexpected az invocation: " + " ".join(args) + "\\n")
raise SystemExit(99)
"""

GH_SHIM = """import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("gh " + " ".join(args) + "\\n")
if args[:2] == ["auth", "status"]:
    raise SystemExit(0)
if args[:2] == ["variable", "get"]:
    values = json.loads(os.environ["KP_TEST_GH_VARIABLES"])
    value = values.get(args[2])
    if value is None:
        raise SystemExit(1)
    print(value)
    raise SystemExit(0)
sys.stderr.write("unexpected gh invocation: " + " ".join(args) + "\\n")
raise SystemExit(99)
"""


def _plan_change(kind: str, name: str, actions: list[str], index: int | None = None) -> dict[str, object]:
    address = f"{kind}.{name}" + (f"[{index}]" if index is not None else "")
    return {"address": address, "type": kind, "name": name, "change": {"actions": actions}}


# What `stop` actually plans: the registry, Redis, their private endpoints, the
# redis-url secret, the Container Apps, and the two ACS resources that are also
# gated on deploy_workloads. Nothing protected.
IDLE_PLAN_JSON = json.dumps(
    {
        "format_version": "1.2",
        "resource_changes": [
            _plan_change("azurerm_container_registry", "main", ["delete"], 0),
            _plan_change("azurerm_managed_redis", "main", ["delete"], 0),
            _plan_change("azurerm_private_endpoint", "registry", ["delete"], 0),
            _plan_change("azurerm_key_vault_secret", "runtime", ["delete"]),
            _plan_change("azurerm_container_app", "operator", ["delete"], 0),
            _plan_change("azurerm_eventgrid_system_topic", "acs_delivery", ["delete"], 0),
            _plan_change("azurerm_role_definition", "acs_email_sender", ["delete"], 0),
        ],
    }
)

TERRAFORM_SHIM = """import os
import sys

args = sys.argv[1:]
with open(os.environ["KP_TEST_CALL_LOG"], "a", encoding="utf-8") as target:
    target.write("terraform " + " ".join(args) + "\\n")
if args[:1] == ["init"]:
    raise SystemExit(0)
if args[:1] == ["plan"]:
    print("Plan: 0 to add, 0 to change, 20 to destroy.")
    raise SystemExit(0)
if args[:2] == ["show", "-json"]:
    # The structured plan the destroy guard parses. Tests override it with
    # KP_TEST_PLAN_JSON to exercise a plan that touches a protected resource.
    print(os.environ["KP_TEST_PLAN_JSON"])
    raise SystemExit(0)
if args[:1] == ["apply"]:
    print("Apply complete!")
    raise SystemExit(0)
raise SystemExit(0)
"""

DEFAULT_AZURE = {
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "state_container_readable": True,
    "key_vault_public_network_access": "Enabled",
    "postgres_name": "psql-kp-staging-6117w",
    "postgres_state": "Ready",
    "acs_verified": True,
}

DEFAULT_GH_VARIABLES = {
    "TF_STATE_RESOURCE_GROUP": "rg-kp-tfstate-staging",
    "TF_STATE_STORAGE_ACCOUNT": "kptfstatestg1165",
    "TF_STATE_CONTAINER": "tfstate",
}


def _install_shim(directory: Path, name: str, body: str) -> None:
    implementation = directory / f"{name}_impl.py"
    implementation.write_text(body, encoding="utf-8")
    launcher = directory / name
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(implementation))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o700)


def _environment(
    tmp_path: Path,
    *,
    azure: dict[str, object] | None = None,
    gh_variables: dict[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> tuple[dict[str, str], Path]:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    _install_shim(shim_dir, "az", AZ_SHIM)
    _install_shim(shim_dir, "gh", GH_SHIM)
    _install_shim(shim_dir, "terraform", TERRAFORM_SHIM)
    call_log = tmp_path / "calls"
    call_log.write_text("", encoding="utf-8")
    return {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        "KP_TEST_CALL_LOG": str(call_log),
        "KP_TEST_AZURE": json.dumps({**DEFAULT_AZURE, **(azure or {})}),
        "KP_TEST_GH_VARIABLES": json.dumps(DEFAULT_GH_VARIABLES if gh_variables is None else gh_variables),
        "KP_TEST_EMAIL_SERVICE_ID": EMAIL_SERVICE_ID,
        "KP_TEST_COMMUNICATION_ID": COMMUNICATION_ID,
        "KP_TEST_DOMAIN": SENDING_DOMAIN,
        "KP_TEST_SENDER": SENDER_LOCAL_PART,
        "KP_TEST_PLAN_JSON": IDLE_PLAN_JSON,
        **(extra or {}),
    }, call_log


def _run_script(
    tmp_path: Path,
    *arguments: str,
    stdin: str = "",
    azure: dict[str, object] | None = None,
    gh_variables: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    environment, call_log = _environment(tmp_path, azure=azure, gh_variables=gh_variables, extra=extra_env)
    result = subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), *arguments],  # noqa: S607
        cwd=REPO_ROOT,
        env=environment,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=180,
    )
    calls = [line for line in call_log.read_text(encoding="utf-8").splitlines() if line]
    return result, calls


# --------------------------------------------------------------------------
# The interactive gate — the only thing standing in front of the destroy
# --------------------------------------------------------------------------


def test_the_script_parses() -> None:
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=60)  # noqa: S603,S607


def test_stop_shows_a_plan_and_waits_for_a_typed_yes(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "stop", stdin="yes\n")

    assert result.returncode == 0, result.stdout + result.stderr
    # bash only renders a `read -p` prompt on a terminal, so the banner is what a
    # piped run sees; the prompt itself is pinned against the source.
    assert "REVIEW THE PLAN ABOVE" in result.stdout
    assert "Type 'yes' to apply this plan:" in _source(SCRIPT)
    plans = [call for call in calls if call.startswith("terraform plan")]
    applies = [call for call in calls if call.startswith("terraform apply")]
    assert len(plans) == 1, calls
    assert len(applies) == 1, calls
    # The plan is saved and the apply consumes exactly that saved plan, so the
    # thing the operator reviewed is the thing that runs.
    assert "-out=.idle.tfplan" in plans[0]
    assert ".idle.tfplan" in applies[0]
    assert "-auto-approve" not in applies[0]


def test_anything_other_than_yes_applies_nothing(tmp_path: Path) -> None:
    for answer in ("no\n", "y\n", "YES\n", "\n"):
        result, calls = _run_script(tmp_path, "stop", stdin=answer)
        assert result.returncode != 0
        assert "aborted — nothing applied" in result.stderr
        assert not [call for call in calls if call.startswith("terraform apply")], answer


def test_there_is_no_local_way_to_skip_the_confirmation() -> None:
    """No flag, argument or environment variable skips the typed 'yes' locally.

    There is exactly one non-interactive path, `apply-idle`, and it is not a
    bypass: it refuses unless it is running inside GitHub Actions AND the
    `confirm` dispatch input of .github/workflows/azure-idle.yml was the exact
    string IDLE, which a human types into the dispatch form. That path exists
    because the private Key Vault data plane is unreachable from a laptop, and
    it is covered by tests/test_azure_idle_workflow_contract.py.
    """
    source = _source(SCRIPT)
    # A saved-plan apply is the only apply; both paths reach it through the same
    # helper, and the interactive one only after the read.
    assert source.count("terraform apply") == 1
    assert "read -r -p" in source
    assert "require_dispatch_confirmation" in source
    # The header comment names `--yes` in order to say it does not exist, so only
    # lines that can actually do something are scanned.
    executable = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
    for bypass in ("-auto-approve", "--auto-approve", "--yes", "-y ", "KP_YES", "FORCE"):
        assert bypass not in executable, f"azure-idle.sh must not offer {bypass!r}"


def test_destroy_scope_is_pinned_to_the_idle_var_file(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "stop", stdin="no\n")
    plan = next(call for call in calls if call.startswith("terraform plan"))

    assert "-var-file=environments/idle.tfvars" in plan
    assert "-var=deploy_workloads=false" in plan
    assert "-var=deploy_data_plane=false" in plan
    # The ACS binding resources carry prevent_destroy; at the "disabled" default
    # their count drops to 0 and terraform refuses the whole plan.
    assert "-var=acs_deployment_stage=workloads" in plan
    assert "-var-file=environments/staging.tfvars" in plan


def test_idle_var_file_pins_the_whole_expensive_tier_off() -> None:
    idle = _source(IDLE_TFVARS)
    for flag in ("deploy_workloads", "deploy_data_plane", "deploy_ai_gateway", "deploy_ci_runner"):
        assert re.search(rf"^{flag}\s*=\s*false$", idle, re.MULTILINE), f"{flag} must be pinned false"


# --------------------------------------------------------------------------
# Blocker 1: the backend is initialised exactly the way CI does it
# --------------------------------------------------------------------------


def test_terraform_is_initialised_before_any_plan(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "stop", stdin="no\n")
    terraform_calls = [call for call in calls if call.startswith("terraform ")]

    assert terraform_calls, "the script must run terraform"
    assert terraform_calls[0].startswith("terraform init"), terraform_calls


def test_backend_configuration_matches_the_deploy_workflow(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "preflight")
    init = next(call for call in calls if call.startswith("terraform init"))

    # The five keys the workflow passes at "Initialize Terraform".
    workflow = _source(WORKFLOW)
    for key in (
        "resource_group_name",
        "storage_account_name",
        "container_name",
        "key",
        "use_azuread_auth",
    ):
        assert f'-backend-config="{key}=' in workflow, f"workflow no longer passes {key}"
        assert f"-backend-config={key}=" in init, f"azure-idle.sh must pass {key}"
    assert "-backend-config=key=staging/kingphisher.tfstate" in init
    assert "-backend-config=use_azuread_auth=true" in init


def test_backend_location_is_read_from_github_not_hardcoded(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "preflight")

    fetched = {call.split()[3] for call in calls if call.startswith("gh variable get")}
    assert fetched == {"TF_STATE_RESOURCE_GROUP", "TF_STATE_STORAGE_ACCOUNT", "TF_STATE_CONTAINER"}
    source = _source(SCRIPT)
    for value in ("rg-kp-tfstate-staging", "kptfstatestg1165"):
        assert value not in source, f"{value!r} must not be hardcoded in the script"
    # They are ENVIRONMENT-scoped variables, not repository-scoped.
    assert '--env "$ENVNAME"' in source


def test_a_missing_backend_variable_is_named_not_a_stack_trace(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "preflight",
        gh_variables={"TF_STATE_RESOURCE_GROUP": "rg-kp-tfstate-staging"},
    )

    assert result.returncode == 2
    assert "PREFLIGHT FAILED" in result.stderr
    assert "TF_STATE_STORAGE_ACCOUNT" in result.stderr
    assert "TF_STATE_CONTAINER" in result.stderr
    assert "gh variable list" in result.stderr
    assert not [call for call in calls if call.startswith("terraform ")]


def test_a_missing_state_data_role_names_the_exact_grant(tmp_path: Path) -> None:
    """Subscription Owner is a control-plane role; blob content needs a data role."""
    result, calls = _run_script(tmp_path, "preflight", azure={"state_container_readable": False})

    assert result.returncode == 2
    assert "cannot read the Terraform state container" in result.stderr
    assert "az role assignment create" in result.stderr
    assert "Storage Blob Data Contributor" in result.stderr
    assert not [call for call in calls if call.startswith("terraform ")]


# --------------------------------------------------------------------------
# Blocker 2: every no-default variable actually has a value, from one source
# --------------------------------------------------------------------------


def test_every_no_default_variable_is_supplied(tmp_path: Path) -> None:
    """The var-file the script generates plus staging.tfvars must cover them all."""
    generated = tmp_path / "reviewed.json"
    environment, _ = _environment(tmp_path)
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _embedded_program("PYVARS"), str(DISPATCH), "rg-kp-staging", "staging", str(generated)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    supplied = set(json.loads(generated.read_text(encoding="utf-8")))
    for line in _source(STAGING_TFVARS).splitlines():
        name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if name:
            supplied.add(name.group(1))
    supplied |= {"environment", "network_mode", "acs_deployment_stage"}

    missing = [name for name in _no_default_variables() if name not in supplied]
    assert not missing, f"no local value for: {missing}"


def test_the_reviewed_configuration_is_read_not_copied() -> None:
    """One source of truth: the CONFIG line the deploy workflow already consumes."""
    source = _source(SCRIPT)
    assert "dispatch-staging-workloads.sh" in source
    assert re.search(r'r"\^CONFIG=', source), "it must parse the CONFIG line out of that script"
    # No second copy of the reviewed values anywhere in the script.
    for value in ("floridamanevolved", "calmflower", "169644fd", "808f2f63"):
        assert value not in source, f"{value!r} is a copy of a reviewed value; read it instead"


def test_the_transforms_match_the_deploy_workflow() -> None:
    """The workflow coerces four ACS values to int and derives two endpoints."""
    program = _embedded_program("PYVARS")
    workflow = _source(WORKFLOW)
    for key in (
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
    ):
        assert key in program and key in workflow
    for derived in ("graph_endpoint", "reported_mailbox_endpoint"):
        assert f'config["{derived}"]' in program
        assert f'config["{derived}"]' in workflow
    assert "https://graph.microsoft.com/v1.0" in program


def test_acs_readiness_is_read_live_and_stamped_now(tmp_path: Path) -> None:
    generated = tmp_path / "reviewed.json"
    environment, calls_path = _environment(tmp_path)
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _embedded_program("PYVARS"), str(DISPATCH), "rg-kp-staging", "staging", str(generated)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    config = json.loads(generated.read_text(encoding="utf-8"))
    for key in (
        "acs_domain_verification_status",
        "acs_spf_verification_status",
        "acs_dkim_verification_status",
        "acs_dkim2_verification_status",
    ):
        assert config[key] == "verified"
    # A fresh timestamp is mandatory: acs_domain_live_ready compares it against
    # plantimestamp() minus acs_readiness_max_age_hours.
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z", config["acs_readiness_checked_at"])
    # It came from Azure, not from the committed file.
    reads = [line for line in calls_path.read_text(encoding="utf-8").splitlines() if line.startswith("az rest")]
    assert reads, "the ACS statuses must be read from the live control plane"


def test_an_unverified_acs_domain_refuses_to_plan(tmp_path: Path) -> None:
    """prevent_destroy on the association/sender means terraform would refuse anyway."""
    result, calls = _run_script(tmp_path, "stop", azure={"acs_verified": False}, stdin="no\n")

    assert result.returncode != 0
    assert "not fully Verified" in result.stderr
    assert "prevent_destroy" in result.stderr
    assert not [call for call in calls if call.startswith("terraform plan")]


def test_the_generated_var_file_never_survives_the_run(tmp_path: Path) -> None:
    result, _ = _run_script(tmp_path, "preflight")
    assert result.returncode == 0, result.stdout + result.stderr
    leftovers = list(Path("/tmp").glob("kp-azure-idle*"))  # noqa: S108
    assert not leftovers, f"the temporary variable file must be cleaned up: {leftovers}"


# --------------------------------------------------------------------------
# Blocker 3: an already-stopped PostgreSQL server is a no-op, not an error
# --------------------------------------------------------------------------


def test_an_already_stopped_postgres_is_a_logged_no_op(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "stop", azure={"postgres_state": "Stopped"}, stdin="no\n")

    assert "already not running (state=Stopped)" in result.stdout
    assert not [call for call in calls if call.startswith("az postgres flexible-server stop")]
    assert "ServerIsNotReady" not in result.stdout + result.stderr
    # It still went on to plan, so a stopped server never blocks the idle.
    assert [call for call in calls if call.startswith("terraform plan")]


def test_a_running_postgres_is_stopped(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "stop", azure={"postgres_state": "Ready"}, stdin="no\n")
    assert [call for call in calls if call.startswith("az postgres flexible-server stop")]


def test_an_already_running_postgres_is_a_logged_no_op_on_start(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "start", azure={"postgres_state": "Ready"}, stdin="no\n")

    assert "already running (state=Ready)" in result.stdout
    assert not [call for call in calls if call.startswith("az postgres flexible-server start")]


def test_postgres_is_never_destroyed_or_deleted() -> None:
    executable = "\n".join(
        line
        for line in _source(SCRIPT).splitlines()
        if not line.lstrip().startswith(("#", "echo ", 'echo "', "note ", 'note "'))
    )
    for forbidden in (
        "flexible-server delete",
        "terraform destroy",
        "group delete",
        "az storage account delete",
        "keyvault delete",
        "keyvault purge",
    ):
        assert forbidden not in executable, f"azure-idle.sh must never contain {forbidden!r}"


# --------------------------------------------------------------------------
# start is symmetric, and honest about the images ACR took with it
# --------------------------------------------------------------------------


def test_start_initialises_the_backend_too(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "start", stdin="no\n")
    terraform_calls = [call for call in calls if call.startswith("terraform ")]
    assert terraform_calls[0].startswith("terraform init")
    plan = next(call for call in calls if call.startswith("terraform plan"))
    assert "-var=deploy_data_plane=true" in plan


def test_the_default_resume_does_not_deploy_workloads_against_deleted_images(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "start", stdin="no\n")
    plan = next(call for call in calls if call.startswith("terraform plan"))
    assert "-var=deploy_workloads=false" in plan
    assert "environments/idle.tfvars" not in plan


def test_start_workloads_refuses_without_digest_pinned_images(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "start", "--workloads", stdin="no\n")

    assert result.returncode == 2
    assert "KP_OPERATOR_IMAGE" in result.stderr
    assert "dispatch-staging-workloads.sh" in result.stderr
    assert not [call for call in calls if call.startswith("terraform plan")]


def test_start_workloads_passes_the_supplied_images(tmp_path: Path) -> None:
    _, calls = _run_script(
        tmp_path,
        "start",
        "--workloads",
        stdin="no\n",
        extra_env={
            "KP_OPERATOR_IMAGE": "r.azurecr.io/operator-api@sha256:aa",
            "KP_TRACKING_IMAGE": "r.azurecr.io/tracking-api@sha256:bb",
            "KP_WORKER_IMAGE": "r.azurecr.io/worker@sha256:cc",
            "KP_MIGRATION_IMAGE": "r.azurecr.io/migration@sha256:dd",
        },
    )
    plan = next(call for call in calls if call.startswith("terraform plan"))
    assert "-var=deploy_workloads=true" in plan
    assert "-var=operator_image=r.azurecr.io/operator-api@sha256:aa" in plan


# --------------------------------------------------------------------------
# The private data plane, and what the operator is told about it
# --------------------------------------------------------------------------


def test_a_private_key_vault_refuses_to_run_from_outside_the_vnet(tmp_path: Path) -> None:
    result, calls = _run_script(tmp_path, "stop", azure={"key_vault_public_network_access": "Disabled"}, stdin="no\n")

    assert result.returncode == 2
    assert "public network access DISABLED" in result.stderr
    assert "KP_INSIDE_VNET=1" in result.stderr
    assert not [call for call in calls if call.startswith("terraform ")]


def test_the_vnet_acknowledgement_lets_it_proceed(tmp_path: Path) -> None:
    result, calls = _run_script(
        tmp_path,
        "stop",
        azure={"key_vault_public_network_access": "Disabled"},
        extra_env={"KP_INSIDE_VNET": "1"},
        stdin="no\n",
    )
    assert "aborted — nothing applied" in result.stderr
    assert [call for call in calls if call.startswith("terraform plan")]


def test_idling_from_the_runner_can_keep_the_runner(tmp_path: Path) -> None:
    _, calls = _run_script(tmp_path, "stop", extra_env={"KP_KEEP_CI_RUNNER": "1"}, stdin="no\n")
    plan = next(call for call in calls if call.startswith("terraform plan"))
    assert "-var=deploy_ci_runner=true" in plan


# --------------------------------------------------------------------------
# No secrets, and the docs say the expensive parts out loud
# --------------------------------------------------------------------------


def test_the_script_commits_no_secret() -> None:
    source = _source(SCRIPT)
    credential = re.compile(
        r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
        r"(?:password|secret|token|api[_-]?key|accountkey)\s*[:=]\s*[\"']?[A-Za-z0-9+/=_-]{12,})",
        re.IGNORECASE,
    )
    assert credential.search(source) is None


def test_the_runbook_says_acr_is_destroyed_and_images_must_be_repushed() -> None:
    runbook = _source(RUNBOOK)
    assert "re-push" in runbook or "re-pushed" in runbook
    assert "dispatch-staging-workloads.sh" in runbook
    script = _source(SCRIPT)
    assert "destroyed the container registry" in script


def test_the_runbook_documents_every_precondition() -> None:
    runbook = _source(RUNBOOK)
    for required in (
        "TF_STATE_RESOURCE_GROUP",
        "Storage Blob Data Contributor",
        "az role assignment create",
        "KP_INSIDE_VNET",
        "KP_KEEP_CI_RUNNER",
        "prevent_destroy",
        "acs_deployment_stage",
        "dispatch-staging-workloads.sh",
        "Type 'yes' to apply this plan",
    ):
        assert required in runbook, f"docs/AZURE-IDLE.md must document {required}"


def test_the_runbook_lists_what_survives_and_what_does_not() -> None:
    runbook = _source(RUNBOOK)
    for destroyed in (
        "azurerm_container_registry.main[0]",
        "azurerm_managed_redis.main[0]",
        'azurerm_key_vault_secret.runtime["redis-url"]',
        "azurerm_eventgrid_system_topic.acs_delivery[0]",
    ):
        assert destroyed in runbook
    for survives in (
        "azurerm_postgresql_flexible_server.main",
        "azurerm_storage_container.audit_anchor",
        "azurerm_container_app_environment.main",
    ):
        assert survives in runbook


def test_the_resolved_terraform_blocker_is_written_down_where_it_was_hit() -> None:
    """The redis-url indexing bug is fixed; the record of it must stay where it bit.

    main.tf now merges redis-url into common_secrets only when local.data_plane and
    filters workload_secret_access against keys(local.secret_values), so
    deploy_data_plane=false plans instead of failing with "Invalid index". The
    history stays documented so nobody reintroduces the unconditional index.
    """
    runbook = _source(RUNBOOK)
    assert "RESOLVED blocker: redis-url was indexed unconditionally" in runbook
    assert "local.workload_secret_access" in runbook
    assert "local.common_secrets" in runbook
    assert "Known blocker: redis-url is indexed unconditionally" in _source(IDLE_TFVARS) or (
        "redis-url" in _source(IDLE_TFVARS)
    )
    # The script translates the raw terraform error rather than leaving it bare.
    script = _source(SCRIPT)
    assert "does not identify an element" in script


@pytest.mark.parametrize("command", ["status", "preflight"])
def test_read_only_commands_never_mutate(tmp_path: Path, command: str) -> None:
    _, calls = _run_script(tmp_path, command)
    for call in calls:
        assert not call.startswith(("terraform apply", "terraform destroy")), call
        assert " stop " not in f" {call} "
        assert " start " not in f" {call} "
        assert "containerapp update" not in call
