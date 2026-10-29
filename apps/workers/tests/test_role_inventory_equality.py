"""KP-AUD-002 regression guard: the worker-role inventory is ONE set, everywhere.

The managed deployment previously omitted the ``reply-mailbox`` and ``curation``
worker roles (and therefore their DB login/secret/database-url), so a role that
the worker entrypoint knows how to run had no provisioned identity. This test
pins the three independent declarations of "which worker roles exist" to a
single equal set so they can never silently drift again:

* ``kp_workers.__main__.WORKERS`` — the roles the supervisor can actually run;
* ``kp_database.grants.RUNTIME_ROLES`` — the roles the least-privilege grant
  matrix (and ``scripts/azure_migrate.py``, which consumes it) provisions, minus
  the two non-worker consoles ``operator`` and ``tracking``;
* the Terraform role universe in ``infrastructure/terraform/main.tf`` —
  ``core_worker_roles`` plus every provider-conditional key in
  ``provider_worker_env`` (the full set of roles Terraform can create a DB role,
  secret and ``KP_WORKER_DATABASE_URL_*`` for).

These are static, DB-free, offline checks (no terraform/cloud invocation).
"""

from __future__ import annotations

import re
from pathlib import Path

from kp_database import grants
from kp_workers.__main__ import WORKERS

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MAIN_TF = _REPO_ROOT / "infrastructure" / "terraform" / "main.tf"

#: workload keys in RUNTIME_ROLES that are NOT worker roles (console/API logins).
_NON_WORKER_WORKLOADS = frozenset({"operator", "tracking"})


def _terraform_worker_roles() -> set[str]:
    """Parse main.tf for the full set of worker roles Terraform can provision.

    That is ``local.core_worker_roles`` (always created) unioned with every key
    of ``local.provider_worker_env`` (created when its provider is configured).
    """
    text = _MAIN_TF.read_text(encoding="utf-8")

    core_match = re.search(r"core_worker_roles\s*=\s*toset\(\[([^\]]*)\]\)", text)
    assert core_match is not None, "could not locate core_worker_roles in main.tf"
    core = set(re.findall(r'"([^"]+)"', core_match.group(1)))

    # Each provider_worker_env entry gates a role on an endpoint/address var with
    # the `<role> = trimspace(var.X) == "" ? {} : {` fail-closed idiom.
    provider = set(
        re.findall(
            r'^\s*"?([A-Za-z0-9_-]+)"?\s*=\s*trimspace\(var\.[A-Za-z0-9_]+\)\s*==\s*""\s*\?\s*\{\}\s*:\s*\{',
            text,
            flags=re.MULTILINE,
        )
    )
    assert provider, "could not locate any provider_worker_env roles in main.tf"
    return core | provider


def _grants_worker_roles() -> set[str]:
    return set(grants.RUNTIME_ROLES) - _NON_WORKER_WORKLOADS


def test_worker_role_inventory_is_one_equal_set() -> None:
    source = set(WORKERS)
    grant = _grants_worker_roles()
    terraform = _terraform_worker_roles()

    assert source == grant, f"WORKERS vs grants.RUNTIME_ROLES drift: {source ^ grant}"
    assert source == terraform, f"WORKERS vs terraform role universe drift: {source ^ terraform}"


def test_formerly_missing_roles_are_present_everywhere() -> None:
    # The specific KP-AUD-002/020 gap: these two must appear in all three.
    for role in ("reply-mailbox", "curation"):
        assert role in WORKERS, role
        assert role in grants.RUNTIME_ROLES, role
        assert role in _terraform_worker_roles(), role


def test_every_worker_role_has_a_least_privilege_grant_slice() -> None:
    # A provisioned role with no TABLE_GRANTS entry would receive no least-
    # privilege grants at all (azure_migrate iterates TABLE_GRANTS per role).
    for role in _grants_worker_roles():
        assert role in grants.TABLE_GRANTS, f"{role} has no TABLE_GRANTS slice"


def test_new_roles_follow_the_runtime_role_naming_convention() -> None:
    # Terraform derives the PG role name as kp_worker_${replace(role,"-","_")};
    # grants.RUNTIME_ROLES must match byte-for-byte or the two inventories name
    # different Postgres roles.
    for role in _grants_worker_roles():
        expected = "kp_worker_" + role.replace("-", "_")
        assert grants.RUNTIME_ROLES[role] == expected, (role, grants.RUNTIME_ROLES[role], expected)
