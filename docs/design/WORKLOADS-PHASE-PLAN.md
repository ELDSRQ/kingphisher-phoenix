# Workloads phase — enablement plan

Goal: run the `workloads` deploy phase, which provisions the application
container apps (operator-api, tracking-api, workers, migration; plus the
ai-gateway when enabled) into Azure. Unlike bootstrap/finalize (which ran in
`starter` mode on hosted runners), workloads is `private`-only and needs
infrastructure that does not exist yet.

Status: PLAN. Building the runner infrastructure first (the keystone).

## Why workloads is different (the hard constraints)

- `deployment_orchestration.py:858` rejects `workloads` unless
  `network_mode == "private"`.
- In `private` mode the data plane (Postgres, Redis, Key Vault, ACR) moves
  behind **private endpoints**, unreachable from the public internet, so the
  deploy job runs on a **self-hosted runner inside the VNet**
  (`["self-hosted","linux","azure-vnet"]`, azure-deploy.yml:340). The env guard
  refuses `private` if that runner is absent.
- Our staging foundation is `starter` (public, the 11 `private_network`-gated
  resources are count=0). So both the runner and the private networking must be
  created before workloads can run.

## The three prerequisites and the plan for each

### 1. Self-hosted VNet runner (the keystone — building now)

Terraform-managed (no state drift), gated by a new `var.deploy_ci_runner`,
created by a **starter-mode bootstrap** (hosted runner can create a VM in the
VNet even though the VM lives inside it — that resolves the chicken-and-egg:
the runner is created from the public path, then used for the private path):

- New subnet `snet-ci-runner` `10.42.3.0/24` in `vnet-kp-staging`.
- A small Linux VM (e.g. Standard_B2s) with a system-assigned identity, no
  inbound (NSG denies all inbound; outbound to GitHub via the default route /
  a NAT path), cloud-init that installs the GitHub Actions runner and registers
  it with labels `self-hosted,linux,azure-vnet` using an operator-supplied,
  short-lived **registration token**.
- The token is never committed: passed as `TF_VAR_ci_runner_registration_token`
  from a repo/environment secret the operator sets right before the run (GitHub
  runner tokens expire in ~1h), consumed only by cloud-init.

### 2. Convert the foundation to private mode

Re-run **bootstrap in `private`** (from the new runner). Terraform then *adds*
the private DNS zones, private endpoints, and VNet links, and flips the data
plane to private — all create/update, so the create/update-only allowlist holds
and the ACS/email work already finished is preserved (no teardown).

### 3. Real operator/tracking hostnames + certificates

The container apps' ingress + the OIDC redirect use `operator_fqdn` /
`tracking_fqdn` (currently onmicrosoft placeholders). For a reachable console
these become custom hostnames on `floridamanevolved.us` (e.g.
`kp-admin.floridamanevolved.us`, `kp-link.floridamanevolved.us`) with managed
certificates — a later step; a first workloads apply can proceed with distinct
valid hostnames and have DNS/cert bound afterward.

## Sequence

1. Build + review the runner terraform (this change), `terraform validate`.
2. Operator sets `DEPLOY_CI_RUNNER=true` + a fresh runner registration token,
   dispatches a starter bootstrap → the runner VM comes up and registers.
3. Dispatch bootstrap in `private` (now runs on the runner) → private endpoints.
4. Dispatch `workloads` (on the runner) → builds the 5 images in ACR, scans,
   attests, runs migration, deploys the container apps, activates receipts.
5. Bind custom hostnames + certs; point `ai_endpoint`/FQDNs at the real hosts.

## Related requirement: GUI-driven DNS + console wizard

Operator feedback from the email setup: the ACS DNS records (domain TXT, SPF,
DKIM/DKIM2 CNAMEs) and their verification should be a **guided console wizard**,
not manual dig/paste. The platform already computes the exact records
(`acs_delivery_readiness.dns_records`); the gap is a console flow that (a)
displays the exact records to add with copy buttons, (b) lets the operator mark
them added, (c) triggers/reads back verification, and (d) surfaces per-record
Verified/Pending state. To be built as a follow-up after the runner keystone.
See the console Azure-deployment wizard (`console.py`) as the host surface.
