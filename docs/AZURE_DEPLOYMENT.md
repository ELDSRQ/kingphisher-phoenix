# Azure deployment

The Terraform stack in `infrastructure/terraform` deploys a single-tenant,
Azure-contained runtime. It is deliberately separate from the disposable local
Docker Compose installation.

The product target is one 125-person tenant operated by two IT staff. Wave 38
keeps the existing secure Azure/provider path supported while prioritizing the
minimum operator loop before further deployment breadth. Deferred features are
retained and supported without expansion; never delete potentially valuable
behavior merely because it is deferred.

Current local/static alignment: `ORG-001` is complete with creator plus one
independent dual-capability approver while security/privacy facets and every
RoE/audience/canary/provider/stop/review gate remain separate and mandatory.
`THR-001A` and `DOCSIM-001` are complete with evidence fidelity and
recipient-bound ICS behavior (150 focused tests). The
`IMP-001` and `THR-001B` are complete locally with guided serialized CSV import
and the bounded explicit-curation Threat Campaigns workflow.
`OUT-001`/`RET-005`/`INT-001` retention integration is present at Alembic head
`0032_source_explicit_curation` with confirmed interaction, current
outcome-writer locks, terminal-only project-before-purge, stable pseudonym
configuration/grants, a 365-day raw maximum, and a PII-free 1,826-day ledger.
Privacy/RBAC, named-history API, and remaining ANA-010 consumers remain open.
The retained P1 (ORM mirroring of migration `0032`'s retention check and
single-default index) is closed, and the migration revision-id overflow was
fixed. The build is committed and pushed through `c9ea716` (checkpoint
`d25313d` + ANA-010 increments); use the continuation prompt in
`RESUME-HERE.md`.

The target local build/qualification worker is the project-isolated native
ARM64 host at `192.168.1.140`, with canonical source
`/Users/edierks/Projects/kingphisher-phoenix` mounted read-only in its
`kingphisher` Colima VM and VM/cache/socket rooted under
`/Volumes/DockerExternal/KingPhisher-Phoenix`. External preflight and restore
passed; the seven internal Docker Desktop project containers are stopped and
preserved while unrelated containers remain running. Validated snapshot
`20260829T013332Z-tsX1WQ`, archive SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
passed external restore; external installation and `verify_install.sh` also
passed. That USB/HFS+
worker is not part
of the Terraform or production topology. Its explicit-socket/no-Docker-Desktop
isolation is documented in `scripts/operator/remote-docker-worker/README.md`.
Docker Desktop on `.140` remains a separate shared engine whose unrelated
workloads are never selected or mutated by this project.
Controller context `kp-external-mac` reports
`colima-kingphisher|aarch64|/var/lib/docker` at exact endpoint
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`;
the default remains
`desktop-linux`.
The legacy Docker contexts `DockerExternal` and `kp-remote-mac` omit the
reviewed socket and can select shared Docker Desktop; never use them for
project operations. The `DockerExternal` volume label identifies storage, not
a Docker context. Rosetta/binfmt are disabled and unnecessary for native ARM64.

> **Current release decision (2026-08-29): NO-GO for production and RSA
> Conference.** The checked-in application and infrastructure contracts are not
> live-environment evidence. Production planning is deliberately blocked by the
> console until custom-domain/certificate and edge controls, live HSTS,
> backup/restore, and a reviewed rollback path are implemented or qualified.

The 2,230/86/2/8 external run was superseded by a pre-remediation snapshot at
head `0029`: 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340 deselected, 2
Redis/2,424 deselected, and 8 live local E2Es plus audit/install verification.
The pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with
0 failures in 158.15 seconds. The final local Wave 36 hermetic suite at checked-in
head `0030_default_privacy_notice` passed 2,501 tests/97 deselected with 0
failures in 183.40 seconds. Ruff/format covered 336 Python files, mypy covered
124 source files, Bandit passed, Semgrep ran 4 rules across 125 targets with 0
findings, Trivy repository scans found 0 HIGH/CRITICAL vulnerabilities,
secrets, or misconfigurations, pip-audit found no known vulnerabilities, and
Actionlint/Zizmor passed in their recorded scopes. PostgreSQL, Redis, and E2E
current-head `0032` external profiles and exact-image evidence remain pending.
PostgreSQL test jobs use Redis DB14
and flush only DB14 before/after; the Redis queue contract uses DB15; neither
may touch application DB0. Provider-aware GUI, privacy, OIDC, release-verifier,
and test-contract edits are included in the final local Wave 36 hermetic result.
The dated
controller snapshot at about 5.6 GiB is historical evidence that the local
capacity gates stopped safely. External capacity and restore are proven. Later
source edits through Wave 38 make the interim five-image native ARM64 snapshot stale, and no
exact-final rebuild/rescan has yet been claimed. AMD64
and registry evidence remain unwitnessed. Final local audit acceptance also
fixed an audit-store owner-fallback revocation defect, reconciled 36 stranded
idempotent queue intents, and left the audit chain green. These local results do
not qualify an Azure deployment, Entra identity, Graph/Outlook or ACS mail path,
browser, full recovery, rotation canary, or witness.

## Guided setup

Open the operator console and select **Azure deployment**. The five-page GUI
wizard explains every non-secret value, provides a “Where do I find this?” link
beside each field, and offers privacy-filtered AI guidance. It validates Azure
IDs, hostnames, endpoint safety, environment choices, and Terraform-state names
before enabling configuration downloads.

The wizard never asks for passwords, client secrets, access keys, federated
tokens, or Terraform state. Its validation is structural and does not contact
Azure. The generated non-secret Terraform values use the same exact ACS endpoint
shape enforced by API, Terraform, and preflight; secrets and external tenant,
DNS, identity, consent, and protected-environment administration remain outside
the download.

When the server-side GitHub Actions connector is configured, the GUI can bind a
staging plan to a reviewed commit/workflow/environment, request an explicit
operator confirmation, dispatch it, and show redacted status. GitHub environment
approval remains a separate control. Terraform does not currently configure the
connector's repository/ref/token settings, and a new tenant still needs external
Azure, Entra, GitHub, DNS, and Microsoft 365 administration. The deployment path
is therefore not yet 100% GUI-driven.

Connector reads do not trust GitHub response size or shape. Workflow metadata,
run status, and activity are streamed under separate small limits, reject
duplicate/malformed `Content-Length`, cap decoded compressed/chunked bytes, and
return stable content-free errors for malformed UTF-8/JSON/schema. Dispatch is
status-only and never buffers the response body. The same boundary applies to
OIDC discovery/token/JWKS and the setup assistant: provider bodies, tokens, and
low-level exception text are not exposed or logged.

## Architecture

- Azure Container Apps: three default continuously running deployables — the
  operator API/UI, tracking API, and one fair multi-role queue worker — plus a
  one-shot migration job invoked by the deployment workflow. Optional delivery
  isolation adds exactly one worker app and is disabled by default.
- Azure Container Registry: immutable application images; admin credentials are
  disabled and every deployed app or migration job pulls through its own
  user-assigned managed identity.
- PostgreSQL Flexible Server 16: private endpoint, TLS, point-in-time backups,
  and zone-redundant HA in production.
- Azure Managed Redis: encrypted port 10000, no-eviction queue semantics,
  private endpoint, and HA in production.
- Key Vault: versionless secret references with secret-level managed-identity
  RBAC. Each workload can read only the references it consumes; no application
  secret is placed in an image or GitHub secret.
- Azure Communication Services Email: a provisioned or reviewed existing
  Communication Service associated with a customer-managed sending domain.
  Engagement tracking is disabled and only worker identities that send mail
  receive Email Sender. The application uses managed identity, never an ACS
  connection string, in managed deployments.
- Azure Event Grid: a system topic filters ACS to
  `Microsoft.Communication.EmailDeliveryReportReceived` and posts only to the
  operator API's dedicated receipt endpoint. Event delivery uses an Entra
  bearer token; no ACS or Event Grid access key is accepted at the webhook.
- Log Analytics and Application Insights: 30-day default retention and an
  explicit daily ingestion quota. These controls prevent the unbounded local-log
  failure mode from becoming an unbounded Azure bill.

## Network modes

The workflow takes a `network_mode` input, and it decides both the security
posture and what infrastructure you need before deploying.

| | `private` (default) | `starter` |
| --- | --- | --- |
| Postgres, Redis, Key Vault, ACR | Private endpoints, public access disabled | Publicly reachable |
| Runner | Self-hosted, inside the VNet | GitHub-hosted `ubuntu-latest` |
| Prerequisite infrastructure | A runner VM in a peered admin subnet | None |
| Production | Required infrastructure mode; release currently **NO-GO** | **Refused** |

`private` is the hardened target state and the default. Because the data planes
are unreachable from the public internet, Terraform must run from a runner that
already has routed access to the VNet. A hosted job cannot create a new VNet and
retroactively place itself inside that VNet during the same deployment.

For a first deployment, either provision and connect the private runner through
a separately reviewed network bootstrap, or use `starter` only for an empty,
authorized non-production foundation. `starter` leaves data planes publicly
reachable so that foundation can run from a hosted runner; it is not the secure
default and it is not production-shaped infrastructure. The customer-domain
verification cycle may require a later dispatch, so neither choice promises
one-dispatch readiness. Terraform refuses `starter` for the production
environment (`terraform_data.network_mode_guard`) and the workflow refuses it
before making any Azure call. Establish the private runner, switch to `private`,
and re-qualify the deployment before introducing recipient data or campaign
workloads.

Images are built with `az acr build` in both modes. The build happens inside the
registry, so no runner needs a Docker daemon.

## Day zero: current staging boundary

There is no honest three-command production path. Use this sequence only for an
authorized non-production staging tenant:

1. Create and protect the GitHub `staging` environment: require at least one
   reviewer and disable administrator bypass.
2. Review and run the mutating bootstrap below. It creates state resources,
   Entra applications/roles, subscription role assignments, federation, and a
   bounded set of protected environment variables.
3. Download the non-secret Terraform values from the Azure deployment GUI, run
   the read-only preflight below, assign human roles, and complete any selected
   Microsoft 365 permission handoff.
4. Dispatch `foundation_bootstrap` to plan and apply the complete
   `deploy_workloads=false` foundation, including ACR, private-network, data,
   ACS/email/domain, and DNS resources. It uses no Terraform targets, refuses
   delete/replacement, explicitly forbids sender/association changes, and
   initiates Domain/SPF/DKIM/DKIM2 verification. Publish the
   generated DNS records, then use `foundation_finalize` only after fresh
   authenticated all-four Verified readback; that stage permits only the exact
   domain association/sender changes and proves them post-apply. `workloads`
   independently revalidates those resources before runtime deployment.
5. After the fixed workflow is committed and the server-side connector is
   configured, use **Azure deployment** in the console to validate and dispatch
   a reviewed staging plan. Direct `gh workflow run` is not the normal path: the
   workflow requires connector-bound request and reviewed-revision inputs.
6. Capture live readiness, receipt, DNS/certificate, restore, and recovery
   evidence. None of those gates may be inferred from a successful Terraform
   apply.

### Preflight

The latest read-only prerequisite audit on 2026-08-28 confirmed the selected
subscription/tenant, subscription Owner authority, `eastus2`, and the required
provider registrations, including `Microsoft.Communication`. It found no
Terraform backend, foundation resource group, platform Entra applications, or
application resources. Current read-only GitHub inspection proves valid
`ELDSRQ` authentication with `repo`/`workflow` scopes; public, enabled
`ELDSRQ/kingphisher-phoenix` with default `main`; Actions enabled; and the Azure
workflow active. It also proves zero environments, variables, and secrets,
unprotected `main`, and remote `main` still at old-tree SHA
`1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time; the checkpoint push has since advanced remote `main` to `c9ea716` (this re-audit is not a branch-protection or secret-protection pass). No workflow dispatch/run,
deployment, or other workload mutation occurred. This is the starting inventory, not a
`foundation_bootstrap`, `foundation_finalize`, or `workloads` pass. The associated script/preflight repair suite passed
56 tests with 1 pre-existing live test skipped.

`scripts/azure_preflight.sh` checks the subscription is visible and enabled,
deployment permissions, current provider registrations, regional Container Apps
availability, required-reviewer/admin-bypass environment controls, and the six
protected environment variables. It parses the GUI-exported values and rejects
Azure-managed test domains, invalid sender/quota/pacing relationships, and
incomplete directory or reported-mailbox role inputs.

```bash
scripts/azure_preflight.sh \
  --subscription <subscription-id> \
  --repo <owner>/<repo> \
  --environment staging \
  --values-file staging.auto.tfvars
```

For ACS this proves only configuration structure and provider registration. It
does not prove custom-domain creation, DNS, quota, certificates, private-runner
reachability, managed-identity send, receipt processing, or inbox placement.

It changes nothing, exits non-zero when the tenant is not ready, and takes
`--json` for scripting.

## Bootstrap: create the core prerequisites

`scripts/azure_bootstrap.sh` creates part of the workflow's prerequisites. It is
designed to converge on re-runs, supports `--dry-run`, and creates no application
runtime, but a normal run is highly mutating: it creates the Terraform-state
resources and Entra applications, validates the exact existing app-role
contract, reconciles federation, grants subscription roles, and writes reviewed
protected GitHub environment variables. Before its first mutation it uniquely
resolves both expected applications and validates every role on an existing
operator application; malformed, missing, changed, extra, duplicate, or
ambiguous identity evidence stops the run. The same contract is checked again
at point of use. Review the script with the Azure, Entra, and GitHub owners
before running it.

```bash
az login
gh auth login

scripts/azure_bootstrap.sh \
  --subscription <subscription-id> \
  --repo <owner>/<repo> \
  --environment staging \
  --operator-fqdn awareness.corp.example
```

It provisions:

- a resource group, storage account and container for Terraform state, with
  blob versioning plus blob/container delete retention enabled, shared-key and
  public blob access disabled, and a narrowly scoped data-plane role for the
  deployment identity (state holds generated credentials);
- an Entra application for **deployment**, with a GitHub federated credential so
  CI authenticates with a short-lived token and no client secret is ever
  created;
- a **separate** Entra application for **operator sign-in**, carrying seven
  human app roles (`source_curator`, `campaign_author`,
  `security_approver`, `privacy_approver`, `campaign_operator`, `auditor`,
  `administrator`) and the application-only
  `AzureEventGridSecureWebhookSubscriber` role. Bootstrap idempotently assigns
  that role to both `Microsoft.EventGrid` and the deployment application, as
  Azure requires before an Entra-protected webhook subscription can be
  created;
- `Contributor` and `User Access Administrator` on the subscription — the second
  is required because Terraform assigns AcrPull and secret-level Key Vault
  roles to workload managed identities;
- these protected environment variables: `AZURE_SUBSCRIPTION_ID`,
  `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `TF_STATE_RESOURCE_GROUP`,
  `TF_STATE_STORAGE_ACCOUNT`, and `TF_STATE_CONTAINER`; and
- optional connector values only when
  `--deployment-orchestration-mode` is explicitly supplied; otherwise existing
  deployment connector variables are preserved.

It requires but does **not** create the GitHub environment/reviewer policy, and
refuses mutation unless required reviewers exist and administrator bypass is
disabled. It
also does not create a private runner, custom hostname bindings/certificates,
ACS configuration, optional integration grants, human role assignments, or
Microsoft 365 consent. Its complete six-input command is a break-glass contract
reference only; use the reviewed GUI dispatcher after prerequisites are complete.

## Prerequisites

1. An Azure Storage account/container for the Terraform backend with Azure AD
   authentication and blob versioning enabled. Copy `backend.hcl.example` to an
   untracked backend file or configure the equivalent CI arguments.
2. A GitHub `staging` environment with required reviewers. A production
   environment is not authorization to deploy while the release remains NO-GO.
3. Protected GitHub environment variables: `AZURE_CLIENT_ID`,
   `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `TF_STATE_RESOURCE_GROUP`,
   `TF_STATE_STORAGE_ACCOUNT`, and `TF_STATE_CONTAINER`. Optional GUI dispatch
   configuration uses `DEPLOYMENT_ORCHESTRATION_MODE` (`disabled` or
   `github_actions`), `DEPLOYMENT_GITHUB_REPOSITORY`,
   `DEPLOYMENT_GITHUB_REF` (default `main`), and the versionless deployment-Key-
   Vault `DEPLOYMENT_GITHUB_TOKEN_SECRET_ID`. Insert the token value directly
   into Key Vault after foundation; never put it in a variable, GUI field, or
   shell argument.

   All hostnames, Entra sign-in ID, ACS/domain/sender/quota/pacing, recipient
   allowlist, AI/alert endpoints, and optional directory/mailbox settings travel
   in the canonical non-secret `deployment_config` generated by the reviewed GUI.

   Recipient ciphertext settings carry only the active key ID, ordered prior
   key IDs, and a versionless Key Vault reference for the bounded prior-key
   value. Key material must never appear in the GUI/export. Prior keys are
   metadata-bound legacy/recovery input, not a managed active-key rotation
   feature. A first foundation may establish the active ID; every later GUI
   dispatch must preserve it, and active rotation is deliberately blocked.
   See [the ciphertext recovery contract](../infrastructure/terraform/CIPHERTEXT_ROTATION.md).

   The `allowed_recipient_domains` deployment value is **mandatory**. Azure runs
   the platform under OIDC, where the recipient allowlist fails closed: with it
   empty, recipient import is refused and no campaign can be delivered.
   Terraform validates that before apply.
4. Workload-identity federation between GitHub and the deployment identity. Do
   not create a client secret for CI.
5. Public DNS and certificates for the operator and tracking hostnames. Bind
   them to the two Container Apps before production traffic. The default
   `azurecontainerapps.io` hostnames are used by the automated health gate.

The supported AI target is internal-model-first: benchmark two or three small
permissively licensed models, digest-pin the selected weights/license/runtime,
and run a pinned `llama.cpp` generation role/job in the existing worker image.
Use CPU-only Container Apps consumption/job first. Consider scale-to-zero
serverless GPU only if measured latency fails and quota, region, cold start, and
cost are acceptable. Foundry serverless/token inference is an optional measured
fallback; Foundry managed compute and always-on GPU capacity are out of scope.
The `.140` worker may qualify the same pinned model but is never a production
Azure dependency. Deterministic setup and generation fallback remain usable
when inference is unavailable.

The existing `ai_endpoint` `/propose` and `/setup-assist` gateway contract is a
preserved optional adapter rather than the mandatory default. When selected, it
must still be approved non-local HTTPS; an Azure OpenAI resource endpoint alone
does not implement those routes, and loopback, credentials, queries, and
fragments remain rejected. AI output stays advisory. Pattern approval records
only the durable request boundary, never asynchronous provider completion.

The configuration GUI exposes explicit SMTP/ACS and Mailpit/Microsoft 365
provider selects. Only active fields are visible, required, tested, saved, or
sent as non-secret setup-assist context; inactive saved values remain preserved.
Provider/destination changes validate before atomic credential rebinding. The
ACS probe permits only an exact HTTPS `*.communication.azure.com:443` runtime
origin, transmits no credential or message, and reports reachability as a
warning. The Microsoft 365 probe uses one quoted, bounded Graph delta path;
bearer 2xx is verified, no bearer is reachability-only, and 401/403/redirects
fail closed. Managed mode performs no operator-side token, environment, or
managed-identity probe.

Privacy export is authenticated `POST`; privacy list/export responses are
`private, no-store`, and cookie mutations enforce trusted same-origin CSRF
metadata. Migration `0030_default_privacy_notice` persists a safe default only
when no current notice exists and enforces one current notice with a unique
partial index; `0031_awareness_ledger` adds the local PII-free five-year ledger
foundation and `0032_source_explicit_curation` requires explicit legacy
threat re-review plus migrated retention-policy invariants. Privacy/RBAC,
named-history API, reporting/graph, and export consumers remain open. The console loads requests separately from the notice, so a
notice read failure warns without disabling request operations. OIDC endpoints are issuer-origin bound and use single-resolution
IP-pinned TLS transport that preserves Host/SNI while refusing environment
proxies, HTTP/2, and redirects. Cross-origin authorization redirects and
secret-bearing token/JWKS requests fail before use.

## Deployment

Use the console's reviewed dispatcher when it is configured; GitHub environment
approval is still mandatory. The connector intentionally rejects workflow
content whose exact reviewed SHA-256 does not match its code/test constant. The
frozen digest is
`4e57244790ac4cfc582421e39575d0085977abb85772bed55365faa14317804e`.
The verifier checks the explicit Docker endpoint/root/native platform,
unchanged source/context manifests, the caller-supplied expected source-manifest
digest, and all five image IDs. It binds the exact Trivy 0.74.0 executable/hash/cache,
rejects ambient `TRIVY_*`, records fresh database/check-bundle metadata, makes
the verified cache immutable, then scans those exact IDs and binds
no-clobber JSON/checksum evidence into `qualification.json`. The preserved
`final-v2` attempt failed closed before build on BSD filesystem-mode and
evidence-path/source-context defects. Those defects are repaired for
`final-v3`, but only validated retained evidence can pass ARM64 qualification.
The five GUI configuration pages are not execution stages. The fixed workflow
has exactly three reviewed stages:

1. Lint, type checking, static security scans, hermetic/contract/migration
   tests, a fail-closed audit of the frozen/hash-verified external production
   dependency closure, release-image smoke tests, and image vulnerability scans.
2. `foundation_bootstrap`: plan and apply the complete
   `deploy_workloads=false` foundation—including ACR, private-network, data,
   ACS/email/domain, and DNS resources—without Terraform targets. Refuse all
   delete/replacement and association/sender changes, emit exact DNS guidance,
   and initiate exactly Domain/SPF/DKIM/DKIM2 verification.
3. `foundation_finalize`: after fresh authenticated all-four Verified readback,
   permit only the exact association/sender changes and prove both with
   authenticated post-apply readback. Pending verification is not success.
4. `workloads`: re-read the exact association/sender and perform remote
   image builds in ACR, tagged with the Git commit SHA.
5. CycloneDX SBOM/provenance generation and registry attestation verification,
   followed by the workload plan and apply. The local dependency SBOM contains
   59 total components/58 external package PURLs; release-image attestations
   remain a distinct artifact and must be verified against the published image.
6. The one-shot database role/migration job.
7. Operator and tracking `/readyz` qualification; then exactly one active
   Healthy/Provisioned worker revision, every enabled role ready in two
   consecutive simultaneous Log Analytics observations, and a same-revision
   health recheck; then a narrowly scoped second plan/apply for the ACS Event
   Grid subscription. Any worker role failure keeps environment health closed.

Terraform derives `TRACKING_API_TRUSTED_PROXIES` from the exact Container Apps
infrastructure subnet plus loopback CIDRs. The tracking API validates and bounds
that set, accepts forwarding only from a trusted direct peer, and walks the
canonical `X-Forwarded-For` chain right-to-left; Uvicorn proxy rewriting is
disabled. This prevents all clients behind the managed ingress from collapsing
onto the ingress peer for client-IP rate limiting.

The current workflow explicitly requests `linux/amd64`, captures and re-resolves
each immutable ACR digest, binds SBOM/provenance subjects to those digests,
rejects credentials or tokens in reviewed configuration, avoids persisted
checkout credentials, and removes ephemeral registry credentials. Its focused
hardening gate passed 23 tests, Actionlint, and Zizmor. This is workflow evidence,
not a registry or Azure execution result. Wave 21 Terraform integration remains
active and unqualified.

Every reviewed plan begins an append-only, hash-chained checkpoint sequence with
bounded non-secret evidence. The stored recovery contract requires preservation
of working/runtime state, provider and build caches, images, containers, named
volumes, databases, and qualification evidence; it forbids automatic cleanup.
Environment and operation leases prevent concurrent dispatches, while the opaque
request ID, reviewed revision, and correlation ID bind refreshes to the same
attempt. If dispatch or status becomes uncertain, inspect and reconcile that
existing request against GitHub evidence. Do not submit a second request,
overwrite an unknown operation, or infer that an absent response means no Azure
mutation occurred.

Container Apps use multiple revisions for the two public APIs. There is no
allowlisted GUI rollback workflow or recorded qualified recovery target. If a
staging qualification fails, stop and use a separately reviewed manual recovery
procedure; do not improvise a production cutover. Database migrations must
remain backward compatible because a prior application revision may need to be
restored manually.

The exact checked-in Alembic head is `0032_source_explicit_curation` (`0026`
training-resource library, `0027` recipient-exclusion lifecycle, `0028` exact
campaign-training binding, `0029` durable reviewed-canary launch gate, and
`0030` persisted default/single-current privacy notice, `0031`
confirmed-interaction/PII-free 1,826-day ledger foundation, and `0032` explicit
legacy threat curation plus retention-policy invariants). The current-head
external PostgreSQL profile passed 92 tests on 2026-08-29, including
fresh/historical migration coverage to exact head `0032`; the historical 86-test
result at `0029` is superseded. Qualification
repaired leaked schema/table/role/engine cleanup paths; the earlier targeted
`0025`→`0026` preservation/write-bound/least-privilege evidence remains valid.
The native ARM64 migration image passed at the latest completed snapshot, but
later source edits through Wave 38 make that interim image stale. External-worker capacity
is now the execution path, but the exact-final rebuild/rescan remains pending.
AMD64, registry,
and live Azure migration-job evidence remain required before production or RSA
Conference use.

## Secrets, state, and initial access

Terraform generates the database passwords, audit HMAC key, active encryption key,
JWT secret, recipient salt, tracking and training token HMAC keys, ACS
receipt-signing key, and break-glass console password. Values are stored in Key
Vault, but they also exist as sensitive data inside Terraform state. The
backend therefore requires encryption, RBAC, blob versioning, a resource lock,
and access logging. Never print state or secret outputs in CI.

The active ciphertext KEK therefore remains in protected Terraform state and
its history. Its resource uses `prevent_destroy`: that blocks accidental active
key replacement but also means teardown requires an explicit, separately
reviewed removal of the lifecycle protection. The external prior-key recovery
secret is prepared directly in Key Vault and is not a Terraform variable, plan,
or state value. Safe active-key rotation still requires a future
pre-stage/prove/promote sequence across all revisions, a database decrypt
canary, bulk re-encryption, and proof before any prior key is retired.

Every privilege boundary has a distinct PostgreSQL login and DSN: `kp_operator`,
`kp_tracking`, and one `kp_worker_<role>` login per enabled worker role. The
single worker identity can read only that enabled set of role DSNs, and its
supervisor builds an independent database context for each role; consolidating
containers therefore does not turn the worker into a database super-role. The
migration job alone receives the `kpadmin` owner DSN and the raw runtime-role
passwords needed to create or rotate those logins. Runtime roles receive
explicit table grants, no table ownership, no schema creation, no migration
authority, and no blanket sequence grants. `audit_writer` remains a shared,
separate DSN because every audited workload appends to the same hash chain; it
owns no tables and is limited to the two audit tables.

Disabling an optional provider role removes its DSN and provider configuration
from the combined worker identity through Terraform; the next migration-job run
also changes its database role to
`NOLOGIN` and revokes all table, sequence, and schema privileges. The role name
is retained only so historical database/audit records remain intelligible.

The core role set is `ingestion`, `delivery`, `retention`, `reminder`, `alert`,
and `audit-anchor`. `generation`, `directory`, and `mailbox` join the same
supervisor only when their explicit HTTPS provider endpoint is configured. The
supervisor polls
each enabled role once per round, isolates role backoff/failures, reports
role-level readiness in structured logs, and recovers expired Redis leases at
startup and on a bounded cadence.

Set `isolate_delivery_worker = true` only when delivery needs a separate scaling
or blast-radius boundary. This creates one delivery-only identity/app with only
the delivery DSN, RoE key, receipt-signing key, common queue/encryption secrets,
ACR pull, and ACS sender permission. The operator and whichever deployment owns
the delivery role receive separate secret-scoped Key Vault references to the
same receipt-signing secret; no other workload can read it. This does not
recreate the former per-role app fan-out.
`terraform output -json runtime_topology` shows the enabled roles, app count,
minimum and maximum replicas, migration-job count, and role placement before an
operator approves deployment.

Adding a table or a new worker data path is deliberately fail-closed: update
the reviewed grant map in `scripts/azure_migrate.py`, publish the migration
image, and rerun the manual migration job. Do not grant `ALL TABLES`, schema
`CREATE`, role membership, or the migration DSN to make a new feature start.

The only vault-wide data-plane grant belongs to the Terraform deployment
principal (`Key Vault Secrets Officer`) because it creates and rotates the
declared secrets. Runtime identities use `Key Vault Secrets User` assignments
at individual secret resource scopes.

### Residual tenant-admin steps

Terraform does not grant people access or approve third-party APIs. Before
production, a tenant/subscription administrator must still:

1. retain `User Access Administrator` (or Owner) on the deployment identity so
   reviewed applies can create the per-secret, ACR, and ACS role assignments;
2. assign the operator Entra application roles to the approved users/groups;
3. complete the reviewed Microsoft 365 application-permission procedure below
   if the optional directory or mailbox worker is enabled; and
4. bind and validate the operator/tracking DNS names and certificates.

### Microsoft 365 application permissions

Use **two distinct user-assigned managed identities (UAMIs)**. The directory
UAMI reads membership and basic user attributes for explicitly configured Entra
groups. The mailbox UAMI reads only the configured report mailbox. Do not reuse
one identity for both jobs: doing so combines their effective permissions and
defeats this separation.

The deterministic permission matrix is:

| UAMI | Resource | Permission type | Permission | Intended boundary |
| --- | --- | --- | --- | --- |
| Directory | Microsoft Graph | Application | `GroupMember.Read.All` (`98830695-27a2-44f7-8c18-0c3ebc9698f6`) | Configured Entra group object IDs only |
| Directory | Microsoft Graph | Application | `User.ReadBasic.All` (`97235f07-e226-4f63-ace3-39588e11d3a1`) | Users returned from those groups only |
| Mailbox | Exchange Online Application RBAC | Application | `Application Mail.Read` | Custom resource scope matching only the configured report mailbox |

Microsoft Graph application permissions are tenant-wide capabilities; selected
group IDs are **not** resource-scoped enforcement in Entra consent. The worker
code must constrain every directory query to the reviewed group-object-ID
allowlist. A new group is not authorized merely because the directory UAMI can
technically query it: add its immutable object ID to reviewed configuration.

For mailbox ingestion, grant Exchange Online `Application Mail.Read` through a
custom resource scope whose recipient filter matches only the configured report
mailbox. **Do not also grant Entra/Microsoft Graph `Mail.Read` or Exchange's
legacy unscoped `full_access_as_app` permission.** Permissions are additive; an
unscoped grant would bypass the Exchange Application RBAC mailbox boundary.

Prerequisites for the tenant-admin handoff:

- the directory and mailbox UAMIs have been deployed, and their separate
  application/client IDs and service-principal object IDs have been recorded;
- the immutable object ID of every approved source group and the exact SMTP
  address of the dedicated report mailbox have been reviewed;
- a tenant administrator authorized to grant Microsoft Graph application roles
  is available for the directory consent; and
- an Exchange administrator with the Exchange Online PowerShell module and
  permission to create service principals, management scopes, and role
  assignments is available for the mailbox scope.

First print the exact commands for review. This mode makes no cloud calls:

```bash
scripts/entra_graph_preflight.sh \
  --directory-client-id <directory-uami-client-id> \
  --directory-principal-id <directory-uami-object-id> \
  --mailbox-client-id <mailbox-uami-client-id> \
  --mailbox-principal-id <mailbox-uami-object-id> \
  --mailbox reports@corp.example \
  --group-id <approved-group-object-id> \
  --print-commands
```

The printed Graph commands assign only the two application roles in the table.
The printed Exchange commands register the mailbox UAMI in Exchange Online,
create the one-mailbox management scope, assign `Application Mail.Read` through
that scope, and show `Test-ServicePrincipalAuthorization` for verification.
They are deliberately not executed by the script; a tenant administrator must
review current state and run the required commands in an authenticated admin
shell.

After the administrator completes the grants, omit `--print-commands` to run
the read-only Entra preflight with `az login` established in the target tenant:

```bash
scripts/entra_graph_preflight.sh \
  --directory-client-id <directory-uami-client-id> \
  --directory-principal-id <directory-uami-object-id> \
  --mailbox-client-id <mailbox-uami-client-id> \
  --mailbox-principal-id <mailbox-uami-object-id> \
  --mailbox reports@corp.example \
  --group-id <approved-group-object-id>
```

This checks the two Entra service principals, exact Graph role IDs, and selected
group IDs without changing tenant state. Exchange authorization is a separate
control plane, so the script prints the read-only
`Test-ServicePrincipalAuthorization` command for an Exchange administrator to
run after `Connect-ExchangeOnline`. Neither a zero exit from this preflight nor
successful command review is a live-readiness claim: production readiness still
requires authorized end-to-end directory synchronization and mailbox-ingestion
qualification with audit evidence and no secrets or access tokens in logs.

No admin consent is required for the built-in managed-identity ACR, Key Vault,
or ACS data-plane roles. The workflow starts the one-shot migration job after a
reviewed apply; it is not a scheduled or continuously running service.
The Event Grid secure-webhook application-role reconciliation is an Entra
control-plane change: the person running bootstrap must be an Application
Administrator or an owner of the operator application, in addition to holding
the Azure subscription permissions checked by preflight.

The console password can be retrieved only by an authorized operator from Key
Vault. Normal production login uses Entra OIDC. The setup wizard remains useful
for guidance and connection tests, but deployment-owned environment settings
must be changed through reviewed Terraform/release configuration so changes are
consistent across every worker. AI suggestions never apply or deploy changes.

## ntfy

The generic ntfy delivery contract remains supported. For a strictly
Azure-contained deployment, do not allowlist `ntfy.sh`. Deploy a separately
hardened ntfy Container App with authentication, private persistent storage,
TLS, backup, and a dedicated hostname, then place only that exact hostname in
`ALERT_WEBHOOK_DOMAINS`. The current Terraform stack intentionally does not
create an unauthenticated ntfy server. This prevents an apparently convenient
deployment from becoming an open notification relay.

## Preservation and recovery

PostgreSQL has `prevent_destroy`; Key Vault has production purge protection.
Normal deployment is create/update-only and preserves the recorded resource and
state identities. A failed or interrupted operation is handled by refreshing
the same request, verifying its hash-chained checkpoints and GitHub correlation,
and reconciling observed resources in place. No deployment script deletes logs,
databases, Key Vault contents, or Terraform state, and this guide does not treat
an error as authorization to replace them. Any separately proposed retirement
of infrastructure remains outside the automated deployment and recovery path.

Audit-head blobs use a locked time-based WORM policy. That policy cannot be
unlocked or shortened, and retained blobs constrain any separately reviewed
infrastructure-retirement plan. The default retention is 365 days in production
and 1 day in other environments; an explicit override becomes equally
irreversible once applied. A rollback therefore cannot promise immediate
resource-group retirement after an anchor has been written. Check
`terraform output -json audit_anchor_readiness` before deployment and retain
that evidence with the operation checkpoints.

## Email: where simulations are sent from

Simulated phishing must not leave from corporate mail. It needs a separate
sending domain, it goes to external recipients, and a corporate domain would
both contaminate real mail flow and make the simulation indistinguishable from
a genuine internal message.

The supported Azure path uses a **customer-managed sending domain**. The
Azure-managed `*.azurecomm.net` test-domain fallback is rejected for managed
delivery. Choose `acs_resource_mode=provision` to create a dedicated
Communication Service, Email Communication Service, custom domain, and sender
username. Choose `existing` only with the reviewed Communication Service's
complete resource ID and non-secret HTTPS endpoint, plus the
customer-domain resource ID. Never provide an ACS access key or connection
string to Terraform; reading the service through an Azure data source would
also persist those exported credentials in Terraform state.
In existing mode that domain must already be fully verified, connected to the
selected Communication Service, and contain the configured sender username;
the workflow records fresh evidence and does not overwrite an unknown link.

Set `ACS_SENDING_DOMAIN`, `ACS_SENDER_LOCAL_PART`, and
`ACS_SENDER_DISPLAY_NAME` as GitHub environment variables. The resulting sender
is exactly `<local-part>@<customer-domain>`; a different mailbox fails worker
startup and send-time readiness checks.

### DNS and the repeatable three-stage deployment

The first foundation apply creates the custom-domain resource and the
`acs_delivery_readiness` Terraform output lists Azure's exact ownership, SPF,
DKIM, and DKIM2 record name, type, value, and TTL. It reports
`manual_dns_required`; it does not call generated records “verified.”

If `ACS_DNS_ZONE_ID` names a public Azure DNS zone in the same subscription and
that zone contains the sending domain, Terraform writes those exact TXT/CNAME
records. No zone ID means a DNS administrator must copy the output records in
the DNS provider's GUI. DNS propagation and Azure verification remain live
external steps in both cases.

After DNS records exist, the foundation workflow initiates verification for the
exact Domain, SPF, DKIM, and DKIM2 resources and records only that initiation.
Verification is asynchronous, so repeat the GUI's foundation-finalization step
until authenticated Azure readback reports all four as **Verified**. Any manual
status strings or timestamps in reviewed configuration are erased before
Terraform and cannot unlock the next stage. Live evidence expires after 24 hours
by default.

The verified `foundation_finalize` stage—not the workload apply—then links the exact domain
and creates the exact sender username. Workloads performs another authenticated
readback of the association/sender and blocks on missing, stale, future-dated,
failed, mismatched, or ambiguous evidence. The console now presents all three
stages, rejects the seven obsolete manual readiness fields, restores and
advances digest-bound plans, and displays bounded `kp.acs-stage-result.v1`
evidence. That is local implementation evidence, not a live-qualified GUI
deployment.

This release assumes a fresh Azure deployment. The read-only cloud audit found
no existing project Terraform state or resources. A legacy state containing the
old `AzureManagedDomain` address cannot be safely upgraded by this flow and is
explicitly unsupported; migration would require a separate side-by-side domain
and sender cutover with its own approval/evidence path.

### Verifying it works

The ACS SDK operation ID proves provider acceptance, not mailbox or inbox
delivery. Terraform now provisions an Event Grid system topic and an
Entra-protected webhook subscription for ACS delivery reports. A `Delivered`
report means ACS handed the message to the recipient MTA; it still does not
prove inbox placement or that a person saw the message.

Inside the single `workloads` execution stage, Event Grid activation uses two
internal apply passes to prevent Event Grid from reaching a newly replaced
workload before its schema and audit dependencies are qualified. These passes
are not additional GUI/workflow stages:

1. the workload plan explicitly disables the Event Grid subscription; on an
   upgrade this creates a short, intentional receipt-ingress pause;
2. the migration job completes and `/readyz` proves database, queue, rate-limit,
   and audit/outbox integrity;
3. a second Terraform plan is rejected unless its only change is the ACS event
   subscription; and
4. the workflow applies that plan and requires Azure to report the subscription
   provisioning state as `Succeeded`.

The webhook authenticates the Entra JWT's signature, issuer, tenant, audience,
`Microsoft.EventGrid` application ID, and application role. It also matches the
exact subscription name and ACS resource topic, handles Event Grid's synchronous
validation response, limits the request to 256 KiB and 64 events, and accepts
only the documented ACS email delivery schema. It validates the original event,
then removes topic, subject, mailboxes, Internet Message-ID, unknown properties,
and raw diagnostic text. Redis receives only bounded delivery identifiers,
status, time, a diagnostic hash, and an HMAC from the independent receipt key.
The worker verifies that HMAC and exact minimized schema before applying
idempotent receipt, suppression, and pacing state. If audit health or Redis is
unavailable, the endpoint returns `503` so Event Grid retries; it never bypasses
the unsafe-route audit gate.

`scripts/azure_mail_check.sh` is a read-only, exact-resource ACS control-plane
diagnostic:

```bash
scripts/azure_mail_check.sh \
  --resource-group rg-kp-staging \
  --communication-service acs-kp-staging-<suffix> \
  --email-service email-kp-staging-<suffix> \
  --sending-domain simulations.example \
  --sender-local-part awareness
```

The helper refuses resource guessing and Azure-managed test domains. It checks
the exact customer domain, Domain/SPF/DKIM/DKIM2 status, domain association, and
sender username. It never reads a primary connection string or access key and
never sends mail. These are control-plane observations only: they do not prove
the worker's managed identity, current quota, campaign/audit gates, provider
acceptance, Event Grid receipt processing, MTA handoff, or inbox placement.

For live qualification, confirm `terraform output -json acs_receipt_ingress`
shows `enabled: true`, run an authorized one-recipient campaign through the
normal GUI/worker path, and verify its assignment transitions from
provider-accepted to the matching terminal Event Grid status. The repository
tests the protocol and deployment contract locally, but a real tenant delivery
receipt remains required before production or RSA Conference use. See Microsoft's
[ACS email event schema](https://learn.microsoft.com/azure/event-grid/communication-services-email-events),
[webhook validation contract](https://learn.microsoft.com/azure/event-grid/end-point-validation-event-grid-events-schema),
and [Entra-protected webhook guidance](https://learn.microsoft.com/azure/event-grid/secure-webhook-delivery).

Record the reviewed daily quota, messages-per-minute limit, initial ramp batch,
and ramp interval in the wizard's reviewed deployment configuration.
Configuration rejects an initial batch above the per-minute limit or a
per-minute limit above the daily limit. These values constrain batch
configuration but are not a claim that ACS will accept or deliver that volume;
verify current Azure quota and warm the domain with a small authorized pilot.

Keep the simulation domain distinct from your corporate mail domain, and keep
`user_engagement_tracking_enabled = false` — the platform does its own,
consent-aware tracking, and ACS-side open tracking would double-count.

## Send safety on Azure

Two controls are always on in an Azure deployment and cannot be disabled from
the console:

- **Two-person approval.** `OPERATOR_APPROVAL_POLICY` is pinned to `enforce`. A
  campaign cannot be scheduled or delivered until one independent operator
  holding both capabilities completes the separately recorded security and
  privacy facets. The campaign creator cannot approve either facet. The
  operator API refuses to start under OIDC if this is set to `single-admin`, so
  the offline stack's relaxed mode cannot reach a real tenant.
- **Recipient-domain allowlist.** `KP_ALLOWED_RECIPIENT_DOMAINS` gates both
  recipient import and delivery, and is re-checked in the delivery worker so a
  message queued before the policy tightened cannot go out under the old rules.

For the intended two-person tenant, assign `security_approver` and
`privacy_approver` to the same independent reviewer, not the campaign creator.
Both facets remain explicit and audited; self-approval remains refused.

## Configuration is managed, not console-edited

On Container Apps the operator API runs with `OPERATOR_API_CONFIG_STORE=managed`.
The container filesystem is ephemeral and there is no local supervisor, so the
console endpoints that edit `.env` or restart the stack refuse with HTTP 409 and
point at Terraform instead. This is deliberate: previously those calls appeared
to succeed and the change silently vanished on the next revision restart.

To change configuration on Azure, edit the reviewed Terraform/release inputs
(and declared Key Vault secrets where applicable) and re-run the deployment
workflow. Do not edit an individual secret ad hoc without reconciling Terraform
state and every consuming workload.

The setup wizard remains useful on Azure for validating values. Its current
downloads are partial. The separate Azure deployment page can dispatch the
fixed staging workflow only when the server-side GitHub connector is configured;
ordinary Settings changes still cannot mutate a managed deployment.

If external campaign alerts are enabled, configure
`OPERATOR_API_ALERT_DESTINATION_ALLOWLIST` with exact approved HTTPS hostnames.
The API rejects embedded credentials, non-HTTPS destinations, unlisted hosts,
and destination URLs on local-web subscriptions. This is an outbound SSRF/data
egress boundary, not proof that the destination or alert delivery is live-ready.
