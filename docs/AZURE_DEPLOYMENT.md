# Azure deployment

The Terraform stack in `infrastructure/terraform` deploys a single-tenant,
Azure-contained runtime. It is deliberately separate from the disposable local
Docker Compose installation.

## Guided setup

Open the operator console and select **Azure deployment**. The four-stage GUI
wizard explains every non-secret value, provides a “Where do I find this?” link
beside each field, and offers privacy-filtered AI guidance. It validates Azure
IDs, hostnames, endpoint safety, environment choices, and Terraform-state names
before enabling configuration downloads.

The wizard never asks for passwords, client secrets, access keys, federated
tokens, or Terraform state. It does not silently save or deploy anything. After
review, it generates Terraform values and the GitHub environment-variable
handoff used by the protected workflow. An authorized operator must still start
the workflow, review the plan, and approve the target GitHub environment.

## Architecture

- Azure Container Apps: operator API/UI, tracking API, eight continuously
  running queue workers, and a manually triggered migration job.
- Azure Container Registry: immutable application images; admin credentials are
  disabled and workloads pull with a user-assigned managed identity.
- PostgreSQL Flexible Server 16: private endpoint, TLS, point-in-time backups,
  and zone-redundant HA in production.
- Azure Managed Redis: encrypted port 10000, no-eviction queue semantics,
  private endpoint, and HA in production.
- Key Vault: versionless secret references with managed identity. No application
  secret is placed in an image or GitHub secret.
- Azure Communication Services Email: provisioned Azure-managed sending domain,
  engagement tracking disabled, and the runtime receives only the Email Sender
  role. The application uses managed identity rather than an ACS connection
  string.
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
| Production | Supported | **Refused** |

`private` is the hardened target state and the default. Because the data planes
are unreachable from the public internet, Terraform must run from a runner
inside the VNet.

`starter` exists to solve the bootstrap problem: standing up a brand-new tenant
in `private` mode requires a runner VM in a VNet that does not exist yet. It
leaves the data planes publicly reachable so the whole platform can be deployed
from a hosted runner in a single dispatch. **It is for evaluation and first
bring-up only.** Terraform refuses it for the production environment
(`terraform_data.network_mode_guard`) and the workflow refuses it before making
any Azure call. Move to `private` before the platform holds real recipient data.

Images are built with `az acr build` in both modes. The build happens inside the
registry, so no runner needs a Docker daemon.

## Day zero: check, bootstrap, deploy

Three commands, in order. The first two change nothing and take seconds.

```bash
# 1. Is this tenant able to run the platform at all?
scripts/azure_preflight.sh --subscription <id> --repo <owner>/<repo>

# 2. Create everything the deploy workflow expects to already exist.
scripts/azure_bootstrap.sh --subscription <id> --repo <owner>/<repo> \
  --operator-fqdn awareness.corp.example --allowed-domains corp.example

# 3. Deploy.
gh workflow run "Azure deployment" --repo <owner>/<repo> \
  -f environment=staging -f network_mode=starter
```

### Preflight

`scripts/azure_preflight.sh` answers "will this deployment fail twenty minutes
in?" before it starts. It checks the subscription is visible and enabled, that
you hold Owner (or Contributor **and** User Access Administrator — Terraform
assigns roles to a managed identity, which plain Contributor cannot do), that
all ten required resource providers are registered, that the region offers
Container Apps, that the tenant can create ACS email, and that every GitHub
variable and the target environment exist.

It changes nothing, exits non-zero when the tenant is not ready, and takes
`--json` for scripting.

## Bootstrap: create what the workflow expects

`scripts/azure_bootstrap.sh` creates everything the workflow expects to already
exist. It is idempotent, supports `--dry-run`, and creates no application
infrastructure — provisioning stays the workflow's job so there is exactly one
path that builds the platform.

```bash
az login
gh auth login

scripts/azure_bootstrap.sh \
  --subscription <subscription-id> \
  --repo <owner>/<repo> \
  --environment staging \
  --operator-fqdn awareness.corp.example \
  --allowed-domains corp.example
```

It provisions:

- a resource group, storage account and container for Terraform state, with
  blob versioning on and public blob access off (state holds generated
  credentials);
- an Entra application for **deployment**, with a GitHub federated credential so
  CI authenticates with a short-lived token and no client secret is ever
  created;
- a **separate** Entra application for **operator sign-in**, carrying the seven
  app roles the platform recognises (`source_curator`, `campaign_author`,
  `security_approver`, `privacy_approver`, `campaign_operator`, `auditor`,
  `administrator`);
- `Contributor` and `User Access Administrator` on the subscription — the second
  is required because Terraform assigns AcrPull and Key Vault roles to the
  runtime managed identity;
- the GitHub repository variables the workflow reads.

Three things it deliberately leaves to a human, because none can be inferred:
creating the GitHub environment with reviewers, assigning console roles to
people, and confirming the hostnames.

Then deploy:

```bash
gh workflow run "Azure deployment" --repo <owner>/<repo> \
  -f environment=staging -f network_mode=starter
```

## Prerequisites

1. An Azure Storage account/container for the Terraform backend with Azure AD
   authentication and blob versioning enabled. Copy `backend.hcl.example` to an
   untracked backend file or configure the equivalent CI arguments.
2. A GitHub environment named `staging` and `production`. Production should have
   required reviewers.
3. GitHub repository variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID`, `ENTRA_APPLICATION_CLIENT_ID`, `OPERATOR_FQDN`,
   `TRACKING_FQDN`, `ALLOWED_RECIPIENT_DOMAINS`, `AI_GATEWAY_ENDPOINT`,
   `ALERT_WEBHOOK_DOMAINS`, `TF_STATE_RESOURCE_GROUP`,
   `TF_STATE_STORAGE_ACCOUNT`, and `TF_STATE_CONTAINER`. The bootstrap script
   sets all but the hostnames and the two optional endpoints.

   `ALLOWED_RECIPIENT_DOMAINS` is **mandatory**. Azure runs the platform under
   OIDC, where the recipient allowlist fails closed: with it empty, recipient
   import is refused and no campaign can be delivered. Terraform validates that
   it is non-empty rather than letting you discover this at send time.
4. Workload-identity federation between GitHub and the deployment identity. Do
   not create a client secret for CI.
5. Public DNS and certificates for the operator and tracking hostnames. Bind
   them to the two Container Apps before production traffic. The default
   `azurecontainerapps.io` hostnames are used by the automated health gate.

`AI_GATEWAY_ENDPOINT` must implement this repository's bounded `/propose` and
`/setup-assist` contracts. An Azure OpenAI resource endpoint alone does not have
those routes and must not be entered directly. Keep it empty to retain
deterministic setup guidance until an approved private Azure gateway is present.
The application continues to remove secrets and credential-shaped prompt text
before calling that gateway, and AI output remains advisory.

## Deployment

Run the **Azure deployment** workflow manually. It performs:

1. Local lint, type checking, and the complete test suite.
2. Foundation apply with workloads disabled.
3. Remote image builds in ACR, tagged with the Git commit SHA.
4. A reviewed Terraform plan and workload apply.
5. The one-shot database role/migration job.
6. Operator and tracking health qualification.

Container Apps use multiple revisions for the two public APIs. If qualification
fails, do not shift custom-domain traffic; route 100% back to the previously
qualified revision in Azure Container Apps. Database migrations must remain
backward compatible because a prior application revision may be restored.

## Secrets, state, and initial access

Terraform generates the database passwords, audit HMAC key, encryption key,
JWT secret, recipient salt, corrections secret, and break-glass console
password. Values are stored in Key Vault, but they also exist as sensitive data
inside Terraform state. The backend therefore requires encryption, RBAC, blob
versioning, a resource lock, and access logging. Never print state or secret
outputs in CI.

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

## Destruction and recovery

PostgreSQL has `prevent_destroy`; Key Vault has production purge protection.
Normal deployment never destroys data. Removing the stack requires a separate,
explicitly authorized recovery plan, backup verification, removal of the
database lifecycle guard, and a second apply. No deployment script deletes logs,
databases, Key Vault contents, or Terraform state.

## Email: where simulations are sent from

Simulated phishing must not leave from corporate mail. It needs a separate
sending domain, it goes to external recipients, and a corporate domain would
both contaminate real mail flow and make the simulation indistinguishable from
a genuine internal message.

The deployment therefore provisions its **own** email infrastructure: an Azure
Communication Services Email resource with an **Azure-managed sending domain**.
Nothing in your existing mail estate is touched, and no DNS records are needed.

Messages arrive from `DoNotReply@<generated>.azurecomm.net`. Terraform wires
that address into the workers, so the platform sends as the domain it owns.

**One consequence to understand:** under ACS the `From` header is forced to the
managed-domain address, and a campaign's configured `sender_mailbox` is
overridden. The SPF pre-flight and the delivery logs both report the address
that will actually be used, not the one on the campaign — but the campaign form
will still show the value you typed.

### Verifying it works

Deploying successfully does not prove mail works — the domain has to finish
provisioning and the runtime needs the Email Sender role, and both fail at
*send* time. Prove the path before scheduling anything:

```bash
scripts/azure_mail_check.sh \
  --resource-group rg-kp-staging \
  --to you@somewhere-you-can-read.example
```

It sends one message through the same SDK the delivery worker uses and tells
you what to conclude from where it lands. It is deliberately **not** part of the
deploy workflow: it sends real mail to a real person.

### Choosing a sending domain

| | Azure-managed (default) | Custom domain |
|---|---|---|
| Setup | None — provisioned with the deployment | Add the domain in ACS, publish SPF/DKIM/DMARC |
| Address | `DoNotReply@<guid>.azurecomm.net` | Anything on your domain |
| Deliverability | Poor. No reputation, and recipients often filter `azurecomm.net` | Good, once DNS is correct and warmed |
| Send limits | Rate limited; intended for testing | Higher, tied to your ACS tier |
| Use for | Validating the pipeline, demos, first bring-up | Any real assessment |

**Start with the Azure-managed domain** to prove the deployment works end to
end. Move to a custom domain before running an assessment that anyone will draw
conclusions from: a simulation that lands in spam measures your spam filter,
not your people.

Whichever you use, keep it distinct from your corporate mail domain, and keep
`user_engagement_tracking_enabled = false` — the platform does its own,
consent-aware tracking, and ACS-side open tracking would double-count.

## Send safety on Azure

Two controls are always on in an Azure deployment and cannot be disabled from
the console:

- **Two-person approval.** `OPERATOR_APPROVAL_POLICY` is pinned to `enforce`. A
  campaign cannot be scheduled or delivered without both a security and a
  privacy approval, and a person cannot approve their own campaign. The operator
  API refuses to start under OIDC if this is set to `single-admin`, so the
  offline stack's relaxed mode cannot reach a real tenant.
- **Recipient-domain allowlist.** `KP_ALLOWED_RECIPIENT_DOMAINS` gates both
  recipient import and delivery, and is re-checked in the delivery worker so a
  message queued before the policy tightened cannot go out under the old rules.

Assign `security_approver` and `privacy_approver` to **different people** during
setup. With both roles on one person the platform still refuses self-approval,
so nothing can be scheduled at all.

## Configuration is managed, not console-edited

On Container Apps the operator API runs with `OPERATOR_API_CONFIG_STORE=managed`.
The container filesystem is ephemeral and there is no local supervisor, so the
console endpoints that edit `.env` or restart the stack refuse with HTTP 409 and
point at Terraform instead. This is deliberate: previously those calls appeared
to succeed and the change silently vanished on the next revision restart.

To change configuration on Azure, edit `infrastructure/terraform` (or the Key
Vault secret) and re-run the deployment workflow.

The setup wizard remains useful on Azure for validating values and generating
the Terraform inputs; it just cannot apply them itself.
