# Azure deployment

The Terraform stack in `infrastructure/terraform` deploys a single-tenant,
Azure-contained runtime. It is deliberately separate from the disposable local
Docker Compose installation.

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

The network is intentionally private for PostgreSQL, Redis, Key Vault, and ACR.
For that reason Terraform and ACR builds must run from the `azure-vnet`
self-hosted runner named in `.github/workflows/azure-deploy.yml`. A public GitHub
runner cannot reach those data planes. Bootstrap that runner in a peered
administration subnet before enabling the workflow.

## Prerequisites

1. An Azure Storage account/container for the Terraform backend with Azure AD
   authentication and blob versioning enabled. Copy `backend.hcl.example` to an
   untracked backend file or configure the equivalent CI arguments.
2. A GitHub environment named `staging` and `production`. Production should have
   required reviewers.
3. GitHub environment variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID`, `ENTRA_APPLICATION_CLIENT_ID`, `OPERATOR_FQDN`,
   `TRACKING_FQDN`, `AI_GATEWAY_ENDPOINT`, `ALERT_WEBHOOK_DOMAINS`,
   `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`, and
   `TF_STATE_CONTAINER`.
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
