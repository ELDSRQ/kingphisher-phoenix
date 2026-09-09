# Self-Hosted Keycloak IdP — Entra Alternative Component

This directory contains the self-hosted Identity Provider (IdP) component that makes
Kingphisher-Phoenix independent of Microsoft Entra/O365 for operator login.

**Task:** IAM-003 · **Status:** Built · **Lane:** AUTH · **Priority:** P1

---

## Overview

The operator API uses provider-neutral OIDC verification (`OidcIdP` in
`apps/operator-api/src/kp_operator_api/auth.py`). It already supports Keycloak's
`realm_access.roles` claim shape and fail-closed role mapping. Swapping from Entra
to a self-hosted Keycloak is a **pure configuration change** — no application code
modification required.

This component provides:
1. **Keycloak realm definition** (`realm-kingphisher.json`) — the canonical realm
   with the two OIDC clients and 7 realm roles matching the app's RBAC.
2. **Docker Compose deployment** (`docker-compose.keycloak.yml`) — Keycloak + its
   own PostgreSQL, running on loopback (127.0.0.1:8443).
3. **Provisioning script** (`provision_idp.py`) — idempotent setup via Keycloak
   Admin REST API, creates clients, roles, and optional test users.
4. **Runbook** — how to start, configure, and flip the operator API to use it.

---

## Quick Start

### 1. Start Keycloak

```bash
# From repo root
docker compose -f infrastructure/idp/docker-compose.keycloak.yml up -d
```

Wait for health check (~30s):
```bash
docker compose -f infrastructure/idp/docker-compose.keycloak.yml ps
```

### 2. Provision the Realm and Clients

```bash
# Dry-run first (validates structure, no Keycloak connection)
python infrastructure/idp/provision_idp.py --dry-run

# Full provision against running Keycloak
python infrastructure/idp/provision_idp.py \
  --keycloak-url http://localhost:8443 \
  --admin-user admin \
  --admin-password admin \
  --realm kingphisher \
  --create-test-users \
  --test-user-password "TestPass123!"
```

This outputs the client secrets and environment variables to set.

### 3. Configure the Operator API

Add/update these in your `.env`:

```bash
OPERATOR_API_OIDC_MODE=oidc
OPERATOR_API_OIDC_ISSUER=http://localhost:8443/realms/kingphisher
OPERATOR_API_OIDC_AUDIENCE=kp-operator-api
OPERATOR_API_OIDC_CLIENT_ID=kp-operator-console
OPERATOR_API_OIDC_CLIENT_SECRET=<console-client-secret-from-provision>
OPERATOR_API_OIDC_REDIRECT_URI=http://localhost:8000/api/v1/console/oidc/callback
OPERATOR_API_OIDC_SCOPES=openid profile
```

### 4. Restart the Operator API

```bash
# If running via supervisor
scripts/run_console.sh

# Or if running dev mode
make dev
```

### 5. Test Login

Open http://localhost:8000/console → click "Sign in with OIDC" → you'll be
redirected to Keycloak. Log in with a test user (e.g., `operator` / `TestPass123!`).
After consent, you're redirected back with a session cookie and full RBAC.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Operator API (localhost:8000)             │
│  OidcIdP verifies tokens via Keycloak discovery + JWKS         │
└──────────────────────────┬──────────────────────────────────────┘
                           │ OIDC discovery: /.well-known/openid-configuration
                           │ JWKS: /realms/kingphisher/protocol/openid-connect/certs
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Keycloak (localhost:8443)                 │
│  Realm: kingphisher                                            │
│  Clients:                                                       │
│    • kp-operator-console (confidential, auth-code + PKCE)      │
│      - Redirect: http://localhost:8000/api/v1/console/oidc/callback
│      - Audience mapper → kp-operator-api                       │
│    • kp-operator-api (confidential, audience reference)        │
│  Realm Roles:                                                   │
│    source_curator, campaign_author, security_approver,         │
│    privacy_approver, campaign_operator, auditor, administrator │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Keycloak PostgreSQL                          │
│  (separate DB, not shared with app)                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## SSRF / Public-HTTPS Caveat

**Important:** The operator API's OIDC egress policy (`auth.py:169-235`) only allows:
- **HTTP for localhost/127.0.0.1/::1** (loopback development)
- **HTTPS for public, global-unicast addresses** (production)

A private-LAN Keycloak reached over HTTPS at `10.x`, `172.16-31.x`, or `192.168.x`
is **rejected** with:
```
identity provider ... must resolve only to public addresses
```

### Two Resolution Paths

| Path | Description | Code Change |
|------|-------------|-------------|
| **(a) Public HTTPS (RECOMMENDED)** | Put Keycloak behind a reverse proxy / DNS name (`idp.example.com`) that resolves to a public IP and terminates TLS. | **None** — config only |
| **(b) Private Issuer Carve-out** | Add a config-gated allowance for one operator-declared private issuer origin in `resolve_oidc_endpoint` (`auth.py:229-235`). | **Required** — small change to `auth.py` |

**This component uses Path (a) for local development** — Keycloak runs on
`http://localhost:8443` which is explicitly permitted by the loopback carve-out.

For a hardened local deployment on a private LAN, you would need Path (b).
See `docs/design/INTERNAL-IDP-KEYCLOAK.md §4` for the exact change.

---

## Environment Variables

### Keycloak (docker-compose)

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLOAK_DB_PASSWORD` | `keycloak` | Keycloak DB password |
| `KEYCLOAK_ADMIN` | `admin` | Keycloak admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` | Keycloak admin password |

### Provisioning Script

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLOAK_URL` | `http://localhost:8443` | Keycloak base URL |
| `KEYCLOAK_ADMIN` | `admin` | Admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` | Admin password |
| `KEYCLOAK_REALM` | `kingphisher` | Realm name |

### Operator API (in `.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `OPERATOR_API_OIDC_MODE` | Yes | `oidc` to enable Keycloak |
| `OPERATOR_API_OIDC_ISSUER` | Yes | `http://localhost:8443/realms/kingphisher` |
| `OPERATOR_API_OIDC_AUDIENCE` | Yes | `kp-operator-api` |
| `OPERATOR_API_OIDC_CLIENT_ID` | Yes | `kp-operator-console` |
| `OPERATOR_API_OIDC_CLIENT_SECRET` | Yes | From provisioning output |
| `OPERATOR_API_OIDC_REDIRECT_URI` | Yes | `http://localhost:8000/api/v1/console/oidc/callback` |
| `OPERATOR_API_OIDC_SCOPES` | Yes | `openid profile` |

---

## Role Mapping

The operator API maps Keycloak realm roles to capabilities via:

```python
# auth.py:_ROLE_ALIASES
"operator" → CAMPAIGN_OPERATOR
"campaign-operator" → CAMPAIGN_OPERATOR
"campaign_operator" → CAMPAIGN_OPERATOR
"admin" → ADMINISTRATOR
"administrator" → ADMINISTRATOR

# Direct Role enum matches
source_curator, campaign_author, security_approver,
privacy_approver, campaign_operator, auditor, administrator
```

**Fail-closed:** Any realm role not in the enum or aliases grants **no capability**.

The 7 realm roles in `realm-kingphisher.json` match the `Role` enum in
`packages/authorization/src/kp_authorization/rbac.py:20-27` exactly.

---

## Testing

### Hermetic Contract Test

```bash
# Validates realm JSON role names match RBAC enum
python -m pytest tests/test_entra_alternative_idp.py -v
```

This test is fast, requires no Keycloak, and pins the contract between the
IdP realm definition and the app's fail-closed RBAC mapping.

### Provisioning Dry-Run

```bash
python infrastructure/idp/provision_idp.py --dry-run
```

Validates the request structures that would be sent to Keycloak.

### E2E Manual Verification

1. Start Keycloak + provision
2. Configure `.env` with `oidc` mode + client secret
3. Start operator API (`scripts/run_console.sh` or `make dev`)
4. Open http://localhost:8000/console
5. Click "Sign in with OIDC" → Keycloak login → consent → back to console
6. Verify `/api/v1/console/session` returns mapped roles/capabilities

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `identity provider discovery failed` | Keycloak not ready | Wait for health check, check logs |
| `identity provider has no authorization endpoint` | Wrong issuer URL | Verify `OPERATOR_API_OIDC_ISSUER` ends with `/realms/kingphisher` |
| `invalid or expired token` | Client secret mismatch | Re-run provisioning, update `.env` with new secret |
| `identity provider ... must resolve only to public addresses` | Private-LAN HTTPS issuer | Use Path (a) public HTTPS, or Path (b) auth.py carve-out |
| `redirect_uri_mismatch` | Keycloak redirect URI doesn't match | Ensure Keycloak client has exact redirect URI registered |

---

## Files

```
infrastructure/idp/
├── realm-kingphisher.json          # Canonical realm definition (import-realm)
├── docker-compose.keycloak.yml     # Keycloak + Postgres services
├── provision_idp.py                # Idempotent admin API provisioning
├── README.md                       # This file
└── tests/
    └── test_entra_alternative_idp.py  # Hermetic contract test
```

---

## Related Documentation

- `docs/design/INTERNAL-IDP-KEYCLOAK.md` — Full design doc for IAM-003
- `docs/WAVE-BUILD-PLAN.md` — Task IAM-003 in wave plan
- `docs/HYBRID-AZURE-LOCAL-PLAN.md` §Phase 3 — Fully local when Entra expires
- `apps/operator-api/src/kp_operator_api/auth.py` — OIDC verifier implementation
- `packages/authorization/src/kp_authorization/rbac.py` — Role enum & capabilities

---

## Maintenance

- **Realm changes:** Edit `realm-kingphisher.json` and re-run provisioning, or
  use Keycloak Admin Console directly.
- **Client secret rotation:** Re-run `provision_idp.py` (it regenerates secrets
  on existing clients) and update `.env`.
- **Keycloak version upgrades:** Update image tag in `docker-compose.keycloak.yml`,
  test with `provision_idp.py --dry-run` first.
- **Adding roles:** Add to `REALM_ROLES` in `provision_idp.py` AND to `realm-kingphisher.json`,
  then re-provision. Ensure the role name matches `rbac.py:Role` enum exactly.