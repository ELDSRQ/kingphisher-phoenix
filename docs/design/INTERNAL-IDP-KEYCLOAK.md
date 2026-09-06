# Self-Hosted Internal IdP (Keycloak) — Removing the Entra/O365 Dependence for Operator Login

**Task:** IAM-003 · **Status:** design drafted / not started · **Lane:** AUTH · **Priority:** P1

**Goal:** Let operator login run against a self-hosted, locally-DB-backed OIDC provider
(Keycloak) instead of Microsoft Entra/O365, with **no application code change** for the
swap. This document is concrete and evidence-based; every claim cites `file:line` in the
current tree.

---

## 0. TL;DR

The operator API is **provider-neutral OIDC**, not Entra-specific. The verifier is
discovery-based and already understands Keycloak's `realm_access.roles` claim shape, so
pointing it at a self-hosted Keycloak is a **pure configuration change**:

- `OidcIdP` verifies any RS256 issuer via `/.well-known/openid-configuration` discovery
  and JWKS (`apps/operator-api/src/kp_operator_api/auth.py:365-459`).
- Roles are read from **both** Entra `roles` and Keycloak `realm_access.roles`
  (`auth.py:484-491`), mapped through aliases (`auth.py:462-468`), and are **fail-closed**:
  unknown/absent roles grant no capability (`auth.py:501-502`).
- The shipped default issuer is already a **Keycloak realm URL**, not Entra:
  `OPERATOR_API_OIDC_ISSUER=http://localhost:8443/realms/kingphisher`
  (`.env.example:14`, `config.py:97`).

**One caveat blocks a naive on-prem deployment:** the OIDC egress policy only accepts a
**public-resolvable HTTPS** issuer (or `localhost`). A private-LAN Keycloak on
`192.168.x`/`10.x` over HTTPS is **rejected** (`auth.py:169-177,180-190,229-235`). See §4.

---

## 1. How to flip between Entra and a local IdP

The mode is chosen by one env var and the verifier is built from it at startup — no code
branch to edit:

- `make_idp(issuer, audience, mode=settings.oidc_mode, dev_secret=...)`
  (`auth.py:505-510`), wired in `apps/operator-api/src/kp_operator_api/main.py:487-491`.
- `mode == "oidc"` → `OidcIdP` (discovery + JWKS, real verification).
- `mode == "dev"` → `DevIdP` (HS256 shared secret; offline demo only).

All OIDC coordinates are env-driven (`config.py:97-102`, `.env.example:14-19`):

| Env var | Meaning |
| --- | --- |
| `OPERATOR_API_OIDC_MODE` | `dev` or `oidc`. Set `oidc` for any real IdP (Entra **or** Keycloak). |
| `OPERATOR_API_OIDC_ISSUER` | Issuer base URL. Discovery = `{issuer}/.well-known/openid-configuration`. |
| `OPERATOR_API_OIDC_AUDIENCE` | Expected `aud` of the **API access token**. |
| `OPERATOR_API_OIDC_CLIENT_ID` | Console confidential-client id (also the `aud` of the id_token, see `console.py:821`). |
| `OPERATOR_API_OIDC_CLIENT_SECRET` | Confidential-client secret (sent to the token endpoint, `console.py:812-813`). |
| `OPERATOR_API_OIDC_REDIRECT_URI` | Console callback; must be exactly `.../api/v1/console/oidc/callback` (`console.py:600-631`). |
| `OPERATOR_API_OIDC_SCOPES` | Space-separated scopes, e.g. `openid profile`. |

### Side-by-side: Entra vs local Keycloak

| Setting | Entra (today) | Local Keycloak (target) |
| --- | --- | --- |
| `OPERATOR_API_OIDC_MODE` | `oidc` | `oidc` |
| `OPERATOR_API_OIDC_ISSUER` | `https://login.microsoftonline.com/<tenant-id>/v2.0` | `https://idp.example.com/realms/kingphisher` (public HTTPS — see §4) |
| `OPERATOR_API_OIDC_AUDIENCE` | API app registration's Application ID URI / client id | `kp-operator-api` (client scope / audience mapper) |
| `OPERATOR_API_OIDC_CLIENT_ID` | Console app registration client id | `kp-operator-console` |
| `OPERATOR_API_OIDC_CLIENT_SECRET` | Console app client secret | Keycloak confidential-client secret |
| `OPERATOR_API_OIDC_REDIRECT_URI` | `https://console.example/api/v1/console/oidc/callback` | `https://console.example/api/v1/console/oidc/callback` |
| `OPERATOR_API_OIDC_SCOPES` | `openid profile` | `openid profile` |
| Roles claim consumed | top-level `roles` (`auth.py:484-486`) | `realm_access.roles` (`auth.py:487-491`) |
| Stable principal id | `oid` (preferred) (`auth.py:471-476`) | `sub` UUID fallback (`auth.py:475-482`) |

**No app code changes** are required to switch between these two columns. The
`_claims_to_principal` function already reads either claim shape and prefers `oid` when
present, falling back to a UUID `sub` for Keycloak (`auth.py:471-502`). The presence of a
working mock RS256 OIDC provider in-repo (`infrastructure/mock-services/mock_idp.py:1-45`,
issuer `http://localhost:8443/realms/kingphisher`) confirms the non-Entra path is a
first-class, exercised design.

> Keycloak **must issue a UUID `sub`** (its default) — `_claims_to_principal` rejects a
> non-UUID principal (`auth.py:479-482`). Keycloak user ids are UUIDs, so this holds out
> of the box.

---

## 2. Keycloak setup

### 2.1 docker-compose service sketch (Keycloak + its own Postgres)

> Illustrative sketch — pin exact image digests and inject secrets from the vault, not
> literals, before any real deployment. Keycloak carries its **own** database; it does not
> share the application Postgres.

```yaml
services:
  keycloak-db:
    image: postgres:16
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${KEYCLOAK_DB_PASSWORD}   # from vault, not committed
    volumes:
      - keycloak-db-data:/var/lib/postgresql/data
    networks: [idp]

  keycloak:
    image: quay.io/keycloak/keycloak:26.0
    command: ["start", "--optimized", "--import-realm"]
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KEYCLOAK_DB_PASSWORD}
      KC_HOSTNAME: idp.example.com          # public HTTPS hostname (see §4)
      KC_HTTPS_CERTIFICATE_FILE: /certs/tls.crt
      KC_HTTPS_CERTIFICATE_KEY_FILE: /certs/tls.key
      KC_HEALTH_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded           # when behind a reverse proxy terminating TLS
    volumes:
      - ./realm-kingphisher.json:/opt/keycloak/data/import/realm-kingphisher.json:ro
      - ./certs:/certs:ro
    depends_on: [keycloak-db]
    networks: [idp]
    ports:
      - "8443:8443"                          # local-only; public exposure via §4 path (a)

volumes:
  keycloak-db-data:
networks:
  idp:
```

The default local issuer `http://localhost:8443/realms/kingphisher` (`.env.example:14`)
is the loopback development case; the egress policy permits **http only for
localhost/127.0.0.1/::1** (`auth.py:169-177`, `auth.py:229-233`). Any non-loopback
deployment must be HTTPS (§4).

### 2.2 Realm + confidential client

Create realm `kingphisher` with two OIDC clients:

- **`kp-operator-console`** — a *confidential* client (client authentication ON), standard
  authorization-code + PKCE flow, valid redirect URI exactly
  `https://console.example/api/v1/console/oidc/callback` (the API rejects anything else,
  `console.py:600-631`). Its secret becomes `OPERATOR_API_OIDC_CLIENT_SECRET`. The console
  sends this secret at the token exchange (`console.py:812-813`) and validates the
  id_token against `aud == client_id` (`console.py:821`).
- **`kp-operator-api`** — the audience the **access token** must carry
  (`OPERATOR_API_OIDC_AUDIENCE`, checked on every request in `OidcIdP.verify_claims`,
  `auth.py:446-456`). Configure an audience mapper on the console client (or a dedicated
  API client scope) so issued access tokens include `aud: kp-operator-api`.

The console browser flow that consumes this — `/oidc/start` → `/oidc/callback` →
session cookie `kp_oidc_session` — is already implemented and gated to `oidc` mode
(`console.py:717-774` start, `console.py:777-838` callback, `auth.py:513-527`
cookie/bearer resolution).

### 2.3 Role mapping (the load-bearing step)

Capabilities are derived from token role **names**, matched against the app's `Role`
enum and a small alias table. **Keycloak realm roles must be named to match.**

- App role enum (`packages/authorization/src/kp_authorization/rbac.py:20-27`):
  `source_curator`, `campaign_author`, `security_approver`, `privacy_approver`,
  `campaign_operator`, `auditor`, `administrator`.
- Aliases also accepted (`auth.py:462-468`): `operator`, `campaign-operator`,
  `campaign_operator` → `CAMPAIGN_OPERATOR`; `admin`, `administrator` → `ADMINISTRATOR`.
- Capability map per role: `rbac.py:130-176` (e.g. `CAMPAIGN_OPERATOR` →
  `schedule/send/stop/kill-switch/verify-domain/sign-roe/...`; `ADMINISTRATOR` → the full
  set).
- **Fail-closed:** any realm role that is not an exact enum value or alias is silently
  dropped and grants nothing (`auth.py:493-502`).

**Action:** in the realm, create realm roles named **exactly** `campaign_author`,
`security_approver`, `privacy_approver`, `campaign_operator`, `auditor`,
`administrator`, `source_curator`, and assign them to operator users/groups. Keycloak
emits assigned realm roles under `realm_access.roles` by default, which is exactly what
`_claims_to_principal` reads (`auth.py:487-491`). No custom mapper is needed for realm
roles; if you instead use **client** roles, add a mapper that surfaces them into
`realm_access.roles` (or top-level `roles`), because those two are the only claim paths
the verifier inspects.

The in-repo mock IdP demonstrates the exact expected principal→role fixtures
(`infrastructure/mock-services/mock_idp.py:33-40`: `campaign_author`, `security_approver`,
`privacy_approver`, `campaign_operator`, `administrator`).

---

## 3. Verification is strict in both modes (do not weaken)

`OidcIdP` performs full signature (JWKS/RS256), `iss`, `aud`, and lifetime checks and
requires `exp`/`iss`/`aud` (`auth.py:446-459`); discovery validates the returned issuer
matches (`auth.py:420-422`) and pins the JWKS endpoint origin (`auth.py:423-441`). The
console callback additionally validates `state`, PKCE `code_verifier`, and `nonce`
(`console.py:788-825`). Keep all of this — a self-hosted IdP does not relax it.

---

## 4. The SSRF / public-HTTPS caveat (important)

The OIDC egress boundary is deliberately SSRF-hardened. The issuer (and every discovered
endpoint) is validated and then DNS-pinned before use:

- HTTP is allowed **only** for `localhost`/`127.0.0.1`/`::1`; every other issuer must be
  HTTPS (`auth.py:169-177`).
- After DNS resolution, a local-http issuer must resolve to a **loopback** address, and
  **any other issuer must resolve only to public, global-unicast addresses**
  (`auth.py:229-235`), where "public" is enforced by `_is_global_unicast` requiring
  `address.is_global` (`auth.py:180-190`).

**Consequence:** a self-hosted Keycloak reached over HTTPS at an **RFC1918 private-LAN
address** (`10.x`, `172.16-31.x`, `192.168.x`) is **rejected** — the issuer resolves to a
non-global address and `resolve_oidc_endpoint` raises
`"identity provider ... must resolve only to public addresses"` (`auth.py:234-235`).
Only two clean resolution paths exist:

**(a) Expose Keycloak on a public HTTPS endpoint (RECOMMENDED).** Put Keycloak behind a
reverse proxy / DNS name (`idp.example.com`) that resolves to a public, global-unicast
address and terminates TLS. No code change; the existing SSRF hardening stays fully
intact.
- *Trade-offs:* requires a public DNS name + certificate and a hardened proxy; the IdP
  login endpoint is internet-reachable (mitigated by WAF/allowlist/geofencing at the
  proxy). This is the safe default and matches how Entra is reached today.

**(b) Small code change to allow a configured private issuer (only if (a) is impossible).**
Add an explicit, config-gated allowance for one operator-declared private issuer origin.
The narrowest change: introduce a setting (e.g. `OPERATOR_API_OIDC_PRIVATE_ISSUER=true`
plus the exact issuer origin) and, when set, permit that **single** origin's resolved
private address in `resolve_oidc_endpoint`'s address check
(`auth.py:229-235`) — mirroring the existing local-http loopback carve-out
(`auth.py:229-233`) rather than opening private ranges globally.
- *Trade-offs:* widens the SSRF trust boundary; must stay pinned to exactly one
  operator-declared origin, be off by default, and be covered by tests that prove every
  other private target is still rejected. Higher review burden than (a).

**Recommendation:** ship path **(a)**. It is config-only, preserves the SSRF invariant
that the security model depends on, and needs no change to `auth.py`. Reserve **(b)** for
a genuinely air-gapped LAN with no option to publish a public HTTPS name, and treat it as
a reviewed trust-boundary change (not a config toggle).

---

## 5. The three identity options

| Option | What it is | Code change? | Prod-grade? |
| --- | --- | --- | --- |
| **(a) dev-mode shared password** | `OPERATOR_API_OIDC_MODE=dev`; `POST /api/v1/console/session` checks a single `KP_CONSOLE_PASSWORD` and mints an HS256 token for one hard-coded identity with **blanket `administrator`** (`console.py:872-897`). | none | **No** — offline demo only |
| **(b) self-hosted Keycloak issuer** | `OPERATOR_API_OIDC_MODE=oidc` pointed at Keycloak; real multi-user, real roles, JWKS verification. | **none** (config only) | **Yes — RECOMMENDED** |
| **(c) native app user table** | Users/credentials live in the application DB itself; no external IdP at all. | **large new build** | Yes, but does not exist |

Option (a) is deliberately the fail-open/offline posture: unset recipient allowlist +
dev-auth → **allow all** (`apps/operator-api/src/kp_operator_api/send_policy.py:35`,
`.env.example:153-154`), and `single-admin` approval is only permitted in dev
(`config.py:182-186`). It is single-user, single shared password, blanket admin — **not**
production identity.

Option (b) is the recommended path and the subject of §1–§4.

### 5.1 What a native internal user DB (option c) would require

There is **no** users/credentials/accounts/principals table anywhere today — identity is
always delegated to the OIDC provider (verified: none of the 39 `__tablename__`
declarations in `packages/database/src` is an identity table; no `password_hash` in any
Alembic migration under `packages/database/alembic/versions`). Building option (c) would
require, at minimum:

1. **Schema + migration:** a `users` (and role-assignment) table with a `password_hash`
   column; a new Alembic migration and matching SQLAlchemy models in
   `packages/database/src`.
2. **Password hashing:** an Argon2id/bcrypt hashing + verification module, plus password
   policy, lockout, and rotation (some of the lockout machinery already exists as
   `LoginThrottle`, reused by the dev password path, `console.py:874-885`).
3. **Session/token issuance:** mint and verify the operator session token locally (the
   HS256 machinery exists in `DevIdP`, `auth.py:338-362`, and in
   `create_session`, `console.py:887-897`), but productionized: proper key management,
   rotation, revocation, and `sub` = the user's UUID.
4. **A third `make_idp` branch:** e.g. `mode == "internal"` returning a new `LocalIdP`
   that verifies a locally-minted token and builds a `Principal` from the DB
   (`auth.py:505-510` is the extension point).
5. **Admin UI + API:** create/disable users, assign roles (capability `manage_roles`
   already exists, `rbac.py`), reset passwords — none of which exists today.

This is materially more work than option (b) and re-implements what an off-the-shelf IdP
already provides. Recommend only if running **no** external IdP is a hard requirement.

---

## 6. Hardening note (found during review — recommend fixing alongside)

Dev-mode is **not fail-closed-gated out of managed/production deployments.** The managed
validator only *adds* requirements when **not** in dev (`config.py:187-202`); nothing
refuses `OPERATOR_API_OIDC_MODE=dev` when `config_store=managed`. So a managed deploy left
in `dev` yields **single shared-password blanket-admin with fail-open send-safety** and no
startup error. Its "dev-only" nature is enforced only *indirectly* (fail-open recipient
allowlist + `single-admin` coupling), not by an environment gate.

**Recommendation:** add a startup guard in `OperatorApiSettings` (alongside the existing
`@model_validator` at `config.py:178-202`) that **rejects `oidc_mode == "dev"` when
`config_is_managed`** (and ideally when `APP_ENV`/deployment is non-local), so dev-auth
cannot silently reach a real deployment. Small, high-value, and independent of the
Keycloak work above.

---

## 7. Acceptance (for IAM-003)

- With `OPERATOR_API_OIDC_MODE=oidc` and the issuer/audience/client envs pointed at a
  Keycloak realm, an operator completes `/oidc/start` → `/oidc/callback`, receives a
  `kp_oidc_session` cookie, and `/session` returns the mapped roles/capabilities.
- Keycloak realm roles named per `rbac.py:20-27` map to the correct capabilities via
  `realm_access.roles`; an unrecognized role grants nothing (fail-closed).
- The Keycloak issuer is reachable per §4 path (a) (public HTTPS) with SSRF hardening
  intact; unit tests still prove private/loopback rejection where expected.
- **No** change to `apps/operator-api/src/kp_operator_api/auth.py` was required for the
  swap (config-only), unless §4 path (b) is deliberately chosen.
- (Recommended, separable) managed + `oidc_mode=dev` is rejected at startup.

---

## 8. Evidence index (file:line)

- Mode selection / verifier construction: `auth.py:505-510`, `main.py:487-491`.
- Provider-neutral OIDC verify (discovery + JWKS + strict claims): `auth.py:365-459`.
- Roles from `roles` **and** `realm_access.roles`; aliases; fail-closed:
  `auth.py:462-468`, `auth.py:484-502`.
- Principal id `oid` preferred, UUID `sub` fallback: `auth.py:471-482`.
- SSRF / public-HTTPS egress policy: `auth.py:169-177`, `auth.py:180-190`,
  `auth.py:229-235`.
- OIDC env keys + defaults: `config.py:96-102`, `.env.example:13-19`.
- dev-mode password login (single blanket-admin identity): `console.py:872-897`.
- OIDC console browser flow: `console.py:600-631` (redirect validation),
  `console.py:717-774` (`/oidc/start`), `console.py:777-838` (`/oidc/callback`).
- Role enum + capability map: `packages/authorization/src/kp_authorization/rbac.py:20-27`,
  `:130-176`.
- Reference RS256 mock IdP (non-Entra path already exercised):
  `infrastructure/mock-services/mock_idp.py:1-45`.
- Dev-mode fail-open send-safety / approval coupling: `send_policy.py:35`,
  `config.py:182-186`, `.env.example:153-154`.
- Managed validator lacking a dev-mode guard: `config.py:187-202`.
