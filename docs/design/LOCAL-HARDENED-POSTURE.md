# Local-Hardened Posture — separating hardening from hosting (PLT-002)

_Status: DRAFT design note. The **safety subset** described in §4 is implemented in this
change; the full posture/profile model in §3 is scoped as the follow-up. Nothing here
touches the safety core on the "don't break" list of
[`REVIEW-FINDINGS-2026-09.md`](./REVIEW-FINDINGS-2026-09.md)._

## 1. Problem — "managed" is conflated with "Azure"

The top cross-cutting finding of all four reviews (P0-1 in
[`REVIEW-FINDINGS-2026-09.md`](./REVIEW-FINDINGS-2026-09.md), lines 41–50) is that **how
hardened** a deployment is has no first-class axis: it is inferred from **where it is hosted**.

Concretely, two independent knobs each double as the hardening switch:

- **Operator API** — `config_store` (`env_file` | `managed`,
  `apps/operator-api/src/kp_operator_api/config.py:159`). `managed` means "Azure Container
  Apps, config from Terraform/Key Vault", but it is also the only thing that turns on ACS
  receipt-ingress hardening (`config.py:187-201`). And the two-person default is only
  demanded once you leave `oidc_mode=dev` (`config.py:182`), which is itself the "dev-auth
  blanket-admin password" posture.
- **Workers** — `runtime_mode` (`development` | `managed` | `production`,
  `apps/workers/src/kp_workers/config.py:170`). All least-privilege / real-provider
  validation hangs off `runtime_mode in {managed, production}`
  (`config.py:339-341`, `_validate_managed_role_providers` at `config.py:343`).

Because the only "fully validated" path is the Azure path, a fully-featured **and** safe
deployment cannot run locally, and the disposable DEV defaults leak: a single env flip
(`approval_policy=single-admin`, `oidc_mode=dev`, empty allowlist) collapses
separation-of-duties, enables allow-all recipients, and drops ingress checks — with nothing
refusing to start.

The unsafe defaults today:

| Knob | File:line | Current default | Why unsafe |
|---|---|---|---|
| `approval_policy` (operator) | `apps/operator-api/.../config.py:117-118` | `SINGLE_ADMIN` | one admin schedules unilaterally |
| `approval_policy` (worker) | `apps/workers/.../config.py:263-266` | `SINGLE_ADMIN` | worker delivery `unrestricted` gate keys on this (`jobs.py:1447`) |
| `oidc_mode` (operator) | `apps/operator-api/.../config.py:96` | `dev` | shared blanket-admin password |
| managed + dev-auth | `config.py:187` | **permitted** (checks only added when NOT dev) | managed posture silently runs dev-auth |

## 2. Target model — one profile, two orthogonal axes

Adopt the portability reviewer's model
([`REVIEW-FINDINGS-2026-09.md`](./REVIEW-FINDINGS-2026-09.md) lines 178–216): **separate the
hardening axis from the hosting/backend axis**, both selected by a single profile.

```
KP_PROFILE = local-dev | local-hardened | azure     # the one operator-facing knob
   ├── runtime_mode  (hardening axis)  : dev | hardened          # HOW hardened
   └── backends      (hosting axis)    : per-capability enum      # WHICH implementation
```

- **`runtime_mode` is the hardening axis** and is orthogonal to hosting. `local-hardened`
  selects `runtime_mode=hardened` with **local** backends — the missing posture.
- **Per-capability backend enums** (one per capability, not one global "managed" flag), so a
  capability can be hardened without being Azure. From the findings table (line 186-198):

  | Capability | Backends |
  |---|---|
  | identity | keycloak / entra |
  | directory | none / mock / graph |
  | reported-mailbox | mailpit / imap / m365 |
  | email | smtp / acs |
  | receipts | none / smtp / acs_eventgrid |
  | AI backend | llama / openai_compatible (Foundry, = D-0001) |
  | audit-anchor | local_worm / s3_object_lock / azure_blob |
  | secrets | env_file / managed |
  | DB / cache | local / azure |

- **Per-provider validators, not per-mode.** Replace the monolithic
  `_validate_managed_role_providers` (`apps/workers/.../config.py:343-427`) and the
  managed-gated ACS block (`apps/operator-api/.../config.py:187-201`) with one validator per
  provider enum value, invoked whenever that provider is selected — under any profile. The
  hardening axis then only decides which *strength* of provider is _permitted_ (e.g.
  `local_worm` audit-anchor is a valid hardened choice; `none` is not).

### Composition with existing tracks

- **IAM-003** (`docs/design/INTERNAL-IDP-KEYCLOAK.md`; `WAVE-BUILD-PLAN.md:526`) supplies the
  `identity=keycloak` backend needed for `local-hardened`. It already recommends "a startup
  guard rejecting `oidc_mode=dev` under managed config" — §4B implements exactly that guard.
  The remaining IAM-003 seam is the SSRF address-policy carve-out for a private (LAN) issuer
  at `apps/operator-api/.../auth.py:229-235`, which today rejects non-public issuers; a
  `local-hardened` profile needs the `local_http`/private-issuer branch there promoted from
  optional to supported.
- **D-0001** (`docs/DECISIONS.md:10`) fixes the AI-backend row: Azure uses Foundry
  Serverless (`openai_compatible`), local stays self-hosted Qwen (`llama`). The AI backend is
  a per-capability enum, not a function of `runtime_mode`.
- **Receipts abstraction:** the DB `CHECK (provider IN ('acs'))` constraints at
  `packages/database/src/kp_database/models.py:862,894,919` hard-code the ACS receipts
  backend; the `receipts` enum (§3) needs those widened before a non-ACS hardened receipts
  provider can persist.

## 3. Follow-up scope (NOT in this change)

Deliberately out of scope here to keep the diff reviewable and the safety change isolated:

1. The `KP_PROFILE` enum and its expansion into `runtime_mode` + per-capability backends.
2. The per-provider validator refactor (splitting `_validate_managed_role_providers`).
3. Least-privilege DB roles running locally (the KP-008 class; tracked as **AUD-002**).
4. The local audit-anchor provider, private-issuer OIDC allowance (IAM-003 path b), and the
   receipts `CHECK`-constraint widening.

These remain **PLT-002** follow-ups / dependencies as listed in `WAVE-BUILD-PLAN.md:552`.

## 4. Implemented safety subset (this change)

The P0 safety core — closing the "one env flip" leak — without the full enum system. Each is
flagged as a **behavior change** for the human reviewer.

**A. Default `approval_policy` → `ENFORCE`, both apps.**
`apps/operator-api/.../config.py:117-118` and `apps/workers/.../config.py:263-266` now default
to `ENFORCE` (two-person). `SINGLE_ADMIN` — and, transitively, the worker's empty-allowlist
allow-all (`jobs.py:1447`: `unrestricted = not allowlist and approval_policy is SINGLE_ADMIN`)
— now require an **explicit dev-stack marker** `KP_DEV_STACK=1` **and** the dev posture
(operator `oidc_mode=dev`; worker `runtime_mode=development`). Absent the marker, an operator
who sets `single-admin` is refused at startup rather than silently getting the unsafe policy.

**B. Managed/hardened requires real OIDC.**
New operator guard: `config_store=managed` **and** `oidc_mode=dev` now **refuses to start**
(previously `config.py:187` only *added* ACS requirements when NOT dev, so managed+dev ran
dev-auth silently). This is the `runtime_mode` (hardening) vs `config_store` (hosting) seam,
expressed for the two knobs we have today.

**C. Allow-all import requires the marker.**
`resolve_recipient_policy` (`apps/operator-api/.../send_policy.py`) previously allowed an
empty allowlist to mean allow-all whenever `oidc_mode=dev`; it now additionally requires
`KP_DEV_STACK=1`. Outside the explicitly-marked dev stack, an unset allowlist fails closed.

**D. Decouple identity mode from mail provider (the receipts seam).**
The operator's managed ACS/Event-Grid block (`config.py:187-201`) is now gated on a new
`receipts_provider` field (`none` | `acs_eventgrid`, default `acs_eventgrid` to preserve
current behavior) instead of on "managed" alone. A hardened deployment that does not use ACS
receipts (`receipts_provider=none`) no longer has to configure Event Grid. This is the
minimal instance of the per-capability `receipts` enum from §2.

### What stays allowed (regression guardrails)

- **`env_file` + `oidc_mode=dev` still starts** — the guard in §4B fires only on
  `config_store=managed`, never on `env_file`. The running `.105` stack
  (`env_file`+`dev`) is unaffected by §4B.
- The local demo path still works **with the marker**: `.env.example` now ships
  `KP_DEV_STACK=1`, so a fresh dev stack keeps `single-admin` + allow-all.
- **Reviewer action for the running `.105` stack:** its existing `.env` sets
  `OPERATOR_APPROVAL_POLICY=single-admin` (from the old `.env.example`) **without**
  `KP_DEV_STACK`. After this change that stack must either add `KP_DEV_STACK=1` to keep
  `single-admin`, or drop the `single-admin` line to run under the safe `ENFORCE` default.
  This is the one behavior change that can make a *currently-running* dev stack refuse to
  start, and is called out explicitly for the human reviewer.
