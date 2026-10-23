# Session handoff — 2026-10-23 (template asset library shipped; FLUX full chain proven)

Supersedes `docs/SESSION-HANDOFF-2026-10-09-SIMPLE-FLOW.md` for the asset-library /
real-send thread. Earlier handoffs remain valid for their own topics.

## Remediation follow-up — October 23

Controller baseline is `main @ 9566530` (#144 merged). A read-only check found
the worker still at `e80146b`, with only its preserved
`docker-compose.override.yml` untracked, supervisor active and operator/tracking
readiness both HTTP 200. The baseline difference is handoff documentation.

The follow-up patch repairs two asset-library apply defects:

- Valid uploaded rasters can exceed the 400,000-character combined HTML cap
  after base64 expansion, alone or across multiple slots. The sanitizer error
  now becomes an actionable API validation error before any template mutation,
  audit event or commit; the size limit stays enforced.
- Re-sanitization now uses the configured image-host policy, preserving allowed
  HTTPS body images while still stripping disallowed images. Sanitization and
  SafetyValidator use the same host set.

Three regression cases failed against the baseline and pass with the patch.
The focused asset/logo, route-authorization, sanitizer/raster and safety suite
passed **131 tests, zero skips**; the existing handoff-preservation contract
passed **17 tests, zero skips**. Strict mypy passed **198 source files**;
changed-file Ruff lint/format and `git diff --check` passed. Source and logs are
preserved in `.105:/tmp/kp-asset-remediation-20261023-H4BUfWy1/`
(`regression-before.log`, `regression-after.log`, `mypy.log`, `handoff-check.log`), with a controller
copy under `/private/tmp/kp-asset-remediation-mtu8qkpy/`.

The validation snapshot predates publication/deployment. Tests used an isolated
source snapshot and the worker's existing Python 3.13 environment, without changing the deployed
checkout, services, `.env`, normal databases or assets. The controller `.venv`
points to a missing Python 3.13 interpreter and was preserved unchanged.
No full-suite, exact-image, browser, cloud, real-mail or human-acceptance gate
is claimed by this follow-up. Proton confirmation and the Gmail route decision
remain pending; optional M365 provisioning was not run.

Reply ingestion already shipped in #138, with the Mailpit header-endpoint fix
in #141. The [current resume prompt](NEXT-SESSION-PROMPT.md#current-resume-prompt--october-23)
now reflects that implementation and supersedes the historical October 9 PR
stack/unimplemented-reply guidance. External mailbox qualification remains a
separate gate.

### Publication scope

The operator subsequently requested **commit, deploy and land everything**.
This includes the six remediation/resume files and the five previously
untracked files listed in the original handoff below. The QA review is retained
as dated evidence, with its assessment in `QA-REMEDIATION-PLAN-2026-10-07.md`;
its historical prescriptions do not supersede current operator instructions.
The four scripts are manual administrative tools; committing/deploying them
does not run M365 provisioning or change the live Gmail SMTP configuration.
Their Bash syntax was checked; no live M365 provisioning result is claimed.

Resolve the landed source with `git log` and the deployed source with the
worker's `git rev-parse HEAD`. Deployment receipts belong under
`data/qualification/deployments/` on `.105`; preserved isolated test logs above
remain the pre-publication evidence. Proton confirmation and the Gmail route
decision remain open independently of code publication/deployment.

## Original landed handoff

**Repo state at the original checkpoint:** `main` was deployed at **`e80146b`**, **0 open PRs**,
**0 uncommitted code**. `.105` is deployed to the same `main @ e80146b`
(verified: retire/usage routes live `401` unauth, worker on the Gmail wire
`smtp.gmail.com:587`, provider `smtp`). The only working-tree noise is five
untracked files that predate this thread — see "Untracked, deliberately left"
below.

---

## What shipped this thread: template asset library + 3 gaps

In-platform DB asset store so operators manage reusable image assets
(FLUX-generated banners, brand logos) and apply them to templates. Apply inlines
the asset bytes into the template `safe_html` as a `data:image` URI (rides the
already-validated raster path — no sanitizer-scheme change, email stays
self-contained). Vetted DRAFT→APPROVED; only APPROVED applies.

| PR | Merge | Change |
|---|---|---|
| #142 | `f6674e3` | Feature: `template_assets` table (migration `0045`, BYTEA), raster inspector (no Pillow), apply-service, routes (`/api/v1/assets` CRUD + `/approve` + `/templates/{id}/apply-asset`), operator-UI "Apply from asset library" control + dedicated **Asset library** nav view. All 3 CI gates green. |
| #143 | `e80146b` | Three gaps: (1) **distinct decorative slot** (banner+logo+decorative coexist via `_SLOT_ORDER`/`_SLOT_BLOCKS` in `asset_service.py`); (2) **retire** — `POST /api/v1/assets/{id}/retire` (approve:template) APPROVED→SUPERSEDED, no DELETE, inlined copies preserved; (3) **usage** — `GET /api/v1/assets/{id}/usage` lists templates using an asset via the new `edited_content["asset_ids"]` {slot: asset_id} map recorded at apply time (forward-looking: templates branded before this change have no `asset_ids`). Console: Superseded filter, per-row Usage view, Retire button on approved. |

Both deployed and live on `.105`. 4 assets preserved in the `.105` library
(MS365 banner `4f199744…`, DocuSign banner `c8842f1a…`, Microsoft logo
`62517e70…`, DocuSign logo `3b33679f…`).

**UI build gotcha:** `apps/operator-ui/src/console/app.js` is a GENERATED esbuild
bundle. Edit the SOURCE `apps/operator-ui/src/console-js/app.js`, then
`node scripts/build-console.mjs` (run from `apps/operator-ui/`) to regenerate the
committed bundle. Both are committed. CSP contract forbids inline `style:` in the
bundle.

---

## Real-send verification this thread (FLUX full chain)

- **(A) Mailpit full-chain proof.** Clone approved MS template `ed1bf731` → apply
  FLUX banner `4f199744` + logo `62517e70` via the NEW asset-library apply path →
  self-approve → `reviewed_direct` campaign (example.com RoE) → send. To render
  into Mailpit the worker transport was temporarily flipped from the Gmail wire to
  `127.0.0.1:1025`, then **restored byte-identical** (backup
  `.env.bak-fluxproof-20261017-142735`). Delivered message confirmed: 3×
  `data:image/png`, FLUX banner (`width:100%`) + logo (`max-height:48px`) inlined
  intact. Flip was safe — outbox had 0 pending deliver jobs.
- **(B) Real Proton send.** Same clone+apply+approve FLUX template, sent via the
  PROVEN `floridamanevolved.us` Namecheap forwarder
  (`phish-test@floridamanevolved.us` → `eldsrq@proton.me`), Gmail wire live.
  Campaign `f9644a31-6990-402d-8955-cd57e560cd10`; send HTTP 200 `queued=1`;
  deliver outbox `dispatched attempts=1 no error` ⇒ SMTP relay accepted.

Scripts (staged on `.105 ~/`): `flux_mailpit_proof.py`, `flux_proton_send.py`,
`set_env_keys.py` (secrets-safe `.env` key rewriter).

---

## Open items (next session — awaiting operator)

1. **Confirm the Proton send landed** in `eldsrq@proton.me`. Only the operator can
   see the inbox. Last comparable send (2026-10-14) landed straight to inbox, not
   spam. If confirmed, the FLUX branded → neutralized real-world delivery is proven
   end to end through the asset-library path.
2. **Gmail leg (`erik.dierks@gmail.com`) — blocked by Gmail self-dedup.** We send
   *as* `erik.dierks@gmail.com` (Gmail rewrites From to the authenticated account);
   forwarding a message back to that SAME Gmail makes Gmail drop it as a dup. To
   land in a Gmail inbox, pick ONE:
   - add a second Namecheap `.us` alias forwarding to a **different** Gmail, or
   - use a **non-Gmail sending account** for the SMTP wire.
   Operator decision pending — not actionable from here without that choice.
3. **(Optional) External M365 path.** `floridamanevolved.com` forwarders
   (`phish-test-gmail@` / `phish-test-proton@`) are NOT provisioned and that path is
   rate-limited/blocked on the trial tenant (550 5.7.233) anyway. The `.us`
   Namecheap path is the working one; only run
   `scripts/operator/provision-recipients.sh` (interactive Exchange-admin sign-in)
   if the M365 path is specifically wanted.

---

## Originally untracked, deliberately left (superseded by publication scope above)

These five files predate this thread and are not asset-library work. The
provisioning scripts contain interactive M365/Graph/Exchange admin sign-in flows;
committing them (or another session's WIP) was out of scope for "land my changes."
Operator to decide whether they belong on `main`:

- `docs/QA-REVIEW-2026-10-07.md`
- `scripts/operator/get-reply-secret.sh`
- `scripts/operator/provision-recipients.sh`
- `scripts/operator/provision-reply-mailbox.sh`
- `scripts/operator/provision-sending-mailbox.sh`

---

## `.105` access / deploy reminder

- Access: `ssh -p 2222 builder@192.168.1.105`; repo `/home/builder/phishing-awareness-platform`.
- App runs under systemd `--user` unit `kp-supervisor.service` (`scripts/supervisor.py`).
- Deploy = `git pull` → (`alembic upgrade head` only if a migration landed) →
  `touch data/run/restart` (in-process restart marker).
- Mailpit container `phishing-awareness-platform-mailpit-1` → `127.0.0.1:1025`
  (SMTP) / `127.0.0.1:8025` (HTTP API). Postgres container
  `phishing-awareness-platform-postgres-1`, DB/user `kingphisher`.
- Untracked `docker-compose.override.yml` on `.105` is local runtime config — leave it.
- Preservation rules (AGENTS.md) in full effect: never prune/reset/down the stack
  or touch other projects' containers on this shared host.
