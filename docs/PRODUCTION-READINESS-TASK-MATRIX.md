# Production-readiness task matrix

Last reconciled: 2026-08-30 (ANA-010 named disposition/trend/repeat/drill-down GUI wiring complete; key rotation remains operator-gated)

This is the conflict-control ledger for work through Wave 36. Historical detail
remains in `docs/WAVE-BUILD-PLAN.md`. An item is complete only when its stated
acceptance evidence exists; implementation alone is not production evidence.

## Authoritative priority reset

New work is governed by the
[goal-aligned priority policy](WAVE-BUILD-PLAN.md#goal-aligned-priority-policy-2026-08-29),
not by older commercial-parity language or historical wave numbers. The target
is one 125-person tenant operated by two IT staff. Priority order is:

1. Decide the two-person approval, outcome, retention, provider, and internal
   model contracts.
2. Repair existing false/lossy paths: threat evidence, CSV import, confirmed
   interaction, and document tracking claims.
3. Complete one Threat Campaigns → safe AI draft → review → delivery → focused
   training → five-year result workflow.
4. Simplify Azure/mail deployment in the GUI, then qualify the exact product
   across live cloud/provider/browser/recovery gates.
5. Simplify navigation/modules only after the core behavior is stable.

Adaptive programs, new-hire/difficulty automation, LMS/course-catalog depth,
localization, gamification, advanced cohorts/causal analytics, scheduled report
delivery, extra mail connectors, Graph `Mail.Send`, autonomous APT attribution,
more services, Redis replacement, more GitHub orchestration, Foundry managed
compute, always-on GPUs, fine-tuning, and tool-using agents are `DEFERRED` or
rejected. They may not be assigned without an explicit scope change.

| ID | Outcome | Owner files | Inputs | Acceptance | Depends | Conflict group | Priority | Status |
|---|---|---|---|---|---|---|---|---|
| ORG-001 | Two-person-safe campaign approval | Authorization/campaign/domain/API/GUI/delivery | Current safe review flow | Creator cannot self-approve; one independent operator completes combined safety/privacy checklist; RoE, frozen audience, canary, provider evidence, stop, and immutable review remain | — | AUTH/CAMPAIGN | P0 | Complete locally; creator plus one independent dual-capability approver, all existing safety gates retained |
| OUT-001 | Canonical honest outcomes | Domain/database/tracking/reporting | Existing event/funnel vocabulary | Separate accepted/delivered, reported, observed open/click, confirmed interaction, training state, and no observed activity at close; deletion absent | — | DOMAIN/ANALYTICS | P0 | Complete locally through event/ledger boundary; ANA-010 reporting consumers are implemented |
| RET-005 | Minimized five-year awareness ledger | Retention/privacy/database/reporting | OUT-001; legal/privacy review | Raw evidence remains at most 365 days; pseudonymous 1,826-day projection supports protected named history and trend; notice/RBAC/export/recovery tested | OUT-001 | DB/PRIVACY/ANALYTICS | P0 | Complete locally at head `0033`: migrated retention bounds mirrored in ORM metadata (P1 closed) and named disposition/trend/repeat/per-recipient drill-down GUI wired. Key rotation/recovery remains operator-gated |
| MAIL-005 | Truthful provider support | Provider/setup UI/docs | Existing ACS, SMTP, Graph directory/report implementations | ACS recommended managed send; SMTP advanced send; Graph directory/report only; no Graph send, deletion, or “any provider” promise | — | MAILER/DOCS | P0 | Proposed decision; no code change |
| AI-005 | Internal-model-first inference architecture | Generation/worker/deployment/docs | Fixed sanitized model evaluation set | Select digest-pinned licensed model/runtime by structured output, evidence fidelity, safety/injection resistance, latency/memory/cost; deterministic fallback always works | — | AI/ARCHITECTURE | P0 | Preferred: pinned `llama.cpp` in existing worker role/job, CPU first, scale-to-zero GPU only if measured; Foundry serverless optional fallback; managed compute rejected |
| THR-001A | Repair threat evidence fidelity | Source adapters/ingestion/pattern/generation | AI-005 | Preserve excerpt, `as_of`, actor, sector, TTP, citation, confidence and freshness into bounded reviewed generation context | AI-005 | SOURCE/GENERATION | P0 | Complete locally with bounded reviewed evidence and untrusted-data treatment |
| IMP-001 | Guided GUI CSV import | Recipient API/GUI/database | Existing CSV import | Header mapping, bounded file/error handling, masked preview, dedupe, merge/deactivate choices and audited final count | CAM-001 | PEOPLE/UI/DB | P0 | Complete locally, including arbitrary header mode and serialized concurrent apply behavior |
| INT-001 | Confirmed human interaction | Tracking/training/database/reporting | OUT-001; existing event type | A deliberate training-page/question action creates a separate confirmed event; observed events remain unchanged | OUT-001 | TRACKING/DB/ANALYTICS | P0 | Complete locally at event/ledger boundary; ANA-010 consumers are implemented |
| DOCSIM-001 | Truthful safe document behavior | Template/generation/tracking/docs | OUT-001 | ICS no longer claims missing tracked URL; any later document uses non-executable tracked preview/link and never captures credentials | OUT-001 | CONTENT/TRACKING | P0 | Complete locally with recipient-bound safe tracked ICS behavior |
| THR-001B | Threat Campaigns curation screen | Source API/GUI/worker | THR-001A | Bounded daily ingest/status and source-backed review queue with citation/date/freshness/actor/TTP/sector/confidence; operator selects basis | THR-001A | SOURCE/UI/WORKER | P1 | Complete locally: bounded GUI/API, daily governed ingest, default quarantine, explicit activation, and source/provenance rechecks |
| AI-010 | Supported internal inference path | Existing worker image/durable requests/setup UI | AI-005, THR-001A | No-tool/no-network schema-constrained generation, versioned evidence, status/cost, scale-to-zero hosting, no model approval/launch authority | AI-005, THR-001A | AI/WORKER/DEPLOYMENT | P1 | Inference path BUILT 2026-08-31: apps/ai-gateway (kp-ai-gateway) implements the /propose and /setup-assist contract against the pinned Qwen2.5-7B llama.cpp model with strict json_schema decoding, gateway-injected pinned model_id (not the model's self-report), and a guaranteed training placeholder. Proven end-to-end live against Qwen on .140; output validates through the GenerationResponse contract. 7 gateway tests. Remaining: package the gateway image and run it as the pinned worker role in managed deployment |
| TRN-010 | Campaign-specific micro-training | Training/content/generation/API/GUI | THR-001B, AI-010 | Approved evidence yields one concise human-reviewed lesson/question bound to campaign; generic fallback retained | THR-001B, AI-010 | TRAINING/CONTENT | P1 | Generic governed training exists; specific content missing |
| ANA-010 | Named disposition and five-year trend UX | Database/reporting/API/GUI/export | RET-005, INT-001 | Capability-protected named status, explicit close disposition, five-year click/no-click graph, reported/training rates, basic repeat history, and per-recipient pseudonymous drill-down | RET-005, INT-001 | ANALYTICS/DB/UI | P1 | Complete locally through the per-recipient GUI drill-down (`fae8929`); key rotation/recovery remains governed follow-up |
| DEP-010 | Simplified GUI Azure/mail deployment | Deployment API/GUI/Azure discovery/recovery | AI-005, MAIL-005, existing staged workflow | Browser discovery supplies tenant/subscription/regions/DNS/groups; strong defaults; Advanced-only internals; GUI progress/retry/rollback/recovery/cost | AI-005, MAIL-005, GOV-002 | DEPLOY-UX/AZURE | P1 | Secure staged contract exists; browser sign-in discovery remains operator-required. The console can now be started for that walkthrough with `scripts/operator/dep010/start-console.sh`, which prints the exact URL, username and password |
| UX-010 | Five-area operator navigation | Operator UI/API navigation contracts | Stable Alignment Waves A–D | Home/Threats, Campaigns, People/Training, Reports, and Settings/Deployment expose the full core loop without weakening capability gates or deep links | Stable core behavior | UI | P2 | Deferred until the core workflow is stable; current 17-item navigation is too dense |
| EXT-001 | Project-only Docker engine on `.140` stores its VM and cache on `DockerExternal` | `scripts/operator/remote-docker-worker/*` | Mounted external volume; canonical remote source | External mount identity and writability checked; global Docker context unchanged; Docker socket and VM disk proven under the external root; unrelated Docker Desktop workloads unchanged | — | RUNTIME | P0 | Complete |
| EXT-002 | Preserve and cut over project state from one canonical source root | Remote qualification evidence only | EXT-001; fresh PostgreSQL and Redis checkpoint | Encrypted checkpoint verified; only project processes stopped; clean external target restored; internal project state retained stopped as rollback; Compose labels name one canonical source | EXT-001 | RUNTIME/DB | P0 | Complete; snapshot staged/restored, internal project stopped/preserved |
| SEC-030 | Remove onboarding-test SSRF and credential-exfiltration paths | `apps/operator-api/src/kp_operator_api/console.py`; focused tests | Existing pinned egress policy | Private, link-local, metadata, DNS-rebinding, stored-secret/overridden-destination and managed-mode regressions fail closed; valid bounded probes pass | — | API/SECURITY | P0 | Complete |
| REL-030 | Integrate Wave 29 recovery/release hardening | Wave 29 script and focused test files | Three completed agent reports | Focused suites, Bash syntax, ShellCheck, Ruff, mypy and diff check pass from the shared tree | — | META/RUNTIME | P0 | Complete |
| SEC-031 | Bound and bounded ACS Event Grid signing-key discovery | `apps/operator-api/src/kp_operator_api/acs_receipts.py`; focused tests | Existing authenticated ACS receipt ingress | Tenant-derived Microsoft HTTPS URL is revalidated before fetch; redirects, headers, compressed/declared bodies, JSON/JWK shape and rotation are bounded; only valid sets enter cache | — | API/SECURITY | P0 | Complete |
| REL-031 | Make GUI `.env` updates atomic, durable and recoverable | `apps/operator-api/src/kp_operator_api/console.py`; focused tests | Existing local GUI configuration routes | Whole candidate validates before mutation; concurrent processes serialize; same-directory staged replace, fsync, retained private recovery and rollback work; secrets/errors/audit remain sanitized | SEC-030 | API/RUNTIME | P0 | Complete |
| A11Y-030 | Establish a keyboard/contrast accessibility shell | Console HTML/CSS and static contract test | Existing GUI | Skip navigation, focus visibility, main landmark, reduced motion, forced colors and contrast contracts pass; no full WCAG claim | — | UI | P1 | Complete (static only). The human walkthrough is now a literal procedure at `scripts/operator/a11y030/WCAG-WALKTHROUGH.md`; it remains operator-required and makes no full WCAG claim |
| DOC-030 | Every handoff document describes the current external-worker architecture | `README.md`; `RESUME-HERE.md`; `RUNBOOK.md`; `QA_TASKS.md`; `AGENTS.md`; `docs/*.md`; `docs/architecture/README.md`; remote-worker README | Current EXT-001/EXT-002 evidence | No stale current-capacity/recovery claim; exact host/storage/context/access facts agree; historical incidents stay dated; production status remains evidence-based | — | DOCS | P0 | Complete for current post-restore state |
| UX-030 | Campaigns explicitly bind an approved training resource | API, UI, database service, tracking service, seed/grant scripts and focused tests | Production audit | Create/clone/program/review/schedule paths require and freeze a valid resource; tracking never silently selects the first UUID and revalidates exact content; legacy state is surfaced and fails closed | SEC-030 | DOMAIN/API/DB/UI | P0 | Complete |
| SAFE-030 | Two-phase launch makes a successful canary a durable prerequisite to full publication | Campaign/API/worker/UI/migration files | UX-030; provider evidence contract | Review binds RoE and immutable manifest; canary occurs before full queue; evidence binds manifest/provider/config; worker rechecks; failed/missing required canary prevents publication | UX-030 | DOMAIN/API/DB/RUNTIME/UI | P0 | Complete locally; migrated-PostgreSQL/Mailpit E2E passed at `0029`; provider-live E2E pending |
| AZ-030 | ACS/provider readiness is live, resource-bound evidence rather than operator-entered status | Deployment orchestrator, Azure workflow/scripts, Terraform and tests | Azure identity and disposable subscription/resource access | Exact ACS/domain/sender resources are queried after login; evidence is bound to subscription, resource IDs and plan digest; GUI evidence and canary receipt/inbox acknowledgement gate promotion | SAFE-030 | PROVIDER/META/UI | P0 | Three-stage workflow/GUI complete locally at frozen SHA; live gates pending |
| PRIV-036 | Privacy has a durable safe default and request work survives notice failure | Migration `0030`; privacy API/UI and focused contracts | Existing privacy tables/routes | Historical duplicate-current rows reconcile deterministically; exactly one current notice is database-enforced; default is inserted only when absent; request UI remains usable with a bounded notice warning | — | DB/API/UI | P1 | Complete locally/static; external `0030` PostgreSQL qualification pending |
| AI-036 | Existing external-gateway contract tells the truth | Managed configuration/API/UI and generation contracts | Approved AI gateway | Configured endpoint is non-local HTTPS and implements `/propose` plus `/setup-assist`; pattern approval records a durable request without claiming provider completion | — | API/UI/PROVIDER | P1 | Complete locally/static as an adapter contract; it is not the supported default deployment path and will be superseded by `AI-005`/`AI-010` rather than live-qualified as mandatory Foundry infrastructure |
| NET-036 | Managed tracking rate limits resolve the real trusted client safely | Tracking config/middleware/main; Terraform | Container Apps infrastructure subnet | Terraform supplies exact bounded trusted CIDRs plus loopback; only trusted direct peers can supply XFF; canonical hops are walked right-to-left; Uvicorn rewriting is disabled | — | SECURITY/RUNTIME | P1 | Complete locally/static; live ingress/rate-limit exercise pending |
| OBS-036 | A failed managed worker role cannot coexist with a healthy environment checkpoint | Azure workflow/Terraform outputs and focused contracts | Log Analytics and deployed worker revision | Exactly one active Healthy/Provisioned revision; every enabled role is simultaneously ready twice; same revision remains healthy at final recheck | AZ-030 | META/RUNTIME | P1 | Complete locally/static; live Azure telemetry execution pending |
| QA-030 | Final shared tree passes hermetic, PostgreSQL, Redis, browser/a11y, security and image gates | Qualification evidence; fixes get exclusive ownership per failure | Prior tasks | Zero unexpected skips/warnings; final-source images built/scanned; native ARM64 proven; native AMD64, live Azure/mail and human-browser evidence recorded separately | REL-030, SEC-030, EXT-002 | META | P0 | Partial, materially advanced: at head `63a3a20` hermetic 2707/103, lint, strict mypy 140 files, external PostgreSQL 92, Redis 2, fresh-migration 1 and E2E 8/8 pass head-exact; exact-final native **ARM64 passed at `2adb2a2`** and native **AMD64 passed at `63a3a20`** (25/25 phases, `linux/amd64` on Docker CE 29.7.2 in WSL2 on an Intel Core Ultra 9 285H, five images non-root, pinned Trivy 0.74.0). Registry publication/attestation, browser/WCAG, cloud/provider, recovery/rotation and human witness remain open |
| PROD-030 | Human/production readiness decision | Current handoff/readiness docs | All P0 gates | Production/RSA `GO` is recorded only after live cloud/provider, recovery, browser/WCAG, external witness and native release evidence pass | DOC-030, QA-030, AZ-030 | DOCS | P0 | NO-GO |

## Current ownership

- Root owns `EXT-001`, `EXT-002`, integration, live cutover decisions, and the
  shared task matrix. Conflict-controlled implementation lanes are complete and
  their results are recorded below; agent names are not durable ownership.
- Handoff reconciliation owns the documents listed by `DOC-030` for the current
  current post-restore truth. Any later context or qualification evidence
  requires another serial reconciliation.
- No concurrent lane may change a file outside its explicitly assigned set
  without root rescheduling the work.

## Validation evidence

Evidence is appended here after each integrated wave. In-progress observations
are not release claims.

- The `.140` host is Apple Silicon (`arm64`); Rosetta and binfmt are disabled
  and not required for the native ARM64 stack. Emulated AMD64 remains
  compatibility evidence only.
- `.140` Docker Desktop is a shared engine and contains active, unrelated
  `technology-procurement-dev` workloads. Its global disk image must not be
  moved, pruned, or used as the final project architecture.
- `/Volumes/DockerExternal` is a writable Journaled HFS+ USB volume with UUID
  `FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4`. Availability risk from removable USB
  storage and unavailable SMART telemetry remains an operational consideration.
- The initial external Colima profile reserves a fixed 200 GiB data disk on
  this HFS+ filesystem; this reservation is preservation-required and must not
  be deleted or recreated as a cleanup shortcut.
- Current state is post-restore: the external socket/profile and read-only
  source mount passed preflight; inactive `kp-external-mac` is created and
  reports `colima-kingphisher|aarch64|/var/lib/docker` at exact endpoint
  `ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`,
  while the default
  remains `desktop-linux`. The seven internal project containers are
  stopped/preserved on shared Docker Desktop; unrelated containers remain
  running. External mount/profile/socket drift blocks;
  there is no Docker Desktop or internal Colima fallback, and the global
  context remains `desktop-linux`.
- The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit
  the reviewed socket and can select shared Docker Desktop; never use them for
  project operations. The external volume named `DockerExternal` is the
  required storage target, not a Docker context.
- The canonical remote source is
  `/Users/edierks/Projects/kingphisher-phoenix`; its target VM mount is
  read-only. The smaller controller/staging paths are not canonical remote
  Compose sources.
- The legacy encrypted snapshot is preserved but unrecoverable because its age
  identity is absent; it does not satisfy `EXT-002`. The controller recovery
  identity is verified at public recipient
  `age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
  `checkpoint-remote.sh` temporarily transfers that identity because the remote
  login Keychain is unavailable over headless SSH. A resulting archive must
  pass controller `stage-remote.sh`, remote `stage-checkpoint.sh`, and
  no-clobber publication to
  `migration-checkpoint/` before external-engine-scoped `restore-state.sh`.
  Snapshot `20260829T013332Z-tsX1WQ`, archive SHA-256
  `e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`,
  passed staging and restore. PostgreSQL restored 39 tables; Redis DB0 preserved
  766 keys and DB15 preserved 12. External installation and
  `verify_install.sh` passed. Final external preflight re-proved the exact
  engine/volume identity with approximately 744,006,440 KiB free.
- The installer timeout repair is integrated locally: default 900 seconds,
  maximum 3600, strict validation, and 42 tests green. The fix is synced and
  remote `--check-uv` passed; no cold full rerun under the new default is
  claimed.
- The pre-remediation local/external snapshot reached head `0029`: hermetic
  2,329/97 deselected; PostgreSQL 86/2,340 on Redis DB14; Redis 2/2,424 on DB15;
  audit/install verification; and 8 E2Es. Its 03Z log window was clean. The
  pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with 0
  failures in 158.15 seconds. At checked-in head
  `0030_default_privacy_notice`, the final local Wave 36 hermetic suite passed
  2,501/97 with 0 failures in 183.40 seconds. PostgreSQL, Redis, and E2E external
  reruns at `0030` and exact-image evidence remain pending. Ruff/format covered
  336 Python files, strict mypy 124 source files,
  Bandit, Semgrep (4 rules/125 targets/0 findings), Trivy repository
  checks (0 HIGH/CRITICAL vulnerabilities, secrets, or misconfigurations),
  pip-audit with no known vulnerabilities, Actionlint, and Zizmor are green
  scopes. `QA-030` remains open for live cloud/provider, real-browser/WCAG and
  human assistive-technology, exact-final images/native AMD64/registry
  attestation, and rollback evidence.
- Exact-final ARM64 status is evidence-conditional. A pass requires retained
  no-clobber `qualification.json` and scan evidence for the exact non-emulated
  Docker server platform, explicit `--platform`, all-five OS/architecture/image-ID
  metadata, unchanged source/context manifests, Trivy 0.74.0, and verified
  labeled-disposable cleanup. It also requires the expected source-manifest
  digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files, ambient-`TRIVY_*` rejection, fresh
  database/check-bundle metadata, and an immutable verified cache. Azure workloads scan exact immutable ACR
  `repository@sha256` images with pinned Trivy before SBOM/attestation/deploy and
  retain scan JSON/checksums. Implementation of these gates is not a pass.
  The preserved `final-v2` attempt failed closed before image build on BSD
  filesystem-mode and evidence-path/source-context defects; its evidence was
  retained. Repaired `final-v3` then PASSED on 2026-08-30 (status `passed`,
  exit 0, 25 phases, five images built/scanned/run on native `linux/arm64`) —
  but **only for source `d0f03e9`**, the isolated `.140` worktree
  `gate-worktree-final-v3`, whose manifest is byte-identical to controller
  `d0f03e9`. It is **stale at HEAD**: `fae8929` changed
  `apps/operator-ui/src/console/app.js`, which `Dockerfile.operator-api:17`
  copies into the operator-api image, so HEAD's source-manifest digest is
  `sha256:f40741ed…` versus the bound `sha256:3dfa1dc9…` and the verifier's
  `expected_source_manifest` phase would have failed closed. **That gap is now
  closed:** the gate was re-run at head `2adb2a2` on 2026-08-30 and PASSED —
  status `passed`, exit 0, 25/25 phases, native `linux/arm64`, source bound
  `sha256:62e768ed…` over 487 files, five images non-root `65532:65532`, Trivy
  0.74.0 cache unchanged, volume inventory unchanged, evidence root
  `qualification-evidence/arm64-release-20260830-head-2adb2a2/verifier`. The new
  operator-api image was confirmed to carry HEAD's console bundle
  (`543bd007…`, 61 ledger refs) where final-v3's carried `886bc1df…` (50).
  `QA-030`'s exact-final ARM64 element is therefore PASSED at `2adb2a2`;
  final-v3 remains valid only for `d0f03e9` and is superseded, not deleted.
  Because `docs/` and `RESUME-HERE.md` are inside the release build context,
  any later documentation commit re-stales this gate.
  Separately, `/Users/edierks/Projects/kingphisher-phoenix` on `.140` is 37
  commits behind at `1403d94` and contains none of the post-`1403d94` work; it
  was never the build source and must not be mistaken for one.
- Provider-aware SMTP/ACS and Mailpit/Microsoft 365 selects now enforce active
  field, probe, AI-context, and atomic credential-rebinding boundaries. Privacy
  export is POST-only with no-store/list and same-origin CSRF protections. OIDC
  uses issuer-origin-bound, DNS-pinned TLS transport without redirects/proxy
  inheritance/HTTP2. Migration `0030` supplies the safe default/single-current
  privacy invariant, and notice failure no longer disables request work.
  Managed AI requires its approved HTTPS contract and pattern approval records
  only a durable request. These remain focused/static changes, not live proof.
- PostgreSQL integration jobs now use Redis DB14 and flush only DB14 before and
  after that profile. The Redis queue contract remains on DB15. Neither profile
  may flush or repurpose application DB0. This prevents transactional-outbox
  rows created against a disposable PostgreSQL test database from leaking into
  the live application workers' queue.
- A mixed-source Compose-label drift was found on the rollback engine. Even
  the non-deleting sync established the canonical source while excluding
  secrets, data, `.git`, evidence, and environment state.
- `SEC-030`: 99 operator-console/security/managed-configuration tests passed;
  Ruff, formatting, strict mypy, and diff checks passed. Probes now use one
  vetted pinned address, preserve Host/SNI, reject unsafe address classes and
  mixed DNS answers, separate stored secrets from changed destinations, and
  refuse env-file probing in managed mode.
- `REL-030`: the combined Azure-operator, recovery-preflight, launcher,
  release-packaging, supervisor-log, and external-worker suites completed with
  only one declared environment-only skip. Bash syntax and ShellCheck passed
  for the integrated shell paths.
- `SEC-031`: the bounded JWKS and ACS receipt suites passed as part of a
  147-test integrated console/security/receipt/accessibility lane. The fetcher
  rejects redirection and excessive headers/bodies before caching, preserves a
  last-known-good set through invalid rotation, and accepts real RSA rotation.
- `REL-031`: the same integrated lane covered atomic configuration tests plus
  the SSRF and managed-configuration regressions; Ruff, formatting, JavaScript
  syntax, and diff checks passed.
- `A11Y-030`: nine focused static shell contracts passed. This does not replace
  a real-browser, assistive-technology, or WCAG acceptance gate.
- `UX-030`: explicit lesson-binding, tracking, Azure-grant, seed-order,
  campaign-program and route lanes passed 68 tests with four declared
  PostgreSQL-only tests skipped in the hermetic run. Ruff, formatting, and
  strict mypy passed. Alembic advanced linearly through
  `0028_campaign_training_binding`, `0029_campaign_canary_gate`, and checked-in
  `0030_default_privacy_notice`. The last complete external profile remains at
  exact `0029`; live base/historical-to-`0030` qualification remains required
  before release.
- `SAFE-030`: focused canary migration, database, API, worker, action-flag, and
  UI-contract lanes pass, with Ruff, strict mypy, and JavaScript syntax clean.
  The seed and loopback lifecycle no longer use the retired direct preparation
  shortcut: both bind durable launch reviews and the canary worker evidence.
  PostgreSQL-marked and provider-live cases remain assigned to external
  qualification rather than being counted as local passes.
- `AZ-030`: 96 ACS workflow/readiness/initiation tests passed with one declared
  environment-only skip; Ruff, formatting, Actionlint, and Zizmor are clean.
  The workflow now applies the complete `deploy_workloads=false` foundation,
  including ACR/private-network/data and ACS/DNS resources, without Terraform targets.
  It refuses delete/replacement and sender/association changes while
  initiating exactly Domain/SPF/DKIM/DKIM2 verification from authenticated,
  bounded foundation evidence. No live Azure mutation or DNS propagation is
  claimed. The exact `foundation_bootstrap`,
  `foundation_finalize`, and `workloads` stage/artifact/GUI contract is now
  integrated and pinned to workflow SHA-256
  `314193e7a0afc01661ce7d927010b50b8a48e6ac5ed0b1892e75d98bace4f028`;
  its live GitHub/Azure/provider evidence remains open.
- `PRIV-036`, `AI-036`, `NET-036`, and `OBS-036` are integrated as
  implemented/static contracts only. They add the persisted privacy default and
  UI degradation boundary, managed AI endpoint/durable-request truthfulness,
  exact ACS export/preflight parity, trusted-proxy/XFF enforcement, and the
  current-revision two-observation worker-role health gate. The final local Wave
  36 hermetic suite passed 2,501/97 with 0 failures; exact images, Azure telemetry,
  ingress, AI-provider, and other external execution remain unclaimed.

- The 2026-08-29 live read-only GitHub evidence proves valid `ELDSRQ` authentication with
  `repo`/`workflow` scopes; public, enabled `ELDSRQ/kingphisher-phoenix` with
  default `main`; Actions enabled; and the Azure workflow active, with no
  billing-disabled run signal. It also proves zero environments, variables,
  secrets, rulesets, and workflow runs, unprotected `main`, disabled secret
  scanning and push protection, and remote `main` at old-tree SHA
  `1403d944a40214714b6cbfcf5cbabc4fa7225eb9` at re-audit time (the checkpoint
  push has since advanced it to `c9ea716`). No workflow dispatch/run occurred.
  The 2026-08-29 read-only GitHub boundary facts remain recorded in the
  handoff documents so the re-audit observation is not lost when the tree
  advances.
  The 2026-08-29 sandbox could not resolve `management.azure.com`, so the
  historical Azure inventory does not establish current management-plane state.
  Protected configuration, repository hardening, current Azure inspection, and
  reviewed final-source sync remain `AZ-030` blockers.
