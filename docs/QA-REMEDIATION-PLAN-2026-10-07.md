# QA validity review and remediation plan — 2026-10-07

The review below assesses source `ad997f9`. Subsequent implementation and
validation are recorded in [Implementation — 2026-10-07](#implementation--2026-10-07).

**Current operator direction (October 8):** console-password rotation waits
until the user signs off on this build as fully completed and human ready.
Earlier pre-D6 rotation sequencing below is superseded. Do not rotate before
that sign-off or treat rotation as a blocker to the human trial.

Reviewed source: `ad997f9f64368d3c7ccb9bb7ae8e127b08e52b83`. The source review is the user-provided `docs/QA-REVIEW-2026-10-07.md`, retained unchanged. Scope: bounded static inspection of relevant code, tests, CI and dated operational evidence, plus inert Python/SQLAlchemy demonstrations. No full suite, SSH probes, campaign actions, storage access, process signals, deployments or source changes were performed.

The assessment identifies useful work, but its executable plan should not be adopted verbatim. Select the worker-status fix, bounded credential hygiene, bootstrap correctness repair, current-document cleanup and evidence reporting. Keep the previously accepted key-file and flake investigations as bounded follow-ups. Do not turn all of UX Wave 2 into a prerequisite for the pending D6 human run. Several blanket evidence statements and the review's replacement route count are demonstrably wrong.

Priority meanings: P1 = next practical fix, P2 = bounded follow-up, P3 = optional polish. P0-release denotes a release gate, not proof of an urgent code defect. No new critical code defect was demonstrated.

## Findings and evidence

| Finding | Verdict / revised priority | Verified evidence and practical interpretation |
|---|---|---|
| N-01: two worker roles missing from console status | **Valid, P1.** Highest-impact new code fix. | `apps/operator-api/src/kp_operator_api/console/runtime_status.py:86` probes eight roles; `scripts/supervisor.py:31` defines ten, including curation at line 42 and audit-anchor at line 46. `apps/operator-ui/src/console-js/app.js:2650` renders returned worker keys dynamically. Missing roles are consequently invisible in the UI. This is process-presence observability, not proof of correct work: `_process_alive` at `runtime_status.py:124` uses PID plus `os.kill(pid, 0)`, not a worker heartbeat or audit freshness. The review's live process/API observation was not independently repeated. Managed deployments intentionally return an empty worker map (`runtime_status.py:60`). |
| N-02: selected BYO key plaintext in runtime JSON | **Valid existing declared debt, P2 conditional.** Keep the accepted deferral unless deployment needs an authenticated hosted provider or the operator selects this work. | `console/ai_providers.py:226` reads decrypted key and line 259 serializes it. `_write_state_file` at line 72 writes JSON using a 0600 temporary file. `apps/operator-api/tests/test_ai_providers.py:186` explicitly asserts the plaintext synthetic key. `docs/SESSION-HANDOFF-2026-10-06.md:43` records conscious deferral and KEK blast-radius tradeoff; `docs/ONPREM-GO-RUNBOOK.md:131` already warns that backups of runtime data are secret. Custom self-hosted selection without a key is supported and tested (`test_ai_providers.py:260`). No live provider key was read in this review; do not imply the active HALO endpoint contains a secret key. |
| N-03: documentation/count drift | **Partly valid, P2.** Correct current claims, preserve dated evidence. | Present-tense 113-route claims remain at `README.md:159`, `docs/architecture/README.md:200`, `docs/AI_HANDOFF.md:379`, `docs/REMEDIATION_PLAN.md:59` and other handoffs. However, the proposed replacement **143 = 132 + 11 is wrong**. Independent AST inspection finds **143 capability-protected method/path keys plus 11 dedicated/public keys, zero overlap, 154 total**. Manifest definitions start at `apps/operator-api/tests/test_route_authorization_inventory.py:30` and line 288; the actual app inventory is enforced against their union at line 356. `README.md:60` already labels the current state as dated, head 0042, ten roles and approximately 3,500 tests. A dated October 5 review saying 3,506 tests is historical evidence, not a defect because a later run has more tests. Root handoff moves and a new counts test framework are unnecessary to fix misleading current entrypoints; do not rewrite historical counts. |
| N-04: deployment password in tracked public docs | **Valid credential hygiene, P1, constrained exposure.** Separate doc change from coordinated operational rotation. | Credential literal locations: `docs/SESSION-HANDOFF-2026-10-04.md:25` and `docs/SESSION-HANDOFF-2026-10-06.md:106` (values deliberately not reproduced). A read-only GitHub API query verified repository `private:false`, visibility `public`. The supplied handoff/user context identifies the password as the deployed one; this independent review did not test it. Password login produces administrator authority (`apps/operator-api/src/kp_operator_api/console/__init__.py:448`) and reads the local `.env` (`console/env_store.py:517`). LAN topology is lower-risk operational information and is not a credential. No public Internet reachability, credential reuse or compromise was demonstrated. Local-only/tunneled access limits attack opportunity; do not claim LAN users can access loopback-only services without a path, or dismiss a published password because the IP is private. Current recipient PII and disposable-data assertions were not verified. |
| N-05: tool-dependent hermetic deselections lack reasons | **Valid narrow evidence-reporting gap, P2.** No evidence of the required CI drift guard being absent. | `scripts/run-hermetic-tests.sh:25` deselects macOS contracts off Darwin; lines 32–34 deselect absent zsh/node/esbuild gates; line 66 invokes pytest without a tool/reason summary. `.github/workflows/ci.yml:48` deliberately installs Node and esbuild before `make test`, so claiming a current missing CI bundle guard is incorrect. OS-dependent `macos_only` exclusions remain normal on Linux CI: Q-07's acceptance that CI prints no exclusions is wrong. Hermetic/profile exclusions are intentional; show them distinctly from missing-tool exclusions. |
| N-06: bootstrap SQL and URL construction | **Valid, P2, more than a quoting issue.** A useful small operational correctness repair. | `scripts/bootstrap_local_parity.py:64` interpolates password into CREATE/ALTER ROLE SQL at lines 72–78. Loopback/database restriction at line 56 and static `RUNTIME_ROLES` bound the exposure: this is an operator-controlled dev bootstrap, not a remotely reachable injection endpoint. More significantly, `_probe_runtime_privileges` at line 231 inserts a new `@` but leaves the original password and `@host` suffix, corrupting an ordinary URL. In an inert SQLAlchemy parser demonstration with synthetic `old_example` / `new_example`, the parsed host becomes `old_example@127.0.0.1`. URL `.set(username=..., password=...)` retains the correct `127.0.0.1` host. The review's `_replace(password=...)` suggestion is not the SQLAlchemy URL API and also fails to change username. Use URL `.set` and the existing SQLAlchemy/psycopg execution boundary deliberately. |
| N-07: broad source enum versus creatable source types | **Valid vocabulary asymmetry, P3, optional.** No mission-blocking feature defect established. | `packages/domain-models/src/kp_domain_models/models.py:41` includes advisory/curated, while `apps/operator-api/src/kp_operator_api/routes/sources.py:203` rejects these for POST creation. A storage/domain enum may legitimately be broader than a creation API. The worker accepts them as RSS-shaped sources (`apps/workers/src/kp_workers/jobs.py:2447`). Do not split the domain enum without a concrete need, remove persisted values, or enable types without implementation/governance. The proposed message "created automatically by threat curation" is unsupported: `packages/curation/src/kp_curation/curation_service.py:50` creates a DRAFT `TemplateVersion` at line 87, not a Source row. Minimal truthful wording is "source type is not supported by this creation endpoint" with accepted values. The review's executive section incorrectly cites N-07 for the public credential issue; correct identifier is N-04. |

## Prescriptions requiring correction

**Q-01 shared role constant / worker-kill acceptance.** Importing `kp_workers.roles` into operator-api would introduce a reverse application dependency. Neither app's declared dependencies contains the other (`apps/operator-api/pyproject.toml:6`, `apps/workers/pyproject.toml:6`), and `apps/workers/tests/test_package_boundary.py:1` explains that shared logic belongs in packages. Prefer adding the two missing names to a named local tuple with a daemon-free contract against the AST of the supervisor's CHILDREN map. If shared runtime configuration is eventually required, place it in an existing low-level package both apps already depend on; it does not require a new framework. Replace "killing worker-curation" acceptance with missing/invalid PID fixtures and stubbed liveness for both new roles, plus an optional read-only deployed status check. No automatic process kill is authorized; `AGENTS.md:5` requires preservation and the handoff at line 132 explicitly forbids auto-killing agent shells. Healthy PID rows are not successful audit-witness evidence.

**Q-02 public-topology scrub / credential store.** A docs-only change cannot rotate a running deployment, so the assessment's self-review at line 548 calling Q-02 content-only is wrong. Redact actual deployment credential literals and coordinate a separate operator rotation before D6 credentials are handed to the driver. Preserve operational topology, exact socket guards, rollback facts and usable runbooks unless the user requests a private-ops migration; scrubbing AGENTS/RUNBOOK topology can damage fail-closed targeting. Do not invent a `.105` "keychain / data secret store": the verified implementation reads the password from `.env`; cite the existing protected operator retrieval/runbook without printing its value. A blanket ban on any `KP_CONSOLE_PASSWORD=<value>` would flag harmless fake test fixtures, examples and recovery instructions. Scope a guard to deployment docs/known exposed values, with inert examples permitted, and never put a currently valid replacement secret in its tests or logs. Rotate the credential rather than rely on removal from the latest tree: older Git commits remain public. Rewriting public Git history/force-pushing is not authorized, not necessary for initial containment, and would disrupt preserved evidence and other workstreams. Password rotation does not itself revoke previously minted JWTs (`console/__init__.py:448`); if incident response is needed, operator must decide session-signing rotation separately. No compromise is evidenced here.

**Q-03 precision / historical documents.** Use a bounded current summary or link to the enforced manifest instead of replacing one drifting magic number with another. Report 154 total only with source binding and counting definition (method/path keys excluding HEAD/OPTIONS). Historical test counts, migration heads and qualification results remain dated evidence. Root handoff archiving is optional organization, not a pre-D6 correctness requirement. A migration-head documentation contract must inspect migration files without opening an operational database; running `alembic heads` from ambient live configuration adds avoidable coupling.

**Q-04 secret lifecycle.** Local selection already clears the file (`ai_providers.py:250`; tested at `test_ai_providers.py:232`). Unlink-on-shutdown is actively unsafe: gateway `_active_provider` interprets absent file as local selection (`apps/ai-gateway/src/kp_ai_gateway/main.py:525`, tested at `test_gateway.py:1289`). Restart must preserve selected routing and model identity; selected-but-unavailable state must return 503 without any upstream call. Key fetch requires authentication/authorization; loopback alone is not a process identity. Giving the gateway the application KEK expands authority and does not protect backups if the KEK accompanies them. This needs an explicit narrow design choice, not both architectures.

Design acceptance must include concurrent selections, interrupted write/decrypt/fetch, request in flight during selection, restart, DB/file consistency and local switch. The fixed `.json.tmp` filename (`ai_providers.py:76`) and DB commit before file/environment side effects (line 244) make these necessary boundaries. They were inspected, not reproduced as new failures here. Current tests prove DB commit failure does not publish a file; they do **not** prove DB-selected provider and runtime file always match after a crash. Keep the claimed R-05 regression scope honest. Do not delete preserved runtime files as a diagnostic action; intentional local-provider switching is an application lifecycle operation, not storage cleanup.

**Q-06 root cause.** Diagnostic assertions are implemented at `tests/test_azure_idle_contract.py:640`. They mention early exit under load as an example, not an established cause. The subprocess harness is shim-based (`test_azure_idle_contract.py:289`), and `azure-idle.sh` uses `set -euo pipefail` at line 49. No trace identifying the failing branch was supplied by this review; one green broad run proves neither root cause nor flake rate. First reproduce the focused shim test under bounded controlled load with return code/stdout/stderr/calls retained. Inspect the recorded branch before changing azure-idle.sh. Reject ten consecutive full-suite runs as the default acceptance: costly and weak evidence without a known reproducer; use focused repeatability plus normal relevant CI. Do not remove guard checks or add arbitrary sleeps/retries to conceal failures. Script uses a fixed plan file at line 69; any parallel harness experiment needs isolated plan/work paths so test repetitions do not interfere with one another or preserved deployment plans.

**Q-08 behavioral smoke.** Relevant P1 follow-up. Playwright suites already exist (`apps/operator-ui/package.json:9`, `apps/operator-ui/tests/e2e/console-nav.smoke.spec.mjs` and `playwright.config.mjs`); `Makefile:74` explicitly excludes real-console browser tests from ordinary CI. Add a small isolated authentication/readiness/one benign workflow smoke rather than duplicating the full live acceptance suite. Existing `docker-compose.e2e.yml:5-31` provisions PostgreSQL only, with a fixed `kp-e2e-postgres` container name, persistent `kp_e2e_postgres_data` volume and environment-supplied credentials; it is not a complete isolated browser/API fixture. The Playwright config starts no web server. Provision the missing test-only services and browser lifecycle explicitly, using separate CI names and synthetic credentials. Preserve the existing E2E container/volume; do not assume they are disposable or recreate them. Retain failure artifacts. This supplements D3/D6; it cannot replace a human.

**Q-09–Q-12 UX.** Keep as findings to validate during D6, then choose changes demonstrated by observed hesitation or a blocked task. The October 6 handoff at line 47 explicitly deferred UX; making all four tasks prerequisites at QA review line 526 silently changes that decision and postpones useful human evidence. Preserve two separate canary/publication operations, server-designated test cohort and current evidence-bound gates (`AGENTS.md:64` onward). "Send to everyone" is too broad: publication is to the frozen authorized audience. Identity labels must use the entity-specific label, not route campaign/source/privacy IDs through recipientLabel. Do not assume queue remediation strings have been browser-validated.

## Evidence scope corrections

| Evidence area | What is already recorded or verified | What remains distinct |
|---|---|---|
| Current source hermetic / lint / types | Read-only GitHub metadata verified successful exact-head CI for `ad997f9`: [hermetic job](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37486456258/job/112347607698). The QA review separately reports its own 3,515/111 run; its raw log was not independently read. | Do not sum runs or treat equal counts across different host profiles as equivalence. This independent review did not rerun suites. |
| PostgreSQL / Redis / fresh migration | Read-only GitHub metadata verified successful [exact-head integration job](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37486456258/job/112347608184). `.github/workflows/ci.yml:67` provisions fresh services, prepares roles and migrates schema at line 120, then runs both gates at lines 127/129. The postgres gate also selects `packages/database/tests/test_migrations_fresh_install.py:109`, the fresh base-to-head upgrade test marked postgres at line 107. | QA line 391 legitimately says it did not run them, but line 393's claim that latest recorded profiles predate the feature cycle is stale. Q-13 current-source postgres/redis/fresh-chain is CI-backed, not a new prerequisite to rerun by default. Deployed-topology/full E2E evidence remains separately scoped. Workflow currently uses ubuntu-latest at line 69; ONPREM runbook's phrase "self-hosted .105 runner" is stale. |
| Native AMD64 / exact release images | `docs/ONPREM-GO-RUNBOOK.md:20` records `.105` linux/amd64 image qualification on 2026-09-27 with evidence directory; `docs/PRODUCTION-READINESS-TASK-MATRIX.md:65` also records older native AMD64 at source `63a3a20`. | These are historical source-bound results, not current ad997f9 final-image/registry attestations. QA's blanket "no native AMD64 evidence" is wrong; current release requalification can remain open. |
| Browser / accessibility | `docs/ONPREM-GO-RUNBOOK.md:21` records live 9/9-view axe pass with no skips/violations, 2026-09-30. | This review did not run a browser. Manual keyboard/screen-reader D3 at line 22 and non-builder D6 at line 24 remain human gates. The older automated pass is not current human acceptance or proof of every workflow. |
| Recovery | `docs/ONPREM-GO-RUNBOOK.md:23` records `.105` backup/restore to disposable DB, schema 0040, data intact in 3 seconds. | QA line 279's "retired topology only" is false. A PostgreSQL drill does not prove all audit/files/Redis/DR/rotation/rollback at head0042. Runbook line 83 describes wider recovery scope. Inventory what needs refreshing before commissioning another drill; never restore over live volumes. The reported hung `/mnt/wsl/uat-data` device blocks storage access and may require a separate operator decision if chosen recovery targets depend on it. |
| Cloud/provider | Historical staging evidence exists (`docs/STANDALONE-READINESS.md:49` records four running Azure apps; line 103 records earlier single-operator lifecycle). | Does not qualify current Graph/ACS receipts/Entra/DNS/registry or new code. Preserve Azure gating in the October 6 handoff at line 114; no billable redeployment is authorized by this review request. Production/RSA remains NO-GO. |

## Minimal PR-sized remediation plan

1. **P1 — Worker status coverage (Q-01 revised).** Write set: `apps/operator-api/src/kp_operator_api/console/runtime_status.py`, `apps/operator-api/tests/test_console.py`; only if friendly labels are desired, `apps/operator-ui/src/console-js/app.js`, its built `src/console/app.js` and the existing relevant UI contract. Add two roles, derive expected worker names in a daemon-free AST contract from `scripts/supervisor.py`, keep managed response empty. Acceptance: exact ten-key local payload, both new rows reflect stubbed missing/alive PID outcomes, invalid PID safely false, managed behavior preserved. Run focused console/runtime tests, relevant boundary/bundle checks if touched, ordinary CI. Prerequisite to deployment: finished D6 run or a coordinated quiet window; do not restart in the middle of acceptance.

2. **P1 — Deployment-credential documentation hygiene (Q-02 narrowed), independent from 1.** Write set: affected handoff docs and the existing security/credential guidance; add a narrowly scoped doc scan only if it prevents the actual recurrence without banned fake fixtures. Remove actual deployed password literals, refer to established protected retrieval, state rotation/session considerations without secrets. Separate operator task: rotate the deployed console credential and privately hand it to the D6 driver; old login fails/new login succeeds, and record time/target without values. No topology scrub, history rewriting or fictional store. An actual rotation is outside this assessment's authorized actions and requires coordination with active sessions; the docs PR itself is reversible. Retain historical evidence except credential text.

3. **P2 — Local parity bootstrap correctness (Q-05 strengthened).** Write set: `scripts/bootstrap_local_parity.py`, focused bootstrap contract tests. Correct CREATE/ALTER ROLE password quoting using the actual psycopg connection/SQL-composition boundary or a documented safe-input restriction before any writes; build verification URL using `.set(username=role_name, password=password)` on parsed SQLAlchemy URL. Acceptance: ordinary password, quote/at/colon password handling, unchanged host/port/database/options, non-default existing username, supported loopback constraints; inert tests inspect composition and parser results without touching an application DB. Any optional live bootstrap follow-up must use an isolated disposable PostgreSQL instance with synthetic data: this script restricts the database name to `kingphisher`, so it cannot simply target a differently named database. Never run this repair against the deployed app database.

4. **P2 — Current docs and evidence scope (Q-03/Q-13–15 narrowed).** Write set: README current summary and misleading current architecture/plan sections plus one current evidence/plan document. Prefer an enforced-manifest reference; if numerical, 154 method/path keys at reviewed SHA. Mark historical sections with date/source rather than updating their facts. Record exact-head CI postgres/redis/fresh-chain as satisfied for source, dated D2/D3/D5 evidence with its limits, D3-manual and D6 pending, Azure gated. No root-file move needed. Acceptance: dated source-bound evidence links are usable, present-tense claims do not contradict them, no gate promoted beyond scope. Lightweight fact check/diff review suffices; no new counting framework or suite rerun for prose.

5. **P2 — Hermetic exclusion summary (Q-07 revised).** Write set: `scripts/run-hermetic-tests.sh`, focused shim contract tests; CI only if an explicit missing-tool refusal is added for tools already provisioned. Print selected profile, OS exclusions and absent-tool exclusions before exec. Acceptance on synthetic PATHs: reasons name zsh/node/esbuild; Linux reports macOS exclusion; CI with tools reports those gates included and still names deliberate integration exclusions. Do not require every host to run macOS tests or change no-skips semantics. Test the actual script control flow with fake tools; retain normal suite CI.

6. **P1 follow-up — Existing-console CI smoke (Q-08).** Write set: existing Playwright smoke/config, Makefile target and `.github/workflows/ci.yml` (plus dedicated test-only service config only if necessary). Prerequisite: isolated fixtures/credential and browser runner; no production connection. Acceptance: source-served UI login→status/readiness→one reversible test-fixture action verifies DOM and API outcome; failure screenshots retained; no real recipients/provider delivery; all safety/authorization checks remain. D6 remains a human task and should proceed while this small harness work is scheduled.

7. **Deferred P2 — Key-state protection (Q-04) and flake diagnosis (Q-06), two separate decisions/PRs.** Key work write set: operator provider seam, gateway reader/config, existing provider/gateway tests and backup guidance; prerequisite: agreed threat model and narrow authenticated secret handoff or independent encryption-key scope. Include crash/concurrency/restart/fail-closed acceptance above, existing provider preset behavior and secret-free logs/backups. No unlink-on-shutdown. Flake work write set initially only the targeted test/harness and diagnostic evidence; touch azure-idle.sh only after a reproduced branch supports a fix. Bounded focused repetition replaces ten full-suite runs.

8. **P3 — Source vocabulary and observed UX polish.** Write set for enum wording only: domain SourceType docstring or source-create validation text plus focused API test. No enum split or invented automation promise. UX write sets: source console JS/bundle and appropriate existing behavioral checks, one observed problem per PR. Prerequisite: D6/D3 observations unless an independently reproduced blocking defect emerges. Do not weaken launch or stop governance to simplify labels.

## Task ownership and execution order

The numbered tasks above map to stable IDs below. All are **planned**, not implemented. Listed files are prospective implementation ownership; this review edited none of them.

| ID | Priority / outcome | Owner files or components | Input / acceptance | Depends | Conflict group |
|---|---|---|---|---|---|
| V-01 | P1: ten-role local status | runtime_status.py; test_console.py; optional console JS/bundle | Supervisor roster; exact local keys, false missing-PID rows, unchanged managed response | None | API / UI if labels touched |
| V-02 | P1: redact deployment credentials | Affected handoffs and credential guidance | Exposed-doc inventory; no active credential literals, usable protected retrieval reference | None; rotation coordinated separately | DOCS |
| V-03 | P2: correct bootstrap SQL/URLs | bootstrap_local_parity.py; focused bootstrap tests | Synthetic SQL/URL inputs; ordinary and special passwords handled, URL target preserved | None | RUNTIME |
| V-04 | P2: correct current claims/evidence | Current README/architecture/plan sections | Manifest and exact-head CI; dated scoped claims, historical results retained | Integrate V-02 first if same docs | DOCS |
| V-05 | P2: explain hermetic exclusions | run-hermetic-tests.sh; focused harness tests | Fake tool PATHs/OS cases; reasons printed, profile semantics unchanged | None | META |
| V-06 | P1 follow-up: browser CI smoke | Existing Playwright files; Makefile; ci.yml; isolated fixture config if needed | Real-DOM auth/readiness/benign fixture action; retained failure artifacts | Isolated browser/fixture runner; include V-01 if checking new rows | META / UI |
| V-07a | Deferred P2: key-state protection | Provider seam; gateway reader/config; provider/gateway tests; backup guidance | Agreed narrow design; restart/concurrency/failure retain selected-provider routing | Operator selects debt/design; separate PR | PROVIDER / DOCS |
| V-07b | Deferred P2: flake investigation | Focused azure-idle harness/evidence; script only after diagnosis | Reproduced failing branch; focused repeatability and normal CI | Reproducer before code fix | RUNTIME / META |
| V-08 | P3: vocabulary/observed UX | Source enum doc or validation/test; UX JS/bundle per observed issue | Truthful supported types; human-observed usability finding; gates unchanged | D6/D3 observations for UX | DOMAIN / API / UI |
| R-01 | P0-release: remaining qualification | Evidence records; isolated qualification harness | Refresh stale intended-release gates; manual D3/D6; provider and registry evidence as applicable | Exact implementation SHA; human/operator actions; Azure approval when needed | EVIDENCE / EXTERNAL |

Execution order:

- First repair wave: V-01 and V-02 have independent write sets. Credential rotation is a coordinated operational step, not implied by merging a docs change.
- Follow-up wave: V-03, V-04 and V-05 can run with separate ownership after any overlapping V-02 docs are integrated. V-06 is its own bounded harness task; it does not delay D6.
- Deferred lane: V-07a/V-07b need their stated design/reproduction prerequisites. V-08 UX changes follow observed human findings.
- Human/release lane: run D6 on an identified stable deployment with no mid-run repairs. After any implementation merges, run appropriate ordinary CI and refresh only affected release evidence. Serialize shared UI/bundle, CI, docs and deployment changes; do not combine these prospective write sets without checking overlap.

Release work remains its own operator-owned lane: refresh only source-/topology-stale gates required for the intended release; retain existing valid evidence; complete manual D3 and non-builder D6; obtain explicit Azure go-ahead before staging actions. No mass retest, process cleanup, USB reset, engine reset or evidence deletion is implied.

## Checks and limitations

Read the repository preservation rules. Independently read the seven finding paths, associated tests, supervisor roster, provider state flow, CI, current handoff and dated readiness runbooks. Verified route counts by AST without importing operational settings. Verified the ordinary-password URL defect using installed SQLAlchemy with inert values and no DB connections. Read-only GitHub visibility/current-head job results are linked above. The requested assessment/plan is the sole new repository artifact; no implementation or deployment was changed. Live `.105` health, current credentials, exact release evidence files, browser behavior, USB state and external provider acceptance were not independently probed. Treat review-reported full-run counts and live observations as attributed claims; CI/source/historical-doc evidence does not authorize release promotion.

Source-review preservation check: SHA-256 `adf2d973b9759431400a9c081a21c485625398b5e68faa8c42cd2981a52012ff` before and after this review. Exact-head CI success was verified from job metadata; supplementary raw-log retrieval was unavailable, so no new per-profile counts are asserted.

## Second independent review

A second subagent audited N-01–N-07 against the source before reading this plan. It confirmed the substantive verdicts and priorities and found one factual correction: `docker-compose.e2e.yml` exists, but supplies PostgreSQL only, with a fixed container name, persistent volume and environment-supplied credentials. The Q-08 paragraph above now states that scope correctly and preserves those existing assets. The independent API/browser fixture prerequisite remains; no new task or priority change is warranted.

This second pass used targeted source reads, AST counts and a synthetic URL demonstration. It did not rerun suites or independently revalidate GitHub metadata, live credentials, the deployed stack or external qualification. The original assessment remains unchanged; this pass changed only the remediation-plan document. D6 and manual D3 remain human gates, and Azure remains gated.

## Implementation — 2026-10-07

Implemented on `fix/qa-oct07-validated-20261007`, based on `ad997f9`. These changes
are prepared for review; `.105` was not redeployed. This status supersedes the
prospective task schedule above without changing the historical review evidence.

| Task | Result |
|---|---|
| V-01 | Complete: ten local worker roles, roster contracts against both launchers, PID-presence cases for curation/audit-anchor, managed status unchanged. No application dependency added. |
| V-02 | Documentation complete: both published handoff password literals replaced with private retrieval references; location-only handoff guard and credential guidance added. Live rotation awaits the operator's coordination answer; the old password is not claimed to be invalidated. |
| V-03 | Complete: CREATE/ALTER ROLE uses psycopg SQL/Identifier/Literal on the existing transaction's driver connection; parsed probe URLs replace credentials without corrupting the target. Synthetic tests cover quoting, URL options and loopback restrictions. |
| V-04 | Complete: current README/architecture link to the enforced manifest instead of drifting route counts; source CI and historical qualification are distinguished; old handoffs/registers point to the current operational reference. Historical counts remain intact. |
| V-05 | Complete: the hermetic runner explains profile, OS and missing-tool exclusions and prints its marker selection; shim tests cover both profiles and tool/OS combinations. Isolation/no-skips behavior retained. |
| V-06 | Complete: `make test-console-smoke` starts an isolated loopback fixture and tests the actual served UI, password login, status and reversible configuration edit. CI provisions Chromium and retains uniquely named evidence. Audit persistence and ancillary reads are synthetic; this is not live campaign/provider qualification. |
| V-07a | Deferred as agreed: key-state architecture needs a bounded design choice and applicable authenticated-provider requirements. No shutdown state-file deletion introduced. |
| V-07b | Investigated: five focused repetitions passed; diagnostics retained at `data/qualification/qa-remediation/20261007T145038Z-idle-contract/`. No root cause reproduced and no Azure-idle behavior changed. This is not a measured loaded-host flake rate. |
| V-08 | SourceType documentation now distinguishes persisted/internal values from types supported by creation. Broader UX remains deferred to D6/D3 observations. No enum values or API acceptance changed. |
| R-01 | Human/release gates remain open. No production/RSA readiness upgrade, Azure deployment, image/registry attestation, restore or USB operation occurred. |

Validation of the implementation tree:

- `make test`: **3,579 passed, 111 deselected, 0 failures**, 210.11 seconds. Host
  tooling included macOS, zsh, Node and esbuild contracts; service integration
  profiles remained deliberately excluded.
- `make lint`: Ruff and formatting clean (568 files), console JavaScript syntax
  checks passed. `make typecheck`: strict mypy clean over 190 source files.
- `make test-console-smoke`: **1 Chromium test passed**, 3.6 seconds; retained
  evidence at `data/qualification/console-smoke/0a99462e-319e-4129-b3f5-7d3ca129dd6e/`.
  Previous failed-run artifacts were preserved; subsequent runs use unique paths.
- Actionlint, offline Zizmor, ShellCheck, targeted Bandit and `git diff --check`
  passed. Dependency versions and lockfiles were unchanged.
- Original source assessment SHA-256 remains
  `adf2d973b9759431400a9c081a21c485625398b5e68faa8c42cd2981a52012ff`.

Remote CI, deployment-specific E2E and final-image qualification must bind to
the eventual implementation commit. Earlier `ad997f9` CI evidence does not
qualify these later changes. Credential rotation is a separate coordinated
live step, and manual D3/non-builder D6 remain human tasks.

## D6 usability repair — observed October 7

The operator's attempted validation exposed overlapping template badges,
clipped review states and campaign columns, hard-to-find content and unnecessary
pattern/lesson choices. This activates the previously deferred V-08 UX work.
The attempted D6 run is a finding, not a pass.

Prepared on `fix/d6-console-usability-20261007`, based on merged QA commit
`50b8c44`. This section does not claim deployment or human acceptance.

| Task | Ownership / dependencies | Acceptance and result |
|---|---|---|
| U-01: layout and campaign flow | Root owns shared UI source, generated bundle and CSS | Separate badges from subjects; wrap states; three library columns and five campaign columns; stack narrow rows with visible actions. Pattern supplied automatically; approved after-click default optional. |
| U-02: exact uploaded roster | Root owns CSV planning/routes and tests; consumes existing audience-group interface | Name included in preview digest; upload plus exact-address group saved in one transaction; creation binds only the selected group. Existing recipients included, wider department/domain excluded. |
| U-03: wording and graphics | Root owns content API/source; consumes existing preview/clone/logo/review routes | Edit an immutable copy; both message alternatives updated; recipient link preserved; bounds and safety validation before persistence. UI checks renderer syntax before saving; logo upload remains in Draft review. |
| U-04: instructions | Root owns operator guide, current D6 script and this record | Exact section/control paths; September setup marked historical; expired example campaign explicitly excluded. |
| S-01/S-02: safety review | Independent subagent, read-only API/test review; no shared writes | Found an HTML size expansion defect; root fixed it with revalidation and no-write tests. Follow-up found no remaining blocker in reviewed scope. |
| U-05: workflow review | Independent subagent, read-only UI/docs/screenshots | Found hidden narrow actions and a missing plaintext recipient link after replace-all editing. Root corrected both; fresh screenshots confirmed visible actions. |
| U-06: browser editor verification | Workflow subagent owns only `console-ci.smoke.spec.mjs`; stable root preview/clone interfaces | Isolated fixtures exercise actual UI edits, carried selections, action bounds, and exact roster-binding payloads. Integration and final validation remain root-owned. |

Reviews ran concurrently without shared write ownership. Root integrated API,
UI and documentation changes serially; the browser test extension is the only
delegated write. The normal validation commands are `make test`, `make lint`,
`make typecheck` and `make test-console-smoke`. PostgreSQL cases belong to the
isolated CI integration profile, never the normal application database. Final
exact-commit results belong to the associated PR and CI checks.

Browser fixtures prove UI behavior with synthetic data; they do not prove live
provider delivery or human usability. Existing authorization, exact launch
review, test cohort, canary evidence and full-publication gates remain in force.
The default after-click page still exists for recipients; an operator is not
required to author a lesson or knowledge-check questions. Graphics adjustment
currently means the existing logo upload, not a general email design editor.
The deployed `.105` stack, credentials, USB mount and other sessions were not
changed by this repair. Repeating D6 requires deployment followed by a fresh
human attempt.

Local repair validation: `make test` passed **3,588 tests, 113 deliberately
deselected**; `make lint` passed (569 formatted files and console syntax);
`make typecheck` passed (190 source files); `make test-console-smoke` passed
**3 Chromium tests**, including edit validation before cloning, approved-only
library defaults, retained roster selection and visible actions at 1280/768px.
Final browser evidence is retained at
`data/qualification/console-smoke/bc0a74f0-9687-4c7f-8a0e-acb245a8a952/`.
The original adversarial assessment remains unchanged at the SHA-256 recorded
above. No remote integration result is implied by these local results.

## Resume verification — 2026-10-08

PR [#131](https://github.com/ELDSRQ/kingphisher-phoenix/pull/131) merged as
`a87aabf1bbb5efe44f8f3d32864b7b11f440217e`. The
[CI run on that merge commit](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37724925659)
passed the hermetic lint/type/no-skip job, PostgreSQL/Redis integration job and
isolated console browser job. This verifies source and synthetic-fixture
behavior; it does not qualify live delivery, images or human acceptance.

Read-only probes during session resumption found the `.105` checkout already
at that exact commit. The supervisor is active; PID entries for both APIs and
all ten worker roles refer to live processes started October 8 at 00:00:35 EDT.
PID presence is the existing supervisor probe and does not prove worker job
completion. Operator, tracking and AI-gateway `/readyz` returned ready, and the
HALO tunnel unit is active. No generation request was made.

The controller's existing console (`8600`), tracking (`8001`) and Mailpit
(`8025`) tunnels respond. Served console JavaScript and CSS are byte-identical
to the merged checkout:

- `app.js` SHA-256: `9984a0d99e6ac36f756f016aa869c2c6b289ec4833674745301e9f5caf14a7bb`.
- `styles.css` SHA-256: `2d083c9e3a2679fc1eed58eeeb062d97b984ceb85780b6f19ea85325d9c78903`.

Mailpit reported zero captured messages at the probe time. This is inventory,
not delivery evidence. The unauthenticated `/openapi.json` probe returned 404;
no authenticated API workflow or live browser walkthrough was performed.

No redeployment or restart was needed or performed. The controller's
untracked original QA assessment and the worker's untracked
`docker-compose.override.yml` were preserved. No credentials, campaign state,
databases, storage, other sessions or Azure resources were changed.

The next step is a fresh unassisted human attempt using the
[current D6 script](D6-HUMAN-ACCEPTANCE-SCRIPT.md#current-run-october-7-usability-finding).
Use synthetic Mailpit recipients and valid new dates; the old October 6
campaign is expired. D6 and manual D3 remain open; production/RSA remains
NO-GO and Azure work remains gated.

## Human-readiness follow-up — 2026-10-08

Live authenticated inspection found training configured for workers but absent
from the operator wizard. The existing worker URL
`http://127.0.0.1:8001/v1/training/awareness` returned 200. An audited
`PUT /api/v1/console/onboarding` saved that same URL and the existing
`example.com,127.0.0.1` allowlist as operator values; the worker values stayed
identical and the training step now reports ready. Evidence is retained at
`data/qualification/human-readiness/e71dde9583b441888d6db7c6c5e18f94/`.

The campaign form also hid a required blank training host when multiple sending
domains were registered. The repair derives that host from training setup
independently of the mail domain count and stops guessing a training hostname
from a sending domain. Sender prefill now uses the already loaded domain
collection; the old duplicate read expected an array instead of the API's
`domains` envelope and silently discarded it. Isolated browser coverage tests
two-domain setup, missing training setup, exact create payloads and retained
roster binding at 1280/768px.

Live browser coverage now includes Get started and Domains & RoE, plus choosing
an approved library email and reaching a campaign form with its supplied
training host at both widths. Live runs retain separate UUID evidence
directories and disable traces that could record deployment credentials.
The browser connector could not initialize in this session (a rejected runtime
import), so the repository's standalone Playwright checks provide this evidence.
The pinned test browser was added under `data/tooling/playwright`; existing
caches and failed-run evidence were preserved. Missing controller Python
workspace dependencies were added from the frozen lockfile with `--inexact`.

Initial live result at deployed `a87aabf`: **13 passed**, including login plus
eight views with no blocking axe findings and four navigation checks; no skips.
Evidence: `data/qualification/human-readiness/c1eecd73697e4863b2360ca03778df1e/`.
Local hermetic suite: **3,588 passed, 113 deliberately deselected**, 241.78 s.
Lint and strict types passed; the repaired isolated browser workflow passed
all three tests. Source CI and post-deploy live checks are recorded below.

Scenario preparation: the `example.com` signed RoE is valid through December 20,
2026, while the mixed-domain October 2 RoE is expired. The current D6 script
uses synthetic recipients and explicitly includes test-account designation;
CSV import alone never authorizes a canary. Two active test accounts existed
at inspection; no saved roster existed before any rehearsal. Human acceptance
and manual assistive-technology testing remain human gates. No model-reasoning
blocker requiring Astra has been encountered.

### Deployment and backend rehearsal

[PR #132](https://github.com/ELDSRQ/kingphisher-phoenix/pull/132) carries
the follow-up. All three required jobs passed at implementation commit
`680429cf8296c1d36ee85c662af53d9f39eb1c82`
([CI](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37815634645)).
The preserved `.105` checkout was switched to that feature branch and its
normal supervisor restart marker was used. `main` was not merged or rewritten.
Both APIs and the gateway subsequently returned ready; served-source JavaScript
SHA-256 is `1bac81b2200a3631db3389d6c11ab8901063d86293fe5e78ea1b74b097618ddb`.
There are no migrations or dependency changes in this repair.

The governed API/Mailpit rehearsal created exactly two new synthetic
`example.com` recipients and one named roster; only its new canary was designated
as a test account. It froze that roster, completed the normal single-operator
launch review, queued one locked canary, waited for server-derived SMTP
evidence, and separately published one non-canary. Both were captured in
loopback Mailpit. The recipient link led to the bound training page; a normal
knowledge-check submission completed training. The report showed two provider
acceptances, one click and one training completion. SMTP acceptance is not
external delivered-receipt or inbox evidence.

Both exports were downloaded; the ZIP passed its integrity check and each JSON
member parsed. Recall affected only rehearsal campaign
`5dfe5813-9c49-4bac-b7ca-8bcebda8ea52` and revoked its two tracking tokens.
Its two recipients, roster, recalled campaign, captured mail and audit evidence
were retained. Evidence:
`data/qualification/human-readiness/rehearsal-b4861d169fd84402b9d8fabd072bbdde/`.
The log retains an initial helper failure at a nonexistent lesson-detail URL;
continuation used the supported preview endpoint and completed the same
rehearsal. Creation/delivery ran at `a87aabf`; training/export/recall ran after
the UI-only deployment to `680429c`. Backend application files were unchanged
between those commits. This was an automated diagnostic, not a D6 attempt.

The expanded live browser sweep hit the unchanged 120 requests/minute user
limiter when it rapidly opened fresh sessions/views. Earlier failed artifacts
remain preserved. The live harness now uses one worker with an eight-second
pause before each check; authenticated setup-response matching excludes the
normal pre-login rejection. No server limits were changed or bypassed.

The paced post-deploy sweep passed **17 checks, zero skips**, in 2.5 minutes:
11 accessibility checks (login and ten views) with no blocking axe findings,
and six navigation/form checks. Evidence and successful form screenshots:
`data/qualification/human-readiness/a38250eef69f46ceaf379d70fe39565a/`.
Visual inspection at 1280px and 768px found readable cards and accessible
campaign actions. The same inventory reported both APIs, PostgreSQL, Redis
and all ten workers ready. The final changes after `680429c` affect test pacing
and these evidence records only; runtime assets remain identical.

**Build ready for a controlled human trial on `.105`.** On October 8, the user
explicitly deferred console-password rotation until signing off on this build
as fully completed and human ready. This supersedes the earlier pre-D6
rotation sequencing and resolves the coordination question: rotation is not
a human-trial blocker and must not run before that sign-off. No new credential
is recorded here, and no rotation is claimed. D6 unassisted
acceptance and manual keyboard/screen-reader checks remain open. Use the current D6 script,
refresh the console, and create a distinct synthetic roster/campaign. PR #132
still requires integration into `main`; this trial runs its feature branch.
No unresolved implementation or model-reasoning blocker was found. Release
image, recovery, cloud/provider and production approval gates are not renewed
by this synthetic diagnostic; production/RSA remains NO-GO.

## Operator-flow remediation — 2026-10-09

The October 9 human attempt failed on authorization inspection, CSV preparation,
roster ambiguity, email selection, separate audience/launch controls and silent
send buttons. D6 remains open. Preserve the user's approved, unsent campaign
`8a0a7e2a-ebb5-464f-9d0f-9a555be5e838` ("Test 10-09-2026").

`fix/human-operator-flow-20261009` builds on PR #132. Domain rows now open the
signed authorization record and show approved target domains. Recipients offers
a header-only CSV template, optional greeting names, a saved-roster selector
and server-scoped pagination; earlier imports appear only when explicitly
selected. The current roster is displayed first; subsequent uploads and
employee-reported mail collection are expandable. That collector reads reported
phishing and does not validate target mailboxes. Recipient checks distinguish
address/domain eligibility from unverified mailbox existence.

Approved email cards and their safe previews offer Select for current campaign,
retaining the roster. One Confirm recipients dialog shows the server-derived
included/excluded list and campaign-bound RoE domains; it performs the existing
exact-manifest freeze and launch review internally. Editing roster options is
optional. A missing designated test account is detected before confirmation can
commit. Server authorization, immutable review, exclusions and worker delivery
checks remain in force.

The silent send failure was an event-handler bug: `currentTarget` was read after
awaiting a confirmation dialog. The handlers now capture the clicked button
before awaiting. Queued, successful, failed and expired test states have explicit
next-action wording; full send remains a separate confirmed action.

Local validation: **3,591 passed, 113 deliberately deselected** in 211.41 seconds;
lint/format and strict types passed. The final wording and freshly generated
bundle passed 30 focused contracts and **four isolated browser checks** in
8.4 seconds, including CSV download, scoped roster/history, preview selection,
cancel-without-mutation, missing-test-account handling, exact confirmation and
observable test/full sends. The final source CI and live deployment are pending
at this record's initial commit. No migrations or dependency changes are needed.

The user also requested an optional canary. The pending scope question is
whether this applies only to on-prem single-operator mode or to production/cloud
too. This repair does not claim an exemption or canary success: both the API and
worker currently require fresh campaign/provider/config-bound evidence. A launch
policy change must cover both enforcement paths and its audit/evidence semantics;
changing only button availability would leave the operator blocked at delivery.
This is the remaining design decision suitable for a separate model review.
Password rotation remains deferred until the user's completed-build sign-off.

### Live verification findings

Implementation `3527c7c` and plain-language confirmation follow-up `fc7ba16`
passed all three required CI jobs. `.105` was switched to the preserved feature
branch at `fc7ba16` and normally restarted. Its served bundle matched SHA-256
`2c84708300c2787a00d5d88d52cdb3659e1de04262cf5c0362cec57f175281b7`.

The live UI saved two new synthetic recipients, inspected authorization,
selected an approved email from preview, created campaign
`b534f3e4-2800-424b-a9c0-9d32536c24bc`, and confirmed its exact roster through
the single confirmation control. A rapid automated test-send attempt received
HTTP 429; it never queued mail. Its retained evidence is
`data/qualification/human-readiness/ui-rehearsal-1a1de79fc45941cabd84a51f84d16921/`.
An earlier navigation-only helper attempt remains retained separately; initial
login correctly redirected the incomplete setup session to Get started, so the
helper needed to click Domains & RoE explicitly.

The request-limit follow-up gives HTTP 429 a bounded Retry-After instruction,
does not automatically retry mutations, retains the selected email when the
template collection is unavailable, and prevents detached campaign renders
from changing current selections. The isolated browser test now proves that a
throttled test request does not change campaign state or queue a send, and that
a failed template read does not falsely announce lost approval. All four browser
checks passed in 10 seconds, plus 26 focused contracts and lint/strict types.
Live continuation will reuse only the above rehearsal campaign at a slower pace.

The paced continuation queued exactly one test email and Mailpit captured it;
the server derived successful canary evidence. A fresh page load then returned
the incomplete-setup session to Get started. The test-send action now refreshes
the campaign view in place, just like full send. Initial programmatic roster
selection also incorrectly marked the new-campaign form as dirty, pausing the
30-second status refresh; initial defaults are now marked saved while genuine
operator edits retain their refresh guard. The browser scenario explicitly
covers incomplete setup and an unedited prefilled form.
