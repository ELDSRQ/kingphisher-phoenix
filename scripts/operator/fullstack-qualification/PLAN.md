# Isolated full-stack qualification plan

Historical design plan. The implementation is under active native qualification;
current results and preserved failures are recorded in the
[remediation registry](../../../docs/remediation/registry.json).

## Scope and claims

Run the actual operator API, tracking API and `kp-worker supervise` entry points
against task-owned PostgreSQL, Redis, Mailpit and a bounded SMTP fault proxy on
the current `.105` native AMD64 worker. Exercise the current reviewed-direct
launch flow with 125 and 1,250 synthetic recipients, then recover the complete
service state into separately named services. Do not invoke handlers directly,
replace `JobQueue`, seed dispatched assignments, or reuse the legacy canary test.

Results establish the tested source/configuration and synthetic service envelope.
They do not establish live Azure/ACS/Graph delivery, DNS ownership, production
capacity, signed human acceptance, clean-VM installation, or final release-image
qualification. Report SMTP sink acceptance separately from recipient delivery.

## Preservation and isolation contract

* Generate a run UUID. Every container, network, named volume, database, source
  staging directory, virtual environment, log and snapshot contains that UUID.
  Reserve the output directory with an atomic, exclusive create; never resume
  into an existing directory without an explicit read-only verification mode.
* Run only through an explicit `.105` SSH target and explicit native Docker
  socket. Record host/engine ID, Linux/AMD64 architecture and Docker root. Refuse
  retired hosts, Docker Desktop, inherited Docker contexts and unknown identity.
* Create a new dedicated bridge Docker network and fresh PostgreSQL/Redis/Mailpit
  containers with dedicated volumes. Bind host access only to dynamically
  assigned `127.0.0.1` ports; capture actual ports from only the newly created
  containers. Never use normal 5432/6379/8000/8001/8025, task51458/51459, or fixed
  project container/volume names. Every Docker mutation must first verify the
  exact run label and expected resource ID.
  Native smokev1 showed internal networks do not publish the required host ports
  on this engine. New runs use an explicitly recorded `Internal=false` bridge;
  containers and native application processes have no all-egress-isolation claim.
  Every expected publication must be exactly one IPv4 `127.0.0.1` binding, and
  every pinned image must inspect as native Linux/AMD64 before network creation.
* Pin infrastructure image digests already approved/present on `.105`, using
  `--pull never`; missing images block with an inventory. Check bounded disk
  availability before creating resources. Never reclaim storage to proceed.
* Stage source files from an explicit code allowlist with per-file hashes,
  including uncommitted remediation files and the frozen lock. Exclude `.env`,
  normal `data/`, recovery evidence, credentials, caches and Git metadata. Build
  a fresh run-owned Python environment; never alter the normal checkout/venv.
* Generate synthetic-only secrets/configuration in a private directory
  (`0700`, files `0600`). Do not source the project's `.env`. Refuse non-loopback
  SMTP/HTTP/DB/Redis URLs and non-`.test` recipient domains. Use real role URLs
  from `azure_migrate.py`, including separate audit_writer and per-worker URLs;
  forbid `KP_WORKER_SUPERVISE_SHARED_DB=1` and owner/development SQL fallback.
* Preserve every artifact, volume, container and failed partial result. No
  `compose down`, `rm`, `prune`, `flush`, schema reset, namespace cleanup, or
  deletion of Mailpit messages. Never stop normal services. Harness-controlled
  pause/stop is limited to exact, newly created run resources and recorded PIDs.

## Proposed implementation files

1. `run.py`: CLI, exclusive run reservation, absolute deadline, phase/state
   journal, process ownership, safe reporting and additive resume inspection.
2. `stack.py`: resource manifests, exact identity/label checks, fresh services,
   source/environment staging, actual bootstrap, role URLs, API/worker startup
   and health/role-readiness collection. Track process start time as well as PID
   before any signal; never rely on a stale PID alone.
3. `campaign.py`: HTTP-only campaign/roster/review/approval/send/monitor client,
   synthetic authentication, content fixtures, tracking/training interactions
   and API/report/sink reconciliation. Fixture setup may create synthetic
   domain-evidence/library prerequisites, but cannot create assignments or set
   campaign launch/approval/send state directly.
4. `smtp_proxy.py`: bounded loopback SMTP forwarder to this run's Mailpit only.
   Modes: pass-through, fixed pre-DATA delay, deterministic pre-acceptance451,
   and disconnect after upstream acceptance. Journal protocol phase and message
   fingerprint without storing auth material. Fixed connection/body/time limits
   prevent the fault injector itself from hanging or exhausting the host.
5. `recovery.py`: quiesced full-state checkpoint, hash/config/key inventory,
   restore into entirely new run-owned target services, actual API/workers
   restart, and post-restore behavioral reconciliation. Do not call existing
   restore scripts with hardcoded normal project container/volume names.
6. `README.md` and focused hermetic tests: ownership rejection, URL/identity
   checks, exclusive evidence writes, deadline enforcement, secret redaction,
   controlled proxy modes and observation accounting. A real bounded smoke run
   precedes the larger scenarios.

## Actual application paths to use

* `scripts/azure_migrate.py`: migration, canonical role grants and fresh-login
  privilege probes. A fresh task cluster allows canonical runtime role names
  without changing credentials in any existing cluster.
* `apps/operator-api/src/kp_operator_api/main.py:create_app` and
  `apps/tracking-api/src/kp_tracking_api/main.py:create_app`: serve with Uvicorn
  as separate real processes, using only generated run configuration.
* `apps/workers/src/kp_workers/__main__.py:main`: invoke `kp-worker supervise`
  with explicit role URLs and real provider handlers. Capture role readiness and
  isolate the delivery role in its own supervisor process where supported.
* `sending_domains_roe.py:create_roe`, `POST /api/v1/roe`: produce the actual
  signed RoE for the synthetic domain and current run window. The DNS-evidence
  prerequisite is explicitly a synthetic fixture, never live DNS qualification.
* `routes/recipients.py`: `POST /api/v1/recipients/import/preview`, followed by
  `/import/apply`, binding the exact CSV digest/preview and saved roster.
* `routes/campaigns.py`: `POST /api/v1/campaigns` with
  `delivery_mode=reviewed_direct`; configure its roster/RoE; obtain audience
  preview; `POST /{id}/confirm`; apply exact cue-coverage/content review and both
  enforced security/privacy approvals; `POST /{id}/send`; poll `/{id}/report`.
  Confirm current request/response schemas from OpenAPI before implementation.
* Use distinct synthetic author, security approver and privacy approver UUIDs
  through the real supported development authentication implementation. These
  are logical test principals and cannot satisfy two-human acceptance.
* Follow links extracted from this run's Mailpit messages into the actual
  tracking/training HTTP service; never fabricate tracking tokens or results.

## Bounded scenario sequence

1. **Preflight and smoke:** validate ownership/identity/ports/configuration;
   run actual migration and runtime-role probes; wait for API and every selected
   worker role to be ready; complete a small reviewed-direct campaign through
   real SMTP, tracking, training and report reads. Any failure blocks escalation.
2. **125-recipient baseline:** exact uploaded roster, reviewed content and
   approvals. Send once, repeat the send request to verify refusal/idempotency,
   wait for complete assignment/outbox/sink accounting. Observe each recipient's
   sink acceptance separately from any delivery evidence. Exercise a stable
   synthetic subset of click/training/report flows and verify report counts.
3. **1,250-recipient burst/soak:** repeat the authorized flow with a fresh
   roster/campaign. Concurrently poll health/report endpoints and submit bounded
   tracking/training traffic. Sample queue ready/delayed/processing/DLQ, outbox
   pending/failed/dispatched, assignment dispositions, service RSS and request
   latencies. Keep normal-operation and fault-phase metrics separate. Continue
   a five-minute observation window and drain within a fixed overall deadline.
4. **Controlled degradation:** fresh campaigns with deterministic SMTP delay,
   retryable rejection before acceptance, and post-acceptance disconnect. Confirm
   unrelated roles/API still progress, retries remain bounded, and uncertain
   deliveries require reconciliation without automatic duplicate send. Compare
   actual Mailpit message fingerprints with assignment/outbox state. Fault modes
   and time windows must appear explicitly in the report.
5. **Checkpoint/recovery:** create acknowledged PostgreSQL and Redis sentinels,
   plus an identifiable set of completed, queued and deliberately uncertain
   assignments. Quiesce only run-owned application processes, then checkpoint
   PostgreSQL custom dump+globals, Redis persistence, Mailpit sink storage and
   all synthetic configuration/key identities. Hash every file and record each
   capture boundary. Keep source services and snapshots preserved.
6. Restore snapshots into new target containers/volumes/ports, validate hashes
   before import and start actual services against the restored role URLs and
   exact keyring/audit/token/ledger keys. Verify audit chain/head, ciphertext,
   signed review/RoE, ledger, existing tracking/training links, queue lease
   recovery, outbox reconciliation and uncertainty handling. Finish a new
   reviewed-direct campaign after restore. Compare source/target/sink journals
   for acknowledged-write loss, duplicate acceptance and unresolved work.

## Proposed acceptance and reporting

Hard correctness gates: exact accepted-work accounting; no unexplained loss or
duplicate SMTP acceptance; no unintended subject/provider access; valid audit
verification; bounded role readiness; unrelated-role progress during faults;
zero unclassified failed/leased/DLQ work after the drain deadline; explicit
review-required disposition for uncertain sends. Never relabel unresolved work
as success merely because counts drain.

The CLI exposes a bounded profile with defaults:125/1,250 recipients,300-second
soak,120-second phase readiness,600-second drain and1,800-second total deadline.
Proposed synthetic targets:normal API p95≤1second and critical-role observed
progress≤2seconds. Report maximums and p95 with sample counts. These are reviewed
test targets, not a production SLA; if root chooses different values, record
the exact profile before starting and never adjust it after a failure.

RPO measures the age/number of acknowledged sentinels missing from restored
state relative to the recorded recovery cutoff; RTO measures from initiating
the isolated restore until API, required worker roles and behavioral smoke are
all healthy. Target zero loss at the deliberately quiesced checkpoint and
RTO≤15minutes for this synthetic test. Explicitly label this a consistent
quiesced-backup recovery proof; it does not establish continuous live-backup RPO.

Write an append-only phase journal, sanitized service logs, HTTP observations,
SMTP protocol/fingerprint journal, source/dependency/image digests, resource and
configuration fingerprints, checkpoint manifests, measurements, failures and a
machine-readable final result using exclusive file creation. Credentials and
secret values stay only in the private synthetic configuration archive. Every
claim links to its exact phase/profile/resource evidence; interrupted or
incomplete runs remain failed/incomplete. Report preserved resource identifiers
and disk use so another operator can inspect them without cleanup.
