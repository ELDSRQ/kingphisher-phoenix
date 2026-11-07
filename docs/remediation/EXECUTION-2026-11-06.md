# Registry completion execution

Authorization: continue the approved build until the registry is complete or no
agent-actionable jobs remain. Baseline `db55667` (PR169). Preserve the original
dirty checkout, all runtimes, databases, environments and qualification evidence.

The original 29-item registry and FU-1 through FU-20 carryovers were recovered
from the relevant project's retained tool records after their temporary storage
directory was emptied. The seven-item summary omitted real carryover defects.
The root integrator owns the durable registry and all status changes; historical
completion is distinguished from current qualification.

## Wave 1 ownership and acceptance

| Assignment | IDs | Exclusive components | Acceptance |
| --- | --- | --- | --- |
| Queue transport | FU-6/7/8 | contracts queue and tests; worker queue configuration and focused tests | Explicit replay allowlist, bounded replay window, fenced acknowledgement/rejection surviving a lost lease-renewal response; real isolated Redis effects |
| Database roles/recovery | FU-2/5/9 | database grants/outbox; migration 0054; grants/outbox tests | Actual mailbox row locking under its role; role/topic-limited SECURITY DEFINER reconciliation; bounded review-needed logging; migrated PostgreSQL effects |
| Adaptive programs/accessibility | FU-18/19, W2-05 | program service/jobs/API/UI/tests; generated console bundle; accessibility tag selection | Authenticated bounded iteration/adaptation controls, creator preservation, failure/stall honesty, DRAFT-only output, WCAG 2.2 tag coverage |
| Root integration/privacy/recovery | FU-10/11/12/13, recovery capture | privacy helpers/routes and dedicated tests; checkpoint helper and preservation tests; registry/docs | Hold-aware historical tombstone purge; truthful purge counts; least-privilege/malformed-key atomicity; preserved checkpoint collisions and partial failures |

Shared interfaces and migration numbering are integrated serially by root.
No branch is committed or merged by an assignment owner. Dedicated test targets
use task-owned databases and Redis namespaces; no normal database reset or queue
flush is permitted.

## Subsequent jobs

- Validate FU-1 Terraform connector completeness and remove unsafe out-of-band
  Foundry role-assignment deletion before any cloud workflow dispatch.
- Repair confirmed offline AI-evaluation classification/baseline honesty,
  concurrent threat-ingest deduplication and health-dashboard failure reporting.
- Reconfirm cue-coverage author/remediation behavior (FU-15/16) and meaningful
  missing characterization cases (FU-20); preserve current single-operator
  policy and existing independently reviewed attestation semantics.
- Build an isolated full-stack workload/recovery qualifier for 125 and 1,250
  synthetic recipients, real workers/outbox, controlled mail sink and bounded
  slow/error cases. Never substitute synthetic callbacks for provider handling.
- Integrate serially, obtain independent code review, run focused and required
  CI checks, qualify exact native images, and only then advance deployment.
- Wake the retained Azure runner rather than provisioning/replacing it; retain
  plan guards, private ACR restoration and registry attestation requirements.

## Gates that require actual external or human results

Clean-machine installation requires genuine supported VMs/hosts; a container
does not prove OS installation or reboot persistence. Full service recovery must
include Redis/files and independent key recovery. Manual accessibility and D6
require one independent human driver for current on-prem readiness. Pilot and
broad-use GO require observed acceptance and human sign-off. These remain open
until evidence exists; broad engineering authorization is already granted.

## Integrated repair evidence

The repair wave passes 4,184 hermetic tests with no skips (173 integration
tests deselected), strict mypy on 219 production sources, and the frozen lock
check. Checkpoint/deployment preservation has 25 focused tests and independent
review; five offline mocked Terraform plans exercise connector completeness.
Actionlint and zizmor pass for the updated deployment workflow, whose digest is
updated with its connector contract.

Actual PostgreSQL effects cover the operator's historical erasure, retained
versions, holds and projector race (six tests), managed privacy export and
NOINHERIT migration (seven), adaptive iteration concurrency and creator
preservation (six), and cue/threat concurrency (three). Managed adaptive-worker
and paginated queue recovery results are recorded in the registry as their
final gates finish. Fourteen Chromium scenarios include WCAG 2.2 AA tags.

Independent review found and prompted repairs for lost-job starvation beyond
the first reconciliation page, the erasure/projector race, managed export
undergrants and adaptive-worker undergrants. SQL export identity binding remains
the application's responsibility; see [the boundary](PRIVACY-EXPORT-BOUNDARY.md).
PR170 merged these repairs after required CI passed: 4,158 hermetic tests,
161 PostgreSQL effects, four Redis effects, fourteen browser scenarios and
strict mypy on 219 sources. The separate full-stack harness is implemented and
independently reviewed; its native smoke runs have exposed additional runtime
defects that must be repaired before the full profile. None of these checks
constitutes human acceptance or production GO.

## Wave 2 ownership and acceptance

All work uses the isolated `codex/fullstack-qualification-20261106` worktree.
The original dirty checkout and normal development runtime remain preserved.

| Assignment | Exclusive components | Acceptance |
| --- | --- | --- |
| Runtime role repair | Program scheduling lock, canonical grant matrix, migration 0057 and dedicated real-role tests | Standalone and program SEND without occurrence UPDATE; both pause/send lock orders; minimum provider/session/cue, delivery roster and receipt-retention permissions under actual NOINHERIT logins |
| Credential concurrency | Console credential/provider operations, private locking helper and dedicated race tests | Monotonic durable revocation and generation markers, serialized password/provider changes across processes, refreshed locked ORM state, deterministic reversed-completion proofs with synthetic credentials |
| Preserved runtime upgrade | New development-upgrade coordinator and preservation tests | Read-only preflight, private checkpoint, isolated restore/migration/decryption rehearsal, explicit reviewed cutover preserving original source/environment/configuration and all normal container identities |
| Root integration | Registry, integration, native full-stack execution, final images, cloud deployment and clean-VM execution | Independent review, focused and full CI gates, fresh immutable source per native attempt, exact-source image scans, truthful measured qualification and preserved failure evidence |

The Ubuntu Compose package repair is reviewed and passes the focused tooling
suite. Azure's removed runner registration was repaired additively using a new
runner directory, private home and service; the previous assets remain intact.
The new runner is online. Cloud workflow dispatch and clean-machine execution
wait for qualified source, not another general engineering authorization.

Native smoke v1 exposed unusable published ports on an internal bridge. The
reviewed repair requires a dedicated bridge with explicit loopback publications
and verifies all native images and running services. Native smoke v2 completed
signed RoE, roster import/confirmation and logical approvals, then found SEND's
unnecessary joined row lock. Its source processes were quiesced and its new
containers, volumes, network and evidence were preserved. The normal runtime
was never stopped or reconfigured by either attempt.

The later native smoke attempts exposed minimal exclusion, recipient and live
authorization row-lock undergrants. Migrations 0058–0060 repair those boundaries
without mutable mailbox/content/authorization access or password rotation.
Native smoke v6 passes actual SMTP sink acceptance, bound training, knowledge
completion, replay and queue accounting; it preserves all resources and does
not assert recipient delivery or qualify the full profile.

The final tracking repair removes the provider/assignment lock inversion and
rechecks bearer authorization after waits. Nine actual-role concurrency cases
pass in 62.690 seconds with no skips, including token and purpose-specific
verifier rotations and immutable first training timestamps. Independent review
and 52 local tracking tests pass; combined lint checks 711 files and strict mypy
checks 224 production sources. Two test-fixture failures are preserved in their
original unique XML files; the final proof uses fresh evidence. The combined
source still needs exact-source CI, full native load/recovery and image gates
before deployment or the preserved normal-runtime upgrade.

Full native v7 completed both delivery baselines and the 300-second observation,
and proved critical-role progress during a five-second SMTP stall. It failed
honestly on a pre-DATA451 refusal classified as uncertain; recovery was not
reached. All source processes quiesced and all resources remain preserved.
The cause was Python's SMTP exceptions inheriting `OSError`, which masked
structured refusal evidence in both transport paths.

The reviewed repair permits only typed SMTP DATA4xx refusals to retry, with at
most three durable claims and five/ten-second spacing between attempt starts.
Stable attempt/message/correlation identity preserves the existing foreign-key
history. Exact generation/counter/date and server-clock claim checks reject
original, stale and early jobs. Refusal audit plus a singleton delayed outbox
intent commit together; uncertain outcomes never automatically retry. All normal
recipient and signed live authorization gates run again. Both 147 focused and
147 independent tests pass. Five actual-role PostgreSQL effects pass in78.583s,
including durable three-call exhaustion, rollback, revocation and exact audit
intent-to-signed-event projection. The complete native profile and final CI must
now run against the repaired source before advancing the release.

At892c651 all three CI jobs pass:4,325 hermetic,214 PostgreSQL,four Redis and
fourteen browser tests. Native v8 also passes the SMTP retry and uncertainty
cases and reaches full-state restore. It stops on cached endpoint metadata:
Docker reallocates random loopback ports when the new Redis/Mailpit targets
restart after their snapshot copy. Owned current-port readback verifies the
Redis checkpoint sentinel and1,381 restored sink messages. Application and
pending-work recovery are not yet qualified; the failure remains preserved.

The endpoint repair now proves the exact recorded target/container label,
pinned image and volume before copying, then refreshes validated loopback
bindings and appends before/after receipts before updating shared metadata.
The original resource manifest remains untouched. Both52 local and52 independent
tests pass, including real cache/application/proxy URL consumers and unsafe
metadata rejection. Strict mypy and Ruff pass. Baseline startup, data checks,
snapshot bytes and all profile deadlines remain unchanged. A fresh full native
run and current-source CI are the next release gates.

Native v9 passes the restored port/data/configuration checks and launches the
restored process group, then its SMTP proxy alone exits with `Address already
in use`. The readiness gate correctly refuses qualification. The repair enables
closed-connection address reuse while explicitly disabling multi-listener port
reuse. Two real loopback tests prove immediate same-endpoint restart after
QUIT/EOF and refusal to replace an active listener. Independent source review,
Ruff and strict mypy pass. Readiness, ownership, URLs, data and deadlines remain
unchanged; all failed-run assets remain preserved for inspection.

On 2026-11-07 native full v10 passes at b2ef25e: 1,387 unique SMTP sink
acceptances, both 125/1,250 baselines, 300-second observation, five-second
provider stall, typed refusal retries and post-acceptance uncertainty all pass.
The restored application verifies keys/configuration, audit, previous training,
pending queue work and a new campaign. RTO is 75.323 seconds with zero missing
acknowledged sentinels. This is a quiesced same-host synthetic checkpoint, not
off-host custody, continuous backup SLA or confirmed external recipient delivery.
The 1,250 sends finish 76.273 seconds into the observation, leaving 223.727
seconds idle; this is not a constant-load or long-duration stability claim.
All owned application processes quiesce and every resource remains preserved.

PR171 merges at fbbc690 with the identical reviewed b2ef25e tree. Candidate
and merged-main CI pass: 4,343 hermetic, 214 PostgreSQL, four Redis and fourteen
browser tests; Ruff checks 716 files and strict mypy checks 224 sources.
Merged-main workflow 42333004166 full job logs are preserved privately.

Staging workflow 42374390352 passes its exact-source guard but fails security
qualification on Bandit B608 in historical migration 0047. Deployment is skipped;
no Terraform or application changes occur. REG-025 replaces the three known
interpolated grant targets with literal statement pairs and rejects unknown
identifiers before SQL. Sixteen focused and sixteen independent tests pass;
schema, revision, role conditions and permissions are unchanged. No suppression
or scanner exception is introduced. Complete source/dependency security checks
and current-source CI must pass before retrying staging. The retained staging
runner VM is started and registration22 is online/idle; old assets are preserved.

The private image adapter v1 stops before clone/build because Docker's built-in
host/none networks return null IPAM configuration. Its inputs and empty log are
preserved. Reviewed v2 accepts null only for those canonical unaddressed networks
and rejects unverifiable addressed networks; 56 author and 56 independent tests
pass. The scanner refreshes only the new candidate cache before freezing it for
all six image scans. A final exact-source image pass is still required.

The complete security gate passes on tracked-only source eaedf77: Bandit1.9.4,
Semgrep1.171.0, Trivy0.74.0 (vulnerability/secret/misconfiguration HIGH/CRITICAL)
and pip-audit2.10.1 against the frozen hash-verified non-development dependency
closure. All logs, exported requirements, fresh scanner caches and receipts are
preserved in the private source-security-1794057244586575000 directory. Trivy
retains its warning that Terraform input values are absent from static scanning;
this does not replace provider plans or live qualification. No waiver is added.
