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
The separate full-stack harness wave still requires implementation and actual
execution. None of these checks constitutes human acceptance or production GO.
