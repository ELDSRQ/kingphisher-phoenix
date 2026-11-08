# November 7 continuation: persistent recovery qualification

Continue the existing authorization to remediate until the registry is complete
or no engineering work can proceed. Preserve the original checkout at
`main@cf659d5` and its seven campaign UX changes. Published main is `790171d`;
the qualified `.105` runtime is `3512a41` / schema `0060`, running from its
separate `kp-runtime-releases` directory. The old checkout's HEAD is not the
deployed release. Keep published main frozen until actual target recovery and
the separate isolated B-engine upgrade proof complete.

Recovery [PR #176](https://github.com/ELDSRQ/kingphisher-phoenix/pull/176)
is open at `fac9a0e1ec981e3cb83585f4047752de8b6729a5`.
[CI 42416805378](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/42416805378)
passed for those exact public tool bytes.

## Persistent work and evidence

The old `/private/tmp/kp-registry-completion-20261106-3lkIJ1` copies are absent.
New work is retained in `data/qualification/resume-20261107/`. Read the latest
`ACTIVE-STATE*.json` there, then inspect live process/receipt state before retrying.

- `reconstruction-manifest.json` records 315 recovered files and historical
  hunk-context gaps. Do not assume every reconstructed file is complete.
- `recovered/qualified-tools/` is a registered detached worktree at `fac9a0e`.
- `recovered/offhost-reviewed-v1/` holds the controllers, private requests,
  tests and phase evidence. Requests are in `recovered-inputs-v1/`.
- The source coordinator and guest match their original recorded SHA-256 pins.
  Original temporary provisioning/state receipt bodies are unavailable. A new
  explicit attestation binds the recorded eight actual A-stage results and
  Azure's current source VM UUID, creation time and disk. It does not fabricate
  replacement historical receipt bodies. Actual capture still checks the five
  original on-host A proofs and exact Git/engine/container/mount/volume/state.
- The retained age identity stays in
  `data/recovery/offhost-20261107-3lkij1-v1/`; never print it or copy it to the source.

## Actual source capture

`capture-v4/` **passed** against CI-bound `fac9a0e`: synthetic PostgreSQL,
Redis, complete project files, protected configuration/key state, audit state,
acknowledged sentinels and maintenance work were captured and encrypted on the
source. Conditional off-host upload and independently retained controller copy
match ciphertext SHA-256:

`032a1fd4f4131a6692ed46b9cf4164457df6714813e598ecfb0108b654126d79`

Source `vm-kp-cleanlinux-20261106-3lkij1-v5` was verified deallocated. Its complete
original shutdown timer was restored and checked. Remote `offhost-tools-v4`
and `offhost-capture-v4` remain preserved. No separate-target success is inferred.

## Target and quota

`target-v1/` stopped before provisioning: East US 2 regional and Dsv7-family
quotas were both 10 used of 10. Azure counts deallocated VMs toward quota;
all preserved VMs/disks remain intact.
[Microsoft quota documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/quotas)

`Microsoft.Quota` was registered. Dsv7-family increase request
`72ad61bc-70d8-49f5-9852-1b70cc9a199c` failed with
`QuotaNotAvailableForResource`. Regional request
`fb31a632-a332-44ad-b837-19ea11537ee8` **succeeded**, raising the regional limit
to 12. Actual subsequent usage was regional 10/12, Dsv7 10/10, Dasv7 0/10.
The API reported unrestricted `Standard_D2as_v7` (two vCPUs, 8 GiB).

A new `controller_v7.py` explicitly loads the separately pinned
`clean-linux-target-v7/coordinator.py` for that target size and family. The
source retains its old hardware/cloud pins. **190** coordinator/controller/
hardware-binding checks passed. `target-request-v2.json` binds controller SHA
`94894ae3cd88d61858ef9e74c968c3b813c6bea62056b891bb429d7906ebbc0b`.

Actual `target-v2/` provisioned and bootstrapped. Fresh-process retained-key
rewrap passed without plaintext on controller disk. Full pre-startup database,
Redis, file, key, audit, sentinel and queued-maintenance checks passed, but the
installer unit failed before service qualification. The target was verified
deallocated and every partial asset retained.

A corrected evidence-only diagnostic also finished and verified target
deallocation/prior-timer restoration. It confirms the qualified uv executable
exists outside the install invocation's PATH. Two real-shell regression cases
reproduce absent uv and unqualified ambient-uv selection against the old code.
The public target environment now puts the hash-pinned bootstrap uv directory
first. Fresh exact-source CI is required before any live use of this fix.
Diagnostic attempt1's missing summary imports were corrected in a new namespace;
its original evidence is retained. The exact combined guest diagnostic is tested.
No installer retry, overwrite, second restore or full recovery pass is claimed.
Target group/VM remain `rg-kp-offhost-20261107-3lkij1-v1` /
`vm-kp-offhost-20261107-3lkij1-v1`.

## Next work

Finish the actual separate-target restore: target-local key, retained-key
retrieval in a fresh controller process, piped re-encryption, complete protected
data/file/audit/Redis/sentinel checks, actual installer and service checks,
measured recovery times, and verified target deallocation.

Only then run the new bounded B inspection and qualify source VM5's preserved
empty B root / bridge repair / baseline `0056` to target `0060` upgrade / final
browser and preservation proofs. Prepared `inspect_B_after_offhost.py` has eight
passing checks and defaults to zero cloud calls, but needs its request/controller
binding updated to the actual successful target. `resume_v5_upgrade_v3.py` has
89 passing checks and uses new inspection pins and `offhost-tools-v4`; it has not
executed. Its actual request must be built from that new inspection. Older B
helpers still depend on absent temporary metadata; preserve them and do not run
them unchanged.

Public recovery tools also passed **236** focused checks; the new persistent
controller/source-attestation/timer/bootstrap checks passed **115**. These are
engineering results, not human acceptance or recipient-delivery proof.

Reconcile the current worktree's `docs/remediation/registry.json` and recovery
report with actual results before publishing/integrating PR #176. Original
controller changes, `.venv`, source, normal `.105` service, data and Docker
assets remain preserved. No cleanup or retired `.140` operation is authorized.

## Development history and human evidence

REG-031 requires an explicit development-history scope choice. Five preserved
September 21 witnesses disagree with today's internally valid audit chain.
The found three-event checkpoint matches today's lineage but does not recover
the missing earlier history; engineering approval cannot establish authenticity.
Recommend retaining current data and every old artifact, declaring the gap, and
starting a new development anchoring epoch. That choice authorizes a new private
witness directory, one active configuration-key change, a bounded restart of the
owned `.105` development service and thirteen children, a declaring audit event
and a fresh maintenance anchor after review/testing. It authorizes no old-file
deletion, failed-job replay, recovered-continuity claim or production GO.
Alternatives are another matching backup/key location for read-only inspection
and isolated recovery, or leaving the continuity gate open with no active
configuration/history change. The async question has no recorded answer in this
continuation; no new epoch has executed.

On-prem D6 requires one independent human driver plus manual keyboard/screen-reader
and email/training review. Pilot/broad-use GO needs authentic human acceptance
and signatures. A second production account is not required by that D6 scope.
Password rotation stays deferred until completed-build human signoff.
Production/RSA remains NO-GO.
